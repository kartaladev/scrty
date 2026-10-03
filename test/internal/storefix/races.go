package storefix

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/onetime"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/test/storetest"
)

// ConsumeRace is the race over consume, of any store that consumes like the
// one-time token store: Seed inserts token i through s, and Attempt consumes
// it, the refusal mapped to (false, nil).
func ConsumeRace[S onetime.Store]() storetest.Race[S] {
	return storetest.Race[S]{
		Seed: func(ctx context.Context, t *testing.T, s S, i int) string {
			tok := RaceToken(i)
			require.NoError(t, s.Insert(ctx, tok))
			return tok.ID.String()
		},
		Attempt: func(ctx context.Context, s S, key string, _ int) (bool, error) {
			err := s.Consume(ctx, id.MustParse(key), time.Now())
			if errors.Is(err, onetime.ErrTokenNotFound) {
				return false, nil
			}
			return err == nil, err
		},
	}
}

// StepRace is the race over AcceptStep: Seed confirms user i's enrolment at
// step 1000, and every racer records step 1002.
func StepRace[S mfa.EnrolmentStore]() storetest.Race[S] {
	return storetest.Race[S]{
		Seed: func(ctx context.Context, t *testing.T, s S, i int) string {
			user := identity.UserID(fmt.Sprintf("race-user-%d", i))
			require.NoError(t, s.PutPending(ctx, Pending(user, "secret")))
			ok, err := s.Confirm(ctx, user, 1000, EnrolmentBegun.Add(time.Minute))
			require.NoError(t, err)
			require.True(t, ok)
			return string(user)
		},
		Attempt: func(ctx context.Context, s S, key string, _ int) (bool, error) {
			return s.AcceptStep(ctx, identity.UserID(key), 1002)
		},
	}
}

// Times and values the enrolment-path races seed with: the device is proven
// at RaceProvenAt with an emailed code good until RaceCodeUntil, and every
// racer writes at RaceAttemptAt, before the code expires.
var (
	RaceProvenAt  = EnrolmentBegun.Add(time.Minute)
	RaceCodeUntil = EnrolmentBegun.Add(11 * time.Minute)
	RaceAttemptAt = EnrolmentBegun.Add(2 * time.Minute)
)

// RaceEmailCode is the emailed code every enrolment-path race's device proof
// issues.
const RaceEmailCode = "271828"

// provenKeySep separates the user from the generation in a proven
// enrolment's race key. The users the races seed never hold it.
const provenKeySep = "|"

// seedProven begins user i's enrolment on a generation of its own, proves its
// device at step 1001 with the race's emailed code, and returns the key
// "race-user-i|generation".
func seedProven[S storetest.DeviceProofEnrolmentStore](
	ctx context.Context, t *testing.T, s S, gen id.Generator, i int,
) string {
	t.Helper()

	user := identity.UserID(fmt.Sprintf("race-user-%d", i))
	g, err := gen.NewID()
	require.NoError(t, err)

	e := Pending(user, "secret")
	e.Generation = g
	require.NoError(t, s.PutPending(ctx, e))
	proven, err := s.ProveDevice(ctx, user, g, 1001, []byte(RaceEmailCode), RaceCodeUntil, RaceProvenAt)
	require.NoError(t, err)
	require.True(t, proven, "the seeded enrolment of %q must be proven", user)

	return string(user) + provenKeySep + g.String()
}

// provenKey recovers the user and the generation from a key seedProven made.
func provenKey(key string) (identity.UserID, id.ID, error) {
	user, g, ok := strings.Cut(key, provenKeySep)
	if !ok {
		return "", id.Nil, fmt.Errorf("storefix: race key %q holds no generation", key)
	}
	gen, err := id.Parse(g)
	if err != nil {
		return "", id.Nil, fmt.Errorf("storefix: race key %q: %w", key, err)
	}
	return identity.UserID(user), gen, nil
}

// CompleteRace is the race over Complete: Seed begins user i's enrolment on
// a generation of its own and proves its device, and every racer completes
// that generation.
func CompleteRace[S storetest.DeviceProofEnrolmentStore]() storetest.Race[S] {
	gen := id.NewV7Generator()
	return storetest.Race[S]{
		Seed: func(ctx context.Context, t *testing.T, s S, i int) string {
			return seedProven(ctx, t, s, gen, i)
		},
		Attempt: func(ctx context.Context, s S, key string, _ int) (bool, error) {
			user, g, err := provenKey(key)
			if err != nil {
				return false, err
			}
			return s.Complete(ctx, user, g, RaceAttemptAt)
		},
	}
}

// ChargeRace is the race over ChargeEmailCode: Seed begins user i's
// enrolment on a generation of its own and proves its device with an emailed
// code, and every racer charges an attempt against that code before it
// expires. Check then requires each enrolment to hold exactly
// mfa.MaxEmailCodeFailures attempts and its code, still stored with its
// expiry.
func ChargeRace[S storetest.DeviceProofEnrolmentStore]() storetest.Race[S] {
	gen := id.NewV7Generator()
	return storetest.Race[S]{
		Seed: func(ctx context.Context, t *testing.T, s S, i int) string {
			return seedProven(ctx, t, s, gen, i)
		},
		Attempt: func(ctx context.Context, s S, key string, _ int) (bool, error) {
			user, g, err := provenKey(key)
			if err != nil {
				return false, err
			}
			_, charged, err := s.ChargeEmailCode(ctx, user, g, RaceAttemptAt)
			return charged, err
		},
		Check: func(ctx context.Context, t *testing.T, s S, key string) {
			t.Helper()

			user, _, err := provenKey(key)
			require.NoError(t, err)
			e, ok, err := s.Get(ctx, user)
			require.NoError(t, err)
			require.True(t, ok, "the enrolment of %q must be present after the race", user)
			assert.Equal(t, mfa.MaxEmailCodeFailures, e.EmailCodeAttempts,
				"%q: EmailCodeAttempts after the race must be the cap", user)
			assert.Equal(t, []byte(RaceEmailCode), e.EmailCode,
				"%q: EmailCode must still be stored after the race", user)
			assert.True(t, e.EmailCodeUntil.Equal(RaceCodeUntil),
				"%q: EmailCodeUntil after the race is %v, want %v", user, e.EmailCodeUntil, RaceCodeUntil)
		},
	}
}

// VerifyChargeRace is the race over TOTP verification charges: Seed stores and
// confirms the enrolment of race-user-i, every racer charges it at
// RaceAttemptAt with the default limit and window, and Check requires each
// enrolment to hold exactly the limit, in the window the charges opened.
func VerifyChargeRace[S mfa.EnrolmentStore]() storetest.Race[S] {
	return storetest.Race[S]{
		Seed: func(ctx context.Context, t *testing.T, s S, i int) string {
			user := identity.UserID(fmt.Sprintf("race-user-%d", i))
			require.NoError(t, s.PutPending(ctx, Pending(user, "secret")))
			ok, err := s.Confirm(ctx, user, 1000, EnrolmentBegun.Add(time.Minute))
			require.NoError(t, err)
			require.True(t, ok, "the seeded enrolment of %q must confirm", user)
			return string(user)
		},
		Attempt: func(ctx context.Context, s S, key string, _ int) (bool, error) {
			_, charged, err := s.ChargeVerifyAttempt(ctx, identity.UserID(key), RaceAttemptAt,
				mfa.DefaultVerifyAttemptLimit, mfa.DefaultVerifyAttemptWindow)
			return charged, err
		},
		Check: func(ctx context.Context, t *testing.T, s S, key string) {
			t.Helper()

			e, ok, err := s.Get(ctx, identity.UserID(key))
			require.NoError(t, err)
			require.True(t, ok, "the enrolment of %q must be present after the race", key)
			assert.Equal(t, mfa.DefaultVerifyAttemptLimit, e.VerifyAttempts,
				"%q: VerifyAttempts after the race must be the limit", key)
			want := RaceAttemptAt.Add(mfa.DefaultVerifyAttemptWindow)
			assert.True(t, e.VerifyWindowUntil.Equal(want),
				"%q: VerifyWindowUntil after the race is %v, want %v", key, e.VerifyWindowUntil, want)
		},
	}
}

// HandoffRace is the race over handoff consumption: Seed inserts the record
// race-token-i, and every racer consumes it, the refusal mapped to
// (false, nil).
func HandoffRace[S oidc.HandoffStore]() storetest.Race[S] {
	return storetest.Race[S]{
		Seed: func(ctx context.Context, t *testing.T, s S, i int) string {
			rec := Handoff(t, fmt.Sprintf("race-token-%d", i))
			require.NoError(t, s.Insert(ctx, rec))
			return rec.TokenID
		},
		Attempt: func(ctx context.Context, s S, key string, _ int) (bool, error) {
			err := s.Consume(ctx, key, time.Now())
			if errors.Is(err, oidc.ErrHandoffNotFound) {
				return false, nil
			}
			return err == nil, err
		},
	}
}

// LinkRace is the race over link inserts: record i is the subject
// race-subject-i, which Seed does not insert, and every racer inserts it for
// a user of its own, the refusal mapped to (false, nil).
func LinkRace[S oidc.LinkStore]() storetest.Race[S] {
	gen := id.NewV7Generator()
	return storetest.Race[S]{
		Seed: func(_ context.Context, _ *testing.T, _ S, i int) string {
			return fmt.Sprintf("race-subject-%d", i)
		},
		Attempt: func(ctx context.Context, s S, key string, racer int) (bool, error) {
			linkID, err := gen.NewID()
			if err != nil {
				return false, err
			}
			err = s.Insert(ctx, oidc.Link{
				ID: linkID, Provider: "corp", Issuer: "https://race.example", Subject: key,
				UserID: identity.UserID(fmt.Sprintf("u-%d", racer)), CreatedAt: OIDCStart,
			})
			if errors.Is(err, oidc.ErrLinkExists) {
				return false, nil
			}
			return err == nil, err
		},
	}
}
