package storefix

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

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
