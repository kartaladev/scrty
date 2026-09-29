package mfa_test

import (
	"context"
	"encoding/base32"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
)

// rfc6238SHA1Secret is the ASCII seed RFC 6238 Appendix B uses for HMAC-SHA-1,
// "12345678901234567890", which an enrolment carries as raw bytes and a
// provisioning URI as base32.
const rfc6238SHA1Secret = "12345678901234567890"

// base32Secret renders a raw secret the way an authenticator is given it.
func base32Secret(secret []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
}

// enrolConfirmed writes a confirmed enrolment straight to the store, with a
// last step of zero so that no verification under test is refused as a replay
// of a step this fixture recorded.
func enrolConfirmed(t *testing.T, s mfa.EnrolmentStore, user identity.UserID, secret []byte) {
	t.Helper()

	require.NoError(t, s.PutPending(t.Context(), mfa.Enrolment{User: user, Secret: secret}))

	ok, err := s.Confirm(t.Context(), user, 0, time.Now())
	require.NoError(t, err)
	require.True(t, ok)
}

// codeAt computes the code a well-behaved authenticator would show at at.
//
// It goes through pquerna/otp directly rather than through anything in mfa, so
// a bug shared by the implementation and the expectation cannot hide here.
func codeAt(t *testing.T, secret []byte, at time.Time, digits int, period time.Duration) string {
	t.Helper()

	code, err := totp.GenerateCodeCustom(base32Secret(secret), at, totp.ValidateOpts{
		Period:    uint(period.Seconds()),
		Digits:    otp.Digits(digits),
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)

	return code
}

// codeForSecret is codeAt for a secret already in the base32 form an enrolment
// hands back.
func codeForSecret(t *testing.T, secret string, at time.Time) string {
	t.Helper()

	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	require.NoError(t, err)

	return codeAt(t, raw, at, 6, 30*time.Second)
}

// countingEnrolmentStore counts the calls that decide acceptance, so a test can
// assert that a code refused on its form never reached the store at all.
type countingEnrolmentStore struct {
	mfa.EnrolmentStore

	acceptStep atomic.Int64
}

func (s *countingEnrolmentStore) AcceptStep(
	ctx context.Context, user identity.UserID, step int64,
) (bool, error) {
	s.acceptStep.Add(1)

	return s.EnrolmentStore.AcceptStep(ctx, user, step)
}

func (s *countingEnrolmentStore) AcceptStepCalls() int64 { return s.acceptStep.Load() }

func TestTOTPRFC6238Vectors(t *testing.T) {
	t.Parallel()

	type testCase struct {
		unix int64
		code string
	}

	// Appendix B, the SHA-1 rows, at 8 digits.
	cases := []testCase{
		{unix: 59, code: "94287082"},
		{unix: 1111111109, code: "07081804"},
		{unix: 1111111111, code: "14050471"},
		{unix: 1234567890, code: "89005924"},
		{unix: 2000000000, code: "69279037"},
		{unix: 20000000000, code: "65353130"},
	}

	for _, tc := range cases {
		t.Run(strconv.FormatInt(tc.unix, 10), func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			at := time.Unix(tc.unix, 0).UTC()
			store := mfa.NewMemoryEnrolmentStore()

			m, err := mfa.NewTOTP(store, "Example",
				mfa.WithDigits(8),
				mfa.WithClock(clockwork.NewFakeClockAt(at)),
			)
			require.NoError(t, err)

			enrolConfirmed(t, store, "u-1", []byte(rfc6238SHA1Secret))

			assert.NoError(t, m.Verify(ctx, "u-1", tc.code))
		})
	}
}

func TestTOTPStepWindow(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)

	type testCase struct {
		name   string
		offset time.Duration
		mutate func(code string) string
		assert func(t *testing.T, err error)
	}

	ok := func(t *testing.T, err error) { assert.NoError(t, err) }
	invalid := func(t *testing.T, err error) { assert.ErrorIs(t, err, mfa.ErrInvalidCode) }

	cases := []testCase{
		{name: "the current step", offset: 0, assert: ok},
		{name: "one step back", offset: -30 * time.Second, assert: ok},
		{name: "one step forward", offset: 30 * time.Second, assert: ok},
		{name: "two steps back", offset: -60 * time.Second, assert: invalid},
		{name: "two steps forward", offset: 60 * time.Second, assert: invalid},
		{
			name:   "a wrong code",
			mutate: func(string) string { return "000000" },
			assert: invalid,
		},
		{name: "too few digits", mutate: func(c string) string { return c[:5] }, assert: invalid},
		{name: "too many digits", mutate: func(c string) string { return c + "0" }, assert: invalid},
		{name: "not digits", mutate: func(string) string { return "12345a" }, assert: invalid},
		{name: "a signed number", mutate: func(string) string { return "+12345" }, assert: invalid},
		{name: "unicode digits", mutate: func(string) string { return "١٢٣٤٥٦" }, assert: invalid},
		{name: "empty", mutate: func(string) string { return "" }, assert: invalid},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			store := &countingEnrolmentStore{EnrolmentStore: mfa.NewMemoryEnrolmentStore()}
			m, err := mfa.NewTOTP(store, "Example",
				mfa.WithClock(clockwork.NewFakeClockAt(base)),
			)
			require.NoError(t, err)

			secret := []byte(rfc6238SHA1Secret)
			enrolConfirmed(t, store, "u-1", secret)

			code := codeAt(t, secret, base.Add(tc.offset), 6, 30*time.Second)
			if tc.mutate != nil {
				code = tc.mutate(code)
			}

			before := store.AcceptStepCalls()
			tc.assert(t, m.Verify(ctx, "u-1", code))

			if tc.mutate != nil {
				assert.Equal(t, before, store.AcceptStepCalls(),
					"a malformed or wrong code must not reach the store")
			}
		})
	}
}
