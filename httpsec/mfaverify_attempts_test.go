package httpsec_test

import (
	"context"
	"encoding/base32"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/session"
)

// barrierLimiter holds every Exceeded call until n callers have checked, so
// every request passes the endpoint's throttle before any failure is recorded:
// the interleaving a limiter that checks and records in two steps admits.
type barrierLimiter struct {
	wg sync.WaitGroup
}

func newBarrierLimiter(n int) *barrierLimiter {
	l := &barrierLimiter{}
	l.wg.Add(n)

	return l
}

func (l *barrierLimiter) Exceeded(context.Context, string) (bool, error) {
	l.wg.Done()
	l.wg.Wait()

	return false, nil
}

func (l *barrierLimiter) RecordFailure(context.Context, string) error { return nil }

// TestMFAVerify_RefusedChargeIsNotRecorded pins that a method refusing a
// verification because its attempt charge was refused compared nothing, so the
// endpoint returns the refusal unchanged and records no failed verification. A
// wrong code that was compared still is recorded.
func TestMFAVerify_RefusedChargeIsNotRecorded(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		verifyErr error
		// failures is how many failed verifications the limiter must record.
		failures int
		assert   func(t *testing.T, s served)
	}

	cases := []testCase{
		{
			name:      "a refused attempt charge is returned unchanged and not recorded",
			verifyErr: mfa.ErrVerifyAttemptsExhausted,
			failures:  0,
			assert: func(t *testing.T, s served) {
				require.ErrorIs(t, s.err, mfa.ErrVerifyAttemptsExhausted)
				require.ErrorIs(t, s.err, mfa.ErrVerifyThrottled)
				assert.NotErrorIs(t, s.err, mfa.ErrInvalidCode)
				assert.Equal(t, 401, httpsec.StatusForError(s.err))
			},
		},
		{
			name:      "a compared wrong code is still recorded",
			verifyErr: mfa.ErrInvalidCode,
			failures:  1,
			assert: func(t *testing.T, s served) {
				require.ErrorIs(t, s.err, mfa.ErrInvalidCode)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newMFAHarness(t)
			h.channel(factor.AuthenticatorApp)
			h.method.EXPECT().Verify(gomock.Any(), testMFAUser, gomock.Any()).Return(tc.verifyErr)
			h.limiter.EXPECT().Exceeded(gomock.Any(), mfa.VerifyThrottleKey(testMFAUser)).
				Return(false, nil)
			h.limiter.EXPECT().RecordFailure(gomock.Any(), mfa.VerifyThrottleKey(testMFAUser)).
				Return(nil).Times(tc.failures)

			s := h.pendingSession(t, factor.Password)
			c := h.chain(t, s)

			out := serve(t, c, postCode(t.Context(), testMFAVerifyPath))
			tc.assert(t, out)
			assert.Equal(t, session.MFAPending, h.stored(t, s.ID).MFA, "the challenge stays pending")
		})
	}
}

// TestMFAVerify_ConcurrentWrongCodesComparedAtMostTheLimit pins that however
// many wrong codes race through the endpoint's throttle at once, a real TOTP
// compares at most its attempt limit of them, and refuses the rest as
// throttled.
func TestMFAVerify_ConcurrentWrongCodesComparedAtMostTheLimit(t *testing.T) {
	t.Parallel()

	const racers = 20

	secret := []byte(rfc6238Secret)
	clk := clockwork.NewFakeClockAt(time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC))

	store := mfa.NewMemoryEnrolmentStore()
	require.NoError(t, store.PutPending(t.Context(), mfa.Enrolment{User: testMFAUser, Secret: secret}))
	ok, err := store.Confirm(t.Context(), testMFAUser, 0, clk.Now())
	require.NoError(t, err)
	require.True(t, ok)

	method, err := mfa.NewTOTP(store, "scrty-test", mfa.WithClock(clk))
	require.NoError(t, err)

	h := newMFAHarness(t)

	// The harness's own method double is not in this chain; the real method
	// is, and it is named "totp" as the default verify path expects.
	s := h.pendingSession(t, factor.Password)
	c, err := httpsec.New(
		httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
			Verifier: h.tokens,
			Sessions: h.sessions,
			Users:    h.users,
		}),
		httpsec.EnableMFA([]mfa.Method{method},
			httpsec.WithMFAVerifyLimiter(newBarrierLimiter(racers)),
			httpsec.WithMFATokens(h.tokens)),
	)
	require.NoError(t, err)

	wrong := wrongTOTPCode(t, secret, clk.Now())

	var compared, throttled atomic.Int32

	var wg sync.WaitGroup
	for range racers {
		wg.Go(func() {
			req := formRequest(t.Context(), testMFAVerifyPath, "code="+wrong)
			req.Header.Set("Authorization", "Bearer "+mfaTokenFor(s.ID))

			out := serve(t, c, req)

			switch {
			case errors.Is(out.err, mfa.ErrInvalidCode):
				compared.Add(1)
			case errors.Is(out.err, mfa.ErrVerifyThrottled):
				throttled.Add(1)
			}
		})
	}

	wg.Wait()

	assert.LessOrEqual(t, int(compared.Load()), mfa.DefaultVerifyAttemptLimit,
		"wrong codes compared against one enrolment")
	assert.Equal(t, int32(racers), compared.Load()+throttled.Load(),
		"every request is either compared or refused as throttled")
}

// rfc6238Secret is the ASCII seed RFC 6238 Appendix B uses for HMAC-SHA-1.
const rfc6238Secret = "12345678901234567890"

// wrongTOTPCode returns a well-formed code that none of the steps a
// verification at at accepts would match. It computes the accepted codes
// through pquerna/otp directly, so the expectation shares no code with mfa.
func wrongTOTPCode(t *testing.T, secret []byte, at time.Time) string {
	t.Helper()

	key := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
	accepted := map[string]bool{}

	for _, d := range []time.Duration{-30 * time.Second, 0, 30 * time.Second} {
		code, err := totp.GenerateCodeCustom(key, at.Add(d), totp.ValidateOpts{
			Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
		})
		require.NoError(t, err)

		accepted[code] = true
	}

	for _, c := range []string{"000000", "111111", "222222", "333333"} {
		if !accepted[c] {
			return c
		}
	}

	t.Fatal("no wrong code found")

	return ""
}
