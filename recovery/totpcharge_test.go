package recovery_test

import (
	"encoding/base32"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/recovery"
)

// totpCodeAt computes the code an authenticator holding secret shows at at,
// straight from the RFC 6238 generator rather than through mfa.
func totpCodeAt(t *testing.T, secret []byte, at time.Time) string {
	t.Helper()

	code, err := totp.GenerateCodeCustom(
		base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret), at,
		totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	require.NoError(t, err)

	return code
}

// A recovery that proves the account with a TOTP code calls the method's
// Verify directly, so it is bound by the same per-enrolment attempt charge as
// a login: a wrong code is charged, and a valid one gives its own charge back.
func TestRecoverer_TOTPProofIsCharged(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	e := newRecoverEnv(t)

	secret := []byte("recovery-totp-secret")
	store := mfa.NewMemoryEnrolmentStore()
	require.NoError(t, store.PutPending(ctx, mfa.Enrolment{User: anaID, Secret: secret}))
	confirmed, err := store.Confirm(ctx, anaID, 0, e.clock.Now())
	require.NoError(t, err)
	require.True(t, confirmed)

	method, err := mfa.NewTOTP(store, "scrty-test", mfa.WithClock(e.clock))
	require.NoError(t, err)

	e.defaults()

	r, err := recovery.NewRecoverer(e.deps(), e.fixture.opts(
		recovery.WithProofs(recovery.ProofIssued, recovery.ProofMFA),
		recovery.WithMFAMethods(method),
		recovery.WithIssuedCodeStore(e.tokens),
		recovery.WithUserLimiter(e.limiter),
	)...)
	require.NoError(t, err)

	accepted := map[string]bool{}
	for _, d := range []time.Duration{-30 * time.Second, 0, 30 * time.Second} {
		accepted[totpCodeAt(t, secret, e.clock.Now().Add(d))] = true
	}

	wrong := "000000"
	for _, c := range []string{"000000", "111111", "222222"} {
		if !accepted[c] {
			wrong = c

			break
		}
	}

	attempts := func() int {
		got, ok, err := store.Get(ctx, anaID)
		require.NoError(t, err)
		require.True(t, ok)

		return got.VerifyAttempts
	}

	_, err = recoverOnce(ctx, r, recovery.Request{
		Username: anaUsername, Issued: e.issued, MFAMethod: "totp", MFACode: wrong,
	})
	require.ErrorIs(t, err, recovery.ErrRefused)
	assert.Equal(t, 1, attempts(), "the wrong code was charged against the enrolment")

	v, err := recoverOnce(ctx, r, recovery.Request{
		Username: anaUsername, Issued: e.issued, MFAMethod: "totp", MFACode: totpCodeAt(t, secret, e.clock.Now()),
	})
	require.NoError(t, err)
	assert.Equal(t, []recovery.ProofKind{recovery.ProofIssued, recovery.ProofMFA}, v.Proofs())
	assert.Equal(t, 1, attempts(), "the valid code gave its own charge back")
}
