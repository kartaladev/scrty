package httpsec_test

import (
	"context"
	"encoding/base32"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

// TestEnablePasskeys_NeedsReauthenticationOnAnMFAChain pins the wiring rule: a
// chain with the MFA slot and passkeys must enable re-authentication, in any
// option order, because the slot's verify endpoint would otherwise be a
// step-up path into passkey management; a chain without the MFA slot is not
// bound by it.
func TestEnablePasskeys_NeedsReauthenticationOnAnMFAChain(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		noMFA  bool
		reauth func(h *passkeyHarness, opts []httpsec.Option) []httpsec.Option
		assert func(t *testing.T, err error)
	}{
		{
			name:   "MFA and passkeys without re-authentication is refused",
			reauth: func(_ *passkeyHarness, opts []httpsec.Option) []httpsec.Option { return opts },
			assert: func(t *testing.T, err error) {
				t.Helper()
				require.ErrorIs(t, err, httpsec.ErrConfig)
				require.ErrorContains(t, err, "EnableReauthentication")
			},
		},
		{
			name: "re-authentication enabled after the other options builds",
			reauth: func(h *passkeyHarness, opts []httpsec.Option) []httpsec.Option {
				return append(opts, httpsec.EnableReauthentication(httpsec.WithReauthenticationTokens(h.tokens)))
			},
			assert: func(t *testing.T, err error) { t.Helper(); require.NoError(t, err) },
		},
		{
			name: "re-authentication enabled before the other options builds",
			reauth: func(h *passkeyHarness, opts []httpsec.Option) []httpsec.Option {
				return append([]httpsec.Option{httpsec.EnableReauthentication(httpsec.WithReauthenticationTokens(h.tokens))}, opts...)
			},
			assert: func(t *testing.T, err error) { t.Helper(); require.NoError(t, err) },
		},
		{
			name:   "passkeys without the MFA slot build without re-authentication",
			noMFA:  true,
			reauth: func(_ *passkeyHarness, opts []httpsec.Option) []httpsec.Option { return opts },
			assert: func(t *testing.T, err error) { t.Helper(); require.NoError(t, err) },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newPasskeyHarness(t)
			h.withoutEnrolment = true
			h.withoutReauth = true
			opts := h.chainOptions(t, h.sessionIn(t, factor.Password, session.MFANone))
			if tc.noMFA {
				// chainOptions ran, so the manager exists; the chain below
				// carries the passkey endpoints alone.
				opts = []httpsec.Option{
					httpsec.EnablePasskeys(httpsec.PasskeyDeps{Passkeys: h.manager, Sessions: h.sessions, Users: h.users}),
				}
			}

			_, err := httpsec.New(tc.reauth(h, opts)...)
			tc.assert(t, err)
		})
	}
}

// TestEnablePasskeys_ReauthenticationStepsUpPasskeyManagement drives the
// supported path: a session owing no second factor, whose user enrolled TOTP,
// proves it at the re-authentication endpoint and may then begin a passkey
// registration.
func TestEnablePasskeys_ReauthenticationStepsUpPasskeyManagement(t *testing.T) {
	t.Parallel()

	h := newPasskeyHarness(t)
	h.withoutEnrolment = true

	secret := []byte(rfc6238Secret)
	gen := id.MustParse("01920000-0000-7000-8000-0000000000f1")
	require.NoError(t, h.store.PutPending(t.Context(), mfa.Enrolment{User: testMFAUser, Secret: secret, Generation: gen}))
	ok, err := h.store.Confirm(t.Context(), testMFAUser, gen, 0, h.clock.Now())
	require.NoError(t, err)
	require.True(t, ok)

	var rotatedTo atomic.Value

	h.tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, sid string, _ *identity.Principal) (string, error) {
			rotatedTo.Store(sid)

			return "tok-" + sid, nil
		})

	s := h.sessionIn(t, factor.Password, session.MFANone)
	chain := h.build(t, s)

	before := serve(t, chain, post(t.Context(), passkeyBeginPath, ""))
	require.Error(t, before.err, "precondition: begin is refused before the step-up")

	code := h.codeFor(t, base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret))
	verified := serve(t, chain, post(t.Context(), reauthVerifyTOTP, "code="+code))
	require.NoError(t, verified.err)
	require.Equal(t, http.StatusOK, verified.rec.Code)

	newID, _ := rotatedTo.Load().(string)
	require.NotEmpty(t, newID)
	assert.NotEqual(t, s.ID, newID)

	stepped := h.stored(t, newID)
	assert.Equal(t, session.MFASatisfied, stepped.MFA)

	h.pinned = stepped
	after := serve(t, chain, post(t.Context(), passkeyBeginPath, ""))
	require.NoError(t, after.err)
	assert.Equal(t, http.StatusOK, after.rec.Code)
}
