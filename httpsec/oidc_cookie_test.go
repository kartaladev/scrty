package httpsec_test

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// errOIDCCookieDelivery is what a failing delivery port answers a federated
// sign-in's cookie with.
var errOIDCCookieDelivery = errors.New("oidc_cookie_test: the delivery failed")

// failingOIDCDelivery is a SessionDelivery that writes nothing and fails.
func failingOIDCDelivery(t *testing.T) *MockSessionDelivery {
	t.Helper()

	delivery := NewMockSessionDelivery(gomock.NewController(t))
	delivery.EXPECT().Deliver(gomock.Any(), gomock.Any(), gomock.Any()).Times(1).
		Return("", errOIDCCookieDelivery)

	return delivery
}

// oidcCookieChain builds the harness's federated login on a cookie chain whose
// user loader is users, with the harness's session manager, the cookie
// session's options cookieOpts, and no handoff manager.
func oidcCookieChain(
	h *oidcHarness, users identity.UserLoader, cookieOpts []httpsec.SessionCookieOption, opts ...httpsec.OIDCOption,
) (*httpsec.Chain, error) {
	h.chainOpts = append(h.chainOpts, httpsec.WithoutCSRFProtection(),
		httpsec.EnableSessionCookie(httpsec.SessionBearerDeps{Sessions: h.sessions, Users: users}, cookieOpts...))

	return h.assemble(nil, append([]httpsec.OIDCOption{httpsec.WithOIDCSessions(h.sessions)}, opts...)...)
}

// enableCookieMFA enables the second-factor slot over one enrolled method,
// with no token generator, as a cookie chain requires.
func enableCookieMFA(t *testing.T) httpsec.Option {
	t.Helper()

	method := NewMockMethod(gomock.NewController(t))
	method.EXPECT().Name().Return("totp").AnyTimes()
	method.EXPECT().Response().Return(mfa.FormField("code", 4<<10)).AnyTimes()
	method.EXPECT().Channel().Return(factor.AuthenticatorApp).AnyTimes()
	method.EXPECT().Enrolled(gomock.Any(), gomock.Any()).Return(true, nil).AnyTimes()

	return httpsec.EnableMFA([]mfa.Method{method})
}

// TestOIDCLogin_CookieChainCallback pins the federated callback of a cookie
// chain with no consumer callback success: it completes the sign-in in the
// callback, creating the session in one write with the federated first
// factor and the provider's session and assurance, sets the session cookie
// through the chain's delivery, and sends the browser 303 to the destination
// the redirect allowlist resolved, with no handoff code anywhere. A challenge
// the policy raises still sets the pending session's cookie and redirects. A
// user the cookie session cannot load, and a delivery that fails, end the
// sign-in with no cookie and no redirect. A consumer's callback success
// still writes the whole response.
func TestOIDCLogin_CookieChainCallback(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// setup configures the harness and builds the chain, returning the
		// spy on the session store's writes when the case reads it.
		setup func(t *testing.T, h *oidcHarness) (*httpsec.Chain, *sessionWrites)

		// next is the destination the login is started with.
		next string

		assert func(t *testing.T, h *oidcHarness, w *sessionWrites, out served)
	}

	spied := func(t *testing.T, h *oidcHarness) *sessionWrites {
		t.Helper()

		sessions, w := spiedSessions(t)
		h.sessions = sessions

		return w
	}

	noRedirect := func(t *testing.T, h *oidcHarness, out served) {
		t.Helper()

		require.Error(t, out.err)
		noSessionCookie(t, out)
		assert.Empty(t, out.rec.Header().Get("Location"), "nothing is redirected to")
		assert.Zero(t, h.activeSessions(t), "no sign-in is left live")
	}

	cases := []testCase{
		{
			name: "completes in the callback and redirects to the allowlisted destination",
			setup: func(t *testing.T, h *oidcHarness) (*httpsec.Chain, *sessionWrites) {
				w := spied(t, h)

				chain, err := oidcCookieChain(h, referenceUsers(t), nil, httpsec.WithOIDCAllowedRedirects("/orders"))
				require.NoError(t, err)

				return chain, w
			},
			next: "/orders",
			assert: func(t *testing.T, h *oidcHarness, w *sessionWrites, out served) {
				t.Helper()

				require.NoError(t, out.err)
				id := deliveredOnlyInCookie(t, h.sessions, out)

				assert.Equal(t, http.StatusSeeOther, out.rec.Code)
				assert.Equal(t, "/orders", out.rec.Header().Get("Location"))
				assert.NotContains(t, out.rec.Header().Get("Location"), "code=")
				assert.NotContains(t, out.rec.Header().Get("Location"), httpsec.DefaultOIDCHandoffParam+"=")
				assert.Equal(t, "no-referrer", out.rec.Header().Get("Referrer-Policy"))
				assert.Equal(t, "no-store", out.rec.Header().Get("Cache-Control"), "the redirect is never cached")
				assert.False(t, out.handlerRan)
				assert.Zero(t, h.storedHandoffs(t), "no handoff code was issued")

				creates := w.creates()
				require.Len(t, creates, 1, "one creating write")
				assert.Empty(t, w.saves(), "nothing was added after the creating write")

				created := creates[0]
				assert.Equal(t, id, created.ID)
				assert.Equal(t, factor.OIDC, created.FirstFactor)
				assert.Equal(t, oidcTestUserID, created.UserID)
				assert.Equal(t, testOIDCProvider, created.ExternalProvider)
				assert.Equal(t, h.provider.srv.URL, created.ExternalIssuer)
				assert.NotEmpty(t, created.ExternalIDToken)
				assert.Equal(t, session.MFANone, created.MFA)
			},
		},
		{
			name: "a destination off the allowlist lands on the root",
			setup: func(t *testing.T, h *oidcHarness) (*httpsec.Chain, *sessionWrites) {
				chain, err := oidcCookieChain(h, referenceUsers(t), nil)
				require.NoError(t, err)

				return chain, nil
			},
			next: "//evil.example/",
			assert: func(t *testing.T, h *oidcHarness, _ *sessionWrites, out served) {
				t.Helper()

				require.NoError(t, out.err)
				deliveredOnlyInCookie(t, h.sessions, out)
				assert.Equal(t, http.StatusSeeOther, out.rec.Code)
				assert.Equal(t, "/", out.rec.Header().Get("Location"))
			},
		},
		{
			name: "a challenge sets the pending session's cookie and still redirects",
			setup: func(t *testing.T, h *oidcHarness) (*httpsec.Chain, *sessionWrites) {
				w := spied(t, h)
				h.chainOpts = append(h.chainOpts,
					httpsec.WithPolicyEngine(oidcMFAEngine(t, false, func() bool { return true })),
					enableCookieMFA(t))

				chain, err := oidcCookieChain(h, referenceUsers(t), nil, httpsec.WithOIDCAllowedRedirects("/orders"))
				require.NoError(t, err)

				return chain, w
			},
			next: "/orders",
			assert: func(t *testing.T, h *oidcHarness, w *sessionWrites, out served) {
				t.Helper()

				require.NoError(t, out.err, "the callback answers the challenge with its redirect")
				id := deliveredOnlyInCookie(t, h.sessions, out)
				assert.Equal(t, http.StatusSeeOther, out.rec.Code)
				assert.Equal(t, "/orders", out.rec.Header().Get("Location"))

				creates := w.creates()
				require.Len(t, creates, 1)
				assert.Equal(t, id, creates[0].ID)
				assert.Equal(t, session.MFAPending, creates[0].MFA, "the cookie names the pending session")
				assert.Equal(t, factor.OIDC, creates[0].FirstFactor)
			},
		},
		{
			name: "a user the cookie session cannot find is refused",
			setup: func(t *testing.T, h *oidcHarness) (*httpsec.Chain, *sessionWrites) {
				users := NewMockUserLoader(gomock.NewController(t))
				users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).AnyTimes().
					Return(nil, identity.ErrUserNotFound)

				chain, err := oidcCookieChain(h, users, nil)
				require.NoError(t, err)

				return chain, nil
			},
			assert: func(t *testing.T, h *oidcHarness, _ *sessionWrites, out served) {
				t.Helper()
				noRedirect(t, h, out)
				assert.ErrorIs(t, out.err, oidc.ErrInvalidHandoff)
			},
		},
		{
			name: "an inactive user is refused",
			setup: func(t *testing.T, h *oidcHarness) (*httpsec.Chain, *sessionWrites) {
				users := NewMockUserLoader(gomock.NewController(t))
				users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).AnyTimes().
					Return(&identity.Details{ID: oidcTestUserID, Username: "ada@example.com"}, nil)

				chain, err := oidcCookieChain(h, users, nil)
				require.NoError(t, err)

				return chain, nil
			},
			assert: func(t *testing.T, h *oidcHarness, _ *sessionWrites, out served) {
				t.Helper()
				noRedirect(t, h, out)
				assert.ErrorIs(t, out.err, oidc.ErrInvalidHandoff)
			},
		},
		{
			name: "a policy denial at the completion check stores nothing and redirects nowhere",
			setup: func(t *testing.T, h *oidcHarness) (*httpsec.Chain, *sessionWrites) {
				w := spied(t, h)
				h.chainOpts = append(h.chainOpts, httpsec.WithPolicyEngine(denyingEngine(t, nil)))

				chain, err := oidcCookieChain(h, referenceUsers(t), nil, httpsec.WithOIDCAllowedRedirects("/orders"))
				require.NoError(t, err)

				return chain, w
			},
			next: "/orders",
			assert: func(t *testing.T, h *oidcHarness, w *sessionWrites, out served) {
				t.Helper()
				noRedirect(t, h, out)
				assert.ErrorIs(t, out.err, policy.ErrDenied)
				assert.Empty(t, w.creates(), "no session was stored")
				assert.Empty(t, w.saves())
			},
		},
		{
			name: "a user the loader answers as another is refused and stores nothing",
			setup: func(t *testing.T, h *oidcHarness) (*httpsec.Chain, *sessionWrites) {
				w := spied(t, h)

				users := NewMockUserLoader(gomock.NewController(t))
				users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).AnyTimes().
					Return(&identity.Details{ID: "someone-else", Username: "eve@example.com", Active: true}, nil)

				chain, err := oidcCookieChain(h, users, nil, httpsec.WithOIDCAllowedRedirects("/orders"))
				require.NoError(t, err)

				return chain, w
			},
			next: "/orders",
			assert: func(t *testing.T, h *oidcHarness, w *sessionWrites, out served) {
				t.Helper()
				noRedirect(t, h, out)
				assert.ErrorIs(t, out.err, oidc.ErrInvalidHandoff)
				assert.Empty(t, w.creates(), "no session was stored")
				assert.Empty(t, w.saves())
			},
		},
		{
			name: "a user loader outage is a dependency failure",
			setup: func(t *testing.T, h *oidcHarness) (*httpsec.Chain, *sessionWrites) {
				users := NewMockUserLoader(gomock.NewController(t))
				users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).AnyTimes().
					Return(nil, errOIDCCookieDelivery)

				chain, err := oidcCookieChain(h, users, nil)
				require.NoError(t, err)

				return chain, nil
			},
			assert: func(t *testing.T, h *oidcHarness, _ *sessionWrites, out served) {
				t.Helper()
				noRedirect(t, h, out)
				assert.ErrorIs(t, out.err, errOIDCCookieDelivery)
				assert.NotErrorIs(t, out.err, oidc.ErrInvalidHandoff)
			},
		},
		{
			name: "a delivery that fails ends the sign-in and redirects nowhere",
			setup: func(t *testing.T, h *oidcHarness) (*httpsec.Chain, *sessionWrites) {
				chain, err := oidcCookieChain(h, referenceUsers(t),
					[]httpsec.SessionCookieOption{httpsec.WithSessionDelivery(failingOIDCDelivery(t))},
					httpsec.WithOIDCAllowedRedirects("/orders"))
				require.NoError(t, err)

				return chain, nil
			},
			next: "/orders",
			assert: func(t *testing.T, h *oidcHarness, _ *sessionWrites, out served) {
				t.Helper()
				noRedirect(t, h, out)
				assert.ErrorIs(t, out.err, errOIDCCookieDelivery)
				assert.NotEqual(t, http.StatusSeeOther, out.rec.Code)
			},
		},
		{
			name: "a consumer callback success writes the response",
			setup: func(t *testing.T, h *oidcHarness) (*httpsec.Chain, *sessionWrites) {
				chain, err := oidcCookieChain(h, referenceUsers(t), nil, httpsec.WithOIDCCallbackSuccess(
					func(ex *httpsec.Exchange, _ oidc.CallbackResult, next string) error {
						ex.Writer.SetHeader("X-Next", next)
						ex.Writer.WriteHeader(http.StatusNoContent)

						return nil
					}), httpsec.WithOIDCAllowedRedirects("/orders"))
				require.NoError(t, err)

				return chain, nil
			},
			next: "/orders",
			assert: func(t *testing.T, h *oidcHarness, _ *sessionWrites, out served) {
				t.Helper()

				require.NoError(t, out.err)
				assert.Equal(t, http.StatusNoContent, out.rec.Code)
				assert.Equal(t, "/orders", out.rec.Header().Get("X-Next"))
				noSessionCookie(t, out)
				assert.Zero(t, h.activeSessions(t), "the consumer's function owns the sign-in")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newOIDCHarness(t)
			chain, w := tc.setup(t, h)

			l := startLogin(t, chain, tc.next)
			out := serve(t, chain, callbackRequest(t.Context(), l.genuineCallback(), l.handle))

			tc.assert(t, h, w, out)
		})
	}
}

// TestOIDCLogin_CookieChainRefusesHandoff pins that a cookie chain conveys a
// federated login in its callback alone: a handoff manager, and every option
// that governs only a handoff's redemption, are configuration errors from
// New, as is a token generator, and role sync while the callback reloads the
// user's stored roles.
func TestOIDCLogin_CookieChainRefusesHandoff(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name  string
		build func(t *testing.T, h *oidcHarness) error

		assert func(t *testing.T, err error)
	}

	refused := func(names ...string) func(*testing.T, error) {
		return func(t *testing.T, err error) {
			t.Helper()
			require.ErrorIs(t, err, httpsec.ErrConfig)

			for _, n := range names {
				assert.Contains(t, err.Error(), n)
			}
		}
	}

	cookie := func(t *testing.T, h *oidcHarness) {
		t.Helper()
		h.chainOpts = append(h.chainOpts, httpsec.WithoutCSRFProtection(),
			httpsec.EnableSessionCookie(httpsec.SessionBearerDeps{Sessions: h.sessions, Users: referenceUsers(t)}))
	}

	cases := []testCase{
		{
			name: "handoff manager",
			build: func(t *testing.T, h *oidcHarness) error {
				cookie(t, h)
				_, err := h.assemble(h.handoffs, httpsec.WithOIDCSessions(h.sessions))

				return err
			},
			assert: refused("OIDCDeps.Handoff", "EnableSessionCookie"),
		},
		{
			name: "handoff path",
			build: func(t *testing.T, h *oidcHarness) error {
				cookie(t, h)
				_, err := h.assemble(nil, httpsec.WithOIDCSessions(h.sessions), httpsec.WithOIDCHandoffPath("/x"))

				return err
			},
			assert: refused("WithOIDCHandoffPath"),
		},
		{
			name: "handoff rate limit",
			build: func(t *testing.T, h *oidcHarness) error {
				cookie(t, h)
				_, err := h.assemble(nil, httpsec.WithOIDCSessions(h.sessions),
					httpsec.WithOIDCHandoffRateLimit(5, time.Minute))

				return err
			},
			assert: refused("WithOIDCHandoffRateLimit"),
		},
		{
			name: "token generator",
			build: func(t *testing.T, h *oidcHarness) error {
				cookie(t, h)
				_, err := h.assemble(nil, httpsec.WithOIDCSessions(h.sessions), httpsec.WithOIDCTokens(h.tokens))

				return err
			},
			assert: refused("WithOIDCTokens"),
		},
		{
			name: "role sync",
			build: func(t *testing.T, h *oidcHarness) error {
				cookie(t, h)
				h.manager = newTestOIDCManager(t,
					oidc.WithBrokerRoleClaim(testOIDCProvider, "realm_access.roles"),
					oidc.WithBrokerRoleSync(testOIDCProvider, true))
				_, err := h.assemble(nil, httpsec.WithOIDCSessions(h.sessions))

				return err
			},
			assert: refused("role sync"),
		},
		{
			name: "no handoff manager builds",
			build: func(t *testing.T, h *oidcHarness) error {
				cookie(t, h)
				_, err := h.assemble(nil, httpsec.WithOIDCSessions(h.sessions))

				return err
			},
			assert: func(t *testing.T, err error) {
				t.Helper()
				require.NoError(t, err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.build(t, newOIDCHarness(t)))
		})
	}
}
