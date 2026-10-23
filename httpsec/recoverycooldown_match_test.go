package httpsec_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
)

// TestRecoveryCooldown_Matching pins how broadly the cool-down matches a marked
// route: a request a lenient router could send to it (another letter case, one
// trailing slash, HEAD for a marked GET) is refused as the marked route is,
// while a different route is not, and the exemptions other gates make stay
// exact.
func TestRecoveryCooldown_Matching(t *testing.T) {
	t.Parallel()

	marked := []httpsec.Route{
		{Method: http.MethodPost, Path: "/account/email"},
		{Method: http.MethodGet, Path: "/account/export"},
	}

	type testCase struct {
		name   string
		routes []httpsec.Route

		// mfaPending leaves the session owing a second factor, on a chain
		// whose MFA gate enforces it.
		mfaPending bool

		method, path string
		assert       func(t *testing.T, s *session.Session, out served)
	}

	held := func(t *testing.T, _ *session.Session, out served) {
		t.Helper()

		require.ErrorIs(t, out.err, recovery.ErrCooldown, "the cool-down did not hold the request")
		assert.False(t, out.handlerRan)
	}

	reached := func(t *testing.T, _ *session.Session, out served) {
		t.Helper()

		require.NoError(t, out.err)
		assert.True(t, out.handlerRan)
	}

	cases := []testCase{
		{name: "the marked route itself is held", method: http.MethodPost, path: "/account/email", assert: held},
		{name: "the marked path in another letter case is held", method: http.MethodPost, path: "/Account/Email", assert: held},
		{name: "the marked path with a trailing slash is held", method: http.MethodPost, path: "/account/email/", assert: held},
		{
			name: "the marked path in another case with a trailing slash is held", method: http.MethodPost,
			path: "/ACCOUNT/EMAIL/", assert: held,
		},
		{name: "the method in lower case is held", method: "post", path: "/account/email", assert: held},
		{name: "HEAD on a marked GET is held", method: http.MethodHead, path: "/account/export", assert: held},
		{name: "a path beneath the marked one is not held", method: http.MethodPost, path: "/account/email/x", assert: reached},
		{name: "two trailing slashes are held", method: http.MethodPost, path: "/account/email//", assert: held},
		{name: "many trailing slashes in another case are held", method: http.MethodPost, path: "/Account/Email///", assert: held},
		{name: "GET on a marked POST is not held", method: http.MethodGet, path: "/account/email", assert: reached},
		{name: "HEAD on a marked POST is not held", method: http.MethodHead, path: "/account/email", assert: reached},
		{
			name:   "a route marked with a trailing slash and upper case holds its plain form",
			routes: []httpsec.Route{{Method: "post", Path: "/Account/Email/"}},
			method: http.MethodPost, path: "/account/email", assert: held,
		},
		{
			name:   "root route marked matches only root",
			routes: []httpsec.Route{{Method: http.MethodGet, Path: "/"}},
			method: http.MethodGet, path: "/", assert: held,
		},
		{
			name:   "root route marked matches a run of slashes",
			routes: []httpsec.Route{{Method: http.MethodGet, Path: "/"}},
			method: http.MethodGet, path: "//", assert: held,
		},
		{
			name:   "root route marked does not match another path",
			routes: []httpsec.Route{{Method: http.MethodGet, Path: "/"}},
			method: http.MethodGet, path: "/orders", assert: reached,
		},
		{
			name:   "root route marked does not match a path ending in a slash",
			routes: []httpsec.Route{{Method: http.MethodGet, Path: "/"}},
			method: http.MethodGet, path: "/orders/", assert: reached,
		},
		{
			name:       "the MFA gate exempts its verify path exactly",
			mfaPending: true,
			method:     http.MethodPost, path: httpsec.DefaultMFAVerifyPrefix + "/totp",
			assert: func(t *testing.T, _ *session.Session, out served) {
				t.Helper()

				var ch *httpsec.ChallengeError
				assert.NotErrorAs(t, out.err, &ch, "the verify endpoint is reached, not the gate's challenge")
				assert.False(t, out.handlerRan)
			},
		},
		{
			name:       "the MFA gate does not exempt its verify path in another letter case",
			mfaPending: true,
			method:     http.MethodPost, path: "/MFA/verify/totp",
			assert: func(t *testing.T, s *session.Session, out served) {
				t.Helper()

				var ch *httpsec.ChallengeError
				require.ErrorAs(t, out.err, &ch, "the MFA gate let a session owing a factor through")
				assert.Equal(t, policy.ChallengeMFA, ch.Kind)
				assert.Equal(t, s.ID, ch.Session.ID)
				assert.False(t, out.handlerRan)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newRecoveryHarness(t)

			routes := tc.routes
			if routes == nil {
				routes = marked
			}

			opts := []httpsec.Option{
				httpsec.EnableBearerToken(httpsec.BearerTokenDeps{Verifier: h.tokens, Sessions: h.sessions, Users: h.users}),
				httpsec.EnableRecoveryCooldown(completedRecoveryAgo(t, 3*time.Hour), recoveryCooldown, routes...),
			}
			if tc.mfaPending {
				opts = append(opts, httpsec.EnableMFA([]mfa.Method{h.totp}, httpsec.WithMFATokens(h.tokens)))
			}

			chain, err := httpsec.New(opts...)
			require.NoError(t, err)

			s, err := h.sessions.Create(t.Context(), e2eUser, session.WithFirstFactor(factor.Password))
			require.NoError(t, err)

			if tc.mfaPending {
				s.MFA = session.MFAPending
				require.NoError(t, h.sessions.Save(t.Context(), s))
			}

			req := httptest.NewRequestWithContext(t.Context(), tc.method, tc.path, nil)
			req.RemoteAddr = e2eSource + ":51000"
			req.Header.Set("Authorization", "Bearer "+mfaTokenFor(s.ID))

			tc.assert(t, s, serve(t, chain, req))
		})
	}
}
