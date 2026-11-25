package httpsec_test

import (
	"context"
	"crypto/elliptic"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/session"
)

// TestGuards_RecencyAccessToken pins the recency guard for a caller a resource server authenticated
// (design 16): it is judged by its token's authentication time, a token without one is stale, and
// a stale one is answered 401 with exactly one challenge naming insufficient_user_authentication
// and max_age, the window in whole seconds, under the scheme its token came under. A stale session
// is still answered 403 with no body and no challenge.
func TestGuards_RecencyAccessToken(t *testing.T) {
	t.Parallel()

	key := newDPoPKey(t, elliptic.P256())

	type testCase struct {
		name string

		// authTime is the token's authentication time; session publishes a session that
		// authenticated at sessionAt instead of presenting a token.
		authTime  time.Time
		session   bool
		sessionAt time.Time

		// bound presents the token bound to key under DPoP, on a chain with DPoP optional.
		bound bool

		// window is the route's; zero is the guards' default.
		window time.Duration

		assert func(t *testing.T, rec *httptest.ResponseRecorder, routeRan bool)
	}

	refused := func(want string) func(t *testing.T, rec *httptest.ResponseRecorder, routeRan bool) {
		return func(t *testing.T, rec *httptest.ResponseRecorder, routeRan bool) {
			t.Helper()
			assert.Equal(t, http.StatusUnauthorized, rec.Code)
			assert.Equal(t, []string{want}, rec.Header().Values("WWW-Authenticate"), "exactly one challenge")
			assert.Empty(t, rec.Body.String())
			assert.False(t, routeRan)
		}
	}

	passes := func(t *testing.T, rec *httptest.ResponseRecorder, routeRan bool) {
		t.Helper()
		assert.Equal(t, http.StatusNoContent, rec.Code)
		assert.True(t, routeRan)
	}

	cases := []testCase{
		{
			name:     "a fresh access token passes",
			authTime: dpopNow.Add(-10 * time.Minute),
			assert:   passes,
		},
		{
			name:     "a stale access token is answered 401 with the guards' window as max_age",
			authTime: dpopNow.Add(-20 * time.Minute),
			assert:   refused(`Bearer error="insufficient_user_authentication", max_age=900`),
		},
		{
			name:     "a route's 5-minute window is max_age=300",
			authTime: dpopNow.Add(-20 * time.Minute),
			window:   5 * time.Minute,
			assert:   refused(`Bearer error="insufficient_user_authentication", max_age=300`),
		},
		{
			name:   "an access token without an authentication time is stale",
			assert: refused(`Bearer error="insufficient_user_authentication", max_age=900`),
		},
		{
			name:     "a stale token under DPoP is challenged under DPoP",
			authTime: dpopNow.Add(-20 * time.Minute),
			bound:    true,
			assert:   refused(`DPoP error="insufficient_user_authentication", max_age=900, algs="ES256"`),
		},
		{
			name:      "a stale session is still 403 with no body and no challenge",
			session:   true,
			sessionAt: dpopNow.Add(-16 * time.Minute),
			assert: func(t *testing.T, rec *httptest.ResponseRecorder, routeRan bool) {
				t.Helper()
				assert.Equal(t, http.StatusForbidden, rec.Code)
				assert.Empty(t, rec.Header().Values("WWW-Authenticate"))
				assert.Empty(t, rec.Body.String())
				assert.False(t, routeRan)
			},
		},
		{
			name:      "a fresh session passes",
			session:   true,
			sessionAt: dpopNow.Add(-5 * time.Minute),
			assert:    passes,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(dpopNow)

			src := &httpsec.StubSource{
				Name: "provider", Provider: true, Unbound: !tc.bound, AuthTime: tc.authTime,
				Verify: func(context.Context, string) (*identity.Principal, map[string]string, error) {
					var cnf map[string]string
					if tc.bound {
						cnf = map[string]string{"jkt": key.jkt}
					}

					return &identity.Principal{ID: "u-1", Kind: identity.KindUser}, cnf, nil
				},
			}

			opts := []httpsec.Option{
				httpsec.WithClock(clk),
				httpsec.EnableResourceServer("urn:orders", httpsec.WithPathPrefix("/api/"),
					httpsec.WithStubSource(src)),
			}
			if tc.bound {
				opts = append(opts, httpsec.EnableDPoP(httpsec.DPoP{PublicURL: dpopPublicURL}))
			}

			if tc.session {
				s := &session.Session{ID: "s-1", UserID: "u-1", AuthenticatedAt: tc.sessionAt}
				opts = append(opts, httpsec.RegisterInterceptor(httpsec.InterceptorFunc(
					func(ex *httpsec.Exchange, next httpsec.Next) error {
						ex.Authentication = &authenticate.Authentication{
							Principal: &identity.Principal{ID: "u-1", Kind: identity.KindUser},
						}
						ex.Session = s
						ex.SetContext(httpsec.WithSession(httpsec.WithCaller(ex.Context(), ex.Authentication), s))

						return next(ex)
					}), httpsec.OrderBearerToken))
			}

			c, err := httpsec.New(opts...)
			require.NoError(t, err)

			guards, err := httpsec.NewGuards(permittingAuthorizer(t), httpsec.WithGuardClock(clk))
			require.NoError(t, err)

			guard := guards.RequireRecentAuthentication()
			if tc.window > 0 {
				guard = guards.RequireAuthenticationWithin(tc.window)
			}

			var routeRan bool

			h := c.Middleware()(guard(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				routeRan = true
				w.WriteHeader(http.StatusNoContent)
			})))

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com/api/orders", nil)

			switch {
			case tc.session:
			case tc.bound:
				req.Header.Set("Authorization", "DPoP "+rsToken)
				req.Header.Set("DPoP", key.validProof("j-recency").with(map[string]any{"ath": tokenHash(rsToken)}).sign(t))
			default:
				req.Header.Set("Authorization", "Bearer "+rsToken)
			}

			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			tc.assert(t, rec, routeRan)
		})
	}
}

// TestInsufficientUserAuthenticationError pins the recency refusal of an access-token caller: it is
// both the insufficient-user-authentication refusal and the reauthentication-required one, carries
// its window, maps to 401, and names nothing but the window.
func TestInsufficientUserAuthenticationError(t *testing.T) {
	t.Parallel()

	var err error = &httpsec.InsufficientUserAuthenticationError{Window: 5 * time.Minute}

	require.ErrorIs(t, err, httpsec.ErrInsufficientUserAuthentication)
	require.ErrorIs(t, err, httpsec.ErrReauthenticationRequired)
	assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(err))

	var got *httpsec.InsufficientUserAuthenticationError
	require.ErrorAs(t, err, &got)
	assert.Equal(t, 5*time.Minute, got.Window)
	assert.Equal(t, "httpsec: insufficient user authentication: sign-in required within 5m0s", err.Error())
}
