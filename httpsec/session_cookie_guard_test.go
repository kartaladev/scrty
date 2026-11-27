package httpsec_test

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/policy/lockout"
)

// guardAPIPath is a route the resource server covers.
const guardAPIPath = "/api/orders"

// countingSource is a resource-server source that accepts rsToken as u-2's
// and counts every token it is asked to verify.
func countingSource(calls *atomic.Int64) *httpsec.StubSource {
	return &httpsec.StubSource{
		Name: "provider", Provider: true, Unbound: true,
		Verify: func(_ context.Context, raw string) (*identity.Principal, map[string]string, error) {
			calls.Add(1)

			if raw != rsToken {
				return nil, nil, httpsec.ErrInvalidToken
			}

			return &identity.Principal{ID: "u-2", Kind: identity.KindUser}, nil, nil
		},
	}
}

// TestSessionCookie_BothCredentialsRefused pins that a cookie chain refuses,
// with the authentication-required error, a request carrying the session
// cookie and an Authorization header of any scheme or value, before Basic
// authentication, the resource server or the cookie session reads either: no
// session is loaded, no token verified, no password checked, the source is
// not charged and the cookie is not expired, since neither was judged. A
// request carrying only the header is judged by the resource server as
// before, one carrying only the cookie by the cookie session, and a chain
// without the cookie session has no such guard.
func TestSessionCookie_BothCredentialsRefused(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// cookieChain builds the chain with the cookie session; without it
		// the chain has the resource server and Basic authentication alone.
		cookieChain bool

		path          string
		cookie        func(f *cookieFixture) string
		authorization []string

		assert func(t *testing.T, f *cookieFixture, out served, verified int64)
	}

	live := func(f *cookieFixture) string { return named(f.signIn.ID) }

	refusedUnread := func(t *testing.T, f *cookieFixture, out served, verified int64) {
		t.Helper()
		require.ErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)
		assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
		assert.False(t, out.handlerRan)
		assert.Zero(t, f.store.loads.Load(), "no session is loaded")
		assert.Zero(t, verified, "the resource server verified nothing")
		assert.Zero(t, f.reloads.Load(), "no user is loaded")
		assert.Empty(t, f.limiter.recorded(), "the source is not charged")
		assert.Empty(t, out.rec.Header().Values("Set-Cookie"), "the cookie is not expired: it was not judged")
	}

	cases := []testCase{
		{
			name: "the cookie and a bearer token on a resource-server path", cookieChain: true,
			path: guardAPIPath, cookie: live, authorization: []string{"Bearer " + rsToken},
			assert: refusedUnread,
		},
		{
			name: "the cookie and Basic credentials", cookieChain: true,
			path: guardAPIPath, cookie: live, authorization: []string{"Basic dXNlcjpwdw=="},
			assert: refusedUnread,
		},
		{
			name: "the cookie and an empty Authorization header", cookieChain: true,
			path: guardAPIPath, cookie: live, authorization: []string{""},
			assert: refusedUnread,
		},
		{
			name: "the cookie and a scheme nothing on the chain reads", cookieChain: true,
			path: "/orders", cookie: live, authorization: []string{"ApiKey k-1"},
			assert: refusedUnread,
		},
		{
			name: "the cookie twice and a bearer token", cookieChain: true,
			path: guardAPIPath,
			cookie: func(f *cookieFixture) string {
				return named(f.signIn.ID) + "; " + named(f.signIn.ID)
			},
			authorization: []string{"Bearer " + rsToken},
			assert:        refusedUnread,
		},
		{
			name: "a well-formed but unknown cookie and a bearer token", cookieChain: true,
			path: guardAPIPath, cookie: func(*cookieFixture) string { return named(unknownReference(1)) },
			authorization: []string{"Bearer " + rsToken},
			assert:        refusedUnread,
		},
		{
			name: "a bearer token alone is judged by the resource server", cookieChain: true,
			path: guardAPIPath, authorization: []string{"Bearer " + rsToken},
			assert: func(t *testing.T, f *cookieFixture, out served, verified int64) {
				t.Helper()
				require.NoError(t, out.err)
				require.True(t, out.handlerRan)
				assert.Equal(t, int64(1), verified)
				assert.Zero(t, f.store.loads.Load())

				p, ok := identity.PrincipalFromContext(out.handled.Context())
				require.True(t, ok)
				assert.Equal(t, identity.UserID("u-2"), p.ID)
			},
		},
		{
			name: "the cookie alone is judged by the cookie session", cookieChain: true,
			path: guardAPIPath, cookie: live,
			assert: func(t *testing.T, f *cookieFixture, out served, verified int64) {
				t.Helper()
				require.NoError(t, out.err)
				require.True(t, out.handlerRan)
				assert.Zero(t, verified)
				assert.Equal(t, int64(1), f.store.loads.Load())

				s, ok := httpsec.SessionFromContext(out.handled.Context())
				require.True(t, ok)
				assert.Equal(t, f.signIn.ID, s.ID)
			},
		},
		{
			// A name padded with a Unicode space is another cookie, so the guard
			// sees no session cookie beside the header, and refuses nothing.
			name: "a padded twin of the cookie name and a bearer token is not refused", cookieChain: true,
			path: guardAPIPath,
			cookie: func(f *cookieFixture) string {
				return httpsec.DefaultSessionCookieName + "\u2000=" + f.signIn.ID
			},
			authorization: []string{"Bearer " + rsToken},
			assert: func(t *testing.T, f *cookieFixture, out served, verified int64) {
				t.Helper()
				require.NoError(t, out.err)
				require.True(t, out.handlerRan, "the resource server judged the token")
				assert.Equal(t, int64(1), verified)
				assert.Zero(t, f.store.loads.Load(), "the padded cookie was never looked up")
			},
		},
		{
			name: "a chain without the cookie session has no guard",
			path: guardAPIPath, cookie: live, authorization: []string{"Bearer " + rsToken},
			assert: func(t *testing.T, f *cookieFixture, out served, verified int64) {
				t.Helper()
				require.NoError(t, out.err)
				require.True(t, out.handlerRan, "the resource server accepted the token")
				assert.Equal(t, int64(1), verified)
				assert.Zero(t, f.store.loads.Load())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newCookieFixture(t)

			var verified atomic.Int64

			// Basic authentication is wired with an authenticator no case may
			// reach: a call fails the case.
			authn := NewMockAuthenticator(gomock.NewController(t))

			opts := []httpsec.Option{
				httpsec.EnableResourceServer("urn:orders",
					httpsec.WithPathPrefix("/api/"), httpsec.WithStubSource(countingSource(&verified))),
				httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{
					Authenticator: authn, Attempts: must.Must(lockout.NewMemoryAttemptStore()),
				}),
			}

			if tc.cookieChain {
				opts = f.chainOptions(opts...)
			} else {
				opts = append(opts, httpsec.WithClock(f.clk))
			}

			chain, err := httpsec.New(opts...)
			require.NoError(t, err)

			var cookie string
			if tc.cookie != nil {
				cookie = tc.cookie(f)
			}

			req := sessionCookieRequest(t.Context(), http.MethodGet, cookie, nil)
			req.URL.Path = tc.path

			for _, a := range tc.authorization {
				req.Header.Add("Authorization", a)
			}

			out := f.serve(t, chain, req, nil)

			tc.assert(t, f, out, verified.Load())
		})
	}
}

// TestSessionCookie_RefusedBesideAnotherCaller pins that the cookie session
// never judges a cookie on a request another authenticator has already
// published a caller for, through a credential the guard cannot see (here a
// consumer's API key in its own header): the request is refused with the
// authentication-required error before the cookie is looked up, whether the
// cookie is live or unknown, so neither credential silently wins and a bad
// cookie is never ignored. Neither is the source charged nor the cookie
// expired, since the cookie was not judged. The other credential alone is
// served as before.
func TestSessionCookie_RefusedBesideAnotherCaller(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		cookie func(f *cookieFixture) string
		apiKey bool
		assert func(t *testing.T, f *cookieFixture, out served)
	}

	refusedUnread := func(t *testing.T, f *cookieFixture, out served) {
		t.Helper()
		require.ErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)
		assert.False(t, out.handlerRan)
		assert.Zero(t, f.store.loads.Load(), "the cookie is not looked up")
		assert.Empty(t, f.limiter.recorded(), "the source is not charged")
		assert.Empty(t, out.rec.Header().Values("Set-Cookie"), "the cookie is not expired")
	}

	cases := []testCase{
		{
			name:   "a live cookie beside an API key",
			cookie: func(f *cookieFixture) string { return named(f.signIn.ID) },
			apiKey: true,
			assert: refusedUnread,
		},
		{
			name:   "an unknown cookie beside an API key",
			cookie: func(*cookieFixture) string { return named(unknownReference(2)) },
			apiKey: true,
			assert: refusedUnread,
		},
		{
			name:   "a malformed cookie beside an API key",
			cookie: func(*cookieFixture) string { return named("not-an-identifier") },
			apiKey: true,
			assert: refusedUnread,
		},
		{
			name:   "an API key alone",
			apiKey: true,
			assert: func(t *testing.T, f *cookieFixture, out served) {
				t.Helper()
				require.NoError(t, out.err)
				require.True(t, out.handlerRan)
				assert.Zero(t, f.store.loads.Load())

				p, ok := identity.PrincipalFromContext(out.handled.Context())
				require.True(t, ok)
				assert.Equal(t, identity.UserID("machine-1"), p.ID)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newCookieFixture(t)

			// The consumer's own authenticator, ahead of the cookie session, for
			// a key in a header of its own.
			apiKeys := httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
				if ex.Request.Header("X-Api-Key") == "k-1" {
					ex.Authentication = &authenticate.Authentication{
						Principal: &identity.Principal{ID: "machine-1", Kind: identity.KindUser},
						Time:      time.Now(),
					}
					ex.SetContext(httpsec.WithCaller(ex.Context(), ex.Authentication))
				}

				return next(ex)
			})

			chain, err := httpsec.New(f.chainOptions(
				httpsec.RegisterInterceptor(apiKeys, httpsec.OrderAPIKey))...)
			require.NoError(t, err)

			var cookie string
			if tc.cookie != nil {
				cookie = tc.cookie(f)
			}

			headers := map[string]string{}
			if tc.apiKey {
				headers["X-Api-Key"] = "k-1"
			}

			out := f.serve(t, chain, sessionCookieRequest(t.Context(), http.MethodGet, cookie, headers), nil)

			tc.assert(t, f, out)
		})
	}
}
