package httpsec_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
)

// TestSessionCookie_Attributes pins the session cookie's attributes at their
// defaults and under each override, and that every override breaking a
// guarantee (a name a browser would not store, a Domain on a __Host- name or
// without a __Secure- one, SameSite None or Default) and every wiring mistake
// fails in New.
func TestSessionCookie_Attributes(t *testing.T) {
	t.Parallel()

	const id = "c2Vzc2lvbi1pZGVudGlmaWVyLW9mLTMyLWJ5dGVzLW9r"

	type testCase struct {
		name string

		// deps replaces the fixture's dependencies when not nil.
		deps func(f *cookieFixture) httpsec.SessionBearerDeps
		opts []httpsec.SessionCookieOption

		// twice enables the cookie session a second time.
		twice bool

		assert func(t *testing.T, chain *httpsec.Chain, err error)
	}

	// sets is a chain whose cookie, set with id and no Max-Age, is want.
	sets := func(want string) func(t *testing.T, chain *httpsec.Chain, err error) {
		return func(t *testing.T, chain *httpsec.Chain, err error) {
			t.Helper()
			require.NoError(t, err)

			c := httpsec.SessionCookieOf(chain, id, 0)
			require.NotNil(t, c)
			assert.Equal(t, want, c.String())
			assert.True(t, c.Secure, "Secure has no override")
			assert.True(t, c.HttpOnly, "HttpOnly has no override")
			assert.Equal(t, "/", c.Path)
		}
	}

	misconfigured := func(names ...string) func(t *testing.T, chain *httpsec.Chain, err error) {
		return func(t *testing.T, chain *httpsec.Chain, err error) {
			t.Helper()
			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.Nil(t, chain)

			for _, n := range names {
				assert.ErrorContains(t, err, n)
			}
		}
	}

	var typedNilLimiter *ratelimit.MemoryLimiter

	cases := []testCase{
		{
			name:   "default: __Host- name, Path=/, Secure, HttpOnly, SameSite=Lax, no Domain or Max-Age",
			assert: sets("__Host-scrty-session=" + id + "; Path=/; HttpOnly; Secure; SameSite=Lax"),
		},
		{
			name: "the default name expires with the attributes it is set with",
			assert: func(t *testing.T, chain *httpsec.Chain, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, "__Host-scrty-session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax",
					httpsec.SessionCookieOf(chain, "", -1).String())
			},
		},
		{
			name:   "strict same-site",
			opts:   []httpsec.SessionCookieOption{httpsec.WithSessionCookieSameSite(http.SameSiteStrictMode)},
			assert: sets("__Host-scrty-session=" + id + "; Path=/; HttpOnly; Secure; SameSite=Strict"),
		},
		{
			name: "a __Secure- name shared across a domain",
			opts: []httpsec.SessionCookieOption{
				httpsec.WithSessionCookieName("__Secure-scrty-session"),
				httpsec.WithSessionCookieDomain("example.com"),
			},
			assert: sets("__Secure-scrty-session=" + id + "; Path=/; Domain=example.com; HttpOnly; Secure; SameSite=Lax"),
		},
		{
			name: "the domain may come before the name",
			opts: []httpsec.SessionCookieOption{
				httpsec.WithSessionCookieDomain("example.com"),
				httpsec.WithSessionCookieName("__Secure-scrty-session"),
			},
			assert: sets("__Secure-scrty-session=" + id + "; Path=/; Domain=example.com; HttpOnly; Secure; SameSite=Lax"),
		},
		{
			name: "an unprefixed name shared across a domain is still refused for its missing __Secure- prefix",
			opts: []httpsec.SessionCookieOption{
				httpsec.WithSessionCookieName("sid"),
				httpsec.WithSessionCookieDomain("example.com"),
			},
			assert: misconfigured("sid", "__Secure-"),
		},
		{
			name:   "an unprefixed name with no domain is refused: it names the __Host- rule and the alternative",
			opts:   []httpsec.SessionCookieOption{httpsec.WithSessionCookieName("sid")},
			assert: misconfigured("sid", "__Host-", "__Secure-", "WithSessionCookieDomain"),
		},
		{
			name:   "a __Secure- name with no domain is refused",
			opts:   []httpsec.SessionCookieOption{httpsec.WithSessionCookieName("__Secure-sid")},
			assert: misconfigured("__Secure-sid", "__Host-"),
		},
		{
			name:   "a custom __Host- name with no domain builds",
			opts:   []httpsec.SessionCookieOption{httpsec.WithSessionCookieName("__Host-app")},
			assert: sets("__Host-app=" + id + "; Path=/; HttpOnly; Secure; SameSite=Lax"),
		},
		{
			name:   "a __Host- name in lower case is refused, naming the canonical spelling",
			opts:   []httpsec.SessionCookieOption{httpsec.WithSessionCookieName("__host-app")},
			assert: misconfigured("__host-app", "__Host-"),
		},
		{
			name:   "a __Host- name in upper case is refused, naming the canonical spelling",
			opts:   []httpsec.SessionCookieOption{httpsec.WithSessionCookieName("__HOST-app")},
			assert: misconfigured("__HOST-app", "__Host-"),
		},
		{
			name: "a __Secure- name in lower case shared across a domain is refused, naming the canonical spelling",
			opts: []httpsec.SessionCookieOption{
				httpsec.WithSessionCookieName("__secure-app"),
				httpsec.WithSessionCookieDomain("example.com"),
			},
			assert: misconfigured("__secure-app", "__Secure-"),
		},
		{
			name:   "an empty name is refused",
			opts:   []httpsec.SessionCookieOption{httpsec.WithSessionCookieName("")},
			assert: misconfigured("WithSessionCookieName"),
		},
		{
			name:   "a name with ';' is refused",
			opts:   []httpsec.SessionCookieOption{httpsec.WithSessionCookieName("a;b")},
			assert: misconfigured("a;b"),
		},
		{
			name:   "a name with a space is refused",
			opts:   []httpsec.SessionCookieOption{httpsec.WithSessionCookieName("a b")},
			assert: misconfigured("a b"),
		},
		{
			name:   "a name with '=' is refused",
			opts:   []httpsec.SessionCookieOption{httpsec.WithSessionCookieName("a=b")},
			assert: misconfigured("a=b"),
		},
		{
			name:   "a domain on the default __Host- name is refused",
			opts:   []httpsec.SessionCookieOption{httpsec.WithSessionCookieDomain("example.com")},
			assert: misconfigured("WithSessionCookieDomain", "__Host-"),
		},
		{
			name: "a domain on a __Host- name in another case is refused",
			opts: []httpsec.SessionCookieOption{
				httpsec.WithSessionCookieName("__host-sid"),
				httpsec.WithSessionCookieDomain("example.com"),
			},
			assert: misconfigured("WithSessionCookieDomain", "__Host-"),
		},
		{
			name: "a domain on an unprefixed name is refused",
			opts: []httpsec.SessionCookieOption{
				httpsec.WithSessionCookieName("sid"),
				httpsec.WithSessionCookieDomain("example.com"),
			},
			assert: misconfigured("WithSessionCookieDomain", "__Secure-"),
		},
		{
			name:   "an empty domain is refused",
			opts:   []httpsec.SessionCookieOption{httpsec.WithSessionCookieDomain("")},
			assert: misconfigured("WithSessionCookieDomain"),
		},
		{
			name: "a domain net/http would drop is refused",
			opts: []httpsec.SessionCookieOption{
				httpsec.WithSessionCookieName("__Secure-sid"),
				httpsec.WithSessionCookieDomain("exa mple.com"),
			},
			assert: misconfigured("exa mple.com"),
		},
		{
			name:   "same-site None is refused",
			opts:   []httpsec.SessionCookieOption{httpsec.WithSessionCookieSameSite(http.SameSiteNoneMode)},
			assert: misconfigured("WithSessionCookieSameSite"),
		},
		{
			name:   "same-site Default is refused",
			opts:   []httpsec.SessionCookieOption{httpsec.WithSessionCookieSameSite(http.SameSiteDefaultMode)},
			assert: misconfigured("WithSessionCookieSameSite"),
		},
		{
			name:   "a nil option is refused",
			opts:   []httpsec.SessionCookieOption{nil},
			assert: misconfigured("EnableSessionCookie"),
		},
		{
			name:   "a nil limiter is refused",
			opts:   []httpsec.SessionCookieOption{httpsec.WithSessionCookieLimiter(nil)},
			assert: misconfigured("WithSessionCookieLimiter"),
		},
		{
			name:   "a typed-nil limiter is refused",
			opts:   []httpsec.SessionCookieOption{httpsec.WithSessionCookieLimiter(typedNilLimiter)},
			assert: misconfigured("WithSessionCookieLimiter"),
		},
		{
			name: "a missing session manager is refused",
			deps: func(f *cookieFixture) httpsec.SessionBearerDeps {
				return httpsec.SessionBearerDeps{Users: f.users}
			},
			assert: misconfigured("EnableSessionCookie", "session manager"),
		},
		{
			name: "a typed-nil session manager is refused",
			deps: func(f *cookieFixture) httpsec.SessionBearerDeps {
				var none *session.Sessions

				return httpsec.SessionBearerDeps{Sessions: none, Users: f.users}
			},
			assert: misconfigured("EnableSessionCookie", "session manager"),
		},
		{
			name: "a missing user loader is refused",
			deps: func(f *cookieFixture) httpsec.SessionBearerDeps {
				return httpsec.SessionBearerDeps{Sessions: f.sessions}
			},
			assert: misconfigured("EnableSessionCookie", "user loader"),
		},
		{
			name:   "enabling it twice is refused",
			twice:  true,
			assert: misconfigured("EnableSessionCookie"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newCookieFixture(t)

			deps := f.deps()
			if tc.deps != nil {
				deps = tc.deps(f)
			}

			opts := []httpsec.Option{
				httpsec.EnableCSRFProtection(),
				httpsec.EnableSessionCookie(deps, tc.opts...),
			}
			if tc.twice {
				opts = append(opts, httpsec.EnableSessionCookie(deps))
			}

			chain, err := httpsec.New(opts...)
			tc.assert(t, chain, err)
		})
	}
}

// TestSessionCookie_ExclusiveWithBearers pins that a chain delivers either
// cookies or tokens: the cookie session with either bearer mode, in either
// order, is a configuration error naming both, and the cookie session needs
// CSRF protection or its explicit opt-out.
func TestSessionCookie_ExclusiveWithBearers(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		options func(f *cookieFixture) []httpsec.Option
		assert  func(t *testing.T, chain *httpsec.Chain, err error)
	}

	refusedNaming := func(names ...string) func(t *testing.T, chain *httpsec.Chain, err error) {
		return func(t *testing.T, chain *httpsec.Chain, err error) {
			t.Helper()
			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.Nil(t, chain)

			for _, n := range names {
				assert.ErrorContains(t, err, n)
			}
		}
	}

	cookie := func(f *cookieFixture) httpsec.Option { return httpsec.EnableSessionCookie(f.deps()) }
	sessionBearer := func(f *cookieFixture) httpsec.Option { return httpsec.EnableSessionBearer(f.deps()) }
	tokenBearer := func(f *cookieFixture) httpsec.Option {
		return httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
			Verifier: exampleTokens{}, Sessions: f.sessions, Users: f.users,
		})
	}

	cases := []testCase{
		{
			name: "the cookie session and the session bearer",
			options: func(f *cookieFixture) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableCSRFProtection(), cookie(f), sessionBearer(f)}
			},
			assert: refusedNaming("EnableSessionCookie", "EnableSessionBearer"),
		},
		{
			name: "the session bearer and the cookie session",
			options: func(f *cookieFixture) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableCSRFProtection(), sessionBearer(f), cookie(f)}
			},
			assert: refusedNaming("EnableSessionCookie", "EnableSessionBearer"),
		},
		{
			name: "the cookie session and the signed-token bearer",
			options: func(f *cookieFixture) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableCSRFProtection(), cookie(f), tokenBearer(f)}
			},
			assert: refusedNaming("EnableSessionCookie", "EnableBearerToken"),
		},
		{
			name: "the signed-token bearer and the cookie session",
			options: func(f *cookieFixture) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableCSRFProtection(), tokenBearer(f), cookie(f)}
			},
			assert: refusedNaming("EnableSessionCookie", "EnableBearerToken"),
		},
		{
			name: "the cookie session without CSRF protection",
			options: func(f *cookieFixture) []httpsec.Option {
				return []httpsec.Option{cookie(f)}
			},
			assert: refusedNaming("EnableCSRFProtection", "WithoutCSRFProtection"),
		},
		{
			name: "the cookie session with the explicit opt-out builds",
			options: func(f *cookieFixture) []httpsec.Option {
				return []httpsec.Option{httpsec.WithoutCSRFProtection(), cookie(f)}
			},
			assert: func(t *testing.T, chain *httpsec.Chain, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.NotNil(t, chain)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newCookieFixture(t)
			chain, err := httpsec.New(tc.options(f)...)
			tc.assert(t, chain, err)
		})
	}
}
