package fibersec_test

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/httpsec/fibersec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/session"
)

// TestExchange_CookieHeaderSurvivesForwardedRemoval pins that the Cookie lines
// an interceptor reads are the lines the client sent, whatever the adapter or
// fiber did to the request before: fasthttp parses the cookies of a request
// the first time it lists the headers or reads a cookie, and then rebuilds the
// header from the parse, dropping quotes and values it cannot keep and merging
// the lines. A duplicate or quoted session cookie must reach the chain as sent,
// to be refused, not as the one clean pair the parse leaves.
func TestExchange_CookieHeaderSurvivesForwardedRemoval(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		lines  []string
		before func(c fiber.Ctx)
		assert func(t *testing.T, got []string)
	}

	removeForwarded := func(c fiber.Ctx) {
		fibersec.NewRequest(c).(interface{ DelHeaders(func(string) bool) }).DelHeaders(
			func(name string) bool { return name == "X-Forwarded-For" })
	}

	sent := func(lines ...string) func(*testing.T, []string) {
		return func(t *testing.T, got []string) { assert.Equal(t, lines, got) }
	}

	const (
		duplicate = `a=1; __Host-scrty-session=ID; __Host-scrty-session=x\y; q=QQ`
		quoted    = `__Host-scrty-session="ID"`
	)

	cases := []testCase{
		{name: "lines nobody touched", lines: []string{duplicate, "b=2"}, assert: sent(duplicate, "b=2")},
		{
			name: "a duplicate after the forwarded headers are removed", lines: []string{duplicate, "b=2"},
			before: removeForwarded, assert: sent(duplicate, "b=2"),
		},
		{
			name: "a quoted value after the forwarded headers are removed", lines: []string{quoted},
			before: removeForwarded, assert: sent(quoted),
		},
		{
			name: "a duplicate after fiber read one cookie", lines: []string{duplicate},
			before: func(c fiber.Ctx) { _, _ = fibersec.NewRequest(c).Cookie("a") }, assert: sent(duplicate),
		},
		{
			name: "no cookie after the forwarded headers are removed", before: removeForwarded,
			assert: func(t *testing.T, got []string) { assert.Empty(t, got) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// The lines are read inside the request: fiber recycles its
			// context once the handler returns.
			var got []string

			app := fiber.New()
			app.Get("/*", func(c fiber.Ctx) error {
				if tc.before != nil {
					tc.before(c)
				}

				got = fibersec.NewRequest(c).HeaderValues("Cookie")

				return c.SendStatus(http.StatusOK)
			})

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://app.example.com/x", nil)
			req.Header.Set("X-Forwarded-For", "203.0.113.9")

			for _, line := range tc.lines {
				req.Header.Add("Cookie", line)
			}

			res, err := app.Test(req)
			require.NoError(t, err)
			require.NoError(t, res.Body.Close())

			tc.assert(t, got)
		})
	}
}

// TestSessionCookie_TrustedProxiesKeepRawCookies pins that a duplicated or a
// quoted session cookie is refused, with the cookie expired, the same with and
// without EnableTrustedProxies: the chain removes the forwarded headers it
// consumed, and that must not clean up the cookie it is about to judge.
func TestSessionCookie_TrustedProxiesKeepRawCookies(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		proxies bool
		cookie  func(id string) string
		assert  func(t *testing.T, status int, setCookie []string)
	}

	duplicate := func(id string) string { return "__Host-scrty-session=" + id + `; __Host-scrty-session=x\y` }
	quoted := func(id string) string { return `__Host-scrty-session="` + id + `"` }

	refused := func(t *testing.T, status int, setCookie []string) {
		t.Helper()

		assert.Equal(t, http.StatusUnauthorized, status, "a malformed presentation is refused on every adapter")
		require.Len(t, setCookie, 1)
		assert.Contains(t, strings.ToLower(setCookie[0]), "__host-scrty-session=;")
		assert.Contains(t, strings.ToLower(setCookie[0]), "max-age=0")
	}

	cases := []testCase{
		{
			name:   "a clean cookie authenticates",
			cookie: func(id string) string { return "__Host-scrty-session=" + id },
			assert: func(t *testing.T, status int, setCookie []string) {
				t.Helper()
				assert.Equal(t, http.StatusOK, status)
				assert.Empty(t, setCookie)
			},
		},
		{name: "a duplicate without trusted proxies", cookie: duplicate, assert: refused},
		{name: "a duplicate with trusted proxies", proxies: true, cookie: duplicate, assert: refused},
		{name: "a quoted value without trusted proxies", cookie: quoted, assert: refused},
		{name: "a quoted value with trusted proxies", proxies: true, cookie: quoted, assert: refused},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sessions, err := session.New()
			require.NoError(t, err)

			live, err := sessions.Create(t.Context(), "u-1",
				session.WithFirstFactor(factor.Password), session.WithCSRFToken())
			require.NoError(t, err)

			users := NewMockUserLoader(gomock.NewController(t))
			users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).AnyTimes().Return(&identity.Details{
				ID: "u-1", Username: "ada", Active: true, PasswordChangedAt: time.Now().Add(-time.Hour),
			}, nil)

			opts := []httpsec.Option{
				httpsec.EnableCSRFProtection(),
				httpsec.EnableSessionCookie(httpsec.SessionBearerDeps{Sessions: sessions, Users: users}),
			}
			if tc.proxies {
				opts = append(opts, httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
					Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")},
					Headers:  httpsec.XForwarded(httpsec.ForwardedFor),
				}))
			}

			chain, err := httpsec.New(opts...)
			require.NoError(t, err)

			app := fiber.New(fiber.Config{ErrorHandler: fibersec.ErrorHandler})
			app.Use(fibersec.Middleware(chain))
			app.Get("/*", func(c fiber.Ctx) error { return c.SendStatus(http.StatusOK) })

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://app.example.com/x", nil)
			req.Header.Set("Cookie", tc.cookie(live.ID))
			req.Header.Set("Sec-Fetch-Site", "same-origin")

			res := serveFrom(t, app, req, "198.51.100.7:51000")

			tc.assert(t, res.status, res.header.Values("Set-Cookie"))
		})
	}
}
