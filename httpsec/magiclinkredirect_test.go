package httpsec_test

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
)

// TestMagicLinkRedirects pins which redirect targets survive a link request.
// A target that reaches the browser is a target an attacker would like to
// choose, so a submitted one is used only when it exactly equals something the
// consumer configured, and everything else becomes "/".
//
// The target is read back off the emailed link, which is where it actually
// matters, rather than out of the interceptor's own state.
func TestMagicLinkRedirects(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		allowed   []string
		origins   []string
		submitted string
		assert    func(t *testing.T, resolved string, buildErr error)
	}

	configErrorNaming := func(entry string) func(*testing.T, string, error) {
		return func(t *testing.T, _ string, buildErr error) {
			t.Helper()

			require.Error(t, buildErr)
			require.ErrorIs(t, buildErr, httpsec.ErrConfig)
			assert.Contains(t, buildErr.Error(), entry, "the error names the entry at fault")
		}
	}

	resolvesTo := func(want string) func(*testing.T, string, error) {
		return func(t *testing.T, resolved string, buildErr error) {
			t.Helper()

			require.NoError(t, buildErr)
			assert.Equal(t, want, resolved)
		}
	}

	cases := []testCase{
		{name: "the default allowlist is empty", submitted: "/dashboard", assert: resolvesTo("/")},
		{
			name:      "an exact host-relative match",
			allowed:   []string{"/dashboard"},
			submitted: "/dashboard",
			assert:    resolvesTo("/dashboard"),
		},
		{
			name:      "a prefix is not a match",
			allowed:   []string{"/dashboard"},
			submitted: "/dashboard.evil.example",
			assert:    resolvesTo("/"),
		},
		{
			name:      "protocol-relative is not a match",
			allowed:   []string{"/dashboard"},
			submitted: "//evil.example/dashboard",
			assert:    resolvesTo("/"),
		},
		{
			name:      "a trailing slash is not a match",
			allowed:   []string{"/dashboard"},
			submitted: "/dashboard/",
			assert:    resolvesTo("/"),
		},
		{name: "an empty entry", allowed: []string{""}, assert: configErrorNaming("WithAllowedRedirects")},
		{
			name:    "an undeclared absolute entry",
			allowed: []string{"https://partner.example.com/landing"},
			assert:  configErrorNaming("https://partner.example.com/landing"),
		},
		{
			name:    "an entry with userinfo",
			allowed: []string{"https://a@partner.example.com/landing"},
			origins: []string{"https://partner.example.com"},
			assert:  configErrorNaming("https://a@partner.example.com/landing"),
		},
		{
			name:    "a cleartext declared origin",
			origins: []string{"http://partner.example.com"},
			assert:  configErrorNaming("http://partner.example.com"),
		},
		{
			name:    "a declared origin with a path",
			origins: []string{"https://partner.example.com/app"},
			assert:  configErrorNaming("https://partner.example.com/app"),
		},
		{
			name:      "a declared origin makes its entry usable",
			allowed:   []string{"https://partner.example.com/landing"},
			origins:   []string{"https://partner.example.com"},
			submitted: "https://partner.example.com/landing",
			assert:    resolvesTo("https://partner.example.com/landing"),
		},
		{
			name:      "a loopback origin over http is accepted",
			allowed:   []string{"http://localhost:3000/landing"},
			origins:   []string{"http://localhost:3000"},
			submitted: "http://localhost:3000/landing",
			assert:    resolvesTo("http://localhost:3000/landing"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newMagicLinkHarness(t)
			h.linkOpts = []httpsec.MagicLinkOption{
				httpsec.WithAllowedRedirects(tc.allowed...),
				httpsec.WithAllowedOrigins(tc.origins...),
			}

			c, err := h.build()
			if err != nil {
				tc.assert(t, "", err)

				return
			}

			out := serve(t, c, postValues(t.Context(), httpsec.DefaultMagicLinkRequestPath,
				magicLinkSource, url.Values{"email": {magicLinkKnown}, "next": {tc.submitted}}))
			require.NoError(t, out.err)

			tc.assert(t, h.sender.lastNext(t), nil)
		})
	}
}
