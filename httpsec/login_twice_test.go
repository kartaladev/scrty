package httpsec_test

import (
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
)

// TestChain_LoginEnabledTwice pins that one chain has one form login and one
// Basic authentication: a second call is a configuration error naming the
// option, even when the second call is shaped differently (another path, its
// own limiter), because a chain that honoured both would run two guards over
// one endpoint set.
func TestChain_LoginEnabledTwice(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		options func(t *testing.T, h *loginGuardHarness) []httpsec.Option
		assert  func(t *testing.T, c *httpsec.Chain, err error)
	}

	formLogin := func(h *loginGuardHarness, opts ...httpsec.LoginOption) httpsec.Option {
		return httpsec.EnableFormLogin(httpsec.FormLoginDeps{
			Authenticator: h.authn, Sessions: h.sessions, Tokens: h.tokens, Attempts: h.attempts,
		}, opts...)
	}
	basicAuth := func(h *loginGuardHarness, opts ...httpsec.BasicAuthOption) httpsec.Option {
		return httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{
			Authenticator: h.authn, Attempts: h.attempts,
		}, opts...)
	}

	refusedTwice := func(option string) func(t *testing.T, c *httpsec.Chain, err error) {
		return func(t *testing.T, c *httpsec.Chain, err error) {
			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.Contains(t, err.Error(), option, "the error names the option given twice")
			assert.Contains(t, err.Error(), "given twice")
			assert.Nil(t, c)
		}
	}

	cases := []testCase{
		{
			name: "form login twice",
			options: func(t *testing.T, h *loginGuardHarness) []httpsec.Option {
				return []httpsec.Option{
					formLogin(h, httpsec.WithLoginLimiter(memLimiter(t, 10, time.Minute))),
					formLogin(h,
						httpsec.WithLoginRequestPath("/admin/login"),
						httpsec.WithLoginLimiter(memLimiter(t, 5, time.Hour))),
				}
			},
			assert: refusedTwice("EnableFormLogin"),
		},
		{
			name: "Basic twice",
			options: func(t *testing.T, h *loginGuardHarness) []httpsec.Option {
				return []httpsec.Option{
					basicAuth(h, httpsec.WithBasicAuthLimiter(memLimiter(t, 10, time.Minute))),
					basicAuth(h,
						httpsec.WithBasicAuthRealm("admin"),
						httpsec.WithBasicAuthLimiter(memLimiter(t, 5, time.Hour))),
				}
			},
			assert: refusedTwice("EnableBasicAuth"),
		},
		{
			name: "each once",
			options: func(_ *testing.T, h *loginGuardHarness) []httpsec.Option {
				return []httpsec.Option{formLogin(h), basicAuth(h)}
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.NoError(t, err)
				assert.NotNil(t, c)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newLoginGuardHarness(t)

			c, err := httpsec.New(append([]httpsec.Option{
				httpsec.WithLogger(slog.New(slog.DiscardHandler)),
			}, tc.options(t, h)...)...)
			tc.assert(t, c, err)
		})
	}
}
