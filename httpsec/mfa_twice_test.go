package httpsec_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/mfa"
)

// TestChain_MFAEnabledTwice pins that one chain has one MFA configuration: a
// second EnableMFA is a configuration error naming the option, whatever
// prefixes or methods it carries, because the challenge a refused request
// carries lists the methods of one configuration only, so a method given to
// the other would never be offered.
func TestChain_MFAEnabledTwice(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		options func(t *testing.T, h *mfaHarness) []httpsec.Option
		assert  func(t *testing.T, c *httpsec.Chain, err error)
	}

	enable := func(h *mfaHarness, methods []mfa.Method, opts ...httpsec.MFAOption) httpsec.Option {
		return httpsec.EnableMFA(methods, append([]httpsec.MFAOption{
			httpsec.WithMFAVerifyLimiter(h.limiter), httpsec.WithMFATokens(h.tokens),
		}, opts...)...)
	}

	cases := []testCase{
		{
			name: "MFA enabled twice",
			options: func(t *testing.T, h *mfaHarness) []httpsec.Option {
				h.channel(factor.AuthenticatorApp)
				email := emailCodeMethod(t)

				return []httpsec.Option{
					enable(h, []mfa.Method{h.method}),
					enable(h, []mfa.Method{email},
						httpsec.WithMFAVerifyPrefix("/x/verify"),
						httpsec.WithMFABeginPrefix("/x/begin")),
				}
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Contains(t, err.Error(), "EnableMFA", "the error names the option given twice")
				assert.Contains(t, err.Error(), "given twice")
				assert.Nil(t, c)
			},
		},
		{
			name: "MFA enabled once with every method",
			options: func(t *testing.T, h *mfaHarness) []httpsec.Option {
				h.channel(factor.AuthenticatorApp)

				return []httpsec.Option{enable(h, []mfa.Method{h.method, emailCodeMethod(t)})}
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

			h := newMFAHarness(t)
			sessions := httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: h.sessions})

			c, err := httpsec.New(append(tc.options(t, h), sessions)...)
			tc.assert(t, c, err)
		})
	}
}
