package httpsec_test

import (
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/policy"
)

// TestOIDCRedeemMFAExemptionRemoved pins the consumer's override of the
// default OIDC exemption: once their classification makes a federated login
// non-exempt, the MFA policies judge it like any other login, and the chain
// insists that the challenge they can now raise is enforced.
func TestOIDCRedeemMFAExemptionRemoved(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// withMFA wires EnableMFA beside the policies.
		withMFA bool

		assert func(t *testing.T, h *oidcHarness, enrolled *atomic.Bool)
	}

	cases := []testCase{
		{
			name:    "with EnableMFA wired, a required-but-unenrolled user is refused with enrolment required and keeps the code",
			withMFA: true,
			assert: func(t *testing.T, h *oidcHarness, enrolled *atomic.Bool) {
				c := h.chain(t)
				code := h.issueHandoff(t, "")

				out := serve(t, c, handoffRequest(t.Context(), oidcTestSource, code))
				require.ErrorIs(t, out.err, policy.ErrMFAEnrollmentRequired)
				assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(out.err))
				assert.Zero(t, h.activeSessions(t), "no session is established")

				// Once the user has enrolled, the same code redeems — into a
				// challenge, since the login is no longer exempt.
				enrolled.Store(true)

				again := serve(t, c, handoffRequest(t.Context(), oidcAnotherSource, code))

				var challenge *httpsec.ChallengeError
				require.ErrorAs(t, again.err, &challenge, "the code was kept for a later redemption")
				assert.Equal(t, policy.ChallengeMFA, challenge.Kind)
				assert.Equal(t, []httpsec.MFAMethod{{Name: "totp", Channel: factor.AuthenticatorApp}},
					challenge.Methods, "the handoff's challenge names the method the user can answer it with")
				assert.Equal(t, 1, h.activeSessions(t))
			},
		},
		{
			name: "without EnableMFA, the classification fails chain assembly",
			assert: func(t *testing.T, h *oidcHarness, _ *atomic.Bool) {
				c, err := h.assemble(h.handoffs,
					httpsec.WithOIDCTokens(h.tokens), httpsec.WithOIDCSessions(h.sessions))
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Nil(t, c)
				assert.Contains(t, strings.ToLower(err.Error()), "enablemfa",
					"the error names what is missing")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newOIDCHarness(t)
			h.issueTokens()

			var enrolled atomic.Bool

			h.chainOpts = []httpsec.Option{
				httpsec.WithPolicyEngine(oidcMFAEngine(t, false, enrolled.Load)),
			}
			if tc.withMFA {
				h.chainOpts = append(h.chainOpts, enableMFAFor(t))
			}

			tc.assert(t, h, &enrolled)
		})
	}
}
