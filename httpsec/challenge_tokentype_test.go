package httpsec_test

import (
	"crypto/elliptic"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/session"
)

// TestChallengeError_TokenType pins that a challenge carrying a token names
// how that token is presented, as the login success document would, and that
// a challenge carrying none names no type. Each case reaches its challenge
// through a different endpoint, so its setup lives in its challenge closure.
func TestChallengeError_TokenType(t *testing.T) {
	t.Parallel()

	key := newDPoPKey(t, elliptic.P256())
	d := httpsec.DPoP{PublicURL: dpopPublicURL}

	// challengedLogin is a form login, on a chain with the signed bearer and
	// DPoP, that a post-authentication policy challenges for a second factor.
	challengedLogin := func(proof prover) func(t *testing.T) served {
		return func(t *testing.T) served {
			t.Helper()

			b := newIssuingBase(t)
			f := b.fixture(t, d,
				httpsec.EnableFormLogin(httpsec.FormLoginDeps{
					Authenticator: b.authn, Sessions: b.sessions, Tokens: b.gen,
					Attempts: must.Must(lockout.NewMemoryAttemptStore()),
				}),
				httpsec.WithPolicyEngine(challengingIn(t, policy.PostAuthentication, policy.ChallengeMFA)),
				httpsec.EnableGateForTest(policy.ChallengeMFA),
			)

			req := postValues(t.Context(), httpsec.DefaultLoginPath, e2eSource, url.Values{
				httpsec.DefaultLoginUsernameParam: {e2eAddress},
				httpsec.DefaultLoginPasswordParam: {e2ePassword},
			})

			return serve(t, f.chain, withProof(req, proof(t, httpsec.DefaultLoginPath, "")))
		}
	}

	type testCase struct {
		name      string
		challenge func(t *testing.T) served
		assert    func(t *testing.T, ch *httpsec.ChallengeError)
	}

	cases := []testCase{
		{
			name:      "a bearer-chain password login challenged for a second factor names Bearer",
			challenge: challengedLogin(noProof),
			assert: func(t *testing.T, ch *httpsec.ChallengeError) {
				assert.Equal(t, policy.ChallengeMFA, ch.Kind)
				assert.NotEmpty(t, ch.Token)
				assert.Equal(t, httpsec.TokenTypeBearer, ch.TokenType)
			},
		},
		{
			name:      "a DPoP-proofed login challenged for a second factor names DPoP",
			challenge: challengedLogin(key.validProver("j-challenged")),
			assert: func(t *testing.T, ch *httpsec.ChallengeError) {
				assert.Equal(t, policy.ChallengeMFA, ch.Kind)
				assert.NotEmpty(t, ch.Token)
				assert.Equal(t, httpsec.TokenTypeDPoP, ch.TokenType)
			},
		},
		{
			name: "an MFA verification raising a password change names the rotated token's type",
			challenge: func(t *testing.T) served {
				t.Helper()

				totpLookup := NewMockMFAMethodLookup(gomock.NewController(t))
				totpLookup.EXPECT().Name().Return("totp").AnyTimes()
				totpLookup.EXPECT().Channel().Return(factor.AuthenticatorApp).AnyTimes()
				totpLookup.EXPECT().Enrolled(gomock.Any(), e2eUser).Return(true, nil).AnyTimes()

				second, err := policy.NewMFA([]policy.MFAMethodLookup{totpLookup})
				require.NoError(t, err)

				age, err := policy.NewPasswordAge(policy.WithUnknownPasswordAge(policy.UnknownAgeChallenge))
				require.NoError(t, err)

				f := mfaVerifyOver(t, newIssuingBase(t), d,
					httpsec.WithPolicyEngine(engineOf(t, second, age)),
					httpsec.EnableGateForTest(policy.ChallengePasswordChange),
				)

				return f.prepare(t, key.jkt)(t, key.validProver("j-rotated"))
			},
			assert: func(t *testing.T, ch *httpsec.ChallengeError) {
				assert.Equal(t, policy.ChallengePasswordChange, ch.Kind)
				assert.NotEmpty(t, ch.Token)
				require.NotNil(t, ch.Session)
				assert.Equal(t, key.jkt, ch.Session.KeyBinding.JKT, "the rotated session keeps its binding")
				assert.Equal(t, httpsec.TokenTypeDPoP, ch.TokenType)
			},
		},
		{
			name: "the password-change gate's challenge carries no token and names no type",
			challenge: func(t *testing.T) served {
				t.Helper()

				b := newIssuingBase(t)
				f := b.fixture(t, d, httpsec.EnablePasswordChangeGate(b.sessions))
				tok := b.signedIn(t, "", func(s *session.Session) { s.PasswordChangePending = true })

				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/app", nil)

				return serve(t, f.chain, presenting(t, req, tok, "", noProof))
			},
			assert: func(t *testing.T, ch *httpsec.ChallengeError) {
				assert.Equal(t, policy.ChallengePasswordChange, ch.Kind)
				assert.Empty(t, ch.Token)
				assert.Empty(t, ch.TokenType)
			},
		},
		{
			name: "the second-factor gate's challenge carries no token and names no type",
			challenge: func(t *testing.T) served {
				t.Helper()

				b := newIssuingBase(t)
				f := mfaVerifyOver(t, b, d)
				tok := b.signedIn(t, "", func(s *session.Session) { s.MFA = session.MFAPending })

				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/app", nil)

				return serve(t, f.chain, presenting(t, req, tok, "", noProof))
			},
			assert: func(t *testing.T, ch *httpsec.ChallengeError) {
				assert.Equal(t, policy.ChallengeMFA, ch.Kind)
				assert.Empty(t, ch.Token)
				assert.Empty(t, ch.TokenType)
			},
		},
		{
			name: "a consumer-built challenge with a token and no type keeps the type empty",
			challenge: func(*testing.T) served {
				return served{err: &httpsec.ChallengeError{Kind: policy.ChallengeMFA, Token: "consumer-token"}}
			},
			assert: func(t *testing.T, ch *httpsec.ChallengeError) {
				assert.Equal(t, "consumer-token", ch.Token)
				assert.Empty(t, ch.TokenType, "the type is never guessed")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			out := tc.challenge(t)

			var ch *httpsec.ChallengeError
			require.ErrorAs(t, out.err, &ch)
			tc.assert(t, ch)
		})
	}
}
