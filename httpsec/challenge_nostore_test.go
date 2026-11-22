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

// upstreamCacheControl is the cache policy a consumer's own middleware puts on
// every response before the chain runs.
const upstreamCacheControl = "public, max-age=300"

// upstreamCachePolicy is the consumer's middleware ahead of everything the
// chain does: it marks the response cacheable before any interceptor runs, as
// an outer net/http, gin or fiber middleware would.
func upstreamCachePolicy() httpsec.Option {
	return httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		ex.Writer.SetHeader("Cache-Control", upstreamCacheControl)

		return next(ex)
	}), httpsec.Order(1))
}

// TestChallengeToken_NoStore pins that a challenge carrying a credential is
// never cacheable: the chain marks the response no-store, replacing whatever
// cache policy an upstream middleware set, where it raises the challenge. A
// challenge carrying no credential leaves the consumer's policy alone. Each
// case reaches its challenge through a different endpoint, so its setup lives
// in its challenge closure.
func TestChallengeToken_NoStore(t *testing.T) {
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
				upstreamCachePolicy(),
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

	// noStore asserts the challenge carries a token and the response is
	// exactly no-store: replaced, not appended to.
	noStore := func(t *testing.T, ch *httpsec.ChallengeError, header http.Header) {
		t.Helper()

		assert.NotEmpty(t, ch.Token)
		assert.Equal(t, []string{"no-store"}, header.Values("Cache-Control"))
	}

	// untouched asserts the challenge carries no token and the upstream policy
	// is left as the consumer set it.
	untouched := func(t *testing.T, ch *httpsec.ChallengeError, header http.Header) {
		t.Helper()

		assert.Empty(t, ch.Token)
		assert.Equal(t, []string{upstreamCacheControl}, header.Values("Cache-Control"))
	}

	type testCase struct {
		name      string
		challenge func(t *testing.T) served
		assert    func(t *testing.T, ch *httpsec.ChallengeError, header http.Header)
	}

	cases := []testCase{
		{
			name:      "a bearer-chain password login challenged for a second factor is no-store",
			challenge: challengedLogin(noProof),
			assert:    noStore,
		},
		{
			name:      "a DPoP-bound password login challenged for a second factor is no-store",
			challenge: challengedLogin(key.validProver("j-nostore-login")),
			assert:    noStore,
		},
		{
			name: "an MFA verification raising a further token-bearing challenge is no-store",
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
					upstreamCachePolicy(),
					httpsec.WithPolicyEngine(engineOf(t, second, age)),
					httpsec.EnableGateForTest(policy.ChallengePasswordChange),
				)

				return f.prepare(t, key.jkt)(t, key.validProver("j-nostore-rotated"))
			},
			assert: noStore,
		},
		{
			name: "the password-change gate's challenge carries no token and keeps the upstream policy",
			challenge: func(t *testing.T) served {
				t.Helper()

				b := newIssuingBase(t)
				f := b.fixture(t, d, upstreamCachePolicy(), httpsec.EnablePasswordChangeGate(b.sessions))
				tok := b.signedIn(t, "", func(s *session.Session) { s.PasswordChangePending = true })

				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/app", nil)

				return serve(t, f.chain, presenting(t, req, tok, "", noProof))
			},
			assert: untouched,
		},
		{
			name: "the second-factor gate's challenge carries no token and keeps the upstream policy",
			challenge: func(t *testing.T) served {
				t.Helper()

				b := newIssuingBase(t)
				f := mfaVerifyOver(t, b, d, upstreamCachePolicy())
				tok := b.signedIn(t, "", func(s *session.Session) { s.MFA = session.MFAPending })

				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/app", nil)

				return serve(t, f.chain, presenting(t, req, tok, "", noProof))
			},
			assert: untouched,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			out := tc.challenge(t)

			var ch *httpsec.ChallengeError
			require.ErrorAs(t, out.err, &ch)
			tc.assert(t, ch, out.rec.Header())
		})
	}
}
