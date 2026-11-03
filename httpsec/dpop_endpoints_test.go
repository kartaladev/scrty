package httpsec_test

import (
	"context"
	"crypto/elliptic"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
)

// chargeCounter is a rate-limiter factory whose every limiter is never
// exceeded and counts, across all of them, the failures charged and not
// refunded.
type chargeCounter struct {
	factory *MockLimiterFactory
	net     atomic.Int64
}

func newChargeCounter(t *testing.T) *chargeCounter {
	t.Helper()

	ctrl := gomock.NewController(t)
	c := &chargeCounter{factory: NewMockLimiterFactory(ctrl)}

	c.factory.EXPECT().NewLimiter(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(string, int, time.Duration) (ratelimit.Limiter, error) {
			l := NewMockLimiter(ctrl)
			l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).AnyTimes().Return(false, nil)
			l.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).AnyTimes().
				DoAndReturn(func(context.Context, string) error {
					c.net.Add(1)

					return nil
				})
			l.EXPECT().Charge(gomock.Any(), gomock.Any()).AnyTimes().
				DoAndReturn(func(context.Context, string) (ratelimit.Receipt, bool, error) {
					c.net.Add(1)

					return ratelimit.Receipt{}, false, nil
				})
			l.EXPECT().Refund(gomock.Any(), gomock.Any()).AnyTimes().
				DoAndReturn(func(context.Context, ratelimit.Receipt) error {
					c.net.Add(-1)

					return nil
				})

			return l, nil
		})

	return c
}

// TestDPoP_ProofCharges pins what a bad proof at an issuing endpoint costs
// the source it came from: magic link and the OIDC handoff charge it as a
// redemption carrying no usable link or code, and passkey login and recovery
// charge nothing, as for a malformed request.
func TestDPoP_ProofCharges(t *testing.T) {
	t.Parallel()

	key := newDPoPKey(t, elliptic.P256())

	type testCase struct {
		name  string
		build func(t *testing.T, d httpsec.DPoP, extra ...httpsec.Option) issuingFixture
		// charged is how many failures the bad proof charges its source.
		charged int64
	}

	cases := []testCase{
		{name: "magic link", build: magicLinkEndpoint, charged: 1},
		{name: "OIDC handoff", build: oidcHandoffEndpoint, charged: 1},
		{name: "passkey login", build: passkeyLoginEndpoint, charged: 0},
		{name: "recovery", build: recoveryEndpoint, charged: 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			charges := newChargeCounter(t)
			f := tc.build(t, httpsec.DPoP{PublicURL: dpopPublicURL}, httpsec.WithRateLimiterFactory(charges.factory))
			send := f.prepare(t, "")

			before := charges.net.Load()
			out := send(t, key.brokenProver("j-bad"))

			require.ErrorIs(t, out.err, httpsec.ErrInvalidDPoPProof)
			assert.Equal(t, tc.charged, charges.net.Load()-before)
		})
	}
}

// recoveryFinishFixture is a held recovery's finish, on a chain with DPoP
// on: prepare holds a recovery, completed without a proof, waits out the
// hold, and returns the finish request for its completion token.
func recoveryFinishFixture(t *testing.T) issuingFixture {
	t.Helper()

	return recoveryFinishFixtureWith(t)
}

// recoveryFinishFixtureWith is recoveryFinishFixture on a chain that also
// takes extra.
func recoveryFinishFixtureWith(t *testing.T, extra ...httpsec.Option) issuingFixture {
	t.Helper()

	h := newRecoveryHarness(t)
	gen := issuingGenerator(t)

	h.noFormLogin = true
	h.proofs = []recovery.ProofKind{recovery.ProofSaved, recovery.ProofIssued}
	h.withHold()
	h.recOpts = append(h.recOpts, httpsec.WithRecoveryTokens(gen))
	h.chainOpts = append(h.chainOpts,
		httpsec.EnableBearerToken(httpsec.BearerTokenDeps{Verifier: gen, Sessions: h.sessions, Users: h.users}),
		httpsec.EnableDPoP(httpsec.DPoP{PublicURL: dpopPublicURL}))
	h.chainOpts = append(h.chainOpts, extra...)
	h.build(t)

	f := issuingFixture{chain: h.chain, sessions: h.sessions, gen: gen, user: e2eUser}
	f.prepare = func(t *testing.T, _ string) func(*testing.T, prover) served {
		t.Helper()

		held := h.hold(t)
		h.clock.Advance(recoveryHoldDelay + time.Minute)

		return func(t *testing.T, proof prover) served {
			t.Helper()

			req := postValues(t.Context(), httpsec.DefaultRecoveryFinishPath, e2eSource,
				url.Values{httpsec.RecoveryCompletionTokenParam: {held.completion}})

			return serve(t, f.chain, withProof(req, proof(t, httpsec.DefaultRecoveryFinishPath, "")))
		}
	}

	return f
}

// TestDPoP_RecoveryFinish pins that a held recovery's finish is an issuing
// endpoint: a valid proof binds the recovered sign-in and its token, and a
// bad proof is refused with the hold left unspent.
func TestDPoP_RecoveryFinish(t *testing.T) {
	t.Parallel()

	key := newDPoPKey(t, elliptic.P256())

	type testCase struct {
		name   string
		run    func(t *testing.T, f *issuingFixture, send func(*testing.T, prover) served) served
		assert func(t *testing.T, f *issuingFixture, out served)
	}

	boundTo := func(t *testing.T, f *issuingFixture, out served) {
		t.Helper()

		jkt, s := f.issued(t, out)
		assert.Equal(t, key.jkt, jkt, "the token carries cnf.jkt")
		assert.Equal(t, session.KeyBinding{JKT: key.jkt}, s.KeyBinding, "the recovered sign-in is bound")
	}

	cases := []testCase{
		{
			name: "a valid proof binds the recovered sign-in and its token",
			run: func(t *testing.T, _ *issuingFixture, send func(*testing.T, prover) served) served {
				return send(t, key.validProver("j-1"))
			},
			assert: boundTo,
		},
		{
			name: "a bad proof leaves the hold unspent",
			run: func(t *testing.T, f *issuingFixture, send func(*testing.T, prover) served) served {
				bad := send(t, key.brokenProver("j-bad"))
				require.ErrorIs(t, bad.err, httpsec.ErrInvalidDPoPProof)
				assert.Zero(t, f.activeSessions(t), "nothing was recovered")

				return send(t, key.validProver("j-2"))
			},
			assert: boundTo,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := recoveryFinishFixture(t)
			send := f.prepare(t, "")
			tc.assert(t, &f, tc.run(t, &f, send))
		})
	}
}

// TestDPoP_SessionReferenceIssuing pins that, in session-reference mode, a
// sign-in with a proof binds the stored session alone: the credential is the
// reference, no signed token, and its type is DPoP.
//
// Standalone: one chain in session-reference mode, unlike the signed issuing
// fixtures.
func TestDPoP_SessionReferenceIssuing(t *testing.T) {
	t.Parallel()

	key := newDPoPKey(t, elliptic.P256())
	b := newIssuingBase(t)

	chain := must.Must(httpsec.New(
		httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: b.sessions, Users: b.users}),
		httpsec.EnableFormLogin(httpsec.FormLoginDeps{
			Authenticator: b.authn, Sessions: b.sessions, Attempts: must.Must(lockout.NewMemoryAttemptStore()),
		}),
		httpsec.EnableDPoP(httpsec.DPoP{PublicURL: dpopPublicURL}),
	))

	req := postValues(t.Context(), httpsec.DefaultLoginPath, e2eSource, url.Values{
		httpsec.DefaultLoginUsernameParam: {e2eAddress},
		httpsec.DefaultLoginPasswordParam: {e2ePassword},
	})
	out := serve(t, chain, withProof(req, key.validProver("j-1")(t, httpsec.DefaultLoginPath, "")))
	require.NoError(t, out.err)

	var doc struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &doc))

	assert.Equal(t, string(httpsec.TokenTypeDPoP), doc.TokenType)
	assert.NotEqual(t, 2, strings.Count(doc.AccessToken, "."), "a session reference, not a signed token")

	s, err := b.sessions.Load(t.Context(), doc.AccessToken)
	require.NoError(t, err, "the credential is the stored session's reference")
	assert.Equal(t, session.KeyBinding{JKT: key.jkt}, s.KeyBinding)
}

// TestDPoP_SecondFactorCarriesBinding pins that a second factor keeps the
// binding the sign-in was created with: a valid proof on an unbound sign-in
// issues an unbound token, and never binds the session afterwards.
//
// Standalone: one endpoint, one case; the binding of a bound sign-in is
// TestDPoP_Binding's row.
func TestDPoP_SecondFactorCarriesBinding(t *testing.T) {
	t.Parallel()

	key := newDPoPKey(t, elliptic.P256())
	f := mfaVerifyEndpoint(t, httpsec.DPoP{PublicURL: dpopPublicURL})

	out := f.prepare(t, "")(t, key.validProver("j-1"))

	jkt, s := f.issued(t, out)
	assert.Empty(t, jkt, "the token carries no cnf")
	assert.True(t, s.KeyBinding.IsZero(), "the sign-in stays unbound")

	var doc struct {
		TokenType string `json:"token_type"`
	}
	require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &doc))
	assert.Equal(t, string(httpsec.TokenTypeBearer), doc.TokenType)
}

// TestDPoP_SignInWritesEveryCreateOption pins that a sign-in carrying a DPoP
// binding, sign-in metadata and a CSRF token stores all three in its one
// creating write.
//
// Standalone: one chain with all three features on.
func TestDPoP_SignInWritesEveryCreateOption(t *testing.T) {
	t.Parallel()

	key := newDPoPKey(t, elliptic.P256())
	sessions := must.Must(session.New(session.WithSessionMetadata()))
	b := newIssuingBaseOver(t, sessions, sessions)

	f := b.fixture(t, httpsec.DPoP{PublicURL: dpopPublicURL},
		httpsec.EnableFormLogin(httpsec.FormLoginDeps{
			Authenticator: b.authn, Sessions: b.sessions, Tokens: b.gen,
			Attempts: must.Must(lockout.NewMemoryAttemptStore()),
		}),
		httpsec.EnableCSRFProtection(),
		httpsec.RegisterInterceptor(httpsec.NewTestCookieAuthenticator(b.sessions, "sid"), httpsec.OrderBearerToken),
	)

	req := postValues(t.Context(), httpsec.DefaultLoginPath, e2eSource, url.Values{
		httpsec.DefaultLoginUsernameParam: {e2eAddress},
		httpsec.DefaultLoginPasswordParam: {e2ePassword},
	})
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("User-Agent", "Mozilla/5.0 (test)")

	out := serve(t, f.chain, withProof(req, key.validProver("j-1")(t, httpsec.DefaultLoginPath, "")))
	require.Equal(t, http.StatusOK, out.rec.Code)

	_, s := f.issued(t, out)
	assert.Equal(t, session.KeyBinding{JKT: key.jkt}, s.KeyBinding, "the binding")
	assert.Equal(t, e2eSource, s.ClientIP, "the client address")
	assert.Equal(t, "Mozilla/5.0 (test)", s.UserAgent, "the user agent")
	assert.NotEmpty(t, s.CSRFToken, "the CSRF token")
}
