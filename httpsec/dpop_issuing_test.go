package httpsec_test

import (
	"context"
	"crypto/elliptic"
	"encoding/json"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
	"github.com/kartaladev/scrty/token/signingkey"
)

// prover makes the DPoP header of one issuing request for path: credential is
// the access credential the request presents under the DPoP scheme, which the
// proof's ath hashes, and empty when it presents none that way. It returns ""
// for a request that carries no proof.
type prover func(t *testing.T, path, credential string) string

// noProof is a request that carries no proof.
func noProof(*testing.T, string, string) string { return "" }

// issuingProofParts is k's proof for a POST to path, issued now, carrying jti,
// and ath over credential unless it is empty.
func (k dpopKey) issuingProofParts(path, jti, credential string) proofParts {
	parts := k.validProof(jti).with(map[string]any{
		"htm": http.MethodPost,
		"htu": "http://example.com" + path,
		"iat": time.Now().Unix(),
	})
	if credential != "" {
		parts = parts.with(map[string]any{"ath": tokenHash(credential)})
	}

	return parts
}

// validProver is a valid proof by k carrying jti.
func (k dpopKey) validProver(jti string) prover {
	return func(t *testing.T, path, credential string) string {
		t.Helper()

		return k.issuingProofParts(path, jti, credential).sign(t)
	}
}

// brokenProver is a proof naming k's public key, carrying jti, signed by
// another key: its signature does not verify.
func (k dpopKey) brokenProver(jti string) prover {
	return func(t *testing.T, path, credential string) string {
		t.Helper()

		parts := k.issuingProofParts(path, jti, credential)
		parts.signKey = newDPoPKey(t, elliptic.P256()).priv

		return parts.sign(t)
	}
}

// wrongURLProver is a valid proof by k for another path.
func (k dpopKey) wrongURLProver(jti string) prover {
	return func(t *testing.T, path, credential string) string {
		t.Helper()

		return k.issuingProofParts(path+"/elsewhere", jti, credential).sign(t)
	}
}

// issuingFixture is one issuing endpoint on a chain of its own, with DPoP on
// and a generator that can bind.
type issuingFixture struct {
	chain    *httpsec.Chain
	sessions *session.Sessions
	gen      *token.JWTGenerator
	user     identity.UserID

	// lookups counts the account lookups the chain made, and is nil where
	// the fixture's user store cannot count them.
	lookups func() int64

	// attempts is form login's failure store, nil on every other endpoint.
	attempts *lockout.MemoryAttemptStore

	// prepare readies one issuing request: its single-use material (a link,
	// a code, a challenge) and, for an endpoint a session reaches, that
	// session, bound to bound unless it is empty. The request it returns may
	// be sent more than once, so a test can show a refusal left its material
	// unspent.
	prepare func(t *testing.T, bound string) func(t *testing.T, proof prover) served
}

// issued reads the credential a successful issuing response carries: the
// cnf.jkt of its token, and the stored session it names.
func (f *issuingFixture) issued(t *testing.T, out served) (string, *session.Session) {
	t.Helper()

	require.NoError(t, out.err)

	var doc struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &doc))
	require.NotEmpty(t, doc.AccessToken, "the response carries a credential")

	claims, err := f.gen.Verify(t.Context(), doc.AccessToken)
	require.NoError(t, err)

	s, err := f.sessions.Load(t.Context(), claims.ID())
	require.NoError(t, err)

	return claims.Confirmation().JKT, s
}

// activeSessions counts the user's live sessions.
func (f *issuingFixture) activeSessions(t *testing.T) int {
	t.Helper()

	n, err := f.sessions.CountActiveByUser(t.Context(), f.user)
	require.NoError(t, err)

	return n
}

// issuingBase is what the fixtures over their own collaborators share: a
// real session manager, a JWT generator that binds and verifies, and a user
// store answering e2eUser that counts its lookups.
type issuingBase struct {
	sessions *session.Sessions
	// creator creates the sign-ins a case starts from: sessions itself,
	// unless a case creates them under another manager over the same store.
	creator *session.Sessions
	gen     *token.JWTGenerator
	users   *MockUserLoader
	authn   authenticate.Authenticator
	lookups *atomic.Int64
}

func newIssuingBase(t *testing.T) *issuingBase {
	t.Helper()

	sessions := must.Must(session.New())

	return newIssuingBaseOver(t, sessions, sessions)
}

// newIssuingBaseOver is newIssuingBase whose chain uses sessions and whose
// cases sign in through creator.
func newIssuingBaseOver(t *testing.T, sessions, creator *session.Sessions) *issuingBase {
	t.Helper()

	hash, err := e2eEncoder(t).Encode(e2ePassword)
	require.NoError(t, err)

	details := func() *identity.Details {
		return &identity.Details{ID: e2eUser, Name: "Grace Hopper", Username: e2eAddress, Password: hash, Active: true}
	}

	b := &issuingBase{
		sessions: sessions,
		creator:  creator,
		gen:      issuingGenerator(t),
		users:    NewMockUserLoader(gomock.NewController(t)),
		lookups:  &atomic.Int64{},
	}

	b.users.EXPECT().LoadByUsername(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, username string) (*identity.Details, error) {
			b.lookups.Add(1)

			if username != e2eAddress {
				return nil, identity.ErrUserNotFound
			}

			return details(), nil
		})
	b.users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, user identity.UserID) (*identity.Details, error) {
			b.lookups.Add(1)

			if user != e2eUser {
				return nil, identity.ErrUserNotFound
			}

			return details(), nil
		})

	b.authn, err = authenticate.NewUsernamePasswordAuthenticator(b.users,
		authenticate.WithPasswordEncoder(e2eEncoder(t)))
	require.NoError(t, err)

	return b
}

// issuingGenerator is the built-in JWT generator, which binds, on a fresh key.
func issuingGenerator(t *testing.T) *token.JWTGenerator {
	t.Helper()

	keys, err := signingkey.New(t.Context(), signingkey.WithKeyStore(signingkey.NewMemoryKeyStore()))
	require.NoError(t, err)

	return must.Must(token.NewGenerator(keys, token.WithoutIssuer(), token.WithoutAudience()))
}

// bearer is the signed bearer over the base's collaborators.
func (b *issuingBase) bearer() httpsec.Option {
	return httpsec.EnableBearerToken(httpsec.BearerTokenDeps{Verifier: b.gen, Sessions: b.sessions, Users: b.users})
}

// fixture builds the chain from opts, beside the signed bearer and DPoP
// configured by d.
func (b *issuingBase) fixture(t *testing.T, d httpsec.DPoP, opts ...httpsec.Option) issuingFixture {
	t.Helper()

	chain, err := httpsec.New(append(opts, b.bearer(), httpsec.EnableDPoP(d))...)
	require.NoError(t, err)

	return issuingFixture{
		chain: chain, sessions: b.sessions, gen: b.gen, user: e2eUser, lookups: b.lookups.Load,
	}
}

// signedIn creates a sign-in of e2eUser's, bound to bound unless it is empty,
// changed by change before it is stored again, and returns the token issued
// for it, bound as the session is.
func (b *issuingBase) signedIn(t *testing.T, bound string, change func(*session.Session)) string {
	t.Helper()

	opts := []session.CreateOption{session.WithFirstFactor(factor.Password)}
	if bound != "" {
		opts = append(opts, session.WithKeyBinding(session.KeyBinding{JKT: bound}))
	}

	s, err := b.creator.Create(t.Context(), e2eUser, opts...)
	require.NoError(t, err)

	if change != nil {
		change(s)
		require.NoError(t, b.creator.Save(t.Context(), s))
	}

	tok, err := b.gen.GenerateWith(t.Context(), s.ID, &identity.Principal{ID: e2eUser, Username: e2eAddress},
		token.WithConfirmation(token.Confirmation{JKT: bound}))
	require.NoError(t, err)

	return tok
}

// presenting is req presenting credential: under the DPoP scheme with a
// proof whose ath hashes it when the session is bound, and as Bearer with an
// issuing proof, if any, otherwise.
func presenting(t *testing.T, req *http.Request, credential, bound string, proof prover) *http.Request {
	t.Helper()

	if bound == "" {
		req.Header.Set("Authorization", "Bearer "+credential)

		return withProof(req, proof(t, req.URL.Path, ""))
	}

	req.Header.Set("Authorization", "DPoP "+credential)

	return withProof(req, proof(t, req.URL.Path, credential))
}

// withProof is req carrying header as its DPoP proof, unless it is empty.
func withProof(req *http.Request, header string) *http.Request {
	if header != "" {
		req.Header.Set("DPoP", header)
	}

	return req
}

// loginEndpoint is form login.
func loginEndpoint(t *testing.T, d httpsec.DPoP) issuingFixture {
	t.Helper()

	b := newIssuingBase(t)
	attempts := must.Must(lockout.NewMemoryAttemptStore())

	f := b.fixture(t, d, httpsec.EnableFormLogin(httpsec.FormLoginDeps{
		Authenticator: b.authn, Sessions: b.sessions, Tokens: b.gen, Attempts: attempts,
	}))
	f.attempts = attempts
	f.prepare = func(*testing.T, string) func(*testing.T, prover) served {
		return func(t *testing.T, proof prover) served {
			t.Helper()

			req := postValues(t.Context(), httpsec.DefaultLoginPath, e2eSource, url.Values{
				httpsec.DefaultLoginUsernameParam: {e2eAddress},
				httpsec.DefaultLoginPasswordParam: {e2ePassword},
			})

			return serve(t, f.chain, withProof(req, proof(t, httpsec.DefaultLoginPath, "")))
		}
	}

	return f
}

// mfaVerifyEndpoint is second-factor verification of a pending sign-in, over
// TOTP.
func mfaVerifyEndpoint(t *testing.T, d httpsec.DPoP) issuingFixture {
	t.Helper()

	b := newIssuingBase(t)
	clk := clockwork.NewFakeClockAt(time.Now().Truncate(time.Second))

	method, err := mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example", mfa.WithClock(clk))
	require.NoError(t, err)

	prov, err := method.BeginEnrolment(t.Context(), e2eUser, e2eAddress)
	require.NoError(t, err)
	require.NoError(t, method.ConfirmEnrolment(t.Context(), e2eUser, must.Must(totp.GenerateCode(prov.Secret, clk.Now()))))

	f := b.fixture(t, d, httpsec.EnableMFA([]mfa.Method{method}, httpsec.WithMFATokens(b.gen)))
	path := httpsec.DefaultMFAVerifyPrefix + "/totp"

	f.prepare = func(t *testing.T, bound string) func(*testing.T, prover) served {
		t.Helper()

		tok := b.signedIn(t, bound, func(s *session.Session) { s.MFA = session.MFAPending })

		clk.Advance(method.Period())
		code := must.Must(totp.GenerateCode(prov.Secret, clk.Now()))

		return func(t *testing.T, proof prover) served {
			t.Helper()

			req := postValues(t.Context(), path, e2eSource, url.Values{"code": {code}})

			return serve(t, f.chain, presenting(t, req, tok, bound, proof))
		}
	}

	return f
}

// reauthEndpoint is a password re-proof of a full sign-in.
func reauthEndpoint(t *testing.T, d httpsec.DPoP) issuingFixture {
	t.Helper()

	b := newIssuingBase(t)

	f := b.fixture(t, d,
		httpsec.EnableFormLogin(httpsec.FormLoginDeps{
			Authenticator: b.authn, Sessions: b.sessions, Tokens: b.gen,
			Attempts: must.Must(lockout.NewMemoryAttemptStore()),
		}),
		httpsec.EnableReauthentication(httpsec.WithReauthenticationTokens(b.gen)),
	)
	path := httpsec.DefaultReauthenticationPrefix + "/password"

	f.prepare = func(t *testing.T, bound string) func(*testing.T, prover) served {
		t.Helper()

		tok := b.signedIn(t, bound, nil)

		return func(t *testing.T, proof prover) served {
			t.Helper()

			req := postValues(t.Context(), path, e2eSource, url.Values{httpsec.DefaultLoginPasswordParam: {e2ePassword}})

			return serve(t, f.chain, presenting(t, req, tok, bound, proof))
		}
	}

	return f
}

// renewalEndpoint is session renewal of a full sign-in.
func renewalEndpoint(t *testing.T, d httpsec.DPoP) issuingFixture {
	t.Helper()

	return renewalOver(t, newIssuingBase(t), d)
}

// renewalOver is renewalEndpoint over b.
func renewalOver(t *testing.T, b *issuingBase, d httpsec.DPoP) issuingFixture {
	t.Helper()

	f := b.fixture(t, d, httpsec.EnableSessionRenewal(httpsec.SessionRenewalDeps{Users: b.users, Tokens: b.gen}))

	f.prepare = func(t *testing.T, bound string) func(*testing.T, prover) served {
		t.Helper()

		tok := b.signedIn(t, bound, nil)

		return func(t *testing.T, proof prover) served {
			t.Helper()

			req := postValues(t.Context(), httpsec.DefaultSessionRenewalPath, e2eSource, url.Values{})

			return serve(t, f.chain, presenting(t, req, tok, bound, proof))
		}
	}

	return f
}

// magicLinkEndpoint is magic-link redemption.
func magicLinkEndpoint(t *testing.T, d httpsec.DPoP) issuingFixture {
	t.Helper()

	h := newMagicLinkHarness(t)
	gen := issuingGenerator(t)

	h.tokens = nil
	h.linkOpts = append(h.linkOpts, httpsec.WithMagicLinkTokens(gen))
	h.chainOpts = append(h.chainOpts,
		httpsec.EnableBearerToken(httpsec.BearerTokenDeps{Verifier: gen, Sessions: h.sessions, Users: h.users}),
		httpsec.EnableDPoP(d))

	f := issuingFixture{chain: h.chain(t), sessions: h.sessions, gen: gen, user: magicLinkUserID}
	f.prepare = func(t *testing.T, _ string) func(*testing.T, prover) served {
		t.Helper()

		link, nonce := h.link(t, f.chain)

		return func(t *testing.T, proof prover) served {
			t.Helper()

			req := postValues(t.Context(), httpsec.DefaultMagicLinkConsumePath, magicLinkSource,
				url.Values{"token": {link}})
			if nonce != "" {
				req.AddCookie(bindingCookie(nonce))
			}

			return serve(t, f.chain, withProof(req, proof(t, httpsec.DefaultMagicLinkConsumePath, "")))
		}
	}

	return f
}

// oidcHandoffEndpoint is the redemption of a federated login's handoff code.
func oidcHandoffEndpoint(t *testing.T, d httpsec.DPoP) issuingFixture {
	t.Helper()

	h := newOIDCHarness(t)
	gen := issuingGenerator(t)

	h.chainOpts = append(h.chainOpts,
		httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
			Verifier: gen, Sessions: h.sessions, Users: NewMockUserLoader(gomock.NewController(t)),
		}),
		httpsec.EnableDPoP(d))

	f := issuingFixture{
		chain:    h.build(t, h.handoffs, httpsec.WithOIDCTokens(gen), httpsec.WithOIDCSessions(h.sessions)),
		sessions: h.sessions, gen: gen, user: oidcTestUserID,
	}
	f.prepare = func(t *testing.T, _ string) func(*testing.T, prover) served {
		t.Helper()

		code := h.issueHandoff(t, "")

		return func(t *testing.T, proof prover) served {
			t.Helper()

			req := handoffRequest(t.Context(), oidcTestSource, code)

			return serve(t, f.chain, withProof(req, proof(t, httpsec.DefaultOIDCHandoffPath, "")))
		}
	}

	return f
}

// passkeyLoginEndpoint is passwordless passkey login.
func passkeyLoginEndpoint(t *testing.T, d httpsec.DPoP) issuingFixture {
	t.Helper()

	dep := newPwlDeployment(t)
	dep.required.on.Store(false)
	dep.jwt = issuingGenerator(t)
	dep.extra = append(dep.extra, httpsec.EnableDPoP(d))
	dep.build(t)

	handle := dep.seed(t, e2eUser, "cred-1", passkey.StateActive)

	f := issuingFixture{
		chain: dep.chain, sessions: dep.sessions, gen: dep.jwt, user: e2eUser, lookups: dep.lookups.Load,
	}
	f.prepare = func(t *testing.T, _ string) func(*testing.T, prover) served {
		t.Helper()

		cookie, challenge := dep.begun(t)
		body := handleAssertionBody(challenge, "cred-1", handle)

		return func(t *testing.T, proof prover) served {
			t.Helper()

			req := jsonPost(t.Context(), passwordlessFinishPath, body)
			req.AddCookie(&http.Cookie{Name: httpsec.DefaultPasswordlessCookieName, Value: cookie}) //nolint:gosec // G124: a request cookie

			return serve(t, f.chain, withProof(req, proof(t, passwordlessFinishPath, "")))
		}
	}

	return f
}

// recoveryEndpoint is account recovery's completion, with a saved and an
// issued code.
func recoveryEndpoint(t *testing.T, d httpsec.DPoP) issuingFixture {
	t.Helper()

	h := newRecoveryHarness(t)
	gen := issuingGenerator(t)

	h.noFormLogin = true
	h.proofs = []recovery.ProofKind{recovery.ProofSaved, recovery.ProofIssued}
	h.recOpts = append(h.recOpts, httpsec.WithRecoveryTokens(gen))
	h.chainOpts = append(h.chainOpts,
		httpsec.EnableBearerToken(httpsec.BearerTokenDeps{Verifier: gen, Sessions: h.sessions, Users: h.users}),
		httpsec.EnableDPoP(d))
	h.build(t)

	f := issuingFixture{chain: h.chain, sessions: h.sessions, gen: gen, user: e2eUser}
	f.prepare = func(t *testing.T, _ string) func(*testing.T, prover) served {
		t.Helper()

		form := recoveryForm(httpsec.RecoverySavedCodeParam, h.saved(t), httpsec.RecoveryIssuedCodeParam, h.issued(t))

		return func(t *testing.T, proof prover) served {
			t.Helper()

			req := postValues(t.Context(), httpsec.DefaultRecoveryCompletePath, e2eSource, form)

			return serve(t, f.chain, withProof(req, proof(t, httpsec.DefaultRecoveryCompletePath, "")))
		}
	}

	return f
}

// issuingEndpoint is one row of the issuing tables.
type issuingEndpoint struct {
	name  string
	build func(t *testing.T, d httpsec.DPoP) issuingFixture

	// inherits is true for an endpoint a session reaches that keeps the
	// binding it was signed in with: its proof is the one the bearer
	// verified, for a session bound to that key.
	inherits bool
}

// issuingEndpoints are every endpoint that issues a credential.
var issuingEndpoints = []issuingEndpoint{
	{name: "login", build: loginEndpoint},
	{name: "MFA verify", build: mfaVerifyEndpoint, inherits: true},
	{name: "passkey login", build: passkeyLoginEndpoint},
	{name: "magic link", build: magicLinkEndpoint},
	{name: "OIDC handoff", build: oidcHandoffEndpoint},
	{name: "recovery", build: recoveryEndpoint},
	{name: "re-authentication", build: reauthEndpoint},
	{name: "renewal", build: renewalEndpoint, inherits: true},
}

func TestDPoP_Binding(t *testing.T) {
	t.Parallel()

	key := newDPoPKey(t, elliptic.P256())

	type testCase struct {
		name string
		// bound is the key the prior session is bound to, for an endpoint
		// that inherits its binding.
		bound  func(ep issuingEndpoint) string
		proof  prover
		assert func(t *testing.T, f *issuingFixture, out served)
	}

	cases := []testCase{
		{
			name: "a valid proof binds the token and the stored session",
			bound: func(ep issuingEndpoint) string {
				if ep.inherits {
					return key.jkt
				}

				return ""
			},
			proof: key.validProver("j-bind"),
			assert: func(t *testing.T, f *issuingFixture, out served) {
				jkt, s := f.issued(t, out)
				assert.Equal(t, key.jkt, jkt, "the token carries cnf.jkt")
				assert.Equal(t, session.KeyBinding{JKT: key.jkt}, s.KeyBinding, "the stored session is bound")
			},
		},
		{
			name:  "no proof issues an unbound token and session",
			bound: func(issuingEndpoint) string { return "" },
			proof: noProof,
			assert: func(t *testing.T, f *issuingFixture, out served) {
				jkt, s := f.issued(t, out)
				assert.Empty(t, jkt, "the token carries no cnf")
				assert.True(t, s.KeyBinding.IsZero(), "the stored session is unbound")
			},
		},
	}

	for _, ep := range issuingEndpoints {
		for _, tc := range cases {
			t.Run(ep.name+"/"+tc.name, func(t *testing.T) {
				t.Parallel()

				f := ep.build(t, httpsec.DPoP{})
				send := f.prepare(t, tc.bound(ep))
				tc.assert(t, &f, send(t, tc.proof))
			})
		}
	}
}

func TestDPoP_ProofBeforeSpend(t *testing.T) {
	t.Parallel()

	key := newDPoPKey(t, elliptic.P256())

	type testCase struct {
		name string
		d    httpsec.DPoP
		// bound is the key the prior session is bound to, for an endpoint
		// that inherits its binding.
		bound func(ep issuingEndpoint) string
		proof prover
		// skip reports whether the case does not apply to ep.
		skip   func(ep issuingEndpoint) bool
		assert func(t *testing.T, f *issuingFixture, out served, retry func(*testing.T, prover) served, before int, lookups int64)
	}

	refused := func(t *testing.T, f *issuingFixture, out served, before int) {
		t.Helper()

		require.ErrorIs(t, out.err, httpsec.ErrInvalidDPoPProof)
		assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
		assert.False(t, out.handlerRan)
		assert.Equal(t, before, f.activeSessions(t), "no session is stored")
	}
	// unspent shows the refused request spent nothing: the same request
	// with a valid proof then succeeds.
	unspent := func(t *testing.T, retry func(*testing.T, prover) served) {
		t.Helper()

		out := retry(t, key.validProver("j-retry"))
		require.NoError(t, out.err, "the link, code, attempts or proofs were left unspent")
	}
	boundIfInherited := func(ep issuingEndpoint) string {
		if ep.inherits {
			return key.jkt
		}

		return ""
	}

	cases := []testCase{
		{
			name:  "a bad proof is refused with everything left unspent",
			bound: boundIfInherited,
			proof: key.brokenProver("j-bad"),
			skip:  func(issuingEndpoint) bool { return false },
			assert: func(t *testing.T, f *issuingFixture, out served, retry func(*testing.T, prover) served, before int, _ int64) {
				refused(t, f, out, before)
				unspent(t, retry)
			},
		},
		{
			name:  "a proof for another URL at login records no lockout failure",
			bound: boundIfInherited,
			proof: key.wrongURLProver("j-url"),
			skip:  func(ep issuingEndpoint) bool { return ep.name != "login" },
			assert: func(t *testing.T, f *issuingFixture, out served, _ func(*testing.T, prover) served, before int, _ int64) {
				refused(t, f, out, before)

				n, err := f.attempts.FailureCount(t.Context(), e2eAddress, time.Time{})
				require.NoError(t, err)
				assert.Zero(t, n, "charged as a malformed request, never as a failed password")
			},
		},
		{
			name:  "required DPoP refuses a request without a proof before any account lookup",
			d:     httpsec.DPoP{Require: true},
			bound: func(issuingEndpoint) string { return "" },
			proof: noProof,
			skip:  func(issuingEndpoint) bool { return false },
			assert: func(t *testing.T, f *issuingFixture, out served, retry func(*testing.T, prover) served, before int, lookups int64) {
				refused(t, f, out, before)

				if f.lookups != nil {
					assert.Equal(t, lookups, f.lookups(), "no account was looked up")
				}
			},
		},
	}

	for _, ep := range issuingEndpoints {
		for _, tc := range cases {
			if tc.skip(ep) {
				continue
			}

			t.Run(ep.name+"/"+tc.name, func(t *testing.T) {
				t.Parallel()

				f := ep.build(t, tc.d)
				send := f.prepare(t, tc.bound(ep))

				before := f.activeSessions(t)

				var lookups int64
				if f.lookups != nil {
					lookups = f.lookups()
				}

				tc.assert(t, &f, send(t, tc.proof), send, before, lookups)
			})
		}
	}
}

func TestDPoP_TokenType(t *testing.T) {
	t.Parallel()

	key := newDPoPKey(t, elliptic.P256())

	type testCase struct {
		name string
		// bound is the key the prior session is bound to, for an endpoint
		// that inherits its binding.
		bound  func(ep issuingEndpoint) string
		proof  prover
		assert func(t *testing.T, out served)
	}

	// documented reads the token type the default responder wrote.
	documented := func(want httpsec.TokenType) func(*testing.T, served) {
		return func(t *testing.T, out served) {
			t.Helper()

			require.NoError(t, out.err)

			var doc struct {
				TokenType string `json:"token_type"`
			}
			require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &doc))
			assert.Equal(t, string(want), doc.TokenType)
		}
	}

	cases := []testCase{
		{
			name: "with a proof the token is DPoP",
			bound: func(ep issuingEndpoint) string {
				if ep.inherits {
					return key.jkt
				}

				return ""
			},
			proof:  key.validProver("j-type"),
			assert: documented(httpsec.TokenTypeDPoP),
		},
		{
			name:   "without a proof the token is Bearer",
			bound:  func(issuingEndpoint) string { return "" },
			proof:  noProof,
			assert: documented(httpsec.TokenTypeBearer),
		},
	}

	for _, ep := range issuingEndpoints {
		for _, tc := range cases {
			t.Run(ep.name+"/"+tc.name, func(t *testing.T) {
				t.Parallel()

				f := ep.build(t, httpsec.DPoP{})
				send := f.prepare(t, tc.bound(ep))
				tc.assert(t, send(t, tc.proof))
			})
		}
	}
}

// TestDPoP_TokenTypeToConsumerResponder pins that a consumer's own responder
// is handed the token type, beside the default responders' token_type.
//
// Standalone: one consumer responder on one endpoint; every endpoint's
// default responder is a row of TestDPoP_TokenType.
func TestDPoP_TokenTypeToConsumerResponder(t *testing.T) {
	t.Parallel()

	key := newDPoPKey(t, elliptic.P256())

	type testCase struct {
		name  string
		proof prover
		want  httpsec.TokenType
	}

	cases := []testCase{
		{name: "with a proof", proof: key.validProver("j-1"), want: httpsec.TokenTypeDPoP},
		{name: "without a proof", proof: noProof, want: httpsec.TokenTypeBearer},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			b := newIssuingBase(t)

			var got httpsec.LoginResult

			f := b.fixture(t, httpsec.DPoP{}, httpsec.EnableFormLogin(httpsec.FormLoginDeps{
				Authenticator: b.authn, Sessions: b.sessions, Tokens: b.gen,
				Attempts: must.Must(lockout.NewMemoryAttemptStore()),
			}, httpsec.WithLoginResponder(func(_ *httpsec.Exchange, r httpsec.LoginResult) error {
				got = r

				return nil
			})))

			req := postValues(t.Context(), httpsec.DefaultLoginPath, e2eSource, url.Values{
				httpsec.DefaultLoginUsernameParam: {e2eAddress},
				httpsec.DefaultLoginPasswordParam: {e2ePassword},
			})

			out := serve(t, f.chain, withProof(req, tc.proof(t, httpsec.DefaultLoginPath, "")))
			require.NoError(t, out.err)
			assert.Equal(t, tc.want, got.TokenType)
		})
	}
}
