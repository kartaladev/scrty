package httpsec_test

import (
	"crypto/elliptic"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/session"
)

// overlaidRequest is a Request whose headers named in headers read as given
// there, by Header (the first line) and HeaderValues alike.
type overlaidRequest struct {
	httpsec.Request
	headers map[string][]string
}

func (r overlaidRequest) Header(name string) string {
	if lines, ok := r.headers[http.CanonicalHeaderKey(name)]; ok {
		if len(lines) == 0 {
			return ""
		}

		return lines[0]
	}

	return r.Request.Header(name)
}

func (r overlaidRequest) HeaderValues(name string) []string {
	if lines, ok := r.headers[http.CanonicalHeaderKey(name)]; ok {
		return lines
	}

	return r.Request.HeaderValues(name)
}

// presentedAs rewrites, before the bearer reads it, every request presenting
// a Bearer credential: headers receives that credential and returns the
// headers the request then carries in place of its own. seen, when not nil,
// receives the credential.
func presentedAs(t *testing.T, seen *string, headers func(t *testing.T, path, tok string) map[string][]string) httpsec.Option {
	t.Helper()

	return httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		tok, ok := strings.CutPrefix(ex.Request.Header("Authorization"), "Bearer ")
		if ok {
			if seen != nil {
				*seen = tok
			}
			ex.Request = overlaidRequest{Request: ex.Request, headers: headers(t, ex.Request.Path(), tok)}
		}

		return next(ex)
	}), httpsec.Before(httpsec.OrderBearerToken))
}

// continuingEndpoint is one endpoint that continues a sign-in already
// created, over b.
type continuingEndpoint struct {
	name  string
	build func(t *testing.T, b *issuingBase, d httpsec.DPoP, extra ...httpsec.Option) issuingFixture
}

var continuingEndpoints = []continuingEndpoint{
	{"MFA verify", mfaVerifyOver},
	{"re-authentication", reauthOver},
	{"renewal", renewalOver},
}

// assertNotRotated asserts that the sign-in tok names was neither rotated nor
// joined by another.
func assertNotRotated(t *testing.T, f issuingFixture, tok string) {
	t.Helper()

	claims, err := f.gen.Verify(t.Context(), tok)
	require.NoError(t, err)

	s, err := f.sessions.Load(t.Context(), claims.ID())
	require.NoError(t, err, "the sign-in is still live")
	assert.Empty(t, s.SuccessorDigest, "the sign-in was not rotated")
	assert.Equal(t, 1, f.activeSessions(t), "no session was issued")
}

// TestContinuingProof_RequiresAthBesideAccessToken pins RFC 9449 section 4.2
// at the endpoints that continue a sign-in: a proof beside an access token
// presented as Bearer, the sign-in unbound or bound to a certificate, carries
// ath over that token. With it the proof is accepted; without it the request
// is refused with ErrInvalidDPoPProof and nothing is rotated.
func TestContinuingProof_RequiresAthBesideAccessToken(t *testing.T) {
	t.Parallel()

	key := newDPoPKey(t, elliptic.P256())
	c := newClientCert(t, "service-c")

	type testCase struct {
		name      string
		endpoint  continuingEndpoint
		certBound bool
		withAth   bool
		assert    func(t *testing.T, f issuingFixture, tok string, out served)
	}

	accepted := func(t *testing.T, _ issuingFixture, _ string, out served) {
		require.NoError(t, out.err, "a proof beside an access token carrying its ath is accepted")
	}
	refused := func(t *testing.T, f issuingFixture, tok string, out served) {
		require.ErrorIs(t, out.err, httpsec.ErrInvalidDPoPProof, "ath is required beside an access token")
		assertNotRotated(t, f, tok)
	}

	var cases []testCase
	for _, ep := range continuingEndpoints {
		for _, certBound := range []bool{false, true} {
			binding := "unbound"
			if certBound {
				binding = "cert-bound"
			}
			cases = append(cases,
				testCase{name: ep.name + "/" + binding + "/with ath", endpoint: ep, certBound: certBound, withAth: true, assert: accepted},
				testCase{name: ep.name + "/" + binding + "/without ath", endpoint: ep, certBound: certBound, assert: refused},
			)
		}
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var tok string
			b := newIssuingBase(t)
			extra := []httpsec.Option{presentedAs(t, &tok, func(t *testing.T, path, tok string) map[string][]string {
				ath := ""
				if tc.withAth {
					ath = tok
				}

				return map[string][]string{"Dpop": {key.issuingProofParts(path, "j-1", ath).sign(t)}}
			})}
			if tc.certBound {
				b.certThumb = c.thumb
				extra = append(extra, httpsec.EnableCertificateBinding(), presentingCertificate(c))
			}

			f := tc.endpoint.build(t, b, httpsec.DPoP{PublicURL: dpopPublicURL}, extra...)
			out := f.prepare(t, "")(t, noProof)

			tc.assert(t, f, tok, out)
		})
	}
}

// TestContinuingProof_PresentedToken pins which token a continuing endpoint
// judges a proof's ath against: the credential the chain's bearer
// authenticated. With two Authorization headers that is the one the bearer
// read, the first, so a proof hashing it is accepted, and one hashing the
// other, or carrying no ath, is refused; an unbound sign-in under the DPoP
// scheme stays refused by its binding check; a Bearer header with no token
// authenticates nothing.
func TestContinuingProof_PresentedToken(t *testing.T) {
	t.Parallel()

	key := newDPoPKey(t, elliptic.P256())

	type testCase struct {
		name     string
		endpoint continuingEndpoint
		headers  func(t *testing.T, path, tok string) map[string][]string
		assert   func(t *testing.T, f issuingFixture, tok string, out served)
	}

	twoHeaders := func(hashed func(tok string) string) func(t *testing.T, path, tok string) map[string][]string {
		return func(t *testing.T, path, tok string) map[string][]string {
			return map[string][]string{
				"Authorization": {"Bearer " + tok, "Bearer other-token"},
				"Dpop":          {key.issuingProofParts(path, "j-1", hashed(tok)).sign(t)},
			}
		}
	}
	accepted := func(t *testing.T, _ issuingFixture, _ string, out served) {
		require.NoError(t, out.err, "the proof hashes the credential the bearer authenticated")
	}
	refused := func(t *testing.T, f issuingFixture, tok string, out served) {
		require.ErrorIs(t, out.err, httpsec.ErrInvalidDPoPProof)
		assertNotRotated(t, f, tok)
	}

	var cases []testCase
	for _, ep := range continuingEndpoints {
		cases = append(cases,
			testCase{
				name:     ep.name + "/two Authorization headers/proof hashing the authenticated one",
				endpoint: ep,
				headers:  twoHeaders(func(tok string) string { return tok }),
				assert:   accepted,
			},
			testCase{
				name:     ep.name + "/two Authorization headers/proof hashing the other",
				endpoint: ep,
				headers:  twoHeaders(func(string) string { return "other-token" }),
				assert:   refused,
			},
			testCase{
				name:     ep.name + "/two Authorization headers/proof without ath",
				endpoint: ep,
				headers:  twoHeaders(func(string) string { return "" }),
				assert:   refused,
			},
		)
	}
	cases = append(cases,
		testCase{
			name:     "renewal/unbound sign-in under the DPoP scheme",
			endpoint: continuingEndpoint{"renewal", renewalOver},
			headers: func(t *testing.T, path, tok string) map[string][]string {
				return map[string][]string{
					"Authorization": {"DPoP " + tok},
					"Dpop":          {key.issuingProofParts(path, "j-1", tok).sign(t)},
				}
			},
			assert: refused,
		},
		testCase{
			name:     "re-authentication/Bearer header with no token",
			endpoint: continuingEndpoint{"re-authentication", reauthOver},
			headers: func(t *testing.T, path, _ string) map[string][]string {
				return map[string][]string{
					"Authorization": {"Bearer "},
					"Dpop":          {key.issuingProofParts(path, "j-1", "").with(map[string]any{"ath": tokenHash("")}).sign(t)},
				}
			},
			assert: func(t *testing.T, f issuingFixture, tok string, out served) {
				require.ErrorIs(t, out.err, httpsec.ErrAuthenticationRequired, "a Bearer header with no token authenticates nothing")
				assertNotRotated(t, f, tok)
			},
		},
	)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var tok string
			b := newIssuingBase(t)
			f := tc.endpoint.build(t, b, httpsec.DPoP{PublicURL: dpopPublicURL}, presentedAs(t, &tok, tc.headers))
			out := f.prepare(t, "")(t, noProof)

			tc.assert(t, f, tok, out)
		})
	}
}

// cookieSession publishes the sign-in the "sid" cookie names, for e2eUser, as
// a consumer's cookie authenticator would: the request presents no access
// token.
func cookieSession(sessions *session.Sessions) httpsec.Option {
	return httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		sid, ok := ex.Request.Cookie("sid")
		if !ok {
			return next(ex)
		}

		s, err := sessions.Load(ex.Context(), sid)
		if err != nil {
			return httpsec.ErrAuthenticationRequired
		}

		a := &authenticate.Authentication{Principal: &identity.Principal{ID: e2eUser, Username: e2eAddress}}
		if err := ex.PublishSession(a, s); err != nil {
			return err
		}

		return next(ex)
	}), httpsec.OrderBearerToken)
}

// TestContinuingProof_CookieSession pins that a sign-in presented by cookie
// presents no access token: a proof beside it carries no ath, and one that
// does is refused.
func TestContinuingProof_CookieSession(t *testing.T) {
	t.Parallel()

	key := newDPoPKey(t, elliptic.P256())

	type testCase struct {
		name   string
		ath    string
		assert func(t *testing.T, f issuingFixture, s *session.Session, out served)
	}

	cases := []testCase{
		{
			name: "proof without ath",
			assert: func(t *testing.T, _ issuingFixture, _ *session.Session, out served) {
				require.NoError(t, out.err)
			},
		},
		{
			name: "proof with ath",
			ath:  "some-token",
			assert: func(t *testing.T, f issuingFixture, s *session.Session, out served) {
				require.ErrorIs(t, out.err, httpsec.ErrInvalidDPoPProof)

				got, err := f.sessions.Load(t.Context(), s.ID)
				require.NoError(t, err, "the sign-in is still live")
				assert.Empty(t, got.SuccessorDigest, "the sign-in was not rotated")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			b := newIssuingBase(t)
			f := b.fixture(t, httpsec.DPoP{PublicURL: dpopPublicURL},
				httpsec.EnableSessionRenewal(httpsec.SessionRenewalDeps{Users: b.users, Tokens: b.gen}),
				cookieSession(b.sessions),
			)

			s, err := b.creator.Create(t.Context(), e2eUser, session.WithFirstFactor(factor.Password))
			require.NoError(t, err)

			req := postValues(t.Context(), httpsec.DefaultSessionRenewalPath, e2eSource, url.Values{})
			req.AddCookie(&http.Cookie{Name: "sid", Value: s.ID}) //nolint:gosec // G124: a request cookie
			out := serve(t, f.chain, withProof(req, key.issuingProofParts(httpsec.DefaultSessionRenewalPath, "j-1", tc.ath).sign(t)))

			tc.assert(t, f, s, out)
		})
	}
}

// consumerBearer is a consumer's own bearer at OrderBearerToken: it
// authenticates an access token presented as "Opaque <session id>" and
// publishes its session. It records the token it verified when record is set.
func consumerBearer(sessions *session.Sessions, record bool) httpsec.Option {
	return httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		sid, ok := strings.CutPrefix(ex.Request.Header("Authorization"), "Opaque ")
		if !ok {
			return next(ex)
		}

		s, err := sessions.Load(ex.Context(), sid)
		if err != nil {
			return httpsec.ErrAuthenticationRequired
		}

		a := &authenticate.Authentication{Principal: &identity.Principal{ID: e2eUser, Username: e2eAddress}}
		if err := ex.PublishSession(a, s); err != nil {
			return err
		}

		if record {
			ex.RecordPresentedToken(sid)
		}

		return next(ex)
	}), httpsec.OrderBearerToken)
}

// TestContinuingProof_AuthenticatedCredential pins that the token a proof's
// ath is judged against is the credential the bearer authenticated, however
// it was presented: under a consumer's own scheme, as a session reference,
// and by a consumer's own bearer, which records it with RecordPresentedToken
// or, not recording, is judged as presenting none.
func TestContinuingProof_AuthenticatedCredential(t *testing.T) {
	t.Parallel()

	key := newDPoPKey(t, elliptic.P256())

	type testCase struct {
		name string
		// mode is the bearer mode and the renewal endpoint over b.
		mode func(b *issuingBase) []httpsec.Option
		// credential is the credential a sign-in s presents in mode.
		credential func(t *testing.T, b *issuingBase, s *session.Session) string
		scheme     string
		withAth    bool
		assert     func(t *testing.T, b *issuingBase, s *session.Session, out served)
	}

	customScheme := func(b *issuingBase) []httpsec.Option {
		return []httpsec.Option{
			httpsec.EnableBearerToken(httpsec.BearerTokenDeps{Verifier: b.gen, Sessions: b.sessions, Users: b.users},
				httpsec.WithBearerScheme("Token")),
			httpsec.EnableSessionRenewal(httpsec.SessionRenewalDeps{Users: b.users, Tokens: b.gen}),
		}
	}
	signedToken := func(t *testing.T, b *issuingBase, s *session.Session) string {
		tok, err := b.gen.GenerateWith(t.Context(), s.ID, &identity.Principal{ID: e2eUser, Username: e2eAddress})
		require.NoError(t, err)

		return tok
	}
	reference := func(b *issuingBase) []httpsec.Option {
		return []httpsec.Option{
			httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: b.sessions, Users: b.users}),
			httpsec.EnableSessionRenewal(httpsec.SessionRenewalDeps{Users: b.users}),
		}
	}
	sessionID := func(_ *testing.T, _ *issuingBase, s *session.Session) string { return s.ID }
	consumer := func(record bool) func(b *issuingBase) []httpsec.Option {
		return func(b *issuingBase) []httpsec.Option {
			return append(customScheme(b), consumerBearer(b.sessions, record))
		}
	}

	renewed := func(t *testing.T, _ *issuingBase, _ *session.Session, out served) {
		require.NoError(t, out.err, "a proof carrying ath over the authenticated credential is accepted")
	}
	refused := func(t *testing.T, b *issuingBase, s *session.Session, out served) {
		require.ErrorIs(t, out.err, httpsec.ErrInvalidDPoPProof, "ath is required beside an access token")

		got, err := b.sessions.Load(t.Context(), s.ID)
		require.NoError(t, err, "the sign-in is still live")
		assert.Empty(t, got.SuccessorDigest, "the sign-in was not rotated")
	}

	cases := []testCase{
		{name: "custom bearer scheme/with ath", mode: customScheme, credential: signedToken, scheme: "Token", withAth: true, assert: renewed},
		{name: "custom bearer scheme/without ath", mode: customScheme, credential: signedToken, scheme: "Token", assert: refused},
		{name: "session reference/with ath", mode: reference, credential: sessionID, scheme: "Bearer", withAth: true, assert: renewed},
		{name: "session reference/without ath", mode: reference, credential: sessionID, scheme: "Bearer", assert: refused},
		{name: "consumer bearer recording/with ath", mode: consumer(true), credential: sessionID, scheme: "Opaque", withAth: true, assert: renewed},
		{name: "consumer bearer recording/without ath", mode: consumer(true), credential: sessionID, scheme: "Opaque", assert: refused},
		{name: "consumer bearer not recording/with ath", mode: consumer(false), credential: sessionID, scheme: "Opaque", withAth: true, assert: refused},
		{name: "consumer bearer not recording/without ath", mode: consumer(false), credential: sessionID, scheme: "Opaque", assert: renewed},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			b := newIssuingBase(t)
			chain, err := httpsec.New(append(tc.mode(b), httpsec.EnableDPoP(httpsec.DPoP{PublicURL: dpopPublicURL}))...)
			require.NoError(t, err)

			s, err := b.creator.Create(t.Context(), e2eUser, session.WithFirstFactor(factor.Password))
			require.NoError(t, err)
			credential := tc.credential(t, b, s)

			ath := ""
			if tc.withAth {
				ath = credential
			}

			req := postValues(t.Context(), httpsec.DefaultSessionRenewalPath, e2eSource, url.Values{})
			req.Header.Set("Authorization", tc.scheme+" "+credential)
			out := serve(t, chain, withProof(req, key.issuingProofParts(httpsec.DefaultSessionRenewalPath, "j-1", ath).sign(t)))

			tc.assert(t, b, s, out)
		})
	}
}

// TestDPoP_IssuingIgnoresUnauthenticatedHeader pins that a login request
// carrying an Authorization header no bearer authenticated presents no
// access token: its proof carries no ath, and binds the sign-in it issues.
func TestDPoP_IssuingIgnoresUnauthenticatedHeader(t *testing.T) {
	t.Parallel()

	key := newDPoPKey(t, elliptic.P256())

	f := loginEndpoint(t, httpsec.DPoP{PublicURL: dpopPublicURL})
	req := postValues(t.Context(), httpsec.DefaultLoginPath, e2eSource, url.Values{
		httpsec.DefaultLoginUsernameParam: {e2eAddress},
		httpsec.DefaultLoginPasswordParam: {e2ePassword},
	})
	req.Header.Set("Authorization", "Bearer x")
	out := serve(t, f.chain, withProof(req, key.issuingProofParts(httpsec.DefaultLoginPath, "j-1", "").sign(t)))

	jkt, s := f.issued(t, out)
	assert.Equal(t, key.jkt, jkt, "the token carries cnf.jkt")
	assert.Equal(t, session.KeyBinding{JKT: key.jkt}, s.KeyBinding, "the stored session is bound")
}

// TestDPoP_IssuingBesideAuthenticatedBearer pins that a login request whose
// token a bearer authenticated carries ath over it in its proof, and is
// refused without. The built-in bearers run after the login endpoint
// (OrderBearerToken follows OrderFormLogin), so only a consumer's own bearer,
// registered before it, can authenticate a token on a login request.
func TestDPoP_IssuingBesideAuthenticatedBearer(t *testing.T) {
	t.Parallel()

	key := newDPoPKey(t, elliptic.P256())

	type testCase struct {
		name    string
		withAth bool
		assert  func(t *testing.T, out served)
	}

	cases := []testCase{
		{
			name:    "proof with ath over the token",
			withAth: true,
			assert: func(t *testing.T, out served) {
				require.NoError(t, out.err)
			},
		},
		{
			name: "proof without ath",
			assert: func(t *testing.T, out served) {
				require.ErrorIs(t, out.err, httpsec.ErrInvalidDPoPProof)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			b := newIssuingBase(t)
			attempts := must.Must(lockout.NewMemoryAttemptStore())
			early := httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
				if tok, ok := strings.CutPrefix(ex.Request.Header("Authorization"), "Bearer "); ok {
					if _, err := b.gen.Verify(ex.Context(), tok); err != nil {
						return httpsec.ErrAuthenticationRequired
					}

					ex.RecordPresentedToken(tok)
				}

				return next(ex)
			}), httpsec.Before(httpsec.OrderFormLogin))
			f := b.fixture(t, httpsec.DPoP{PublicURL: dpopPublicURL},
				httpsec.EnableFormLogin(httpsec.FormLoginDeps{
					Authenticator: b.authn, Sessions: b.sessions, Tokens: b.gen, Attempts: attempts,
				}),
				early,
			)

			s, err := b.creator.Create(t.Context(), e2eUser, session.WithFirstFactor(factor.Password))
			require.NoError(t, err)

			tok, err := b.gen.GenerateWith(t.Context(), s.ID, &identity.Principal{ID: e2eUser, Username: e2eAddress})
			require.NoError(t, err)

			ath := ""
			if tc.withAth {
				ath = tok
			}

			req := postValues(t.Context(), httpsec.DefaultLoginPath, e2eSource, url.Values{
				httpsec.DefaultLoginUsernameParam: {e2eAddress},
				httpsec.DefaultLoginPasswordParam: {e2ePassword},
			})
			req.Header.Set("Authorization", "Bearer "+tok)
			out := serve(t, f.chain, withProof(req, key.issuingProofParts(httpsec.DefaultLoginPath, "j-1", ath).sign(t)))

			tc.assert(t, out)
		})
	}
}
