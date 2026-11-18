package test_test

// The three framework servers below are built by hand rather than through the
// conformance adapters: those adapters pin the bare-status defaults the
// conformance table compares, and this file compares a different thing, the
// problem document a consumer who wired prblmsec gets. What is shared with the
// rest of the suite is the request builder, the in-memory fiber transport and
// the fixtures' shapes.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gofiber/fiber/v3"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/prblm"
	"github.com/kartaladev/prblm/adapters/fiberprblm"
	"github.com/kartaladev/prblm/adapters/ginprblm"
	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/httpsec/fibersec"
	"github.com/kartaladev/scrty/httpsec/ginsec"
	"github.com/kartaladev/scrty/httpsec/prblmsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/store/seal"
	httpsecconformance "github.com/kartaladev/scrty/test/httpsecconformance"
	"github.com/kartaladev/scrty/token"
	"github.com/kartaladev/scrty/token/signingkey"
)

const (
	parityUserID   identity.UserID = "u-1"
	parityUsername                 = "ada"
	parityPassword                 = "s3cret" //nolint:gosec // a fixture credential
	parityPeer                     = "198.51.100.7"
	parityOrigin                   = "http://example.com"

	paritySecuredPath = "/records/r-1"
	parityBoomPath    = "/boom"
	parityDeniedPath  = "/guarded/denied"
	parityMissingPath = "/guarded/missing"
)

var errParityBoom = errors.New("parity: disk on fire (secret=sk-live-123)")

// parityResponse is what one framework answered.
type parityResponse struct {
	status int
	header http.Header
	body   string
}

func (r parityResponse) problem(t *testing.T) map[string]any {
	t.Helper()

	var doc map[string]any
	require.NoError(t, json.Unmarshal([]byte(r.body), &doc), "the body is a JSON problem: %q", r.body)

	return doc
}

// parityDPoPKey is a client's DPoP key.
type parityDPoPKey struct {
	priv *ecdsa.PrivateKey
	pub  jwk.Key
}

func newParityDPoPKey(t *testing.T) parityDPoPKey {
	t.Helper()

	priv := must.Must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))

	return parityDPoPKey{priv: priv, pub: must.Must(jwk.PublicKeyOf(priv))}
}

// proof is a proof for method and path carrying no server nonce.
func (k parityDPoPKey) proof(t *testing.T, method, path string) string {
	t.Helper()

	sum := sha256.Sum256([]byte(rand.Text()))
	claims := map[string]any{
		"jti": base64.RawURLEncoding.EncodeToString(sum[:]),
		"htm": method,
		"htu": parityOrigin + path,
		"iat": time.Now().Unix(),
	}

	headers := jws.NewHeaders()
	require.NoError(t, headers.Set(jws.TypeKey, "dpop+jwt"))
	require.NoError(t, headers.Set(jws.JWKKey, k.pub))

	return string(must.Must(jws.Sign(must.Must(json.Marshal(claims)),
		jws.WithKey(jwa.ES256(), k.priv, jws.WithProtectedHeaders(headers)))))
}

// parityUsers is the one user the chain knows.
type parityUsers struct{}

func (parityUsers) details() *identity.Details {
	return &identity.Details{
		ID: parityUserID, Username: parityUsername, Name: "Ada", Active: true,
		PasswordChangedAt: time.Now().Add(-time.Hour),
	}
}

func (u parityUsers) LoadByUsername(_ context.Context, name string) (*identity.Details, error) {
	if name != parityUsername {
		return nil, identity.ErrUserNotFound
	}

	return u.details(), nil
}

func (u parityUsers) LoadByUserID(_ context.Context, id identity.UserID) (*identity.Details, error) {
	if id != parityUserID {
		return nil, identity.ErrUserNotFound
	}

	return u.details(), nil
}

type parityAuthenticator struct{}

func (parityAuthenticator) Authenticate(_ context.Context, c identity.Credentials) (*authenticate.Authentication, error) {
	up, ok := c.(*identity.UsernamePassword)
	if !ok || up.Username != parityUsername || string(up.Password) != parityPassword {
		return nil, authenticate.ErrAuthenticationFailed
	}

	return &authenticate.Authentication{
		Principal:         identity.PrincipalFromDetails(parityUsers{}.details()),
		Time:              time.Now(),
		PasswordChangedAt: time.Now().Add(-time.Hour),
	}, nil
}

// parityAuthorizer judges the privilege guards by the resource they name: one
// is denied, one is not found, the rest pass.
type parityAuthorizer struct{}

func (parityAuthorizer) Authorize(_ context.Context, attrs authorize.Attributes) error {
	p, ok := attrs.(authorize.PrivilegeAttributes)
	if !ok {
		return authorize.ErrUnsupportedAttributes
	}

	switch p.Resource {
	case "denied":
		return authorize.ErrAccessDenied
	case "missing":
		return httpsec.ErrSessionHandleNotFound
	}

	return nil
}

type parityChallengePolicy struct{}

func (parityChallengePolicy) Name() string { return "parity/challenge" }

func (parityChallengePolicy) Phases() []policy.Phase {
	return []policy.Phase{policy.PostAuthentication}
}

func (parityChallengePolicy) Evaluate(context.Context, *policy.Input) policy.Decision {
	return policy.Decision{Outcome: policy.Challenge, Challenge: policy.ChallengeMFA}
}

func (parityChallengePolicy) Challenges() []policy.ChallengeKind {
	return []policy.ChallengeKind{policy.ChallengeMFA}
}

// parityWorld is one server's wiring: the one chain configuration all three
// frameworks run, over stores no other server shares.
type parityWorld struct {
	options []httpsec.Option
	bearer  string
	pending string // a bearer credential of a session that owes a second factor
	key     parityDPoPKey
	problem *prblmsec.Problems
	prblm   []prblm.Option
	handler *prblm.Handler
}

func newParityWorld(t *testing.T) *parityWorld {
	t.Helper()

	keys := must.Must(signingkey.New(t.Context(), signingkey.WithKeyStore(signingkey.NewMemoryKeyStore())))
	gen := must.Must(token.NewGenerator(keys, token.WithoutIssuer(), token.WithoutAudience()))

	store := must.Must(session.NewMemoryStore())
	sessions := must.Must(session.New(session.WithStore(store)))
	attempts := must.Must(lockout.NewMemoryAttemptStore())

	secret := make([]byte, 32)
	_ = must.Must(rand.Read(secret))
	keyring := must.Must(seal.NewKeyring(seal.WithKeyringEncryptionKey("k1", secret)))

	engine := must.Must(policy.NewEngine(parityChallengePolicy{}))

	method := must.Must(mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example"))
	provisioning, err := method.BeginEnrolment(t.Context(), parityUserID, parityUsername)
	require.NoError(t, err)
	require.NoError(t, method.ConfirmEnrolment(t.Context(), parityUserID,
		must.Must(totp.GenerateCode(provisioning.Secret, time.Now()))))

	registry := must.Must(oidc.NewRegistry(oidc.Provider{
		Name: "corp", Issuer: "https://idp.example", ClientID: "c", ClientSecret: "s",
		RedirectURL:           "https://app.example/sso/callback/corp",
		AuthorizationEndpoint: "https://idp.example/authorize",
		TokenEndpoint:         "https://idp.example/token",
		JWKSURI:               "https://idp.example/jwks",
	}))
	relyingParty := must.Must(oidc.NewRelyingParty(registry,
		must.Must(oidc.NewBroker(oidc.NewMemoryLinkStore(), parityUsers{}))))
	handoffs := must.Must(oidc.NewHandoff(oidc.NewMemoryHandoffStore(), parityUsers{}))

	live, err := sessions.Create(t.Context(), parityUserID)
	require.NoError(t, err)

	bearer, err := gen.Generate(t.Context(), live.ID, identity.PrincipalFromDetails(parityUsers{}.details()))
	require.NoError(t, err)

	// A second session owing its second factor, which is what the verify
	// endpoint serves; a session that owes none is refused before the method
	// is read.
	owing, err := sessions.Create(t.Context(), parityUserID, session.WithFirstFactor(factor.Password))
	require.NoError(t, err)

	owing.MFA = session.MFAPending
	require.NoError(t, sessions.Save(t.Context(), owing))

	pendingToken, err := gen.Generate(t.Context(), owing.ID, identity.PrincipalFromDetails(parityUsers{}.details()))
	require.NoError(t, err)

	problems, err := prblmsec.New()
	require.NoError(t, err)

	opts := []prblm.Option{prblm.WithNamespace("/probs"), problems.Option()}

	return &parityWorld{
		options: []httpsec.Option{
			httpsec.EnableFormLogin(httpsec.FormLoginDeps{
				Authenticator: parityAuthenticator{}, Sessions: sessions, Tokens: gen, Attempts: attempts,
			}),
			httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{Authenticator: parityAuthenticator{}, Attempts: attempts}),
			httpsec.EnableBearerToken(httpsec.BearerTokenDeps{Verifier: gen, Sessions: sessions, Users: parityUsers{}}),
			httpsec.EnableDPoP(httpsec.DPoP{
				PublicURL: parityOrigin, Nonce: true,
				NonceCipher:   seal.SessionCipher(must.Must(seal.NewAEADCipher(keyring))),
				NonceLifetime: httpsec.MinDPoPNonceLifetime,
			}),
			httpsec.WithPolicyEngine(engine),
			httpsec.EnableMFA([]mfa.Method{method}, httpsec.WithMFATokens(gen)),
			httpsec.EnableOIDCLogin(httpsec.OIDCDeps{RelyingParty: relyingParty, Handoff: handoffs},
				httpsec.WithOIDCTokens(gen), httpsec.WithOIDCSessions(sessions)),
			httpsec.EnableAuthorization(parityAuthorizer{},
				authorize.Rule[httpsec.Request]{
					Match:   func(r httpsec.Request) bool { return r.Path() == paritySecuredPath },
					Require: authorize.Authenticated(),
				},
				authorize.Rule[httpsec.Request]{
					Match:   func(httpsec.Request) bool { return true },
					Require: authorize.PermitAll(),
				}),
		},
		bearer:  "Bearer " + bearer,
		pending: "Bearer " + pendingToken,
		key:     newParityDPoPKey(t),
		problem: problems,
		prblm:   opts,
		handler: prblm.NewHandler(opts...),
	}
}

func (w *parityWorld) chain(t *testing.T, extra ...httpsec.Option) *httpsec.Chain {
	t.Helper()

	chain, err := httpsec.New(append(slices.Clone(w.options), extra...)...)
	require.NoError(t, err)

	return chain
}

// A parityServer answers one request through one framework.
type parityServer func(t *testing.T, req httpsecconformance.RequestSpec) parityResponse

func okHandler(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }

// nethttpParityServer is the net/http deployment: the chain's and the guards'
// error handlers are the prblm handler's Write.
func nethttpParityServer(t *testing.T, w *parityWorld) parityServer {
	t.Helper()

	chain := w.chain(t, httpsec.WithErrorHandler(w.handler.Write))

	guards, err := httpsec.NewGuards(parityAuthorizer{}, httpsec.WithGuardErrorHandler(w.handler.Write))
	require.NoError(t, err)

	guarded := func(resource string) http.Handler {
		return guards.ResourcePrivileges("records", resource).RequireOne("read")(http.HandlerFunc(okHandler))
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET "+paritySecuredPath, okHandler)
	mux.HandleFunc("GET "+parityBoomPath, func(rw http.ResponseWriter, r *http.Request) {
		w.handler.Write(rw, r, errParityBoom)
	})
	mux.Handle("GET "+parityDeniedPath, guarded("denied"))
	mux.Handle("GET "+parityMissingPath, guarded("missing"))

	handler := chain.Middleware()(mux)

	return func(t *testing.T, req httpsecconformance.RequestSpec) parityResponse {
		t.Helper()

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, nethttpRequest(t, req))

		return parityResponse{rec.Code, rec.Header(), rec.Body.String()}
	}
}

// ginMode is how a gin deployment is wired.
type ginMode int

const (
	// ginRendered is the full wiring: ginprblm ahead of the chain and
	// WithRefusalsRendered declared.
	ginRendered ginMode = iota
	// ginProblemsOnly mounts ginprblm ahead of the chain without declaring
	// WithRefusalsRendered.
	ginProblemsOnly
	// ginNoRenderer mounts the chain on its own, which is gin as the library
	// leaves it by default: no error middleware and no option.
	ginNoRenderer
)

func (m ginMode) String() string {
	switch m {
	case ginRendered:
		return "gin rendered"
	case ginProblemsOnly:
		return "gin ginprblm without the option"
	default:
		return "gin no renderer"
	}
}

// ginParityServer is the gin deployment wired as mode says.
func ginParityServer(t *testing.T, w *parityWorld, mode ginMode) parityServer {
	t.Helper()

	var opts []ginsec.Option
	if mode == ginRendered {
		opts = append(opts, ginsec.WithRefusalsRendered())
	}

	guards, err := ginsec.NewGuards(parityAuthorizer{})
	require.NoError(t, err)

	engine := gin.New()
	if mode != ginNoRenderer {
		engine.Use(ginprblm.Middleware(w.prblm...))
	}

	engine.Use(ginsec.Middleware(w.chain(t), opts...))
	engine.GET(paritySecuredPath, func(gc *gin.Context) { gc.Status(http.StatusOK) })
	engine.GET(parityBoomPath, func(gc *gin.Context) { _ = gc.Error(errParityBoom) })
	engine.GET(parityDeniedPath, guards.ResourcePrivileges("records", "denied").RequireOne("read"),
		func(gc *gin.Context) { gc.Status(http.StatusOK) })
	engine.GET(parityMissingPath, guards.ResourcePrivileges("records", "missing").RequireOne("read"),
		func(gc *gin.Context) { gc.Status(http.StatusOK) })

	return func(t *testing.T, req httpsecconformance.RequestSpec) parityResponse {
		t.Helper()

		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, nethttpRequest(t, req))

		return parityResponse{rec.Code, rec.Header(), rec.Body.String()}
	}
}

// fiberParityServer is the fiber deployment.
func fiberParityServer(t *testing.T, w *parityWorld) parityServer {
	t.Helper()

	guards, err := fibersec.NewGuards(parityAuthorizer{})
	require.NoError(t, err)

	app := fiber.New(fiber.Config{ErrorHandler: fiberprblm.ErrorHandler(w.prblm...)})
	app.Use(fibersec.Middleware(w.chain(t)))
	app.Get(paritySecuredPath, func(fc fiber.Ctx) error { return fc.SendStatus(http.StatusOK) })
	app.Get(parityBoomPath, func(fiber.Ctx) error { return errParityBoom })
	app.Get(parityDeniedPath, guards.ResourcePrivileges("records", "denied").RequireOne("read"),
		func(fc fiber.Ctx) error { return fc.SendStatus(http.StatusOK) })
	app.Get(parityMissingPath, guards.ResourcePrivileges("records", "missing").RequireOne("read"),
		func(fc fiber.Ctx) error { return fc.SendStatus(http.StatusOK) })

	return func(t *testing.T, req httpsecconformance.RequestSpec) parityResponse {
		t.Helper()

		status, header, body := fiberServeFrom(t, app, nethttpRequest(t, req), net.JoinHostPort(parityPeer, "54321"))

		return parityResponse{status, header, body}
	}
}

// parityOutcome is a response reduced to what must be equal across
// frameworks. Per-request values are compared by presence: an access token is
// signed per request and a DPoP nonce is sealed per request, so two servers
// never issue the same one, and what must agree is that both carry one.
type parityOutcome struct {
	status        int
	contentType   []string
	wwwAuth       []string
	cacheControl  []string
	hasDPoPNonce  bool
	hasAccessTkn  bool
	problemFields map[string]any
}

func outcomeOf(t *testing.T, r parityResponse) parityOutcome {
	t.Helper()

	doc := r.problem(t)
	_, hasToken := doc["access_token"]
	delete(doc, "access_token")

	return parityOutcome{
		status:        r.status,
		contentType:   r.header.Values("Content-Type"),
		wwwAuth:       slices.Sorted(slices.Values(r.header.Values("WWW-Authenticate"))),
		cacheControl:  r.header.Values("Cache-Control"),
		hasDPoPNonce:  r.header.Get("DPoP-Nonce") != "",
		hasAccessTkn:  hasToken,
		problemFields: doc,
	}
}

type parityRequestFunc func(t *testing.T, w *parityWorld) httpsecconformance.RequestSpec

func parityGet(path string, header map[string]string) parityRequestFunc {
	return func(*testing.T, *parityWorld) httpsecconformance.RequestSpec {
		return httpsecconformance.RequestSpec{
			Method: http.MethodGet, Path: path, Header: header, ClientAddress: parityPeer,
		}
	}
}

func parityPost(path string, header map[string]string, body string) parityRequestFunc {
	return func(*testing.T, *parityWorld) httpsecconformance.RequestSpec {
		return httpsecconformance.RequestSpec{
			Method: http.MethodPost, Path: path, Header: header, Body: body, ClientAddress: parityPeer,
		}
	}
}

func parityLogin() parityRequestFunc {
	return parityPost(httpsec.DefaultLoginPath,
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
		"username="+parityUsername+"&password="+parityPassword)
}

func countPrefix(values []string, prefix string) int {
	var n int

	for _, v := range values {
		if strings.HasPrefix(v, prefix) {
			n++
		}
	}

	return n
}

func TestProblemParity(t *testing.T) {
	t.Parallel()

	const typePrefix = "/probs/security/"

	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte(parityUsername+":wrong"))
	unknownProvider := parityGet(httpsec.DefaultOIDCAuthorizePath+"nope", nil)
	unknownMethod := func(t *testing.T, w *parityWorld) httpsecconformance.RequestSpec {
		return parityPost(httpsec.DefaultMFAVerifyPrefix+"/nope",
			map[string]string{"Authorization": w.pending}, "")(t, w)
	}

	notFound := func(t *testing.T, r parityResponse) {
		assert.Equal(t, http.StatusNotFound, r.status)
		assert.Equal(t, typePrefix+"not-found", r.problem(t)["type"])
	}

	type testCase struct {
		name    string
		request parityRequestFunc

		// ginOnly runs the case on gin deployments wired in these modes, and on
		// nothing else.
		ginOnly []ginMode

		// extraGin adds gin deployments wired in these modes to the three
		// framework servers, and each must answer as net/http does.
		extraGin []ginMode

		// withProof makes the request carry a DPoP proof without a nonce.
		withProof bool

		// assert is what every framework's own answer must be, so three
		// servers that agree on a wrong answer do not pass.
		assert func(t *testing.T, r parityResponse)
	}

	cases := []testCase{
		{
			name:    "unauthenticated",
			request: parityGet(paritySecuredPath, nil),
			assert: func(t *testing.T, r parityResponse) {
				assert.Equal(t, http.StatusUnauthorized, r.status)
				assert.Equal(t, typePrefix+"authentication-required", r.problem(t)["type"])
				assert.NotEmpty(t, r.header.Values("WWW-Authenticate"), "the chain's challenge is kept")
			},
		},
		{
			name:    "challenged password login",
			request: parityLogin(),
			assert: func(t *testing.T, r parityResponse) {
				doc := r.problem(t)
				assert.Equal(t, http.StatusUnauthorized, r.status)
				assert.Equal(t, typePrefix+"mfa-required", doc["type"])
				assert.Equal(t, "mfa", doc["challenge"])
				assert.NotEmpty(t, doc["access_token"], "the token the prompt is answered with is delivered")
				assert.Equal(t, []string{"no-store"}, r.header.Values("Cache-Control"))
			},
		},
		{
			name:    "basic failure",
			request: parityGet(paritySecuredPath, map[string]string{"Authorization": basic}),
			assert: func(t *testing.T, r parityResponse) {
				assert.Equal(t, http.StatusUnauthorized, r.status)
				assert.Equal(t, typePrefix+"authentication-failed", r.problem(t)["type"])
				assert.Equal(t, 1, countPrefix(r.header.Values("WWW-Authenticate"), "Basic"),
					"WWW-Authenticate: Basic appears exactly once: %v", r.header.Values("WWW-Authenticate"))
			},
		},
		{
			name:      "dpop nonce",
			withProof: true,
			request:   parityLogin(),
			assert: func(t *testing.T, r parityResponse) {
				assert.Equal(t, http.StatusUnauthorized, r.status)
				assert.Len(t, r.header.Values("DPoP-Nonce"), 1, "the nonce the client must retry with is kept")
				assert.NotEmpty(t, r.header.Get("DPoP-Nonce"))
				assert.Equal(t, 1, countPrefix(r.header.Values("WWW-Authenticate"), "DPoP"),
					"the DPoP challenge is kept once: %v", r.header.Values("WWW-Authenticate"))
			},
		},
		{
			name:    "unknown handler error",
			request: parityGet(parityBoomPath, nil),
			assert: func(t *testing.T, r parityResponse) {
				assert.Equal(t, http.StatusInternalServerError, r.status)
				doc := r.problem(t)
				assert.Nil(t, doc["type"], "prblm omits the about:blank type")
				assert.EqualValues(t, http.StatusInternalServerError, doc["status"])
				assert.NotContains(t, r.body, "sk-live-123", "the error text never reaches the client")
			},
		},
		{
			name: "unknown identity provider", request: unknownProvider, assert: notFound,
			extraGin: []ginMode{ginProblemsOnly},
		},
		{
			name: "unknown MFA method", request: unknownMethod, assert: notFound,
			extraGin: []ginMode{ginProblemsOnly},
		},
		{
			name: "unknown identity provider, gin with no renderer", request: unknownProvider,
			ginOnly: []ginMode{ginNoRenderer},
			assert: func(t *testing.T, r parityResponse) {
				assert.Equal(t, http.StatusNotFound, r.status)
				assert.Empty(t, r.body, "the default is the bare status")
			},
		},
		{
			name: "unknown MFA method, gin with no renderer", request: unknownMethod,
			ginOnly: []ginMode{ginNoRenderer},
			assert: func(t *testing.T, r parityResponse) {
				assert.Equal(t, http.StatusNotFound, r.status)
				assert.Empty(t, r.body, "the default is the bare status")
			},
		},
		{
			name: "not-found refusal from a guard on a consumer route",
			request: func(t *testing.T, w *parityWorld) httpsecconformance.RequestSpec {
				return parityGet(parityMissingPath, map[string]string{"Authorization": w.bearer})(t, w)
			},
			assert: notFound,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			serve := func(t *testing.T, build func(*parityWorld) parityServer) parityResponse {
				t.Helper()

				w := newParityWorld(t)
				req := tc.request(t, w)

				if tc.withProof {
					req.Header = map[string]string{
						"Content-Type": "application/x-www-form-urlencoded",
						"DPoP":         w.key.proof(t, req.Method, req.Path),
					}
				}

				return build(w)(t, req)
			}

			if len(tc.ginOnly) > 0 {
				for _, mode := range tc.ginOnly {
					got := serve(t, func(w *parityWorld) parityServer { return ginParityServer(t, w, mode) })
					tc.assert(t, got)
				}

				return
			}

			answers := map[string]parityResponse{
				"net/http": serve(t, func(w *parityWorld) parityServer { return nethttpParityServer(t, w) }),
				"gin":      serve(t, func(w *parityWorld) parityServer { return ginParityServer(t, w, ginRendered) }),
				"fiber":    serve(t, func(w *parityWorld) parityServer { return fiberParityServer(t, w) }),
			}

			compared := []string{"gin", "fiber"}

			for _, mode := range tc.extraGin {
				name := mode.String()
				answers[name] = serve(t, func(w *parityWorld) parityServer { return ginParityServer(t, w, mode) })
				compared = append(compared, name)
			}

			for name, got := range answers {
				t.Run(name, func(t *testing.T) { tc.assert(t, got) })
			}

			reference := outcomeOf(t, answers["net/http"])
			for _, name := range compared {
				assert.Equal(t, reference, outcomeOf(t, answers[name]),
					"%s answers differently from net/http", name)
			}
		})
	}
}

func TestProblemParity_GuardRefusal(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		path   string
		err    error
		assert func(t *testing.T, r parityResponse)
	}

	cases := []testCase{
		{
			name: "a privilege guard refusing",
			path: parityDeniedPath,
			err:  authorize.ErrAccessDenied,
			assert: func(t *testing.T, r parityResponse) {
				assert.Equal(t, http.StatusForbidden, r.status)
				assert.Equal(t, "/probs/security/access-denied", r.problem(t)["type"])
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Each server has its own signing keys, so each is sent a token its own
			// world issued.
			serve := func(build func(*parityWorld) parityServer) parityResponse {
				w := newParityWorld(t)

				return build(w)(t, httpsecconformance.RequestSpec{
					Method: http.MethodGet, Path: tc.path, ClientAddress: parityPeer,
					Header: map[string]string{"Authorization": w.bearer},
				})
			}

			// The chain's problem for the same error: what the handler writes
			// when the chain itself refuses with it.
			rec := httptest.NewRecorder()
			newParityWorld(t).handler.Write(rec,
				httptest.NewRequestWithContext(t.Context(), http.MethodGet, tc.path, nil), tc.err)
			chainProblem := parityResponse{rec.Code, rec.Header(), rec.Body.String()}
			tc.assert(t, chainProblem)

			answers := map[string]parityResponse{
				"net/http": serve(func(w *parityWorld) parityServer { return nethttpParityServer(t, w) }),
				"gin":      serve(func(w *parityWorld) parityServer { return ginParityServer(t, w, ginRendered) }),
				"fiber":    serve(func(w *parityWorld) parityServer { return fiberParityServer(t, w) }),
			}

			for name, got := range answers {
				t.Run(name, func(t *testing.T) {
					tc.assert(t, got)
					assert.Equal(t, outcomeOf(t, chainProblem).problemFields, outcomeOf(t, got).problemFields,
						"the guard's problem is the chain's for the same error")
				})
			}
		})
	}
}
