package httpsec_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/apikey"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/magiclink"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/expiry"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/notify"
	"github.com/kartaladev/scrty/outbound"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
	"github.com/kartaladev/scrty/token/onetime"
)

// stubRequest and stubWriter stand in for a framework's request and response
// wherever a test needs an exchange but not a real transport. They are the
// smallest thing that satisfies the ports, so a test that cares about one
// accessor leaves the rest zero.
type stubRequest struct {
	method, path string
	headers      map[string]string
	query        map[string]string
	cookies      map[string]string
	form         map[string]string
	body         []byte
	clientIP     string
}

func (r stubRequest) Method() string            { return r.method }
func (r stubRequest) Path() string              { return r.path }
func (r stubRequest) Header(n string) string    { return r.headers[n] }
func (r stubRequest) Query(n string) string     { return r.query[n] }
func (r stubRequest) FormValue(n string) string { return r.form[n] }

// QueryValues answers from the single-valued query map, so a stub never sends
// a parameter twice.
func (r stubRequest) QueryValues(n string) []string {
	v, ok := r.query[n]
	if !ok {
		return nil
	}
	return []string{v}
}
func (r stubRequest) ClientIP() string { return r.clientIP }

func (r stubRequest) Cookie(n string) (string, bool) {
	v, ok := r.cookies[n]
	return v, ok
}

func (r stubRequest) Body(limit int64) ([]byte, error) {
	if int64(len(r.body)) > limit {
		return nil, httpsec.ErrRequestTooLarge
	}
	return r.body, nil
}

type stubWriter struct {
	header http.Header
	status int
	body   []byte
	cookie []*httpsec.Cookie
}

func (w *stubWriter) SetHeader(n, v string) {
	if w.header == nil {
		w.header = http.Header{}
	}
	w.header.Set(n, v)
}

func (w *stubWriter) SetCookie(c *httpsec.Cookie) { w.cookie = append(w.cookie, c) }
func (w *stubWriter) WriteHeader(s int)           { w.status = s }

func (w *stubWriter) Write(b []byte) (int, error) {
	w.body = append(w.body, b...)
	return len(b), nil
}

type ctxKey string

// runExpiryTask runs the task of tasks with the given name.
func runExpiryTask(t *testing.T, tasks []expiry.Task, name string) (int, error) {
	t.Helper()

	for _, task := range tasks {
		if task.Name == name {
			return task.Run(t.Context())
		}
	}
	require.Failf(t, "no such task", "%q not among %v", name, expiryTaskNames(tasks))

	return 0, nil
}

// errChangeRefused is what a consumer's change-password function refuses with,
// so a test can assert the chain returned that error and not one of its own.
var errChangeRefused = errors.New("passwordchange_test: the new password is too weak")

// jsonDocument is a valid JSON document of exactly size bytes.
func jsonDocument(size int) string {
	const open, closing = `{"assertion":"`, `"}`

	return open + strings.Repeat("a", size-len(open)-len(closing)) + closing
}

const day = 24 * time.Hour

// sessionBearerDeps is what EnableSessionBearer is handed for this harness.
func (h *authHarness) sessionBearerDeps() httpsec.SessionBearerDeps {
	return httpsec.SessionBearerDeps{Sessions: h.sessions, Users: h.users}
}

// otherManager is a session manager over a store of its own, standing in for
// the manager a built-in was wired to when it is not the chain's.
func otherManager(t *testing.T, f resolveFixture) *session.Sessions {
	t.Helper()

	m, err := session.New(session.WithClock(f.clk), session.WithStore(
		session.NewMemoryStore(session.WithMemoryStoreClock(f.clk))))
	require.NoError(t, err)

	return m
}

// basicRequest builds a request carrying the credential as a client would, and
// rawBasicRequest one carrying whatever a test wants after the prefix.
func basicRequest(ctx context.Context, username, password string) *http.Request {
	return rawBasicRequest(ctx, "Basic "+
		base64.StdEncoding.EncodeToString([]byte(username+":"+password)))
}

func rawBasicRequest(ctx context.Context, header string) *http.Request {
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/orders", nil)
	if header != "" {
		req.Header.Set("Authorization", header)
	}

	return req
}

// switchableUser is the user record a user loader answers with, which a case
// changes between requests to disable, re-enable or replace the user.
type switchableUser struct {
	current atomic.Pointer[identity.Details]
}

// set makes d what the loader answers with from now on.
func (u *switchableUser) set(d *identity.Details) { u.current.Store(d) }

// loader is a user loader answering every lookup, by username or by user
// reference, with a copy of the record u currently holds, or with neither a
// user nor an error once u was set to nil.
func (u *switchableUser) loader(t *testing.T) *MockUserLoader {
	t.Helper()

	answer := func() (*identity.Details, error) {
		current := u.current.Load()
		if current == nil {
			return nil, nil //nolint:nilnil // a loader that finds no user and reports no error is the case under test
		}

		d := *current

		return &d, nil
	}

	users := NewMockUserLoader(gomock.NewController(t))
	users.EXPECT().LoadByUsername(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(context.Context, string) (*identity.Details, error) { return answer() })
	users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(context.Context, identity.UserID) (*identity.Details, error) { return answer() })

	return users
}

// userActive is storedUser, u-1, active or disabled.
func userActive(active bool) *identity.Details {
	d := storedUser()
	d.Active = active

	return d
}

// otherUser is an active u-2 under u-1's username: the username reassigned.
func otherUser() *identity.Details {
	d := storedUser()
	d.ID = "u-2"

	return d
}

// The identifiers the bearer tests share. The session identifier is the
// token's jti, so one constant names both.
const (
	testJTI     = "sess-0123456789abcdef"
	testSubject = "ada"
)

func bearerRequest(ctx context.Context, header string) *http.Request {
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/orders", nil)
	if header != "" {
		req.Header.Set("Authorization", header)
	}

	return req
}

// liveSession is a session the store hands back for testJTI.
func liveSession() *session.Session {
	now := time.Now()

	return &session.Session{
		ID:                testJTI,
		UserID:            "u-1",
		CreatedAt:         now,
		LastAccessedAt:    now,
		IdleExpiresAt:     now.Add(30 * time.Minute),
		AbsoluteExpiresAt: now.Add(12 * time.Hour),
		FirstFactor:       factor.Password,
		FamilyID:          id.ID{1},
	}
}

// storedUser is what the user loader returns. Its role is deliberately one no
// claim carries, so a test can tell a reloaded principal from one assembled
// out of the token.
func storedUser() *identity.Details {
	return &identity.Details{
		ID:       "u-1",
		Name:     "Ada Lovelace",
		Username: testSubject,
		Active:   true,
		Roles: []*identity.AssignedRole{
			{ID: "r-admin", Name: "administrator", Primary: true},
		},
	}
}

// expectVerified wires the verifier to accept any token as testSubject's, on
// the session testJTI.
func (h *authHarness) expectVerified() {
	h.verifier.EXPECT().Verify(gomock.Any(), gomock.Any()).
		Return(token.NewClaims(testSubject, testJTI), nil).AnyTimes()
}

// expectLiveSessionAndUser wires the whole resolution a valid token drives.
func (h *authHarness) expectLiveSessionAndUser(s *session.Session) {
	h.store.EXPECT().Load(gomock.Any(), testJTI).Return(s, nil)
	h.users.EXPECT().LoadByUsername(gomock.Any(), testSubject).Return(storedUser(), nil)
	h.acceptsActivityWriteBack()
}

// serveBearer builds a chain with bearer authentication enabled and runs one
// request through it.
func serveBearer(
	t *testing.T,
	h *authHarness,
	e *policy.Engine,
	req *http.Request,
	opts ...httpsec.BearerTokenOption,
) served {
	t.Helper()

	return serveBearerOn(t, h, e, req, nil, opts...)
}

// serveBearerOn is serveBearer with further chain options, such as something
// to enforce the challenge the engine raises.
func serveBearerOn(
	t *testing.T,
	h *authHarness,
	e *policy.Engine,
	req *http.Request,
	extra []httpsec.Option,
	opts ...httpsec.BearerTokenOption,
) served {
	t.Helper()

	chainOpts := []httpsec.Option{
		httpsec.WithLogger(h.logger()),
		httpsec.EnableBearerToken(h.bearerTokenDeps(), opts...),
	}
	if e != nil {
		chainOpts = append(chainOpts, httpsec.WithPolicyEngine(e))
	}

	chain, err := httpsec.New(append(chainOpts, extra...)...)
	require.NoError(t, err)

	return serve(t, chain, req)
}

// guardThrottledMsg is the record a source guard writes for a source over its
// limit: the one throttled-source record a refused attempt produces.
const guardThrottledMsg = "ratelimit: refusing an attempt from a source over its limit"

// presentUnknownKey sends an unknown API key from addr, which may be IPv6, and
// reports whether the attempt reached the key store; a throttled source is
// refused before it does.
func presentUnknownKey(t *testing.T, h *apiKeyHarness, c *httpsec.Chain, addr string) (reachedStore bool) {
	t.Helper()

	before := h.store.reads.Load()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/invoices", nil)
	req.RemoteAddr = net.JoinHostPort(addr, "51000")
	req.Header.Set("Authorization", httpsec.DefaultAPIKeyScheme+unknownAPIKey)

	out := serve(t, c, req)
	require.Error(t, out.err, "an unknown key never authenticates")

	return h.store.reads.Load() > before
}

// limiterAsked is one limiter a flow asks the chain's factory for.
type limiterAsked struct {
	namespace string
	limit     int
	window    time.Duration
}

// declaring is a consumer's own challenging policy: it declares the kinds it
// can raise and is asked per request, which is all the assembly check reads.
type declaring struct{ kinds []policy.ChallengeKind }

func (declaring) Name() string { return "chain_test: declaring" }

func (declaring) Phases() []policy.Phase { return []policy.Phase{policy.PerRequest} }

func (d declaring) Challenges() []policy.ChallengeKind { return slices.Clone(d.kinds) }

func (declaring) Evaluate(context.Context, *policy.Input) policy.Decision {
	return policy.Decision{Outcome: policy.Allow}
}

// everyoneRequired is a requirement lookup under which every user must use a
// second factor.
type everyoneRequired struct{}

func (everyoneRequired) Required(context.Context, identity.UserID) (bool, error) { return true, nil }

// passThroughAt occupies the slot at with an interceptor that only passes the
// request on. It does not make the slot's challenge kind count as enforced —
// only the built-in gate does, which is what the rows using it pin; a test
// that needs the kind enforced records the gate with EnableGateForTest.
func passThroughAt(at httpsec.Order) httpsec.Option {
	return httpsec.RegisterInterceptor(httpsec.InterceptorFunc(
		func(ex *httpsec.Exchange, next httpsec.Next) error { return next(ex) }), at)
}

// raisingDeclared is a policy that declares kind and raises it in phase, the
// shape of a policy the assembly check would have refused had it been
// registered in time.
type raisingDeclared struct {
	kind  policy.ChallengeKind
	phase policy.Phase
}

func (raisingDeclared) Name() string { return "chain_test: raising declared" }

func (r raisingDeclared) Phases() []policy.Phase { return []policy.Phase{r.phase} }

func (r raisingDeclared) Challenges() []policy.ChallengeKind { return []policy.ChallengeKind{r.kind} }

func (r raisingDeclared) Evaluate(context.Context, *policy.Input) policy.Decision {
	return policy.Decision{Outcome: policy.Challenge, Challenge: r.kind}
}

// enrollableLookup is a method lookup that reports it supports the enrolment
// path, as the library's own TOTP does over a store that can hold its proofs.
// The requirement policy admits a login to the path only over such a method.
type enrollableLookup struct{ policy.MFAMethodLookup }

func (enrollableLookup) SupportsEnrolmentPath() bool { return true }

// enableMFAFor is EnableMFA wired to everything it needs, so a case that is
// about the assembly check is not about the MFA options.
func enableMFAFor(t *testing.T) httpsec.Option {
	t.Helper()

	ctrl := gomock.NewController(t)

	method := NewMockMethod(ctrl)
	method.EXPECT().Name().Return("totp").AnyTimes()
	method.EXPECT().Response().Return(mfa.FormField("code", 4<<10)).AnyTimes()
	method.EXPECT().Channel().Return(factor.AuthenticatorApp).AnyTimes()
	method.EXPECT().Enrolled(gomock.Any(), gomock.Any()).Return(true, nil).AnyTimes()

	return httpsec.EnableMFA([]mfa.Method{method}, httpsec.WithMFATokens(NewMockGenerator(ctrl)))
}

// flushSource is the client address every guarded refusal in these tests comes
// from, so one source's refusals share one sampling key.
const flushSource = "198.51.100.23"

// summaries returns the suppressed count of every record in recs written with
// msg and, when attr is non-empty, whose attribute attr equals value.
func summaries(t *testing.T, recs []slog.Record, msg, attr, value string) []int64 {
	t.Helper()

	var counts []int64

	for _, r := range recs {
		if r.Message != msg {
			continue
		}

		if attr != "" {
			v, ok := attrValue(r, attr)
			if !ok || v.String() != value {
				continue
			}
		}

		counts = append(counts, suppressedCount(t, r))
	}

	return counts
}

// guardSummaries returns the suppressed count of every summary in recs that a
// source guard the chain built reported for flow. A chain-built guard reports
// through the chain's reporter, so its summaries are the chain's summary
// record, told apart by a key naming the flow between the separators the guard
// joins its sampler keys with.
func guardSummaries(t *testing.T, recs []slog.Record, flow string) []int64 {
	t.Helper()

	var counts []int64

	for _, r := range recs {
		if r.Message != summaryChain {
			continue
		}

		if key, ok := attrValue(r, "key"); ok && strings.Contains(key.String(), ":"+flow+":") {
			counts = append(counts, suppressedCount(t, r))
		}
	}

	return counts
}

// exceededLimiter is a consumer limiter reporting every source over its limit,
// so every attempt through a guard built over it is refused and sampled.
func exceededLimiter(t *testing.T) *MockLimiter {
	t.Helper()

	l := NewMockLimiter(gomock.NewController(t))
	l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(true, nil).AnyTimes()
	l.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	return l
}

// guardRun is what putting one request through a guard produced.
type guardRun struct {
	rec      *httptest.ResponseRecorder
	routeRan bool

	// refusal is what the guard handed its error handler, and nil when the
	// guard let the request through.
	refusal error
}

// guardRequest builds the request a guard judges: a GET of one record, carrying
// the principal and the authorizer the caller wants published on it.
func guardRequest(t *testing.T, p *identity.Principal, az authorize.Authorizer) *http.Request {
	t.Helper()

	ctx := t.Context()
	if p != nil {
		ctx = identity.WithPrincipal(ctx, p)
	}
	if az != nil {
		ctx = authorize.WithAuthorizer(ctx, az)
	}

	return httptest.NewRequestWithContext(ctx, http.MethodGet, "/records/r-1", nil)
}

// runGuard puts req through mw onto a route that records that it was reached.
func runGuard(t *testing.T, mw func(http.Handler) http.Handler, req *http.Request) guardRun {
	t.Helper()

	out := guardRun{rec: httptest.NewRecorder()}
	route := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { out.routeRan = true })

	mw(route).ServeHTTP(out.rec, req)

	return out
}

// refusingAuthorizer refuses every attempt with err.
func refusingAuthorizer(t *testing.T, err error) *MockAuthorizer {
	t.Helper()

	az := NewMockAuthorizer(gomock.NewController(t))
	az.EXPECT().Authorize(gomock.Any(), gomock.Any()).Return(err).AnyTimes()

	return az
}

// authHarness is the collaborators a first-factor interceptor is wired to,
// each a double so a test says what the store, the authenticator or the policy
// answered without standing up any of them.
//
// It is shared by the form login, Basic and bearer tests because those three
// are wired to overlapping sets of the same collaborators, and one harness
// keeps "what was this test given" in one place per test rather than three.
type authHarness struct {
	authn    *MockAuthenticator
	users    *MockUserLoader
	verifier *MockVerifier
	store    *MockStore
	sessions *session.Sessions
	tokens   *MockGenerator
	attempts *MockAttemptStore

	logs *capturingHandler
}

func newAuthHarness(t *testing.T) *authHarness {
	t.Helper()

	ctrl := gomock.NewController(t)
	store := NewMockStore(ctrl)

	manager, err := session.New(session.WithStore(store))
	require.NoError(t, err)

	return &authHarness{
		authn:    NewMockAuthenticator(ctrl),
		users:    NewMockUserLoader(ctrl),
		verifier: NewMockVerifier(ctrl),
		store:    store,
		sessions: manager,
		tokens:   NewMockGenerator(ctrl),
		attempts: NewMockAttemptStore(ctrl),
		logs:     &capturingHandler{},
	}
}

func (h *authHarness) logger() *slog.Logger { return slog.New(h.logs) }

// expectAuthenticated wires the authenticator to resolve any credentials to p.
func (h *authHarness) expectAuthenticated(p *identity.Principal) {
	h.authn.EXPECT().Authenticate(gomock.Any(), gomock.Any()).
		Return(&authenticate.Authentication{Principal: p, Time: time.Now()}, nil)
}

// expectAuthenticationFailed wires the authenticator to refuse any credentials.
func (h *authHarness) expectAuthenticationFailed() {
	h.authn.EXPECT().Authenticate(gomock.Any(), gomock.Any()).
		Return(nil, authenticate.ErrAuthenticationFailed)
}

// expectSessionOpened wires the store and the generator a successful login
// reaches: one created session, one issued token.
func (h *authHarness) expectSessionOpened(tok string) {
	h.store.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
	h.tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).Return(tok, nil)
}

// basicAuthDeps is what EnableBasicAuth is handed for this harness.
func (h *authHarness) basicAuthDeps() httpsec.BasicAuthDeps {
	return httpsec.BasicAuthDeps{Authenticator: h.authn, Attempts: h.attempts}
}

// bearerTokenDeps is what EnableBearerToken is handed for this harness.
func (h *authHarness) bearerTokenDeps() httpsec.BearerTokenDeps {
	return httpsec.BearerTokenDeps{
		Verifier: h.verifier,
		Sessions: h.sessions,
		Users:    h.users,
	}
}

// formLoginDeps is what EnableFormLogin is handed for this harness.
func (h *authHarness) formLoginDeps() httpsec.FormLoginDeps {
	return httpsec.FormLoginDeps{
		Authenticator: h.authn,
		Sessions:      h.sessions,
		Tokens:        h.tokens,
		Attempts:      h.attempts,
	}
}

// served is what running one request through a chain produced.
type served struct {
	rec        *httptest.ResponseRecorder
	handlerRan bool
	err        error

	// handled is the exchange as the downstream handler saw it, and nil when
	// the handler was never reached. It is what a test reads to assert on the
	// state an interceptor published for the application.
	handled *httpsec.Exchange
}

// serve runs req through chain, recording whether the downstream handler was
// reached. The handler is the application's, so a built-in that answers the
// request itself must not call it.
func serve(t *testing.T, chain *httpsec.Chain, req *http.Request) served {
	t.Helper()

	out := served{rec: httptest.NewRecorder()}
	run := chain.Assemble(func(ex *httpsec.Exchange) error {
		out.handlerRan = true
		out.handled = ex

		return nil
	})

	ex := httpsec.NewExchange(t.Context(),
		httpsec.NewHTTPRequest(req), httpsec.NewHTTPResponseWriter(out.rec))
	out.err = run(ex)

	return out
}

func formRequest(ctx context.Context, path, body string) *http.Request {
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return req
}

func jsonRequest(ctx context.Context, path, body string) *http.Request {
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	return req
}

// loginBody is the default success document, read back the way a client would.
type loginBody struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ValidUntil   time.Time `json:"valid_until"`
}

// denyingIn is an engine that denies with reason in phase and allows elsewhere.
func denyingIn(t *testing.T, phase policy.Phase, reason error) *policy.Engine {
	t.Helper()

	return engineOf(t, phasePolicy(t, policy.Decision{Outcome: policy.Deny, Reason: reason}, phase))
}

// challengingIn is an engine that challenges for kind in phase and allows
// elsewhere.
func challengingIn(t *testing.T, phase policy.Phase, kind policy.ChallengeKind) *policy.Engine {
	t.Helper()

	return engineOf(t, phasePolicy(t,
		policy.Decision{Outcome: policy.Challenge, Challenge: kind}, phase))
}

// recordAt reports the first record written at level with this message, so a
// test asserts on what an operator would actually read.
func recordAt(records []slog.Record, level slog.Level, msg string) (slog.Record, bool) {
	for _, r := range records {
		if r.Level == level && r.Message == msg {
			return r, true
		}
	}

	return slog.Record{}, false
}

func testPrincipal() *identity.Principal {
	return &identity.Principal{ID: "u-1", Username: "ada", Name: "Ada Lovelace"}
}

// policyAnswering is a policy that gives one fixed answer in the
// post-authentication phase, which is how a test says what the phase decided
// without writing a rule of its own.
func policyAnswering(t *testing.T, d policy.Decision) policy.Policy {
	t.Helper()

	p := NewMockPolicy(gomock.NewController(t))
	p.EXPECT().Name().Return("test: fixed answer").AnyTimes()
	p.EXPECT().Phases().Return([]policy.Phase{policy.PostAuthentication}).AnyTimes()
	p.EXPECT().Evaluate(gomock.Any(), gomock.Any()).Return(d).AnyTimes()

	return p
}

func engineOf(t *testing.T, policies ...policy.Policy) *policy.Engine {
	t.Helper()

	e, err := policy.NewEngine(policies...)
	require.NoError(t, err)

	return e
}

func denyingEngine(t *testing.T, reason error) *policy.Engine {
	t.Helper()

	return engineOf(t, policyAnswering(t, policy.Decision{Outcome: policy.Deny, Reason: reason}))
}

func challengingEngine(t *testing.T, kind policy.ChallengeKind) *policy.Engine {
	t.Helper()

	return engineOf(t, policyAnswering(t,
		policy.Decision{Outcome: policy.Challenge, Challenge: kind}))
}

// callLog records the order the login tail's dependencies were called in. The
// order is the whole point of the seam, so the tests pin it rather than the
// outcome alone.
type callLog struct {
	mu    sync.Mutex
	calls []string
}

func (l *callLog) add(name string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.calls = append(l.calls, name)
}

func (l *callLog) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()

	return append([]string(nil), l.calls...)
}

// federatedSession is familiedSession as a federated login would have created
// it: it records the identity provider the login came through.
func federatedSession() *session.Session {
	s := familiedSession()
	s.ExternalProvider = "corp"
	s.ExternalIssuer = "https://idp.example"
	s.ExternalSessionID = "sid-9"

	return s
}

// logoutFormRequest is an authorized logout carrying form, as a browser
// relaying the provider's state would send it.
func logoutFormRequest(ctx context.Context, form url.Values) *http.Request {
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, httpsec.DefaultLogoutPath,
		strings.NewReader(form.Encode()))
	req.Header.Set("Authorization", "Bearer a-token")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return req
}

// testFamily is the family a signed-in session belongs to in these cases.
var testFamily = id.ID{0x01}

// familiedSession is touchableSession as a sign-in's family records it.
func familiedSession() *session.Session {
	s := touchableSession()
	s.FamilyID = testFamily

	return s
}

// nilInterceptor exists so a test can hand RegisterInterceptor an interface
// that is not nil but holds a nil pointer.
type nilInterceptor struct{}

func (*nilInterceptor) Intercept(ex *httpsec.Exchange, next httpsec.Next) error { return next(ex) }

// capturingHandler keeps every record written through it, so a test asserts on
// the records themselves rather than on formatted text.
type capturingHandler struct {
	mu   sync.Mutex
	recs []slog.Record
}

func (h *capturingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *capturingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.recs = append(h.recs, r.Clone())

	return nil
}

func (h *capturingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h *capturingHandler) WithGroup(string) slog.Handler { return h }

func (h *capturingHandler) records() []slog.Record {
	h.mu.Lock()
	defer h.mu.Unlock()

	return append([]slog.Record(nil), h.recs...)
}

// attrValue reads one attribute off a record, reporting whether it was there at
// all — an attribute that is absent and one that is zero are different claims.
func attrValue(r slog.Record, name string) (slog.Value, bool) {
	var (
		v     slog.Value
		found bool
	)

	r.Attrs(func(a slog.Attr) bool {
		if a.Key == name {
			v, found = a.Value, true

			return false
		}

		return true
	})

	return v, found
}

// throttledRecords returns the throttled-source records among recs.
func throttledRecords(recs []slog.Record) []slog.Record {
	var out []slog.Record

	for _, r := range recs {
		if r.Message == guardThrottledMsg {
			out = append(out, r)
		}
	}

	return out
}

// renewalSetup is what a renewal case varies about its fixture.
type renewalSetup struct {
	// recovery turns the manager's unused-successor recovery on.
	recovery bool

	// defaultSessions leaves SessionRenewalDeps.Sessions nil, so the endpoint
	// takes the bearer's manager.
	defaultSessions bool

	// withoutRenewal leaves the renewal endpoint off the chain.
	withoutRenewal bool

	// record installs a responder that records every result and writes the
	// credential as the body, with 201.
	record bool

	opts []httpsec.SessionRenewalOption

	// interceptors are consumer interceptors registered on the chain.
	interceptors []httpsec.Option

	// users replaces the default user loader, which answers u-1 active.
	users identity.UserLoader
}

func newRenewalFixture(t *testing.T, setup renewalSetup) *renewalFixture {
	t.Helper()

	f := &renewalFixture{
		clk:  clockwork.NewFakeClockAt(time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)),
		logs: &lockedBuffer{},
	}
	logger := slog.New(slog.NewTextHandler(f.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Long idle and absolute timeouts, so a session renewed the next day is
	// still stored and only its renewal window has ended.
	managerOpts := []session.Option{
		session.WithClock(f.clk),
		session.WithStore(session.NewMemoryStore(session.WithMemoryStoreClock(f.clk))),
		session.WithLogger(logger),
		session.WithIdleTimeout(7 * 24 * time.Hour),
		session.WithAbsoluteTimeout(30 * 24 * time.Hour),
	}
	if setup.recovery {
		managerOpts = append(managerOpts, session.WithUnusedSuccessorRecovery())
	}

	var err error

	f.sessions, err = session.New(managerOpts...)
	require.NoError(t, err)

	s, err := f.sessions.Create(t.Context(), "u-1", session.WithFirstFactor(factor.Password))
	require.NoError(t, err)

	f.old = s.ID

	users := setup.users
	if users == nil {
		defaults := NewMockUserLoader(gomock.NewController(t))
		defaults.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(storedUser(), nil).AnyTimes()
		users = defaults
	}

	opts := setup.opts
	if setup.record {
		opts = append(opts, httpsec.WithRenewalResponder(f.recordingResponder))
	}

	chainOpts := []httpsec.Option{
		httpsec.WithClock(f.clk),
		httpsec.WithLogger(logger),
		httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: f.sessions, Users: users}),
	}
	if !setup.withoutRenewal {
		deps := httpsec.SessionRenewalDeps{Sessions: f.sessions, Users: users}
		if setup.defaultSessions {
			deps.Sessions = nil
		}

		chainOpts = append(chainOpts, httpsec.EnableSessionRenewal(deps, opts...))
	}

	chainOpts = append(chainOpts, setup.interceptors...)

	f.chain, err = httpsec.New(chainOpts...)
	require.NoError(t, err)

	return f
}

// resolveFixture is a session manager over the memory store on a fake clock,
// and a session created in it ten minutes before the request.
type resolveFixture struct {
	start    time.Time
	clk      *clockwork.FakeClock
	sessions *session.Sessions
	session  *session.Session
}

func newResolveFixture(t *testing.T) resolveFixture {
	t.Helper()

	start := time.Date(2026, 9, 26, 9, 0, 0, 0, time.UTC)
	clk := clockwork.NewFakeClockAt(start)

	// The store judges expiry by the manager's clock, so deadlines drawn from
	// the fake clock are read against it.
	sessions, err := session.New(session.WithClock(clk), session.WithStore(
		session.NewMemoryStore(session.WithMemoryStoreClock(clk))))
	require.NoError(t, err)

	s, err := sessions.Create(t.Context(), "u-1", session.WithFirstFactor(factor.Password))
	require.NoError(t, err)

	clk.Advance(10 * time.Minute)

	return resolveFixture{start: start, clk: clk, sessions: sessions, session: s}
}

// consumerAuthenticating is a consumer's own authenticating interceptor: it
// loads the fixture's session, publishes it with the caller through
// PublishSession, and, when evaluate is set, runs the per-request phase
// through EvaluatePerRequest, as a built-in authenticator does.
func consumerAuthenticating(f resolveFixture, evaluate bool) httpsec.Interceptor {
	return httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		s, err := f.sessions.Load(ex.Context(), f.session.ID)
		if err != nil {
			return err
		}

		details := storedUser()
		p := identity.PrincipalFromDetails(details)

		if err := ex.PublishSession(&authenticate.Authentication{
			Principal:         p,
			Time:              f.clk.Now(),
			PasswordChangedAt: details.PasswordChangedAt,
		}, s); err != nil {
			return err
		}

		if evaluate {
			if err := ex.EvaluatePerRequest(s, p); err != nil {
				return err
			}
		}

		return next(ex)
	})
}

// touchableSession is a live session whose idle deadline is well short of the
// manager's idle timeout, so an advance is a visible five-and-twenty minutes
// rather than the nanoseconds between two calls to time.Now.
func touchableSession() *session.Session {
	now := time.Now()

	return &session.Session{
		ID:                testJTI,
		UserID:            "u-1",
		CreatedAt:         now.Add(-time.Hour),
		LastAccessedAt:    now.Add(-25 * time.Minute),
		IdleExpiresAt:     now.Add(5 * time.Minute),
		AbsoluteExpiresAt: now.Add(11 * time.Hour),
		FirstFactor:       factor.Password,
		FamilyID:          id.ID{1},
	}
}

// savedSessions records what the store was asked to persist. Each entry is a
// copy taken at the moment of the call, so a later mutation of the live
// session cannot rewrite what a test observed.
type savedSessions struct {
	mu      sync.Mutex
	records []session.Session
}

func (s *savedSessions) record(v *session.Session) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.records = append(s.records, *v)
}

func (s *savedSessions) all() []session.Session {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]session.Session(nil), s.records...)
}

// expectResolvedSession wires the session and the user a bearer request
// resolves, and deliberately not the write-back: this test's own recorder is
// what the store's Save must reach.
func (h *authHarness) expectResolvedSession(s *session.Session) {
	h.store.EXPECT().Load(gomock.Any(), testJTI).Return(s, nil)
	h.users.EXPECT().LoadByUsername(gomock.Any(), testSubject).Return(storedUser(), nil)
	h.acceptsFirstPresentation()
}

// acceptsFirstPresentation lets the store take the first-presentation mark the
// manager makes on the first load of a never-presented session. It is incidental
// to the tests that use it: its failure never changes what a load answers.
func (h *authHarness) acceptsFirstPresentation() {
	h.store.EXPECT().MarkPresented(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(nil).AnyTimes()
}

// expectSaved wires the store to accept the activity write-back, recording
// what it was handed, and to fail with err when one is given.
func (h *authHarness) expectSaved(saved *savedSessions, err error) {
	h.store.EXPECT().Save(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, s *session.Session) error {
			saved.record(s)

			return err
		}).AnyTimes()
}

// activityWrites records the activity writes the store was asked to make, in
// the order they arrived.
type activityWrites struct {
	mu      sync.Mutex
	records []activityWrite
}

func (a *activityWrites) record(w activityWrite) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.records = append(a.records, w)
}

func (a *activityWrites) all() []activityWrite {
	a.mu.Lock()
	defer a.mu.Unlock()

	return append([]activityWrite(nil), a.records...)
}

// expectActivity wires the store to take the activity write-back, recording
// what it was handed, and to fail with err when one is given.
func (h *authHarness) expectActivity(writes *activityWrites, err error) {
	h.store.EXPECT().RecordActivity(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, id string, lastAccessed, idleExpires, olderThan time.Time) error {
			writes.record(activityWrite{id, lastAccessed, idleExpires, olderThan})

			return err
		}).AnyTimes()
}

// acceptsActivityWriteBack lets the store take the activity write-back the
// chain performs after every request that carried a session through to the
// handler. The write-back is always active, so a test pinning something else
// about such a request still performs one.
func (h *authHarness) acceptsActivityWriteBack() {
	h.store.EXPECT().RecordActivity(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return(nil).AnyTimes()
	h.acceptsFirstPresentation()
}

// denyPolicy denies with no reason at all, which is what a consumer policy
// that refuses without explaining itself looks like to the engine.
type denyPolicy struct{ phase policy.Phase }

func (denyPolicy) Name() string { return "test: reasonless deny" }

func (p denyPolicy) Phases() []policy.Phase { return []policy.Phase{p.phase} }

func (denyPolicy) Evaluate(context.Context, *policy.Input) policy.Decision {
	return policy.Decision{Outcome: policy.Deny}
}

// guardOver builds a real source guard over limiter, which is what every chain
// is wired with, so the tests exercise the same canonicalisation and the same
// refusal shapes production does.
func guardOver(t *testing.T, limiter ratelimit.Limiter) *ratelimit.SourceGuard {
	t.Helper()

	g, err := ratelimit.NewSourceGuard("login", limiter,
		ratelimit.WithSourceGuardLogger(discardLogger()))
	require.NoError(t, err)

	return g
}

func limiterThrottling(t *testing.T) *MockLimiter {
	t.Helper()

	m := NewMockLimiter(gomock.NewController(t))
	m.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(true, nil)

	return m
}

func limiterFailing(t *testing.T) *MockLimiter {
	t.Helper()

	m := NewMockLimiter(gomock.NewController(t))
	m.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(true, errLimiterDown)

	return m
}

// The machine caller these tests authenticate.
const (
	apiKeyPrincipal identity.UserID = "svc-billing"
	apiKeySource    string          = "203.0.113.7"
)

// apiKeyHarness is a real key manager holding one live key, because what is
// being pinned is which requests reach the verification at all.
type apiKeyHarness struct {
	keys  *apikey.Keys
	store *countingStore
	valid string

	keyOpts []httpsec.APIKeyOption
	engine  *policy.Engine
}

func newAPIKeyHarness(t *testing.T) *apiKeyHarness {
	t.Helper()

	store := &countingStore{Store: apikey.NewMemoryStore()}

	keys, err := apikey.New(apikey.WithStore(store))
	require.NoError(t, err)

	presented, _, err := keys.Issue(
		t.Context(), apiKeyPrincipal, "billing", []string{"invoices:read"}, 0)
	require.NoError(t, err)

	// The issuance wrote a record; only what a verification reads is counted.
	store.reads.Store(0)

	return &apiKeyHarness{keys: keys, store: store, valid: presented}
}

func (h *apiKeyHarness) chain(t *testing.T) *httpsec.Chain {
	t.Helper()

	c, err := h.build()
	require.NoError(t, err)

	return c
}

func (h *apiKeyHarness) build() (*httpsec.Chain, error) {
	opts := []httpsec.Option{httpsec.EnableAPIKey(h.keys, h.keyOpts...)}
	if h.engine != nil {
		opts = append(opts, httpsec.WithPolicyEngine(h.engine))
	}

	return httpsec.New(opts...)
}

// present sends a request carrying header, from source.
func (h *apiKeyHarness) present(t *testing.T, c *httpsec.Chain, source, header string) served {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/invoices", nil)
	req.RemoteAddr = source + ":51000"

	if header != "" {
		req.Header.Set("Authorization", header)
	}

	return serve(t, c, req)
}

// withKey presents the live key under the default scheme.
func (h *apiKeyHarness) withKey(t *testing.T, c *httpsec.Chain, source, key string) served {
	t.Helper()

	return h.present(t, c, source, httpsec.DefaultAPIKeyScheme+key)
}

// The source and the password every password-login guard test logs in with.
const (
	loginGuardSource = "203.0.113.7"

	//nolint:gosec // G101: a fixture password, not a credential
	loginGuardRightPassword = "right horse battery"
)

func newLoginGuardHarness(t *testing.T) *loginGuardHarness {
	t.Helper()

	ctrl := gomock.NewController(t)
	h := &loginGuardHarness{
		authn:    NewMockAuthenticator(ctrl),
		attempts: lockout.NewMemoryAttemptStore(),
		tokens:   NewMockGenerator(ctrl),
		logs:     &capturingHandler{},
		reported: map[string]int{},
	}

	store := NewMockStore(ctrl)
	store.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	sessions, err := session.New(session.WithStore(store))
	require.NoError(t, err)

	h.sessions = sessions

	h.tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).Return("tok", nil).AnyTimes()

	// The right password authenticates as the submitted user; any other is
	// refused, as a password provider refuses it.
	h.authn.EXPECT().Authenticate(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, c identity.Credentials) (*authenticate.Authentication, error) {
			h.authnCalls.Add(1)

			creds, ok := c.(*identity.UsernamePassword)
			if !ok || string(creds.Password) != loginGuardRightPassword {
				return nil, authenticate.ErrAuthenticationFailed
			}

			return &authenticate.Authentication{
				Principal: &identity.Principal{ID: identity.UserID("id-" + creds.Username), Username: creds.Username},
				Time:      time.Now(),
			}, nil
		}).AnyTimes()

	return h
}

// formLoginFrom posts a form login for username from the guard test's source.
func formLoginFrom(t *testing.T, c *httpsec.Chain, addr, username, password string) served {
	t.Helper()

	return serve(t, c, fromSource(formRequest(t.Context(), httpsec.DefaultLoginPath,
		"username="+username+"&password="+password), addr))
}

// failForm makes n failed form logins, each for its own username, and
// requires that none was throttled.
func failForm(t *testing.T, c *httpsec.Chain, n int, prefix string) {
	t.Helper()

	for i := range n {
		out := formLoginFrom(t, c, loginGuardSource, fmt.Sprintf("%s%d", prefix, i+1), "wrong")
		require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed, "failure %d", i+1)
		require.NotErrorIs(t, out.err, ratelimit.ErrThrottled, "failure %d is within the allowance", i+1)
	}
}

// memLimiter is an in-memory limiter allowing limit failures per window.
func memLimiter(t *testing.T, limit int, window time.Duration) ratelimit.Limiter {
	t.Helper()

	l, err := ratelimit.NewMemoryLimiter(limit, window,
		ratelimit.WithMemoryLimiterLogger(slog.New(slog.DiscardHandler)))
	require.NoError(t, err)

	return l
}

var lockReferenceHash = []byte("reference-hash")

// activityWrite is one RecordActivity call as the store received it.
type activityWrite struct {
	id           string
	lastAccessed time.Time
	idleExpires  time.Time
	olderThan    time.Time
}

// countingStore forwards to the real store and counts the reads a verification
// makes, which is how a test pins that a request refused earlier never reached
// the store at all.
type countingStore struct {
	apikey.Store

	reads atomic.Int64
}

func (s *countingStore) Get(ctx context.Context, keyID id.ID) (apikey.Key, error) {
	s.reads.Add(1)

	return s.Store.Get(ctx, keyID)
}

// discardLogger keeps a test's own output clean: what these tests pin is the
// refusal, and the records themselves are pinned in chain_test.go.
func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

// errLimiterDown is the outage a limiter reports when it cannot answer at all.
var errLimiterDown = errors.New("limiter: store unreachable")

// expiryTaskNames returns the names of tasks, in order.
func expiryTaskNames(tasks []expiry.Task) []string {
	names := make([]string, 0, len(tasks))
	for _, task := range tasks {
		names = append(names, task.Name)
	}

	return names
}

// loginGuardHarness is a chain with form login and Basic both enabled over one
// authenticator, counting what reached the authenticator and the
// pre-authentication phase, so a row can say a refused request reached
// neither.
type loginGuardHarness struct {
	authn    *MockAuthenticator
	attempts *lockout.MemoryAttemptStore
	sessions *session.Sessions
	tokens   *MockGenerator
	logs     *capturingHandler

	authnCalls   atomic.Int64
	preAuthCalls atomic.Int64

	// lockout, when set, is registered beside the counting policy.
	lockout policy.Policy

	mu       sync.Mutex
	reported map[string]int
}

// engine is the policy engine the chain judges by: a pre-authentication
// policy that counts and allows, and the lockout when the row set one.
func (h *loginGuardHarness) engine(t *testing.T) *policy.Engine {
	t.Helper()

	counter := NewMockPolicy(gomock.NewController(t))
	counter.EXPECT().Name().Return("test: counts pre-authentication").AnyTimes()
	counter.EXPECT().Phases().Return([]policy.Phase{policy.PreAuthentication}).AnyTimes()
	counter.EXPECT().Evaluate(gomock.Any(), gomock.Any()).DoAndReturn(
		func(context.Context, *policy.Input) policy.Decision {
			h.preAuthCalls.Add(1)

			return policy.Decision{Outcome: policy.Allow}
		}).AnyTimes()

	policies := []policy.Policy{counter}
	if h.lockout != nil {
		policies = append(policies, h.lockout)
	}

	return engineOf(t, policies...)
}

// chain builds form login and Basic over the harness, with opts applied last.
func (h *loginGuardHarness) chain(
	t *testing.T,
	loginOpts []httpsec.LoginOption,
	basicOpts []httpsec.BasicAuthOption,
	opts ...httpsec.Option,
) *httpsec.Chain {
	t.Helper()

	c, err := h.tryChain(t, loginOpts, basicOpts, opts...)
	require.NoError(t, err)

	return c
}

// tryChain is chain for a row that expects construction to fail.
func (h *loginGuardHarness) tryChain(
	t *testing.T,
	loginOpts []httpsec.LoginOption,
	basicOpts []httpsec.BasicAuthOption,
	opts ...httpsec.Option,
) (*httpsec.Chain, error) {
	t.Helper()

	return httpsec.New(append([]httpsec.Option{
		httpsec.WithLogger(slog.New(h.logs)),
		httpsec.WithRefusalLogReporter(h.report),
		httpsec.WithPolicyEngine(h.engine(t)),
		httpsec.EnableFormLogin(httpsec.FormLoginDeps{
			Authenticator: h.authn,
			Sessions:      h.sessions,
			Tokens:        h.tokens,
			Attempts:      h.attempts,
		}, loginOpts...),
		httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{Authenticator: h.authn, Attempts: h.attempts}, basicOpts...),
	}, opts...)...)
}

func (h *loginGuardHarness) report(key string, suppressed int) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.reported[key] += suppressed
}

func (h *loginGuardHarness) reportedFor(key string) int {
	h.mu.Lock()
	defer h.mu.Unlock()

	return h.reported[key]
}

// fromSource sends req as if from addr; an empty addr is a request with no
// client address at all.
func fromSource(req *http.Request, addr string) *http.Request {
	req.RemoteAddr = ""
	if addr != "" {
		req.RemoteAddr = net.JoinHostPort(addr, "51000")
	}

	return req
}

// lockedBuffer is a log sink several requests may write to at once.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}

// renewalFixture is a session-reference chain with the renewal endpoint, over
// a manager on the memory store and a fake clock, and a session O created in
// it.
type renewalFixture struct {
	clk      *clockwork.FakeClock
	logs     *lockedBuffer
	sessions *session.Sessions
	chain    *httpsec.Chain

	// old is O's identifier, which is its credential in this mode.
	old string

	mu      sync.Mutex
	results []httpsec.RenewalResult
}

// supersede renews O directly through the manager, as a renewal whose
// response was lost would have, and returns the successor's identifier.
func (f *renewalFixture) supersede(t *testing.T) string {
	t.Helper()

	s, err := f.sessions.LoadForRenewal(t.Context(), f.old)
	require.NoError(t, err)

	next, _, err := f.sessions.RotateWithGrace(t.Context(), s, 30*time.Second)
	require.NoError(t, err)

	return next.ID
}

// unpresented asserts that O is still superseded by successor, which was never
// presented: nothing recovered or revoked the family.
func (f *renewalFixture) unpresented(t *testing.T, successor string) {
	t.Helper()

	old, err := f.sessions.LoadForRenewal(t.Context(), f.old)
	require.NoError(t, err)
	assert.False(t, old.SupersededAt.IsZero())

	_, err = f.sessions.Load(t.Context(), successor)
	require.NoError(t, err, "the successor is still stored")
}

// recordingResponder records r and writes its credential as a plain body.
func (f *renewalFixture) recordingResponder(ex *httpsec.Exchange, r httpsec.RenewalResult) error {
	f.mu.Lock()
	f.results = append(f.results, r)
	f.mu.Unlock()

	ex.Writer.WriteHeader(http.StatusCreated)
	_, err := ex.Writer.Write([]byte(r.Credential))

	return err
}

func (f *renewalFixture) recorded() []httpsec.RenewalResult {
	f.mu.Lock()
	defer f.mu.Unlock()

	return append([]httpsec.RenewalResult(nil), f.results...)
}

// request runs method path through the chain, bearing credential when it is
// not empty.
func (f *renewalFixture) request(t *testing.T, method, path, credential string) served {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), method, path, nil)
	if credential != "" {
		req.Header.Set("Authorization", "Bearer "+credential)
	}

	return serve(t, f.chain, req)
}

// renew posts credential to path and returns the credential the default
// responder answered with.
func (f *renewalFixture) renew(t *testing.T, path, credential string) string {
	t.Helper()

	out := f.request(t, http.MethodPost, path, credential)
	require.NoError(t, out.err)
	require.Equal(t, http.StatusOK, out.rec.Code)

	var body loginBody
	require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &body))
	require.NotEmpty(t, body.AccessToken)

	return body.AccessToken
}

// use is an ordinary request bearing credential.
func (f *renewalFixture) use(t *testing.T, credential string) served {
	t.Helper()

	return f.request(t, http.MethodGet, "/api/resource", credential)
}

// phasePolicy answers with one fixed decision in the phases it declares, which
// is how a test says what a phase decided without writing a rule of its own.
func phasePolicy(t *testing.T, d policy.Decision, phases ...policy.Phase) policy.Policy {
	t.Helper()

	p := NewMockPolicy(gomock.NewController(t))
	p.EXPECT().Name().Return("test: fixed answer").AnyTimes()
	p.EXPECT().Phases().Return(phases).AnyTimes()
	p.EXPECT().Evaluate(gomock.Any(), gomock.Any()).Return(d).AnyTimes()

	return p
}

func suppressedCount(t *testing.T, r slog.Record) int64 {
	t.Helper()

	v, ok := attrValue(r, "suppressed")
	require.True(t, ok, "the record carries no suppressed count")

	return v.Int64()
}

// unknownAPIKey is well formed but names no issued key, so presenting it reaches
// the store and is counted as a failure against its source.
//
//nolint:gosec // G101: a fixture naming no issued key, not a credential
const unknownAPIKey = "sk_0199a0e1-0000-7000-8000-000000000000.Z3Vlc3M"

// summaryChain is the summary record the chain writes when a flush reports
// what it held back.
const summaryChain = "httpsec: refusal logs suppressed"

// testDeviceChannel is the channel the scripted challenge method reports. It
// is a test-only value, the channel of no first-factor kind, so a challenge
// method is never refused as same-channel unless a case asks for it.
const testDeviceChannel factor.Channel = "authenticator-device"

// challengeStub is a scripted mfa.ChallengeMethod, named "passkey" unless a
// case names it otherwise.
//
// It is hand-written rather than generated because its behaviour, not only
// its calls, is what the cases rely on: BeginChallenge builds the document a
// client would answer from the challenge it is given, and PresentedChallenge
// reads that challenge back out of the client's answer, so a round trip through
// the chain behaves as a real challenge protocol does. What it answers at
// Enrolled and Verify is scripted, and every Verify is counted, because "the
// method was never asked" is the guarantee most of the cases pin.
//
// It is safe for concurrent use, as the port requires.
type challengeStub struct {
	// name is what Name reports: "passkey" when empty.
	name string

	// channel is what Channel reports: testDeviceChannel unless a case needs
	// the method on a first factor's channel.
	channel factor.Channel

	// enrolled and enrolledErr are what Enrolled answers.
	enrolled    bool
	enrolledErr error

	// verifyErr is what Verify answers, for every call, and beginErr what
	// BeginChallenge answers.
	verifyErr error
	beginErr  error

	// verifyCalls counts Verify calls.
	verifyCalls atomic.Int32

	// onVerify, when set, runs at the start of every Verify with the response
	// being verified, so a case can observe what the chain had done by then.
	onVerify func(ctx context.Context, response []byte)

	mu sync.Mutex
	// issued are the challenges BeginChallenge was handed, in order.
	issued []string
}

var _ mfa.ChallengeMethod = (*challengeStub)(nil)

// newChallengeStub is a passkey the user is enrolled on and that accepts
// every response it is asked to verify.
func newChallengeStub() *challengeStub {
	return &challengeStub{channel: testDeviceChannel, enrolled: true}
}

func (c *challengeStub) Name() string {
	if c.name == "" {
		return "passkey"
	}

	return c.name
}

func (c *challengeStub) Channel() factor.Channel { return c.channel }

func (c *challengeStub) Enrolled(context.Context, identity.UserID) (bool, error) {
	return c.enrolled, c.enrolledErr
}

func (*challengeStub) Response() mfa.ResponseFormat { return mfa.JSONBody(16 << 10) }

func (c *challengeStub) Verify(ctx context.Context, _ identity.UserID, response []byte) error {
	c.verifyCalls.Add(1)

	if c.onVerify != nil {
		c.onVerify(ctx, response)
	}

	return c.verifyErr
}

// stubChallengeDocument is the document BeginChallenge sends and a client
// answers with: the challenge, carried back as it was received.
type stubChallengeDocument struct {
	Challenge string `json:"challenge"`
}

func (c *challengeStub) BeginChallenge(
	_ context.Context,
	_ identity.UserID,
	challenge string,
) (json.RawMessage, error) {
	if c.beginErr != nil {
		return nil, c.beginErr
	}

	c.mu.Lock()
	c.issued = append(c.issued, challenge)
	c.mu.Unlock()

	return json.Marshal(stubChallengeDocument{Challenge: challenge})
}

// errStubUnreadableAnswer is what PresentedChallenge refuses an answer whose
// challenge member is not a string with.
var errStubUnreadableAnswer = errors.New("mfachallenge_stub_test: the answer's challenge is unreadable")

// PresentedChallenge reads the challenge member of a JSON answer. An answer
// without one presents the empty challenge, and one whose member is not a
// string cannot be read at all.
func (*challengeStub) PresentedChallenge(response []byte) (string, error) {
	var doc stubChallengeDocument
	if err := json.Unmarshal(response, &doc); err != nil {
		return "", errors.Join(errStubUnreadableAnswer, err)
	}

	return doc.Challenge, nil
}

// lastIssued is the challenge the most recent begin was handed, and empty when
// no begin reached the method.
func (c *challengeStub) lastIssued() string {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.issued) == 0 {
		return ""
	}

	return c.issued[len(c.issued)-1]
}

// answer is a response to challenge, as a client of this method would post it.
func answer(challenge string) string {
	b, err := json.Marshal(stubChallengeDocument{Challenge: challenge})
	if err != nil {
		panic(err) // a string always marshals
	}

	return string(b)
}

// issuedAll is every challenge a begin handed the method, in order.
func (c *challengeStub) issuedAll() []string {
	c.mu.Lock()
	defer c.mu.Unlock()

	return append([]string(nil), c.issued...)
}

// enrolUsername is the enrolling user's username, which is an address, so the
// default label and contact resolvers read it unchanged.
const enrolUsername = "ana@example.com"

// enrolIssuer is the issuer the TOTP method is built with.
const enrolIssuer = "Example"

// The enrolment endpoints' paths for the harness's TOTP method, named "totp",
// under the default prefixes.
const (
	enrolBeginPath   = httpsec.DefaultEnrolmentBeginPrefix + "/totp"
	enrolConfirmPath = httpsec.DefaultEnrolmentConfirmPrefix + "/totp"
	enrolEmailPath   = httpsec.DefaultEnrolmentEmailConfirmPrefix + "/totp"
)

// queuedSender is a sender double that declares itself non-blocking, as
// notify.QueuedSender does, so the enrolment path accepts it without the
// synchronous-delivery option. What it is asked to send is the mock's to pin.
type queuedSender struct{ *MockSender }

func (queuedSender) NonBlocking() bool { return true }

var _ notify.NonBlocking = queuedSender{}

// enrolHarness is what an enrolment chain is wired to: a real session manager,
// a real TOTP method over the in-memory store — so a begin really provisions a
// secret and a code computed from it really proves the device — and doubles for
// the user loader and the sender, whose calls are part of what is pinned.
type enrolHarness struct {
	t *testing.T

	sessions *session.Sessions
	store    *mfa.MemoryEnrolmentStore
	totp     *mfa.TOTP

	// clock is the TOTP method's clock. Tests move it between requests, never
	// during one.
	clock *clockwork.FakeClock

	users  *MockUserLoader
	sender *MockSender
	tokens *MockGenerator

	// username is what the user loader reports for the enrolling user.
	username string

	// method is what EnableMFA is given, the TOTP method unless a case
	// replaces it, and extraMethods are further methods given after it, in
	// order.
	method       mfa.Method
	extraMethods []mfa.Method

	enrolOpts  []httpsec.EnrolmentOption
	logoutOpts []httpsec.LogoutOption

	// mfaOpts is further options for EnableMFA, after the harness's tokens.
	mfaOpts []httpsec.MFAOption

	// extra is further chain options, applied after the harness's own.
	extra []httpsec.Option

	// pinned, when set, is carried as it stands in memory on every request
	// instead of being loaded from the store: a test uses it to hand the chain
	// a session the store would no longer load, or to read what a request
	// left on the very object it was given.
	pinned *session.Session

	// withoutGate builds the chain with the enrolment challenge counted as
	// enforced but no enrolment path registered, which is how a test shows a
	// refusal is the gate's and nothing else's.
	withoutGate bool
}

func newEnrolHarness(t *testing.T) *enrolHarness {
	t.Helper()

	ctrl := gomock.NewController(t)

	sessions, err := session.New()
	require.NoError(t, err)

	h := &enrolHarness{
		t:        t,
		sessions: sessions,
		store:    mfa.NewMemoryEnrolmentStore(),
		clock:    clockwork.NewFakeClockAt(time.Now().Truncate(time.Second)),
		users:    NewMockUserLoader(ctrl),
		sender:   NewMockSender(ctrl),
		tokens:   NewMockGenerator(ctrl),
		username: enrolUsername,
	}

	h.totp, err = mfa.NewTOTP(h.store, enrolIssuer, mfa.WithClock(h.clock))
	require.NoError(t, err)

	h.method = h.totp

	h.users.EXPECT().LoadByUserID(gomock.Any(), testMFAUser).AnyTimes().
		DoAndReturn(func(context.Context, identity.UserID) (*identity.Details, error) {
			return &identity.Details{ID: testMFAUser, Name: "Ana", Username: h.username, Active: true}, nil
		})

	return h
}

// enrolmentEngine is an engine holding the MFA requirement policy with the
// enrolment path on, which is what declares the enrolment challenge the path
// must be paired with.
func enrolmentEngine(t *testing.T) *policy.Engine {
	t.Helper()

	ctrl := gomock.NewController(t)

	lookup := NewMockMFAMethodLookup(ctrl)
	lookup.EXPECT().Name().Return("totp").AnyTimes()
	lookup.EXPECT().Enrolled(gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()
	lookup.EXPECT().Channel().Return(factor.AuthenticatorApp).AnyTimes()

	p, err := policy.NewMFARequirement(everyoneRequired{}, []policy.MFAMethodLookup{enrollableLookup{lookup}}, policy.WithMFAEnrolmentPath())
	require.NoError(t, err)

	return engineOf(t, p)
}

// deps is what EnableMFAEnrolment is handed: the user loader and a
// non-blocking sender.
func (h *enrolHarness) deps() httpsec.EnrolmentDeps {
	return httpsec.EnrolmentDeps{Users: h.users, Sender: queuedSender{h.sender}}
}

// options is every option the harness's chain is built from.
func (h *enrolHarness) options(t *testing.T, s *session.Session) []httpsec.Option {
	t.Helper()

	enrolment := httpsec.EnableMFAEnrolment(h.deps(), h.enrolOpts...)
	if h.withoutGate {
		enrolment = httpsec.EnableGateForTest(policy.ChallengeMFAEnrolment)
	}

	return append([]httpsec.Option{
		httpsec.WithPolicyEngine(enrolmentEngine(t)),
		h.carries(s),
		httpsec.EnableMFA(append([]mfa.Method{h.method}, h.extraMethods...), append([]httpsec.MFAOption{httpsec.WithMFATokens(h.tokens)}, h.mfaOpts...)...),
		enrolment,
		httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: h.sessions}, h.logoutOpts...),
	}, h.extra...)
}

// chain assembles the chain under test, with s carried as a first factor
// would have carried it.
func (h *enrolHarness) chain(t *testing.T, s *session.Session) *httpsec.Chain {
	t.Helper()

	c, err := httpsec.New(h.options(t, s)...)
	require.NoError(t, err)

	return c
}

// carries stands in for the bearer interceptor: at its slot, it loads s afresh
// from the store on every request, as the bearer loads the session a token
// names, so a request sees what the one before it saved. A session that no
// longer loads is not carried.
func (h *enrolHarness) carries(s *session.Session) httpsec.Option {
	carrier := httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		if s == nil {
			return next(ex)
		}

		loaded := h.pinned
		if loaded == nil {
			var err error

			loaded, err = h.sessions.Load(ex.Context(), s.ID)
			if err != nil {
				return next(ex)
			}
		}

		ex.Authentication = &authenticate.Authentication{Principal: testPrincipal(), Time: time.Now()}
		ex.Session = loaded
		ex.SetContext(httpsec.WithSession(httpsec.WithCaller(ex.Context(), ex.Authentication), loaded))

		return next(ex)
	})

	return httpsec.RegisterInterceptor(carrier, httpsec.OrderBearerToken)
}

// enrolmentOnly is a live session for the enrolling user, established by
// first and marked enrolment-only as the login tail would have marked it.
func (h *enrolHarness) enrolmentOnly(t *testing.T, first factor.Kind) *session.Session {
	t.Helper()

	s, err := h.sessions.Create(t.Context(), testMFAUser, session.WithFirstFactor(first))
	require.NoError(t, err)

	h.sessions.MarkEnrolmentPending(s, 15*time.Minute)
	require.NoError(t, h.sessions.Save(t.Context(), s))

	return s
}

// sessionIn is a live session for the enrolling user, established by first,
// in state: enrolment-only as the login tail marks it, or any other state as
// set directly.
func (h *enrolHarness) sessionIn(t *testing.T, first factor.Kind, state session.MFAState) *session.Session {
	t.Helper()

	if state == session.MFAEnrolmentPending {
		return h.enrolmentOnly(t, first)
	}

	s, err := h.sessions.Create(t.Context(), testMFAUser, session.WithFirstFactor(first))
	require.NoError(t, err)

	s.MFA = state
	require.NoError(t, h.sessions.Save(t.Context(), s))

	return s
}

// stored reloads a session by handle.
func (h *enrolHarness) stored(t *testing.T, handle string) *session.Session {
	t.Helper()

	s, err := h.sessions.Load(t.Context(), handle)
	require.NoError(t, err)

	return s
}

// enrolment reads the enrolling user's enrolment as the store holds it.
func (h *enrolHarness) enrolment(t *testing.T) (mfa.Enrolment, bool) {
	t.Helper()

	e, ok, err := h.store.Get(t.Context(), testMFAUser)
	require.NoError(t, err)

	return e, ok
}

// codeFor is the code an authenticator holding secret shows at the harness's
// clock.
func (h *enrolHarness) codeFor(t *testing.T, secret string) string {
	t.Helper()

	code, err := totp.GenerateCode(secret, h.clock.Now())
	require.NoError(t, err)

	return code
}

// post is a form POST to path, carried under ctx.
func post(ctx context.Context, path, body string) *http.Request {
	return formRequest(ctx, path, body)
}

// serveIn runs req through chain on an exchange seeded from ctx, which a case
// uses to hand the chain a context that is already cancelled.
func serveIn(ctx context.Context, t *testing.T, chain *httpsec.Chain, req *http.Request) served {
	t.Helper()

	out := served{rec: httptest.NewRecorder()}
	run := chain.Assemble(func(ex *httpsec.Exchange) error {
		out.handlerRan = true
		out.handled = ex

		return nil
	})

	ex := httpsec.NewExchange(ctx, httpsec.NewHTTPRequest(req), httpsec.NewHTTPResponseWriter(out.rec))
	out.err = run(ex)

	return out
}

// The registration endpoints' paths under the default prefix.
const (
	passkeyBeginPath        = httpsec.DefaultPasskeyRegistrationPrefix + "/begin"
	passkeyFinishPath       = httpsec.DefaultPasskeyRegistrationPrefix + "/finish"
	passkeyConfirmPath      = httpsec.DefaultPasskeyRegistrationPrefix + "/confirm"
	passkeyConfirmEmailPath = httpsec.DefaultPasskeyRegistrationPrefix + "/confirm-email"
)

// passkeyRP is the relying party the stub verifier reports.
var passkeyRP = passkey.RelyingParty{ID: "example.com", Name: "Example", Origins: []string{"https://example.com"}}

// passkeyVerifierStub drives a generated passkey.Verifier mock with a few
// rules, so the chain's passkey endpoints can be exercised without the
// WebAuthn adapter, which the core module must not depend on.
//
// A registration response is {"challenge","id","name"} and an assertion
// {"challenge","id","handle"}, the challenge base64url-encoded as clientDataJSON
// carries it. Every registration verifies as a user-verified, backup-eligible
// passkey, and every assertion whose challenge is the expected one verifies,
// user-verified, with a zero counter.
type passkeyVerifierStub struct {
	mock *MockPasskeyVerifier

	mu         sync.Mutex
	creations  []string // challenges rendered into creation options
	requests   []string // challenges rendered into request options
	allowed    [][]passkey.Descriptor
	parseCalls int

	// notUserVerified makes every assertion verify with user presence only,
	// refuseAssertions makes every assertion fail to verify, as a bad
	// signature does, and signCount is the counter every verified assertion
	// reports.
	notUserVerified  atomic.Bool
	refuseAssertions atomic.Bool
	signCount        atomic.Uint32
}

func newPasskeyVerifierStub(t *testing.T) *passkeyVerifierStub {
	t.Helper()

	ctrl := gomock.NewController(t)
	v := &passkeyVerifierStub{mock: NewMockPasskeyVerifier(ctrl)}

	v.mock.EXPECT().RelyingParty().Return(passkeyRP).AnyTimes()
	v.mock.EXPECT().CreationOptions(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, in passkey.CreationInput) (json.RawMessage, error) {
			v.mu.Lock()
			defer v.mu.Unlock()

			v.creations = append(v.creations, in.Challenge)

			return json.Marshal(map[string]string{"challenge": encodeChallenge(in.Challenge)})
		})
	v.mock.EXPECT().RequestOptions(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, in passkey.RequestInput) (json.RawMessage, error) {
			v.mu.Lock()
			defer v.mu.Unlock()

			v.requests = append(v.requests, in.Challenge)
			v.allowed = append(v.allowed, in.Allow)

			return json.Marshal(map[string]any{"challenge": encodeChallenge(in.Challenge), "allow": len(in.Allow)})
		})
	v.mock.EXPECT().ParseRegistration(gomock.Any()).AnyTimes().
		DoAndReturn(func(body []byte) (passkey.ParsedRegistration, error) {
			v.mu.Lock()
			v.parseCalls++
			v.mu.Unlock()

			var r struct{ Challenge, ID, Name string }
			if err := json.Unmarshal(body, &r); err != nil || r.ID == "" {
				return nil, errors.New("stub: unreadable registration")
			}

			p := NewMockParsedRegistration(ctrl)
			p.EXPECT().Challenge().Return(r.Challenge).AnyTimes()
			p.EXPECT().CredentialID().Return([]byte(r.ID)).AnyTimes()
			p.EXPECT().Name().Return(r.Name).AnyTimes()

			return p, nil
		})
	v.mock.EXPECT().VerifyRegistration(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, p passkey.ParsedRegistration, exp passkey.RegistrationExpectation) (*passkey.CredentialInput, error) {
			if p.Challenge() != encodeChallenge(exp.Challenge) {
				return nil, errors.New("stub: challenge mismatch")
			}

			return &passkey.CredentialInput{
				CredentialID:   p.CredentialID(),
				PublicKey:      append([]byte("cose-"), p.CredentialID()...),
				UserVerified:   true,
				BackupEligible: true,
				BackupState:    true,
				Transports:     []string{"internal"},
			}, nil
		})
	v.mock.EXPECT().ParseAssertion(gomock.Any()).AnyTimes().
		DoAndReturn(func(body []byte) (passkey.ParsedAssertion, error) {
			var a struct {
				Challenge, ID string
				Handle        []byte
			}
			if err := json.Unmarshal(body, &a); err != nil || a.ID == "" {
				return nil, errors.New("stub: unreadable assertion")
			}

			p := NewMockParsedAssertion(ctrl)
			p.EXPECT().Challenge().Return(a.Challenge).AnyTimes()
			p.EXPECT().CredentialID().Return([]byte(a.ID)).AnyTimes()
			p.EXPECT().UserHandle().Return(a.Handle).AnyTimes()

			return p, nil
		})
	v.mock.EXPECT().VerifyAssertion(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, p passkey.ParsedAssertion, c *passkey.Credential, exp passkey.AssertionExpectation) (*passkey.AssertionResult, error) {
			if v.refuseAssertions.Load() || p.Challenge() != encodeChallenge(exp.Challenge) ||
				!bytes.Equal(p.CredentialID(), c.CredentialID) {
				return nil, errors.New("stub: assertion does not verify")
			}

			return &passkey.AssertionResult{
				SignCount:    v.signCount.Load(),
				UserVerified: !v.notUserVerified.Load(), BackupEligible: c.BackupEligible, BackupState: c.BackupState,
			}, nil
		})

	return v
}

// encodeChallenge is a token string as clientDataJSON carries it.
func encodeChallenge(token string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(token))
}

// lastCreation is the challenge the latest registration begin rendered.
func (v *passkeyVerifierStub) lastCreation(t *testing.T) string {
	t.Helper()

	v.mu.Lock()
	defer v.mu.Unlock()

	require.NotEmpty(t, v.creations, "no registration was begun")

	return v.creations[len(v.creations)-1]
}

// lastRequest is the challenge the latest assertion begin rendered.
func (v *passkeyVerifierStub) lastRequest(t *testing.T) string {
	t.Helper()

	v.mu.Lock()
	defer v.mu.Unlock()

	require.NotEmpty(t, v.requests, "no assertion was begun")

	return v.requests[len(v.requests)-1]
}

// registrationBody is a registration response answering challenge with
// credential credID.
func registrationBody(challenge, credID string) string {
	b, _ := json.Marshal(map[string]string{"challenge": encodeChallenge(challenge), "id": credID, "name": "Laptop"})

	return string(b)
}

// handleAssertionBody is an assertion answering challenge from credential
// credID, carrying the user handle handle, as a passwordless login's does.
func handleAssertionBody(challenge, credID string, handle []byte) string {
	b, _ := json.Marshal(map[string]any{"challenge": encodeChallenge(challenge), "id": credID, "handle": handle})

	return string(b)
}

// assertionBody is an assertion answering challenge from credential credID.
func assertionBody(challenge, credID string) string {
	b, _ := json.Marshal(map[string]string{"challenge": encodeChallenge(challenge), "id": credID})

	return string(b)
}

// jsonPost is a JSON POST of body to path.
func jsonPost(ctx context.Context, path, body string) *http.Request {
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	return req
}

// passkeyHarness is the enrolment harness with passkeys added: a real
// passkey.Passkeys over the in-memory stores and the stub verifier, sending
// its notices and emailed codes to a capturing sender, enabled on the chain.
type passkeyHarness struct {
	*enrolHarness

	verifier *passkeyVerifierStub
	creds    *passkey.MemoryCredentialStore
	notices  *capturingSender
	recovery *passkey.RecoveryDeps

	// pkOpts are further manager options, and passkeyOpts further
	// EnablePasskeys options.
	pkOpts      []passkey.Option
	passkeyOpts []httpsec.PasskeyOption

	// passkeyMethod puts the passkey MFA method on EnableMFA after TOTP, so
	// the enrolment path counts it among its enrolling methods.
	passkeyMethod bool

	// withoutEnrolment builds the chain with no enrolment path, and
	// withRecoveryGate with the recovery gate.
	withoutEnrolment bool
	withRecoveryGate bool

	manager *passkey.Passkeys
}

func newPasskeyHarness(t *testing.T) *passkeyHarness {
	t.Helper()

	return &passkeyHarness{
		enrolHarness: newEnrolHarness(t),
		verifier:     newPasskeyVerifierStub(t),
		creds:        passkey.NewMemoryCredentialStore(),
		notices:      &capturingSender{},
	}
}

// build builds the passkey manager and the chain carrying s.
func (h *passkeyHarness) build(t *testing.T, s *session.Session) *httpsec.Chain {
	t.Helper()

	c, err := httpsec.New(h.chainOptions(t, s)...)
	require.NoError(t, err)

	return c
}

// chainOptions are the options build assembles the chain from.
func (h *passkeyHarness) chainOptions(t *testing.T, s *session.Session) []httpsec.Option {
	t.Helper()

	m, err := passkey.New(passkey.Deps{
		Verifier:    h.verifier.mock,
		Credentials: h.creds,
		Users:       h.users,
		Sender:      h.notices,
		Sessions:    h.sessions,
		Recovery:    h.recovery,
	}, append([]passkey.Option{passkey.WithRepudiationContact("help@example.com")}, h.pkOpts...)...)
	require.NoError(t, err)

	h.manager = m

	if h.passkeyMethod {
		h.extraMethods = append(h.extraMethods, m.MFAMethod())
	}

	h.extra = append(h.extra, httpsec.EnablePasskeys(httpsec.PasskeyDeps{Passkeys: m, Sessions: h.sessions, Users: h.users}, h.passkeyOpts...))
	if h.withRecoveryGate {
		h.extra = append(h.extra, httpsec.EnableRecoveryGateForTest())
	}

	opts := h.options(t, s)
	if h.withoutEnrolment {
		opts = withoutEnrolmentPath(t, h, s)
	}

	return opts
}

// withoutEnrolmentPath is the harness's options with no enrolment path and no
// policy engine.
func withoutEnrolmentPath(t *testing.T, h *passkeyHarness, s *session.Session) []httpsec.Option {
	t.Helper()

	return append([]httpsec.Option{
		h.carries(s),
		httpsec.EnableMFA(append([]mfa.Method{h.method}, h.extraMethods...),
			append([]httpsec.MFAOption{httpsec.WithMFATokens(h.tokens)}, h.mfaOpts...)...),
		httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: h.sessions}, h.logoutOpts...),
	}, h.extra...)
}

// withEnrolledMethod builds the chain with no enrolment path and puts on the
// MFA slot a second method the user is enrolled on, listed nowhere else: the
// manager's Deps carry no MFA methods, so only the chain can tell it the
// session owes a second factor.
func (h *passkeyHarness) withEnrolledMethod(t *testing.T) {
	t.Helper()

	enrolled := NewMockMethod(gomock.NewController(t))
	enrolled.EXPECT().Name().Return("emailcode").AnyTimes()
	enrolled.EXPECT().Channel().Return(factor.Email).AnyTimes()
	enrolled.EXPECT().Enrolled(gomock.Any(), gomock.Any()).Return(true, nil).AnyTimes()
	enrolled.EXPECT().Response().Return(mfa.FormField("code", 64)).AnyTimes()

	h.withoutEnrolment = true
	h.extraMethods = append(h.extraMethods, enrolled)
}

// withPasswordless serves passwordless login on the chain, minting its tokens
// with the harness's generator, over a manager in the optional recovery-codes
// mode.
func (h *passkeyHarness) withPasswordless() {
	h.pkOpts = append(h.pkOpts, passkey.WithOptionalRecoveryCodes())
	h.passkeyOpts = append(h.passkeyOpts, httpsec.WithPasskeyPasswordlessLogin(httpsec.PasswordlessTokens(h.tokens)))
}

// register begins and finishes a registration through chain, returning the
// finish's outcome.
func (h *passkeyHarness) register(t *testing.T, chain *httpsec.Chain, credID string) served {
	t.Helper()

	begun := serve(t, chain, post(t.Context(), passkeyBeginPath, ""))
	require.NoError(t, begun.err)

	return serve(t, chain, jsonPost(t.Context(), passkeyFinishPath, registrationBody(h.verifier.lastCreation(t), credID)))
}

// credential is the user's one stored passkey.
func (h *passkeyHarness) credential(t *testing.T) *passkey.Credential {
	t.Helper()

	list, err := h.creds.List(t.Context(), testMFAUser)
	require.NoError(t, err)
	require.Len(t, list, 1)

	return list[0]
}

// The addresses these tests submit. One has an account and one has none, and
// the whole point of the request endpoint is that a client cannot tell which
// is which.
const (
	magicLinkKnown   = "ada@example.com"
	magicLinkUnknown = "nobody@example.com"
)

// magicLinkUserID is the reference a link records, and the one redemption
// loads by.
const magicLinkUserID identity.UserID = "u-1"

// magicLinkTTL is how long a link lives in these tests, and therefore what the
// binding cookie's lifetime must be.
const magicLinkTTL = 15 * time.Minute

// magicLinkSource is the client address most of these requests come from. It
// is a documentation-range address, so nothing here can reach a real host.
const magicLinkSource = "203.0.113.7"

func magicLinkUser() *identity.Details {
	return &identity.Details{
		ID:       magicLinkUserID,
		Name:     "Ada Lovelace",
		Username: magicLinkKnown,
		Active:   true,
	}
}

// capturingSender is the notify.Sender the magic-link manager sends through.
// It reports itself non-blocking, which is what the manager requires, and it
// keeps every message so a test can read the link a user would have received.
type capturingSender struct {
	mu   sync.Mutex
	sent []notify.Message
}

func (s *capturingSender) Send(_ context.Context, m notify.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sent = append(s.sent, m)

	return nil
}

// NonBlocking reports that Send does not wait for delivery, which is the
// promise the magic-link manager refuses to be built without.
func (s *capturingSender) NonBlocking() bool { return true }

func (s *capturingSender) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.sent)
}

// lastLink is the URL of the most recent message, which is what a recipient
// would click.
func (s *capturingSender) lastLink(t *testing.T) string {
	t.Helper()

	s.mu.Lock()
	defer s.mu.Unlock()

	require.NotEmpty(t, s.sent, "no message was sent")

	found := linkPattern.FindString(s.sent[len(s.sent)-1].TextBody)
	require.NotEmpty(t, found, "the message carries no link")

	return found
}

var linkPattern = regexp.MustCompile(`https?://\S+`)

// lastToken is the token the most recent link carries.
func (s *capturingSender) lastToken(t *testing.T) string {
	t.Helper()

	u, err := url.Parse(s.lastLink(t))
	require.NoError(t, err)

	tok := u.Query().Get("token")
	require.NotEmpty(t, tok, "the link carries no token")

	return tok
}

// lastNext is the redirect target the most recent link carries, which is what
// the flow settled on after the allowlist had its say.
func (s *capturingSender) lastNext(t *testing.T) string {
	t.Helper()

	u, err := url.Parse(s.lastLink(t))
	require.NoError(t, err)

	return u.Query().Get("next")
}

// magicLinkHarness is what a magic-link chain is wired to: a real one-time
// token manager and a real magic-link manager, so a link that is issued can
// actually be redeemed, with doubles only where a test has to say what the
// store answered.
type magicLinkHarness struct {
	sessions *session.Sessions
	users    *MockUserLoader
	tokens   *MockGenerator
	sender   *capturingSender
	manager  *magiclink.Links

	// issued counts the access tokens the login tail asked for, which is how a
	// test pins that a refused redemption issues none, and sessionID is the
	// handle the last of them was issued for.
	issued    atomic.Int64
	sessionID atomic.Value

	// linkOpts and engine are what a case wants configured differently.
	linkOpts []httpsec.MagicLinkOption
	engine   *policy.Engine

	// chainOpts are further chain options a case needs, such as something to
	// enforce the challenge its policy raises.
	chainOpts []httpsec.Option
}

func newMagicLinkHarness(t *testing.T, managerOpts ...magiclink.Option) *magicLinkHarness {
	t.Helper()

	ctrl := gomock.NewController(t)

	sessions, err := session.New()
	require.NoError(t, err)

	h := &magicLinkHarness{
		sessions: sessions,
		users:    NewMockUserLoader(ctrl),
		tokens:   NewMockGenerator(ctrl),
		sender:   &capturingSender{},
	}

	h.users.EXPECT().LoadByUsername(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, username string) (*identity.Details, error) {
			if username == magicLinkKnown {
				return magicLinkUser(), nil
			}

			return nil, identity.ErrUserNotFound
		})

	h.users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, id identity.UserID) (*identity.Details, error) {
			if id == magicLinkUserID {
				return magicLinkUser(), nil
			}

			return nil, identity.ErrUserNotFound
		})

	h.tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, id string, _ *identity.Principal) (string, error) {
			h.issued.Add(1)
			h.sessionID.Store(id)

			return "issued-token", nil
		})

	onetimes, err := onetime.New("magic-link", onetime.WithTokenTTL(magicLinkTTL))
	require.NoError(t, err)

	h.manager, err = magiclink.New(
		onetimes, h.users, h.sender, "https://app.example.com", managerOpts...)
	require.NoError(t, err)

	return h
}

// options are the magic-link options every chain in these tests is built with:
// the collaborators the endpoints need, plus whatever the case configured.
func (h *magicLinkHarness) options() []httpsec.MagicLinkOption {
	var opts []httpsec.MagicLinkOption

	// Left out entirely when the harness has none, so a case can pin what
	// happens to a chain that was never given one.
	if h.sessions != nil {
		opts = append(opts, httpsec.WithMagicLinkSessions(h.sessions))
	}

	if h.tokens != nil {
		opts = append(opts, httpsec.WithMagicLinkTokens(h.tokens))
	}

	return append(opts, h.linkOpts...)
}

// chain assembles the chain under test.
func (h *magicLinkHarness) chain(t *testing.T) *httpsec.Chain {
	t.Helper()

	c, err := h.build()
	require.NoError(t, err)

	return c
}

// build is chain without the assertion, for the cases that are about the
// construction error itself.
func (h *magicLinkHarness) build() (*httpsec.Chain, error) {
	opts := []httpsec.Option{httpsec.EnableMagicLink(h.manager, h.options()...)}
	if h.engine != nil {
		opts = append(opts, httpsec.WithPolicyEngine(h.engine))
	}

	return httpsec.New(append(opts, h.chainOpts...)...)
}

// activeSessions counts the sessions the flow established for the user a link
// authenticates.
func (h *magicLinkHarness) activeSessions(t *testing.T) int {
	t.Helper()

	n, err := h.sessions.CountActiveByUser(t.Context(), magicLinkUserID)
	require.NoError(t, err)

	return n
}

// requestLink drives one link request through the chain and returns what the
// response said.
func (h *magicLinkHarness) requestLink(t *testing.T, c *httpsec.Chain, address string) served {
	t.Helper()

	return serve(t, c, formRequest(t.Context(), DefaultMagicLinkRequestPathForTest,
		url.Values{"email": {address}}.Encode()))
}

// The paths these tests use. They are the library's documented defaults, named
// here so a test reads like the client it stands in for.
const (
	DefaultMagicLinkRequestPathForTest = httpsec.DefaultMagicLinkRequestPath
	DefaultMagicLinkConsumePathForTest = httpsec.DefaultMagicLinkConsumePath
)

// postBody posts an arbitrary body to path, which is how the malformed-body
// cases reach the endpoint.
func postBody(ctx context.Context, path, contentType string, body io.Reader) *http.Request {
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, path, body)
	req.Header.Set("Content-Type", contentType)
	req.RemoteAddr = magicLinkSource + ":51000"

	return req
}

// postValues posts a URL-encoded form from a named source address.
func postValues(ctx context.Context, path, source string, values url.Values) *http.Request {
	req := postBody(ctx, path, "application/x-www-form-urlencoded",
		strings.NewReader(values.Encode()))
	req.RemoteAddr = source + ":51000"

	return req
}

// getFrom is a GET from a named source address, which is what a mail scanner's
// prefetch looks like.
func getFrom(ctx context.Context, path, source string) *http.Request {
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	req.RemoteAddr = source + ":51000"

	return req
}

// cookieNamed returns the cookie the response set under name, or nil.
func cookieNamed(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() { //nolint:bodyclose // the recorder's result has no body to close
		if c.Name == name {
			return c
		}
	}

	return nil
}

// link asks for a link as a browser would, and returns the token the message
// carried and the binding value that browser now holds.
func (h *magicLinkHarness) link(t *testing.T, c *httpsec.Chain) (token, nonce string) {
	t.Helper()

	out := h.requestLink(t, c, magicLinkKnown)
	require.NoError(t, out.err)

	if cookie := cookieNamed(out.rec, httpsec.DefaultBindingCookieName); cookie != nil {
		nonce = cookie.Value
	}

	return h.sender.lastToken(t), nonce
}

// redeem posts a token back as the confirmation page would, from the usual
// source, carrying the binding cookie when there is one.
func (h *magicLinkHarness) redeem(t *testing.T, c *httpsec.Chain, token, nonce string) served {
	t.Helper()

	return h.redeemFrom(t, c, magicLinkSource, token, nonce)
}

// redeemFrom is redeem from a named client address, which is what the
// rate-limit accounting is keyed on.
func (h *magicLinkHarness) redeemFrom(
	t *testing.T,
	c *httpsec.Chain,
	source, token, nonce string,
) served {
	t.Helper()

	req := postValues(t.Context(), httpsec.DefaultMagicLinkConsumePath, source,
		url.Values{"token": {token}})
	if nonce != "" {
		req.AddCookie(bindingCookie(nonce))
	}

	return serve(t, c, req)
}

// consumeWithNext posts a token back along with the redirect target the
// confirmation page carried.
func consumeWithNext(t *testing.T, token, nonce, next string) *http.Request {
	t.Helper()

	req := postValues(t.Context(), httpsec.DefaultMagicLinkConsumePath, magicLinkSource,
		url.Values{"token": {token}, "next": {next}})
	if nonce != "" {
		req.AddCookie(bindingCookie(nonce))
	}

	return req
}

// openedSession is the session the login tail created, read back from the
// store by the identifier the access token was issued for. That identifier is
// the session handle, which is how a later bearer request finds it.
func (h *magicLinkHarness) openedSession(t *testing.T) *session.Session {
	t.Helper()

	id, _ := h.sessionID.Load().(string)
	require.NotEmpty(t, id, "no access token was issued, so no session was opened")

	s, err := h.sessions.Load(t.Context(), id)
	require.NoError(t, err)

	return s
}

// urlValues builds a form body from alternating names and values, so a case
// reads as the submission it stands for.
func urlValues(pairs ...string) url.Values {
	values := url.Values{}
	for i := 0; i+1 < len(pairs); i += 2 {
		values.Set(pairs[i], pairs[i+1])
	}

	return values
}

// bindingCookie is the cookie a browser sends back. The attributes a response
// sets are the library's business and are asserted where they are set; a
// request carries only a name and a value.
func bindingCookie(nonce string) *http.Cookie {
	//nolint:gosec // G124: this is a request cookie, which carries no attributes at all
	return &http.Cookie{Name: httpsec.DefaultBindingCookieName, Value: nonce}
}

// redeemerFunc adapts a function to httpsec.Redeemer, so a test can stand in a
// redemption that behaves as badly as it likes.
type redeemerFunc func(
	ctx context.Context,
	token, nonce string,
	checks ...magiclink.Check,
) (magiclink.Redemption, error)

func (f redeemerFunc) Redeem(
	ctx context.Context,
	token, nonce string,
	checks ...magiclink.Check,
) (magiclink.Redemption, error) {
	return f(ctx, token, nonce, checks...)
}

// testOIDCProvider is the one provider the chain tests' managers register. Its
// endpoints are pinned, so building a manager sends no request.
const testOIDCProvider = "corp"

// newTestOIDCManager builds an OIDC manager for testOIDCProvider over an
// in-memory link store, with brokerOpts configuring the broker it resolves
// identities through. It sends no request: construction never does.
func newTestOIDCManager(t *testing.T, brokerOpts ...oidc.BrokerOption) *oidc.RelyingParty {
	t.Helper()

	registry, err := oidc.NewRegistry(oidc.Provider{ //nolint:gosec // G101: a fixture, not a credential
		Name:                  testOIDCProvider,
		Issuer:                "https://idp.example.com",
		ClientID:              "app",
		ClientSecret:          "secret-" + testOIDCProvider,
		RedirectURL:           "https://app.example.com" + "/login/oauth2/callback/" + testOIDCProvider,
		AuthorizationEndpoint: "https://idp.example.com/authorize",
		TokenEndpoint:         "https://idp.example.com/token",
		JWKSURI:               "https://idp.example.com/jwks",
	})
	require.NoError(t, err)

	broker, err := oidc.NewBroker(oidc.NewMemoryLinkStore(), NewMockUserLoader(gomock.NewController(t)),
		brokerOpts...)
	require.NoError(t, err)

	m, err := oidc.NewRelyingParty(registry, broker)
	require.NoError(t, err)

	return m
}

// newTestHandoffManager builds a handoff manager over an in-memory store.
func newTestHandoffManager(t *testing.T) *oidc.Handoff {
	t.Helper()

	h, err := oidc.NewHandoff(oidc.NewMemoryHandoffStore(), NewMockUserLoader(gomock.NewController(t)))
	require.NoError(t, err)

	return h
}

// The external identity the test provider asserts, and the user it is linked
// to.
const (
	oidcTestSubject                   = "sub-1"
	oidcTestSessionID                 = "sid-1"
	oidcTestUserID    identity.UserID = "u-1"
)

// oidcTestProvider is an httptest TLS server acting as an OpenID provider
// with pinned endpoints, so a manager built on it never runs discovery. Its
// tokens are HS256 under the client secret, so no key set is ever consulted.
//
// The token endpoint echoes the authorization code it is given as the ID
// token's nonce. A test that wants a callback to verify therefore sends the
// nonce the authorize redirect carried as the code; any other code yields a
// token whose nonce does not match.
type oidcTestProvider struct {
	srv *httptest.Server

	// tokenDown makes the token endpoint answer 503, a provider outage.
	tokenDown atomic.Bool

	// assurance, when set, is the amr and acr claims the ID tokens it issues
	// assert; unset, they assert neither.
	assurance atomic.Pointer[map[string]any]
}

// assert makes the ID tokens the provider issues from now on carry amr and
// acr; a nil amr or empty acr leaves that claim out.
func (p *oidcTestProvider) assert(amr []string, acr string) {
	claims := map[string]any{}
	if amr != nil {
		claims["amr"] = amr
	}
	if acr != "" {
		claims["acr"] = acr
	}

	p.assurance.Store(&claims)
}

// newOIDCTestProvider starts the provider; it is closed when the test ends.
func newOIDCTestProvider(t *testing.T) *oidcTestProvider {
	t.Helper()

	p := &oidcTestProvider{}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", p.serveToken)
	p.srv = httptest.NewTLSServer(mux)
	t.Cleanup(p.srv.Close)

	return p
}

// provider is the registration of the test provider as testOIDCProvider.
func (p *oidcTestProvider) provider() oidc.Provider {
	return oidc.Provider{ //nolint:gosec // G101: a fixture, not a credential
		Name:                  testOIDCProvider,
		Issuer:                p.srv.URL,
		ClientID:              "app",
		ClientSecret:          "secret-" + testOIDCProvider + "-0123456789abcdef0123456789abcdef",
		RedirectURL:           "https://app.example.com" + httpsec.DefaultOIDCCallbackPath + testOIDCProvider,
		AuthorizationEndpoint: p.srv.URL + "/authorize",
		TokenEndpoint:         p.srv.URL + "/token",
		JWKSURI:               p.srv.URL + "/jwks",
		SigningAlgs:           []string{"HS256"},
	}
}

// serveToken answers a code exchange with an ID token for oidcTestSubject
// whose nonce is the code.
func (p *oidcTestProvider) serveToken(w http.ResponseWriter, r *http.Request) {
	if p.tokenDown.Load() {
		http.Error(w, `{"error":"temporarily_unavailable"}`, http.StatusServiceUnavailable)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	reg := p.provider()
	now := time.Now()

	claims := map[string]any{
		"iss":   reg.Issuer,
		"aud":   reg.ClientID,
		"sub":   oidcTestSubject,
		"sid":   oidcTestSessionID,
		"iat":   now.Unix(),
		"exp":   now.Add(5 * time.Minute).Unix(),
		"nonce": r.PostForm.Get("code"),
	}
	if asserted := p.assurance.Load(); asserted != nil {
		maps.Copy(claims, *asserted)
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	signed, err := jws.Sign(payload, jws.WithKey(jwa.HS256(), []byte(reg.ClientSecret)))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"access_token": "discarded",
		"token_type":   "Bearer",
		"id_token":     string(signed),
	})
}

// oidcHarness is what a federated-login chain is wired to: a real manager
// over the test provider, a real flow store, broker, handoff manager and
// session manager, with doubles only for the consumer's user store and token
// generator.
type oidcHarness struct {
	provider *oidcTestProvider
	flows    *oidc.MemoryFlowStore
	manager  *oidc.RelyingParty
	handoffs *oidc.Handoff
	store    *oidc.MemoryHandoffStore
	sessions *session.Sessions
	tokens   *MockGenerator
	logs     *syncBuffer

	// chainOpts are chain options a case adds beside EnableOIDCLogin: a
	// policy engine, EnableMFA.
	chainOpts []httpsec.Option

	// issued counts the access tokens the chain issued.
	issued atomic.Int64
}

// newOIDCHarness builds the harness, with managerOpts configuring the OIDC
// manager beside the flow store and outbound client it always gets.
func newOIDCHarness(t *testing.T, managerOpts ...oidc.Option) *oidcHarness {
	t.Helper()

	ctrl := gomock.NewController(t)
	p := newOIDCTestProvider(t)

	users := NewMockUserLoader(ctrl)
	users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, id identity.UserID) (*identity.Details, error) {
			if id != oidcTestUserID {
				return nil, identity.ErrUserNotFound
			}

			return &identity.Details{ID: oidcTestUserID, Username: "ada@example.com", Active: true}, nil
		})

	links := oidc.NewMemoryLinkStore()
	require.NoError(t, links.Insert(t.Context(), oidc.Link{
		Provider:  testOIDCProvider,
		Issuer:    p.srv.URL,
		Subject:   oidcTestSubject,
		UserID:    oidcTestUserID,
		CreatedAt: time.Now(),
	}))

	broker, err := oidc.NewBroker(links, users)
	require.NoError(t, err)

	registry, err := oidc.NewRegistry(p.provider())
	require.NoError(t, err)

	client, err := outbound.New(outbound.WithHTTPClient(p.srv.Client()))
	require.NoError(t, err)

	flows, err := oidc.NewMemoryFlowStore()
	require.NoError(t, err)

	opts := append([]oidc.Option{
		oidc.WithOutboundClient(client),
		oidc.WithFlowStore(flows),
	}, managerOpts...)

	manager, err := oidc.NewRelyingParty(registry, broker, opts...)
	require.NoError(t, err)

	store := oidc.NewMemoryHandoffStore()

	handoffs, err := oidc.NewHandoff(store, users)
	require.NoError(t, err)

	sessions, err := session.New()
	require.NoError(t, err)

	return &oidcHarness{
		provider: p,
		flows:    flows,
		manager:  manager,
		handoffs: handoffs,
		store:    store,
		sessions: sessions,
		tokens:   NewMockGenerator(ctrl),
		logs:     &syncBuffer{},
	}
}

// chain builds a chain with the default conveyance and opts.
func (h *oidcHarness) chain(t *testing.T, opts ...httpsec.OIDCOption) *httpsec.Chain {
	t.Helper()

	return h.build(t, h.handoffs, append([]httpsec.OIDCOption{
		httpsec.WithOIDCTokens(h.tokens),
		httpsec.WithOIDCSessions(h.sessions),
	}, opts...)...)
}

// conveyedChain builds a chain whose callback success is fn, and so with no
// handoff manager.
func (h *oidcHarness) conveyedChain(
	t *testing.T, fn httpsec.CallbackSuccess, opts ...httpsec.OIDCOption,
) *httpsec.Chain {
	t.Helper()

	return h.build(t, nil, append([]httpsec.OIDCOption{
		httpsec.WithOIDCSessions(h.sessions),
		httpsec.WithOIDCCallbackSuccess(fn),
	}, opts...)...)
}

func (h *oidcHarness) build(
	t *testing.T, handoffs *oidc.Handoff, opts ...httpsec.OIDCOption,
) *httpsec.Chain {
	t.Helper()

	c, err := h.assemble(handoffs, opts...)
	require.NoError(t, err)

	return c
}

// assemble is build without the assertion, for the cases that are about the
// construction error itself.
func (h *oidcHarness) assemble(handoffs *oidc.Handoff, opts ...httpsec.OIDCOption) (*httpsec.Chain, error) {
	chainOpts := []httpsec.Option{
		httpsec.WithLogger(slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))),
		httpsec.WithRefusalLogInterval(0),
	}
	chainOpts = append(chainOpts, h.chainOpts...)
	chainOpts = append(chainOpts, httpsec.EnableOIDCLogin(h.manager, handoffs, opts...))

	return httpsec.New(chainOpts...)
}

// issueTokens lets the chain issue access tokens, counting each one.
func (h *oidcHarness) issueTokens() {
	h.tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(context.Context, string, *identity.Principal) (string, error) {
			h.issued.Add(1)

			return "issued-token", nil
		})
}

// oidcTestIDToken is the raw ID token a test handoff carries. It is opaque to
// redemption, which only records it on the session.
const oidcTestIDToken = "raw.id.token" //nolint:gosec // G101: a fixture, not a credential

// handoffResult is the login a genuine callback for the linked user
// conveys, with no destination recorded.
func (h *oidcHarness) handoffResult() oidc.CallbackResult {
	return oidc.CallbackResult{
		Principal: &identity.Principal{ID: oidcTestUserID, Username: "ada@example.com"},
		Provider:  testOIDCProvider,
		Issuer:    h.provider.srv.URL,
		SessionID: oidcTestSessionID,
		IDToken:   oidcTestIDToken,
	}
}

// issueHandoff issues a handoff code for the linked user, as a genuine
// callback would, with next as the destination the login recorded.
func (h *oidcHarness) issueHandoff(t *testing.T, next string) string {
	t.Helper()

	res := h.handoffResult()
	res.Next = next

	return h.issueHandoffFor(t, res)
}

// issueHandoffFor issues a handoff code for res.
func (h *oidcHarness) issueHandoffFor(t *testing.T, res oidc.CallbackResult) string {
	t.Helper()

	code, err := h.handoffs.Issue(t.Context(), res)
	require.NoError(t, err)

	return code
}

// oidcTestSource is the address handoff redemptions come from unless a case
// names another.
const oidcTestSource = "203.0.113.7"

// handoffRequest posts code as the handoff form field from source.
func handoffRequest(ctx context.Context, source, code string) *http.Request {
	return postValues(ctx, httpsec.DefaultOIDCHandoffPath, source,
		url.Values{httpsec.DefaultOIDCHandoffParam: {code}})
}

// liveFlows counts the flows the store holds, by purging all of them: it is
// the last thing a case reads from the store.
func (h *oidcHarness) liveFlows(t *testing.T) int {
	t.Helper()

	n, err := h.flows.DeleteExpired(t.Context(), time.Now().Add(24*time.Hour))
	require.NoError(t, err)

	return n
}

// storedHandoffs counts the handoff codes the store holds, by purging all of
// them: it is the last thing a case reads from the store.
func (h *oidcHarness) storedHandoffs(t *testing.T) int {
	t.Helper()

	n, err := h.store.DeleteExpired(t.Context(), time.Now().Add(24*time.Hour))
	require.NoError(t, err)

	return n
}

// activeSessions counts the linked user's sessions.
func (h *oidcHarness) activeSessions(t *testing.T) int {
	t.Helper()

	n, err := h.sessions.CountActiveByUser(t.Context(), oidcTestUserID)
	require.NoError(t, err)

	return n
}

// oidcLogin is a login a browser started: the flow cookie it holds and the
// state and nonce the authorize redirect carried.
type oidcLogin struct {
	handle, state, nonce string
}

// startLogin starts a login for testOIDCProvider with next as the requested
// destination, and returns what the browser now holds.
func startLogin(t *testing.T, c *httpsec.Chain, next string) oidcLogin {
	t.Helper()

	target := httpsec.DefaultOIDCAuthorizePath + testOIDCProvider
	if next != "" {
		target += "?" + url.Values{httpsec.DefaultOIDCNextParam: {next}}.Encode()
	}

	out := serve(t, c, httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil))
	require.NoError(t, out.err)
	require.Equal(t, http.StatusFound, out.rec.Code)

	// The only cookie the endpoint sets, whatever the chain named it.
	cookies := out.rec.Result().Cookies() //nolint:bodyclose // the recorder's result has no body to close
	require.Len(t, cookies, 1, "the authorize response set no flow cookie")
	cookie := cookies[0]

	loc, err := url.Parse(out.rec.Header().Get("Location"))
	require.NoError(t, err)

	return oidcLogin{
		handle: cookie.Value,
		state:  loc.Query().Get("state"),
		nonce:  loc.Query().Get("nonce"),
	}
}

// callbackRequest is the provider's redirect back to the callback with
// rawQuery, carrying the flow cookie when handle is not empty.
func callbackRequest(ctx context.Context, rawQuery, handle string) *http.Request {
	target := httpsec.DefaultOIDCCallbackPath + testOIDCProvider
	if rawQuery != "" {
		target += "?" + rawQuery
	}

	req := httptest.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if handle != "" {
		req.AddCookie(&http.Cookie{Name: httpsec.DefaultOIDCFlowCookieName, Value: handle}) //nolint:gosec // G124: a request cookie, never set
	}

	return req
}

// genuineCallback is the query the provider sends back for login l.
func (l oidcLogin) genuineCallback() string {
	return url.Values{"code": {l.nonce}, "state": {l.state}}.Encode()
}

// syncBuffer is a bytes.Buffer safe for the concurrent writes of a logger.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}

// logoutTokenSeq numbers the jti of every logout token the helpers sign, so no
// two tokens of one test run share one.
var logoutTokenSeq atomic.Int64

// logoutClaims are the claims of a valid back-channel logout token from the
// test provider, issued at iat, naming sub and sid; an empty sub or sid is
// left out.
func (p *oidcTestProvider) logoutClaims(iat time.Time, sub, sid string) map[string]any {
	reg := p.provider()

	claims := map[string]any{
		"iss":    reg.Issuer,
		"aud":    reg.ClientID,
		"iat":    iat.Unix(),
		"jti":    fmt.Sprintf("jti-%d", logoutTokenSeq.Add(1)),
		"events": map[string]any{oidc.BackchannelLogoutEvent: map[string]any{}},
	}
	if sub != "" {
		claims["sub"] = sub
	}
	if sid != "" {
		claims["sid"] = sid
	}

	return claims
}

// logoutToken signs a valid back-channel logout token naming sub and sid,
// issued now, as the test provider does: HS256 under the client secret.
func (p *oidcTestProvider) logoutToken(t *testing.T, sub, sid string) string {
	t.Helper()

	return p.signClaims(t, []byte(p.provider().ClientSecret), p.logoutClaims(time.Now(), sub, sid))
}

// signClaims signs claims with HS256 under key.
func (p *oidcTestProvider) signClaims(t *testing.T, key []byte, claims map[string]any) string {
	t.Helper()

	payload, err := json.Marshal(claims)
	require.NoError(t, err)

	signed, err := jws.Sign(payload, jws.WithKey(jwa.HS256(), key))
	require.NoError(t, err)

	return string(signed)
}

// managerWith builds a manager over the test provider, as edit leaves its
// registration (nil keeps it as it is), resolving identities through broker.
func (h *oidcHarness) managerWith(
	t *testing.T, broker oidc.IdentityBroker, edit func(*oidc.Provider), opts ...oidc.Option,
) *oidc.RelyingParty {
	t.Helper()

	reg := h.provider.provider()
	if edit != nil {
		edit(&reg)
	}

	registry, err := oidc.NewRegistry(reg)
	require.NoError(t, err)

	client, err := outbound.New(outbound.WithHTTPClient(h.provider.srv.Client()))
	require.NoError(t, err)

	m, err := oidc.NewRelyingParty(registry, broker, append([]oidc.Option{
		oidc.WithOutboundClient(client),
		oidc.WithFlowStore(h.flows),
	}, opts...)...)
	require.NoError(t, err)

	return m
}

// recoveryCodeSubject is the subject the harness's message builder gives the
// message carrying an issued code, so a test can find it among the notices.
const recoveryCodeSubject = "issued-code"

// recoveryMessages is the harness's message builder: the issued code is the
// whole body, so a test reads it back without parsing prose.
type recoveryMessages struct{}

func (recoveryMessages) IssuedCode(code string, _ time.Time) (string, string) {
	return recoveryCodeSubject, code
}

func (recoveryMessages) Recovered(recovery.Notice) (string, string) { return "recovered", "recovered" }

func (recoveryMessages) Held(_ recovery.Notice, link string, _ time.Time) (string, string) {
	return "held", link
}

func (recoveryMessages) Cancelled(recovery.Notice) (string, string) { return "cancelled", "cancelled" }
func (recoveryMessages) Regenerated(time.Time) (string, string)     { return "regenerated", "regenerated" }

// recoveryHarness is what a recovery chain is wired to: the real recovery core
// over its in-memory stores, a real saved-code manager, a real TOTP method,
// the real password authenticator behind form login and a real session
// manager. Only the user store and the token generator are doubles, since
// scrty ships neither; a case replaces a port with a strict double where it
// must show the port was never reached.
type recoveryHarness struct {
	sessions *session.Sessions
	codes    *recovery.Codes
	totp     *mfa.TOTP
	clock    *clockwork.FakeClock
	sender   *capturingSender
	tokens   *MockGenerator
	attempts *lockout.MemoryAttemptStore

	// users is what the chain and the core load users through, and
	// authn what form login judges passwords with. Both are real-backed by
	// default; a case may replace either before build.
	users *MockUserLoader
	authn authenticate.Authenticator

	secret string

	// send, when set, replaces sender as the recovery's sender.
	send notify.Sender

	// records, when set, is the recovery's record store in place of the
	// core's in-memory default.
	records recovery.RecordStore

	// proofs are the proof kinds the core enables.
	proofs []recovery.ProofKind

	// coreOpts are further core options, after the harness's own.
	coreOpts []recovery.Option

	// noCoreClock leaves the harness's clock out of the core options, so the
	// core reads whatever time source the chain hands it.
	noCoreClock bool

	// recOpts are further recovery options.
	recOpts []httpsec.RecoveryOption

	// chainOpts are further chain options, applied before recovery.
	chainOpts []httpsec.Option

	// noFormLogin builds the chain without form login, and noBinding without
	// the password-change resolve endpoint, the harness's one binding route.
	noFormLogin bool
	noBinding   bool

	// reference builds the chain in the session-reference bearer mode: form
	// login is given no token generator, and EnableSessionBearer is on, so
	// every credential the chain issues is a session identifier.
	reference bool

	chain *httpsec.Chain

	// allow and coreCheckCalls are state a case's consumer hooks share with
	// its act and assert.
	allow          *atomic.Bool
	coreCheckCalls *atomic.Int32
}

// last is the most recent message the sender was given.
func (s *capturingSender) last(t *testing.T) notify.Message {
	t.Helper()

	s.mu.Lock()
	defer s.mu.Unlock()

	require.NotEmpty(t, s.sent, "nothing was sent")

	return s.sent[len(s.sent)-1]
}

func newRecoveryHarness(t *testing.T) *recoveryHarness {
	t.Helper()

	ctrl := gomock.NewController(t)
	clk := clockwork.NewFakeClockAt(time.Now().Truncate(time.Minute))

	// The sessions, the core and TOTP share one fake clock, so a case moves
	// time for all of them at once.
	sessions, err := session.New(session.WithClock(clk),
		session.WithStore(session.NewMemoryStore(session.WithMemoryStoreClock(clk))))
	require.NoError(t, err)

	codes, err := recovery.NewCodes()
	require.NoError(t, err)

	h := &recoveryHarness{
		sessions: sessions,
		codes:    codes,
		clock:    clk,
		sender:   &capturingSender{},
		tokens:   NewMockGenerator(ctrl),
		attempts: lockout.NewMemoryAttemptStore(),
		users:    NewMockUserLoader(ctrl),
		proofs: []recovery.ProofKind{
			recovery.ProofSaved, recovery.ProofIssued, recovery.ProofPassword, recovery.ProofMFA,
		},
	}

	h.totp, err = mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example", mfa.WithClock(clk))
	require.NoError(t, err)

	hash, err := e2eEncoder(t).Encode(e2ePassword)
	require.NoError(t, err)

	details := func() *identity.Details {
		return &identity.Details{ID: e2eUser, Name: "Grace Hopper", Username: e2eAddress, Password: hash, Active: true}
	}

	h.users.EXPECT().LoadByUsername(gomock.Any(), e2eAddress).AnyTimes().
		DoAndReturn(func(context.Context, string) (*identity.Details, error) { return details(), nil })
	h.users.EXPECT().LoadByUserID(gomock.Any(), e2eUser).AnyTimes().
		DoAndReturn(func(context.Context, identity.UserID) (*identity.Details, error) { return details(), nil })
	h.users.EXPECT().LoadByUsername(gomock.Any(), gomock.Any()).AnyTimes().
		Return(nil, identity.ErrUserNotFound)

	h.authn, err = authenticate.NewUsernamePasswordAuthenticator(h.users,
		authenticate.WithPasswordEncoder(e2eEncoder(t)))
	require.NoError(t, err)

	h.tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, id string, _ *identity.Principal) (string, error) {
			return mfaTokenFor(id), nil
		})
	h.tokens.EXPECT().Verify(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, presented string) (*token.Claims, error) {
			id, ok := strings.CutPrefix(presented, mfaTokenPrefix)
			if !ok {
				return nil, errMFATokenUnreadable
			}

			return token.NewClaims(e2eAddress, id), nil
		})

	return h
}

// options are the chain options the harness builds with.
func (h *recoveryHarness) options(t *testing.T) []httpsec.Option {
	t.Helper()

	kind, err := recovery.MFAEnrolments(h.totp)
	require.NoError(t, err)

	core := []recovery.Option{
		recovery.WithProofs(h.proofs...),
		recovery.WithRepudiationContact("Write to security@example.com if this was not you."),
		recovery.WithAuthenticatorKinds(kind),
		recovery.WithMFAMethods(h.totp),
		recovery.WithMessages(recoveryMessages{}),
	}
	if !h.noCoreClock {
		core = append(core, recovery.WithClock(h.clock))
	}
	core = append(core, h.coreOpts...)

	opts := append([]httpsec.Option(nil), h.chainOpts...)

	if !h.noFormLogin {
		deps := httpsec.FormLoginDeps{
			Authenticator: h.authn,
			Sessions:      h.sessions,
			Tokens:        h.tokens,
			Attempts:      h.attempts,
		}
		if h.reference {
			deps.Tokens = nil
		}

		opts = append(opts, httpsec.EnableFormLogin(deps))
	}

	if h.reference {
		opts = append(opts, httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: h.sessions, Users: h.users}))
	}

	if !h.noBinding {
		opts = append(opts, httpsec.EnablePasswordChangeGate(h.sessions,
			httpsec.WithPasswordChangeEndpoint(passwordResolvePath, func(*httpsec.Exchange) error { return nil })))
	}

	opts = append(opts,
		httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: h.sessions}),
		httpsec.EnableAccountRecovery(h.deps(),
			append([]httpsec.RecoveryOption{httpsec.WithRecoveryCore(core...)}, h.recOpts...)...),
	)

	return opts
}

// deps are the recovery's ports.
func (h *recoveryHarness) deps() httpsec.RecoveryDeps {
	var sender notify.Sender = h.sender
	if h.send != nil {
		sender = h.send
	}

	return httpsec.RecoveryDeps{
		Users: h.users, Sessions: h.sessions, Sender: sender, Codes: h.codes, Records: h.records,
	}
}

// build assembles the chain, which must succeed.
func (h *recoveryHarness) build(t *testing.T) *recoveryHarness {
	t.Helper()

	var err error

	h.chain, err = httpsec.New(h.options(t)...)
	require.NoError(t, err)

	return h
}

// saved generates the user's saved set and returns its first code.
func (h *recoveryHarness) saved(t *testing.T) string {
	t.Helper()

	set, err := h.codes.Generate(t.Context(), e2eUser)
	require.NoError(t, err)

	return set[0]
}

// issued starts a recovery through the chain and returns the code it emailed.
func (h *recoveryHarness) issued(t *testing.T) string {
	t.Helper()

	before := h.sender.count()

	out := serve(t, h.chain, postValues(t.Context(), httpsec.DefaultRecoveryStartPath, e2eSource,
		url.Values{httpsec.RecoveryUsernameParam: {e2eAddress}}))
	require.NoError(t, out.err)
	require.Equal(t, before+1, h.sender.count(), "the start sent no code")

	h.sender.mu.Lock()
	defer h.sender.mu.Unlock()

	last := h.sender.sent[len(h.sender.sent)-1]
	require.Equal(t, recoveryCodeSubject, last.Subject)

	return last.TextBody
}

// enrolTOTP enrols the user on TOTP, so a TOTP code can serve as a proof.
func (h *recoveryHarness) enrolTOTP(t *testing.T) {
	t.Helper()

	prov, err := h.totp.BeginEnrolment(t.Context(), e2eUser, e2eAddress)
	require.NoError(t, err)

	code, err := totp.GenerateCode(prov.Secret, h.clock.Now())
	require.NoError(t, err)
	require.NoError(t, h.totp.ConfirmEnrolment(t.Context(), e2eUser, code))

	h.secret = prov.Secret
}

// totpCode is a code for the next time step, so it is not the step the
// enrolment already spent.
func (h *recoveryHarness) totpCode(t *testing.T) string {
	t.Helper()

	h.clock.Advance(h.totp.Period())

	code, err := totp.GenerateCode(h.secret, h.clock.Now())
	require.NoError(t, err)

	return code
}

// complete posts values to the complete path from the harness's source.
func (h *recoveryHarness) complete(t *testing.T, values url.Values) served {
	t.Helper()

	return serve(t, h.chain, postValues(t.Context(), httpsec.DefaultRecoveryCompletePath, e2eSource, values))
}

// through runs req through the chain's net/http middleware, which writes the
// status a refusal maps to, so a test compares whole responses.
func (h *recoveryHarness) through(req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.chain.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})).ServeHTTP(rec, req)

	return rec
}
