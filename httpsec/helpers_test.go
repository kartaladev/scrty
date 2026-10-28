package httpsec_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/apikey"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/expiry"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
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

// The summary records each component writes when a flush reports what it held
// back. A row reads its own component's summaries by these, so a row passes
// only when the flush reached that component, not merely some sampler.
const (
	summaryChain     = "httpsec: refusal logs suppressed"
	summaryThrottle  = "mfa: verification refusals suppressed"
	summaryAuthn     = "authentication refusals suppressed"
	summaryOIDC      = "oidc refusals suppressed"
	summaryHandoff   = "oidc handoff refusals suppressed"
	summaryMFAPolicy = "policy: second-factor records suppressed"
)

//go:generate mockgen -source=helpers_test.go -package=httpsec_test -destination=decoyauthenticator_mock_test.go -typed -mock_names=DecoyAuthenticator=MockDecoyAuthenticator

// DecoyAuthenticator is an authenticator that can also spend decoy password
// verifications, as the chain's lock refusal looks for.
type DecoyAuthenticator interface {
	authenticate.Authenticator
	authenticate.DecoyVerifier
}
