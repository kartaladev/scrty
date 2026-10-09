// Package httpsecconformance holds the one set of behaviours every framework
// integration of the security chain must produce identically.
//
// The chain is framework-neutral: net/http, gin and fiber each adapt the same
// interceptors to their own request and response. Scenarios is that agreement
// written down as data, and Run puts it through one adapter, so a change to an
// interceptor is checked on all three at once rather than on whichever one its
// author happened to have in mind.
//
// The four things every adapter must agree on are the ones the framework
// adapters specification names: the status, the headers the library set, the
// session and attempt side effects, and the refusal error.
//
// This package deliberately uses testify outside a _test.go file. It is a
// helper package in scrty's test module, which no other scrty module imports,
// so nothing it depends on reaches a consumer's module graph.
//
// A consumer running the chain on a fourth framework implements Adapter over
// their own integration and calls Run, and learns from the same table whether
// their integration behaves as the three that ship do.
package httpsecconformance

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

// The paths, credentials and fixed bodies every scenario is written against.
// They are exported because an adapter's own suite reads some of them when it
// mounts routes, and because a consumer debugging a failure needs to know what
// the table sent.
const (
	// LoginPath, LogoutPath and KeySetPath are the chain's own defaults, named
	// here so a scenario and an adapter cannot drift apart over them.
	LoginPath  = httpsec.DefaultLoginPath
	LogoutPath = httpsec.DefaultLogoutPath
	KeySetPath = httpsec.DefaultJWKSPath

	// RoutePath is the application route the scenarios mount behind the chain.
	RoutePath = "/records/r-1"

	// Username and Password are the one credential pair the fixture
	// authenticator resolves. Everything else is refused.
	Username = "ada"
	Password = "s3cret" //nolint:gosec // a fixture credential, not a real one

	// UserID is the identifier the fixture user store gives Username.
	UserID identity.UserID = "u-1"

	// ClientAddress is the address every scenario but the unattributable one is
	// sent from.
	ClientAddress = "198.51.100.7"

	// KeySetBody is exactly what the fixture key set provider serves. A
	// scenario asserts the response body equals it, so a route or a no-route
	// handler that appended anything is caught.
	KeySetBody = `{"keys":[]}`

	// NoRouteBody is what a consumer's no-route handler writes. It appears in
	// no expected body: its whole purpose is to be absent.
	NoRouteBody = "no-route"

	// RouteBody is what an application route writes when it is reached.
	RouteBody = "route"

	// UpstreamValue is what middleware outside the chain puts on the request
	// context before the chain runs, so a scenario can pin that the chain
	// derived from the incoming context rather than replacing it.
	UpstreamValue = "trace-7"
)

// tokenPrefix marks a credential the fixture token generator issued. It is not
// a real token: the generator and the verifier are fixtures, and what the
// verifier reports is the only thing the chain reads.
const tokenPrefix = "conformance-token." //nolint:gosec // a fixture prefix, not a credential

// UpstreamKey is the context key an adapter's own middleware publishes
// UpstreamValue under, before the chain runs.
//
// It is exported because each adapter registers that middleware in its own
// framework's terms, and the route behind the chain must read back what the
// middleware in front of it wrote.
type UpstreamKey struct{}

// TestPrincipal is the caller every scenario authenticates.
func TestPrincipal() *identity.Principal {
	return &identity.Principal{ID: UserID, Username: Username, Name: "Ada"}
}

// Effects is the state one run left behind, and the fixtures that recorded it.
//
// It is how a scenario asserts on the side effects the specification requires
// every adapter to agree on — sessions created, attempts recorded — rather than
// only on the response. Build creates one per run, so each framework is judged
// on stores of its own and cannot be credited with another's writes.
type Effects struct {
	// Sessions is the manager every scenario's chain is wired with, and Store
	// is the store underneath it, held separately because counting a user's
	// live sessions is what a scenario asserts on.
	Sessions *session.Manager
	Store    *session.MemoryStore

	// Attempts is the failed-login counter the chain records against.
	Attempts policy.AttemptStore

	// OIDC is the federated-login wiring of an OIDC scenario, and nil for
	// every other scenario.
	OIDC *OIDCFixture

	// Enrolment is the enrolment path's wiring of an enrolment scenario, and
	// nil for every other scenario.
	Enrolment *EnrolmentFixture

	// Recovery is the account-recovery path's wiring of a recovery scenario,
	// over its own durable PostgreSQL-backed stores, and nil for every other
	// scenario.
	Recovery *RecoveryFixture

	// Passkey is the passkey wiring of a passkey scenario, over the same
	// durable stores as Recovery, and nil for every other scenario.
	Passkey *PasskeyFixture

	// SessionID is the session Build pre-created, for the scenarios that need a
	// request to arrive already authenticated. It is empty where none was.
	SessionID string

	// authCalls counts the times the authenticator was asked anything, so a
	// scenario can pin that a password was never checked.
	authCalls atomic.Int64

	// recoveryStandalone and recoveryCompletion are a held-recovery scenario's
	// own Recoverer, sharing the run's durable stores with the chain the
	// adapter serves, and the completion token its hold returned. They let a
	// scenario check a held recovery's disposition directly, without a second
	// request through the adapter under test.
	recoveryStandalone *recovery.Recoverer
	recoveryCompletion string

	// recoverySavedCode and recoveryIssuedCode are the two proofs a recovery
	// scenario's Build minted for the one HTTP request it sends, and that its
	// Assert reuses against the standalone Recoverer to check what the
	// request's own outcome left spendable.
	recoverySavedCode  string
	recoveryIssuedCode string

	// recoveryCancelToken is the cancel token a held-recovery scenario read
	// back from the Held notice's link, for the one cancel request it sends.
	recoveryCancelToken string

	mu sync.Mutex
	// clientAddr is the address the chain was given, as the adapter reported
	// it. It is not compared across frameworks: an in-memory transport names a
	// different peer from a recorder, and what must agree is the decision the
	// chain took, not the string it took it from.
	clientAddr string
	addrSeen   bool
}

// AuthenticatorCalls is how many times the fixture authenticator was asked to
// resolve a credential.
func (e *Effects) AuthenticatorCalls() int { return int(e.authCalls.Load()) }

// ClientAddress is the address the chain read through Request.ClientIP, and
// whether an interceptor got far enough to read one at all.
func (e *Effects) ClientAddress() (addr string, seen bool) {
	e.mu.Lock()
	defer e.mu.Unlock()

	return e.clientAddr, e.addrSeen
}

// recordAddress notes what the adapter attributed this request to.
func (e *Effects) recordAddress(addr string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.clientAddr, e.addrSeen = addr, true
}

// ActiveSessions counts the live sessions the run left for UserID.
func (e *Effects) ActiveSessions(t *testing.T) int {
	t.Helper()

	n, err := e.Store.CountActiveByUser(t.Context(), UserID)
	require.NoError(t, err)

	return n
}

// RecordedFailures counts the failed login attempts the run recorded against
// Username.
func (e *Effects) RecordedFailures(t *testing.T) int {
	t.Helper()

	n, err := e.Attempts.FailureCount(t.Context(), Username, time.Time{})
	require.NoError(t, err)

	return n
}

// LoadSession reads a session back out of the store, so a scenario can assert
// what the chain marked on it.
func (e *Effects) LoadSession(t *testing.T, id string) *session.Session {
	t.Helper()

	s, err := e.Store.Load(t.Context(), id)
	require.NoError(t, err)

	return s
}

// newEffects builds the stores one run is wired with.
func newEffects(t *testing.T) *Effects {
	t.Helper()

	store := session.NewMemoryStore()

	manager, err := session.NewManager(session.WithStore(store))
	require.NoError(t, err)

	return &Effects{
		Sessions: manager,
		Store:    store,
		Attempts: policy.NewMemoryAttemptStore(),
	}
}

// GuardKind names the per-endpoint guard a scenario mounts on its route. Each
// adapter builds the same guard from its own guards package, which is the point
// of the scenario: the three must refuse and admit the same callers.
type GuardKind int

const (
	// GuardNone mounts no guard.
	GuardNone GuardKind = iota

	// GuardAuthenticated mounts the guard that any known caller passes.
	GuardAuthenticated

	// GuardPrivilege mounts a privilege guard over GuardGroup and
	// GuardResource, requiring GuardPrivilegeName.
	GuardPrivilege
)

// The resource a privilege guard is built over. They are spelled as a
// consumer's own role data would spell them; the library compares them and
// never parses them.
const (
	GuardGroup         = "records"
	GuardResource      = "record"
	GuardPrivilegeName = "read"
)

// GuardSpec is the guard an adapter mounts in front of one route.
type GuardSpec struct {
	// Kind is which guard to build. GuardNone means none.
	Kind GuardKind

	// Path is the route the guard sits in front of.
	Path string

	// Authorizer is the fallback judge the guards are built with. A nil one
	// leaves the guards relying on whatever the chain published, which is the
	// wiring a deployment that mounts the chain uses.
	Authorizer authorize.Authorizer
}

// Route is an application route mounted behind the chain.
//
// Status zero writes nothing, so whatever the chain wrote stands and the route
// only records that it ran. A non-zero status is how a scenario tells a route
// that ran from one the adapter stopped: a route that answers 201 on a path the
// chain answers itself would overwrite the chain's answer if it were reached.
type Route struct {
	Method string
	Path   string
	Status int
	Body   string
}

// ChainSpec is everything an adapter needs to stand its framework up for one
// scenario.
//
// The chain is described by its options rather than handed over built, because
// each adapter adds one option of its own: the recorder that captures the
// refusal. On net/http that is httpsec.WithErrorHandler reproducing the
// library's own default exactly; gin and fiber read the refusal from their own
// error channel and need no option. Building from one list of options is what
// makes "the same chain built from the same options" literally true.
type ChainSpec struct {
	// Options are the chain's options, in order.
	Options []httpsec.Option

	// Effects are the stores those options were wired with.
	Effects *Effects

	// Routes are the application routes mounted behind the chain.
	Routes []Route

	// Guard is the per-endpoint guard mounted in front of Guard.Path, and
	// GuardNone when the scenario mounts none.
	Guard GuardSpec

	// NoRoute asks the adapter to register a consumer no-route handler that
	// writes NoRouteBody, so a scenario can prove the chain's own answer was
	// not appended to.
	NoRoute bool

	// Upstream asks the adapter to register middleware outside the chain that
	// publishes UpstreamValue under UpstreamKey, so a scenario can prove the
	// chain derived from the incoming context rather than replacing it.
	Upstream bool
}

// NewChain builds the scenario's chain, plus whatever options the adapter adds
// of its own. It fails the test rather than returning an error: a chain that
// does not build is a fault in the table, not an outcome a scenario asserts on.
func (s ChainSpec) NewChain(t *testing.T, extra ...httpsec.Option) *httpsec.Chain {
	t.Helper()

	c, err := httpsec.New(append(append([]httpsec.Option(nil), s.Options...), extra...)...)
	require.NoError(t, err)

	return c
}

// RequestSpec is the one request a scenario sends.
type RequestSpec struct {
	Method string

	// Path is the request target, query string included.
	Path string

	// Header is what the request carries. An adapter sets every entry verbatim.
	Header map[string]string

	// Body is the request body, sent as given.
	Body string

	// ClientAddress is the address the request must be attributed to, and "" is
	// the scenario that asks what happens when no address can be attributed at
	// all. How an adapter arranges either is its own business: a recorder sets
	// the transport peer, while fiber's in-memory transport reports an
	// unspecified peer and needs a trusted forwarding header instead.
	ClientAddress string
}

// Result is what one run produced, read out in full so a scenario asserts on
// values rather than on an open response.
type Result struct {
	Status int
	Header http.Header
	Body   string

	// RouteRan reports whether an application route behind the chain was
	// reached, and NoRouteRan whether a consumer's no-route handler was.
	RouteRan   bool
	NoRouteRan bool

	// Refusal is the error the adapter's own error channel carried, and nil
	// when the chain refused nothing. Each adapter reads it where its framework
	// puts it: an error handler on net/http, gin's error channel, the error
	// fiber's handler was given.
	Refusal error

	// Principal, Session and Upstream are what a route behind the chain read
	// through its framework's own request context.
	Principal      *identity.Principal
	PrincipalKnown bool
	SessionID      string
	SessionKnown   bool
	Upstream       string

	// Effects are the stores the scenario's chain was wired with, carried here
	// so an assertion reads the response and the side effects in one place.
	Effects *Effects
}

// ReadContext fills the context-derived fields of res from the context a route
// behind the chain was given.
//
// Every adapter's route handler calls it, so the three read the same things the
// same way and a difference in the result is a difference in what the adapter
// published rather than in how the suite looked.
func ReadContext(ctx context.Context, res *Result) {
	res.Principal, res.PrincipalKnown = identity.PrincipalFromContext(ctx)

	if s, ok := httpsec.SessionFromContext(ctx); ok {
		res.SessionID, res.SessionKnown = s.ID, true
	}

	if v, ok := ctx.Value(UpstreamKey{}).(string); ok {
		res.Upstream = v
	}
}

// Scenario is one behaviour, and everything needed to put it through a
// framework.
type Scenario struct {
	// Name is the behaviour, phrased as what must happen.
	Name string

	// Build wires the chain and the stores for one run. It is called once per
	// adapter, so each framework starts from stores nothing else has written.
	Build func(t *testing.T) ChainSpec

	// Request is the one request the scenario sends. It is called after Build,
	// so a scenario can name a session or a token its own wiring created — a
	// bearer request carries a credential for a session that did not exist
	// until Build made it.
	Request func(spec ChainSpec) RequestSpec

	// Assert is what must be true of the run, whichever framework produced it.
	Assert func(t *testing.T, res Result)

	// Steps, when set, replaces Request and Assert for a behaviour that is a
	// conversation rather than one request: a ceremony begun and then
	// finished, a credential presented that an earlier response issued.
	//
	// It is handed the built spec and a send function that serves one request
	// through the adapter under test, so every request of the conversation goes
	// through the same framework, over the stores Build wired and nothing
	// else. Each send builds the framework's chain afresh from spec's options,
	// which is why a scenario that uses it keeps whatever must outlive one
	// request, such as a challenge store, in the stores and not in the chain.
	Steps func(t *testing.T, spec ChainSpec, send func(RequestSpec) Result)
}

// Adapter runs one scenario on one framework.
//
// An implementation stands its framework up from spec, sends req through it and
// reports what happened. It is the only thing a fourth framework has to write
// to be held to the same table the three that ship are held to.
type Adapter interface {
	Serve(t *testing.T, spec ChainSpec, req RequestSpec) Result
}

// Scenarios is every behaviour that must be identical on every adapter.
//
// It is data, not tests: each adapter's own suite runs it through its
// framework, so a change to an interceptor is checked on all three at once
// rather than on whichever one its author had in mind. The list is the one the
// framework adapters specification gives, plus the two this change earned — a
// credential in the query string, and a key set body nothing appended to.
func Scenarios() []Scenario {
	return append([]Scenario{
		loginSucceeds(),
		loginFailsOnAWrongPassword(),
		lockedAccountIsRefused(),
		queryStringCredentialDoesNotAuthenticate(),
		validBearerTokenIsAccepted(),
		tamperedBearerTokenIsRefused(),
		centralizedRuleAllows(),
		centralizedRuleDenies(),
		guardAllows(),
		guardDenies(),
		loginChallenge(),
		endpointAnsweredByTheChain(),
		keySetEndpoint(),
		contextPropagation(),
		unattributableClientAddress(),
		storeFailureTextStaysOutOfTheRefusal(),
	}, slices.Concat(oidcScenarios(), oidcAssuranceScenarios(), enrolmentScenarios(), requestScenarios(), recoveryScenarios(), passkeyScenarios(), lockoutScenarios())...)
}

// formLoginOptions is the wiring every login scenario shares.
func formLoginOptions(e *Effects) []httpsec.Option {
	return []httpsec.Option{
		httpsec.EnableFormLogin(httpsec.FormLoginDeps{
			Authenticator: &fixtureAuthenticator{calls: &e.authCalls},
			Sessions:      e.Sessions,
			Tokens:        fixtureTokens{},
			Attempts:      e.Attempts,
		}),
	}
}

// bearerOptions is the wiring every scenario that arrives authenticated shares.
func bearerOptions(e *Effects) []httpsec.Option {
	return []httpsec.Option{
		httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
			Verifier: fixtureTokens{},
			Sessions: e.Sessions,
			Users:    fixtureUsers{},
		}),
	}
}

// mfaGateFor is the real second-factor gate the login-challenge scenario
// needs wired in: a stand-in occupying the MFA slot no longer counts as
// enforcing the challenge, so this builds the smallest real one. The
// scenario's user is enrolled on it, so the challenge it raises lists a
// usable method rather than an empty set.
func mfaGateFor(t *testing.T) httpsec.Option {
	t.Helper()

	method, err := mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example")
	require.NoError(t, err)

	provisioning, err := method.BeginEnrolment(t.Context(), UserID, Username)
	require.NoError(t, err)

	code, err := totp.GenerateCode(provisioning.Secret, time.Now())
	require.NoError(t, err)
	require.NoError(t, method.ConfirmEnrolment(t.Context(), UserID, code))

	return httpsec.EnableMFA([]mfa.Method{method}, httpsec.WithMFATokens(fixtureTokens{}))
}

// sending is the request of a scenario whose request does not depend on what
// its own wiring created.
func sending(r RequestSpec) func(ChainSpec) RequestSpec {
	return func(ChainSpec) RequestSpec { return r }
}

// authenticatedRequest carries a token for the session Build pre-created, which
// is why it is resolved from the built spec rather than written as a literal.
func authenticatedRequest(method, path string) func(ChainSpec) RequestSpec {
	return func(spec ChainSpec) RequestSpec {
		return RequestSpec{
			Method:        method,
			Path:          path,
			Header:        map[string]string{"Authorization": "Bearer " + issuedTokenFor(Username, spec.Effects.SessionID)},
			ClientAddress: ClientAddress,
		}
	}
}

// liveSession pre-creates the session a bearer request is authenticated
// against, and records it on e.
func liveSession(t *testing.T, e *Effects) {
	t.Helper()

	s, err := e.Sessions.Create(t.Context(), UserID)
	require.NoError(t, err)

	e.SessionID = s.ID
}

// formBody is a URL-encoded login body and the header that declares it.
func formBody(body string) RequestSpec {
	return RequestSpec{
		Method:        http.MethodPost,
		Path:          LoginPath,
		Header:        map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
		Body:          body,
		ClientAddress: ClientAddress,
	}
}

// plainRoute is the application route the authorization scenarios mount, which
// writes nothing so the chain's own answer is what a scenario reads.
func plainRoute() []Route {
	return []Route{{Method: http.MethodGet, Path: RoutePath}}
}

func loginSucceeds() Scenario {
	// A login is the library's own endpoint: it is answered by the chain, so no
	// route behind it may run and the token must reach the client.
	return Scenario{
		Name: "login succeeds",
		Build: func(t *testing.T) ChainSpec {
			effects := newEffects(t)

			return ChainSpec{
				Options: formLoginOptions(effects),
				Effects: effects,
				Routes:  []Route{{Method: http.MethodPost, Path: LoginPath, Status: http.StatusCreated, Body: RouteBody}},
			}
		},
		Request: sending(formBody("username=" + Username + "&password=" + Password)),
		Assert: func(t *testing.T, res Result) {
			assert.Equal(t, http.StatusOK, res.Status)
			assert.Equal(t, "application/json", res.Header.Get("Content-Type"))
			assert.Contains(t, res.Body, `"access_token":"`+tokenPrefix+Username+`.`)
			assert.NoError(t, res.Refusal)
			assert.False(t, res.RouteRan, "the chain answered the login itself")

			assert.Equal(t, 1, res.Effects.ActiveSessions(t), "one session was opened")
			assert.Equal(t, 0, res.Effects.RecordedFailures(t), "a success records no failure")
		},
	}
}

func loginFailsOnAWrongPassword() Scenario {
	return Scenario{
		Name: "login fails on a wrong password",
		Build: func(t *testing.T) ChainSpec {
			effects := newEffects(t)

			return ChainSpec{Options: formLoginOptions(effects), Effects: effects}
		},
		Request: sending(formBody("username=" + Username + "&password=wrong")),
		Assert: func(t *testing.T, res Result) {
			assert.Equal(t, http.StatusUnauthorized, res.Status)
			assert.Empty(t, res.Body, "a refusal carries no error text")
			require.ErrorIs(t, res.Refusal, authenticate.ErrAuthenticationFailed)

			assert.Equal(t, 0, res.Effects.ActiveSessions(t), "a failure opens no session")
			assert.Equal(t, 1, res.Effects.RecordedFailures(t), "one failed attempt was recorded")
		},
	}
}

func lockedAccountIsRefused() Scenario {
	return Scenario{
		Name: "a locked account is refused",
		Build: func(t *testing.T) ChainSpec {
			effects := newEffects(t)

			engine, err := policy.NewEngine(lockedPolicy{})
			require.NoError(t, err)

			return ChainSpec{
				Options: append(formLoginOptions(effects), httpsec.WithPolicyEngine(engine)),
				Effects: effects,
			}
		},
		Request: sending(formBody("username=" + Username + "&password=" + Password)),
		Assert: func(t *testing.T, res Result) {
			// Concealed by default: answered as a wrong password, and still a
			// lock to the consumer's own handler.
			assert.Equal(t, http.StatusUnauthorized, res.Status)
			assert.Empty(t, res.Body)
			require.ErrorIs(t, res.Refusal, policy.ErrAccountLocked)
			require.ErrorIs(t, res.Refusal, authenticate.ErrAuthenticationFailed)

			assert.Equal(t, 0, res.Effects.AuthenticatorCalls(),
				"a locked account is refused before its password is checked")
			assert.Equal(t, 0, res.Effects.ActiveSessions(t))
		},
	}
}

func queryStringCredentialDoesNotAuthenticate() Scenario {
	// A credential accepted from a query string is one already written into
	// every access log, proxy log and browser history that saw the URL. No
	// adapter may reintroduce net/http's merging of the query into the form.
	return Scenario{
		Name: "a credential in the URL query does not authenticate",
		Build: func(t *testing.T) ChainSpec {
			effects := newEffects(t)

			return ChainSpec{Options: formLoginOptions(effects), Effects: effects}
		},
		Request: sending(RequestSpec{
			Method:        http.MethodPost,
			Path:          LoginPath + "?username=" + Username + "&password=" + Password,
			Header:        map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			ClientAddress: ClientAddress,
		}),
		Assert: func(t *testing.T, res Result) {
			assert.Equal(t, http.StatusBadRequest, res.Status)
			assert.Empty(t, res.Body)
			require.ErrorIs(t, res.Refusal, httpsec.ErrCredentialsMissing)

			assert.Equal(t, 0, res.Effects.AuthenticatorCalls(),
				"nothing in the query string was ever offered as a credential")
			assert.Equal(t, 0, res.Effects.ActiveSessions(t))
		},
	}
}

func validBearerTokenIsAccepted() Scenario {
	return Scenario{
		Name:    "a valid bearer token is accepted",
		Request: authenticatedRequest(http.MethodGet, RoutePath),
		Build: func(t *testing.T) ChainSpec {
			effects := newEffects(t)
			liveSession(t, effects)

			return ChainSpec{
				Options: bearerOptions(effects),
				Effects: effects,
				Routes:  plainRoute(),
			}
		},
		Assert: func(t *testing.T, res Result) {
			assert.NoError(t, res.Refusal)
			assert.True(t, res.RouteRan, "an authenticated request reaches the route")
			require.True(t, res.PrincipalKnown, "the route reads the caller the chain resolved")
			assert.Equal(t, UserID, res.Principal.ID)
			assert.Equal(t, res.Effects.SessionID, res.SessionID)
		},
	}
}

func tamperedBearerTokenIsRefused() Scenario {
	return Scenario{
		Name: "a tampered bearer token is refused",
		Build: func(t *testing.T) ChainSpec {
			effects := newEffects(t)
			liveSession(t, effects)

			return ChainSpec{
				Options: bearerOptions(effects),
				Effects: effects,
				Routes:  plainRoute(),
			}
		},
		Request: sending(RequestSpec{
			Method:        http.MethodGet,
			Path:          RoutePath,
			Header:        map[string]string{"Authorization": "Bearer not-a-token"},
			ClientAddress: ClientAddress,
		}),
		Assert: func(t *testing.T, res Result) {
			assert.Equal(t, http.StatusUnauthorized, res.Status)
			assert.Empty(t, res.Body)
			require.ErrorIs(t, res.Refusal, authenticate.ErrAuthenticationFailed)
			assert.False(t, res.RouteRan, "a refused request never reaches the route")
		},
	}
}

func centralizedRuleAllows() Scenario {
	return Scenario{
		Name:    "a centralized rule allows",
		Request: authenticatedRequest(http.MethodGet, RoutePath),
		Build: func(t *testing.T) ChainSpec {
			effects := newEffects(t)
			liveSession(t, effects)

			return ChainSpec{
				Options: append(bearerOptions(effects), httpsec.EnableAuthorization(
					fixtureAuthorizer{},
					authorize.Rule[httpsec.Request]{
						Match:   func(r httpsec.Request) bool { return r.Path() == RoutePath },
						Require: authorize.Authenticated(),
					},
				)),
				Effects: effects,
				Routes:  plainRoute(),
			}
		},
		Assert: func(t *testing.T, res Result) {
			assert.NoError(t, res.Refusal)
			assert.True(t, res.RouteRan, "the rule permitted this request")
			assert.True(t, res.PrincipalKnown)
		},
	}
}

func centralizedRuleDenies() Scenario {
	return Scenario{
		Name:    "a centralized rule denies",
		Request: authenticatedRequest(http.MethodGet, RoutePath),
		Build: func(t *testing.T) ChainSpec {
			effects := newEffects(t)
			liveSession(t, effects)

			return ChainSpec{
				Options: append(bearerOptions(effects), httpsec.EnableAuthorization(
					fixtureAuthorizer{},
					authorize.Rule[httpsec.Request]{
						Match:   func(r httpsec.Request) bool { return r.Path() == RoutePath },
						Require: authorize.DenyAll(),
					},
				)),
				Effects: effects,
				Routes:  plainRoute(),
			}
		},
		Assert: func(t *testing.T, res Result) {
			assert.Equal(t, http.StatusForbidden, res.Status)
			require.ErrorIs(t, res.Refusal, authorize.ErrAccessDenied)
			assert.False(t, res.RouteRan, "the route behind a denied rule did not run")
		},
	}
}

func guardAllows() Scenario {
	return Scenario{
		Name:    "a guard allows",
		Request: authenticatedRequest(http.MethodGet, RoutePath),
		Build: func(t *testing.T) ChainSpec {
			effects := newEffects(t)
			liveSession(t, effects)

			return ChainSpec{
				Options: append(bearerOptions(effects),
					httpsec.EnableAuthorization(fixtureAuthorizer{})),
				Effects: effects,
				Routes:  plainRoute(),
				Guard:   GuardSpec{Kind: GuardPrivilege, Path: RoutePath},
			}
		},
		Assert: func(t *testing.T, res Result) {
			assert.NoError(t, res.Refusal)
			assert.True(t, res.RouteRan, "the guard's authorizer allowed this caller")
			assert.True(t, res.PrincipalKnown)
		},
	}
}

func guardDenies() Scenario {
	return Scenario{
		Name:    "a guard denies",
		Request: authenticatedRequest(http.MethodGet, RoutePath),
		Build: func(t *testing.T) ChainSpec {
			effects := newEffects(t)
			liveSession(t, effects)

			return ChainSpec{
				Options: append(bearerOptions(effects), httpsec.EnableAuthorization(
					fixtureAuthorizer{err: fmt.Errorf(
						"%w: the caller holds no such privilege", authorize.ErrAccessDenied)})),
				Effects: effects,
				Routes:  plainRoute(),
				Guard:   GuardSpec{Kind: GuardPrivilege, Path: RoutePath},
			}
		},
		Assert: func(t *testing.T, res Result) {
			assert.Equal(t, http.StatusForbidden, res.Status)
			require.ErrorIs(t, res.Refusal, authorize.ErrAccessDenied)
			assert.False(t, res.RouteRan, "the route behind a refusing guard did not run")
		},
	}
}

func loginChallenge() Scenario {
	// A challenge is not a refusal of the caller: the session exists, the
	// prompt is owed, and the token the prompt is answered with was issued.
	return Scenario{
		Name: "a login challenge",
		Build: func(t *testing.T) ChainSpec {
			effects := newEffects(t)

			engine, err := policy.NewEngine(challengingPolicy{})
			require.NoError(t, err)

			return ChainSpec{
				Options: append(formLoginOptions(effects),
					httpsec.WithPolicyEngine(engine),
					// The policy can raise a second-factor challenge, so this
					// chain has to carry something that enforces one: a chain
					// that marks a challenge nothing acts on does not build.
					// A stand-in occupying the slot no longer counts, so this
					// wires the real gate — the smallest one that does.
					mfaGateFor(t)),
				Effects: effects,
			}
		},
		Request: sending(formBody("username=" + Username + "&password=" + Password)),
		Assert: func(t *testing.T, res Result) {
			assert.Equal(t, http.StatusUnauthorized, res.Status)

			var challenge *httpsec.ChallengeError
			require.ErrorAs(t, res.Refusal, &challenge,
				"a consumer rendering the prompt reads the challenge from the refusal")
			assert.Equal(t, policy.ChallengeMFA, challenge.Kind)
			assert.NotEmpty(t, challenge.Token, "the prompt is answered with the token issued here")

			require.Len(t, challenge.Methods, 1, "the challenge lists the enrolled method")
			assert.Equal(t, "totp", challenge.Methods[0].Name)
			assert.Equal(t, factor.AuthenticatorApp, challenge.Methods[0].Channel)

			require.Equal(t, 1, res.Effects.ActiveSessions(t))
			assert.Equal(t, session.MFAPending, res.Effects.LoadSession(t, challenge.Session.ID).MFA,
				"the pending challenge was persisted before the token was issued")
		},
	}
}

func endpointAnsweredByTheChain() Scenario {
	// Logout. A route registered on the same path must not run, and must not
	// overwrite the status the chain set.
	return Scenario{
		Name:    "an endpoint answered by the chain",
		Request: authenticatedRequest(http.MethodPost, LogoutPath),
		Build: func(t *testing.T) ChainSpec {
			effects := newEffects(t)
			liveSession(t, effects)

			return ChainSpec{
				Options: append(bearerOptions(effects),
					httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: effects.Sessions})),
				Effects: effects,
				Routes: []Route{{
					Method: http.MethodPost, Path: LogoutPath,
					Status: http.StatusCreated, Body: RouteBody,
				}},
			}
		},
		Assert: func(t *testing.T, res Result) {
			assert.Equal(t, http.StatusOK, res.Status, "the status the chain set survives")
			assert.Empty(t, res.Body, "the chain wrote no body, and no route appended one")
			assert.NoError(t, res.Refusal)
			assert.False(t, res.RouteRan, "the route on the logout path did not run")

			assert.Equal(t, 0, res.Effects.ActiveSessions(t), "the session was ended")
		},
	}
}

func keySetEndpoint() Scenario {
	return Scenario{
		Name: "the key set endpoint",
		Build: func(t *testing.T) ChainSpec {
			effects := newEffects(t)

			return ChainSpec{
				Options: []httpsec.Option{httpsec.EnableJWKSEndpoint(fixtureKeySet{})},
				Effects: effects,
				NoRoute: true,
			}
		},
		Request: sending(RequestSpec{
			Method: http.MethodGet, Path: KeySetPath, ClientAddress: ClientAddress,
		}),
		Assert: func(t *testing.T, res Result) {
			assert.Equal(t, http.StatusOK, res.Status)
			assert.Equal(t, "application/json", res.Header.Get("Content-Type"))
			assert.Equal(t, KeySetBody, res.Body,
				"the body is exactly the key set, with nothing appended to it")
			assert.False(t, res.NoRouteRan, "a no-route handler never saw this request")
			assert.NoError(t, res.Refusal)
		},
	}
}

func contextPropagation() Scenario {
	return Scenario{
		Name:    "context propagation to the handler",
		Request: authenticatedRequest(http.MethodGet, RoutePath),
		Build: func(t *testing.T) ChainSpec {
			effects := newEffects(t)
			liveSession(t, effects)

			return ChainSpec{
				Options: append(bearerOptions(effects),
					observingAddress(effects),
					httpsec.EnableAuthorization(fixtureAuthorizer{})),
				Effects:  effects,
				Routes:   plainRoute(),
				Upstream: true,
			}
		},
		Assert: func(t *testing.T, res Result) {
			require.True(t, res.RouteRan)
			require.True(t, res.PrincipalKnown, "the caller reaches the handler's context")
			assert.Equal(t, UserID, res.Principal.ID)
			require.True(t, res.SessionKnown, "the session reaches the handler's context")
			assert.Equal(t, res.Effects.SessionID, res.SessionID)
			assert.Equal(t, UpstreamValue, res.Upstream,
				"a value set before the chain survives it")

			addr, seen := res.Effects.ClientAddress()
			require.True(t, seen)
			assert.Equal(t, ClientAddress, addr,
				"every adapter attributes this request to the address it was sent from")
		},
	}
}

func unattributableClientAddress() Scenario {
	// The chain refuses an address that cannot key a rate-limit bucket, so
	// unrelated clients are never pooled into one. What must agree across the
	// frameworks is that decision, not the string each transport reported.
	return Scenario{
		Name: "an unattributable client address",
		Build: func(t *testing.T) ChainSpec {
			effects := newEffects(t)

			return ChainSpec{
				Options: append(formLoginOptions(effects), attributableAddressRequired(effects)),
				Effects: effects,
			}
		},
		Request: sending(RequestSpec{
			Method: http.MethodPost,
			Path:   LoginPath,
			Header: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			Body:   "username=" + Username + "&password=" + Password,
		}),
		Assert: func(t *testing.T, res Result) {
			assert.Equal(t, http.StatusUnauthorized, res.Status)
			assert.Empty(t, res.Body)
			require.ErrorIs(t, res.Refusal, authenticate.ErrAuthenticationFailed)

			assert.Equal(t, 0, res.Effects.AuthenticatorCalls(),
				"the request was refused before any credential was checked")
			assert.Equal(t, 0, res.Effects.ActiveSessions(t), "nothing was pooled or opened")

			_, seen := res.Effects.ClientAddress()
			assert.True(t, seen, "the chain did read an address before refusing")
		},
	}
}

// observingAddress records the address the chain was given and passes the
// request on. It is registered outside every named slot so it sees whatever the
// adapter attributed the request to.
func observingAddress(e *Effects) httpsec.Option {
	return httpsec.RegisterInterceptor(
		httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
			e.recordAddress(ex.Request.ClientIP())

			return next(ex)
		}),
		httpsec.Before(httpsec.OrderJWKS))
}

// attributableAddressRequired refuses a request whose client address cannot key
// a rate-limit bucket.
//
// It is the scenario's own interceptor rather than a built-in because no
// shipped interceptor throttles a flow yet — httpsec's throttle seam exists but
// is not wired to one. The rule is the chain's: an empty address names nobody,
// an address that is not exactly one IP names more than one client, and an
// unspecified address is what a peer that is not a TCP client is reported as.
// Keying any of them pools unrelated clients into one bucket, so all three are
// refused as an ordinary failed attempt, which is what a client sees.
func attributableAddressRequired(e *Effects) httpsec.Option {
	return httpsec.RegisterInterceptor(
		httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
			addr := ex.Request.ClientIP()
			e.recordAddress(addr)

			if !attributable(addr) {
				return authenticate.ErrAuthenticationFailed
			}

			return next(ex)
		}),
		httpsec.Before(httpsec.OrderFormLogin))
}

// attributable reports whether addr names exactly one client.
func attributable(addr string) bool {
	if addr == "" {
		return false
	}

	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return false
	}

	return !ip.Unmap().IsUnspecified()
}

// fixtureAuthenticator resolves exactly one credential pair and refuses
// everything else.
//
// It is written here rather than generated, because what the scenarios compare
// is the state three frameworks left behind — the calls it took, the sessions
// it caused — rather than a sequence of expected calls. A generated double
// binds its expectations to one *testing.T and reports on them itself, which is
// the opposite of a fixture three adapters are judged against.
type fixtureAuthenticator struct{ calls *atomic.Int64 }

func (a *fixtureAuthenticator) Authenticate(
	_ context.Context, c identity.Credentials,
) (*authenticate.Authentication, error) {
	a.calls.Add(1)

	up, ok := c.(*identity.UsernamePassword)
	if !ok || up.Username != Username || string(up.Password) != Password {
		return nil, authenticate.ErrAuthenticationFailed
	}

	return &authenticate.Authentication{
		Principal:         TestPrincipal(),
		Time:              time.Now(),
		PasswordChangedAt: time.Now().Add(-time.Hour),
	}, nil
}

// fixtureTokens issues a token naming the session it was issued for, and
// verifies the ones it issued. It is stateless, so the generator a login is
// wired with and the verifier a later request is judged by need not be the same
// value.
type fixtureTokens struct{}

func (fixtureTokens) Generate(
	_ context.Context, id string, p *identity.Principal,
) (string, error) {
	if id == "" || p == nil || p.Username == "" {
		return "", fmt.Errorf("httpsecconformance: %w: nothing to identify the token by",
			token.ErrTokenInvalid)
	}

	return issuedTokenFor(p.Username, id), nil
}

func (fixtureTokens) Verify(_ context.Context, presented string) (*token.Claims, error) {
	rest, ok := strings.CutPrefix(presented, tokenPrefix)
	if !ok {
		return nil, fmt.Errorf("httpsecconformance: %w: not a token this fixture issued",
			token.ErrTokenInvalid)
	}

	subject, id, ok := strings.Cut(rest, ".")
	if !ok || subject == "" || id == "" {
		return nil, fmt.Errorf("httpsecconformance: %w: the token names no session",
			token.ErrTokenInvalid)
	}

	return token.NewClaims(subject, id), nil
}

// issuedTokenFor is the one shape the fixture issues and accepts.
func issuedTokenFor(username, sessionID string) string {
	return tokenPrefix + username + "." + sessionID
}

// fixtureUsers is the one user record bearer authentication reloads.
type fixtureUsers struct{}

func (fixtureUsers) LoadByUsername(
	_ context.Context, username string,
) (*identity.Details, error) {
	if username != Username {
		return nil, identity.ErrUserNotFound
	}

	return fixtureUserDetails(), nil
}

func (fixtureUsers) LoadByUserID(
	_ context.Context, id identity.UserID,
) (*identity.Details, error) {
	if id != UserID {
		return nil, identity.ErrUserNotFound
	}

	return fixtureUserDetails(), nil
}

// fixtureUserDetails is the one record both lookups return, so a scenario
// reaching the user by reference sees exactly what reaching it by username sees.
func fixtureUserDetails() *identity.Details {
	return &identity.Details{
		ID:                UserID,
		Username:          Username,
		Name:              "Ada",
		Active:            true,
		PasswordChangedAt: time.Now().Add(-time.Hour),
	}
}

// fixtureAuthorizer answers every attribute set with err, so a scenario names
// the decision rather than arranging role data to produce it.
type fixtureAuthorizer struct{ err error }

func (a fixtureAuthorizer) Authorize(context.Context, authorize.Attributes) error { return a.err }

// lockedPolicy denies pre-authentication, which is what a lockout looks like to
// the chain.
type lockedPolicy struct{}

func (lockedPolicy) Name() string { return "httpsecconformance/locked" }

func (lockedPolicy) Phases() []policy.Phase { return []policy.Phase{policy.PreAuthentication} }

func (lockedPolicy) Evaluate(context.Context, *policy.Input) policy.Decision {
	return policy.Decision{Outcome: policy.Deny, Reason: policy.ErrAccountLocked}
}

// challengingPolicy asks a successful login for a second factor.
type challengingPolicy struct{}

func (challengingPolicy) Name() string { return "httpsecconformance/challenge" }

func (challengingPolicy) Phases() []policy.Phase {
	return []policy.Phase{policy.PostAuthentication}
}

func (challengingPolicy) Evaluate(context.Context, *policy.Input) policy.Decision {
	return policy.Decision{Outcome: policy.Challenge, Challenge: policy.ChallengeMFA}
}

// Challenges declares what this policy can ask for, which is what lets a chain
// check that something is wired to enforce it. A policy that challenges and
// says nothing is taken to challenge for nothing, so declaring it here is what
// makes this fixture stand in for a real deployment's rule.
func (challengingPolicy) Challenges() []policy.ChallengeKind {
	return []policy.ChallengeKind{policy.ChallengeMFA}
}

// fixtureKeySet serves fixed bytes, which is what the key set scenario compares
// the response body against byte for byte.
type fixtureKeySet struct{}

func (fixtureKeySet) JWKS() ([]byte, error) { return []byte(KeySetBody), nil }

// The fixtures satisfy the ports the chain is wired with, so a change to any of
// them is a compile error here rather than a failure inside a scenario.
var (
	_ authenticate.Authenticator = (*fixtureAuthenticator)(nil)
	_ token.Generator            = fixtureTokens{}
	_ identity.UserLoader        = fixtureUsers{}
	_ authorize.Authorizer       = fixtureAuthorizer{}
	_ policy.Policy              = lockedPolicy{}
	_ policy.Policy              = challengingPolicy{}
	_ policy.Challenger          = challengingPolicy{}
	_ httpsec.KeySetProvider     = fixtureKeySet{}
)

// UnenforcedMFAChallenge is a policy that can ask a login for a second factor,
// on a chain with nothing registered to enforce one.
//
// It is the second wiring mistake every adapter must refuse identically. The
// failure it stands for has no symptom at all at request time — the session is
// marked, the marker is never read, and the caller is served — which is why it
// is refused at construction, and why every adapter has to refuse it the same
// way.
func UnenforcedMFAChallenge() httpsec.Option {
	engine, err := policy.NewEngine(challengingPolicy{})
	if err != nil {
		// Unreachable: the policy is this package's own and is never nil. A
		// panic here would be a fault in the fixture, not in what it tests.
		panic(err)
	}

	return httpsec.WithPolicyEngine(engine)
}

// MisconfiguredFormLogin is form login wired with everything a login needs
// except the session manager it must open a session in.
//
// It is the one wiring mistake every adapter must refuse identically, and it is
// exported so the construction-parity test names it once rather than restating
// the deps three times and risking a fourth mistake between the rows.
func MisconfiguredFormLogin() httpsec.Option {
	return httpsec.EnableFormLogin(httpsec.FormLoginDeps{
		Authenticator: &fixtureAuthenticator{calls: new(atomic.Int64)},
		Tokens:        fixtureTokens{},
		Attempts:      policy.NewMemoryAttemptStore(),
	})
}
