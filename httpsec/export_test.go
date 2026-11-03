package httpsec

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/internal/assurance"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

// This file exposes what the package's tests need and consumers must not have.
// It is a test file, so nothing here reaches a production build.

// Committed reports whether w has already sent a status or a body. It is the
// unexported signal the default error handling reads before writing a status
// of its own.
func Committed(w ResponseWriter) bool {
	c, ok := w.(interface{ committed() bool })
	return ok && c.committed()
}

// PolicyDenyReason exposes the unexported reader every deny site refuses
// through, so a test can pin what a reduced decision refuses with.
var PolicyDenyReason = policyDenyReason

// Registration is one recorded registration, flattened for a test to read.
type Registration struct {
	Interceptor Interceptor
	Order       Order
	Seq         int
}

// Registrations applies opts to a fresh configuration and reports what they
// recorded, so a test can pin an option's effect before New exists.
func Registrations(opts ...Option) ([]Registration, error) {
	var c config
	for _, opt := range opts {
		if err := opt(&c); err != nil {
			return nil, err
		}
	}

	out := make([]Registration, 0, len(c.registrations))
	for _, r := range c.registrations {
		out = append(out, Registration{Interceptor: r.interceptor, Order: r.order, Seq: r.seq})
	}
	return out, nil
}

// TestBuiltInDeps stands in for the *Deps struct an Enable* option takes. The
// fields are `any` because the check under test is presence, not type: what is
// being pinned is that a dependency left out, or present but holding a typed
// nil, is refused before the chain exists.
type TestBuiltInDeps struct {
	Sessions any
	Users    any
}

// EnableTestBuiltIn is a built-in that exists only for the tests, registered
// through the same seam every real Enable* option uses. It lets the validation
// machinery be pinned on its own, before any interceptor has been written, and
// it is the worked example of what such an option has to do: capture its
// dependencies and hand config.enable the check over them.
func EnableTestBuiltIn(d TestBuiltInDeps) Option {
	const option = "EnableTestBuiltIn"

	return func(c *config) error {
		c.enable(option, func() error {
			if err := requireDep(option, "session manager", d.Sessions); err != nil {
				return err
			}
			return requireDep(option, "user loader", d.Users)
		})
		return nil
	}
}

// ChainSettings is what the options resolved, flattened for a test to read.
type ChainSettings struct {
	PolicyEngine       *policy.Engine
	Logger             *slog.Logger
	RefusalLogInterval time.Duration
	RefusalLogReporter func(key string, suppressed int)
}

// Settings reports the settings c was built with, so a test can pin both the
// default a consumer gets for free and the override that replaces it.
func Settings(c *Chain) ChainSettings {
	return ChainSettings{
		PolicyEngine:       c.engine,
		Logger:             c.logger,
		RefusalLogInterval: c.refusalInterval,
		RefusalLogReporter: c.refusalReporter,
	}
}

// WithSession exposes the unexported publisher, so a test can put a session on
// a context exactly as an interceptor does.
var WithSession = withSession

// ReadResponse exposes the reader the verify endpoint hands a method's
// response through, so its rules can be pinned without a chain.
var ReadResponse = readResponse

// EnableRecoveryGateForTest registers the recovery gate exactly as
// EnableAccountRecovery does, without the recovery endpoints, so a test can
// pin what the gate lets through before those endpoints exist.
func EnableRecoveryGateForTest() Option {
	return func(c *config) error {
		c.enableRecoveryGate(nil)
		return nil
	}
}

// MintProofForTest mints the library's second-factor proof, which only library
// code can do, so a test can hand the login tail a login whose second factor
// was met at its first.
var MintProofForTest = assurance.New

// The accessors below expose the seams other capabilities build their
// redemption flows on, so the package's own black-box tests can pin them before
// an interceptor exists to exercise them.

// ClassifyAddressForTest exposes the unexported address rule, so a test can pin
// which addresses may key a bucket and which are refused outright.
var ClassifyAddressForTest = classifyAddress

// SourceThrottledForTest exposes the throttle seam's check, so a test can pin
// what each refusal returns before any interceptor is built on it.
var SourceThrottledForTest = sourceThrottled

// RecordSourceFailureForTest exposes the throttle seam's recording, so a test
// can observe the context it hands the guard.
var RecordSourceFailureForTest = recordSourceFailure

// PostAuthenticationInputForTest exposes the input builder, so a test can pin
// which parameter lands in which field before an interceptor calls it.
var PostAuthenticationInputForTest = postAuthenticationInput

// CompleteLoginForTest exposes the login tail, so a test can pin its order
// before any first factor is built on it.
var CompleteLoginForTest = completeLogin

// LoginTailDepsForTest builds what the login tail needs, so a test assembles it
// without this package exporting the struct to consumers.
func LoginTailDepsForTest(
	engine *policy.Engine,
	sessions *session.Sessions,
	tokens token.Generator,
) loginTailDeps {
	return loginTailDeps{engine: engine, sessions: sessions, tokens: tokens, enforced: everyBuiltInEnforced()}
}

// PrepareLoginForTest exposes the login tail's first half, which a redemption
// runs inside its redeemer's checks, so a test can pin that it stores nothing
// and what it leaves for the commit.
var PrepareLoginForTest = prepareLogin

// CommitLoginForTest runs the login tail's second half on l, which a
// redemption runs once its single-use credential is spent.
func CommitLoginForTest(ex *Exchange, l *preparedLogin) (string, error) { return l.commit(ex) }

// EnableGateForTest records the built-in gate for kind as enabled, exactly as
// its Enable option does, without registering the gate itself. A test whose
// policy raises kind uses it to pin what raising the kind does rather than what
// the gate does with it; it is also how the enrolment kind is counted as
// enforced before EnableMFAEnrolment exists.
func EnableGateForTest(kind policy.ChallengeKind) Option {
	return func(c *config) error {
		c.enableGate(kind)
		return nil
	}
}

// everyBuiltInEnforced is the enforcer set of a chain with every built-in
// gate enabled. The login-tail seams use it because the tests reaching the
// tail through them pin its order, not the chain's enforcer check, which
// TestUnenforcedChallengeAtRuntime pins through a whole chain.
func everyBuiltInEnforced() map[policy.ChallengeKind]bool {
	enforced := make(map[policy.ChallengeKind]bool, len(builtInEnforcers))
	for kind := range builtInEnforcers {
		enforced[kind] = true
	}

	return enforced
}

// LoginTailDepsWithEnrolmentForTest is LoginTailDepsForTest with the lifetime
// an enrolment challenge marks the session for, which the chain otherwise
// hands every login tail at assembly.
func LoginTailDepsWithEnrolmentForTest(
	engine *policy.Engine,
	sessions *session.Sessions,
	tokens token.Generator,
	enrolmentLifetime time.Duration,
) loginTailDeps {
	return loginTailDeps{
		engine: engine, sessions: sessions, tokens: tokens,
		enrolmentLifetime: enrolmentLifetime, enforced: everyBuiltInEnforced(),
	}
}

// ResolveClient validates tp and opts as EnableTrustedProxies does and
// resolves r's client through them, returning the client and how many
// forwarded entries the resolution parsed. It is how a test proves the walk
// parses only the entries it reaches.
func ResolveClient(r Request, tp TrustedProxies, opts ...ProxyOption) (Client, int, error) {
	p, err := newTrustedProxies(tp, applyProxyOptions(opts))
	if err != nil {
		return Client{}, 0, err
	}

	res, err := p.resolve(r)

	return res.client, res.parsed, err
}

// DPoPSettings applies opts to a fresh configuration and reports the DPoP
// configuration EnableDPoP resolved, defaults filled, and whether it was
// enabled at all.
func DPoPSettings(opts ...Option) (DPoP, bool, error) {
	var c config
	for _, opt := range opts {
		if err := opt(&c); err != nil {
			return DPoP{}, false, err
		}
	}

	if c.dpop == nil {
		return DPoP{}, false, nil
	}

	return c.dpop.cfg, true, nil
}

// DPoPChecker runs the chain's DPoP proof verification on its own, counting
// the signatures it verifies, so a test can pin each check and prove an
// oversized proof costs no signature check.
type DPoPChecker struct {
	v          *dpopVerifier
	signatures atomic.Int64
}

// NewDPoPChecker builds the verifier EnableDPoP would build for d, reading
// time from now and logging through log.
func NewDPoPChecker(d DPoP, now func() time.Time, log *slog.Logger) (*DPoPChecker, error) {
	v, err := newDPoPVerifier(d, now)
	if err != nil {
		return nil, err
	}

	v.log = log

	c := &DPoPChecker{v: v}
	verify := v.verifySignature
	v.verifySignature = func(alg jwa.SignatureAlgorithm, key jwk.Key, compact []byte) error {
		c.signatures.Add(1)

		return verify(alg, key, compact)
	}

	return c, nil
}

// Verify verifies the proof r carries, for token (empty for none), without
// recording it, and returns its key's thumbprint.
func (c *DPoPChecker) Verify(ctx context.Context, r Request, token string) (string, error) {
	p, err := c.v.verify(ctx, r, token)

	return p.jkt, err
}

// Check verifies the proof r carries and then records it, as the chain does
// once every other check has passed.
func (c *DPoPChecker) Check(ctx context.Context, r Request, token string) (string, error) {
	p, err := c.v.verify(ctx, r, token)
	if err != nil {
		return "", err
	}

	if err := c.v.record(ctx, p); err != nil {
		return "", err
	}

	return p.jkt, nil
}

// Signatures reports how many proof signatures were verified.
func (c *DPoPChecker) Signatures() int64 { return c.signatures.Load() }

// ProofKeyThumbprint is the thumbprint the chain computes for a proof's key,
// the value a bound token's cnf.jkt must equal.
func ProofKeyThumbprint(key jwk.Key) (string, error) { return keyThumbprint(key) }

// NewMemoryReplayStoreForTest is the in-memory replay store EnableDPoP uses by
// default, reading time from now.
func NewMemoryReplayStoreForTest(now func() time.Time) ReplayStore { return newMemoryReplayStore(now) }

// SecurityHeadersRandom replaces the security-headers layer's random source,
// so a test can make the nonce's randomness fail or repeat.
func SecurityHeadersRandom(r io.Reader) HeaderOption {
	return func(l *securityHeaders) error {
		l.random = r

		return nil
	}
}

// WithSignInNoticeTracker counts the sign-in notice's work in flight on wg, so
// a test can wait for the background work to finish.
func WithSignInNoticeTracker(wg *sync.WaitGroup) SignInNoticeOption {
	return withSignInNoticeTracker(wg)
}

// SignInDeviceDescription is the device text a sign-in notice carries for a
// user agent.
var SignInDeviceDescription = deviceDescription

// DeclareDPoPForTest records on the configuration that DPoP is enabled, as the
// DPoP option does, so the CORS layer's additions can be pinned before that
// option exists.
func DeclareDPoPForTest() Option {
	return func(c *config) error {
		c.dpopEnabled = true
		return nil
	}
}

// DeclareCSRFTokenHeaderForTest records on the configuration the request
// header CSRF protection reads its token from, as the CSRF option does.
func DeclareCSRFTokenHeaderForTest(name string) Option {
	return func(c *config) error {
		c.csrfTokenHeader = name
		return nil
	}
}

// CORSOrigins applies opts to a fresh configuration and reports the CORS
// layer's exact origins, and whether origin matches one of its patterns, as
// CSRF protection reads them.
func CORSOrigins(origin string, opts ...Option) (exact []string, matchesPattern bool, err error) {
	var c config
	for _, opt := range opts {
		if err := opt(&c); err != nil {
			return nil, false, err
		}
	}

	exact, patterns := c.corsOrigins()

	scheme, host, port, perr := parseOrigin(origin)
	for _, p := range patterns {
		if perr == nil && p.matches(scheme, host, port) {
			return exact, true, nil
		}
	}

	return exact, false, nil
}

// testCookieAuthenticator authenticates a request by the session identifier a
// cookie carries. No built-in authenticates by cookie yet, so it is the shape
// one will have: it carries the cookie-authenticator marker, and has CSRF
// protection check the request's token for the session before publishing it.
type testCookieAuthenticator struct {
	sessions *session.Sessions
	cookie   string
}

func (testCookieAuthenticator) AuthenticatesByCookie() {}

// Intercept loads the cookie's session, checks the CSRF token for it, and
// publishes it. A request without the cookie continues unauthenticated.
func (a testCookieAuthenticator) Intercept(ex *Exchange, next Next) error {
	id, ok := ex.Request.Cookie(a.cookie)
	if !ok {
		return next(ex)
	}

	s, err := a.sessions.Load(ex.Context(), id)
	if err != nil {
		return ErrAuthenticationRequired
	}

	if err := CheckCSRFToken(ex, s); err != nil {
		return err
	}

	ex.Session = s
	ex.SetContext(withSession(ex.Context(), s))

	return next(ex)
}

// NewTestCookieAuthenticator is a cookie-authenticating interceptor reading
// the session named by cookie through sessions.
func NewTestCookieAuthenticator(sessions *session.Sessions, cookie string) Interceptor {
	return testCookieAuthenticator{sessions: sessions, cookie: cookie}
}

// SessionCSRFTokensComparingWith is the default token source with its
// comparison replaced by compare, so a test can see that the comparison the
// default makes is the constant-time one it is handed.
func SessionCSRFTokensComparingWith(compare func(x, y []byte) int) CSRFTokens {
	return sessionCSRFTokens{compare: compare}
}

// CaptureUpgrades records every password-upgrade handle the login layers
// obtain from now until the test ends, and returns the reader of them. It swaps
// a package variable, so the calling test must not run in parallel.
func CaptureUpgrades(t testing.TB) func() []*authenticate.PasswordUpgrade {
	t.Helper()

	var (
		mu   sync.Mutex
		seen []*authenticate.PasswordUpgrade
	)

	orig := requestUpgrade
	requestUpgrade = func(ctx context.Context) (context.Context, *authenticate.PasswordUpgrade) {
		ctx, u := orig(ctx)

		mu.Lock()
		seen = append(seen, u)
		mu.Unlock()

		return ctx, u
	}

	t.Cleanup(func() { requestUpgrade = orig })

	return func() []*authenticate.PasswordUpgrade {
		mu.Lock()
		defer mu.Unlock()

		return append([]*authenticate.PasswordUpgrade(nil), seen...)
	}
}
