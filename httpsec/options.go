package httpsec

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/pkg/logsample"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

//go:generate mockgen -destination=mfamethodlookup_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/policy MFAMethodLookup

// ErrConfig is the wiring fault every option is refused with.
//
// It never reaches a client: a chain that does not build serves no traffic, so
// a consumer matches it once, at start-up, and does not have to know which
// option produced it to tell a configuration mistake from a refusal.
var ErrConfig = errors.New("httpsec: invalid configuration")

// newConfigError reports a wiring fault, wrapping ErrConfig so that a consumer
// matches every one of them with one errors.Is and the message still names the
// option and the dependency at fault.
func newConfigError(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrConfig, fmt.Sprintf(format, args...))
}

// defaultIPv6SourcePrefix is the prefix length IPv6 clients are counted by. It
// matches the rate-limiting default, so a consumer who configures neither gets
// one consistent answer about what "one source" means.
const defaultIPv6SourcePrefix = 64

// maxIPv6SourcePrefix is the width of an IPv6 address, and so the narrowest a
// source can be counted at: one prefix per address.
const maxIPv6SourcePrefix = 128

// defaultRefusalLogInterval is how often one refusal key is written. A refusal
// is driven by whoever is being refused, so an unsampled one is a log flood an
// attacker chooses the size of.
const defaultRefusalLogInterval = time.Minute

// The limit the default in-memory limiter counts a source's failures against.
// They match the account-lockout policy's own defaults, so a consumer who
// configures neither gets one answer about how much guessing is too much
// rather than two that disagree by an order of magnitude.
const (
	defaultFailureLimit  = 5
	defaultFailureWindow = 15 * time.Minute
)

// Option configures a chain.
//
// Every option either takes effect or is refused when the chain is built: none
// is documented away, and none is silently ignored. A nil Option is skipped, so
// a consumer assembling the slice conditionally need not filter it.
type Option func(*config) error

// config is what the options accumulate before the chain is built. New
// validates it and only then builds a Chain, so a chain that exists is one
// whose every option took effect.
type config struct {
	registrations []registration

	// seq counts registrations so two interceptors at one slot stay in the
	// order they were registered in, which sorting alone would not preserve.
	seq int

	// enabled holds one dependency check per built-in the consumer enabled.
	enabled []enabledBuiltIn

	// wiring holds what each enabled built-in still has to be handed once the
	// chain exists. An Enable* option runs before the options that follow it,
	// so an interceptor reading c.engine or c.logger at that moment would
	// capture a setting a later option was about to replace.
	wiring []func(*Chain)

	engine  *policy.Engine
	logger  *slog.Logger
	limiter ratelimit.Limiter

	// sessions is the manager the chain records activity through: the first one
	// any enabled built-in was wired to. A deployment has one session store, so
	// taking it from the built-ins costs the consumer no second declaration,
	// and a chain that resolves no session has nothing to record.
	sessions *session.Manager

	// authorizer is what the authorization stage publishes for the guards
	// behind it, and what the last EnableAuthorization call named: a chain
	// judges by one authorizer, so a second call replacing the first is the
	// consumer changing their mind rather than two judges disagreeing.
	authorizer authorize.Authorizer

	// authzRules is the centralized rule set, in the order the calls arrived
	// in. It accumulates rather than being replaced, so a consumer assembles
	// one ordered set from as many EnableAuthorization calls as their own
	// wiring is split across.
	authzRules []authorize.Rule[Request]

	ipv6Prefix int

	errorHandler func(w http.ResponseWriter, r *http.Request, err error)

	refusalInterval time.Duration
	refusalReporter func(key string, suppressed int)
}

// enabledBuiltIn is one built-in interceptor the consumer switched on, and the
// check its dependencies must pass before the chain is built.
type enabledBuiltIn struct {
	option string
	check  func() error
}

// enable records that the built-in switched on by option is enabled, and the
// check validate runs for it.
//
// It is the seam every Enable* option is added through: the option captures the
// dependencies it was handed and hands enable a check over them, so validate
// gains no knowledge of any one built-in and every built-in is checked the same
// way, in the order the consumer enabled them.
func (c *config) enable(option string, check func() error) {
	c.enabled = append(c.enabled, enabledBuiltIn{option: option, check: check})
}

// wire records what a built-in still has to be handed once the chain exists.
func (c *config) wire(fn func(*Chain)) {
	c.wiring = append(c.wiring, fn)
}

// useSessions records the session manager an enabled built-in was wired to, so
// the chain's own activity write-back has one without the consumer declaring it
// twice.
//
// The first one wins and a nil one is ignored: a deployment has one session
// store, and the built-in whose dependency is missing is refused by its own
// check rather than by this one.
func (c *config) useSessions(m *session.Manager) {
	if c.sessions == nil && m != nil {
		c.sessions = m
	}
}

// register records i at slot at, keeping the sequence that decides which of two
// interceptors sharing a slot runs first.
func (c *config) register(i Interceptor, at Order) {
	c.registrations = append(c.registrations, registration{interceptor: i, order: at, seq: c.seq})
	c.seq++
}

// validate reports the first wiring fault, naming the option and the dependency
// at fault so the consumer fixes it without reading library source.
//
// It runs once every option has been applied, because a built-in's dependencies
// may be set by the Enable* option and refined by the sub-options that follow
// it, and checking half an option's worth of configuration would report a fault
// the next option was about to fix.
func (c *config) validate() error {
	for _, e := range c.enabled {
		if err := e.check(); err != nil {
			return err
		}
	}
	return nil
}

// requireDep refuses a dependency that is absent, or present but holding a
// typed nil.
//
// (*T)(nil) inside an interface is not nil to ==, which is exactly what an
// unchecked constructor error hands over: without this the wiring looks
// complete and the first request panics. option names the option that wanted
// the dependency and dependency names the dependency itself, so the message is
// actionable on its own.
func requireDep(option, dependency string, v any) error {
	if nilcheck.IsNil(v) {
		return newConfigError("%s needs a %s", option, dependency)
	}
	return nil
}

// New builds the chain.
//
// It applies every option in turn, validates what they set, and returns no
// chain at all when anything cannot take effect: there is no partly-configured
// chain to accidentally serve traffic with. A consumer who passes no options
// gets a usable chain with the library's defaults and no built-in interceptors
// enabled.
func New(opts ...Option) (*Chain, error) {
	c := &config{
		logger:          slog.Default(),
		ipv6Prefix:      defaultIPv6SourcePrefix,
		refusalInterval: defaultRefusalLogInterval,
	}

	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(c); err != nil {
			return nil, err
		}
	}

	if err := c.validate(); err != nil {
		return nil, err
	}

	return c.build()
}

// build freezes the validated configuration into the chain that serves it.
func (c *config) build() (*Chain, error) {
	limiter, err := c.resolveLimiter()
	if err != nil {
		return nil, err
	}

	// Activity is recorded for every chain, with no option to enable: a session
	// whose idle deadline stops moving while its owner is using it is logged
	// out mid-work, and that is not a behaviour worth being able to switch off.
	// It is registered last, so a consumer's own interceptor at the same slot
	// wraps it and still sees the request on the way back out.
	touch := &sessionTouch{sessions: c.sessions}
	c.register(touch, OrderSessionTouch)
	c.wire(touch.wire)

	// Authorization is registered for every chain too, with no option to leave
	// it out: the stage is where the guards behind the chain find the authorizer
	// they judge by, and a chain that published none would leave every one of
	// them refusing. With no rules it enforces nothing centrally, which is the
	// consumer saying authorization belongs at the operations.
	stage := &authorization{authorizer: c.authorizer}

	if len(c.authzRules) > 0 {
		rules, err := authorize.NewRules(c.authzRules...)
		if err != nil {
			return nil, newConfigError("EnableAuthorization was given a rule set that "+
				"could not be built: %s", err)
		}

		stage.rules = rules
	}

	c.register(stage, OrderAuthorizer)

	chain := &Chain{
		registrations:   c.ordered(),
		engine:          c.engine,
		logger:          c.logger,
		limiter:         limiter,
		ipv6Prefix:      c.ipv6Prefix,
		errorHandler:    c.errorHandler,
		refusalInterval: c.refusalInterval,
		refusalReporter: c.refusalReporter,
	}

	// The sampler is built here rather than by the option, because the default
	// reporter writes through the chain's logger and there is no chain until
	// every option has been applied.
	reporter := c.refusalReporter
	if reporter == nil {
		reporter = chain.reportSuppressedRefusals
	}
	chain.sampler = logsample.New(c.refusalInterval, logsample.WithReporter(reporter))

	// The built-ins are wired last, because each of them reads settings — the
	// engine, the logger — that an option applied after its own Enable may
	// still have replaced.
	for _, w := range c.wiring {
		w(chain)
	}

	return chain, nil
}

// resolveLimiter returns the limiter failures are counted through, building the
// documented in-memory default when the consumer supplied none.
//
// It is built here rather than in New's initial configuration because the
// default writes its one per-replica warning through the chain's logger, and
// which logger that is is not settled until every option has been applied.
func (c *config) resolveLimiter() (ratelimit.Limiter, error) {
	if c.limiter != nil {
		return c.limiter, nil
	}

	limiter, err := ratelimit.NewMemoryLimiter(defaultFailureLimit, defaultFailureWindow,
		ratelimit.WithMemoryLimiterLogger(c.logger))
	if err != nil {
		return nil, newConfigError("the default in-memory limiter could not be built: %s", err)
	}

	return limiter, nil
}

// WithPolicyEngine evaluates every policy phase through e.
//
// Default: no engine, under which every phase allows and the chain's decisions
// rest on authentication and authorization alone. Supply one to have lockout,
// second-factor and session policies judge each phase.
//
// A nil engine is refused: it would read as "no policies" while the consumer
// believed their policies were running.
func WithPolicyEngine(e *policy.Engine) Option {
	return func(c *config) error {
		if err := requireDep("WithPolicyEngine", "policy engine", e); err != nil {
			return err
		}

		c.engine = e
		return nil
	}
}

// WithLogger writes the chain's own records through l.
//
// Default: slog.Default(), so a consumer who configures logging once for their
// application sees the chain's records without wiring anything here.
//
// A nil logger is refused rather than taken as "log nothing": the records this
// chain writes are refusals and outages, and silently dropping them is not a
// configuration anyone asks for on purpose. Pass a logger over
// slog.DiscardHandler to say so deliberately.
func WithLogger(l *slog.Logger) Option {
	return func(c *config) error {
		if err := requireDep("WithLogger", "logger", l); err != nil {
			return err
		}

		c.logger = l
		return nil
	}
}

// WithRateLimiter counts failed attempts through l.
//
// Default: an in-memory limiter counting five failures per source in fifteen
// minutes — the account-lockout policy's own thresholds, so a consumer who
// configures neither gets one answer about how much guessing is too much. It
// bounds one process: supply a limiter backed by storage the replicas share
// when one limit has to hold across a fleet.
func WithRateLimiter(l ratelimit.Limiter) Option {
	return func(c *config) error {
		if err := requireDep("WithRateLimiter", "limiter", l); err != nil {
			return err
		}

		c.limiter = l
		return nil
	}
}

// WithIPv6SourcePrefix counts IPv6 clients by a prefix of bits rather than by
// their full address.
//
// Default: 64, the narrowest prefix that still costs an attacker something to
// move within. A prefix outside 1..128 is refused: 0 would pool every client
// into one bucket, and more than 128 is not an address.
func WithIPv6SourcePrefix(bits int) Option {
	return func(c *config) error {
		if bits < 1 || bits > maxIPv6SourcePrefix {
			return newConfigError(
				"WithIPv6SourcePrefix takes a prefix length in 1..%d, and %d would either pool "+
					"every IPv6 client into one bucket or name no address at all",
				maxIPv6SourcePrefix, bits)
		}

		c.ipv6Prefix = bits
		return nil
	}
}

// WithRefusalLogInterval writes at most one record per refusal key per d.
//
// Default: one minute. An interval of zero or less disables sampling and writes
// every record, which is the documented way to ask for the full stream — it is
// accepted rather than refused, and it is a choice about volume, not a fault.
func WithRefusalLogInterval(d time.Duration) Option {
	return func(c *config) error {
		c.refusalInterval = d
		return nil
	}
}

// WithRefusalLogReporter reports the records sampling suppressed to fn.
//
// Default: a summary record at WARN naming the key and how many records it
// stood for. fn receives the key and the count, and runs on the goroutine whose
// refusal or flush triggered it, so it must be fast and must not panic.
//
// A nil reporter is refused: with no reporter at all the counts for a key that
// goes quiet are simply dropped, and the suppressed totals stop adding up.
// Omit the option to keep the default summary reporter.
func WithRefusalLogReporter(fn func(key string, suppressed int)) Option {
	return func(c *config) error {
		if fn == nil {
			return newConfigError(
				"WithRefusalLogReporter was given no reporter; omit it to keep the default " +
					"summary reporter")
		}

		c.refusalReporter = fn
		return nil
	}
}

// FormLoginDeps are the collaborators form login is wired to.
//
// Every one is required, and a missing or typed-nil field is refused when the
// chain is built. There is no useful default for any of them: scrty ships no
// user store to authenticate against, no durable session store, no signing key
// to issue a token with, and an attempt store of its own here would be one the
// lockout policy never reads, which is worse than none.
type FormLoginDeps struct {
	// Authenticator judges the submitted credentials. An authenticate.Manager
	// satisfies it, and so does a consumer's own provider.
	Authenticator authenticate.Authenticator

	// Sessions opens the session a successful login establishes.
	Sessions *session.Manager

	// Tokens issues the access token the response carries. The session
	// identifier is the token's jti, which is how a later bearer request finds
	// the session the token was issued for.
	Tokens token.Generator

	// Attempts is where a failed login is recorded and a successful one clears
	// what came before. Supply the same store the account-lockout policy reads
	// — a failure recorded in one store and counted in another locks nothing.
	Attempts policy.AttemptStore
}

// LoginOption configures form login. Each replaces one of the defaults named
// on EnableFormLogin.
type LoginOption func(*formLogin) error

// EnableFormLogin answers logins at the form login slot.
//
// Default: POST on DefaultLoginPath, reading DefaultLoginUsernameParam and
// DefaultLoginPasswordParam from the form and then, when the form yields
// neither and the request declares a JSON content type, from the JSON body;
// at most DefaultLoginBodyLimit bytes of it; answering a success with a JSON
// document carrying the access token, an empty refresh token and the session's
// idle expiry. Every one of those is replaced by the option that names it.
//
// Every other request passes through untouched, so enabling form login costs
// the rest of the application nothing.
//
// # What the binding reads, and what it does not
//
// The credential is bound from the parsed POST body and from nothing else. A
// credential in the URL query never authenticates, because a query string is
// already written into every access log, proxy log and browser history that saw
// the URL, and into the Referer the next page sends. Request.FormValue keeps
// net/http's own semantics, which merge the query into the form, for the
// consumer interceptors that legitimately read a query parameter; only this
// binding narrows.
//
// Two narrowings follow from that, and both are deliberate:
//
//   - A body is read as a form only when it declares
//     "application/x-www-form-urlencoded". A login sent as
//     "multipart/form-data" is therefore refused with ErrCredentialsMissing
//     rather than parsed: a body is what the request says it is, and a login
//     endpoint that guessed would accept a shape nobody wired it for.
//   - A urlencoded body that does not parse yields no credential at all, rather
//     than the pairs that did parse before the error. Half a body is not a
//     credential the client sent.
func EnableFormLogin(d FormLoginDeps, opts ...LoginOption) Option {
	const option = "EnableFormLogin"

	return func(c *config) error {
		l := &formLogin{
			authn:         d.Authenticator,
			sessions:      d.Sessions,
			tokens:        d.Tokens,
			attempts:      d.Attempts,
			now:           time.Now,
			path:          DefaultLoginPath,
			usernameParam: DefaultLoginUsernameParam,
			passwordParam: DefaultLoginPasswordParam,
			bodyLimit:     DefaultLoginBodyLimit,
			respond:       writeLoginResult,
		}

		for _, opt := range opts {
			if opt == nil {
				continue
			}
			if err := opt(l); err != nil {
				return err
			}
		}

		c.enable(option, func() error {
			if err := requireDep(option, "authenticator", d.Authenticator); err != nil {
				return err
			}
			if err := requireDep(option, "session manager", d.Sessions); err != nil {
				return err
			}
			if err := requireDep(option, "token generator", d.Tokens); err != nil {
				return err
			}

			return requireDep(option, "attempt store", d.Attempts)
		})

		c.useSessions(d.Sessions)
		c.wire(l.wire)
		c.register(l, OrderFormLogin)

		return nil
	}
}

// WithLoginRequestPath answers logins on path instead.
//
// Default: DefaultLoginPath. An empty path is refused: it would match nothing,
// so the endpoint the consumer asked for would silently not exist.
func WithLoginRequestPath(path string) LoginOption {
	return func(l *formLogin) error {
		if path == "" {
			return newConfigError("WithLoginRequestPath was given no path, so form login " +
				"would answer nothing")
		}

		l.path = path
		return nil
	}
}

// WithLoginParams reads the identifier and the password from these names.
//
// Default: DefaultLoginUsernameParam and DefaultLoginPasswordParam. They name
// both the form fields and the JSON members, so one call settles both shapes.
// An empty name, or two identical names, is refused: neither could read a
// credential the consumer meant to send.
func WithLoginParams(username, password string) LoginOption {
	return func(l *formLogin) error {
		switch {
		case username == "" || password == "":
			return newConfigError("WithLoginParams needs both field names, and was given "+
				"%q and %q", username, password)
		case username == password:
			return newConfigError("WithLoginParams was given %q for both fields, which cannot "+
				"carry an identifier and a password separately", username)
		}

		l.usernameParam = username
		l.passwordParam = password
		return nil
	}
}

// WithLoginBodyLimit reads at most n bytes of a login body.
//
// Default: DefaultLoginBodyLimit. The bound applies before anything is parsed,
// because the login endpoint is unauthenticated and an unbounded read there
// costs an attacker no credential at all. A limit of zero or less is refused:
// it would reject every login, including the correct ones.
func WithLoginBodyLimit(n int64) LoginOption {
	return func(l *formLogin) error {
		if n <= 0 {
			return newConfigError("WithLoginBodyLimit takes a positive bound, and %d would "+
				"refuse every login", n)
		}

		l.bodyLimit = n
		return nil
	}
}

// WithLoginResponder writes the success response through fn.
//
// Default: a JSON document carrying the access token, an empty refresh token
// field and the session's idle expiry. fn is called instead of the downstream
// handler, because a login is this library's own endpoint.
//
// A nil responder is refused: a login that succeeded and wrote nothing answers
// the caller with an empty 200, which reads as a success carrying no
// credential.
func WithLoginResponder(fn LoginResponder) LoginOption {
	return func(l *formLogin) error {
		if fn == nil {
			return newConfigError("WithLoginResponder was given no responder; omit it to keep " +
				"the default JSON response")
		}

		l.respond = fn
		return nil
	}
}

// BasicAuthDeps are the collaborators Basic authentication is wired to.
//
// Both are required. There is no session manager and no token generator here:
// Basic authentication establishes neither, and a dependency it never uses
// would suggest otherwise.
type BasicAuthDeps struct {
	// Authenticator judges the decoded credentials.
	Authenticator authenticate.Authenticator

	// Attempts is where a refused credential is recorded. Supply the same
	// store the account-lockout policy reads, so a password guessed at over
	// Basic counts towards the same lockout as one guessed at over the login
	// form.
	Attempts policy.AttemptStore
}

// BasicAuthOption configures Basic authentication.
type BasicAuthOption func(*basicAuth) error

// EnableBasicAuth authenticates Basic credentials at the Basic slot.
//
// Default: the realm DefaultBasicAuthRealm, named in the WWW-Authenticate
// header a refusal carries. Requests whose Authorization header does not start
// with the exact prefix "Basic " pass through untouched.
//
// Basic authentication is stateless: it opens no session and issues no token,
// so a caller presents its credential on every request and has nothing to come
// back to. That is why a challenge raised here decides outright.
func EnableBasicAuth(d BasicAuthDeps, opts ...BasicAuthOption) Option {
	const option = "EnableBasicAuth"

	return func(c *config) error {
		b := &basicAuth{
			authn:    d.Authenticator,
			attempts: d.Attempts,
			now:      time.Now,
			realm:    DefaultBasicAuthRealm,
		}

		for _, opt := range opts {
			if opt == nil {
				continue
			}
			if err := opt(b); err != nil {
				return err
			}
		}

		c.enable(option, func() error {
			if err := requireDep(option, "authenticator", d.Authenticator); err != nil {
				return err
			}

			return requireDep(option, "attempt store", d.Attempts)
		})

		c.wire(b.wire)
		c.register(b, OrderBasicAuth)

		return nil
	}
}

// WithBasicAuthRealm names realm in the WWW-Authenticate header.
//
// Default: DefaultBasicAuthRealm. An empty realm is refused, and so is one
// carrying a quote, a backslash or a control character: the realm is written
// into a quoted header value, and a realm that could close that quote would let
// the configuration write header syntax of its own.
func WithBasicAuthRealm(realm string) BasicAuthOption {
	return func(b *basicAuth) error {
		if realm == "" {
			return newConfigError("WithBasicAuthRealm was given no realm; omit it to keep %q",
				DefaultBasicAuthRealm)
		}

		if i := strings.IndexFunc(realm, unquotableInRealm); i >= 0 {
			return newConfigError(
				"WithBasicAuthRealm was given a realm containing %q, which cannot be written "+
					"into a quoted header value", realm[i:i+1])
		}

		b.realm = realm
		return nil
	}
}

// unquotableInRealm reports a rune that must not reach a quoted header value.
func unquotableInRealm(r rune) bool {
	return r == '"' || r == '\\' || r < ' ' || r == 0x7f
}

// BearerTokenDeps are the collaborators bearer authentication is wired to.
//
// All three are required. The session manager and the user loader are what make
// a bearer token a reference to live state rather than a self-contained grant:
// without them a revoked session and a revoked role would both be honoured for
// the rest of the token's life.
type BearerTokenDeps struct {
	// Verifier checks the presented token and reports its claims.
	Verifier token.Verifier

	// Sessions loads the session the token's jti names.
	Sessions *session.Manager

	// Users reloads the user the token's subject names, so the roles the
	// request is judged on are the ones the store holds now.
	Users identity.UserLoader
}

// BearerTokenOption configures bearer authentication.
type BearerTokenOption func(*bearerToken) error

// EnableBearerToken authenticates bearer tokens at the bearer slot.
//
// Default: the scheme DefaultBearerScheme, matched without regard to case, and
// a token presented with no scheme at all is ignored. Requests carrying another
// scheme, or no Authorization header, pass through untouched.
func EnableBearerToken(d BearerTokenDeps, opts ...BearerTokenOption) Option {
	const option = "EnableBearerToken"

	return func(c *config) error {
		b := &bearerToken{
			verifier: d.Verifier,
			sessions: d.Sessions,
			users:    d.Users,
			now:      time.Now,
			scheme:   DefaultBearerScheme,
		}

		for _, opt := range opts {
			if opt == nil {
				continue
			}
			if err := opt(b); err != nil {
				return err
			}
		}

		c.enable(option, func() error {
			if err := requireDep(option, "token verifier", d.Verifier); err != nil {
				return err
			}
			if err := requireDep(option, "session manager", d.Sessions); err != nil {
				return err
			}

			return requireDep(option, "user loader", d.Users)
		})

		c.useSessions(d.Sessions)
		c.wire(b.wire)
		c.register(b, OrderBearerToken)

		return nil
	}
}

// WithBearerScheme presents tokens under scheme instead.
//
// Default: DefaultBearerScheme. The scheme is matched without regard to case
// either way. An empty scheme is refused: it would claim every Authorization
// header, including those of the schemes at neighbouring slots. Use
// WithBearerAllowEmptyScheme to accept a bare token as well.
func WithBearerScheme(scheme string) BearerTokenOption {
	return func(b *bearerToken) error {
		if strings.TrimSpace(scheme) == "" {
			return newConfigError("WithBearerScheme was given no scheme, which would claim " +
				"every Authorization header")
		}

		if strings.ContainsAny(scheme, " \t") {
			return newConfigError("WithBearerScheme was given %q, and a scheme is the one token "+
				"before the credential, so it can hold no space", scheme)
		}

		b.scheme = scheme
		return nil
	}
}

// WithBearerAllowEmptyScheme also accepts a token presented with no scheme.
//
// Default: off, so an Authorization header carrying a bare credential is left
// for whichever interceptor claims it. Turn it on for clients that send the
// token alone; it does not stop the configured scheme being accepted.
//
// The line it does not cross: a bare credential is indistinguishable from
// another scheme's opaque token, so a chain that enables this and another
// credential-bearing scheme hands both to whichever slot runs first. Enable it
// only where bearer tokens are the one thing that header carries.
func WithBearerAllowEmptyScheme() BearerTokenOption {
	return func(b *bearerToken) error {
		b.allowEmptyScheme = true
		return nil
	}
}

// PasswordChangeOption configures the password-change gate. Each replaces one
// of the defaults named on EnablePasswordChangeGate.
type PasswordChangeOption func(*passwordChangeGate) error

// EnablePasswordChangeGate holds every session that owes a password change at
// the password-change slot.
//
// Default: no resolve endpoint, under which a session that owes a change is
// refused until a new login clears it. Register one with
// WithChangePasswordEndpoint to let a caller pay the debt without logging in
// again. A request carrying no session passes the gate untouched.
//
// The session manager is required and is the one the marker is cleared in: a
// gate that could not record the change would refuse the next request just the
// same, and the caller would have changed their password for nothing.
func EnablePasswordChangeGate(sessions *session.Manager, opts ...PasswordChangeOption) Option {
	const option = "EnablePasswordChangeGate"

	return func(c *config) error {
		g := &passwordChangeGate{sessions: sessions}

		for _, opt := range opts {
			if opt == nil {
				continue
			}
			if err := opt(g); err != nil {
				return err
			}
		}

		c.enable(option, func() error {
			return requireDep(option, "session manager", sessions)
		})

		c.useSessions(sessions)
		c.register(g, OrderPasswordChange)

		return nil
	}
}

// WithChangePasswordEndpoint answers POST requests on path with fn.
//
// Default: no endpoint at all, under which only a new login clears the
// challenge. Requests to path pass the gate, so the one endpoint a caller who
// owes a password change can reach is the one that resolves it; every other
// method on that path is gated like anything else.
//
// An empty path, or no function, is refused: either would be an endpoint that
// cannot answer, while the consumer believed their callers had a way out of
// the gate.
func WithChangePasswordEndpoint(path string, fn ChangePasswordFunc) PasswordChangeOption {
	return func(g *passwordChangeGate) error {
		switch {
		case path == "":
			return newConfigError("WithChangePasswordEndpoint was given no path, so a caller " +
				"owing a password change would have no way to resolve it")
		case fn == nil:
			return newConfigError("WithChangePasswordEndpoint was given no function to change "+
				"the password with for %q", path)
		}

		g.path = path
		g.change = fn

		return nil
	}
}

// LogoutDeps are the collaborators logout is wired to.
//
// The session manager is required. Logout exists to end a session, and one
// wired without a store to end it in would answer every caller 200 while
// leaving every session live — a logout that reports success and does nothing
// is worse than no logout at all.
type LogoutDeps struct {
	// Sessions is where the caller's session is deleted. Supply the same
	// manager the authentication interceptors load sessions from, or a logout
	// deletes from a store nothing reads.
	Sessions *session.Manager
}

// LogoutOption configures logout. Each replaces one of the defaults named on
// EnableLogout.
type LogoutOption func(*logout) error

// EnableLogout ends the caller's session at the logout slot.
//
// Default: POST on DefaultLogoutPath, answered 200 with an empty body. The
// downstream handler is never called, because logout is this library's own
// endpoint. A request with no authentication result is refused with
// ErrAuthenticationRequired, and a session that is already gone is a success:
// two clients ending one session is ordinary.
//
// Every other request, including a GET on that path, passes through untouched.
func EnableLogout(d LogoutDeps, opts ...LogoutOption) Option {
	const option = "EnableLogout"

	return func(c *config) error {
		l := &logout{sessions: d.Sessions, path: DefaultLogoutPath}

		for _, opt := range opts {
			if opt == nil {
				continue
			}
			if err := opt(l); err != nil {
				return err
			}
		}

		c.enable(option, func() error {
			return requireDep(option, "session manager", d.Sessions)
		})

		c.useSessions(d.Sessions)
		c.register(l, OrderLogout)

		return nil
	}
}

// WithLogoutRequestPath answers logouts on path instead.
//
// Default: DefaultLogoutPath, which keeps passing through once the consumer
// moves the endpoint. An empty path is refused: it would match nothing, so the
// endpoint the consumer asked for would silently not exist.
func WithLogoutRequestPath(path string) LogoutOption {
	return func(l *logout) error {
		if path == "" {
			return newConfigError("WithLogoutRequestPath was given no path, so logout would " +
				"answer nothing")
		}

		l.path = path

		return nil
	}
}

// JWKSOption configures the key set endpoint. Each replaces one of the
// defaults named on EnableJWKSEndpoint.
type JWKSOption func(*jwksEndpoint) error

// EnableJWKSEndpoint serves the public key set at the key set slot.
//
// Default: GET on DefaultJWKSPath, answered 200 with a JSON content type and
// whatever the provider returned, unchanged. The downstream handler is never
// called, and every other request — including a POST on that path — passes
// through untouched.
//
// The slot is the outermost of the built-ins, because a client fetching the
// keys to verify a token with has no token to be authenticated by.
func EnableJWKSEndpoint(keys KeySetProvider, opts ...JWKSOption) Option {
	const option = "EnableJWKSEndpoint"

	return func(c *config) error {
		j := &jwksEndpoint{keys: keys, path: DefaultJWKSPath}

		for _, opt := range opts {
			if opt == nil {
				continue
			}
			if err := opt(j); err != nil {
				return err
			}
		}

		c.enable(option, func() error {
			return requireDep(option, "key set provider", keys)
		})

		c.register(j, OrderJWKS)

		return nil
	}
}

// WithJWKSEndpointPath serves the key set on path instead.
//
// Default: DefaultJWKSPath, which keeps passing through once the consumer
// moves the endpoint — a deployment that serves the conventional location
// through its own route is free to. An empty path is refused: it would match
// nothing, so the endpoint the consumer asked for would silently not exist.
func WithJWKSEndpointPath(path string) JWKSOption {
	return func(j *jwksEndpoint) error {
		if path == "" {
			return newConfigError("WithJWKSEndpointPath was given no path, so the key set " +
				"would be served nowhere")
		}

		j.path = path

		return nil
	}
}

// EnableAuthorization judges requests through az, applying rules centrally.
//
// Default: without this option the chain still runs its authorization stage,
// but publishes no authorizer and enforces nothing, so every per-endpoint
// guard behind it fails closed. With it and no rules, the authorizer reaches
// the route and the guards there decide alone.
//
// The rules are an ordered set: the first whose matcher accepts the request
// decides, and a request no rule matches is denied, so an endpoint added
// without a rule is closed rather than open. A consumer opts out of that
// default with a trailing rule that matches everything and requires
// authorize.PermitAll — one line, visible where the rules are read.
//
// Calling it more than once appends: the rules of every call form one set in
// the order the calls were made, so wiring split across modules still reads top
// to bottom. The authorizer of the last call is the one the chain judges by,
// because a chain has one authorizer and a second call is the consumer
// replacing their first choice rather than adding a second judge.
//
// A matcher sees the whole Request — path, method, headers — through the same
// abstraction every interceptor reads, so one rule set is written once and
// applies behind whichever framework the chain is mounted on.
func EnableAuthorization(az authorize.Authorizer, rules ...authorize.Rule[Request]) Option {
	const option = "EnableAuthorization"

	return func(c *config) error {
		c.authorizer = az
		c.authzRules = append(c.authzRules, rules...)

		c.enable(option, func() error {
			return requireDep(option, "authorizer", c.authorizer)
		})

		return nil
	}
}

// WithErrorHandler replaces what a refusal answers with on the net/http chain.
//
// Default: the status StatusForError gives and no body, so nothing the library
// knows reaches a client that the consumer did not choose to send. A handler
// set here receives the response writer, the request and the propagated error
// for every refusal, and the default response is not written: the consumer owns
// the whole answer, including its status.
//
// It is refused at construction when nil, because a chain with no way at all to
// answer a refusal would serve the refused request as though it had succeeded.
// Pass the same function to WithGuardErrorHandler so a chain refusal and a
// per-endpoint guard's refusal are rendered alike.
//
// It governs the net/http chain and nothing else, by design. A framework that
// already owns how a request is refused keeps that ownership: on gin the
// refusal goes to gin's error channel, so the consumer's own error middleware
// renders it, and on fiber it goes to fiber's error handler. Setting a handler
// here and mounting the chain on gin or fiber would leave the consumer with two
// places that answer a refusal and no way to tell which one did.
func WithErrorHandler(fn func(w http.ResponseWriter, r *http.Request, err error)) Option {
	return func(c *config) error {
		if fn == nil {
			return newConfigError("WithErrorHandler was given no handler, so a refusal " +
				"would be answered by nothing")
		}

		c.errorHandler = fn

		return nil
	}
}
