package httpsec

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/detach"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/eventsink"
	"github.com/kartaladev/scrty/internal/hangup"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/pkg/logsample"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

//go:generate mockgen -destination=authenticator_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/authenticate Authenticator
//go:generate mockgen -destination=attemptstore_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/policy AttemptStore
//go:generate mockgen -destination=encoder_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/authenticate/password Encoder

// The conventions form login follows when the consumer names none. They are
// constants rather than bare literals so a consumer who wants to follow the
// convention elsewhere — a client, a test, a reverse proxy rule — names the
// same thing this package does.
const (
	// DefaultLoginPath is the path form login answers POST requests on.
	DefaultLoginPath = "/sign-in/password"

	// DefaultLoginUsernameParam is the form field, and JSON member, the
	// submitted identifier is read from.
	DefaultLoginUsernameParam = "username"

	// DefaultLoginPasswordParam is the form field, and JSON member, the
	// submitted password is read from.
	DefaultLoginPasswordParam = "password"

	// DefaultLoginBodyLimit is how many request body bytes a login may carry.
	// The endpoint is unauthenticated, so an unbounded read there is a
	// memory-exhaustion path that costs an attacker no credential at all.
	DefaultLoginBodyLimit int64 = 64 << 10
)

// passwordLoginFlow names the source guard form login and Basic share, its
// rate-limit buckets and its sampler keys. One flow for both endpoints means a
// source spraying passwords across the two spends one allowance, not two.
const passwordLoginFlow = "password-login"

// The flows an endpoint given a limiter of its own runs under, so its guard,
// log keys and IPv6 aggregate namespace ("<flow>-ipv6-aggregate") share
// nothing with the other endpoint's, whatever factory the chain builds from.
const (
	passwordLoginFormFlow  = "password-login-form"
	passwordLoginBasicFlow = "password-login-basic"
)

// The allowance a source gets for failed password logins before its attempts
// stop being evaluated. Fifty bounds one source to fifty accounts sprayed per
// window, and still leaves room for an office or carrier-grade NAT, where many
// users share one address and some of them mistype.
const (
	defaultPasswordLoginLimit  = 50
	defaultPasswordLoginWindow = 15 * time.Minute
)

// LoginResult is what a successful login produced, handed to whatever writes
// the response.
type LoginResult struct {
	// Token is the credential issued for the new session: an access token
	// from FormLoginDeps.Tokens, or, with EnableSessionBearer on, the
	// session's own identifier.
	Token string

	// Session is the session the login opened.
	Session *session.Session

	// TokenType is how Token is presented: TokenTypeDPoP when the login
	// carried a DPoP proof and Token is bound to its key, TokenTypeBearer
	// otherwise. A responder writes it as its token response's token_type.
	TokenType TokenType
}

// LoginResponder writes the response to a successful login.
//
// With none supplied, the library writes a JSON document carrying the access
// token, its token_type, an empty refresh token field and the session's idle
// expiry; a
// consumer replaces that whole response with WithLoginResponder.
//
// It is called instead of the downstream handler, because a login is the
// library's own endpoint and the application has no route behind it. An error
// it returns leaves the chain as the request's refusal.
type LoginResponder func(ex *Exchange, result LoginResult) error

// formLogin answers a login on its own path and passes everything else
// through.
type formLogin struct {
	authn    authenticate.Authenticator
	sessions *session.Sessions
	tokens   token.Generator
	attempts policy.AttemptStore

	// issue issues the login's credential as the chain's bearer mode decides,
	// handed over at assembly.
	issue credentialIssuer

	// deliver hands the credential out once the session is stored: as the
	// session cookie on a cookie chain, unchanged for the body otherwise.
	deliver credentialDelivery

	// engine and log are handed over once the chain exists, because an option
	// applied after EnableFormLogin may still replace either.
	engine *policy.Engine
	log    *slog.Logger

	// enrolmentLifetime is how long a session the login tail marks for an
	// enrolment challenge may live, handed over by wire.
	enrolmentLifetime time.Duration

	// enforced holds the challenge kinds something on the chain enforces,
	// handed over by wire; a raised kind outside it refuses the request.
	enforced map[policy.ChallengeKind]bool

	// challengeMethods looks up the methods a raised challenge offers
	// (Chain.challengeMethods), before the login's session is created.
	challengeMethods challengeMethodsFunc

	// cancelHeld cancels the user's held account recoveries at login, set at
	// assembly when the chain's recovery may hold one, and nil otherwise.
	cancelHeld heldRecoveryCanceller

	// csrfToken is whether the sign-ins this first factor makes carry a CSRF
	// token, decided when the chain is built (config.wireCSRF).
	csrfToken bool

	// limiter is the consumer's own (WithLoginLimiter), and nil means the
	// password-login limiter the chain shares with Basic.
	limiter ratelimit.Limiter

	// guard is the password-login source guard, settled at assembly
	// (wirePasswordLogin), and sampler the chain's, handed over by wire.
	guard   sourceGuard
	sampler *refusalSampler

	// flow is the flow guard was built under, so the records the seam writes
	// name the limiter that is answering: the shared passwordLoginFlow, or
	// the endpoint's own.
	flow string

	// discloseLocks is the chain's WithLockDisclosure, settled at assembly.
	discloseLocks bool

	// discloseInactive is the chain's WithInactiveDisclosure, settled at
	// assembly.
	discloseInactive bool

	now func() time.Time

	// path is the endpoint's path: where the options placed it, and where it
	// answers under the base path once resolved.
	path          endpointPath
	usernameParam string
	passwordParam string
	bodyLimit     int64
	respond       LoginResponder

	// lifetime chooses the session's absolute lifetime, and nil keeps the
	// manager's absolute timeout.
	lifetime func(*Exchange, LoginFields) time.Duration

	// rehash stores an upgraded password hash, and nil upgrades nothing.
	rehash RehashFunc

	// automation is the automation-challenge gate when it was selected for
	// form login, settled at assembly, and nil otherwise.
	automation *challengeGate
}

// wire takes the settings the chain resolved. It runs once, after every option
// has been applied, so a logger or an engine wired after EnableFormLogin is
// still the one this interceptor uses.
func (l *formLogin) wire(c *Chain) {
	l.engine = c.engine
	l.log = c.logger
	l.enrolmentLifetime = c.enrolmentLifetime
	l.enforced = c.enforced
	l.challengeMethods = c.challengeMethods
	l.sampler = c.sampler
}

// flushRefusalLogs reports what the source guard and the authenticator are
// holding back; an authenticator that keeps no refusal logs of its own has
// nothing to report. The authenticator may be a consumer's, whose flush can
// fail, so its error is returned for Chain.FlushRefusalLogs to join.
func (l *formLogin) flushRefusalLogs() error {
	if l.guard != nil {
		l.guard.Flush()
	}

	if f, ok := l.authn.(logsample.Flusher); ok {
		return f.FlushRefusalLogs()
	}

	return nil
}

// wirePasswordLogin settles the password-login source guard of form login and
// Basic against the assembled configuration, once every option has been
// applied.
//
// The default guard is built once, from the chain's factory, and handed to
// every endpoint that was not given a limiter of its own, so form login and
// Basic spend one allowance between them. An endpoint given its own limiter
// gets a guard over that limiter under a flow of its own (passwordLoginFormFlow
// or passwordLoginBasicFlow), so its guard and IPv6 aggregate share nothing
// with the other endpoint's, and a factory that refuses one namespace with two
// policies is never asked for both. No default is built when no endpoint needs
// it, so the factory is not asked for a limiter nothing would use.
func (c *config) wirePasswordLogin() error {
	var shared sourceGuard

	guardFor := func(option, ownFlow string, own ratelimit.Limiter) (sourceGuard, string, error) {
		if own != nil {
			g, err := c.resolveSourceGuard(option, ownFlow, own,
				defaultPasswordLoginLimit, defaultPasswordLoginWindow, c.refusalInterval)

			return g, ownFlow, err
		}

		if shared == nil {
			g, err := c.resolveSourceGuard(option, passwordLoginFlow, nil,
				defaultPasswordLoginLimit, defaultPasswordLoginWindow, c.refusalInterval)
			if err != nil {
				return nil, passwordLoginFlow, err
			}

			shared = g
		}

		return shared, passwordLoginFlow, nil
	}

	if err := eachInterceptor(c, func(l *formLogin) error {
		l.discloseLocks = c.discloseLocks
		l.discloseInactive = c.discloseInactive
		c.warnWithoutDecoy("EnableFormLogin", l.authn)

		g, flow, err := guardFor("EnableFormLogin", passwordLoginFormFlow, l.limiter)
		l.guard, l.flow = g, flow

		return err
	}); err != nil {
		return err
	}

	return eachInterceptor(c, func(b *basicAuth) error {
		b.discloseLocks = c.discloseLocks
		b.discloseInactive = c.discloseInactive
		c.warnWithoutDecoy("EnableBasicAuth", b.authn)

		g, flow, err := guardFor("EnableBasicAuth", passwordLoginBasicFlow, b.limiter)
		b.guard, b.flow = g, flow

		return err
	})
}

// msgNoDecoy is the warning an endpoint whose lock refusals cannot cost the
// same password work as a wrong password is built with.
const msgNoDecoy = "httpsec: lock refusals may be told apart from wrong passwords by their timing, " +
	"because the login authenticator offers no decoy verification"

// warnWithoutDecoy writes msgNoDecoy, once for the endpoint option names,
// when locks are concealed and authn cannot spend a decoy (offersDecoy).
//
// The response to a lock then reads as a wrong password in its status and
// headers, but returns sooner than a password check would, which still tells
// a patient prober the account exists. It is a warning and not a
// configuration error: the authenticator is the consumer's, and one that
// cannot be made to spend the work is still better concealed than disclosed.
func (c *config) warnWithoutDecoy(option string, authn authenticate.Authenticator) {
	if c.discloseLocks {
		return
	}

	if offersDecoy(authn) {
		return
	}

	c.logger.Warn(msgNoDecoy, slog.String("option", option))
}

// offersDecoy reports whether authn may spend a decoy verification: it is an
// authenticate.DecoyVerifier and, if it can also say whether any of its own
// delegates offers one, as authenticate.FirstOf can, it says so. A FirstOf is
// always a DecoyVerifier, so the type alone does not tell.
func offersDecoy(authn authenticate.Authenticator) bool {
	if _, ok := authn.(authenticate.DecoyVerifier); !ok {
		return false
	}

	if o, ok := authn.(interface{ OffersDecoy() bool }); ok {
		return o.OffersDecoy()
	}

	return true
}

// refuseLocked answers a pre-authentication lock.
//
// Unless the consumer chose to disclose locks, it spends the same password
// work a real check would and refuses as a failed authentication, so neither
// the status nor the timing says the account exists and is locked. The lock
// stays reachable through errors.Is for the consumer's own handler. The
// decoy's verdict is never read: it verifies against a reference hash, not
// the account's, and says nothing.
func refuseLocked(
	ctx context.Context,
	authn authenticate.Authenticator,
	disclose bool,
	creds identity.Credentials,
	reason error,
) error {
	if disclose {
		return reason
	}

	if v, ok := authn.(authenticate.DecoyVerifier); ok {
		_ = v.VerifyDecoy(ctx, creds)
	}

	return errors.Join(authenticate.ErrAuthenticationFailed, reason)
}

// Intercept answers a login on the configured path and passes everything else
// through untouched.
func (l *formLogin) Intercept(ex *Exchange, next Next) error {
	if ex.Request.Method() != http.MethodPost || ex.Request.Path() != l.path.at() {
		return next(ex)
	}

	username, password, fields, err := l.bind(ex.Context(), ex.Request)
	if err != nil {
		return err
	}

	ctx := ex.Context()
	now := l.now()

	// The proof is judged before the password, so a bad one is refused as a
	// malformed request is, counted nowhere, and never as a failed password:
	// it cannot lock the account. With DPoP required, a login without one is
	// refused before any account is looked up.
	binding, err := issuingBinding(ctx, ex.dpop(), ex.certBinding(), ex.Request, ex.bearerCredential)
	if err != nil {
		return err
	}

	verifyCtx, upgrade := requestRehash(ctx, l.rehash)

	// Ends the handle on every outcome, after any Result, so the presented
	// password does not outlive the request.
	defer upgrade.Discard()

	// key is the account the identifier resolved to, under which the
	// failures were judged and a success clears them (see judgePassword).
	auth, key, err := l.attemptPasswordAs(verifyCtx, ex.Request.ClientIP(), username, password, now,
		func(ctx context.Context) {
			emitEvent(ctx, userEvent(event.AuthnLoginFail, event.OutcomeFailure, "", factor.Password))
		},
		func(ctx context.Context, src ratelimit.Source) error {
			return l.automation.ask(ctx, ex.Request, challengeQuery{
				flow:       ChallengeFlowFormLogin,
				source:     l.guard,
				clientIP:   ex.Request.ClientIP(),
				identifier: username,
				attempts:   l.attempts,
				charge:     func() { recordSourceFailure(ctx, l.guard, src) },
			})
		})
	if err != nil {
		return err
	}

	// Read before the failures are cleared, and only on a request a sink
	// watches: it decides nothing, and names the success's event.
	afterFailures := l.hadRecentFailures(ctx, key, now)

	// Only a login that named a principal supersedes the failures: one the
	// tail is about to refuse for want of one proved no one.
	if auth != nil && auth.Principal != nil {
		// The identifier as typed carries failures of its own when it is not
		// the account's key (see verifyPassword), cleared with the account's
		// and, like them, reported once: under the account.
		l.resetFailures(ctx, key)
		if username != key {
			l.resetTypedFailures(ctx, username)
		}
	}

	// A provider that answers neither an authentication nor an error has
	// named no principal, which the login tail refuses as it does any other.
	if auth == nil {
		auth = &authenticate.Authentication{}
	}

	ex.Authentication = auth

	var create []session.CreateOption

	if l.lifetime != nil {
		if d := l.lifetime(ex, fields); d > 0 {
			create = append(create, session.WithAbsoluteLifetime(d))
		}
	}

	tok, err := completeLogin(ex, loginTailDeps{
		engine:            l.engine,
		sessions:          l.sessions,
		tokens:            l.tokens,
		issue:             l.issue,
		deliver:           l.deliver,
		enrolmentLifetime: l.enrolmentLifetime,
		enforced:          l.enforced,
		log:               l.log,
		sampler:           l.sampler,
		now:               l.now,
		challengeMethods:  l.challengeMethods,
		cancelHeld:        l.cancelHeld,
		csrfToken:         l.csrfToken,
		binding:           binding,
		afterFailures:     afterFailures,
	}, postAuthenticationInput(
		auth.Principal, factor.Password, key, auth.PasswordChangedAt, now), create...)

	// The password verified, so a login that is answered, or is challenged for a
	// second factor the user can still present, upgrades an outdated hash. Any
	// other refusal does not: the request was not accepted.
	if err == nil || isChallenge(err) {
		runRehash(ctx, l.log, l.rehash, upgrade)
	}

	if err != nil {
		return err
	}

	// A login is answered here, not by the application's handler: the handler
	// behind the chain serves the application, and there is no application
	// route for the library's own endpoint.
	return l.respond(ex, LoginResult{Token: tok, Session: ex.Session, TokenType: tokenTypeOf(ex.Session)})
}

// attemptPassword is the password order a login and a password re-proof both
// run, so neither can drift from the other: the password-login source guard,
// the pre-authentication phase, then the password check (see
// authenticatePassword), with the source charged for what it spent. It does
// not clear the user's recorded failures: what counts as a success is the
// caller's to decide, and a re-proof first confirms the proved account is the
// session's own.
//
// The source is checked once the caller has read the credentials, so a
// malformed request spends nothing, and before the pre-authentication phase,
// so a throttled source costs neither a policy evaluation nor a password
// check.
//
// A source hammering a locked account spends its own allowance, so a lock is
// charged to it. Any other pre-authentication refusal, a policy deny or an
// unenforced challenge, is not. Every refused password check is charged, an
// unavailable user store and a load the client's own hang-up ended included:
// verifyPassword recorded nothing for the username then, and the source still
// pays for the password work it spent, so an outage or a client timing its
// hang-ups cannot spend work no throttle bounds.
func (l *formLogin) attemptPassword(
	ctx context.Context,
	clientIP, username string,
	password []byte,
	now time.Time,
	refused func(ctx context.Context),
	challenge func(ctx context.Context, src ratelimit.Source) error,
) (*authenticate.Authentication, error) {
	auth, _, err := l.attemptPasswordAs(ctx, clientIP, username, password, now, refused, challenge)

	return auth, err
}

// attemptPasswordAs is attemptPassword, also returning the key the attempt was
// judged under (see judgePassword), so a login clears its failures under the
// same key.
//
// The automation challenge, like the source guard, runs before the identifier
// is resolved, so nothing about the account is read for a request either
// refuses. It reads failures under the identifier as typed, which is why a
// refused password is recorded under that identifier too whenever it differs
// from the account's key (see verifyPassword): otherwise a registered email
// would never raise the challenge while an unknown one would.
func (l *formLogin) attemptPasswordAs(
	ctx context.Context,
	clientIP, username string,
	password []byte,
	now time.Time,
	refused func(ctx context.Context),
	challenge func(ctx context.Context, src ratelimit.Source) error,
) (*authenticate.Authentication, string, error) {
	src, err := sourceThrottled(ctx, l.guard, clientIP, l.flow, l.sampler, l.log, now)
	if err != nil {
		return nil, username, err
	}

	if challenge != nil {
		if err := challenge(ctx, src); err != nil {
			return nil, username, err
		}
	}

	return l.judgePassword(ctx, username, password, now, func() {
		recordSourceFailure(ctx, l.guard, src)
	}, refused)
}

// authenticatePassword judges a password the way a login does: the
// pre-authentication phase (preAuthenticate), then the password check
// (verifyPassword). Account recovery's password proof runs them through here,
// and login and re-proof through attemptPassword, which shares the same
// judgement (judgePassword), so none can drift from the others.
//
// The pre-authentication phase runs before the credential is checked, so a
// locked account is refused without its password ever being tested. Testing
// it first would make the refusal an oracle: a locked account would answer
// differently for a right guess than for a wrong one. A lock is refused as
// login refuses it (refuseLocked): concealed behind a decoy by default, the
// lock alone when the consumer discloses locks. A credential the
// authenticator refuses is recorded as a failed attempt; a user store that
// could not answer (authenticate.ErrUnavailable), and a load the request's own
// context ended, are returned as they are and recorded as nothing for the
// username. Clearing the failures a success supersedes is left to the caller,
// because only a login is a success in that sense.
//
// There is no source check or source charge here. The login endpoint and
// re-proof check the password-login guard through attemptPassword, and
// account recovery guards its own endpoint by source.
func (l *formLogin) authenticatePassword(
	ctx context.Context,
	username string,
	password []byte,
	now time.Time,
) (*authenticate.Authentication, error) {
	auth, _, err := l.judgePassword(ctx, username, password, now, func() {}, nil)

	return auth, err
}

// judgePassword is the pre-authentication phase, a lock refused as a login
// refuses it, then the password check, calling charge for a lock and for
// every refused password check, and for nothing else.
//
// refused, when not nil, is called for a lock and for a credential the
// authenticator refused, and never for a user store that could not answer or
// a load the request's own hang-up ended: it is where the caller reports the
// refusal it decided (security events), and a dependency failure or a hang-up
// decided nothing.
//
// The identifier is resolved first (resolveIdentifier), and everything the
// lockout sees is keyed on the result, which is returned: the
// pre-authentication phase, and the failure a refused password records. The
// authenticator is still asked about the identifier as typed, carrying the
// resolution so it does not load the user again. A resolution that fails is
// refused (refuseUnresolved) before the pre-authentication phase and without
// asking the authenticator, charged to the source like an outage, and reported
// to refused never: it decided nothing.
func (l *formLogin) judgePassword(
	ctx context.Context,
	username string,
	password []byte,
	now time.Time,
	charge func(),
	refused func(ctx context.Context),
) (*authenticate.Authentication, string, error) {
	ctx, key, err := resolveIdentifier(ctx, l.authn, username)
	if err != nil {
		charge()

		return nil, key, refuseUnresolved(ctx, unresolvedDeps{
			authn: l.authn, log: l.log, sampler: l.sampler, flow: l.flow, now: now,
		}, identity.NewUsernamePassword(username, password), err)
	}

	if err := l.preAuthenticate(ctx, key, now); err != nil {
		if !errors.Is(err, lockout.ErrAccountLocked) {
			return nil, key, err
		}

		charge()
		reportRefused(ctx, refused)

		return nil, key, refuseLocked(ctx, l.authn, l.discloseLocks,
			identity.NewUsernamePassword(username, password), err)
	}

	auth, err := l.verifyPassword(ctx, username, key, password, now)
	if err != nil {
		charge()

		if credentialRefused(ctx, err) {
			reportRefused(ctx, refused)
		}

		return nil, key, discloseInactive(l.discloseInactive, err)
	}

	return auth, key, nil
}

// resolveIdentifier resolves identifier to the key the lockout judges it under,
// when authn logs in by something other than a username
// (authenticate.ResolverOf), and returns ctx carrying the resolution for authn
// to authenticate without loading the user again.
//
// With no such resolver, identifier is its own key and ctx is returned as it
// is: the path, and its cost, are those of a username-only login. A consumer's
// resolver whose answer carries no key is keyed on the identifier as typed.
//
// A resolution that failed returns its error, with identifier as the key and
// ctx as it was given. The caller refuses it (refuseUnresolved) and never asks
// authn: the account the identifier names is unknown, so its lock and holds
// cannot be judged, and authenticating anyway would let a failing resolver
// bypass them.
func resolveIdentifier(
	ctx context.Context,
	authn authenticate.Authenticator,
	identifier string,
) (context.Context, string, error) {
	r, ok := authenticate.ResolverOf(authn)
	if !ok {
		return ctx, identifier, nil
	}

	resolved, err := r.ResolveIdentifier(ctx, identifier)
	if err != nil {
		return ctx, identifier, err
	}

	key := resolved.Key
	if key == "" {
		key = identifier
	}

	return authenticate.WithResolved(ctx, resolved), key, nil
}

// unresolvedDeps is what refuseUnresolved needs from the endpoint refusing:
// its authenticator, for the decoy, and where and how it records the refusal.
type unresolvedDeps struct {
	authn   authenticate.Authenticator
	log     *slog.Logger
	sampler *refusalSampler
	flow    string
	now     time.Time
}

// refuseUnresolved is the refusal of an identifier whose resolution failed with
// err, for the credentials presented.
//
// The outcome is the one the authenticator would have given for the same load
// failure, after the same password work, so the response says no more than an
// unknown username's outage does:
//
//   - a resolution the request's own context ended is the uniform failure
//     joined with that context's error and, when it differs, its cause, as a
//     user load the caller ended is: no password was compared;
//   - anything else, scrty's ErrUnavailable or a consumer's own error, is a
//     bare authenticate.ErrUnavailable: the resolver's text, which may quote
//     the identifier or a row, stays out of the refusal and of the record.
//
// The password work is one decoy verification, when the authenticator offers
// one (authenticate.DecoyVerifier), which is what scrty's provider spends on a
// lookup it could not finish. Nothing is recorded against any identifier: no
// credential was judged. The refusal is logged, sampled per flow, with a fixed
// reason and the error's type, never the identifier or the error's text.
func refuseUnresolved(ctx context.Context, d unresolvedDeps, creds identity.Credentials, err error) error {
	// The resolver may be the consumer's, and so is its error: one whose chain
	// cannot be walked is recorded once and read as the outage it stands for.
	err = porterr.SanitizeTo(ctx, d.log, err, authenticate.ErrUnavailable)

	if v, ok := d.authn.(authenticate.DecoyVerifier); ok {
		// Deliberately unread: the verification is the point, not its verdict.
		_ = v.VerifyDecoy(ctx, creds)
	}

	if hangup.ByCaller(ctx, err) {
		logSampled(ctx, d.sampler, d.log, slog.LevelDebug, d.now,
			d.flow+sampleKeySeparator+reasonResolveCallerEnded, msgResolveCallerEnded,
			append([]slog.Attr{slog.String("flow", d.flow)},
				diag.Failure(reasonResolveCallerEnded, err)...)...)

		return resolveEndedByCaller(ctx)
	}

	logSampled(ctx, d.sampler, d.log, slog.LevelError, d.now,
		d.flow+sampleKeySeparator+reasonResolveUnavailable, msgResolveUnavailable,
		append([]slog.Attr{slog.String("flow", d.flow)},
			diag.Failure(reasonResolveUnavailable, err)...)...)

	return authenticate.ErrUnavailable
}

// resolveEndedByCaller is the refusal of a resolution the request's own
// context ended: the uniform failure joined with the context's error and, when
// it differs, its cause, the shape loadEndedByCaller recognises.
func resolveEndedByCaller(ctx context.Context) error {
	ctxErr := ctx.Err()
	errs := []error{authenticate.ErrAuthenticationFailed, ctxErr}

	// The cause is read under the bounded walk, and one the walk gives up on
	// is left out, as it may hang or panic whoever reads the error next.
	if matched, abort := detach.CauseWalk(ctx, ctxErr); !matched && abort == nil {
		errs = append(errs, context.Cause(ctx))
	}

	return errors.Join(errs...)
}

// The reasons and records of a resolution refused by refuseUnresolved. The
// messages are constants: the refusal they accompany says nothing about the
// cause, so the record is where an operator learns of it.
const (
	reasonResolveUnavailable = "resolve-unavailable"
	reasonResolveCallerEnded = "resolve-caller-ended"

	msgResolveUnavailable = "httpsec: the login identifier could not be resolved"
	msgResolveCallerEnded = "httpsec: the caller left while the login identifier was resolved"
)

// preAuthenticate is the pre-authentication phase's refusal of username, or
// nil when the phase lets the password be checked.
func (l *formLogin) preAuthenticate(ctx context.Context, username string, now time.Time) error {
	pre := evaluatePhase(ctx, l.engine, policy.PreAuthentication, &policy.Input{
		Username: username,
		Now:      now,
	})

	return refusePreAuthentication(pre, l.enforced)
}

// verifyPassword checks the password presented for username, recording a
// refused one as a failed attempt against the account, under key (see
// judgePassword), and also under username, the identifier as typed, when it is
// not key (recordFailure). Lockout judges key alone; the second record is what
// the automation challenge reads (see attemptPasswordAs), so a registered
// email accrues failures under itself exactly as an unknown one does. With
// scrty's provider an identifier that resolved to a different key is no
// account's username, since a username is always looked up first, so the
// second record locks no one, and it is written unreported
// (recordUnreported), so one account's lock is reported once.
//
// A user store that could not answer (authenticate.ErrUnavailable) is returned
// as it is and recorded as nothing against the account: no credential was
// judged, and counting it would let an outage lock or hold accounts whose
// owners typed the right password. Nor is a load the request's own context
// ended (see loadEndedByCaller) recorded against the account: no password was
// compared, and recording it would let client timeouts in front of a slow
// store hold an account. Both are returned as they are, for the caller to
// charge to the source.
func (l *formLogin) verifyPassword(
	ctx context.Context,
	username, key string,
	password []byte,
	now time.Time,
) (*authenticate.Authentication, error) {
	auth, err := l.authn.Authenticate(ctx, identity.NewUsernamePassword(username, password))
	// The authenticator may be the consumer's, and so is its error. One whose
	// chain cannot be walked becomes a fault matching ErrUnavailable, so it is
	// answered, charged and recorded exactly as a user-store outage is.
	err = porterr.SanitizeTo(ctx, l.log, err, authenticate.ErrUnavailable)
	if err != nil && !credentialRefused(ctx, err) {
		return nil, err
	}
	if err != nil {
		l.recordFailure(ctx, key, username, now)

		return nil, err
	}

	return auth, nil
}

// recordUnreported records a failure for typed, the identifier as presented
// when it resolved to another account key, through store's unreported record
// when store offers one (policy.UnreportedAttemptRecorder): the account's own
// record, under its key, is the one the lockout judges and reports, and a
// second report under typed would report one account twice. A store that
// offers none records it as any failure; it reports nothing, so it has
// nothing to report twice.
func recordUnreported(ctx context.Context, store policy.AttemptStore, typed string, at time.Time) error {
	if r, ok := store.(policy.UnreportedAttemptRecorder); ok {
		return r.RecordFailureUnreported(ctx, typed, at)
	}

	return store.RecordFailure(ctx, typed, at)
}

// resetUnreported is recordUnreported's counterpart for a success: it clears
// typed's failures without reporting the clearing.
func resetUnreported(ctx context.Context, store policy.AttemptStore, typed string) error {
	if r, ok := store.(policy.UnreportedAttemptRecorder); ok {
		return r.ResetUnreported(ctx, typed)
	}

	return store.Reset(ctx, typed)
}

// credentialRefused reports whether err, an authenticator's failure, is a
// credential it judged and refused: neither a user store that could not
// answer (authenticate.ErrUnavailable) nor a load the request's own context
// ended (loadEndedByCaller).
func credentialRefused(ctx context.Context, err error) bool {
	return !errors.Is(err, authenticate.ErrUnavailable) && !loadEndedByCaller(ctx, err)
}

// reportRefused calls refused, when there is one.
func reportRefused(ctx context.Context, refused func(ctx context.Context)) {
	if refused != nil {
		refused(ctx)
	}
}

// loadEndedByCaller reports whether err is the authenticator's uniform failure
// for a user load the request's own context ended, so that no password was
// compared: ctx has ended, and err matches authenticate.ErrAuthenticationFailed
// and ctx's error or its cause, as the password provider's joined failure
// does. It decides from the error, never from ctx alone: a password compared
// and refused before the client left is a failed attempt like any other.
func loadEndedByCaller(ctx context.Context, err error) bool {
	return errors.Is(err, authenticate.ErrAuthenticationFailed) && hangup.ByCaller(ctx, err)
}

// checkPassword is account recovery's password proof (recovery.PasswordCheck):
// this login's pre-authentication phase, authenticator and attempt recording,
// in that order. A correct password clears no recorded failures, since a
// recovery that passes its password proof may still be refused.
//
// A lock is refused as login refuses it (see authenticatePassword), and the
// recovery turns the concealed refusal into its own, so a locked account reads
// as an unknown user or a wrong code does.
func (l *formLogin) checkPassword(ctx context.Context, username string, password []byte) error {
	_, err := l.authenticatePassword(ctx, username, password, l.now())

	return err
}

// bind reads the submitted identifier and password out of the request, and
// the other fields it carried, without the password.
//
// The body is read under the bound first, because everything after it parses
// what was read: an unauthenticated endpoint that parses before it bounds has
// already spent the memory the bound exists to cap.
func (l *formLogin) bind(ctx context.Context, r Request) (string, []byte, LoginFields, error) {
	body, err := readBody(ctx, r, l.bodyLimit)
	if err != nil {
		return "", nil, LoginFields{}, err
	}

	fields := l.bindForm(r, body)
	username, password := l.credentials(fields)

	// The JSON body is read only when the form yielded neither field, so a
	// form login is never re-read as JSON and a client that sent both is not
	// silently judged on the one it did not mean.
	if username == "" && password == "" {
		fields, err = l.bindJSON(r, body)
		if err != nil {
			return "", nil, LoginFields{}, err
		}

		username, password = l.credentials(fields)
	}

	if username == "" || password == "" {
		return "", nil, LoginFields{}, ErrCredentialsMissing
	}

	// The password is taken out of what the lifetime function may read, so
	// that function can never see, log or echo it.
	delete(fields, l.passwordParam)

	return username, []byte(password), LoginFields{values: fields}, nil
}

// credentials reads the identifier and the password from the submitted fields;
// a member that is absent or not a string is empty.
func (l *formLogin) credentials(fields map[string]any) (string, string) {
	username, _ := fields[l.usernameParam].(string)
	password, _ := fields[l.passwordParam].(string)

	return username, password
}

// bindForm reads the submitted fields out of the parsed POST body, and only
// out of it. A field sent more than once is read as its first value.
//
// Request.FormValue looks in the posted form first and falls back to the URL
// query, on every adapter. A credential accepted from a query string is a
// credential already written into every access log, proxy log and browser
// history that saw the URL, and into the Referer the next page sends. A login
// is a body, so the query is not consulted here at all — this reader does not
// use FormValue, unlike the consumer interceptors that legitimately read a
// query parameter through it.
//
// A body that does not declare itself a form is left to bindJSON, and one that
// does not parse yields no credential rather than half of one: a pair the
// client did not send is not a pair this endpoint invents.
func (l *formLogin) bindForm(r Request, body []byte) map[string]any {
	if !declaresForm(r.Header("Content-Type")) {
		return nil
	}

	values, err := url.ParseQuery(string(body))
	if err != nil {
		return nil
	}

	fields := make(map[string]any, len(values))
	for name := range values {
		fields[name] = values.Get(name)
	}

	return fields
}

// bindJSON reads the submitted members from a body that declares itself JSON.
//
// A body that declares another media type is not read as JSON even when it
// would parse: what a body is, is what the request says it is, and guessing
// would let a client reach this path without saying so.
func (l *formLogin) bindJSON(r Request, body []byte) (map[string]any, error) {
	if len(body) == 0 || !declaresJSON(r.Header("Content-Type")) {
		return nil, nil
	}

	var fields map[string]any
	if err := json.Unmarshal(body, &fields); err != nil {
		// The client's mistake, and reported as one: it says nothing about the
		// account, because no account has been looked at yet.
		return nil, ErrCredentialsMissing
	}

	return fields, nil
}

// hadRecentFailures reports whether username has failed attempts within the
// lockout's failure window (identifierWindow), so its success is reported as
// event.AuthnLoginSuccessAfterFail. It reads the attempt store only on a
// request a sink watches, and a store that cannot answer reads as none: the
// answer names an event and decides nothing.
func (l *formLogin) hadRecentFailures(ctx context.Context, username string, now time.Time) bool {
	if !eventsink.Enabled(ctx) || nilcheck.IsNil(l.attempts) {
		return false
	}

	n, err := l.attempts.FailureCount(ctx, username, now.Add(-identifierWindow(l.engine)))

	return err == nil && n > 0
}

// recordFailure counts one failed attempt, logging a store that could not.
//
// Bookkeeping, not the decision: a store that cannot record must not turn a
// wrong password into a server fault, and must not turn it into a success
// either. The refusal the caller returns is the same eitherway.
//
// The record carries a fixed reason and the attempt store's error type, never
// its text: a consumer whose store wraps a database error may quote a column
// of the row the library never saw. A consumer who wants that detail logs it
// inside their own policy.AttemptStore.
//
// It records under key, the account's, and, when typed differs from key, under
// typed too, unreported (recordUnreported). Each write is attempted and logged
// on its own, so a store that fails one still gets the other.
func (l *formLogin) recordFailure(ctx context.Context, key, typed string, now time.Time) {
	// The client's cancellation is not passed on: a client that hangs up after
	// sending its guess must still be charged for it, and an attempt store that
	// honours cancellation would otherwise drop the failure. The context names
	// the password factor, which the lockout's view reports a lock with.
	bounded, cancel := detach.Bounded(ctx, detach.WriteTimeout)
	defer cancel()

	recordCtx := eventsink.WithFactor(bounded, factor.Password)
	logAttemptStoreErr(ctx, l.log, msgAttemptNotRecorded, l.attempts.RecordFailure(recordCtx, key, now))

	if typed != key {
		logAttemptStoreErr(ctx, l.log, msgAttemptNotRecorded, recordUnreported(recordCtx, l.attempts, typed, now))
	}
}

// resetFailures clears what a successful login supersedes, logging a store
// that could not: an account whose failures outlive the login that cleared
// them locks a user who has just proved they are not guessing.
//
// As with recordFailure, the record names the fixed reason and the store's
// error type, never its text.
func (l *formLogin) resetFailures(ctx context.Context, username string) {
	logAttemptStoreErr(ctx, l.log, msgAttemptsNotReset, l.attempts.Reset(ctx, username))
}

// resetTypedFailures clears the failures recorded under typed, the identifier
// as presented when it resolved to another account key, without reporting the
// clearing (resetUnreported): the account's own clearing is reported under its
// key. A store that could not is logged as resetFailures logs it.
func (l *formLogin) resetTypedFailures(ctx context.Context, typed string) {
	logAttemptStoreErr(ctx, l.log, msgAttemptsNotReset, resetUnreported(ctx, l.attempts, typed))
}

// logAttemptStoreErr logs err, a write the attempt store refused, if any,
// with msg, the fixed record of that write (msgAttemptNotRecorded,
// msgAttemptsNotReset). Only logged, but sanitized so an error that cannot be
// walked is recorded as an abort too.
func logAttemptStoreErr(ctx context.Context, log *slog.Logger, msg string, err error) {
	if err = porterr.SanitizeTo(ctx, log, err, porterr.ErrUnwalkable); err != nil {
		log.LogAttrs(ctx, slog.LevelError, msg, diag.Failure("attempt-store", err)...)
	}
}

// The records a broken attempt store is reported with. They are constants
// because the outcome they accompany is deliberately unchanged, so the record
// is the only place an operator learns the lockout count has stopped moving.
const (
	msgAttemptNotRecorded = "httpsec: a failed login attempt could not be recorded"
	msgAttemptsNotReset   = "httpsec: failed login attempts could not be cleared"
)

// refusePreAuthentication is what the pre-authentication decision refuses
// with, before a credential is checked: its deny, or a challenge of a kind
// nothing on the chain enforces (see refuseUnenforced). A challenge of an
// enforced kind refuses nothing here; the phase has no session to mark it on.
func refusePreAuthentication(pre policy.Decision, enforced map[policy.ChallengeKind]bool) error {
	switch pre.Outcome {
	case policy.Deny:
		return policyDenyReason(pre)
	case policy.Challenge:
		return refuseUnenforced(enforced, pre.Challenge)
	case policy.Allow:
	}

	return nil
}

// evaluatePhase asks the engine for a phase's decision, allowing when no engine
// is wired.
//
// With no engine every phase allows, which is the documented default of
// WithPolicyEngine: a consumer who registers no policies rests on
// authentication alone rather than on a phase that refuses everything.
func evaluatePhase(
	ctx context.Context,
	e *policy.Engine,
	phase policy.Phase,
	in *policy.Input,
) policy.Decision {
	if e == nil {
		return policy.Decision{Outcome: policy.Allow}
	}

	return e.EvaluatePhase(ctx, phase, in)
}

// judgeBehindSecondFactor is the post-authentication decision d of a request
// that has just verified a second factor, with what a challenge for that
// factor hid judged too. A second-factor re-proof and MFA verification both
// take their decision through it.
//
// The engine returns the first challenge in registration order, so a
// challenge registered after the policy asking for a second factor never
// surfaces while that one is held: dropping the second-factor challenge,
// because the factor has just been presented, would drop it too. So when d is
// a policy.ChallengeMFA the phase is judged once more, at the same instant,
// on a copy of in saying the request has satisfied a second factor
// (policy.Input.MFASatisfied), which it has. That decision is returned, a
// deny or a challenge of another kind as the caller refuses any, and a second
// policy.ChallengeMFA reduced to an allow: the factor is the one being
// presented. Any other d is returned unchanged, and in is never modified.
//
// When in already says the second factor is satisfied, d was judged with it,
// and asking again would ask the same question: a policy.ChallengeMFA is then
// reduced to an allow without evaluating the phase again.
//
// It can only add refusals to dropping the second-factor challenge outright.
// A policy that raises policy.ChallengeMFA in this phase without honouring
// MFASatisfied keeps raising it, and whatever it hides stays hidden; the
// library's policy.MFA honours it, and policy.MFARequirement raises no
// post-authentication second-factor challenge for a login off the federated
// channel, and allows an unmet federated one once MFASatisfied and
// Reauthenticating are both set.
func judgeBehindSecondFactor(
	ctx context.Context,
	e *policy.Engine,
	in *policy.Input,
	d policy.Decision,
) policy.Decision {
	if d.Outcome != policy.Challenge || d.Challenge != policy.ChallengeMFA {
		return d
	}

	if in.MFASatisfied {
		return policy.Decision{Outcome: policy.Allow}
	}

	satisfied := *in
	satisfied.MFASatisfied = true

	behind := evaluatePhase(ctx, e, policy.PostAuthentication, &satisfied)
	if behind.Outcome == policy.Challenge && behind.Challenge == policy.ChallengeMFA {
		return policy.Decision{Outcome: policy.Allow}
	}

	return behind
}

// writeLoginResult is the response a login succeeds with when the consumer
// supplies none: a JSON document carrying the access token, its token_type,
// an empty refresh token field and the session's idle expiry.
//
// The refresh token field is present and empty rather than absent, so a client
// written against this document does not have to be changed when a capability
// that issues refresh tokens starts filling it.
func writeLoginResult(ex *Exchange, result LoginResult) error {
	body := loginDocument{AccessToken: result.Token, TokenType: result.TokenType}
	if result.Session != nil {
		body.ValidUntil = result.Session.IdleExpiresAt
	}

	return writeSuccessDocument(ex, body)
}

// writeSuccessDocument is the framing every built-in responder answers a
// success with: the document as JSON, with the content type and 200 that go
// with it. The responders differ in the document they build and in nothing
// else, so they share this and cannot drift apart in how they write it.
//
// The response is marked Cache-Control: no-store, because the documents carry
// credentials or the state of a credential. A consumer's own responder owns its
// headers, so this is the default's and nothing here overrides what a
// replacement sets.
func writeSuccessDocument(ex *Exchange, body any) error {
	//nolint:gosec // G117: the access token is the document's purpose, not a leak of one
	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}

	ex.Writer.SetHeader("Content-Type", "application/json")
	ex.Writer.SetHeader("Cache-Control", "no-store")
	ex.Writer.WriteHeader(http.StatusOK)
	_, err = ex.Writer.Write(encoded)

	return err
}

// loginDocument is the default success body. Its member names are the
// documented contract of that default: a consumer who wants other names
// replaces the whole responder rather than having this one reshaped.
type loginDocument struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ValidUntil   time.Time `json:"valid_until"`

	// TokenType is the access token's type, DPoP or Bearer (RFC 9449
	// section 5), left out when the writer did not know it.
	TokenType TokenType `json:"token_type,omitempty"`
}

// LoginFields are the fields a login request carried, as WithLoginLifetime's
// function reads them: the form values (each as its string) or the members of
// the JSON object (each as decoded), by name.
//
// The configured password parameter (WithLoginParams, default
// DefaultLoginPasswordParam) is dropped before the fields are built, so
// Value never reports it, whatever the request sent. The library does not
// interpret the rest: a consumer-defined field such as "remember" is returned
// as submitted, a string from a form and a decoded value from JSON, and its
// meaning belongs to the consumer. The zero value carries no fields.
type LoginFields struct{ values map[string]any }

// Value returns the field called name and whether the request carried it. The
// password parameter is never carried. The result must be treated as
// read-only.
func (f LoginFields) Value(name string) (any, bool) { v, ok := f.values[name]; return v, ok }

// isChallenge reports whether err asks the caller for a second factor rather
// than refusing the request.
func isChallenge(err error) bool {
	var ch *ChallengeError

	return errors.As(err, &ch)
}

// endpoints declares password sign-in.
func (l *formLogin) endpoints() []Endpoint {
	return []Endpoint{
		declare("EnableFormLogin", "WithLoginRequestPath", OperationSignInPassword, l.path.at(),
			MatchExact, OtherMethodsPassThrough, RequiresNothing, http.MethodPost),
	}
}

// WithInactiveDisclosure answers a correct password for an inactive account
// with that refusal alone, instead of as a wrong password.
//
// Default: concealed. The password provider joins
// authenticate.ErrAccountInactive beneath authenticate.ErrAuthenticationFailed,
// and only once the password has verified, so form login and Basic answer it
// 401, Basic with its challenge, and the problem-details integration gives it
// the type a wrong password gets: neither the status, the headers, the problem
// type nor the time taken tells a client the account exists and is inactive.
// errors.Is(err, authenticate.ErrAccountInactive) still holds, so a consumer's
// own error handler can render it however it chooses.
//
// With this option the refusal is authenticate.ErrAccountInactive alone, which
// StatusForError answers 403 Forbidden: the caller is identified and refused,
// and a 401 would invite a retry with the same credentials. A 403 is not a 401,
// so a disclosed Basic refusal carries no WWW-Authenticate header. A wrong
// password for an inactive account is never disclosed: the provider does not
// judge the account's state until the password verifies.
//
// What it gives up: the response tells anyone who holds an account's password
// that the account is inactive, which is no more than that the password is
// right. It governs only form login and Basic, exactly where WithLockDisclosure
// applies, and changes nothing a refusal counts against.
func WithInactiveDisclosure() Option {
	return func(c *config) error {
		c.discloseInactive = true

		return nil
	}
}

// discloseInactive returns the inactive-account refusal alone when disclose is
// on and err carries it, and err unchanged otherwise. The provider joins the
// refusal only after the password verified, so a wrong password never reaches
// the first branch.
func discloseInactive(disclose bool, err error) error {
	if disclose && errors.Is(err, authenticate.ErrAccountInactive) {
		return authenticate.ErrAccountInactive
	}

	return err
}
