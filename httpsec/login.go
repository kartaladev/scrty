package httpsec

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/pkg/logsample"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

//go:generate mockgen -destination=authenticator_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/authenticate Authenticator
//go:generate mockgen -destination=attemptstore_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/policy AttemptStore
//go:generate mockgen -destination=encoder_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/password Encoder

// The conventions form login follows when the consumer names none. They are
// constants rather than bare literals so a consumer who wants to follow the
// convention elsewhere — a client, a test, a reverse proxy rule — names the
// same thing this package does.
const (
	// DefaultLoginPath is the path form login answers POST requests on.
	DefaultLoginPath = "/login"

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
	// Token is the access token issued for the new session.
	Token string

	// Session is the session the login opened.
	Session *session.Session
}

// LoginResponder writes the response to a successful login.
//
// With none supplied, the library writes a JSON document carrying the access
// token, an empty refresh token field and the session's idle expiry; a
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
	sessions *session.Manager
	tokens   token.Generator
	attempts policy.AttemptStore

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

	// limiter is the consumer's own (WithLoginLimiter), and nil means the
	// password-login limiter the chain shares with Basic.
	limiter ratelimit.Limiter

	// guard is the password-login source guard, settled at assembly
	// (wirePasswordLogin), and sampler the chain's, handed over by wire.
	guard   sourceGuard
	sampler *logsample.Sampler

	// flow is the flow guard was built under, so the records the seam writes
	// name the limiter that is answering: the shared passwordLoginFlow, or
	// the endpoint's own.
	flow string

	// discloseLocks is the chain's WithLockDisclosure, settled at assembly.
	discloseLocks bool

	now func() time.Time

	path          string
	usernameParam string
	passwordParam string
	bodyLimit     int64
	respond       LoginResponder
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
// nothing to report.
func (l *formLogin) flushRefusalLogs() {
	if l.guard != nil {
		l.guard.Flush()
	}

	if f, ok := l.authn.(authenticate.RefusalLogFlusher); ok {
		_ = f.FlushRefusalLogs() // documented never to fail: its reporter only logs
	}
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
		c.warnWithoutDecoy("EnableFormLogin", l.authn)

		g, flow, err := guardFor("EnableFormLogin", passwordLoginFormFlow, l.limiter)
		l.guard, l.flow = g, flow

		return err
	}); err != nil {
		return err
	}

	return eachInterceptor(c, func(b *basicAuth) error {
		b.discloseLocks = c.discloseLocks
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
// delegates offers one, as authenticate.Manager can, it says so. A Manager is
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
	if ex.Request.Method() != http.MethodPost || ex.Request.Path() != l.path {
		return next(ex)
	}

	username, password, err := l.bind(ex.Request)
	if err != nil {
		return err
	}

	ctx := ex.Context()
	now := l.now()

	// The source is checked once the credentials are read, so a malformed
	// login spends nothing, and before the pre-authentication phase, so a
	// throttled source costs neither a policy evaluation nor a password check.
	src, err := sourceThrottled(ctx, l.guard, ex.Request.ClientIP(), l.flow,
		l.sampler, l.log, now)
	if err != nil {
		return err
	}

	if err := l.preAuthenticate(ctx, username, now); err != nil {
		if !errors.Is(err, policy.ErrAccountLocked) {
			return err
		}

		// A source hammering a locked account spends its own allowance.
		recordSourceFailure(ctx, l.guard, src)

		return refuseLocked(ctx, l.authn, l.discloseLocks,
			identity.NewUsernamePassword(username, password), err)
	}

	auth, err := l.verifyPassword(ctx, username, password, now)
	if err != nil {
		recordSourceFailure(ctx, l.guard, src)

		return err
	}

	l.resetFailures(ctx, username)

	ex.Authentication = auth

	tok, err := completeLogin(ex, loginTailDeps{
		engine:            l.engine,
		sessions:          l.sessions,
		tokens:            l.tokens,
		enrolmentLifetime: l.enrolmentLifetime,
		enforced:          l.enforced,
		challengeMethods:  l.challengeMethods,
		cancelHeld:        l.cancelHeld,
	}, postAuthenticationInput(
		auth.Principal, factor.Password, username, auth.PasswordChangedAt, now))
	if err != nil {
		return err
	}

	// A login is answered here, not by the application's handler: the handler
	// behind the chain serves the application, and there is no application
	// route for the library's own endpoint.
	return l.respond(ex, LoginResult{Token: tok, Session: ex.Session})
}

// authenticatePassword judges a password the way a login does: the
// pre-authentication phase (preAuthenticate), then the password check
// (verifyPassword). Login runs the same two steps, and account recovery's
// password proof runs them through here, so neither can drift from them.
//
// The pre-authentication phase runs before the credential is checked, so a
// locked account is refused without its password ever being tested. Testing
// it first would make the refusal an oracle: a locked account would answer
// differently for a right guess than for a wrong one. A lock is refused as
// login refuses it (refuseLocked): concealed behind a decoy by default, the
// lock alone when the consumer discloses locks. A credential the
// authenticator refuses is recorded as a failed attempt. Clearing the failures
// a success supersedes is left to the caller, because only a login is a
// success in that sense.
//
// There is no source check here. The login endpoint checks the
// password-login guard before calling the two steps itself, and account
// recovery guards its own endpoint by source.
func (l *formLogin) authenticatePassword(
	ctx context.Context,
	username string,
	password []byte,
	now time.Time,
) (*authenticate.Authentication, error) {
	if err := l.preAuthenticate(ctx, username, now); err != nil {
		if errors.Is(err, policy.ErrAccountLocked) {
			return nil, refuseLocked(ctx, l.authn, l.discloseLocks,
				identity.NewUsernamePassword(username, password), err)
		}

		return nil, err
	}

	return l.verifyPassword(ctx, username, password, now)
}

// preAuthenticate is the pre-authentication phase's refusal of username, or
// nil when the phase lets the password be checked.
func (l *formLogin) preAuthenticate(ctx context.Context, username string, now time.Time) error {
	pre := evaluatePhase(ctx, l.engine, policy.PreAuthentication, &policy.Input{
		Username: username,
		Now:      now,
	})

	return refusePreAuthentication(pre, l.enforced)
}

// verifyPassword checks the password, recording a refused one as a failed
// attempt against the account.
func (l *formLogin) verifyPassword(
	ctx context.Context,
	username string,
	password []byte,
	now time.Time,
) (*authenticate.Authentication, error) {
	auth, err := l.authn.Authenticate(ctx, identity.NewUsernamePassword(username, password))
	if err != nil {
		l.recordFailure(ctx, username, now)

		return nil, err
	}

	return auth, nil
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

// bind reads the submitted identifier and password out of the request.
//
// The body is read under the bound first, because everything after it parses
// what was read: an unauthenticated endpoint that parses before it bounds has
// already spent the memory the bound exists to cap.
func (l *formLogin) bind(r Request) (string, []byte, error) {
	body, err := r.Body(l.bodyLimit)
	if err != nil {
		return "", nil, err
	}

	username, password := l.bindForm(r, body)

	// The JSON body is read only when the form yielded neither field, so a
	// form login is never re-read as JSON and a client that sent both is not
	// silently judged on the one it did not mean.
	if username == "" && password == "" {
		username, password, err = l.bindJSON(r, body)
		if err != nil {
			return "", nil, err
		}
	}

	if username == "" || password == "" {
		return "", nil, ErrCredentialsMissing
	}

	return username, []byte(password), nil
}

// bindForm reads the credentials out of the parsed POST body, and only out of
// it.
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
func (l *formLogin) bindForm(r Request, body []byte) (string, string) {
	if !declaresForm(r.Header("Content-Type")) {
		return "", ""
	}

	values, err := url.ParseQuery(string(body))
	if err != nil {
		return "", ""
	}

	return values.Get(l.usernameParam), values.Get(l.passwordParam)
}

// bindJSON reads the credentials from a body that declares itself JSON.
//
// A body that declares another media type is not read as JSON even when it
// would parse: what a body is, is what the request says it is, and guessing
// would let a client reach this path without saying so.
func (l *formLogin) bindJSON(r Request, body []byte) (string, string, error) {
	if len(body) == 0 || !declaresJSON(r.Header("Content-Type")) {
		return "", "", nil
	}

	var fields map[string]any
	if err := json.Unmarshal(body, &fields); err != nil {
		// The client's mistake, and reported as one: it says nothing about the
		// account, because no account has been looked at yet.
		return "", "", ErrCredentialsMissing
	}

	username, _ := fields[l.usernameParam].(string)
	password, _ := fields[l.passwordParam].(string)

	return username, password, nil
}

// declaresJSON reports whether a content type names JSON, ignoring parameters
// such as a charset and accepting the +json structured suffix.
func declaresJSON(contentType string) bool {
	media, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}

	return media == "application/json" || strings.HasSuffix(media, "+json")
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
func (l *formLogin) recordFailure(ctx context.Context, username string, now time.Time) {
	// The client's cancellation is not passed on: a client that hangs up after
	// sending its guess must still be charged for it, and an attempt store that
	// honours cancellation would otherwise drop the failure.
	if err := l.attempts.RecordFailure(context.WithoutCancel(ctx), username, now); err != nil {
		l.log.LogAttrs(ctx, slog.LevelError, msgAttemptNotRecorded,
			diag.Failure("attempt-store", err)...)
	}
}

// resetFailures clears what a successful login supersedes, logging a store
// that could not: an account whose failures outlive the login that cleared
// them locks a user who has just proved they are not guessing.
//
// As with recordFailure, the record names the fixed reason and the store's
// error type, never its text.
func (l *formLogin) resetFailures(ctx context.Context, username string) {
	if err := l.attempts.Reset(ctx, username); err != nil {
		l.log.LogAttrs(ctx, slog.LevelError, msgAttemptsNotReset,
			diag.Failure("attempt-store", err)...)
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

// writeLoginResult is the response a login succeeds with when the consumer
// supplies none: a JSON document carrying the access token, an empty refresh
// token field and the session's idle expiry.
//
// The refresh token field is present and empty rather than absent, so a client
// written against this document does not have to be changed when a capability
// that issues refresh tokens starts filling it.
func writeLoginResult(ex *Exchange, result LoginResult) error {
	body := loginDocument{AccessToken: result.Token}
	if result.Session != nil {
		body.ValidUntil = result.Session.IdleExpiresAt
	}

	return writeSuccessDocument(ex, body)
}

// writeSuccessDocument is the framing every built-in responder answers a
// success with: the document as JSON, with the content type and 200 that go
// with it. The responders differ in the document they build and in nothing
// else, so they share this and cannot drift apart in how they write it.
func writeSuccessDocument(ex *Exchange, body any) error {
	//nolint:gosec // G117: the access token is the document's purpose, not a leak of one
	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}

	ex.Writer.SetHeader("Content-Type", "application/json")
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
}
