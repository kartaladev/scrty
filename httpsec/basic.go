package httpsec

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/pkg/logsample"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/ratelimit"
)

// DefaultBasicAuthRealm is the realm named in the WWW-Authenticate header when
// the consumer names none. It is deliberately uninformative: a realm is shown
// to whoever is being refused, and naming the system behind it tells a prober
// what they have found.
const DefaultBasicAuthRealm = "Restricted"

// basicPrefix is matched exactly, with its trailing space and its case.
//
// A case-insensitive match here would also claim headers meant for another
// scheme registered at a nearby slot, and this interceptor answers every header
// it claims — a header it claimed by mistake is a request refused rather than
// one passed on.
const basicPrefix = "Basic "

// basicAuth authenticates a Basic credential and establishes no session.
type basicAuth struct {
	authn    authenticate.Authenticator
	attempts policy.AttemptStore

	engine *policy.Engine
	log    *slog.Logger

	// enforced holds the challenge kinds something on the chain enforces,
	// handed over by wire; a raised kind outside it refuses the request.
	enforced map[policy.ChallengeKind]bool

	// limiter is the consumer's own (WithBasicAuthLimiter), and nil means the
	// password-login limiter the chain shares with form login.
	limiter ratelimit.Limiter

	// guard is the password-login source guard, settled at assembly
	// (wirePasswordLogin), and sampler the chain's, handed over by wire.
	guard   sourceGuard
	sampler *logsample.Sampler

	// flow is the flow guard was built under, so the records the seam writes
	// name the limiter that is answering.
	flow string

	// discloseLocks is the chain's WithLockDisclosure, settled at assembly.
	discloseLocks bool

	now func() time.Time

	realm string
}

// wire takes the settings the chain resolved, once every option has been
// applied.
func (b *basicAuth) wire(c *Chain) {
	b.engine = c.engine
	b.log = c.logger
	b.enforced = c.enforced
	b.sampler = c.sampler
}

// flushRefusalLogs reports what the source guard and the authenticator are
// holding back; an authenticator that keeps no refusal logs of its own has
// nothing to report.
func (b *basicAuth) flushRefusalLogs() {
	if b.guard != nil {
		b.guard.Flush()
	}

	if f, ok := b.authn.(authenticate.RefusalLogFlusher); ok {
		_ = f.FlushRefusalLogs() // documented never to fail: its reporter only logs
	}
}

// Intercept authenticates a Basic credential and establishes no session.
//
// Every refusal the status table answers 401 carries the challenge, set here,
// on the one way out, so no refusal path can miss it (RFC 9110 §15.5.2): a
// malformed header, a throttled source, a concealed lock, a wrong password, a
// pre-authentication deny or a stateless challenge alike. A refusal answered
// otherwise, such as a disclosed lock (429) or a deny answered 403, carries
// none. What the protected handler returns is its own, and is never
// challenged here.
func (b *basicAuth) Intercept(ex *Exchange, next Next) error {
	header := ex.Request.Header("Authorization")
	if !strings.HasPrefix(header, basicPrefix) {
		return next(ex)
	}

	auth, err := b.authenticate(ex, strings.TrimPrefix(header, basicPrefix))
	if err != nil {
		if StatusForError(err) == http.StatusUnauthorized {
			b.challenge(ex)
		}

		return err
	}

	ex.Authentication = auth
	ex.SetContext(WithCaller(ex.Context(), auth))

	return next(ex)
}

// authenticate judges the credential after the Basic prefix: the source guard,
// the pre-authentication phase, the authenticator and the stateless phase, in
// that order. It sets no header; Intercept challenges what it refuses.
func (b *basicAuth) authenticate(ex *Exchange, credential string) (*authenticate.Authentication, error) {
	ctx := ex.Context()
	now := b.now()

	username, password, ok := decodeBasic(credential)
	if !ok {
		// A malformed header is reported as a failed authentication, not as a
		// malformed request: telling the two apart tells a prober which of its
		// guesses was even parsed.
		return nil, authenticate.ErrAuthenticationFailed
	}

	// The source is checked only once the header has decoded, so a malformed
	// header spends nothing, and before the pre-authentication phase, as at
	// the login form. A throttled refusal is still a 401, and challenged like
	// one; a throttled response without the challenge would be singled out.
	src, err := sourceThrottled(ctx, b.guard, ex.Request.ClientIP(), b.flow,
		b.sampler, b.log, now)
	if err != nil {
		return nil, err
	}

	// Before the credential is checked, for the same reason as at the login
	// form: a locked account must not answer differently for a right guess.
	pre := evaluatePhase(ctx, b.engine, policy.PreAuthentication, &policy.Input{
		Username: username,
		Now:      now,
	})
	if err := refusePreAuthentication(pre, b.enforced); err != nil {
		if !errors.Is(err, lockout.ErrAccountLocked) {
			return nil, err
		}

		// A source hammering a locked account spends its own allowance.
		recordSourceFailure(ctx, b.guard, src)

		// Concealed, the lock is a 401 and challenged; disclosed, a 429,
		// which is not.
		return nil, refuseLocked(ctx, b.authn, b.discloseLocks,
			identity.NewUsernamePassword(username, password), err)
	}

	auth, err := b.authn.Authenticate(ctx, identity.NewUsernamePassword(username, password))
	if err != nil {
		// The record carries a fixed reason and the attempt store's error
		// type, never its text: a consumer who wants that detail logs it
		// inside their own policy.AttemptStore.
		// The client's cancellation is not passed on: a client that hangs up after
		// sending its guess must still be charged for it, and an attempt store
		// that honours cancellation would otherwise drop the failure. Reset is
		// different, and stays on the request's context: nobody is owed a
		// clearing the client did not wait for.
		if recErr := b.attempts.RecordFailure(context.WithoutCancel(ctx), username, now); recErr != nil {
			b.log.LogAttrs(ctx, slog.LevelError, msgAttemptNotRecorded,
				diag.Failure("attempt-store", recErr)...)
		}

		recordSourceFailure(ctx, b.guard, src)

		// The authenticator's own refusal, not a restatement of it: it already
		// carries no detail that would tell one refusal from another.
		return nil, err
	}

	// A proven password supersedes the guesses before it, as at the login
	// form: a Basic client's typos must not add up to a lock its owner keeps
	// hitting with the right password.
	if err := b.attempts.Reset(ctx, username); err != nil {
		b.log.LogAttrs(ctx, slog.LevelError, msgAttemptsNotReset,
			diag.Failure("attempt-store", err)...)
	}

	// Stateless: there is no later request in which this caller could answer a
	// challenge, so the phase decides outright and its challenge carries
	// nothing to come back to.
	d := evaluatePhase(ctx, b.engine, policy.StatelessAuthentication, postAuthenticationInput(
		auth.Principal, factor.Basic, username, auth.PasswordChangedAt, now))

	switch d.Outcome {
	case policy.Deny:
		return nil, policyDenyReason(d)
	case policy.Challenge:
		return nil, &ChallengeError{Kind: d.Challenge}
	case policy.Allow:
	}

	return auth, nil
}

// decodeBasic reads the user-id and password out of the credential.
//
// Standard base64 with padding, and the first colon separates: a password may
// itself hold colons, and cutting at the last one would refuse a password the
// user actually set.
func decodeBasic(credential string) (username string, password []byte, ok bool) {
	decoded, err := base64.StdEncoding.DecodeString(credential)
	if err != nil {
		return "", nil, false
	}

	name, secret, found := bytes.Cut(decoded, []byte(":"))
	if !found {
		return "", nil, false
	}

	return string(name), secret, true
}

// challenge names the realm a client is being asked to answer for.
//
// It is set before the refusal is returned, so the consumer's error handling —
// which writes a status and, by default, no body — still sends it.
func (b *basicAuth) challenge(ex *Exchange) {
	ex.Writer.SetHeader("WWW-Authenticate", fmt.Sprintf("Basic realm=%q", b.realm))
}

// BasicAuthDeps are the collaborators Basic authentication is wired to.
//
// Both are required. There is no session manager and no token generator here:
// Basic authentication establishes neither, and a dependency it never uses
// would suggest otherwise.
type BasicAuthDeps struct {
	// Authenticator judges the decoded credentials.
	Authenticator authenticate.Authenticator

	// Attempts is where a refused credential is recorded. Supply the
	// account-lockout policy's own view, lockout.Attempts(): it records into
	// the store the policy reads, and it is what reports lockout transitions
	// to an observer the policy was given. A bare store the policy also reads
	// locks just the same, but nothing recorded through it is reported. A
	// password guessed at over Basic counts towards the same lockout as one
	// guessed at over the login form. A successful authentication clears the
	// username's failures through it, as form login does.
	//
	// When the policy has a consecutive-failure cap (lockout.WithCap),
	// its view is required: only the view advances the consecutive count, so
	// any other store here, the policy's own bare store included, fails New
	// with a configuration error naming this field. That check covers only
	// the policies registered in the engine before New runs: a capped policy
	// added later is not checked, and its view must still be what this login
	// records into.
	Attempts policy.AttemptStore
}

// BasicAuthOption configures Basic authentication.
type BasicAuthOption func(*basicAuth) error

// EnableBasicAuth authenticates Basic credentials at the Basic slot.
//
// A chain has one Basic authentication. A second EnableBasicAuth is refused
// with a configuration error naming the option, whatever realm or limiter it
// carries.
//
// Default: the realm DefaultBasicAuthRealm, named in the WWW-Authenticate
// header a refusal carries. Requests whose Authorization header does not start
// with the exact prefix "Basic " pass through untouched.
//
// Basic authentication is stateless: it opens no session and issues no token,
// so a caller presents its credential on every request and has nothing to come
// back to. That is why a challenge raised here decides outright.
//
// A claimed header is answered in this order, and each step refuses before the
// next runs:
//
//  1. Decode the credential. A header that is not valid base64, or has no
//     colon, is refused as a failed authentication, and spends nothing.
//  2. Check the source against the password-login guard, shared with
//     EnableFormLogin: 50 failures per source in 15 minutes by default
//     (WithBasicAuthLimiter). A throttled or unattributable source is
//     refused before any policy or password work.
//  3. Run the pre-authentication policy phase. A deny refuses with its
//     reason, except a locked account, which by default is refused as a
//     wrong password after a decoy password verification (WithLockDisclosure)
//     and counts against the source.
//  4. Authenticate. A failure is recorded against the account and the source.
//     A success clears the username's failures through BasicAuthDeps.Attempts,
//     as form login does, including its count towards a cap set with
//     lockout.WithCap; a store that fails to clear is logged and the
//     request still succeeds. It costs one reset of the attempt store per
//     successful request; for a policy with a cap that reset clears both the
//     failure log and the consecutive count.
//  5. Run the stateless-authentication phase, and continue with the caller
//     published.
//
// Every refusal StatusForError answers 401 carries the WWW-Authenticate
// challenge for the realm, throttled, concealed-lock, pre-authentication and
// stateless-challenge refusals included, and no refusal answered otherwise
// does: a lock disclosed with WithLockDisclosure is a 429, and a deny answered
// 403 carries none.
func EnableBasicAuth(d BasicAuthDeps, opts ...BasicAuthOption) Option {
	const option = "EnableBasicAuth"

	return func(c *config) error {
		b := &basicAuth{
			authn:    d.Authenticator,
			attempts: d.Attempts,
			now:      c.now,
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

		if err := eachInterceptor(c, func(*basicAuth) error {
			return newConfigError("%s was given twice; one chain has one Basic authentication", option)
		}); err != nil {
			return err
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

// WithBasicAuthLimiter counts Basic authentication's failures against l, by
// source, instead of the password-login limiter Basic shares with form login.
//
// Default: one limiter shared by Basic and form login, built from the chain's
// factory (WithRateLimiterFactory, or the in-memory default) under the
// namespace "password-login", allowing 50 failures per source in 15 minutes.
// Sharing it means a source spraying passwords across both endpoints spends
// one allowance. With this option Basic counts against l alone, under the flow
// "password-login-basic", and form login keeps the shared default unless it is
// given its own (WithLoginLimiter). The limit and window are l's own.
//
// The flow is the endpoint's own so that nothing is shared with form login: its
// IPv6 aggregate (WithIPv6Aggregate) is built under the namespace
// "password-login-basic-ipv6-aggregate", and a factory that refuses one
// namespace with two policies builds the chain all the same. That aggregate is
// sized from l's own
// policy, the multiplier times the limit and window l reports through
// ratelimit.PolicyReporter, as the memory limiter does. A limiter that reports
// none gets no default aggregate and one warning at construction naming
// EnableBasicAuth; an explicit WithIPv6Aggregate refuses it with a
// configuration error, and WithoutIPv6Aggregate silences the warning.
//
// A nil limiter, or a typed nil, is refused: it would read as "no limit"
// while the consumer believed one was set.
func WithBasicAuthLimiter(l ratelimit.Limiter) BasicAuthOption {
	return func(b *basicAuth) error {
		if err := requireDep("WithBasicAuthLimiter", "limiter", l); err != nil {
			return err
		}

		b.limiter = l

		return nil
	}
}

// unquotableInRealm reports a rune that must not reach a quoted header value.
func unquotableInRealm(r rune) bool {
	return r == '"' || r == '\\' || r < ' ' || r == 0x7f
}
