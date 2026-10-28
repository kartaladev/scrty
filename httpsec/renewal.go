package httpsec

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

// DefaultSessionRenewalPath is where EnableSessionRenewal answers when the
// consumer names no path (WithRenewalPath).
const DefaultSessionRenewalPath = "/session/renewal"

// defaultRenewalGrace is how long a renewed credential keeps working after its
// renewal when the consumer chooses no grace (WithRenewalGrace): the session
// package's default, so the two cannot drift apart.
const defaultRenewalGrace = session.DefaultRenewalGrace

const (
	// sessionRenewalFlow names the limiter the chain builds for renewals.
	sessionRenewalFlow = "session-renewal"

	// defaultRenewalLimit is how many renewals one session family may make in
	// defaultRenewalWindow before further ones are refused.
	defaultRenewalLimit = 10

	// defaultRenewalWindow is the sliding window defaultRenewalLimit counts in.
	defaultRenewalWindow = 10 * time.Minute
)

// SessionRenewalDeps are the collaborators the renewal endpoint is wired to.
//
// Users is required, and Sessions is optional. Tokens is required in the signed-token
// mode and refused in the session-reference mode (EnableSessionBearer), as
// for every endpoint that issues a credential; a missing or typed-nil
// required field is refused when the chain is built.
type SessionRenewalDeps struct {
	// Sessions rotates the renewed session (session.Sessions.RotateWithGrace),
	// and loads a late one under unused-successor recovery
	// (session.Sessions.LoadForRenewal).
	//
	// Default: the manager the chain's bearer resolves sessions through,
	// whichever bearer mode is enabled and in whatever option order. Given
	// explicitly, it must be that same manager (compared by pointer): any
	// other is refused with a configuration error naming
	// SessionRenewalDeps.Sessions, because a successor written through a
	// manager the bearer does not read could never be presented. When no
	// bearer is enabled there is nothing to default to, so a nil Sessions is
	// refused as a missing session manager, and an explicit one is accepted.
	Sessions *session.Sessions

	// Users reloads the session's user by the user reference the session
	// records (LoadByUserID), never by username, before anything is rotated.
	Users identity.UserLoader

	// Tokens mints the successor's credential in the signed-token mode. Leave
	// it nil when EnableSessionBearer is on: the credential is then the
	// successor's own identifier.
	Tokens token.Generator
}

// SessionRenewalOption configures the renewal endpoint.
type SessionRenewalOption func(*sessionRenewal) error

// RenewalResult is what a successful renewal hands its responder.
type RenewalResult struct {
	// Credential is the successor's credential: a signed token from
	// SessionRenewalDeps.Tokens, or, with EnableSessionBearer on, the
	// successor's own identifier. It is the only credential the result
	// carries; the renewed one is never handed over.
	Credential string

	// Session is the successor, as stored.
	Session *session.Session

	// User is the session's user, reloaded by its user reference.
	User *identity.Details

	// Kind is the kind of renewal performed: a fresh rotation, a re-rotation
	// inside the grace window, or a recovery while the successor was unused.
	Kind session.RenewalKind
}

// RenewalResponder writes the response to a successful renewal.
//
// With none supplied, the library writes the login endpoint's default JSON
// document carrying the successor's credential and validity, with 200 and
// Cache-Control: no-store; WithRenewalResponder replaces it. It is called
// instead of the downstream handler, because the renewal endpoint is the
// library's own. The successor already exists when it runs, so an error it
// returns leaves the chain as the request's refusal while the client still
// holds only the renewed credential, which it may present again inside the
// grace window to be re-rotated.
type RenewalResponder func(ex *Exchange, r RenewalResult) error

// sessionRenewal answers POST on its path by rotating the request's session
// with a grace window, and passes everything else through.
type sessionRenewal struct {
	sessions *session.Sessions
	users    identity.UserLoader
	tokens   token.Generator

	// issue issues the successor's credential as the chain's bearer mode
	// decides, handed over at assembly (config.credentialIssuer).
	issue credentialIssuer

	// engine is the chain's policy engine, handed over at assembly, which
	// judges a session a late renewal recovers.
	engine *policy.Engine

	now func() time.Time

	// limiter counts renewals per session family, from the consumer
	// (WithRenewalLimiter) or built from the chain's factory at assembly.
	limiter ratelimit.Limiter
	logger  *slog.Logger

	path    string
	grace   time.Duration
	respond RenewalResponder

	// lifetime chooses the successor's absolute lifetime, and nil carries the
	// predecessor's deadline over.
	lifetime func(*Exchange, *session.Session) time.Duration
}

// answers reports whether r is a renewal: POST on exactly the endpoint's path.
// A renewal changes state, so a link or a prefetch never triggers one.
func (r *sessionRenewal) answers(req Request) bool {
	return req.Method() == http.MethodPost && req.Path() == r.path
}

// Intercept renews the request's session on a renewal, and passes everything
// else through.
func (r *sessionRenewal) Intercept(ex *Exchange, next Next) error {
	if !r.answers(ex.Request) {
		return next(ex)
	}

	ctx := ex.Context()

	s, err := r.renewing(ex)
	if err != nil {
		return err
	}

	// The user is reloaded before anything is rotated, so a removed user is
	// refused without a successor being written.
	details, principal, err := r.user(ctx, s)
	if err != nil {
		return err
	}

	if ex.renewal != "" {
		// A late renewal reached here with nothing published, so neither the
		// per-request phase nor the gates judged it.
		if err := r.judgeLate(ctx, s, details, principal); err != nil {
			return err
		}
	}

	// The limit is asked after the session is known, so a recovery pass-through
	// is counted like any renewal, and before anything is rotated, so a refusal
	// writes nothing.
	key := "family:" + s.FamilyID.String()
	if err := r.admit(ctx, key); err != nil {
		return err
	}

	successor, kind, err := r.sessions.RotateWithGrace(ctx, s, r.grace, r.rotateOptions(ex, s)...)
	if err != nil {
		return renewalRefusal(err)
	}

	credential, err := r.issue(ctx, successor, principal)
	if err != nil {
		return err
	}

	return r.respond(ex, RenewalResult{Credential: credential, Session: successor, User: details, Kind: kind})
}

// admit refuses a renewal of a family that is over its limit, and fails closed
// when the limiter cannot answer. Every attempt that goes on to rotation is
// then charged, success or refusal, so retries and re-rotations count. The
// charge outlives a client that hangs up.
func (r *sessionRenewal) admit(ctx context.Context, key string) error {
	exceeded, err := r.limiter.Exceeded(ctx, key)
	if err != nil {
		r.logger.WarnContext(ctx, "the renewal limiter could not answer; the renewal is refused")

		return ErrRenewalThrottled
	}

	if exceeded {
		return ErrRenewalThrottled
	}

	if err := r.limiter.RecordFailure(context.WithoutCancel(ctx), key); err != nil {
		r.logger.WarnContext(ctx, "the renewal limiter could not record a renewal")
	}

	return nil
}

// rotateOptions are the rotation options the consumer's lifetime function asks
// for: none when there is no function or it returns zero or less, which
// carries the deadline over.
func (r *sessionRenewal) rotateOptions(ex *Exchange, s *session.Session) []session.RotateOption {
	if r.lifetime == nil {
		return nil
	}

	if d := r.lifetime(ex, s); d > 0 {
		return []session.RotateOption{session.WithSuccessorLifetime(d)}
	}

	return nil
}

// renewing is the session this request renews: the one the chain resolved
// and published, or, under unused-successor recovery, the late one the
// resolution core let through for this endpoint alone, loaded for renewal.
func (r *sessionRenewal) renewing(ex *Exchange) (*session.Session, error) {
	if ex.Session != nil && ex.Authentication != nil && ex.Authentication.Principal != nil {
		return ex.Session, nil
	}

	if ex.renewal == "" {
		return nil, ErrAuthenticationRequired
	}

	s, err := r.sessions.LoadForRenewal(ex.Context(), ex.renewal)
	if err != nil {
		refusal := renewalRefusal(err)

		// A late credential the load refuses as expired, not found or reused is
		// a failed guess like a refused reference at the bearer, and is counted
		// against its source. A lost race or a store fault is not.
		if ex.chargeRenewal != nil && errors.Is(refusal, ErrAuthenticationRequired) {
			ex.chargeRenewal(ex.Context())
		}

		return nil, refusal
	}

	return s, nil
}

// user reloads s's user by the reference s records, and refuses unless it is
// that user and active (ownActiveUser). A late renewal reaches here without
// the resolution core having checked either, so the check is made here too.
func (r *sessionRenewal) user(ctx context.Context, s *session.Session) (*identity.Details, *identity.Principal, error) {
	details, err := r.users.LoadByUserID(ctx, s.UserID)
	if err != nil {
		return nil, nil, ErrAuthenticationRequired
	}

	if err := ownActiveUser(s, details); err != nil {
		return nil, nil, err
	}

	return details, identity.PrincipalFromDetails(details), nil
}

// judgeLate judges a session a late renewal is about to recover, which no gate
// and no per-request phase has seen, since the resolution core published
// nothing for it.
//
// A session in a confined state (owing a second factor, confined to enrolment
// or to an account recovery, or owing a password change) is refused: its gate
// would have refused the renewal, and recovering it must not do what renewing
// it could not. The per-request phase is evaluated without marking anything,
// and anything but an allow refuses: a denial with the policy's reason, and a
// challenge with ErrAuthenticationRequired, since there is no published
// session for a gate to resolve it on.
func (r *sessionRenewal) judgeLate(
	ctx context.Context,
	s *session.Session,
	details *identity.Details,
	p *identity.Principal,
) error {
	switch s.MFA {
	case session.MFAPending, session.MFAEnrolmentPending, session.MFARecoveryPending:
		return ErrAuthenticationRequired
	case session.MFANone, session.MFASatisfied:
	}

	if s.PasswordChangePending {
		return ErrAuthenticationRequired
	}

	d := evaluatePhase(ctx, r.engine, policy.PerRequest, &policy.Input{
		User:               p.ID,
		Username:           p.Username,
		Principal:          p,
		Session:            s,
		FirstFactor:        s.FirstFactor,
		MFASatisfied:       s.MFA == session.MFASatisfied,
		PasswordChangedAt:  details.PasswordChangedAt,
		FederatedAssurance: sessionFederatedAssurance(s),
		Now:                r.now(),
	})

	switch d.Outcome {
	case policy.Deny:
		return policyDenyReason(d)
	case policy.Challenge:
		return ErrAuthenticationRequired
	case policy.Allow:
	}

	return nil
}

// renewalRefusal is the refusal a failed load or rotation answers with.
//
// Reuse stays identifiable beside ErrAuthenticationRequired, so a consumer
// that rolls its request transaction back on a refusal can tell this is the
// one it must commit. A lost race is ErrSessionRenewalConflict, a 409, so the
// client retries with the credential it holds. A missing or ended session is
// ErrAuthenticationRequired, as at the bearer. Anything else is the manager's
// error, already behind fixed text.
func renewalRefusal(err error) error {
	switch {
	case errors.Is(err, session.ErrReused):
		return errors.Join(ErrAuthenticationRequired, err)
	case errors.Is(err, session.ErrRenewalConflict):
		return ErrSessionRenewalConflict
	case errors.Is(err, session.ErrNotFound),
		errors.Is(err, session.ErrExpired),
		errors.Is(err, session.ErrUnreadable):
		return ErrAuthenticationRequired
	default:
		return err
	}
}

// writeRenewalResult is the response a renewal succeeds with when the
// consumer supplies none: the login endpoint's default document, carrying the
// successor's credential and idle expiry, never cached.
func writeRenewalResult(ex *Exchange, r RenewalResult) error {
	ex.Writer.SetHeader("Cache-Control", "no-store")

	return writeLoginResult(ex, LoginResult{Token: r.Credential, Session: r.Session})
}

// EnableSessionRenewal answers session renewals: a POST on
// DefaultSessionRenewalPath by a request carrying a session rotates that
// session into a successor in the same family, with a grace window during
// which the renewed credential still works, and answers with the successor's
// credential.
//
// Default: off. When enabled, the path is DefaultSessionRenewalPath
// (WithRenewalPath replaces it), the grace window is 30 seconds
// (WithRenewalGrace), and the response is the login endpoint's default JSON
// document carrying the successor's credential, with 200 and
// Cache-Control: no-store (WithRenewalResponder). Every other request,
// including any other method on the path, passes through untouched. The
// successor carries its predecessor's absolute deadline over, unless
// WithRenewalLifetime chooses a new lifetime, which the manager's lifetime and
// family maxima bound.
//
// For a renewal it:
//
//  1. refuses a request with no authentication result or no session with
//     ErrAuthenticationRequired;
//  2. reloads the session's user with LoadByUserID, refusing a missing one
//     with ErrAuthenticationRequired;
//  3. rotates the session with session.Sessions.RotateWithGrace. A
//     credential renewed again inside its window is re-rotated
//     (session.RenewalReRotation), so a client that lost a renewal response
//     can retry with the credential it holds. A lost race with a concurrent
//     renewal of the same session is refused with ErrSessionRenewalConflict,
//     a 409, and the client retries with the credential it holds. A renewed
//     credential presented after its window is reuse: the manager revokes the
//     session's whole family, and the refusal is ErrAuthenticationRequired
//     joined to session.ErrReused;
//  4. issues the successor's credential through the chain's bearer mode: the
//     successor's identifier with EnableSessionBearer on, and a token from
//     SessionRenewalDeps.Tokens otherwise;
//  5. hands the result to the responder.
//
// The endpoint sits inside bearer authentication and inside every gate that
// confines a session, so a session owing a second factor, confined to
// enrolment or to an account recovery, or owing a password change, is refused
// by its gate before it can renew.
//
// # Unused-successor recovery
//
// With session.WithUnusedSuccessorRecovery on the manager, a renewed
// credential presented after its window by an ordinary request is refused
// with ErrAuthenticationRequired (it matches session.ErrRenewalRequired)
// and nothing is revoked. The same credential posted to this endpoint is let
// through the bearer to the endpoint alone, publishing no caller and no
// session, so nothing between the bearer and the endpoint, and no handler,
// sees it authenticated. The endpoint then loads it with
// session.Sessions.LoadForRenewal, refuses a confined session and anything the
// per-request policy phase does not allow, and rotates it: while its successor
// was never presented it is recovered (session.RenewalRecovery); otherwise it
// is reuse, refused as above with the family revoked.
//
// A renewal reaching the endpoint this way is anonymous to every interceptor
// between the bearer and the endpoint, so a consumer gate that judges the
// authenticated caller does not see it; the endpoint's own checks above are
// what stand in for it.
//
// # Renewal limit
//
// Renewals are counted per session family, not per source or per user: a
// family may renew 10 times in a sliding 10 minutes, and the eleventh is
// refused with ErrRenewalThrottled, a 429, with nothing rotated. The count is
// of renewals, not of failures: every attempt that reaches rotation is
// charged, re-rotations and refused attempts included. Keyed by family, it
// cannot throttle another user, or the same user's other sign-ins. A limiter
// that cannot answer refuses the renewal. WithRenewalLimiter replaces the
// limiter and with it the limit and the window.
//
// Clients that share one credential across tabs should serialise their
// renewals. A second renewal inside the grace window re-rotates, which
// knocks out the successor the first tab already holds, and that tab's next
// request is then reuse.
//
// # Clients
//
// A client switches to the successor's credential as soon as the renewal
// returns, and retries any request it queued meanwhile with it. The renewed
// credential works only for the grace window, and presenting it after the
// window is treated as theft: the whole family, the successor included, is
// revoked.
//
// # Transactions
//
// The family revocation on reuse is a store write, and like every store write
// joins a transaction the consumer attached to the request's context. A
// consumer that rolls its request transaction back on a refusal must commit
// when errors.Is(err, session.ErrReused), or it rolls the revocation
// back and leaves the stolen family alive.
func EnableSessionRenewal(d SessionRenewalDeps, opts ...SessionRenewalOption) Option {
	const option = "EnableSessionRenewal"

	return func(c *config) error {
		r := &sessionRenewal{
			sessions: d.Sessions,
			users:    d.Users,
			tokens:   d.Tokens,
			now:      c.now,
			path:     DefaultSessionRenewalPath,
			grace:    defaultRenewalGrace,
			respond:  writeRenewalResult,
		}

		for _, opt := range opts {
			if opt == nil {
				continue
			}
			if err := opt(r); err != nil {
				return err
			}
		}

		if c.renewal != nil {
			return newConfigError("%s was given twice; one chain has one renewal endpoint", option)
		}

		c.renewal = r

		c.enable(option, func() error {
			if err := r.resolveSessions(c, option, d.Sessions); err != nil {
				return err
			}
			if err := requireDep(option, "user loader", d.Users); err != nil {
				return err
			}
			if c.logoutPath != "" && c.logoutPath == r.path {
				return newConfigError("%s's path %q is the logout path, so a POST there would "+
					"renew the session it meant to end", option, r.path)
			}

			limiter, err := c.flowLimiter(option, r.limiter, sessionRenewalFlow, defaultRenewalLimit,
				defaultRenewalWindow)
			if err != nil {
				return err
			}

			r.limiter = limiter

			return checkTokenGenerator(c, option, "SessionRenewalDeps.Tokens", d.Tokens)
		})

		c.useSessions(d.Sessions)
		// The bearer mode may be enabled after this option, so the issuer is
		// chosen once every option has been applied.
		c.wire(func(ch *Chain) {
			r.issue = c.credentialIssuer(r.tokens)
			r.engine = ch.engine
			r.logger = c.logger
		})
		c.register(r, OrderSessionRenewal)

		return nil
	}
}

// bearerSessions is the session manager the chain's bearer resolves sessions
// through, whichever bearer mode is enabled, or nil when neither is. The
// bearer may be enabled after the renewal endpoint, so it is read once every
// option has been applied.
func bearerSessions(c *config) *session.Sessions {
	var m *session.Sessions

	_ = eachInterceptor(c, func(b *sessionBearer) error {
		m = b.sessions

		return nil
	})
	_ = eachInterceptor(c, func(b *bearerToken) error {
		m = b.sessions

		return nil
	})

	return m
}

// resolveSessions settles the manager the endpoint rotates through: the
// bearer's when none was given, and only the bearer's when one was, since a
// renewal that rotated through another manager would write a successor the
// bearer cannot find.
func (r *sessionRenewal) resolveSessions(c *config, option string, given *session.Sessions) error {
	bearer := bearerSessions(c)

	if given == nil {
		if bearer == nil {
			// With no bearer there is nothing to default to, and no
			// authenticator would publish the session this endpoint renews.
			return requireDep(option, "session manager", given)
		}

		r.sessions = bearer

		return nil
	}

	if bearer != nil && bearer != given {
		return newConfigError("%s was given a SessionRenewalDeps.Sessions other than the manager "+
			"the bearer resolves sessions through, so a renewal would write a successor the bearer "+
			"cannot find; leave SessionRenewalDeps.Sessions nil to use the bearer's", option)
	}

	r.sessions = given

	return nil
}

// WithRenewalLimiter replaces the limiter that counts renewals per session
// family.
//
// Default: a limiter the chain builds from its rate-limiter factory
// (WithRateLimiterFactory, in memory when none is given) under the flow name
// "session-renewal", allowing 10 renewals per family in a sliding 10 minutes.
// A consumer supplies its own to share the count across replicas or to choose
// another limit; the chain keys it by "family:" followed by the family
// identifier, asks it before every renewal, and charges it once per attempt
// that goes on to rotation. A limiter that returns an error refuses the
// renewal with ErrRenewalThrottled rather than lifting the limit. A nil
// limiter is refused when the chain is built.
func WithRenewalLimiter(l ratelimit.Limiter) SessionRenewalOption {
	return func(r *sessionRenewal) error {
		if err := requireDep("WithRenewalLimiter", "limiter", l); err != nil {
			return err
		}

		r.limiter = l

		return nil
	}
}

// WithRenewalPath answers renewals on path instead.
//
// Default: DefaultSessionRenewalPath. An empty path is refused, because it
// would answer nothing; so is the logout path, when the chain is built. A
// client that renews posts to the path chosen here, so change it on both sides.
func WithRenewalPath(path string) SessionRenewalOption {
	return func(r *sessionRenewal) error {
		if path == "" {
			return newConfigError("WithRenewalPath was given no path, so the renewal endpoint " +
				"would answer nothing")
		}

		r.path = path

		return nil
	}
}

// WithRenewalGrace keeps a renewed credential working for d after its
// renewal, in place of the default 30 seconds.
//
// The window covers requests already in flight with the renewed credential,
// and a client retrying a renewal whose response it lost. It is also the time
// in which a stolen credential works as well as the real one, so it is
// bounded: a d below 0 or above session.MaxRenewalGrace (inclusive) is
// refused with a configuration error. A d of 0 ends the window at once.
//
// A renewed credential presented after its window is reuse: the manager
// revokes the session's whole family. That revocation is a store write, so a
// consumer that rolls its request transaction back on a refusal must commit
// when errors.Is(err, session.ErrReused) (see EnableSessionRenewal).
// Clients should switch to the successor as soon as renewal returns, and retry
// the requests they queued with it, so they rarely need the window at all.
func WithRenewalGrace(d time.Duration) SessionRenewalOption {
	return func(r *sessionRenewal) error {
		if d < 0 || d > session.MaxRenewalGrace {
			return newConfigError("WithRenewalGrace was given %s, outside 0 to %s: the window is "+
				"time in which a stolen credential also works", d, session.MaxRenewalGrace)
		}

		r.grace = d

		return nil
	}
}

// WithRenewalResponder replaces the response written when a renewal succeeds.
//
// Default: the login endpoint's default JSON document carrying the
// successor's credential and validity, with 200 and Cache-Control: no-store.
// A consumer renders its own envelope here, and may write an audit record
// inside its own transaction. A responder that writes the credential should
// forbid caching it too. A nil function is refused. The result carries the
// successor's credential, never the renewed one, and a client should switch to
// it as soon as the response arrives.
func WithRenewalResponder(fn RenewalResponder) SessionRenewalOption {
	return func(r *sessionRenewal) error {
		if fn == nil {
			return newConfigError("WithRenewalResponder was given no function; omit the option " +
				"to keep the default document")
		}

		r.respond = fn

		return nil
	}
}

// WithRenewalLifetime lets fn choose the absolute lifetime of the successor
// each renewal writes, given the exchange and the session being renewed.
//
// Default: with no option, or when fn returns zero or less, the successor
// carries its predecessor's absolute deadline over, so renewing extends only
// the idle deadline and a session never outlives the lifetime it was created
// with. A positive d gives the successor a deadline of now plus d
// (session.WithSuccessorLifetime), which is how a consumer lets an active
// client stay signed in for longer than the original lifetime.
//
// The manager holds the answer to its maxima. A d above the manager's lifetime
// maximum (session.WithMaxAbsoluteLifetime) is a wiring mistake: the renewal
// is refused with session.ErrConfig, a 500, and nothing is stored, so the
// client still holds a working credential. A deadline that would pass the
// family maximum (session.WithMaxFamilyLifetime) is cut to end exactly there:
// the family has run out, and the client signs in again. fn runs after the
// user is reloaded and before anything is rotated, and it must not block. A
// nil fn is refused when the chain is built.
func WithRenewalLifetime(fn func(*Exchange, *session.Session) time.Duration) SessionRenewalOption {
	return func(r *sessionRenewal) error {
		if fn == nil {
			return newConfigError("WithRenewalLifetime was given no function; omit the option " +
				"to carry the deadline over")
		}

		r.lifetime = fn

		return nil
	}
}
