package httpsec

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/pkg/logsample"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

// SessionBearerDeps are the collaborators session-reference authentication is
// wired to.
//
// Both are required, and a missing or typed-nil field is refused when the
// chain is built.
type SessionBearerDeps struct {
	// Sessions loads the session the presented reference names. It looks the
	// session up by the reference's digest, and judges its deadlines and any
	// reuse of a superseded reference.
	Sessions *session.Sessions

	// Users reloads the session's user by the user reference the session
	// records (LoadByUserID), never by username, so the roles a request is
	// judged on are the ones the store holds now.
	Users identity.UserLoader
}

// sessionReferenceFlow names this flow's rate-limit buckets and sampler keys,
// so a source that exhausts its allowance of unknown references still has its
// own at every other endpoint.
const sessionReferenceFlow = "session-reference"

// The allowance a source gets before presented references stop being looked
// up. A live session spends nothing, and a client holding a stale reference
// retries a few times, so the count is generous and the window short.
const (
	defaultSessionReferenceFailureLimit  = 100
	defaultSessionReferenceFailureWindow = time.Minute
)

// SessionBearerOption configures session-reference authentication.
type SessionBearerOption func(*sessionBearer) error

// sessionBearer authenticates a session reference, the session's own
// identifier presented with no signed token around it, against a live session
// and a live user.
type sessionBearer struct {
	sessions *session.Sessions
	users    identity.UserLoader

	// resolver is the resolution core, built by wire over the bearer's own
	// session manager and user loader and the chain's engine, enforcer set and
	// enrolment lifetime: the same core the signed bearer joins.
	resolver sessionResolver

	now func() time.Time

	scheme string

	limiter ratelimit.Limiter
	guard   sourceGuard
	sampler *logsample.Sampler
	log     *slog.Logger
}

// wireSessionBearer settles the limiter and the source guard against the
// assembled configuration, once every option has been applied.
func (c *config) wireSessionBearer() error {
	return eachInterceptor(c, func(b *sessionBearer) error {
		guard, err := c.resolveSourceGuard("EnableSessionBearer", sessionReferenceFlow, b.limiter,
			defaultSessionReferenceFailureLimit, defaultSessionReferenceFailureWindow, c.refusalInterval)
		if err != nil {
			return err
		}

		b.guard = guard

		return nil
	})
}

// flushRefusalLogs reports what the source guard is holding back.
func (b *sessionBearer) flushRefusalLogs() error {
	if b.guard != nil {
		b.guard.Flush()
	}

	return nil
}

// wire takes the settings the chain resolved, once every option has been
// applied.
func (b *sessionBearer) wire(c *Chain) {
	b.sampler = c.sampler
	b.log = c.logger
	b.resolver = sessionResolver{
		sessions: b.sessions,
		users:    b.users,
		log:      c.logger,
		phase: perRequestPhase{
			engine:            c.engine,
			sessions:          b.sessions,
			enrolmentLifetime: c.enrolmentLifetime,
			enforced:          c.enforced,
			now:               b.now,
		},
	}
}

// Intercept authenticates a session reference against a live session and a
// live user.
//
// The source is checked first, before the value is even parsed, so a throttled
// scanner costs one bucket read. A value that cannot be a session identifier is
// then refused before the store is asked, so a stream of junk credentials costs
// no lookup. Every refusal of the presented reference (format, load, user
// reload) is recorded against the source; a policy decision about a valid
// session is not. A request with no claimed Authorization header never reaches
// the limiter. Everything after
// extraction is the resolution core the signed bearer also runs, so the two
// modes refuse identically.
func (b *sessionBearer) Intercept(ex *Exchange, next Next) error {
	presented, ok := presentedCredential(ex.Request.Header("Authorization"), b.scheme, false)
	if !ok {
		return next(ex)
	}

	ctx := ex.Context()

	src, err := sourceThrottled(ctx, b.guard, ex.Request.ClientIP(), sessionReferenceFlow,
		b.sampler, b.log, b.now())
	if err != nil {
		return ErrAuthenticationRequired
	}

	if !session.ValidIdentifier(presented) {
		recordSourceFailure(ctx, b.guard, src)

		return ErrAuthenticationRequired
	}

	if err := b.resolver.resolve(ex, presented, lookupBySessionUser()); err != nil {
		// Only a refusal of the reference itself is a failed guess. Once the
		// session and its user are resolved the caller is published, so an
		// error after that point is a policy decision about a valid session,
		// and counting it would let a policy misconfiguration lock out the
		// very clients it governs.
		if ex.Authentication == nil && errors.Is(err, ErrAuthenticationRequired) {
			recordSourceFailure(ctx, b.guard, src)
		}

		return err
	}

	if ex.renewal != "" {
		// A late credential let through to the renewal endpoint is judged
		// there, after the bearer has gone by, so the endpoint is left the
		// means to charge the source this request came from when it refuses
		// the credential.
		ex.chargeRenewal = func(ctx context.Context) { recordSourceFailure(ctx, b.guard, src) }
	}

	return next(ex)
}

// EnableSessionBearer authenticates session references at the bearer slot: the
// session's own identifier, presented in the Authorization header with no
// signed token around it.
//
// It is the opaque alternative to EnableBearerToken, and occupies the same
// slot. A chain runs one bearer mode, so enabling both is a configuration error
// from New. With this mode on, every endpoint on the chain that issues a
// credential (form login, magic link, federated login redemption, passwordless
// passkey login, second-factor verification, recovery completion) issues the
// session's identifier, and giving any of them a token generator is
// a configuration error from New too: a token it minted would not be accepted
// here.
//
// Unknown references are throttled per source: each refused reference counts
// against the client address, and a source past its allowance (by default 100
// per minute) is refused with ErrAuthenticationRequired before any lookup.
// WithSessionBearerLimiter replaces the limiter. A limiter that cannot answer
// refuses the request (fail closed), and behind a shared address every client
// counts against one allowance, so configure the framework's trusted-proxy
// setting so the real client address is used.
//
// Default: off; the signed-token bearer is the library's default mode. When
// enabled, the scheme is DefaultBearerScheme, matched without regard to case,
// exactly as EnableBearerToken matches it (WithSessionBearerScheme replaces
// it). Requests carrying another scheme, or no Authorization header, pass
// through untouched.
//
// For a claimed request it:
//
//  1. refuses with ErrAuthenticationRequired a value that is not a
//     well-formed session identifier (session.ValidIdentifier), before any
//     store lookup;
//  2. loads the session, which the store looks up by digest, refusing a
//     missing, expired or undecryptable one with ErrAuthenticationRequired,
//     and a superseded one presented after its renewal window with
//     ErrAuthenticationRequired joined to session.ErrReused, by which
//     time the manager has revoked the session's family;
//  3. reloads the user with LoadByUserID on the session's user reference,
//     never by username, refusing a missing user with
//     ErrAuthenticationRequired;
//  4. publishes the caller and the session, and runs the per-request policy
//     phase as EnableBearerToken does.
//
// Why opaque: revocation takes effect at the next request, because there is
// nothing to verify offline; it needs no signing keys; and the store keeps
// only a digest of the high-entropy identifier, so a digest lookup needs no
// constant-time comparison. The cost is one store read per request, which the
// signed-token bearer also pays.
func EnableSessionBearer(d SessionBearerDeps, opts ...SessionBearerOption) Option {
	const option = "EnableSessionBearer"

	return func(c *config) error {
		b := &sessionBearer{
			sessions: d.Sessions,
			users:    d.Users,
			now:      c.now,
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

		if c.sessionBearer {
			return newConfigError("%s was given twice; one chain has one bearer mode", option)
		}

		c.sessionBearer = true

		c.enable(option, func() error {
			if err := eachInterceptor(c, func(*bearerToken) error {
				return newConfigError("%s and EnableBearerToken are both enabled; one chain "+
					"has one bearer mode, and each would refuse the other's credentials", option)
			}); err != nil {
				return err
			}
			if err := requireDep(option, "session manager", d.Sessions); err != nil {
				return err
			}

			return requireDep(option, "user loader", d.Users)
		})

		c.useSessions(d.Sessions)
		c.wire(b.wire)
		// The renewal endpoint may be enabled after this option, so it is
		// handed to the core once every option has been applied.
		c.wire(func(*Chain) { b.resolver.renewal = c.renewal })
		c.register(b, OrderBearerToken)

		return nil
	}
}

// WithSessionBearerScheme presents session references under scheme instead.
//
// Default: DefaultBearerScheme. The scheme is matched without regard to case
// either way. An empty scheme is refused, because it would claim every
// Authorization header, including those of the schemes at neighbouring slots;
// so is a scheme holding a space, because a scheme is the one token before the
// credential.
func WithSessionBearerScheme(scheme string) SessionBearerOption {
	return func(b *sessionBearer) error {
		if strings.TrimSpace(scheme) == "" {
			return newConfigError("WithSessionBearerScheme was given no scheme, which would " +
				"claim every Authorization header")
		}

		if strings.ContainsAny(scheme, " \t") {
			return newConfigError("WithSessionBearerScheme was given %q, and a scheme is the one "+
				"token before the credential, so it can hold no space", scheme)
		}

		b.scheme = scheme

		return nil
	}
}

// checkTokenGenerator checks the token generator a credential-issuing endpoint
// was given against the chain's bearer mode. In the signed-token mode the
// generator is required, since it mints the only credential that mode
// accepts. In the session-reference mode it is refused, since a token it
// minted would not be accepted by this chain: the endpoint issues the
// session's identifier instead. field names where the generator was given.
func checkTokenGenerator(c *config, option, field string, g token.Generator) error {
	if !c.sessionBearer {
		return requireDep(option, "token generator", g)
	}

	if !nilcheck.IsNil(g) {
		return newConfigError("%s was given a token generator (%s), but EnableSessionBearer is "+
			"on, so the chain accepts only session references and would refuse every token it "+
			"minted; leave the generator out, and the endpoint issues the session reference", option, field)
	}

	return nil
}

// WithSessionBearerLimiter counts the unknown session references each source
// presents in l.
//
// Default: the chain's rate-limiter factory (WithRateLimiterFactory) under
// namespace "session-reference", or else an in-memory limiter of 100 failures
// per source per minute, used by this flow alone. A deployment running more
// than one replica supplies a factory or a limiter its replicas share, or the
// limit is per process and a scanner simply spreads its guesses.
//
// A source over its limit is refused with ErrAuthenticationRequired before the
// reference is parsed or looked up, so a throttled scanner costs one bucket
// read. A limiter that cannot answer, or a client address that cannot be
// attributed, refuses the request as well (fail closed): admitting it would
// lift every limit exactly when something is wrong.
//
// It counts refused references and nothing else: a malformed value, an unknown,
// expired or reused session, or a missing user. A live session spends nothing,
// a policy refusal of a valid session is not recorded, and a request carrying
// no claimed Authorization header never reaches the limiter.
//
// The source is the client address the adapter reports, so behind a shared
// address (a proxy or NAT) every client counts against one allowance. Configure
// the framework's trusted-proxy setting (gin's SetTrustedProxies, fiber's
// TrustedProxies) so the real client address is the one used. The flow's IPv6
// aggregate (WithIPv6Aggregate) is sized from l when l reports its policy
// (ratelimit.PolicyReporter), as for WithAPIKeyLimiter.
//
// A nil limiter, including an interface holding a nil pointer, is refused.
func WithSessionBearerLimiter(l ratelimit.Limiter) SessionBearerOption {
	return func(b *sessionBearer) error {
		if err := requireDep("WithSessionBearerLimiter", "limiter", l); err != nil {
			return err
		}

		b.limiter = l

		return nil
	}
}
