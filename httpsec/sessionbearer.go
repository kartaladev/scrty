package httpsec

import (
	"strings"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/nilcheck"
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
	Sessions *session.Manager

	// Users reloads the session's user by the user reference the session
	// records (LoadByUserID), never by username, so the roles a request is
	// judged on are the ones the store holds now.
	Users identity.UserLoader
}

// SessionBearerOption configures session-reference authentication.
type SessionBearerOption func(*sessionBearer) error

// sessionBearer authenticates a session reference, the session's own
// identifier presented with no signed token around it, against a live session
// and a live user.
type sessionBearer struct {
	sessions *session.Manager
	users    identity.UserLoader

	// resolver is the resolution core, built by wire over the bearer's own
	// session manager and user loader and the chain's engine, enforcer set and
	// enrolment lifetime: the same core the signed bearer joins.
	resolver sessionResolver

	now func() time.Time

	scheme string
}

// wire takes the settings the chain resolved, once every option has been
// applied.
func (b *sessionBearer) wire(c *Chain) {
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
// A value that cannot be a session identifier is refused before the store is
// asked, so a stream of junk credentials costs no lookup. Everything after
// extraction is the resolution core the signed bearer also runs, so the two
// modes refuse identically.
func (b *sessionBearer) Intercept(ex *Exchange, next Next) error {
	presented, ok := presentedCredential(ex.Request.Header("Authorization"), b.scheme, false)
	if !ok {
		return next(ex)
	}

	if !session.ValidIdentifier(presented) {
		return ErrAuthenticationRequired
	}

	if err := b.resolver.resolve(ex, presented, lookupBySessionUser()); err != nil {
		return err
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
//     ErrAuthenticationRequired joined to session.ErrSessionReused, by which
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
