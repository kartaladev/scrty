package httpsec

import (
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

//go:generate mockgen -destination=verifier_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/token Verifier
//go:generate mockgen -destination=userloader_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/identity UserLoader

// DefaultBearerScheme is the Authorization scheme bearer tokens are presented
// under when the consumer names none. It is matched without regard to case,
// as RFC 7235 requires of an authentication scheme.
const DefaultBearerScheme = "Bearer"

// bearerToken authenticates a token against a live session and a live user.
type bearerToken struct {
	verifier token.Verifier
	sessions *session.Sessions
	users    identity.UserLoader

	// log is the chain's logger, handed over by wire.
	log *slog.Logger

	// resolver is the resolution core the bearer joins once its token has
	// verified, built by wire over the bearer's own session manager and user
	// loader and the chain's engine, enforcer set and enrolment lifetime.
	resolver sessionResolver

	now func() time.Time

	scheme           string
	allowEmptyScheme bool
}

// wire takes the settings the chain resolved, once every option has been
// applied.
func (b *bearerToken) wire(c *Chain) {
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

// Intercept authenticates a bearer token against a live session and a live
// user.
//
// It sets no WWW-Authenticate header. What a refusal looks like on the wire is
// the consumer's error handling to decide, and a header written here would be
// one the consumer cannot take back.
//
// A token that fails verification is recorded at debug with the verifier's
// own text, kept on purpose: it names the check the token failed (expired,
// wrong signature, wrong audience), which is what an operator chasing a
// rejected client needs, and it is the library's protocol-failure text rather
// than a store's. Every other dependency failure is recorded by a fixed reason
// and its error's Go type, never its text, and a failed save of the session
// comes back behind fixed text, its error still matching through errors.Is and
// errors.As. A consumer who wants a store's full error logs it inside their
// own implementation.
func (b *bearerToken) Intercept(ex *Exchange, next Next) error {
	presented, ok := b.presented(ex.Request.Header("Authorization"))
	if !ok {
		return next(ex)
	}

	ctx := ex.Context()

	claims, err := b.verifier.Verify(ctx, presented)
	if err != nil {
		// Joined rather than wrapped: an operator's log records which check the
		// token failed, while a caller still matches the one uniform failure.
		// The cause reaches the record below, never the client.
		b.log.LogAttrs(ctx, slog.LevelDebug, msgBearerNotVerified,
			slog.String("error", err.Error())) //nolint:forbidigo // stated exception (design decision 6): token verification text at debug

		return errors.Join(authenticate.ErrAuthenticationFailed, err)
	}

	// The session identifier is the token's jti, which is how a token issued at
	// login finds the session it was issued for. The token's subject is the
	// username, which is what the user loader is keyed on.
	if err := b.resolver.resolve(ex, claims.ID(), lookupByUsername(claims.Subject())); err != nil {
		return err
	}

	return next(ex)
}

// presented reports the token an Authorization header carries, and whether this
// interceptor claims the header at all.
func (b *bearerToken) presented(header string) (string, bool) {
	return presentedCredential(header, b.scheme, b.allowEmptyScheme)
}

// presentedCredential reports the credential an Authorization header carries
// under scheme, and whether the header is claimed at all. Both bearer modes
// extract through it, so they claim exactly the same headers.
//
// The scheme is compared without regard to case, as RFC 7235 requires, which is
// deliberately unlike the exact match Basic authentication makes: a bearer
// credential's scheme is the one this chain issues credentials under, whereas
// "Basic" names a scheme whose neighbours share the header. A header naming the
// scheme with nothing after it is not claimed.
func presentedCredential(header, scheme string, allowEmptyScheme bool) (string, bool) {
	header = strings.TrimSpace(header)
	if header == "" {
		return "", false
	}

	got, rest, found := strings.Cut(header, " ")
	if !found {
		// A bare credential is indistinguishable from another scheme's opaque
		// token, so it is claimed only where the consumer said this header
		// carries nothing else.
		if allowEmptyScheme {
			return header, true
		}

		return "", false
	}

	if !strings.EqualFold(got, scheme) {
		return "", false
	}

	if presented := strings.TrimSpace(rest); presented != "" {
		return presented, true
	}

	return "", false
}

// msgBearerNotVerified reports a token that did not verify. It is at debug
// because a stream of expired tokens is ordinary traffic.
const msgBearerNotVerified = "httpsec: a bearer token did not verify" //nolint:gosec // G101: a log message naming what failed, not a credential

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
	Sessions *session.Sessions

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
//
// A token that fails verification is recorded at debug with the verifier's own
// text, kept on purpose: it is the library's own protocol-failure text, not a
// dependency's, and names the check the token failed (expired, wrong
// signature, wrong audience), which an operator chasing a rejected client
// needs. Every other dependency failure — an unreadable session, a failed
// save while marking a challenge — is recorded by a fixed reason and the
// error's Go type, never its text, and a failed save is returned wrapped in
// fixed library text, its error still matching through errors.Is and
// errors.As. A consumer who wants a store's full error logs it inside their
// own implementation of BearerTokenDeps.
func EnableBearerToken(d BearerTokenDeps, opts ...BearerTokenOption) Option {
	const option = "EnableBearerToken"

	return func(c *config) error {
		b := &bearerToken{
			verifier: d.Verifier,
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
		// The renewal endpoint may be enabled after this option, so it is
		// handed to the core once every option has been applied.
		c.wire(func(*Chain) { b.resolver.renewal = c.renewal })
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
