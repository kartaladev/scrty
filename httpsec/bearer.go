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
	sessions *session.Manager
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
//
// The scheme is compared without regard to case, as RFC 7235 requires, which is
// deliberately unlike the exact match Basic authentication makes: a bearer
// token's scheme is the one this chain issues tokens under, whereas "Basic"
// names a scheme whose neighbours share the header.
func (b *bearerToken) presented(header string) (string, bool) {
	header = strings.TrimSpace(header)
	if header == "" {
		return "", false
	}

	scheme, rest, found := strings.Cut(header, " ")
	if !found {
		// A bare credential is indistinguishable from another scheme's opaque
		// token, so it is claimed only where the consumer said this header
		// carries nothing else.
		if b.allowEmptyScheme {
			return header, true
		}

		return "", false
	}

	if !strings.EqualFold(scheme, b.scheme) {
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
