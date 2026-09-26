package httpsec

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
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

	engine *policy.Engine
	log    *slog.Logger

	// enrolmentLifetime is how long a session marked for an enrolment
	// challenge may live, handed over by wire.
	enrolmentLifetime time.Duration

	// enforced holds the challenge kinds something on the chain enforces,
	// handed over by wire; a raised kind outside it refuses the request.
	enforced map[policy.ChallengeKind]bool

	now func() time.Time

	scheme           string
	allowEmptyScheme bool
}

// wire takes the settings the chain resolved, once every option has been
// applied.
func (b *bearerToken) wire(c *Chain) {
	b.engine = c.engine
	b.log = c.logger
	b.enrolmentLifetime = c.enrolmentLifetime
	b.enforced = c.enforced
}

// Intercept authenticates a bearer token against a live session and a live
// user.
//
// It sets no WWW-Authenticate header. What a refusal looks like on the wire is
// the consumer's error handling to decide, and a header written here would be
// one the consumer cannot take back.
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
			slog.String("error", err.Error()))

		return errors.Join(authenticate.ErrAuthenticationFailed, err)
	}

	// The session identifier is the token's jti, which is how a token issued at
	// login finds the session it was issued for.
	s, err := b.sessions.Load(ctx, claims.ID())
	if err != nil {
		if errors.Is(err, session.ErrSessionUnreadable) {
			// Visible to an operator, because it means a sealing key was
			// retired while sessions sealed under it were still live. The
			// caller is answered "log in again", because that is the remedy
			// and a 500 storm is not.
			b.log.LogAttrs(ctx, slog.LevelError, msgSessionUnreadable,
				slog.String("error", err.Error()))
		}

		// Missing, expired and unreadable are the same answer: telling them
		// apart would report whether a session ever existed.
		return ErrAuthenticationRequired
	}

	// Reloaded rather than taken from the token, so a role revoked a minute ago
	// is not honoured for the rest of the token's life. The token's subject is
	// the username, which is what the user loader is keyed on.
	details, err := b.users.LoadByUsername(ctx, claims.Subject())
	if err != nil {
		return ErrAuthenticationRequired
	}

	principal := identity.PrincipalFromDetails(details)
	if principal == nil {
		// A loader that reported no error and no user has told us nothing, and
		// a request judged on no principal is an anonymous one wearing a token.
		return ErrAuthenticationRequired
	}

	now := b.now()
	auth := &authenticate.Authentication{
		Principal:         principal,
		Time:              now,
		PasswordChangedAt: details.PasswordChangedAt,
	}

	ex.Authentication = auth
	ex.Session = s
	ctx = withSession(WithCaller(ctx, auth), s)
	ex.SetContext(ctx)

	d := evaluatePhase(ctx, b.engine, policy.PerRequest, &policy.Input{
		User:              principal.ID,
		Username:          principal.Username,
		Principal:         principal,
		Session:           s,
		FirstFactor:       s.FirstFactor,
		MFASatisfied:      s.MFA == session.MFASatisfied,
		PasswordChangedAt: details.PasswordChangedAt,
		Now:               now,
	})

	switch d.Outcome {
	case policy.Deny:
		return policyDenyReason(d)
	case policy.Challenge:
		// Marked and continued, not refused here: the gate for this challenge
		// enforces it at its own slot, and refusing at this one would also
		// block the very endpoint the caller must reach to resolve it.
		if err := b.markChallenge(ctx, s, d.Challenge); err != nil {
			return err
		}

		// A consumer kind has no field on the session to be marked in, so it
		// is recorded where the gate the consumer declared for it reads it.
		if _, builtIn := builtInEnforcers[d.Challenge]; !builtIn {
			ex.raised = d.Challenge
		}
	case policy.Allow:
	}

	return next(ex)
}

// markChallenge records a per-request challenge on s.
//
// A session entering the enrolment-only state is saved here, before the
// request goes on. That mark lowers the session's deadlines, and the gate that
// enforces it refuses the request at a slot outside the session-touch step, so
// a mark left for that step to persist would never be stored: the session
// would keep its full lifetime while it is confined. A session already in the
// state is not written again, since marking it changes nothing. A failed save
// refuses the request rather than serving it on an unrecorded mark.
//
// The other kinds are marked in memory only, as before: the per-request phase
// raises them again on every request, and they change no deadline.
//
// A kind nothing on the chain enforces is refused with a configuration error
// before anything is marked; see refuseUnenforced.
func (b *bearerToken) markChallenge(ctx context.Context, s *session.Session, kind policy.ChallengeKind) error {
	if err := refuseUnenforced(b.enforced, kind); err != nil {
		return err
	}

	entering := kind == policy.ChallengeMFAEnrolment && s.MFA != session.MFAEnrolmentPending

	challengeMarker{sessions: b.sessions, enrolmentLifetime: b.enrolmentLifetime}.mark(s, kind)

	if !entering {
		return nil
	}

	return b.sessions.Save(ctx, s)
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

// The records a bearer refusal is reported with. The verification cause is at
// debug because a stream of expired tokens is ordinary traffic; an unreadable
// session is at error because it is an outage of the deployment's own keys.
const (
	//nolint:gosec // G101: a log message naming what failed, not a credential
	msgBearerNotVerified = "httpsec: a bearer token did not verify"
	msgSessionUnreadable = "httpsec: a session could not be decrypted"
)
