package httpsec

import (
	"context"
	"time"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

//go:generate mockgen -destination=policy_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/policy Policy
//go:generate mockgen -destination=sessionstore_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/session Store
//go:generate mockgen -destination=tokengenerator_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/token Generator

// policyDenyReason is the error a deny is refused with.
//
// policy.Engine already guarantees a deny carries a reason, substituting
// policy.ErrPolicyDenied where the policy left it nil, so this is a named
// reader rather than a fallback: every deny site refuses with the reason the
// engine reduced to, and none of them returns nil for a refusal.
func policyDenyReason(d policy.Decision) error { return d.Reason }

// loginTailDeps is what the login tail needs to end a login.
type loginTailDeps struct {
	engine   *policy.Engine
	sessions *session.Manager
	tokens   token.Generator
}

// postAuthenticationInput builds the policy input for a login that has just
// succeeded.
//
// Every field is a parameter rather than a struct literal each caller fills in,
// so an interceptor cannot quietly omit one: a missing passwordChangedAt
// disables a password-age gate on that interceptor's path alone, which is
// exactly the kind of hole nobody notices. first is a factor.Kind rather than a
// string so it cannot be transposed with username, and the two times are
// adjacent so every call site's argument order is pinned by a test that fires
// the challenge.
//
// username is the identifier the caller submitted, which is not always the one
// the principal resolved to: a policy keying on what was typed must see what
// was typed.
func postAuthenticationInput(
	p *identity.Principal,
	first factor.Kind,
	username string,
	passwordChangedAt, now time.Time,
) *policy.Input {
	in := &policy.Input{
		Username:          username,
		Principal:         p,
		FirstFactor:       first,
		PasswordChangedAt: passwordChangedAt,
		Now:               now,
	}
	if p != nil {
		in.User = p.ID
	}

	return in
}

// WithCaller publishes an authentication result and the caller it resolved on a
// context derived from ctx.
//
// A consumer writing their own first factor calls this rather than
// authenticate.WithAuthentication, which publishes only the event. The two
// answer different questions: an interceptor asks what authenticated this
// request, while a guard and the consumer's own handler ask who the caller is.
// Publishing only the event leaves every guard reading
// identity.PrincipalFromContext refusing a caller the chain has just
// authenticated, and that refusal is indistinguishable from a missing
// credential. They are published together here so no call site — the library's
// own or a consumer's — can publish one without the other.
//
// The built-in first factors publish through it, so an interceptor a consumer
// registers is left holding nothing a built-in has.
//
// A nil authentication, or one carrying no principal, publishes nothing under
// the principal key, so a reader that checks is never handed an absence
// dressed as a caller. It derives rather than replaces: everything already on
// ctx, including an upstream request identifier and the client's cancellation,
// is still there.
func WithCaller(ctx context.Context, a *authenticate.Authentication) context.Context {
	ctx = authenticate.WithAuthentication(ctx, a)
	if a == nil || a.Principal == nil {
		return ctx
	}

	return identity.WithPrincipal(ctx, a.Principal)
}

// markChallengePending records on s that a challenge is owed, in the field the
// gate enforcing it reads.
//
// A kind this package does not know marks nothing, and the caller still refuses
// the request with the challenge: a challenge nothing can mark is one nothing
// can satisfy, and serving the request instead would let an unrecognised
// challenge read as an allow.
func markChallengePending(s *session.Session, kind policy.ChallengeKind) {
	switch kind {
	case policy.ChallengeMFA:
		s.MFA = session.MFAPending
	case policy.ChallengePasswordChange:
		s.PasswordChangePending = true
	case policy.ChallengeNone:
	}
}

// completeLogin is the tail every first factor shares: policy, session, token.
//
// It exists so a redemption flow added by another capability cannot end a login
// differently from form login — the same phase, the same marking and the same
// ordering guarantee, written once and reused rather than restated.
//
// It returns the token it issued alongside the challenge error, because a
// consumer prompting for a second factor needs the credential the prompt will
// be answered with.
//
// With no policy engine wired the phase allows, which is the documented default
// of WithPolicyEngine: a consumer who registers no policies rests on
// authentication alone rather than on a phase that refuses everything.
func completeLogin(ex *Exchange, deps loginTailDeps, in *policy.Input) (string, error) {
	ctx := ex.Context()

	d := policy.Decision{Outcome: policy.Allow}
	if deps.engine != nil {
		d = deps.engine.EvaluatePhase(ctx, policy.PostAuthentication, in)
	}

	if d.Outcome == policy.Deny {
		return "", policyDenyReason(d)
	}

	s, err := deps.sessions.Create(ctx, in.User, session.WithFirstFactor(in.FirstFactor))
	if err != nil {
		return "", err
	}

	if d.Outcome == policy.Challenge {
		// Marked and saved before the token exists. A token issued first would
		// be a credential for a session whose pending flag never persisted —
		// that is, one that answers requests as though the challenge had been
		// met.
		markChallengePending(s, d.Challenge)

		if err := deps.sessions.Save(ctx, s); err != nil {
			return "", err
		}
	}

	// The session identifier is the token's jti, which is how a later bearer
	// request finds the session the token was issued for.
	tok, err := deps.tokens.Generate(ctx, s.ID, in.Principal)
	if err != nil {
		return "", err
	}

	// Published on the challenge path too, so a consumer rendering the prompt
	// still reads who is being challenged.
	ex.Session = s
	ex.SetContext(withSession(WithCaller(ctx, ex.Authentication), s))

	if d.Outcome == policy.Challenge {
		return tok, &ChallengeError{Kind: d.Challenge, Session: s, Token: tok}
	}

	return tok, nil
}
