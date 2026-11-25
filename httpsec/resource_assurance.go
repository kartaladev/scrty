package httpsec

import (
	"errors"
	"strings"
	"time"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/assurance"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/errwalk"
	"github.com/kartaladev/scrty/policy"
)

// accessTokenInput is the per-request policy input of an access-token caller p of kind, verified as
// vt. Its assurance is minted here, and only here: whether the caller names a local user, the
// provider grant's second-factor marker, and the federated evidence of the grant or the external
// token. A caller naming no local user carries no user reference, so neither the MFA requirement
// lookup nor any other policy can take its qualified identifier for a local user's.
func accessTokenInput(p *identity.Principal, kind factor.Kind, vt *verifiedToken, now time.Time) *policy.Input {
	in := &policy.Input{
		Principal:            p,
		Username:             p.Username,
		FirstFactor:          kind,
		Now:                  now,
		AccessTokenAssurance: assurance.NewAccessToken(!vt.external, vt.secondFactor),
		FederatedAssurance:   vt.evidence,
	}

	if !vt.external {
		in.User = p.ID
	}

	return in
}

// refuseInsufficient is the refusal of an access-token caller whose sign-in does not meet the MFA
// requirement: ErrInsufficientUserAuthentication, answered 401 with the one challenge naming
// insufficient_user_authentication, under the scheme refuse would choose. It carries no max_age: no
// window applies. It is not a verification refusal, so it is never counted against the throttle.
func (s *resourceServers) refuseInsufficient(underDPoP bool, src source) error {
	r := s.refuse(errors.Join(ErrInsufficientUserAuthentication, policy.ErrInsufficientUserAuthentication),
		underDPoP, src)

	var refusal *accessTokenRefusal
	if errors.As(r, &refusal) {
		refusal.code = codeInsufficientUserAuthentication
	}

	return r
}

// textAccessTokenPolicyFailed is the fixed text of a per-request policy that could not decide for an
// access-token caller, because a dependency it consults (the MFA requirement lookup, the
// federated-assurance source) failed.
const textAccessTokenPolicyFailed = "httpsec: the access token's caller could not be judged, " +
	"because a dependency of the per-request policy failed"

// policyRefusal answers a per-request deny of an access-token caller:
//
//   - a reason carrying a library-wrapped dependency failure (a *diag.Fault: the requirement lookup or
//     assurance source failed) is a dependency failure, answered 500 whatever the dependency's own
//     error wraps, so an outage never sends the client round a sign-in loop, and is never counted;
//   - a reason that is the requirement policy's insufficient-user-authentication denial is answered
//     with the RFC 9470 challenge;
//   - any other reason is returned as the policy gave it, as for any caller.
//
// A reason whose chain cannot be walked is a dependency failure too: what it says is not guessed.
func (s *resourceServers) policyRefusal(d policy.Decision, underDPoP bool, src source) error {
	reason := policyDenyReason(d)

	chain, abort := errwalk.Flatten(reason)
	if abort != nil {
		return &dependencyFailure{text: textAccessTokenPolicyFailed, err: reason}
	}

	if _, isFault, stop := errwalk.As[*diag.Fault](chain); stop != nil || isFault {
		return &dependencyFailure{text: textAccessTokenPolicyFailed, err: reason}
	}

	if insufficient, stop := errwalk.Is(chain, policy.ErrInsufficientUserAuthentication); stop == nil && insufficient {
		return s.refuseInsufficient(underDPoP, src)
	}

	return reason
}

// dependencyFailure marks a failure of a dependency the chain consulted for a request it was
// judging. StatusForError answers it 500 before it consults its refusal table, so a dependency whose
// error wraps a sentinel that table answers 401 does not turn an outage into a refusal. Its text is
// fixed library text, and it unwraps to the failure it marks, so the cause, and a context's ending,
// stay reachable through errors.Is and errors.As.
type dependencyFailure struct {
	text string
	err  error
}

// Error returns the fixed text, never the cause's.
func (f *dependencyFailure) Error() string { return f.text }

// Unwrap returns the failure it marks.
func (f *dependencyFailure) Unwrap() error { return f.err }

func (*dependencyFailure) forcedDependency() {}

// forcedDependency is a failure StatusForError answers 500 before anything else it wraps is read:
// an issuing failure, or a dependency a resource server's per-request policy consulted.
type forcedDependency interface {
	error
	forcedDependency()
}

// localExternal is a source whose caller strategy can resolve a local user from an external token
// (WithLinkedUsers, WithClaimsMapper), which the MFA requirement policy then judges through its
// federated-assurance source.
type localExternal interface {
	resolvesLocalUsers() bool
}

// checkAssuranceSource refuses a chain whose policy judges external access tokens with no
// federated-assurance source while a source resolves local users from them: every such caller
// would be judged unmet, so a required user could never reach the API. Exempt mode, or an
// exemption rule exempting oidc, needs no source, as the policy reports (UnwiredFederatedAssurance).
func (s *resourceServers) checkAssuranceSource(c *config) error {
	if c.engine == nil {
		return nil
	}

	unwired := c.engine.UnwiredFederatedAssurance()
	if len(unwired) == 0 {
		return nil
	}

	for _, rs := range s.modes {
		for _, src := range rs.sources {
			if l, ok := src.(localExternal); ok && l.resolvesLocalUsers() {
				return newConfigError("%s (%s): %s resolves local users from external access tokens, and %s "+
					"judges them on provider assurance with no source to match it against, so every such "+
					"caller would be refused: give it policy.WithFederatedAssuranceSource (the shipped OIDC "+
					"manager answers only for providers registered for OIDC login, so an API-only chain "+
					"supplies its own), choose policy.FederatedAssuranceExempt, or exempt factor.OIDC with "+
					"policy.WithMFAExemption", optionResourceServer, rs.id, src.name(), strings.Join(unwired, ", "))
			}
		}
	}

	return nil
}
