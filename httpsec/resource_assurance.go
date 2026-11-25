package httpsec

import (
	"errors"
	"time"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/assurance"
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
