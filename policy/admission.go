package policy

import (
	"context"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/identity"
)

// LoginAdmission answers, ahead of any login, whether a login of a given kind
// would be admitted without a local second factor. A component that must
// judge a login it is not evaluating, such as the account-recovery way-back
// check, asks it rather than repeating the policy's rules, so the two cannot
// disagree.
//
// The requirement policy NewMFARequirementPolicy returns implements it, and
// answers for itself alone: the challenge policy under
// WithFederatedChallengeWhenUnmet(true) may still challenge a federated login
// this answer admits.
type LoginAdmission interface {
	// AdmitsWithoutLocalSecondFactor reports whether a login of kind for user
	// would be admitted without a local second factor, whatever its provider
	// asserts. Provider assurance is never assumed: it is known only at a
	// login, so an answer that would depend on it is false.
	//
	// A lookup the answer depends on that fails is returned as an error,
	// never as false or true.
	AdmitsWithoutLocalSecondFactor(ctx context.Context, user identity.UserID, kind factor.Kind) (bool, error)
}
