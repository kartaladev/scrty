package httpsec

import (
	"context"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// msgMFAMethodsUnavailable is the fixed text a second-factor challenge is
// replaced with when the methods it would offer could not be looked up. The
// failure is the consumer's enrolment store's, and its own text stays out.
const msgMFAMethodsUnavailable = "httpsec: the usable MFA methods could not be looked up"

// challenge is the second-factor challenge the gate refuses s with: the
// challenge on s, carrying token when one was issued with it, and the methods
// s's user can answer it with. A login that raises one builds the same
// challenge from the same methods (usableMethods), looked up before its
// session is created.
//
// The methods are decided by policy.UsableMFAMethods over the same lookups the
// policies were built from, so the challenge never offers a method the verify
// endpoint would refuse as not usable. A lookup that fails replaces the
// challenge with that failure, behind fixed text: a partial list would hide a
// method the user holds, and an empty one would read as "nothing left".
func (i *mfaInterceptor) challenge(ctx context.Context, s *session.Session, token string) error {
	methods, err := i.usableMethods(ctx, s.UserID, s.FirstFactor)
	if err != nil {
		return err
	}

	return &ChallengeError{Kind: policy.ChallengeMFA, Session: s, Token: token, Methods: methods}
}

// usableMethods is the methods a second-factor challenge to user, whose first
// factor was first, offers. A lookup that fails is returned behind fixed text.
func (i *mfaInterceptor) usableMethods(
	ctx context.Context,
	user identity.UserID,
	first factor.Kind,
) ([]MFAMethod, error) {
	usable, err := policy.UsableMFAMethods(ctx, i.lookups, user, first)
	if err != nil {
		return nil, diag.Wrap(err, msgMFAMethodsUnavailable)
	}

	methods := make([]MFAMethod, 0, len(usable))
	for _, l := range usable {
		methods = append(methods, MFAMethod{
			Name:    l.Name(),
			Channel: l.Channel(),
			Begins:  isChallengeMethod(i.byName[l.Name()]),
		})
	}

	return methods, nil
}

// challengeMethodsFunc looks up the methods a raised challenge of kind offers
// user, whose first factor was first. A login calls it before it creates the
// session, so a lookup that fails leaves no session behind.
type challengeMethodsFunc func(
	ctx context.Context,
	kind policy.ChallengeKind,
	user identity.UserID,
	first factor.Kind,
) ([]MFAMethod, error)

// challengeMethods is the chain's challengeMethodsFunc. A second-factor
// challenge offers the methods the MFA interceptor finds usable; every other
// kind offers none. A second-factor challenge on a chain with no MFA
// interceptor is refused at assembly as unenforced, except through a test
// gate, which gets the bare challenge.
func (c *Chain) challengeMethods(
	ctx context.Context,
	kind policy.ChallengeKind,
	user identity.UserID,
	first factor.Kind,
) ([]MFAMethod, error) {
	if kind == policy.ChallengeMFA && c.mfa != nil {
		return c.mfa.usableMethods(ctx, user, first)
	}

	return nil, nil
}

// mfaOf is the chain's MFA interceptor, or nil when EnableMFA was not given.
func (c *config) mfaOf() *mfaInterceptor {
	var found *mfaInterceptor

	_ = eachInterceptor(c, func(i *mfaInterceptor) error {
		found = i

		return nil
	})

	return found
}
