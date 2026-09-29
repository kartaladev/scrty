package policy

import (
	"context"
	"fmt"
	"slices"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/nilcheck"
)

// UsableMFAMethods reports which of methods user can use as a second factor
// after a login whose first factor was first: those the user is enrolled on
// whose channel differs from first's, in the order methods gives them.
//
// It is the one definition of "usable" that both MFA policies and the chain
// share, so none of them can offer a method another would refuse. It is
// exported so a consumer building their own listing decides the same way.
//
// A method on the first factor's own channel is never usable: whoever holds
// that channel holds both factors, so a challenge on it would prove nothing the
// first factor had not already proved.
//
// Any lookup error is returned as it is, with no methods, and never as a
// shorter list: a lost or unreadable enrolment must not read as "not enrolled",
// or it would downgrade exactly the users who had enrolled. The lookups are
// asked in order and the first error stops the walk. A user enrolled on
// nothing usable is an empty result and no error.
//
// methods must hold no absent entry; the policy constructors refuse a set that
// does.
func UsableMFAMethods(
	ctx context.Context, methods []MFAMethodLookup, user identity.UserID, first factor.Kind,
) ([]MFAMethodLookup, error) {
	var usable []MFAMethodLookup

	for _, m := range methods {
		enrolled, err := m.Enrolled(ctx, user)
		if err != nil {
			return nil, err
		}

		if enrolled && m.Channel() != first.Channel() {
			usable = append(usable, m)
		}
	}

	return usable, nil
}

// checkMFAMethods reports a set of methods no policy could decide over, and
// otherwise returns a copy of it, so a caller who reuses the slice they passed
// cannot change what a built policy consults.
//
// who names the policy in the error, and empty says whether an empty set is
// itself the mistake: it is for the challenge policy, which exists only to
// challenge on a method, and is not for the requirement policy, which reads an
// empty set as "no method configured".
func checkMFAMethods(methods []MFAMethodLookup, who string, emptyRefused bool) ([]MFAMethodLookup, error) {
	if len(methods) == 0 {
		if emptyRefused {
			return nil, fmt.Errorf("%w: the %s has no MFA method, so it would complete every "+
				"login on its first factor", ErrConfig, who)
		}

		return nil, nil
	}

	seen := make(map[string]int, len(methods))
	for i, m := range methods {
		if nilcheck.IsNil(m) {
			return nil, fmt.Errorf("%w: MFA method %d given to the %s is absent, so it would "+
				"fail at the first login rather than here", ErrConfig, i, who)
		}

		name := m.Name()
		if first, dup := seen[name]; dup {
			return nil, fmt.Errorf("%w: MFA methods %d and %d given to the %s are both named %q, "+
				"so nothing could tell them apart", ErrConfig, first, i, who, name)
		}
		seen[name] = i
	}

	return slices.Clone(methods), nil
}
