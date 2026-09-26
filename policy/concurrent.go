package policy

import (
	"context"
	"errors"
	"fmt"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/nilcheck"
)

//go:generate mockgen -source=concurrent.go -package=policy_test -destination=concurrent_mock_test.go -typed

// ErrTooManySessions is the reason a ConcurrentSessionPolicy denies with: the
// user is at the cap, or nothing could say whether they are.
//
// The two are deliberately one error to the caller. Telling them apart would
// mean deciding, on the login path, whether an outage is a good enough reason
// to hand out a session the cap may not allow. The cause of a failed count is
// still there to be matched — the reason wraps it — so an operator can see an
// outage in a log without a caller having to act on it.
var ErrTooManySessions = errors.New("policy: too many concurrent sessions")

// SessionCounter reports how many unexpired sessions a user holds.
//
// It is declared here, with the one method the policy needs, rather than taken
// from the session package: a session.Store satisfies it exactly as it stands,
// so a consumer passes the store they already have, and neither package has to
// import the other. A consumer counting sessions somewhere else — a read
// replica, a cache, a service of their own — implements this and nothing more.
type SessionCounter interface {
	// CountActiveByUser counts this user's unexpired sessions. The reference
	// is the consumer's own and is matched exactly as it was supplied.
	//
	// Expired sessions must not be counted, whether or not anything has swept
	// them: a session that will never be served again is not one the user is
	// holding, and counting it would refuse a login on the strength of a row
	// nobody can use.
	CountActiveByUser(ctx context.Context, user identity.UserID) (int, error)
}

// ConcurrentSessionPolicy caps how many sessions one user may hold at once,
// refusing the login that would go past the cap.
//
// It is opt-in: there is no default maximum, so a deployment that has not
// registered this policy is not quietly capped at a number this library chose.
//
// It fails closed. A count that cannot be made is a denial, not an allowance,
// because the alternative is that an unreachable store lifts the cap for
// exactly as long as it is unreachable.
//
// # Limits, stated
//
// The count and the session that follows it are not one atomic step, so a
// burst of simultaneous logins by one user can leave them holding more than
// the maximum: each login may count before any of them has stored a session.
// The cap bounds how many sessions a user accumulates, which is what it is for;
// making it exact would mean a lock across every login in the deployment.
//
// An enrolment-only session, one confined to the second-factor enrolment path
// (WithMFAEnrolmentPath), is a session like any other to the count: it counts
// against the cap until its lowered absolute deadline, 15 minutes by default,
// or until it is logged out. So whoever holds a required user's password can
// occupy that user's slots by beginning enrolments that are never confirmed,
// each for at most that lifetime.
//
// A ConcurrentSessionPolicy is safe for concurrent use and holds no state
// between logins.
type ConcurrentSessionPolicy struct {
	counter     SessionCounter
	maxSessions int
}

// Compile-time proof that this policy is one an Engine can hold.
var _ Policy = (*ConcurrentSessionPolicy)(nil)

// NewConcurrentSessionPolicy returns a policy that refuses a login by a user
// already holding maxSessions unexpired sessions, counted through counter.
//
// maxSessions is a required argument and has no default. A cap is a decision
// about a deployment's users, not something a library can guess, and a policy
// registered with a maximum nobody chose would either refuse logins that should
// stand or permit a number the consumer never agreed to.
//
// An absent counter — nil, or a non-nil interface holding a nil pointer, which
// is what an unchecked constructor result hands over — is a configuration error
// wrapping ErrConfig, as is a maximum of zero or less: a cap of zero refuses
// every login, since every user already holds at least none.
func NewConcurrentSessionPolicy(counter SessionCounter, maxSessions int) (*ConcurrentSessionPolicy, error) {
	p := &ConcurrentSessionPolicy{counter: counter, maxSessions: maxSessions}

	if p.maxSessions <= 0 {
		return nil, fmt.Errorf(
			"%w: maximum number of sessions must be positive, got %d, or the "+
				"policy would refuse every login: every user already holds at "+
				"least none",
			ErrConfig, p.maxSessions)
	}
	if nilcheck.IsNil(p.counter) {
		return nil, fmt.Errorf(
			"%w: session counter must not be nil, or no count can be made and "+
				"the policy would refuse every login it was registered to cap",
			ErrConfig)
	}

	return p, nil
}

// Name identifies this policy in logs and in configuration errors.
func (p *ConcurrentSessionPolicy) Name() string { return "concurrent-session" }

// Phases reports that this policy runs once a login has succeeded and before a
// session is established, which is the only moment at which refusing costs the
// user nothing they already had.
func (p *ConcurrentSessionPolicy) Phases() []Phase { return []Phase{PostAuthentication} }

// Evaluate denies with ErrTooManySessions when the user already holds the
// maximum, and allows otherwise.
//
// The comparison is at or above the maximum, not past it: the session this
// login would establish is the one that must not be created, so a user holding
// three of a permitted three is refused a fourth.
//
// A count that fails denies, with a reason wrapping both ErrTooManySessions and
// the cause, so a caller can refuse on the first and an operator can read the
// second.
func (p *ConcurrentSessionPolicy) Evaluate(ctx context.Context, in *Input) Decision {
	count, err := p.counter.CountActiveByUser(ctx, in.User)
	if err != nil {
		return Decision{
			Outcome: Deny,
			Reason:  fmt.Errorf("%w: counting the user's sessions failed: %w", ErrTooManySessions, err),
		}
	}

	if count >= p.maxSessions {
		return Decision{Outcome: Deny, Reason: ErrTooManySessions}
	}

	return Decision{}
}
