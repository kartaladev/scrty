package policy

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const (
	// defaultIdlePolicyTimeout is how long a session may go unused before this
	// policy refuses the next request, with nothing configured. Half an hour
	// is long enough not to interrupt someone reading a page, and short enough
	// that an unattended browser is not an open session by the time anyone
	// walks past it.
	defaultIdlePolicyTimeout = 30 * time.Minute

	// defaultIdlePolicyAbsoluteTimeout is the deadline nothing extends, with
	// nothing configured. Half a day makes a working day end with a fresh
	// login rather than with a session alive since some morning nobody
	// remembers.
	defaultIdlePolicyAbsoluteTimeout = 12 * time.Hour
)

// ErrSessionIdle is the reason an IdleTimeoutPolicy denies with, and what a
// caller matches to tell "you have been away too long, log in again" from a
// refusal that no amount of logging in would fix.
var ErrSessionIdle = errors.New("policy: session has been idle too long")

// IdleOption configures an IdleTimeoutPolicy. Every option names the default it
// replaces, and every default works with no configuration at all.
type IdleOption func(*IdleTimeoutPolicy)

// WithIdlePolicyTimeout replaces how long a session may go unused before this
// policy refuses the next request. The default is 30 minutes. Zero or less is
// a configuration error: it would refuse every request the instant after the
// one that recorded the access.
//
// It is named for this policy, and is deliberately not session's
// WithIdleTimeout. The session manager's timeout decides when the store stops
// serving a session at all; this one decides when a request carrying a session
// is refused. One option must never govern two subsystems — a consumer who
// wants them to agree passes the same duration to both, and one who wants this
// policy to refuse earlier than the store expires can have that too.
func WithIdlePolicyTimeout(d time.Duration) IdleOption {
	return func(p *IdleTimeoutPolicy) { p.idle = d }
}

// WithIdlePolicyAbsoluteTimeout replaces the deadline nothing extends, which
// this policy reports through Thresholds. The default is 12 hours. Zero or
// less is a configuration error, for the same reason a zero idle timeout is.
//
// Like WithIdlePolicyTimeout it is named for this policy, and is distinct from
// session's WithAbsoluteTimeout, so a deployment can hand the session manager
// one set of deadlines and this policy another without either option reaching
// into the other's subsystem.
func WithIdlePolicyAbsoluteTimeout(d time.Duration) IdleOption {
	return func(p *IdleTimeoutPolicy) { p.absolute = d }
}

// IdleTimeoutPolicy refuses a request whose session has gone unused for longer
// than the idle timeout, and supplies the deadlines a new session gets.
//
// It judges against Input.Now and the session's own last-access time, never the
// wall clock, so every policy in the phase agrees about whether a deadline has
// passed. The comparison is strictly greater: a session evaluated exactly at
// its idle timeout is still served, and the request after it is not.
//
// A session whose last access is the zero time is allowed. Nothing has recorded
// activity on it, so there is no idleness to measure, and reading "never
// accessed" as "idle since the beginning of time" would refuse every request
// made through a store or a consumer that does not keep the field.
//
// The absolute timeout is reported by Thresholds and is not enforced here.
// Enforcing it would duplicate the session store, which already refuses a
// session past either of its deadlines; this policy exists for the deployment
// whose store cannot, and for a refusal the caller can tell apart.
//
// An IdleTimeoutPolicy is safe for concurrent use and holds no state between
// requests.
type IdleTimeoutPolicy struct {
	idle     time.Duration
	absolute time.Duration
}

// Compile-time proof that this policy is one an Engine can hold.
var _ Policy = (*IdleTimeoutPolicy)(nil)

// NewIdleTimeoutPolicy returns a policy that refuses idle sessions, with a
// 30-minute idle timeout and a 12-hour absolute timeout unless opts replace
// them.
//
// A timeout of zero or less is a configuration error wrapping ErrConfig: it
// would make the policy fire on every request, which is never what a caller
// configuring a timeout meant.
func NewIdleTimeoutPolicy(opts ...IdleOption) (*IdleTimeoutPolicy, error) {
	p := &IdleTimeoutPolicy{
		idle:     defaultIdlePolicyTimeout,
		absolute: defaultIdlePolicyAbsoluteTimeout,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(p)
		}
	}

	if p.idle <= 0 {
		return nil, fmt.Errorf(
			"%w: idle timeout must be positive, got %s, or the policy would "+
				"refuse every request made after the one that recorded the access",
			ErrConfig, p.idle)
	}
	if p.absolute <= 0 {
		return nil, fmt.Errorf(
			"%w: absolute timeout must be positive, got %s, or every session "+
				"would be created already past its final deadline",
			ErrConfig, p.absolute)
	}

	return p, nil
}

// Name identifies this policy in logs and in configuration errors.
func (p *IdleTimeoutPolicy) Name() string { return "idle-timeout" }

// Phases reports that this policy runs on every request carrying a session,
// and in no other phase: a session cannot have been idle before it exists.
func (p *IdleTimeoutPolicy) Phases() []Phase { return []Phase{PerRequest} }

// Evaluate denies with ErrSessionIdle when the session has gone unused for
// longer than the idle timeout, and allows otherwise.
//
// A request carrying no session allows. There is nothing to have been idle, and
// whether a request may proceed without a session is decided by whoever
// establishes one, not by a rule about how long ago it was last used.
func (p *IdleTimeoutPolicy) Evaluate(_ context.Context, in *Input) Decision {
	if in.Session == nil || in.Session.LastAccessedAt.IsZero() {
		return Decision{}
	}

	if in.Now.Sub(in.Session.LastAccessedAt) > p.idle {
		return Decision{Outcome: Deny, Reason: ErrSessionIdle}
	}

	return Decision{}
}

// Thresholds returns the deadlines a session created at createdAt has when it
// is accessed at now: the idle deadline that this access extends, and the
// absolute deadline that nothing extends.
//
// It exists so a consumer can hand the session manager the same deadlines this
// policy judges against, rather than configuring the two separately and
// discovering at 3am that they disagree.
//
// The idle deadline is never past the absolute one. A session in its last
// minutes must not be handed an idle deadline that outlives the deadline
// nothing extends, or the two would contradict each other about when it ends.
func (p *IdleTimeoutPolicy) Thresholds(createdAt, now time.Time) (idle, absolute time.Time) {
	absolute = createdAt.Add(p.absolute)

	idle = now.Add(p.idle)
	if idle.After(absolute) {
		idle = absolute
	}

	return idle, absolute
}
