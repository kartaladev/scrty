package policy

import (
	"fmt"
	"time"
)

// LockoutError is the reason an AccountLockoutPolicy denies an identifier it
// holds locked. errors.Is matches it to ErrAccountLocked, so a caller that
// only needs to know "locked" keeps matching the sentinel, and errors.As
// reaches it for the wait.
//
// Wait is the full escalated wait the identifier owed when it was refused,
// which is an upper bound on what remains: the attempt store answers counts,
// not instants, so the policy cannot tell how much of the wait has already
// passed. The refusal lifts no later than the window after the newest failure,
// so a Wait longer than the configured window overstates it. Wait is zero
// where no wait lifts the lock — at the ceiling, under WithSlidingLockout,
// and for an identifier held by the cap (WithLockoutCap) — and a caller must
// not read zero as "try now".
//
// The refusal of a held identifier also matches ErrAccountHeld, so a consumer
// can tell its user to reset their password rather than wait. Every other
// refusal does not.
//
// A consumer that discloses locks may render Wait as an HTTP Retry-After
// header; the library writes none itself. A consumer that does not disclose
// locks should not let Wait reach the client at all, since a wait is only
// owed by an account that exists and has failed.
//
// Its text is fixed library text naming the failure count and the window,
// never anything an attempt store said.
type LockoutError struct {
	// Wait is the escalated wait owed, or zero at the ceiling, under a
	// sliding lock and for a hold.
	Wait time.Duration

	failures int
	window   time.Duration

	// held marks the refusal of an identifier held by the consecutive-failure
	// cap; failures is then the streak's count, and window is unused.
	held bool
}

// Error reports the lock in the library's own words: the failures in the
// window, or, for a hold, the consecutive failures that set it. A LockoutError
// built by a consumer, which carries no failure count, reads as
// ErrAccountLocked.
func (e *LockoutError) Error() string {
	if e.failures == 0 {
		return accountLockedText
	}
	if e.held {
		return fmt.Sprintf("%s: held after %d consecutive failures", accountLockedText, e.failures)
	}

	return fmt.Sprintf("%s: %d failures within %s", accountLockedText, e.failures, e.window)
}

// Is reports whether target is ErrAccountLocked, the sentinel every
// account-locked refusal matches, or ErrAccountHeld, which only the refusal of
// an identifier held by the consecutive-failure cap matches.
func (e *LockoutError) Is(target error) bool {
	//nolint:errorlint // identity: Is compares against its own sentinels
	return target == ErrAccountLocked || (e.held && target == ErrAccountHeld)
}
