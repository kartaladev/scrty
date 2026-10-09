package policy

import (
	"errors"
	"time"
)

// ErrAccountHeld matches the refusal of an identifier held by the
// consecutive-failure cap, alongside ErrAccountLocked.
//
// A hold has no wait: it lasts until the identifier's failures are cleared,
// by a password change through the chain or by the policy's Reset.
var ErrAccountHeld = errors.New("policy: account held until its failures are cleared")

// FailureStreak is an identifier's consecutive failures: how many there have
// been since it was last cleared, the newest of them, and when it became held.
//
// The zero FailureStreak is an identifier with no consecutive failures.
type FailureStreak struct {
	// Failures is how many failures there have been since the streak was
	// last cleared or restarted.
	Failures int

	// Newest is the instant of the newest failure in the streak.
	Newest time.Time

	// HeldAt is the instant of the failure that brought the streak to the
	// cap, and is zero while the streak is not held.
	HeldAt time.Time
}

// Held reports whether the streak has reached a cap and is held.
func (s FailureStreak) Held() bool { return !s.HeldAt.IsZero() }
