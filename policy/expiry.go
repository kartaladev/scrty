package policy

import (
	"context"
	"errors"

	"github.com/kartaladev/scrty/expiry"
)

// LockoutExpiryTask returns the task that deletes the login failures of p that
// have aged out of its lockout window, through p.PurgeExpired.
//
// The task is named "login-attempts". It sets no Interval, because only the
// deployment knows its cadence, and it accepts no cutoff: the cutoff is p's own
// window behind p's own clock (24 hours by default, or what WithLockoutWindow
// or WithSlidingLockout set). It never deletes a failure the policy would still
// count, so a sweep cannot unlock an account that is locked.
//
// With a cap (WithLockoutCap) the task also deletes the consecutive counts
// that have aged out of the cap retention (WithLockoutCapRetention), and never
// a hold: a held identifier stays held however many sweeps run.
//
// A store that cannot purge, the default in-memory one among them, yields an
// error that matches both expiry.ErrPurgeUnsupported and ErrReapUnsupported,
// never a run that removed nothing.
func LockoutExpiryTask(p *AccountLockoutPolicy) expiry.Task {
	return expiry.Task{
		Name: "login-attempts",
		Run: func(ctx context.Context) (int, error) {
			removed, err := p.PurgeExpired(ctx)
			if errors.Is(err, ErrReapUnsupported) {
				return removed, errors.Join(err, expiry.ErrPurgeUnsupported)
			}

			return removed, err
		},
	}
}
