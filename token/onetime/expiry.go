package onetime

import (
	"context"
	"errors"

	"github.com/kartaladev/scrty/expiry"
)

// ExpiryTask returns the task that deletes the expired tokens of m's purpose,
// through m.PurgeExpired.
//
// The task is named "one-time-tokens:" followed by the purpose. It sets no
// Interval, because only the deployment knows its cadence, and it accepts no
// cutoff: the manager derives its own from the issuance window it is
// configured with. It never deletes a token that is still inside that window,
// expired or not, so a sweep cannot free issuance quota.
//
// A store that cannot purge yields an error that matches both
// expiry.ErrPurgeUnsupported and ErrReapUnsupported, never a run that removed
// nothing. A consumer who wants a different task name uses ExpiryTaskNamed.
func ExpiryTask(m *Manager) expiry.Task {
	return ExpiryTaskNamed("one-time-tokens:"+m.Purpose(), m)
}

// ExpiryTaskNamed is ExpiryTask with a name the caller chooses, for owners that
// build on a one-time manager and publish a task under a name of their own.
// Its behaviour, limits and errors are those of ExpiryTask: no interval, no
// cutoff, and nothing inside the issuance window is deleted.
func ExpiryTaskNamed(name string, m *Manager) expiry.Task {
	return expiry.Task{
		Name: name,
		Run: func(ctx context.Context) (int, error) {
			removed, err := m.PurgeExpired(ctx)
			if errors.Is(err, ErrReapUnsupported) {
				return removed, errors.Join(err, expiry.ErrPurgeUnsupported)
			}

			return removed, err
		},
	}
}
