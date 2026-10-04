package session

import "github.com/kartaladev/scrty/expiry"

// ExpiryTask returns the task that deletes the expired sessions of s, through
// the store's own DeleteExpired.
//
// The task is named "sessions". It sets no Interval, because only the
// deployment knows its cadence, and it accepts no cutoff: what counts as
// expired is the store's own rule, judged by the store's own clock. It never
// deletes a session that is still live.
func ExpiryTask(s Store) expiry.Task {
	return expiry.Task{Name: "sessions", Run: s.DeleteExpired}
}
