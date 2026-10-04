package passkey

import (
	"github.com/kartaladev/scrty/expiry"
	"github.com/kartaladev/scrty/onetime"
)

// ExpiryTasks returns the tasks that delete the manager's expired ceremony
// challenges, in this order:
//
//   - "passkey-registration-challenges": registration challenges;
//   - "passkey-login-challenges": passwordless login challenges, which
//     BeginLogin issues to anyone, signed in or not.
//
// The challenges live in Deps.Challenges under one-time managers the Manager
// builds itself, so no task built outside it can reach them; with a durable
// store they would otherwise grow without bound. Each task purges through its
// own manager, which removes only challenges that are expired and older than
// that manager's issuance window, so a sweep never frees issuance quota. The
// inline purge BeginLogin runs at most once per challenge lifetime is
// unaffected; these tasks cover the registration challenges it never touches,
// and a manager that goes quiet.
//
// No task sets an Interval, because only the deployment knows its cadence, and
// none accepts a cutoff. They never delete passkeys, pending or active, user
// handles or sessions. A challenge store that does not implement
// onetime.Reaper makes each task fail with an error matching both
// expiry.ErrPurgeUnsupported and onetime.ErrReapUnsupported. A consumer
// renames a task by setting Name on the returned value, or leaves one out.
func (m *Manager) ExpiryTasks() []expiry.Task {
	return []expiry.Task{
		onetime.ExpiryTaskNamed("passkey-registration-challenges", m.registration),
		onetime.ExpiryTaskNamed("passkey-login-challenges", m.login),
	}
}
