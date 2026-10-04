package recovery

import (
	"github.com/kartaladev/scrty/expiry"
	"github.com/kartaladev/scrty/onetime"
)

// ExpiryTasks returns the tasks that delete the recoverer's expired one-time
// state, in this order, each only when its component is enabled:
//
//   - "recovery-issued-codes": issued recovery codes, when ProofIssued is
//     enabled (WithProofs). Start issues them to anyone who knows a username.
//   - "recovery-finish-tokens" and "recovery-cancel-tokens": the tokens of
//     held recoveries, when holds are enabled (WithDelay or WithRisk; see
//     Holds).
//
// A recoverer with neither returns an empty, non-nil slice. The state lives in
// one-time managers the recoverer builds itself, over WithIssuedCodeStore and
// WithHoldTokenStore, so no task built outside it can reach them. Each task
// purges through its own manager, which removes only tokens that are expired
// and older than that manager's issuance window, so a sweep never frees the
// issued-code limit.
//
// No task sets an Interval, because only the deployment knows its cadence, and
// none accepts a cutoff. They never delete recovery records, which are the
// audit trail of every recovery, nor saved recovery codes or sessions. A store
// that does not implement onetime.Reaper makes its task fail with an error
// matching both expiry.ErrPurgeUnsupported and onetime.ErrReapUnsupported.
// A consumer renames a task by setting Name on the returned value, or leaves
// one out.
func (r *Recoverer) ExpiryTasks() []expiry.Task {
	tasks := make([]expiry.Task, 0, 3)

	if r.issued != nil {
		tasks = append(tasks, onetime.ExpiryTaskNamed("recovery-issued-codes", r.issued))
	}
	if r.finishTokens != nil {
		tasks = append(tasks, onetime.ExpiryTaskNamed("recovery-finish-tokens", r.finishTokens))
	}
	if r.cancelTokens != nil {
		tasks = append(tasks, onetime.ExpiryTaskNamed("recovery-cancel-tokens", r.cancelTokens))
	}

	return tasks
}
