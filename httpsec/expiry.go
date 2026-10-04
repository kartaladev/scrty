package httpsec

import (
	"github.com/kartaladev/scrty/expiry"
	"github.com/kartaladev/scrty/onetime"
)

// mfaChallengeTaskPrefix starts the name of each challenge method's expiry
// task; the method's name follows it.
const mfaChallengeTaskPrefix = "mfa-challenges:"

// ExpiryTasks returns the tasks that delete the expired one-time state of the
// components the chain builds itself, in this order:
//
//  1. "mfa-challenges:<method>" for each challenge method (an
//     mfa.ChallengeMethod, such as a passkey) of each EnableMFA, in
//     registration order and each in its configured order. Its pending
//     challenges are issued to a signed-in user who still owes a second
//     factor. A method with no challenge step, such as TOTP, keeps no pending
//     state and contributes no task. Two EnableMFA that share a challenge
//     method's name yield two tasks of the same name, which expiry.NewRunner
//     refuses; rename one by setting its Name.
//  2. The tasks of the recovery.Recoverer that EnableAccountRecovery builds:
//     "recovery-issued-codes" when issued codes are enabled, and
//     "recovery-finish-tokens" and "recovery-cancel-tokens" when the core may
//     hold a recovery. See recovery.Recoverer.ExpiryTasks.
//
// A component that is not enabled contributes nothing, and a chain with none
// returns an empty, non-nil slice. Passing that alone to expiry.NewRunner
// fails with expiry.ErrNoTasks rather than building a runner that sweeps
// nothing.
//
// The tasks run over the very managers that serve the chain's requests, so a
// sweep reaches the state those requests issued, whether it lives in the
// default in-memory stores or in the stores given to WithMFAChallengeStore,
// WithRecoveryCore's recovery.WithIssuedCodeStore or
// recovery.WithHoldTokenStore. Each purges through its own manager, which
// removes only tokens that are expired and older than that manager's issuance
// window, so a sweep never frees the challenge limit or the issued-code limit.
// The sweep EnableMFA's begin runs inline, at most once per issuance window per
// method, is unaffected; these tasks also cover a method nobody has begun
// lately.
//
// No task sets an Interval, because only the deployment knows its cadence, and
// none accepts a cutoff. They never delete sessions, MFA enrolments, passkeys,
// API keys, OIDC links or recovery records. A store that does not implement
// onetime.Reaper makes its task fail with an error matching both
// expiry.ErrPurgeUnsupported and onetime.ErrReapUnsupported.
//
// State of components the consumer builds and hands to the chain is theirs to
// sweep with those components' own tasks: session.ExpiryTask,
// magiclink.ExpiryTask, (*passkey.Manager).ExpiryTasks, oidc.FlowExpiryTask
// and oidc.HandoffExpiryTask. A consumer renames a returned task by setting its
// Name, or leaves one out.
func (c *Chain) ExpiryTasks() []expiry.Task {
	tasks := []expiry.Task{}

	for _, r := range c.registrations {
		if i, ok := r.interceptor.(*mfaInterceptor); ok {
			tasks = append(tasks, i.expiryTasks()...)
		}
	}

	for _, r := range c.registrations {
		if i, ok := r.interceptor.(*recoveryInterceptor); ok && i.recoverer != nil {
			tasks = append(tasks, i.recoverer.ExpiryTasks()...)
		}
	}

	return tasks
}

// expiryTasks returns a task per challenge method, over the manager its begin
// issues challenges with, in the methods' configured order.
func (i *mfaInterceptor) expiryTasks() []expiry.Task {
	var tasks []expiry.Task

	for _, m := range i.methods {
		if mgr, ok := i.challenges[m.Name()]; ok {
			tasks = append(tasks, onetime.ExpiryTaskNamed(mfaChallengeTaskPrefix+m.Name(), mgr))
		}
	}

	return tasks
}
