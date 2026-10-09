package policy

// AttemptViewRequirer is implemented by a policy whose decisions depend on
// failures being recorded through a view of its attempt store that it hands
// out, rather than through the store itself.
//
// It is the optional interface a wiring check reads. A component that records
// failures, such as an HTTP security chain's password logins, asks the engine
// for every view it must record into (Engine.RequiredAttemptViews) and refuses
// construction when it was given another store. A policy that does not
// implement it is taken to accept failures recorded into any store.
type AttemptViewRequirer interface {
	// RequiredAttemptView returns the view and true when failures must be
	// recorded through it, and false when any attempt store will do.
	RequiredAttemptView() (AttemptStore, bool)
}

// RequiredAttemptView reports the policy's view, Attempts, and true when a cap
// is configured (WithLockoutCap): only the view advances the consecutive
// count, so a failure recorded straight into the store would never bring an
// identifier closer to its hold. Without a cap it reports false, and any store
// the policy reads will do, as before.
func (p *AccountLockoutPolicy) RequiredAttemptView() (AttemptStore, bool) {
	return p.attempts, p.capLimit > 0
}

// RequiredAttemptView names a registered policy, by its Name, and the view
// failures must be recorded through for it to decide correctly.
type RequiredAttemptView struct {
	Policy string
	View   AttemptStore
}
