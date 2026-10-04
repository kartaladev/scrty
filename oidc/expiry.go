package oidc

import "github.com/kartaladev/scrty/expiry"

// FlowExpiryTask returns the task that deletes m's expired login flows through
// m.PurgeExpiredFlows.
//
// The task is named "oidc-flows"; a consumer renames it by
// setting Name on the returned value. It sets no Interval, because only the
// deployment knows its cadence, and it accepts no cutoff: the manager uses its
// own clock's now. It never deletes a flow that has not expired, and it never
// touches OIDC links or identity records.
func FlowExpiryTask(m *Manager) expiry.Task {
	return expiry.Task{Name: "oidc-flows", Run: m.PurgeExpiredFlows}
}

// HandoffExpiryTask returns the task that deletes h's expired handoff records,
// spent or not, through h.PurgeExpired.
//
// The task is named "oidc-handoffs"; a consumer renames
// it by setting Name on the returned value. It sets no Interval, because only
// the deployment knows its cadence, and it accepts no cutoff: the manager uses
// its own clock's now. It never deletes a code that has not expired, and it
// never touches OIDC links, sessions or identity records.
func HandoffExpiryTask(h *HandoffManager) expiry.Task {
	return expiry.Task{Name: "oidc-handoffs", Run: h.PurgeExpired}
}
