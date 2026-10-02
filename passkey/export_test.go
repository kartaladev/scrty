package passkey

import "context"

// WithEmailCodeCompare replaces the constant-time comparison of an emailed
// code, so a test can count how many presented codes are compared.
func WithEmailCodeCompare(fn func(stored, presented string) bool) Option {
	return func(m *Manager) { m.compare = fn }
}

// NotifyRemoved queues the removal notice for c, saying whether sessions were
// ended, so a test can see the rendered text before removal revokes anything.
func (m *Manager) NotifyRemoved(ctx context.Context, c *Credential, sessionsEnded bool) {
	m.notify(ctx, noticeRemoved, c, nil, sessionsEnded)
}

// NotifySuspended queues the suspension notice for c, saying whether sessions
// were ended.
func (m *Manager) NotifySuspended(ctx context.Context, c *Credential, sessionsEnded bool) {
	m.notify(ctx, noticeSuspended, c, nil, sessionsEnded)
}
