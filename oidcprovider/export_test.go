package oidcprovider

import (
	"context"
	"net/http"
	"time"
)

// The defaults New records, read back by the construction table.
func (p *Provider) PendingLifetimeForTest() time.Duration  { return p.cfg.pendingLifetime }
func (p *Provider) CodeLifetimeForTest() time.Duration     { return p.cfg.codeLifetime }
func (p *Provider) AssertionMaxForTest() time.Duration     { return p.cfg.assertionMax }
func (p *Provider) AssertionAudienceForTest() AudienceRule { return p.cfg.assertionAudience }
func (p *Provider) RefetchCooldownForTest() time.Duration  { return p.cfg.keysRefetchCooldown }
func (p *Provider) BoundsForTest() RequestBounds           { return p.cfg.bounds }
func (p *Provider) BrowserSessionsForTest() bool           { return p.cfg.browserSessions }
func (p *Provider) LogoutConfirmationForTest() bool        { return p.cfg.logoutConfirmation }

// ClientForTest reads a client as the provider's endpoints do.
func (p *Provider) ClientForTest(ctx context.Context, id string) (*RegisteredClient, error) {
	return p.client(ctx, id)
}

// MatchesSecretForTest compares a presented secret as client authentication does.
func (c *RegisteredClient) MatchesSecretForTest(secret []byte, now time.Time) bool {
	return c.matchesSecret(secret, now)
}

// AssertionIDsHeldForTest counts what the default assertion identifier store holds.
func (p *Provider) AssertionIDsHeldForTest() int {
	memory, ok := p.stores.assertionIDs.(*MemoryAssertionIDStore)
	if !ok {
		return -1
	}
	memory.mu.Lock()
	defer memory.mu.Unlock()

	return len(memory.held)
}

// HeldForTest reports whether the pair is held, without recording it.
func (m *MemoryAssertionIDStore) HeldForTest(clientID, jti string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, ok := m.held[assertionIDKey{client: clientID, jti: jti}]

	return ok
}

// WithLogoutNoticesForTest watches what leaves for back-channel delivery.
func WithLogoutNoticesForTest(notices func(context.Context, []ClientToNotify)) Option {
	return func(c *config) { c.logoutNotices = notices }
}

// LogoutTokenForTest signs what a client would be sent, for a key source a row chooses.
func (p *Provider) LogoutTokenForTest(ctx context.Context, c ClientToNotify, rc *RegisteredClient) (string, error) {
	return p.mintLogoutToken(ctx, c, rc)
}

// LogoutFailure is what the seam for a failed delivery is told.
type LogoutFailure = logoutFailure

// WithLogoutFailuresForTest watches what the seam for a failed delivery is told.
func WithLogoutFailuresForTest(failed func(context.Context, LogoutFailure)) Option {
	return func(c *config) { c.logoutFailed = failed }
}

// LogoutTransportForTest is the transport the default delivery posts over.
func LogoutTransportForTest() *http.Transport { return newLogoutTransport() }

// JudgeLogoutAttemptForTest runs what a worker comes to with a delivery's context as a row has it, and its
// answer already in, if answered says so. It names the failure's reason, or says it was only cut off.
func JudgeLogoutAttemptForTest(ctx context.Context, posting bool, answer *LogoutFailure, answered bool) (reason string, cutOff bool) {
	done := make(chan *logoutFailure, 1)
	if answered {
		done <- answer
	}
	got, ok := awaitCall(ctx, done)
	failure, cutOff := judgeAttempt(ctx, ClientToNotify{}, posting, got, ok)
	if failure != nil {
		reason = failure.Reason
	}

	return reason, cutOff
}

// AttemptLogoutForTest runs a job as a worker that has just taken it does.
func (p *Provider) AttemptLogoutForTest(ctx context.Context, c ClientToNotify) {
	p.logouts.attempt(logoutJob{client: c, ctx: ctx}) //nolint:contextcheck // the job carries it, as a worker's does
}
