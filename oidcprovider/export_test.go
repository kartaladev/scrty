package oidcprovider

import (
	"context"
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
