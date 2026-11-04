package oidcprovider

import (
	"github.com/kartaladev/scrty/internal/oplineage"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token/onetime"
)

// The stores New settled on, read back by the wiring table.
func (p *Provider) PendingRequestsForTest() PendingRequestStore     { return p.stores.pendingRequests }
func (p *Provider) CodesForTest() CodeStore                         { return p.stores.codes }
func (p *Provider) ConsentsForTest() ConsentStore                   { return p.stores.consents }
func (p *Provider) GrantsForTest() GrantStore                       { return p.stores.grants }
func (p *Provider) CodeTokensForTest() onetime.Store                { return p.stores.codeTokens }
func (p *Provider) AccessTokensForTest() AccessTokenStore           { return p.stores.accessTokens }
func (p *Provider) AssertionIDsForTest() AssertionIDStore           { return p.stores.assertionIDs }
func (p *Provider) BrowserSessionStoreForTest() BrowserSessionStore { return p.stores.browserSessions }

// LineageForTest returns the session store behind the provider's lineage store.
func (p *Provider) LineageForTest() session.Store { return oplineage.Sessions(p.stores.lineage) }

// LineageHeldForTest counts what the default lineage store holds, expired records
// included, and -1 for a store of any other kind.
func (p *Provider) LineageHeldForTest() int {
	lineages, ok := oplineage.Sessions(p.stores.lineage).(*sweepingLineages)
	if !ok {
		return -1
	}
	memory, ok := lineages.Store.(*session.MemoryStore)
	if !ok {
		return -1
	}

	return memory.Len()
}
