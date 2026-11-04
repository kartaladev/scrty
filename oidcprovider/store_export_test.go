package oidcprovider

// The stores New settled on, read back by the wiring table.
func (p *Provider) PendingRequestsForTest() PendingRequestStore { return p.stores.pendingRequests }
func (p *Provider) CodesForTest() CodeStore                     { return p.stores.codes }
func (p *Provider) ConsentsForTest() ConsentStore               { return p.stores.consents }
func (p *Provider) GrantsForTest() GrantStore                   { return p.stores.grants }
