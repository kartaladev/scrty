package oidcprovider

// BrowserSessionsEnabled reports whether the provider keeps a browser session of its
// own. It is on unless WithoutBrowserSessions was given. The chain asks, because a
// browser session answers some requests from a cookie, and a cookie needs CSRF
// protection around it.
func (p *Provider) BrowserSessionsEnabled() bool { return p.cfg.browserSessions }

// Issuer returns the issuer identifier the provider was built with, exactly as given.
// It names the provider in its metadata and in the name of the cookie that carries a
// pending authorization request.
func (p *Provider) Issuer() string { return p.issuer }

// RequiresBinding reports whether any client the provider can see at construction
// requires the sender constraint b. BindingOptional is not a requirement, so it
// answers false.
//
// The provider can see the clients of Deps.Clients, and those of a *MemoryRegistry
// given as Deps.Registry. It cannot list a consumer's own registry, so it answers
// false for the clients that registry holds: that is a stated limit, not a statement
// that none requires b. Such a client is checked as it is read, and one requiring a
// binding the chain does not verify is refused then.
func (p *Provider) RequiresBinding(b BindingRequirement) bool {
	if b == BindingOptional {
		return false
	}

	memory, ok := p.registry.(*MemoryRegistry)
	if !ok {
		return false
	}

	memory.mu.RLock()
	defer memory.mu.RUnlock()

	for _, rc := range memory.clients {
		if rc.RequireBinding == b {
			return true
		}
	}

	return false
}
