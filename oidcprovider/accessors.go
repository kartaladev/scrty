package oidcprovider

import (
	"maps"
	"slices"

	"github.com/kartaladev/scrty/token/signingkey"
)

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

// SigningManager returns the *signingkey.Keys the provider signs with, or nil when
// its key source is any other type, a consumer's wrapper included. The chain asks,
// to compare the key set it publishes with what the provider signs with: a source
// that is not a *signingkey.Keys cannot be compared, so the chain does not judge it.
func (p *Provider) SigningManager() *signingkey.Keys {
	keys, _ := p.keys.(*signingkey.Keys)

	return keys
}

// Capabilities is what the provider can state about itself, for the metadata a chain
// publishes. Each list is a fresh copy, sorted unless its comment says otherwise.
type Capabilities struct {
	// Scopes are the scopes a client may be given: openid, profile and email, then
	// offline_access when a client may ask for it, then every other scope a client
	// lists, sorted.
	Scopes []string
	// Claims are the claims an ID token or UserInfo may carry.
	Claims []string
	// IDTokenAlgs are the algorithms the keys can sign ID tokens with.
	IDTokenAlgs []string
	// AssertionAlgs are the algorithms a client assertion may be signed with.
	AssertionAlgs []string
}

// Capabilities reports what the provider can state about itself.
//
// Scopes follow the clients the provider can list, which are those of Deps.Clients and
// of a *MemoryRegistry given as Deps.Registry, read at the call. A consumer's own registry
// cannot be listed, so offline_access is then offered, because a client may ask for it.
func (p *Provider) Capabilities() Capabilities {
	idAlgs := make([]string, 0, len(p.issuers))
	for alg := range p.issuers {
		idAlgs = append(idAlgs, string(alg))
	}
	slices.Sort(idAlgs)

	assertion := slices.Clone(assertionAlgs)
	slices.Sort(assertion)

	return Capabilities{
		Scopes:        p.offeredScopes(),
		Claims:        slices.Clone(offeredClaims),
		IDTokenAlgs:   idAlgs,
		AssertionAlgs: assertion,
	}
}

// offeredClaims are the claims an ID token or UserInfo may carry: those of the tokens
// themselves, and the ones the scopes profile and email release.
var offeredClaims = []string{
	"iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "azp", "sid", "amr", "acr",
	claimName, claimPreferredUsername, claimEmail, claimEmailVerified,
}

// offeredScopes is Capabilities.Scopes.
func (p *Provider) offeredScopes() []string {
	scopes := []string{scopeOpenID, scopeProfile, scopeEmail}

	memory, ok := p.registry.(*MemoryRegistry)
	if !ok {
		return append(scopes, scopeOffline)
	}

	memory.mu.RLock()
	defer memory.mu.RUnlock()

	var offline bool

	others := map[string]struct{}{}

	for _, rc := range memory.clients {
		refreshes := slices.Contains(rc.GrantTypes, GrantRefreshToken)

		for _, s := range rc.Scopes {
			switch {
			case s == scopeOffline:
				offline = offline || refreshes
			case !slices.Contains(scopes, s):
				others[s] = struct{}{}
			}
		}
	}

	if offline {
		scopes = append(scopes, scopeOffline)
	}

	return append(scopes, slices.Sorted(maps.Keys(others))...)
}
