package oidcprovider

import "slices"

// consentNeeded decides whether a pending request must go through the consent stage.
// remembered is what the user gave this client, nil for nothing.
//
// prompt=consent always asks. offline_access is asked for unless explicitly consented
// to at a consent stage, which only Consent.Offline records, or the client is
// pre-authorized; first-party or not, and whatever other scopes are remembered (OIDC Core
// section 11). Other scopes a first-party client skips, and any other client needs
// covered by what is remembered. Consent given to another client counts for nothing.
func consentNeeded(c *RegisteredClient, req *PendingRequest, remembered *Consent) bool {
	if slices.Contains(req.Prompt, promptConsent) {
		return true
	}
	if remembered != nil && remembered.ClientID != c.ID {
		remembered = nil
	}

	if slices.Contains(req.Scopes, scopeOffline) && c.OfflineAccess != OfflinePreAuthorized &&
		(remembered == nil || !remembered.Offline) {
		return true
	}
	if c.FirstParty {
		return false
	}
	if remembered == nil {
		return true
	}

	return slices.ContainsFunc(req.Scopes, func(scope string) bool {
		return scope != scopeOffline && !slices.Contains(remembered.Scopes, scope)
	})
}
