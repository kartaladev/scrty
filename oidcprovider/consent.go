package oidcprovider

import (
	"context"
	"errors"
	"slices"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/pkg/id"
)

// consentNeeded decides whether a pending request must go through the consent stage.
// remembered is what the user gave this client, nil for nothing.
//
// A request that answers a device authorization always asks, before anything below is
// looked at: neither a first-party client, nor pre-authorized offline access, nor consent
// already remembered skips it. The consent page is the only place the user confirms that the
// code they typed is the one their device shows, which is what stands between them and an
// attacker who sent them a code of their own (RFC 8628 section 5.4). It has no override.
//
// prompt=consent always asks. offline_access is asked for unless explicitly consented
// to at a consent stage, which only Consent.Offline records, or the client is
// pre-authorized; first-party or not, and whatever other scopes are remembered (OIDC Core
// section 11). Other scopes a first-party client skips, and any other client needs
// covered by what is remembered. Consent given to another client counts for nothing.
func consentNeeded(c *RegisteredClient, req *PendingRequest, remembered *Consent) bool {
	if req.DeviceAuthorizationID != id.Nil || slices.Contains(req.Prompt, promptConsent) {
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

// rememberedConsent reads what user gave the client, and nil for nothing.
func (p *Provider) rememberedConsent(ctx context.Context, user identity.UserID, clientID string) (*Consent, error) {
	remembered, err := p.stores.consents.Load(ctx, user, clientID)
	err = porterr.SanitizeTo(ctx, p.cfg.logger, err, porterr.ErrUnwalkable)
	switch {
	case errors.Is(err, ErrNotFound):
		return nil, nil //nolint:nilnil // nothing remembered is an answer, and no failure
	case err != nil:
		return nil, dependencyFailure(ctx, err, "oidcprovider: load the remembered consent")
	case remembered == nil:
		return nil, dependencyFailure(ctx, errNoRecord, "oidcprovider: load the remembered consent")
	}

	return remembered, nil
}
