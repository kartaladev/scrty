package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/kartaladev/scrty/internal/origin"
)

// wellKnownPath is where an issuer publishes its discovery document.
const wellKnownPath = "/.well-known/openid-configuration"

// metadata is what the manager needs from a provider, discovered or pinned.
type metadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

// pinnedMetadata returns the provider's pinned endpoints, and true when all
// three are pinned, so discovery is never needed.
func pinnedMetadata(p Provider) (metadata, bool) {
	if p.AuthorizationEndpoint == "" || p.TokenEndpoint == "" || p.JWKSURI == "" {
		return metadata{}, false
	}
	return metadata{
		Issuer:                p.Issuer,
		AuthorizationEndpoint: p.AuthorizationEndpoint,
		TokenEndpoint:         p.TokenEndpoint,
		JWKSURI:               p.JWKSURI,
		EndSessionEndpoint:    p.EndSessionEndpoint,
	}, true
}

// fetchMetadata returns the provider's metadata: its pinned endpoints when all
// three are pinned, with no request, and otherwise the issuer's discovery
// document, fetched through the outbound client and confined to the issuer.
//
// The document must name the configured issuer exactly, the authorization,
// token and key-set endpoints, and put every endpoint it names on the issuer's
// origin with a scheme the outbound client allows. A pinned end-session
// endpoint wins over a discovered one. Every failure wraps ErrDiscoveryFailed
// and carries no part of the provider's answer.
func (m *Manager) fetchMetadata(ctx context.Context, p Provider) (metadata, error) {
	if md, ok := pinnedMetadata(p); ok {
		return md, nil
	}

	fail := func(format string, args ...any) (metadata, error) {
		return metadata{}, fmt.Errorf("%w: provider %q: discovery: %s", ErrDiscoveryFailed, p.Name, fmt.Sprintf(format, args...))
	}

	res, err := m.out.Get(ctx, strings.TrimSuffix(p.Issuer, "/")+wellKnownPath, nil)
	if err != nil {
		return metadata{}, fmt.Errorf("%w: provider %q: discovery: %w", ErrDiscoveryFailed, p.Name, err)
	}
	if res.Status != http.StatusOK {
		return fail("status %d", res.Status)
	}

	var md metadata
	if err := json.Unmarshal(res.Body, &md); err != nil {
		return fail("the document is not a JSON object")
	}
	if md.Issuer != p.Issuer {
		return fail("the document names another issuer")
	}
	if md.AuthorizationEndpoint == "" || md.TokenEndpoint == "" || md.JWKSURI == "" {
		return fail("a required endpoint is missing")
	}
	for _, raw := range []string{md.AuthorizationEndpoint, md.TokenEndpoint, md.JWKSURI, md.EndSessionEndpoint} {
		if raw == "" {
			continue // only the end-session endpoint may be absent, checked above
		}
		u, err := url.Parse(raw)
		if err != nil || !m.out.AllowsScheme(u.Scheme) || !origin.Same(p.Issuer, raw) {
			return fail("an endpoint is not on the issuer's origin")
		}
	}
	if p.EndSessionEndpoint != "" {
		md.EndSessionEndpoint = p.EndSessionEndpoint // a pin wins over discovery
	}

	return md, nil
}
