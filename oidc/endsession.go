package oidc

import (
	"context"
	"fmt"
	"net/url"

	"github.com/kartaladev/scrty/session"
)

// EndSessionURL returns the URL that ends the user's session at the named
// provider (OpenID Connect RP-initiated logout), for the caller to send the
// browser to after the local session has ended.
//
// The endpoint is the provider's pinned EndSessionEndpoint, which is used
// without discovery, or else the one its discovery document advertises. The
// URL keeps the endpoint's own well-formed query parameters — a malformed
// pair (net/url.Values.Encode cannot round-trip it) is dropped — and adds
// client_id, id_token_hint (the session's raw ID token),
// post_logout_redirect_uri (WithPostLogoutRedirect, default none) and state.
// An empty value is omitted rather than sent empty, since providers compare
// post_logout_redirect_uri byte for byte; when the endpoint's own query
// already carries one of these four parameters and no value is configured
// for it, that stale value is removed rather than left in place.
//
// A provider with no end-session endpoint, and a name the registry does not
// hold (such as a provider removed since the session began), yield "" and no
// error: there is nothing to end at the provider, and local logout must not
// fail for it. A discovery document that cannot be fetched is
// ErrDiscoveryFailed. No error repeats the ID token or the state.
func (m *Manager) EndSessionURL(ctx context.Context, provider, idTokenHint, state string) (string, error) {
	p, ok := m.registry.Lookup(provider)
	if !ok {
		return "", nil
	}
	endpoint := p.EndSessionEndpoint
	if endpoint == "" {
		md, err := m.metadataFor(ctx, p.Name)
		if err != nil {
			return "", err
		}
		endpoint = md.EndSessionEndpoint
	}
	if endpoint == "" {
		return "", nil
	}

	u, err := url.Parse(endpoint)
	if err != nil {
		// The registry and discovery have already required it to parse.
		return "", fmt.Errorf("%w: provider %q: the end-session endpoint is not a valid URL",
			ErrDiscoveryFailed, p.Name)
	}
	q := u.Query()
	for _, kv := range [...][2]string{
		{"client_id", p.ClientID},
		{"id_token_hint", idTokenHint},
		{"post_logout_redirect_uri", m.postLogoutRedirect},
		{"state", state},
	} {
		if kv[1] != "" {
			q.Set(kv[0], kv[1])
		} else {
			q.Del(kv[0])
		}
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// EndSessionBuilder returns the manager's end-session step over a session:
// its EndSessionURL reads the session's ExternalProvider and ExternalIDToken
// and returns Manager.EndSessionURL for them. A nil session, or one that
// records no provider (a password login, say), yields "" and no error.
//
// The returned value satisfies the http-security chain's end-session
// dependency, which httpsec.EnableOIDCLogin supplies by default.
func (m *Manager) EndSessionBuilder() interface {
	EndSessionURL(ctx context.Context, s *session.Session, state string) (string, error)
} {
	return sessionEndSession{m: m}
}

// sessionEndSession adapts Manager.EndSessionURL to a session.
type sessionEndSession struct{ m *Manager }

func (b sessionEndSession) EndSessionURL(ctx context.Context, s *session.Session, state string) (string, error) {
	if s == nil || s.ExternalProvider == "" {
		return "", nil
	}
	return b.m.EndSessionURL(ctx, s.ExternalProvider, s.ExternalIDToken, state)
}
