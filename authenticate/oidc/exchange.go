package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"unicode/utf8"
)

// maxLoggedProviderBody is how much of a provider's failed token response is
// logged. The rest is dropped: the body is the provider's text, not the
// library's, and an unbounded one would let a provider fill the log.
const maxLoggedProviderBody = 256

// tokenResponse is the part of a token endpoint's answer the library reads.
// The access and refresh tokens are deliberately not decoded: they are
// discarded, never held.
type tokenResponse struct {
	IDToken string `json:"id_token"`
	Error   string `json:"error"`
}

// exchange redeems an authorization code at the provider's token endpoint and
// returns the raw ID token, the only part of the answer the library keeps.
//
// The request carries grant_type, code, redirect_uri and code_verifier, and
// authenticates the client as the provider is configured: client_id and
// client_secret in the form by default (ClientSecretPost), or an HTTP Basic
// Authorization header with neither in the form (ClientSecretBasic). It is
// sent through the outbound client's form POST, so its confinement applies.
//
// An unreachable endpoint, a non-200 answer, an answer that is not a JSON
// object, one carrying an error member, and one without an ID token are all
// ErrExchangeFailed. The provider's answer is logged, truncated, through the
// sampler and is never part of the returned error.
func (m *Manager) exchange(ctx context.Context, p Provider, md metadata, code, verifier string) (string, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {p.RedirectURL},
		"code_verifier": {verifier},
	}
	var header http.Header
	switch p.ClientAuth {
	case ClientSecretBasic:
		// RFC 6749 section 2.3.1: both halves are form-encoded before they are
		// joined, so a colon in the client id cannot move the split.
		creds := url.QueryEscape(p.ClientID) + ":" + url.QueryEscape(p.ClientSecret)
		header = http.Header{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte(creds))}}
	default:
		form.Set("client_id", p.ClientID)
		form.Set("client_secret", p.ClientSecret)
	}

	res, err := m.out.PostForm(ctx, md.TokenEndpoint, form, header)
	if err != nil {
		return "", fmt.Errorf("%w: provider %q: %w", ErrExchangeFailed, p.Name, err)
	}

	if res.Status != http.StatusOK {
		m.logExchangeFailure(ctx, p.Name, "the token endpoint refused the code",
			slog.Int("status", res.Status), slog.String("body", truncateUTF8(res.Body, maxLoggedProviderBody)))
		return "", fmt.Errorf("%w: provider %q: status %d", ErrExchangeFailed, p.Name, res.Status)
	}

	// A success-status body may hold live access and refresh tokens, so from
	// here on no part of it is logged.
	var tr tokenResponse
	switch {
	case json.Unmarshal(res.Body, &tr) != nil:
		m.logExchangeFailure(ctx, p.Name, "the token response is not a JSON object")
		return "", fmt.Errorf("%w: provider %q: the token response is not a JSON object", ErrExchangeFailed, p.Name)
	case tr.Error != "":
		m.logExchangeFailure(ctx, p.Name, "the token response carries an error")
		return "", fmt.Errorf("%w: provider %q: the token response carries an error", ErrExchangeFailed, p.Name)
	case tr.IDToken == "":
		m.logExchangeFailure(ctx, p.Name, "the token response has no ID token")
		return "", fmt.Errorf("%w: provider %q: the token response has no ID token", ErrExchangeFailed, p.Name)
	}

	return tr.IDToken, nil
}

// logExchangeFailure writes one WARN record for a failed exchange through the
// sampler, keyed by provider and reason. attrs never carry a credential: the
// only provider text they may hold is a refused answer's body, truncated.
func (m *Manager) logExchangeFailure(ctx context.Context, provider, reason string, attrs ...slog.Attr) {
	write, suppressed := m.sampler.Allow("oidc.exchange:"+reason+":"+provider, m.clock.Now())
	if !write {
		return
	}
	attrs = append([]slog.Attr{
		slog.String("provider", provider),
		slog.String("reason", reason),
		slog.Int("suppressed", suppressed),
	}, attrs...)
	m.log.LogAttrs(ctx, slog.LevelWarn, "oidc code exchange failed", attrs...)
}

// truncateUTF8 returns at most n bytes of b as a string, cut back to a rune
// boundary so the log record stays valid UTF-8.
func truncateUTF8(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	b = b[:n]
	for len(b) > 0 && !utf8.Valid(b) {
		b = b[:len(b)-1]
	}
	return string(b) + "…"
}
