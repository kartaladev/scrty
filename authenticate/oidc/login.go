package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/origin"
)

// Authorization is where to send a browser to start a login, and the flow it
// started.
type Authorization struct {
	// RedirectURL is the provider's authorization endpoint with every
	// parameter of the request.
	RedirectURL string

	// Handle is the opaque flow handle, for the flow cookie.
	Handle string

	// ExpiresAt is when the flow expires, for the cookie's Max-Age.
	ExpiresAt time.Time
}

// Authorize starts a login at the named provider for a client that asked to
// land on next afterwards.
//
// It draws a fresh state, nonce and PKCE verifier of 32 bytes each from the
// manager's random source, stores them in a flow that expires after the flow
// TTL (DefaultFlowTTL unless WithFlowTTL), and returns the provider's
// authorization endpoint carrying the client id, the redirect URL, the
// provider's scopes, the state, the nonce and an S256 code challenge, plus
// acr_values when the provider's Assurance lists RequestACR (none by default;
// see WithProviderAssurance). The verifier never leaves the flow store. Next
// is stored verbatim and untrusted; allowlisting it is the caller's job. A next
// longer than 2048 bytes is not stored: no allowlist entry can be that long,
// so the login proceeds as if none was requested and ends at the default
// destination. The bound is fixed.
//
// A name the registry does not hold is ErrUnknownProvider, and an unusable
// provider is ErrDiscoveryFailed; neither stores a flow. A flow store
// refusal, such as ErrFlowStoreFull, comes back wrapped with fixed library
// text; the store's own error stays reachable by identity, so a consumer who
// wants its own detail logs it inside their own implementation of FlowStore.
func (m *RelyingParty) Authorize(ctx context.Context, provider, next string) (Authorization, error) {
	p, ok := m.registry.Lookup(provider)
	if !ok {
		return Authorization{}, ErrUnknownProvider
	}
	md, err := m.metadataFor(ctx, p.Name)
	if err != nil {
		return Authorization{}, err
	}
	endpoint, err := url.Parse(md.AuthorizationEndpoint)
	if err != nil {
		return Authorization{}, fmt.Errorf("%w: provider %q: unusable authorization endpoint", ErrDiscoveryFailed, p.Name)
	}

	if len(next) > origin.MaxEntryLen {
		next = ""
	}

	var secrets [3]string // state, nonce, verifier
	for i := range secrets {
		if secrets[i], err = randomURLToken(m.random, flowSecretBytes); err != nil {
			return Authorization{}, err
		}
	}
	state, nonce, verifier := secrets[0], secrets[1], secrets[2]

	expires := m.clock.Now().Add(m.flowTTL)
	handle, err := m.flows.Begin(ctx, Flow{
		Provider: p.Name, State: state, Nonce: nonce, Verifier: verifier, Next: next, ExpiresAt: expires,
	})
	if err != nil {
		return Authorization{}, diag.Wrap(err, "oidc: storing the login flow")
	}

	q := endpoint.Query()
	q.Set("response_type", "code")
	q.Set("client_id", p.ClientID)
	q.Set("redirect_uri", p.RedirectURL)
	q.Set("scope", strings.Join(p.Scopes, " "))
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", s256Challenge(verifier))
	q.Set("code_challenge_method", "S256")
	if a, _ := m.assuranceFor(p.Name); len(a.RequestACR) > 0 {
		q.Set("acr_values", strings.Join(a.RequestACR, " "))
	}
	endpoint.RawQuery = q.Encode()

	return Authorization{RedirectURL: endpoint.String(), Handle: handle, ExpiresAt: expires}, nil
}

// errForeignFlow is a refusal of a flow the store completed for another
// provider than the one asked for. Unlike a plain ErrInvalidState the store
// has consumed the flow, so it is spent.
var errForeignFlow = fmt.Errorf("%w: the flow store completed another provider's flow", ErrInvalidState)

// Callback completes a login the provider has redirected back with a code.
//
// It completes the flow the handle names, bound to provider and state, then
// exchanges the code with the flow's PKCE verifier, verifies the ID token
// against the flow's nonce and resolves the identity through the broker. It
// returns the principal, the provider, its issuer, the provider session (the
// token's sid, empty when there is none), the raw ID token, the flow's
// untrusted Next, and the amr and acr the token asserted (see
// CallbackResult.AMR). It creates no session.
//
// The token's amr and acr claims are the only source of provider assurance.
// One present in a form that asserts nothing, such as an amr that is not an
// array of strings, is treated as absent: it never fails the login, and it
// writes a sampled warning naming the provider and the claim, never its value.
//
// Every failure at or before completing the flow leaves the flow live and is
// joined with ErrFlowUnspent, so the caller keeps the flow cookie: an
// unregistered provider (ErrUnknownProvider), an empty code or a flow the
// store refuses (ErrInvalidState), and a store fault, which comes back
// wrapped with fixed library text — still matching the store's own error by
// identity — and logged at ERROR. After completion the flow is spent, and a
// failure is returned without the marker: ErrInvalidState when the store
// completed a flow of another provider, ErrDiscoveryFailed,
// ErrExchangeFailed, ErrInvalidIDToken, or the broker's error as the broker
// returned it (ErrNoLinkedAccount, ErrProvisioningRefused, or a failure).
func (m *RelyingParty) Callback(ctx context.Context, provider, code, state, handle string) (CallbackResult, error) {
	unspent := func(err error) (CallbackResult, error) {
		return CallbackResult{}, errors.Join(err, ErrFlowUnspent)
	}

	p, ok := m.registry.Lookup(provider)
	if !ok {
		return unspent(ErrUnknownProvider)
	}
	if code == "" {
		return unspent(ErrInvalidState)
	}
	f, err := m.completeFlow(ctx, p.Name, state, handle)
	switch {
	case errors.Is(err, errForeignFlow):
		// The store completed, and so spent, a flow of another provider.
		return CallbackResult{}, ErrInvalidState
	case err != nil:
		return unspent(err)
	}

	// From here the flow is spent: no return carries ErrFlowUnspent.
	md, err := m.metadataFor(ctx, p.Name)
	if err != nil {
		return CallbackResult{}, err
	}
	raw, err := m.exchange(ctx, p, md, code, f.Verifier)
	if err != nil {
		return CallbackResult{}, err
	}
	claims, err := m.verifyIDToken(ctx, p, raw, f.Nonce)
	if err != nil {
		if errors.Is(err, ErrInvalidIDToken) {
			m.logCallbackRefusal(ctx, slog.LevelWarn, "invalid-id-token", p.Name, err)
		}
		return CallbackResult{}, err
	}
	if claims.MalformedAMR {
		m.logMalformedAssurance(ctx, p.Name, "amr")
	}
	if claims.MalformedACR {
		m.logMalformedAssurance(ctx, p.Name, "acr")
	}

	principal, err := m.broker.Broker(ctx, ExternalIdentity{
		Provider:      p.Name,
		Issuer:        p.Issuer,
		Subject:       claims.Subject,
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
		Claims:        claims.Claims,
	})
	if err != nil {
		return CallbackResult{}, err
	}
	if principal == nil {
		return CallbackResult{}, fmt.Errorf("oidc: provider %q: the identity broker returned no principal and no error", p.Name)
	}

	return CallbackResult{
		Principal: principal,
		Provider:  p.Name,
		Issuer:    p.Issuer,
		SessionID: claims.SessionID,
		IDToken:   raw,
		Next:      f.Next,
		AMR:       claims.AMR,
		ACR:       claims.ACR,
	}, nil
}

// AbortFlow ends the flow when the echoed state completes it, and reports
// whether it did. It is the error branch of the callback: a provider that
// redirects back with an error echoes the flow's state.
//
// Only when it returns true may the caller clear the flow cookie or log the
// provider's error text. A state that does not complete the flow, including an
// empty one, changes nothing and returns false with no error, so a forged
// error link cannot cancel someone else's login. An unregistered provider is
// ErrUnknownProvider, and a store fault comes back wrapped with fixed library
// text, still matching the store's own error by identity; neither ends the
// flow.
func (m *RelyingParty) AbortFlow(ctx context.Context, provider, state, handle string) (bool, error) {
	p, ok := m.registry.Lookup(provider)
	if !ok {
		return false, ErrUnknownProvider
	}
	_, err := m.completeFlow(ctx, p.Name, state, handle)
	switch {
	case errors.Is(err, errForeignFlow):
		return true, nil // the store spent it; it cannot be completed again
	case errors.Is(err, ErrInvalidState):
		return false, nil
	case err != nil:
		return false, err
	}
	return true, nil
}

// completeFlow completes the flow through the store and checks that the flow
// it returns belongs to provider, so a store that ignored the binding cannot
// hand one provider's flow to another's callback.
//
// A refusal is ErrInvalidState. A flow of another provider is errForeignFlow:
// the store has already consumed it, so the flow is spent though refused. Any
// other store error is a fault, logged at ERROR and returned wrapped with
// fixed library text; a consumer who wants its own detail logs it inside
// their own implementation of FlowStore.
func (m *RelyingParty) completeFlow(ctx context.Context, provider, state, handle string) (Flow, error) {
	f, err := m.flows.Complete(ctx, handle, provider, state)
	switch {
	case errors.Is(err, ErrInvalidState):
		return Flow{}, ErrInvalidState
	case err != nil:
		m.logCallbackFailure(ctx, provider, "flow-store", err)
		return Flow{}, diag.Wrap(err, "oidc: completing the login flow")
	case f.Provider != provider:
		return Flow{}, errForeignFlow
	}
	return f, nil
}

// logCallbackRefusal writes one sampled record for a callback failure, keyed
// by reason and provider. cause is the library's own error text — never a
// consumer dependency's: an invalid ID token's verification failure is the
// only caller, and its text is a deliberate exception operators keep (see
// [RelyingParty]'s package doc). Neither carries a token, a state, a nonce or a
// claim value.
func (m *RelyingParty) logCallbackRefusal(ctx context.Context, level slog.Level, reason, provider string, cause error) {
	write, suppressed := m.sampler.Allow("oidc.callback:"+reason+":"+provider, m.clock.Now())
	if !write {
		return
	}
	m.log.LogAttrs(ctx, level, "oidc callback failed",
		slog.String("reason", reason),
		slog.String("provider", provider),
		slog.Int("suppressed", suppressed),
		slog.String("error", cause.Error())) //nolint:forbidigo // stated exception (design decision 6): ID-token verification text
}

// logCallbackFailure writes one sampled record for a callback failure caused
// by a consumer-supplied dependency — the flow store. The record carries
// diag.Failure's fixed reason and the error's type, never the store's own
// text, so a consumer who wants that detail logs it inside their own
// implementation of FlowStore.
func (m *RelyingParty) logCallbackFailure(ctx context.Context, provider, reason string, err error) {
	write, suppressed := m.sampler.Allow("oidc.callback:"+reason+":"+provider, m.clock.Now())
	if !write {
		return
	}
	attrs := append([]slog.Attr{
		slog.String("provider", provider),
		slog.Int("suppressed", suppressed),
	}, diag.Failure(reason, err)...)
	m.log.LogAttrs(ctx, slog.LevelError, "oidc callback failed", attrs...)
}

// malformedAssuranceReason is the reason, and the sampler key's middle part,
// of the warning about an amr or acr claim the ID token carried in a form that
// asserts nothing.
const malformedAssuranceReason = "malformed-assurance-claim"

// logMalformedAssurance writes one sampled warning that the verified ID token
// of provider carried claim ("amr" or "acr") in a form that asserts nothing.
// The login goes on with that claim not asserted. The record names the
// provider and the claim, never the claim's value. Warnings share the key
// "oidc.callback:malformed-assurance-claim:<provider>", so a provider whose
// every token is malformed writes one record per sampling window.
func (m *RelyingParty) logMalformedAssurance(ctx context.Context, provider, claim string) {
	write, suppressed := m.sampler.Allow("oidc.callback:"+malformedAssuranceReason+":"+provider, m.clock.Now())
	if !write {
		return
	}
	m.log.LogAttrs(ctx, slog.LevelWarn, "oidc assurance claim ignored",
		slog.String("reason", malformedAssuranceReason),
		slog.String("provider", provider),
		slog.String("claim", claim),
		slog.Int("suppressed", suppressed))
}

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
func (m *RelyingParty) exchange(ctx context.Context, p Provider, md metadata, code, verifier string) (string, error) {
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
func (m *RelyingParty) logExchangeFailure(ctx context.Context, provider, reason string, attrs ...slog.Attr) {
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
