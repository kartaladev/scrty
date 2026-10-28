package oidc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/kartaladev/scrty/internal/diag"
)

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
func (m *Manager) Callback(ctx context.Context, provider, code, state, handle string) (CallbackResult, error) {
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
func (m *Manager) AbortFlow(ctx context.Context, provider, state, handle string) (bool, error) {
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
func (m *Manager) completeFlow(ctx context.Context, provider, state, handle string) (Flow, error) {
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
// [Manager]'s package doc). Neither carries a token, a state, a nonce or a
// claim value.
func (m *Manager) logCallbackRefusal(ctx context.Context, level slog.Level, reason, provider string, cause error) {
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
func (m *Manager) logCallbackFailure(ctx context.Context, provider, reason string, err error) {
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
func (m *Manager) logMalformedAssurance(ctx context.Context, provider, claim string) {
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
