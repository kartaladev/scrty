package oidc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
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
// token's sid, empty when there is none), the raw ID token and the flow's
// untrusted Next. It creates no session.
//
// Every failure at or before completing the flow leaves the flow live and is
// joined with ErrFlowUnspent, so the caller keeps the flow cookie: an
// unregistered provider (ErrUnknownProvider), an empty code or a flow the
// store refuses (ErrInvalidState), and a store fault, which is returned as
// itself and logged at ERROR. After completion the flow is spent, and a
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
// ErrUnknownProvider, and a store fault is returned as itself; neither ends
// the flow.
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
// other store error is a fault, logged at ERROR and returned as itself.
func (m *Manager) completeFlow(ctx context.Context, provider, state, handle string) (Flow, error) {
	f, err := m.flows.Complete(ctx, handle, provider, state)
	switch {
	case errors.Is(err, ErrInvalidState):
		return Flow{}, ErrInvalidState
	case err != nil:
		m.logCallbackRefusal(ctx, slog.LevelError, "flow-store-failed", provider, err)
		return Flow{}, err
	case f.Provider != provider:
		return Flow{}, errForeignFlow
	}
	return f, nil
}

// logCallbackRefusal writes one sampled record for a callback failure, keyed
// by reason and provider. cause is the library's own error text or the flow
// store's; neither carries a token, a state, a nonce or a claim value.
func (m *Manager) logCallbackRefusal(ctx context.Context, level slog.Level, reason, provider string, cause error) {
	write, suppressed := m.sampler.Allow("oidc.callback:"+reason+":"+provider, m.now())
	if !write {
		return
	}
	m.log.LogAttrs(ctx, level, "oidc callback failed",
		slog.String("reason", reason),
		slog.String("provider", provider),
		slog.Int("suppressed", suppressed),
		slog.String("error", cause.Error()))
}
