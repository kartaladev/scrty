package oidc

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/kartaladev/scrty/internal/diag"
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
// provider's scopes, the state, the nonce and an S256 code challenge. The
// verifier never leaves the flow store. Next is stored verbatim and untrusted;
// allowlisting it is the caller's job.
//
// A name the registry does not hold is ErrUnknownProvider, and an unusable
// provider is ErrDiscoveryFailed; neither stores a flow. A flow store
// refusal, such as ErrFlowStoreFull, comes back wrapped with fixed library
// text; the store's own error stays reachable by identity, so a consumer who
// wants its own detail logs it inside their own implementation of FlowStore.
func (m *Manager) Authorize(ctx context.Context, provider, next string) (Authorization, error) {
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

	var secrets [3]string // state, nonce, verifier
	for i := range secrets {
		if secrets[i], err = randomURLToken(m.random, flowSecretBytes); err != nil {
			return Authorization{}, err
		}
	}
	state, nonce, verifier := secrets[0], secrets[1], secrets[2]

	expires := m.now().Add(m.flowTTL)
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
	endpoint.RawQuery = q.Encode()

	return Authorization{RedirectURL: endpoint.String(), Handle: handle, ExpiresAt: expires}, nil
}
