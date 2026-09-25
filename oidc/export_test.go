package oidc

import (
	"context"
	"io"
	"log/slog"
	"time"

	"github.com/kartaladev/scrty/outbound"
)

// ManagerWiring is what NewManager resolved, for tests that must see a
// default or a consumer replacement before any request exercises it.
type ManagerWiring struct {
	Out     *outbound.Client
	Random  io.Reader
	Now     func() time.Time
	Flows   FlowStore
	FlowTTL time.Duration
	Log     *slog.Logger
}

// WiringOf exposes m's resolved dependencies to the black-box tests.
func WiringOf(m *Manager) ManagerWiring {
	return ManagerWiring{Out: m.out, Random: m.random, Now: m.now, Flows: m.flows, FlowTTL: m.flowTTL, Log: m.log}
}

// MetadataForTest exposes the manager's provider-metadata lookup.
var MetadataForTest = (*Manager).metadataFor

// MetadataView is the provider metadata the manager resolved.
type MetadataView = metadata

// KeysForTest exposes the manager's key-set lookup.
var KeysForTest = (*Manager).keysFor

// ErrUnknownSigningKeyForTest is the refusal keysFor returns for a key id the
// provider's key set does not hold.
var ErrUnknownSigningKeyForTest = errUnknownSigningKey

// FlowForTest returns the flow s holds under handle, without completing it.
func FlowForTest(s *MemoryFlowStore, handle string) (Flow, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.flows[handle]
	return f, ok
}

// FlowCountForTest returns how many flows s holds, expired ones included.
func FlowCountForTest(s *MemoryFlowStore) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.flows)
}

// ExchangeForTest exchanges code at the named provider's token endpoint, as
// the callback does after completing the flow.
func ExchangeForTest(ctx context.Context, m *Manager, provider, code, verifier string) (string, error) {
	p, ok := m.registry.Lookup(provider)
	if !ok {
		return "", ErrUnknownProvider
	}
	md, err := m.metadataFor(ctx, p.Name)
	if err != nil {
		return "", err
	}
	return m.exchange(ctx, p, md, code, verifier)
}

// IDClaimsView is what ID token verification returns.
type IDClaimsView = idClaims

// VerifyIDTokenForTest verifies raw as an ID token of the named provider for
// a flow holding nonce.
func VerifyIDTokenForTest(ctx context.Context, m *Manager, provider, raw, nonce string) (IDClaimsView, error) {
	p, ok := m.registry.Lookup(provider)
	if !ok {
		return idClaims{}, ErrUnknownProvider
	}
	return m.verifyIDToken(ctx, p, raw, nonce)
}
