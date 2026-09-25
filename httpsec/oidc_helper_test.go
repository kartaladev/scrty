package httpsec_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/oidc"
)

// testOIDCProvider is the one provider the chain tests' managers register. Its
// endpoints are pinned, so building a manager sends no request.
const testOIDCProvider = "corp"

// newTestOIDCManager builds an OIDC manager for testOIDCProvider over an
// in-memory link store, with brokerOpts configuring the broker it resolves
// identities through. It sends no request: construction never does.
func newTestOIDCManager(t *testing.T, brokerOpts ...oidc.BrokerOption) *oidc.Manager {
	t.Helper()

	registry, err := oidc.NewRegistry(oidc.Provider{ //nolint:gosec // G101: a fixture, not a credential
		Name:                  testOIDCProvider,
		Issuer:                "https://idp.example.com",
		ClientID:              "app",
		ClientSecret:          "secret-" + testOIDCProvider,
		RedirectURL:           "https://app.example.com" + "/login/oauth2/callback/" + testOIDCProvider,
		AuthorizationEndpoint: "https://idp.example.com/authorize",
		TokenEndpoint:         "https://idp.example.com/token",
		JWKSURI:               "https://idp.example.com/jwks",
	})
	require.NoError(t, err)

	broker, err := oidc.NewBroker(oidc.NewMemoryLinkStore(), NewMockUserLoader(gomock.NewController(t)),
		brokerOpts...)
	require.NoError(t, err)

	m, err := oidc.NewManager(registry, broker)
	require.NoError(t, err)

	return m
}

// newTestHandoffManager builds a handoff manager over an in-memory store.
func newTestHandoffManager(t *testing.T) *oidc.HandoffManager {
	t.Helper()

	h, err := oidc.NewHandoffManager(oidc.NewMemoryHandoffStore(), NewMockUserLoader(gomock.NewController(t)))
	require.NoError(t, err)

	return h
}
