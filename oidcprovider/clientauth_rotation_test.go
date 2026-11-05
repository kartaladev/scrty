package oidcprovider_test

import (
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidcprovider"
)

// A client rotating its secret holds the old one until tomorrow and the new one: either
// authenticates until the old one expires, and then only the new one does.
func TestAuthenticateClient_RotationWithTwoSecrets(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(authNow)
	registry, err := oidcprovider.NewMemoryRegistry(nil)
	require.NoError(t, err)

	old, err := oidcprovider.NewClientSecret([]byte(oldSecret), authNow.Add(24*time.Hour))
	require.NoError(t, err)
	current, err := oidcprovider.NewClientSecret([]byte(newSecret), time.Time{})
	require.NoError(t, err)
	require.NoError(t, registry.PutRegistered(t.Context(), oidcprovider.RegisteredClient{
		Client: oidcprovider.Client{
			ID: "rotating-web", Type: oidcprovider.Confidential, AuthMethod: oidcprovider.ClientSecretBasic,
			RedirectURIs: []string{"https://rp.example.com/cb"},
		},
		Secrets: []oidcprovider.ClientSecret{old, current},
	}))

	d := validDeps(t)
	d.Clients = nil
	d.Registry = registry
	p, err := oidcprovider.New(d, oidcprovider.WithClock(clk))
	require.NoError(t, err)

	authenticate := func(secret string) error {
		_, err := p.AuthenticateClient(t.Context(), oidcprovider.ClientCredentials{Authorization: basic("rotating-web", secret)})

		return err
	}

	require.NoError(t, authenticate(oldSecret), "the old secret, expiring tomorrow")
	require.NoError(t, authenticate(newSecret), "the new secret")

	clk.Advance(24*time.Hour + time.Second)
	var refusal *oidcprovider.Error
	require.ErrorAs(t, authenticate(oldSecret), &refusal, "the old secret once it has expired")
	assert.Equal(t, oidcprovider.CodeInvalidClient, refusal.Code)
	require.NoError(t, authenticate(newSecret))
}
