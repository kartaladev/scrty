package httpsec_test

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/oidcprovider"
)

// unlistedRegistry hides the client set it reads from, as a consumer's database-backed registry does.
type unlistedRegistry struct{ inner oidcprovider.ClientRegistry }

func (r unlistedRegistry) Client(ctx context.Context, id string) (*oidcprovider.RegisteredClient, error) {
	return r.inner.Client(ctx, id)
}

// A client in a consumer's own registry requires a binding the chain does not verify. The registry
// cannot be listed, so the chain builds, and the client is refused at the token endpoint.
func TestEnableOIDCProvider_ConsumersOwnRegistryBuildsAndRefusesAtTheEndpoint(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(time.Now())
	consents := must.Must(oidcprovider.NewMemoryConsentStore())
	memory := must.Must(oidcprovider.NewMemoryRegistry([]oidcprovider.Client{{
		ID: tokenWeb, Type: oidcprovider.Confidential, Secret: []byte(tokenSecret), RedirectURIs: []string{rpCallback},
		Scopes: []string{"openid"}, RequireBinding: oidcprovider.BindingDPoP,
	}}))

	users := NewMockUserLoader(gomock.NewController(t))
	users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
		func(_ context.Context, user identity.UserID) (*identity.Details, error) {
			return &identity.Details{ID: user, Active: true}, nil
		})

	p, err := oidcprovider.New(oidcprovider.Deps{
		Issuer: opIssuer, Registry: unlistedRegistry{memory}, Keys: tokenKeys(), Users: users,
		LoginURL: opIssuer + "/login", ConsentURL: opIssuer + "/consent",
		LogoutURL: opIssuer + "/logout-page", LoggedOutURL: opIssuer + "/bye",
	}, oidcprovider.WithClock(clk), oidcprovider.WithConsentStore(consents),
		oidcprovider.WithoutBrowserSessions())
	require.NoError(t, err)

	f := &opFixture{keys: tokenKeys()}
	chain, err := httpsec.New(append(f.wired(t, p), httpsec.WithClock(clk), httpsec.EnableOIDCProvider(p))...)
	require.NoError(t, err, "a registry that cannot be listed cannot be judged at construction")

	e := &tokenEndpoint{p: p, chain: chain, clk: clk, consents: consents}
	code := e.issue(t, tokenWeb, func(v url.Values) { v.Set("scope", "openid") })

	refused := e.send(t, exchangeOf(code), asClient(tokenWeb))
	assert.Equal(t, 400, refused.status, refused.body)
	assert.NotContains(t, refused.body, "access_token")
}
