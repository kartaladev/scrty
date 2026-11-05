package httpsec_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"
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
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

// namedUsers is a user loader whose users are renamed while the test runs.
type namedUsers struct {
	mu    sync.Mutex
	names map[identity.UserID]string
}

func (n *namedUsers) rename(user identity.UserID, name string) {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.names[user] = name
}

func (n *namedUsers) load(user identity.UserID) *identity.Details {
	n.mu.Lock()
	defer n.mu.Unlock()

	return &identity.Details{ID: user, Username: n.names[user], Active: true}
}

// usernameChainEndpoint is a provider's token endpoint on a chain whose signed bearer reads
// usernames from the token's subject.
func usernameChainEndpoint(t *testing.T, users *namedUsers) *tokenEndpoint {
	t.Helper()

	clk := clockwork.NewFakeClockAt(time.Now())
	consents := must.Must(oidcprovider.NewMemoryConsentStore())

	loader := NewMockUserLoader(gomock.NewController(t))
	loader.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
		func(_ context.Context, user identity.UserID) (*identity.Details, error) { return users.load(user), nil })

	p, err := oidcprovider.New(oidcprovider.Deps{
		Issuer: opIssuer,
		Clients: []oidcprovider.Client{{
			ID: tokenWeb, Type: oidcprovider.Confidential, Secret: []byte(tokenSecret), RedirectURIs: []string{rpCallback},
			Scopes:     []string{"openid", "profile", "offline_access"},
			GrantTypes: []oidcprovider.GrantType{oidcprovider.GrantAuthorizationCode, oidcprovider.GrantRefreshToken},
		}},
		Keys: tokenKeys(), Users: loader,
		LoginURL: opIssuer + "/login", ConsentURL: opIssuer + "/consent",
		LogoutURL: opIssuer + "/logout-page", LoggedOutURL: opIssuer + "/bye",
	}, oidcprovider.WithClock(clk), oidcprovider.WithConsentStore(consents), oidcprovider.WithoutBrowserSessions())
	require.NoError(t, err)

	// The chain's generator writes usernames, and its bearer reads them. The provider is given
	// neither: it builds its own issuers from its key source.
	gen := must.Must(token.NewGenerator(tokenKeys(), token.WithoutIssuer(), token.WithoutAudience(),
		token.WithClock(clk), token.WithUsernameSubject()))
	verifier := NewMockVerifier(gomock.NewController(t))
	verifier.EXPECT().Verify(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
		func(ctx context.Context, presented string) (*token.Claims, error) { return gen.Verify(ctx, presented) })
	sessions := must.Must(session.New(session.WithClock(clk), session.WithEndObserver(p)))

	chain, err := httpsec.New(
		httpsec.WithClock(clk),
		httpsec.EnableBearerToken(httpsec.BearerTokenDeps{Verifier: verifier, Sessions: sessions, Users: loader},
			httpsec.WithBearerUsernameSubject()),
		httpsec.EnableJWKSEndpoint(tokenKeys()),
		httpsec.EnableSecurityHeaders(),
		httpsec.EnableCSRFProtection(),
		httpsec.EnableOIDCProvider(p),
	)
	require.NoError(t, err)

	return &tokenEndpoint{p: p, chain: chain, clk: clk, consents: consents}
}

// subOf reads the sub of a JWT, without verifying it.
func subOf(t *testing.T, jwt string) string {
	t.Helper()

	parts := strings.Split(jwt, ".")
	require.Len(t, parts, 3, "a JWT")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)

	var claims struct {
		Sub string `json:"sub"`
	}
	require.NoError(t, json.Unmarshal(payload, &claims))

	return claims.Sub
}

func TestOIDCProvider_SubjectIsTheUserIDWhateverSubjectTheChainUses(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// act changes the world between the exchange and a refresh, and the refresh's tokens are what is judged.
		act func(users *namedUsers)
	}

	cases := []testCase{
		{name: "the chain reads usernames", act: func(*namedUsers) {}},
		{name: "the username is renamed and given to another user", act: func(users *namedUsers) {
			users.rename("u-1", "grace")
			users.rename("u-2", "ada")
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			users := &namedUsers{names: map[identity.UserID]string{"u-1": "ada"}}
			e := usernameChainEndpoint(t, users)

			issued := assertTokenIssued(t, e.send(t, exchangeOf(e.issue(t, tokenWeb, nil)), asClient(tokenWeb)), "Bearer")
			assert.Equal(t, "u-1", subOf(t, issued["id_token"].(string)))
			assert.Equal(t, "u-1", subOf(t, issued["access_token"].(string)))

			tc.act(users)

			refreshed := assertTokenIssued(t, e.send(t, refreshOf(issued["refresh_token"].(string)), asClient(tokenWeb)), "Bearer")
			assert.Equal(t, "u-1", subOf(t, refreshed["id_token"].(string)))
			assert.Equal(t, "u-1", subOf(t, refreshed["access_token"].(string)))
		})
	}
}
