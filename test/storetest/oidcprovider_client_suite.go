package storetest

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidcprovider"
)

// ClientRotator is what a client store adds to the port to express a rotation. The
// port's writes hold one secret at a time, so a store with no such method leaves
// ClientStoreSuite's rotation case logged and not run.
type ClientRotator interface {
	PutRegistered(ctx context.Context, rc oidcprovider.RegisteredClient) error
}

// suiteClientSecret is a secret long enough for a consumer to supply.
var suiteClientSecret = []byte("a-consumer-supplied-secret-of-at-least-32-bytes")

// suiteClient is a client with every field a store keeps set to something other than
// its default.
func suiteClient(clientID string) oidcprovider.Client {
	return oidcprovider.Client{
		ID:                     clientID,
		Name:                   "Billing",
		Type:                   oidcprovider.Confidential,
		ApplicationType:        oidcprovider.Native,
		AuthMethod:             oidcprovider.ClientSecretPost,
		PKCE:                   oidcprovider.PKCEOrNonce,
		RedirectURIs:           []string{"https://rp.example.com/cb", "com.example.app:/cb"},
		PostLogoutRedirectURIs: []string{"https://rp.example.com/bye"},
		BackChannelLogoutURI:   "https://rp.example.com/logout",
		Scopes:                 []string{"openid", "profile", "offline_access"},
		Resources:              []string{"https://api.example.com"},
		DefaultAudience:        []string{"https://api.example.com"},
		ResourceIdentifier:     "https://rp.example.com",
		GrantTypes:             []oidcprovider.GrantType{oidcprovider.GrantAuthorizationCode, oidcprovider.GrantRefreshToken},
		FirstParty:             true,
		IDTokenAlg:             "RS256",
		IDTokenLifetime:        4 * time.Minute,
		AccessTokenLifetime:    3 * time.Minute,
		OpaqueAccessTokens:     true,
		RequireBinding:         oidcprovider.BindingDPoP,
		RefreshGrace:           20 * time.Second,
		GrantIdleTimeout:       48 * time.Hour,
		GrantAbsoluteLifetime:  72 * time.Hour,
		DisableRotation:        true,
		EndGrantsWithSignIn:    true,
		Metadata:               map[string]string{"tenant": "a", "tier": "gold"},
	}
}

// ClientStoreSuite holds a client store to the contract oidcprovider.ClientStore
// documents, and MemoryRegistry shows: put and load, a secret held only as its digest,
// GenerateSecret replacing what is held, and Delete. newStore returns an empty store of
// its own for each case. A store that is also a ClientRotator is held to that too.
func ClientStoreSuite(t *testing.T, newStore func(t *testing.T) oidcprovider.ClientStore) {
	t.Helper()

	runSuite(t, clientCases(), withoutClock(newStore))
}

func clientCases() []suiteCase[oidcprovider.ClientStore] {
	type store = oidcprovider.ClientStore

	secretDigest := sha256.Sum256(suiteClientSecret)

	withSecret := func(clientID string) oidcprovider.Client {
		c := suiteClient(clientID)
		c.Secret = suiteClientSecret

		return c
	}

	publicClient := func(clientID string) oidcprovider.Client {
		return oidcprovider.Client{ID: clientID, Type: oidcprovider.Public, RedirectURIs: []string{"https://rp.example.com/cb"}}
	}

	return []suiteCase[store]{
		{
			name: "put and load return every field, with the supplied secret only as its digest",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Put(ctx, withSecret("c-1")))

				got, err := s.Client(ctx, "c-1")
				require.NoError(t, err)
				assert.Empty(t, got.Secret, "a registry holds digests, never a secret")
				require.Len(t, got.Secrets, 1)
				assert.Equal(t, secretDigest[:], []byte(got.Secrets[0].Digest))
				assert.True(t, got.Secrets[0].ExpiresAt.IsZero())

				got.Secret = nil
				assert.Equal(t, suiteClient("c-1"), got.Client)
			},
		},
		{
			name: "an unknown client is not found",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				_, err := s.Client(ctx, "nobody")
				require.ErrorIs(t, err, oidcprovider.ErrClientNotFound)
			},
		},
		{
			name: "a put with no secret keeps the digests held, so a setting does not sign the client out",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Put(ctx, withSecret("c-1")))

				renamed := suiteClient("c-1")
				renamed.Name = "Renamed"
				require.NoError(t, s.Put(ctx, renamed))

				got, err := s.Client(ctx, "c-1")
				require.NoError(t, err)
				assert.Equal(t, "Renamed", got.Name)
				require.Len(t, got.Secrets, 1)
				assert.Equal(t, secretDigest[:], []byte(got.Secrets[0].Digest))
			},
		},
		{
			name: "a put of a client that takes no secret drops the digests held",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Put(ctx, withSecret("c-1")))
				require.NoError(t, s.Put(ctx, publicClient("c-1")))

				got, err := s.Client(ctx, "c-1")
				require.NoError(t, err)
				assert.Empty(t, got.Secrets)
			},
		},
		{
			name: "an invalid client is refused, and what was held stays",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Put(ctx, suiteClient("c-1")))

				invalid := suiteClient("c-1")
				invalid.Type = 0
				require.ErrorIs(t, s.Put(ctx, invalid), oidcprovider.ErrConfig)

				got, err := s.Client(ctx, "c-1")
				require.NoError(t, err)
				assert.Equal(t, oidcprovider.Confidential, got.Type)
			},
		},
		{
			name: "generate secret replaces every secret held, and the secret returned is the digest kept",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Put(ctx, withSecret("c-1")))

				secret, err := s.GenerateSecret(ctx, "c-1")
				require.NoError(t, err)
				assert.NotEmpty(t, secret)

				got, err := s.Client(ctx, "c-1")
				require.NoError(t, err)
				require.Len(t, got.Secrets, 1)
				want := sha256.Sum256([]byte(secret))
				assert.Equal(t, want[:], []byte(got.Secrets[0].Digest))
				assert.Empty(t, got.Secret, "and the secret itself is not held")
			},
		},
		{
			name: "generate secret refuses an unknown client, and one that takes no secret",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				_, err := s.GenerateSecret(ctx, "nobody")
				require.ErrorIs(t, err, oidcprovider.ErrClientNotFound)

				require.NoError(t, s.Put(ctx, publicClient("public")))
				_, err = s.GenerateSecret(ctx, "public")
				require.ErrorIs(t, err, oidcprovider.ErrConfig)
			},
		},
		optionalCase(
			false,
			"put registered holds exactly the secrets given, each with its deadline",
			func(t *testing.T, ctx context.Context, s store, r ClientRotator, _ *clockwork.FakeClock) {
				older, err := oidcprovider.NewClientSecret(suiteClientSecret, suiteStart.Add(time.Hour))
				require.NoError(t, err)
				next, err := oidcprovider.NewClientSecret([]byte("the-next-secret-of-at-least-32-bytes-long"), time.Time{})
				require.NoError(t, err)
				require.NoError(t, r.PutRegistered(ctx, oidcprovider.RegisteredClient{
					Client: suiteClient("c-1"), Secrets: []oidcprovider.ClientSecret{older, next},
				}))

				got, err := s.Client(ctx, "c-1")
				require.NoError(t, err)
				require.Len(t, got.Secrets, 2)
				assert.Equal(t, []byte(older.Digest), []byte(got.Secrets[0].Digest))
				assert.True(t, older.ExpiresAt.Equal(got.Secrets[0].ExpiresAt), "the deadline is kept")
				assert.Equal(t, []byte(next.Digest), []byte(got.Secrets[1].Digest))
				assert.True(t, got.Secrets[1].ExpiresAt.IsZero(), "and no deadline stays none")

				require.NoError(t, r.PutRegistered(ctx, oidcprovider.RegisteredClient{Client: suiteClient("c-1")}))
				got, err = s.Client(ctx, "c-1")
				require.NoError(t, err)
				assert.Empty(t, got.Secrets, "an empty list holds none, unlike a plain put")
			},
		),
		{
			name: "delete removes the client, and a second delete is not found",
			assert: func(t *testing.T, ctx context.Context, s store, _ *clockwork.FakeClock) {
				require.NoError(t, s.Put(ctx, suiteClient("c-1")))
				require.NoError(t, s.Put(ctx, suiteClient("c-2")))

				require.NoError(t, s.Delete(ctx, "c-1"))
				_, err := s.Client(ctx, "c-1")
				require.ErrorIs(t, err, oidcprovider.ErrClientNotFound)
				require.ErrorIs(t, s.Delete(ctx, "c-1"), oidcprovider.ErrClientNotFound)

				_, err = s.Client(ctx, "c-2")
				require.NoError(t, err, "another client is untouched")
			},
		},
	}
}
