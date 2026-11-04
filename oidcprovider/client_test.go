package oidcprovider_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lestrrat-go/jwx/v4/jwk"

	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token/signingkey"
)

const (
	day = 24 * time.Hour

	// rfc7517Key is the public key of RFC 7517 appendix A.1.
	rfc7517Key = `{"keys":[{"kty":"EC","crv":"P-256",` +
		`"x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",` +
		`"y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}]}`
)

// reportingKeys is a key source that reports the lifetimes it is given.
type reportingKeys struct {
	signingkey.KeySource
	lifetime, rotate time.Duration
}

func (k reportingKeys) KeyLifetime() time.Duration    { return k.lifetime }
func (k reportingKeys) RotateInterval() time.Duration { return k.rotate }

// keySet is a JWKS holding the given raw keys.
func keySet(t *testing.T, raw ...any) []byte {
	t.Helper()

	keys := make([]json.RawMessage, 0, len(raw))
	for _, r := range raw {
		key, err := jwk.Import[jwk.Key](r)
		require.NoError(t, err)
		encoded, err := json.Marshal(key)
		require.NoError(t, err)
		keys = append(keys, encoded)
	}
	out, err := json.Marshal(map[string]any{"keys": keys})
	require.NoError(t, err)

	return out
}

func TestClient_Validation(t *testing.T) {
	t.Parallel()

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	ecRaw, err := ecKey.Bytes()
	require.NoError(t, err)
	octKey := []byte("a symmetric key of thirty-two bytes")

	newKeys := func(opts ...signingkey.Option) *signingkey.Keys {
		keys, err := signingkey.New(t.Context(), append([]signingkey.Option{
			signingkey.WithKeyStore(signingkey.NewMemoryKeyStore()),
		}, opts...)...)
		require.NoError(t, err)

		return keys
	}
	rsaOnly := newKeys(signingkey.WithAlgs(signingkey.RS256))
	ecOnly := newKeys(signingkey.WithAlgs(signingkey.ES256))
	// A usable window of one hour: the key lifetime minus the rotate interval.
	capped := newKeys(signingkey.WithAlgs(signingkey.RS256),
		signingkey.WithKeyLifetime(2*time.Hour), signingkey.WithRotateInterval(time.Hour))

	type testCase struct {
		name   string
		client func(c *oidcprovider.Client)
		// clients replaces the single client, for rows about several.
		clients []oidcprovider.Client
		keys    signingkey.KeySource
		assert  func(t *testing.T, got *oidcprovider.RegisteredClient, err error)
	}

	refused := func(setting string) func(*testing.T, *oidcprovider.RegisteredClient, error) {
		return func(t *testing.T, _ *oidcprovider.RegisteredClient, err error) {
			t.Helper()
			require.ErrorIs(t, err, oidcprovider.ErrConfig)
			assert.ErrorContains(t, err, "billing-web")
			assert.ErrorContains(t, err, setting)
		}
	}
	// refusedKey also holds that the error names no key material.
	refusedKey := func(material ...[]byte) func(*testing.T, *oidcprovider.RegisteredClient, error) {
		return func(t *testing.T, _ *oidcprovider.RegisteredClient, err error) {
			t.Helper()
			refused("JWKS")(t, nil, err)
			for _, m := range material {
				assert.NotContains(t, err.Error(), string(m))
				assert.NotContains(t, err.Error(), base64.RawURLEncoding.EncodeToString(m))
			}
		}
	}
	accepted := func(t *testing.T, got *oidcprovider.RegisteredClient, err error) {
		t.Helper()
		require.NoError(t, err)
		require.NotNil(t, got)
	}

	public := func(c *oidcprovider.Client) {
		c.Type = oidcprovider.Public
		c.Secret = nil
	}
	native := func(c *oidcprovider.Client) { c.ApplicationType = oidcprovider.Native }
	redirect := func(uri string) func(*oidcprovider.Client) {
		return func(c *oidcprovider.Client) { c.RedirectURIs = []string{uri} }
	}
	nativeRedirect := func(uri string) func(*oidcprovider.Client) {
		return func(c *oidcprovider.Client) {
			native(c)
			c.RedirectURIs = []string{uri}
		}
	}

	cases := []testCase{
		// Identity and kind.
		{name: "a valid client", assert: accepted},
		{name: "empty identifier", client: func(c *oidcprovider.Client) { c.ID = "" }, assert: func(t *testing.T, _ *oidcprovider.RegisteredClient, err error) {
			t.Helper()
			require.ErrorIs(t, err, oidcprovider.ErrConfig)
			assert.ErrorContains(t, err, "ID")
		}},
		{name: "identifier with a control character", client: func(c *oidcprovider.Client) { c.ID = "billing-web\n" }, assert: refused("ID")},
		{name: "no client type", client: func(c *oidcprovider.Client) { c.Type = 0 }, assert: refused("Type")},
		{name: "unknown client type", client: func(c *oidcprovider.Client) { c.Type = 9 }, assert: refused("Type")},
		{name: "unknown application type", client: func(c *oidcprovider.Client) { c.ApplicationType = 9 }, assert: refused("ApplicationType")},

		// Authentication method.
		{
			name: "public client with client_secret_basic",
			client: func(c *oidcprovider.Client) {
				public(c)
				c.AuthMethod = oidcprovider.ClientSecretBasic
			},
			assert: refused("AuthMethod"),
		},
		{
			name: "public client with private_key_jwt",
			client: func(c *oidcprovider.Client) {
				public(c)
				c.AuthMethod = oidcprovider.PrivateKeyJWT
				c.JWKS = []byte(rfc7517Key)
			},
			assert: refused("AuthMethod"),
		},
		{name: "confidential client with none", client: func(c *oidcprovider.Client) { c.AuthMethod = oidcprovider.AuthMethodNone }, assert: refused("AuthMethod")},
		{name: "client_secret_jwt", client: func(c *oidcprovider.Client) { c.AuthMethod = "client_secret_jwt" }, assert: refused("AuthMethod")},
		{name: "unknown method", client: func(c *oidcprovider.Client) { c.AuthMethod = "tls_client_auth" }, assert: refused("AuthMethod")},
		{
			name: "confidential client's default method",
			assert: func(t *testing.T, got *oidcprovider.RegisteredClient, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, oidcprovider.ClientSecretBasic, got.AuthMethod)
			},
		},
		{
			name:   "public client's default method",
			client: public,
			assert: func(t *testing.T, got *oidcprovider.RegisteredClient, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, oidcprovider.AuthMethodNone, got.AuthMethod)
			},
		},

		// Credentials.
		{name: "supplied secret of 20 bytes", client: func(c *oidcprovider.Client) { c.Secret = make([]byte, 20) }, assert: refused("Secret")},
		{name: "supplied secret of 32 bytes", client: func(c *oidcprovider.Client) { c.Secret = make([]byte, 32) }, assert: accepted},
		{name: "secret method with no way to get a secret", client: func(c *oidcprovider.Client) { c.Secret = nil }, assert: refused("Secret")},
		{
			name: "secret on a public client",
			client: func(c *oidcprovider.Client) {
				public(c)
				c.Secret = make([]byte, 32)
			},
			assert: refused("Secret"),
		},
		{
			name: "secret on a private_key_jwt client",
			client: func(c *oidcprovider.Client) {
				c.AuthMethod = oidcprovider.PrivateKeyJWT
				c.JWKS = []byte(rfc7517Key)
			},
			assert: refused("Secret"),
		},
		{
			name: "private_key_jwt with a registered key set",
			client: func(c *oidcprovider.Client) {
				c.AuthMethod, c.Secret = oidcprovider.PrivateKeyJWT, nil
				c.JWKS = []byte(rfc7517Key)
			},
			assert: accepted,
		},
		{
			name: "private_key_jwt with a key set URL",
			client: func(c *oidcprovider.Client) {
				c.AuthMethod, c.Secret = oidcprovider.PrivateKeyJWT, nil
				c.JWKSURI = "https://rp.example.com/jwks"
			},
			assert: accepted,
		},
		{
			name: "private_key_jwt with no keys",
			client: func(c *oidcprovider.Client) {
				c.AuthMethod, c.Secret = oidcprovider.PrivateKeyJWT, nil
			},
			assert: refused("JWKS"),
		},
		{
			name: "private_key_jwt with both key sources",
			client: func(c *oidcprovider.Client) {
				c.AuthMethod, c.Secret = oidcprovider.PrivateKeyJWT, nil
				c.JWKS = []byte(rfc7517Key)
				c.JWKSURI = "https://rp.example.com/jwks"
			},
			assert: refused("JWKS"),
		},
		{
			name: "a key set URL naming no host",
			client: func(c *oidcprovider.Client) {
				c.AuthMethod, c.Secret = oidcprovider.PrivateKeyJWT, nil
				c.JWKSURI = "https:///jwks"
			},
			assert: refused("JWKSURI"),
		},
		{
			name: "a registered key set that does not parse",
			client: func(c *oidcprovider.Client) {
				c.AuthMethod, c.Secret = oidcprovider.PrivateKeyJWT, nil
				c.JWKS = []byte("not json")
			},
			assert: refused("JWKS"),
		},
		{
			name: "a key set URL over http",
			client: func(c *oidcprovider.Client) {
				c.AuthMethod, c.Secret = oidcprovider.PrivateKeyJWT, nil
				c.JWKSURI = "http://rp.example.com/jwks"
			},
			assert: refused("JWKSURI"),
		},
		{
			name: "a symmetric key in the key set",
			client: func(c *oidcprovider.Client) {
				c.AuthMethod, c.Secret = oidcprovider.PrivateKeyJWT, nil
				c.JWKS = keySet(t, octKey)
			},
			assert: refusedKey(octKey),
		},
		{
			name: "a private EC key in the key set",
			client: func(c *oidcprovider.Client) {
				c.AuthMethod, c.Secret = oidcprovider.PrivateKeyJWT, nil
				c.JWKS = keySet(t, ecKey)
			},
			assert: refusedKey(ecRaw),
		},
		{
			name: "a private RSA key in the key set",
			client: func(c *oidcprovider.Client) {
				c.AuthMethod, c.Secret = oidcprovider.PrivateKeyJWT, nil
				c.JWKS = keySet(t, rsaKey)
			},
			assert: refusedKey(rsaKey.D.Bytes()),
		},
		{
			name: "a private OKP key in the key set",
			client: func(c *oidcprovider.Client) {
				c.AuthMethod, c.Secret = oidcprovider.PrivateKeyJWT, nil
				c.JWKS = keySet(t, edKey)
			},
			assert: refusedKey(edKey.Seed()),
		},
		{
			name: "a private key beside a public one",
			client: func(c *oidcprovider.Client) {
				c.AuthMethod, c.Secret = oidcprovider.PrivateKeyJWT, nil
				c.JWKS = keySet(t, &ecKey.PublicKey, rsaKey)
			},
			assert: refusedKey(rsaKey.D.Bytes()),
		},
		{
			name: "public keys of every type in the key set",
			client: func(c *oidcprovider.Client) {
				c.AuthMethod, c.Secret = oidcprovider.PrivateKeyJWT, nil
				c.JWKS = keySet(t, &ecKey.PublicKey, &rsaKey.PublicKey, edKey.Public())
			},
			assert: accepted,
		},
		{name: "keys on a secret client", client: func(c *oidcprovider.Client) { c.JWKS = []byte(rfc7517Key) }, assert: refused("JWKS")},

		// Redirect URIs.
		{name: "no redirect URI", client: func(c *oidcprovider.Client) { c.RedirectURIs = nil }, assert: refused("RedirectURIs")},
		{
			name: "no redirect URI and no authorization endpoint",
			client: func(c *oidcprovider.Client) {
				c.RedirectURIs = nil
				c.GrantTypes = []oidcprovider.GrantType{oidcprovider.GrantRefreshToken}
			},
			assert: accepted,
		},
		{name: "wildcard", client: redirect("https://*.example.com/cb"), assert: refused("RedirectURIs")},
		{name: "wildcard in the path", client: redirect("https://rp.example.com/*"), assert: refused("RedirectURIs")},
		{name: "fragment", client: redirect("https://rp.example.com/cb#x"), assert: refused("RedirectURIs")},
		{name: "empty fragment", client: redirect("https://rp.example.com/cb#"), assert: refused("RedirectURIs")},
		{name: "relative", client: redirect("/cb"), assert: refused("RedirectURIs")},
		{name: "http for a web client", client: redirect("http://rp.example.com/cb"), assert: refused("RedirectURIs")},
		{name: "loopback http for a web client", client: redirect("http://127.0.0.1/cb"), assert: refused("RedirectURIs")},
		{name: "private-use scheme for a web client", client: redirect("com.example.app:/cb"), assert: refused("RedirectURIs")},
		{name: "https redirect URI naming no host", client: redirect("https:///cb"), assert: refused("RedirectURIs")},
		{name: "a query is kept", client: redirect("https://rp.example.com/cb?tenant=a"), assert: accepted},
		{
			name:   "user information, not repeated in the error",
			client: redirect("https://u:hunter2@rp.example.com/cb"),
			assert: func(t *testing.T, _ *oidcprovider.RegisteredClient, err error) {
				t.Helper()
				refused("RedirectURIs")(t, nil, err)
				assert.NotContains(t, err.Error(), "hunter2")
			},
		},
		{name: "javascript", client: redirect("javascript:alert(1)"), assert: refused("RedirectURIs")},
		{name: "native https", client: nativeRedirect("https://rp.example.com/cb"), assert: accepted},
		{name: "native private-use scheme", client: nativeRedirect("com.example.app:/cb"), assert: accepted},
		{name: "native private-use scheme with no period", client: nativeRedirect("myapp:/cb"), assert: refused("RedirectURIs")},
		{name: "native private-use scheme naming nothing", client: nativeRedirect("com.example.app:"), assert: refused("RedirectURIs")},
		{name: "native loopback IPv4", client: nativeRedirect("http://127.0.0.1/cb"), assert: accepted},
		{name: "native loopback IPv6", client: nativeRedirect("http://[::1]/cb"), assert: accepted},
		{name: "native http to a name", client: nativeRedirect("http://localhost/cb"), assert: refused("RedirectURIs")},
		{name: "native http to another host", client: nativeRedirect("http://rp.example.com/cb"), assert: refused("RedirectURIs")},
		{name: "native http to another loopback address", client: nativeRedirect("http://127.0.0.2/cb"), assert: refused("RedirectURIs")},
		{name: "native javascript", client: nativeRedirect("javascript:alert(1)"), assert: refused("RedirectURIs")},
		{name: "native javascript in capitals", client: nativeRedirect("JAVASCRIPT:alert(1)"), assert: refused("RedirectURIs")},
		{name: "native data", client: nativeRedirect("data:text/html,x"), assert: refused("RedirectURIs")},
		{name: "native vbscript", client: nativeRedirect("vbscript:x"), assert: refused("RedirectURIs")},
		{name: "native file", client: nativeRedirect("file:///etc/passwd"), assert: refused("RedirectURIs")},
		{
			name:   "post-logout wildcard",
			client: func(c *oidcprovider.Client) { c.PostLogoutRedirectURIs = []string{"https://rp.example.com/*"} },
			assert: refused("PostLogoutRedirectURIs"),
		},
		{
			name:   "post-logout accepted",
			client: func(c *oidcprovider.Client) { c.PostLogoutRedirectURIs = []string{"https://rp.example.com/bye"} },
			assert: accepted,
		},
		{
			name:   "back-channel over http",
			client: func(c *oidcprovider.Client) { c.BackChannelLogoutURI = "http://rp.example.com/logout" },
			assert: refused("BackChannelLogoutURI"),
		},
		{
			name:   "back-channel naming no host",
			client: func(c *oidcprovider.Client) { c.BackChannelLogoutURI = "https:///logout" },
			assert: refused("BackChannelLogoutURI"),
		},
		{
			name:   "back-channel with a fragment",
			client: func(c *oidcprovider.Client) { c.BackChannelLogoutURI = "https://rp.example.com/logout#x" },
			assert: refused("BackChannelLogoutURI"),
		},
		{
			name:   "back-channel over https",
			client: func(c *oidcprovider.Client) { c.BackChannelLogoutURI = "https://rp.example.com/logout" },
			assert: accepted,
		},

		// PKCE (R1).
		{
			name: "PKCEOrNonce on a public client",
			client: func(c *oidcprovider.Client) {
				public(c)
				c.PKCE = oidcprovider.PKCEOrNonce
			},
			assert: refused("PKCE"),
		},
		{name: "PKCEOrNonce on a confidential client", client: func(c *oidcprovider.Client) { c.PKCE = oidcprovider.PKCEOrNonce }, assert: accepted},
		{name: "unknown PKCE requirement", client: func(c *oidcprovider.Client) { c.PKCE = 9 }, assert: refused("PKCE")},

		// Lifetimes (R6).
		{
			name:   "ID token lifetime past the key cap",
			client: func(c *oidcprovider.Client) { c.IDTokenLifetime = 61 * time.Minute },
			keys:   capped,
			assert: refused("IDTokenLifetime"),
		},
		{
			name:   "access token lifetime past the key cap",
			client: func(c *oidcprovider.Client) { c.AccessTokenLifetime = 61 * time.Minute },
			keys:   capped,
			assert: refused("AccessTokenLifetime"),
		},
		{
			name: "lifetimes at the key cap",
			client: func(c *oidcprovider.Client) {
				c.IDTokenLifetime = time.Hour
				c.AccessTokenLifetime = time.Hour
			},
			keys:   capped,
			assert: accepted,
		},
		{
			name:   "keys that leave no usable window refuse every lifetime",
			keys:   reportingKeys{KeySource: plainKeys(t), lifetime: time.Hour, rotate: time.Hour},
			assert: refused("IDTokenLifetime"),
		},
		{name: "no cap from a source that reports none", client: func(c *oidcprovider.Client) { c.AccessTokenLifetime = 100 * day }, assert: accepted},
		{name: "negative ID token lifetime", client: func(c *oidcprovider.Client) { c.IDTokenLifetime = -time.Second }, assert: refused("IDTokenLifetime")},
		{name: "fractional access token lifetime", client: func(c *oidcprovider.Client) { c.AccessTokenLifetime = 1500 * time.Millisecond }, assert: refused("AccessTokenLifetime")},

		// Audiences and resources: a value no authorization request could carry fails here.
		{name: "a default audience and a resource, both absolute", client: func(c *oidcprovider.Client) {
			c.DefaultAudience = []string{"https://api.example.com", "https://api.example.com/v2?tenant=a"}
			c.Resources = []string{"https://orders.example.com", "urn:example:billing"}
		}, assert: accepted},
		{name: "a default audience that is blank", client: func(c *oidcprovider.Client) { c.DefaultAudience = []string{" "} }, assert: refused("DefaultAudience")},
		{name: "a default audience that is empty", client: func(c *oidcprovider.Client) { c.DefaultAudience = []string{""} }, assert: refused("DefaultAudience")},
		{name: "a default audience that is relative", client: func(c *oidcprovider.Client) { c.DefaultAudience = []string{"api"} }, assert: refused("DefaultAudience")},
		{name: "a default audience with a fragment", client: func(c *oidcprovider.Client) {
			c.DefaultAudience = []string{"https://api.example.com", "https://api.example.com#part"}
		}, assert: refused("DefaultAudience[1]")},
		{name: "a default audience with an empty fragment", client: func(c *oidcprovider.Client) {
			c.DefaultAudience = []string{"https://api.example.com#"}
		}, assert: refused("DefaultAudience")},
		{name: "a default audience with surrounding space", client: func(c *oidcprovider.Client) {
			c.DefaultAudience = []string{" https://api.example.com"}
		}, assert: refused("DefaultAudience")},
		{name: "a resource that is blank", client: func(c *oidcprovider.Client) { c.Resources = []string{" "} }, assert: refused("Resources")},
		{name: "a resource that is empty", client: func(c *oidcprovider.Client) { c.Resources = []string{""} }, assert: refused("Resources")},
		{name: "a resource that is relative", client: func(c *oidcprovider.Client) { c.Resources = []string{"/orders"} }, assert: refused("Resources")},
		{name: "a resource with a fragment", client: func(c *oidcprovider.Client) {
			c.Resources = []string{"https://api.example.com#part"}
		}, assert: refused("Resources[0]")},

		{name: "a resource url.Parse refuses", client: func(c *oidcprovider.Client) { c.Resources = []string{"http://[::1"} }, assert: refused("Resources[0]")},
		{name: "a resource with surrounding space", client: func(c *oidcprovider.Client) {
			c.Resources = []string{"https://api.example.com/orders "}
		}, assert: refused("Resources[0]")},
		{name: "a resource that is invalid UTF-8", client: func(c *oidcprovider.Client) {
			c.Resources = []string{"https://x/\xff"}
		}, assert: refused("Resources[0]")},
		{name: "a URN, a port, a path and a trailing slash", client: func(c *oidcprovider.Client) {
			c.Resources = []string{"urn:example:api", "https://api.example.com:8443", "https://api.example.com/v2/orders", "https://api.example.com/v2/"}
		}, assert: accepted},

		// Uniqueness and keys.
		{name: "duplicate identifier", clients: []oidcprovider.Client{webClient(), webClient()}, assert: refused("ID")},
		{name: "ES256 under a source that reports nothing", client: func(c *oidcprovider.Client) { c.IDTokenAlg = signingkey.ES256 }, assert: refused("IDTokenAlg")},
		{name: "ES256 under RS256 keys", client: func(c *oidcprovider.Client) { c.IDTokenAlg = signingkey.ES256 }, keys: rsaOnly, assert: refused("IDTokenAlg")},
		{name: "ES256 under ES256 keys", client: func(c *oidcprovider.Client) { c.IDTokenAlg = signingkey.ES256 }, keys: ecOnly, assert: accepted},
		{name: "the default RS256 under ES256 keys", keys: ecOnly, assert: refused("IDTokenAlg")},
		{name: "alg none", client: func(c *oidcprovider.Client) { c.IDTokenAlg = "none" }, assert: refused("IDTokenAlg")},

		// Offline access.
		{name: "pre-authorized on a web client", client: func(c *oidcprovider.Client) {
			c.OfflineAccess = oidcprovider.OfflinePreAuthorized
			c.FirstParty = true
		}, assert: refused("OfflineAccess")},
		{name: "pre-authorized on a third-party native client", client: func(c *oidcprovider.Client) {
			native(c)
			c.OfflineAccess = oidcprovider.OfflinePreAuthorized
		}, assert: refused("OfflineAccess")},
		{name: "pre-authorized on a first-party native client", client: func(c *oidcprovider.Client) {
			native(c)
			c.OfflineAccess = oidcprovider.OfflinePreAuthorized
			c.FirstParty = true
		}, assert: accepted},
		{name: "unknown offline access", client: func(c *oidcprovider.Client) { c.OfflineAccess = 9 }, assert: refused("OfflineAccess")},

		// Refresh.
		{name: "rotation off on a public client", client: func(c *oidcprovider.Client) {
			public(c)
			c.DisableRotation = true
			c.RequireBinding = oidcprovider.BindingDPoP
		}, assert: refused("DisableRotation")},
		{name: "rotation off with binding optional", client: func(c *oidcprovider.Client) { c.DisableRotation = true }, assert: refused("DisableRotation")},
		{name: "rotation off on a bound confidential client", client: func(c *oidcprovider.Client) {
			c.DisableRotation = true
			c.RequireBinding = oidcprovider.BindingMTLS
		}, assert: accepted},
		{name: "unknown binding", client: func(c *oidcprovider.Client) { c.RequireBinding = 9 }, assert: refused("RequireBinding")},
		{name: "grace of 10 minutes", client: func(c *oidcprovider.Client) { c.RefreshGrace = 10 * time.Minute }, assert: refused("RefreshGrace")},
		{name: "grace at the bound", client: func(c *oidcprovider.Client) { c.RefreshGrace = session.MaxRenewalGrace }, assert: accepted},
		{name: "negative grace", client: func(c *oidcprovider.Client) { c.RefreshGrace = -time.Second }, assert: refused("RefreshGrace")},
		{name: "idle past the absolute lifetime", client: func(c *oidcprovider.Client) {
			c.GrantIdleTimeout = 60 * day
			c.GrantAbsoluteLifetime = 30 * day
		}, assert: refused("GrantIdleTimeout")},
		{name: "idle past the default absolute lifetime", client: func(c *oidcprovider.Client) { c.GrantIdleTimeout = 91 * day }, assert: refused("GrantIdleTimeout")},
		{name: "negative absolute lifetime", client: func(c *oidcprovider.Client) { c.GrantAbsoluteLifetime = -day }, assert: refused("GrantAbsoluteLifetime")},
		{
			name:   "the default idle timeout fits a short absolute lifetime",
			client: func(c *oidcprovider.Client) { c.GrantAbsoluteLifetime = 10 * day },
			assert: func(t *testing.T, got *oidcprovider.RegisteredClient, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, 10*day, got.GrantIdleTimeout)
			},
		},
		{name: "unknown grant type", client: func(c *oidcprovider.Client) { c.GrantTypes = []oidcprovider.GrantType{"password"} }, assert: refused("GrantTypes")},

		// Defaults (R13), and what the consumer owns.
		{
			name: "defaults",
			assert: func(t *testing.T, got *oidcprovider.RegisteredClient, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.False(t, got.FirstParty)
				assert.Equal(t, oidcprovider.Web, got.ApplicationType)
				assert.Equal(t, oidcprovider.PKCERequired, got.PKCE)
				assert.Equal(t, []oidcprovider.GrantType{oidcprovider.GrantAuthorizationCode}, got.GrantTypes)
				assert.Equal(t, signingkey.RS256, got.IDTokenAlg)
				assert.Equal(t, 5*time.Minute, got.IDTokenLifetime)
				assert.Equal(t, 5*time.Minute, got.AccessTokenLifetime)
				assert.Equal(t, 30*time.Second, got.RefreshGrace)
				assert.Equal(t, 30*day, got.GrantIdleTimeout)
				assert.Equal(t, 90*day, got.GrantAbsoluteLifetime)
				assert.False(t, got.EndGrantsWithSignIn)
			},
		},
		{
			name: "overrides are kept",
			client: func(c *oidcprovider.Client) {
				c.FirstParty = true
				c.PKCE = oidcprovider.PKCEOrNonce
				c.GrantTypes = []oidcprovider.GrantType{oidcprovider.GrantAuthorizationCode, oidcprovider.GrantRefreshToken}
				c.IDTokenLifetime = time.Minute
				c.AccessTokenLifetime = 2 * time.Minute
				c.RefreshGrace = time.Minute
				c.GrantIdleTimeout = day
				c.GrantAbsoluteLifetime = 2 * day
				c.EndGrantsWithSignIn = true
				c.Metadata = map[string]string{"tenant": "a"}
			},
			assert: func(t *testing.T, got *oidcprovider.RegisteredClient, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.True(t, got.FirstParty)
				assert.Equal(t, oidcprovider.PKCEOrNonce, got.PKCE)
				assert.Len(t, got.GrantTypes, 2)
				assert.Equal(t, time.Minute, got.IDTokenLifetime)
				assert.Equal(t, 2*time.Minute, got.AccessTokenLifetime)
				assert.Equal(t, time.Minute, got.RefreshGrace)
				assert.Equal(t, day, got.GrantIdleTimeout)
				assert.Equal(t, 2*day, got.GrantAbsoluteLifetime)
				assert.True(t, got.EndGrantsWithSignIn)
				assert.Equal(t, map[string]string{"tenant": "a"}, got.Metadata)
			},
		},
		{
			name:   "a public web client's grants end with the sign-in",
			client: public,
			assert: func(t *testing.T, got *oidcprovider.RegisteredClient, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.True(t, got.EndGrantsWithSignIn)
			},
		},
		{
			name: "a public web client may keep its grants",
			client: func(c *oidcprovider.Client) {
				public(c)
				c.KeepPublicWebGrantsPastSignIn = true
			},
			assert: func(t *testing.T, got *oidcprovider.RegisteredClient, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.False(t, got.EndGrantsWithSignIn)
			},
		},
		{
			name: "a public native client's grants do not end by default",
			client: func(c *oidcprovider.Client) {
				public(c)
				native(c)
				c.RedirectURIs = []string{"com.example.app:/cb"}
			},
			assert: func(t *testing.T, got *oidcprovider.RegisteredClient, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.False(t, got.EndGrantsWithSignIn)
			},
		},
		{name: "keeping grants is only for a public web client", client: func(c *oidcprovider.Client) { c.KeepPublicWebGrantsPastSignIn = true }, assert: refused("KeepPublicWebGrantsPastSignIn")},
		{name: "keeping and ending grants at once", client: func(c *oidcprovider.Client) {
			public(c)
			c.KeepPublicWebGrantsPastSignIn = true
			c.EndGrantsWithSignIn = true
		}, assert: refused("KeepPublicWebGrantsPastSignIn")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clients := tc.clients
			if clients == nil {
				c := webClient()
				if tc.client != nil {
					tc.client(&c)
				}
				clients = []oidcprovider.Client{c}
			}

			d := validDeps(t)
			d.Clients = clients
			if tc.keys != nil {
				d.Keys = tc.keys
			}

			p, err := oidcprovider.New(d)
			if err != nil {
				assert.Nil(t, p)
				tc.assert(t, nil, err)

				return
			}

			got, err := p.ClientForTest(t.Context(), clients[0].ID)
			require.NoError(t, err)
			tc.assert(t, got, nil)
		})
	}
}
