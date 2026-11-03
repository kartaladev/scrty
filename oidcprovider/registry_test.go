package oidcprovider_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/token/signingkey"
)

var suppliedSecret = []byte("0123456789abcdef0123456789abcdef")

func digest(secret []byte) []byte {
	sum := sha256.Sum256(secret)

	return sum[:]
}

// A consumer's registry answering with what the row gives, and the provider
// reading through it.
func providerOver(t *testing.T, logs *bytes.Buffer, answer func(*MockClientRegistry)) *oidcprovider.Provider {
	t.Helper()

	registry := NewMockClientRegistry(gomock.NewController(t))
	answer(registry)

	d := validDeps(t)
	d.Clients = nil
	d.Registry = registry

	opts := []oidcprovider.Option{}
	if logs != nil {
		opts = append(opts, oidcprovider.WithLogger(slog.New(slog.NewTextHandler(logs, nil))))
	}
	p, err := oidcprovider.New(d, opts...)
	require.NoError(t, err)

	return p
}

func TestMemoryRegistry(t *testing.T) {
	t.Parallel()

	configured := func(t *testing.T, _ *bytes.Buffer) *oidcprovider.Provider {
		t.Helper()
		p, err := oidcprovider.New(validDeps(t))
		require.NoError(t, err)

		return p
	}

	type testCase struct {
		name     string
		provider func(t *testing.T, logs *bytes.Buffer) *oidcprovider.Provider
		id       string
		ctx      func(ctx context.Context) context.Context
		assert   func(t *testing.T, got *oidcprovider.RegisteredClient, err error, logs string)
	}

	notFound := func(t *testing.T, got *oidcprovider.RegisteredClient, err error, _ string) {
		t.Helper()
		require.ErrorIs(t, err, oidcprovider.ErrClientNotFound)
		assert.Nil(t, got)
	}
	cause := errors.New("dial tcp secret-dsn")
	cancelled := func(ctx context.Context) context.Context {
		cctx, cancel := context.WithCancel(ctx)
		cancel()

		return cctx
	}

	cases := []testCase{
		{
			name:     "a configured client is found",
			provider: configured,
			id:       "billing-web",
			assert: func(t *testing.T, got *oidcprovider.RegisteredClient, err error, _ string) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, "billing-web", got.ID)
			},
		},
		{name: "an unknown client", provider: configured, id: "nobody", assert: notFound},
		{
			name: "a consumer's registry replaces the default",
			provider: func(t *testing.T, _ *bytes.Buffer) *oidcprovider.Provider {
				t.Helper()
				ios := oidcprovider.RegisteredClient{Client: oidcprovider.Client{
					ID:              "billing-ios",
					Type:            oidcprovider.Public,
					ApplicationType: oidcprovider.Native,
					RedirectURIs:    []string{"com.example.billing:/cb"},
				}}

				return providerOver(t, nil, func(m *MockClientRegistry) {
					m.EXPECT().Client(gomock.Any(), "billing-ios").Return(&ios, nil).Times(1)
				})
			},
			id: "billing-ios",
			assert: func(t *testing.T, got *oidcprovider.RegisteredClient, err error, _ string) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, "billing-ios", got.ID)
			},
		},
		{
			name: "a consumer's registry knows nothing of the client",
			provider: func(t *testing.T, _ *bytes.Buffer) *oidcprovider.Provider {
				t.Helper()

				return providerOver(t, nil, func(m *MockClientRegistry) {
					m.EXPECT().Client(gomock.Any(), "nobody").Return(nil, oidcprovider.ErrClientNotFound)
				})
			},
			id:     "nobody",
			assert: notFound,
		},
		{
			name: "a consumer's registry answering with nothing",
			provider: func(t *testing.T, _ *bytes.Buffer) *oidcprovider.Provider {
				t.Helper()

				return providerOver(t, nil, func(m *MockClientRegistry) {
					m.EXPECT().Client(gomock.Any(), "nobody").Return(nil, nil)
				})
			},
			id:     "nobody",
			assert: notFound,
		},
		{
			name: "a failing registry is a dependency failure behind fixed text",
			provider: func(t *testing.T, _ *bytes.Buffer) *oidcprovider.Provider {
				t.Helper()

				return providerOver(t, nil, func(m *MockClientRegistry) {
					m.EXPECT().Client(gomock.Any(), "billing-web").Return(nil, cause)
				})
			},
			id: "billing-web",
			assert: func(t *testing.T, got *oidcprovider.RegisteredClient, err error, _ string) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrDependency)
				require.ErrorIs(t, err, cause)
				assert.NotContains(t, err.Error(), "secret-dsn")
				assert.Nil(t, got)
			},
		},
		{
			name: "a caller who left matches the context's error and logs nothing",
			provider: func(t *testing.T, logs *bytes.Buffer) *oidcprovider.Provider {
				t.Helper()

				return providerOver(t, logs, func(m *MockClientRegistry) {
					m.EXPECT().Client(gomock.Any(), "billing-web").Return(nil, context.Canceled)
				})
			},
			id:  "billing-web",
			ctx: cancelled,
			assert: func(t *testing.T, got *oidcprovider.RegisteredClient, err error, logs string) {
				t.Helper()
				require.ErrorIs(t, err, context.Canceled)
				assert.NotErrorIs(t, err, oidcprovider.ErrDependency)
				assert.Nil(t, got)
				assert.Empty(t, logs)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			var logs bytes.Buffer
			p := tc.provider(t, &logs)

			got, err := p.ClientForTest(ctx, tc.id)
			tc.assert(t, got, err, logs.String())
		})
	}
}

func TestMemoryRegistry_Writes(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// registry replaces the one holding billing-web.
		registry func() *oidcprovider.MemoryRegistry
		act      func(ctx context.Context, r *oidcprovider.MemoryRegistry) error
		assert   func(t *testing.T, r *oidcprovider.MemoryRegistry, err error)
	}

	const generatedID = "billing-web"

	zeroValue := func() *oidcprovider.MemoryRegistry { return &oidcprovider.MemoryRegistry{} }

	cases := []testCase{
		{
			name:     "the zero value accepts a put",
			registry: zeroValue,
			act:      func(ctx context.Context, r *oidcprovider.MemoryRegistry) error { return r.Put(ctx, webClient()) },
			assert: func(t *testing.T, r *oidcprovider.MemoryRegistry, err error) {
				t.Helper()
				require.NoError(t, err)
				got, err := r.Client(t.Context(), generatedID)
				require.NoError(t, err)
				assert.Equal(t, generatedID, got.ID)
			},
		},
		{
			name:     "the zero value accepts a registered put",
			registry: zeroValue,
			act: func(ctx context.Context, r *oidcprovider.MemoryRegistry) error {
				c := webClient()
				c.Secret = nil

				return r.PutRegistered(ctx, oidcprovider.RegisteredClient{Client: c})
			},
			assert: func(t *testing.T, r *oidcprovider.MemoryRegistry, err error) {
				t.Helper()
				require.NoError(t, err)
				_, err = r.Client(t.Context(), generatedID)
				assert.NoError(t, err)
			},
		},
		{
			name: "put validates as construction does",
			act: func(ctx context.Context, r *oidcprovider.MemoryRegistry) error {
				c := webClient()
				c.ID = "crm-web"
				c.RedirectURIs = []string{"https://*.example.com/cb"}

				return r.Put(ctx, c)
			},
			assert: func(t *testing.T, r *oidcprovider.MemoryRegistry, err error) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrConfig)
				assert.ErrorContains(t, err, "crm-web")
				_, err = r.Client(t.Context(), "crm-web")
				assert.ErrorIs(t, err, oidcprovider.ErrClientNotFound)
			},
		},
		{
			name: "put leaves the key algorithm to the provider",
			act: func(ctx context.Context, r *oidcprovider.MemoryRegistry) error {
				c := webClient()
				c.ID = "crm-web"
				c.IDTokenAlg = signingkey.ES256

				return r.Put(ctx, c)
			},
			assert: func(t *testing.T, r *oidcprovider.MemoryRegistry, err error) {
				t.Helper()
				require.NoError(t, err)
				got, err := r.Client(t.Context(), "crm-web")
				require.NoError(t, err)
				assert.Equal(t, signingkey.ES256, got.IDTokenAlg)
			},
		},
		{
			name: "put with no secret keeps the secrets held",
			act: func(ctx context.Context, r *oidcprovider.MemoryRegistry) error {
				c := webClient()
				c.Secret = nil
				c.Name = "Billing"

				return r.Put(ctx, c)
			},
			assert: func(t *testing.T, r *oidcprovider.MemoryRegistry, err error) {
				t.Helper()
				require.NoError(t, err)
				got, err := r.Client(t.Context(), generatedID)
				require.NoError(t, err)
				assert.Equal(t, "Billing", got.Name)
				require.Len(t, got.Secrets, 1)
				assert.Equal(t, digest(suppliedSecret), []byte(got.Secrets[0].Digest))
			},
		},
		{
			name: "a caller changing a client after put leaves what is held alone",
			act: func(ctx context.Context, r *oidcprovider.MemoryRegistry) error {
				c := webClient()
				c.Metadata = map[string]string{"tenant": "a"}
				if err := r.Put(ctx, c); err != nil {
					return err
				}
				c.RedirectURIs[0] = "https://evil.example.com/cb"
				c.Metadata["tenant"] = "evil"
				c.Secret[0] ^= 0xff

				return nil
			},
			assert: func(t *testing.T, r *oidcprovider.MemoryRegistry, err error) {
				t.Helper()
				require.NoError(t, err)
				got, err := r.Client(t.Context(), generatedID)
				require.NoError(t, err)
				assert.Equal(t, []string{"https://rp.example.com/cb"}, got.RedirectURIs)
				assert.Equal(t, map[string]string{"tenant": "a"}, got.Metadata)
			},
		},
		{
			name: "a caller changing a registered client after put leaves what is held alone",
			act: func(ctx context.Context, r *oidcprovider.MemoryRegistry) error {
				c := webClient()
				c.Secret = nil
				rc := oidcprovider.RegisteredClient{
					Client:  c,
					Secrets: []oidcprovider.ClientSecret{{Digest: digest(suppliedSecret)}},
				}
				if err := r.PutRegistered(ctx, rc); err != nil {
					return err
				}
				rc.RedirectURIs[0] = "https://evil.example.com/cb"
				rc.Secrets[0].Digest[0] ^= 0xff

				return nil
			},
			assert: func(t *testing.T, r *oidcprovider.MemoryRegistry, err error) {
				t.Helper()
				require.NoError(t, err)
				got, err := r.Client(t.Context(), generatedID)
				require.NoError(t, err)
				assert.Equal(t, []string{"https://rp.example.com/cb"}, got.RedirectURIs)
				require.Len(t, got.Secrets, 1)
				assert.Equal(t, digest(suppliedSecret), []byte(got.Secrets[0].Digest))
			},
		},
		{
			name: "put with no secret keeps no secret for a client that now uses none",
			act: func(ctx context.Context, r *oidcprovider.MemoryRegistry) error {
				c := webClient()
				c.Secret = nil
				c.AuthMethod = oidcprovider.PrivateKeyJWT
				c.JWKS = []byte(rfc7517Key)

				return r.Put(ctx, c)
			},
			assert: func(t *testing.T, r *oidcprovider.MemoryRegistry, err error) {
				t.Helper()
				require.NoError(t, err)
				got, err := r.Client(t.Context(), generatedID)
				require.NoError(t, err)
				assert.Empty(t, got.Secrets)
			},
		},
		{
			name: "delete removes the client",
			act: func(ctx context.Context, r *oidcprovider.MemoryRegistry) error {
				return r.Delete(ctx, generatedID)
			},
			assert: func(t *testing.T, r *oidcprovider.MemoryRegistry, err error) {
				t.Helper()
				require.NoError(t, err)
				_, err = r.Client(t.Context(), generatedID)
				assert.ErrorIs(t, err, oidcprovider.ErrClientNotFound)
			},
		},
		{
			name: "delete of an unknown client",
			act: func(ctx context.Context, r *oidcprovider.MemoryRegistry) error {
				return r.Delete(ctx, "nobody")
			},
			assert: func(t *testing.T, _ *oidcprovider.MemoryRegistry, err error) {
				t.Helper()
				assert.ErrorIs(t, err, oidcprovider.ErrClientNotFound)
			},
		},
		{
			name: "what a read returns is the caller's own",
			act: func(ctx context.Context, r *oidcprovider.MemoryRegistry) error {
				got, err := r.Client(ctx, generatedID)
				if err != nil {
					return err
				}
				got.RedirectURIs[0] = "https://evil.example.com/cb"
				if len(got.Secrets) == 0 {
					return errors.New("no secret held")
				}
				got.Secrets[0].Digest[0] ^= 0xff

				return nil
			},
			assert: func(t *testing.T, r *oidcprovider.MemoryRegistry, err error) {
				t.Helper()
				require.NoError(t, err)
				got, err := r.Client(t.Context(), generatedID)
				require.NoError(t, err)
				assert.Equal(t, []string{"https://rp.example.com/cb"}, got.RedirectURIs)
				assert.Equal(t, digest(suppliedSecret), []byte(got.Secrets[0].Digest))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r, err := oidcprovider.NewMemoryRegistry([]oidcprovider.Client{webClient()})
			require.NoError(t, err)
			if tc.registry != nil {
				r = tc.registry()
			}

			tc.assert(t, r, tc.act(t.Context(), r))
		})
	}
}

func TestMemoryRegistry_Construction(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		clients []oidcprovider.Client
		assert  func(t *testing.T, r *oidcprovider.MemoryRegistry, err error)
	}

	cases := []testCase{
		{
			name:    "a client with no secret yet is built, to generate one",
			clients: []oidcprovider.Client{func() oidcprovider.Client { c := webClient(); c.Secret = nil; return c }()},
			assert: func(t *testing.T, r *oidcprovider.MemoryRegistry, err error) {
				t.Helper()
				require.NoError(t, err)
				got, err := r.Client(t.Context(), "billing-web")
				require.NoError(t, err)
				assert.Empty(t, got.Secrets)
			},
		},
		{
			name:    "a duplicate identifier",
			clients: []oidcprovider.Client{webClient(), webClient()},
			assert: func(t *testing.T, _ *oidcprovider.MemoryRegistry, err error) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrConfig)
				assert.ErrorContains(t, err, "billing-web")
			},
		},
		{
			name:    "an invalid client",
			clients: []oidcprovider.Client{{ID: "billing-web"}},
			assert: func(t *testing.T, _ *oidcprovider.MemoryRegistry, err error) {
				t.Helper()
				assert.ErrorIs(t, err, oidcprovider.ErrConfig)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r, err := oidcprovider.NewMemoryRegistry(tc.clients)
			tc.assert(t, r, err)
		})
	}
}

// A memory registry handed in is configuration like any other, so New reports
// what it can see of it rather than leaving it to the first read.
func TestNew_MemoryRegistryChecked(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		client func(c *oidcprovider.Client)
		// keys replaces the default key source.
		keys   func(t *testing.T) signingkey.KeySource
		assert func(t *testing.T, err error)
	}

	refused := func(setting string) func(*testing.T, error) {
		return func(t *testing.T, err error) {
			t.Helper()
			require.ErrorIs(t, err, oidcprovider.ErrConfig)
			assert.ErrorContains(t, err, "billing-web")
			assert.ErrorContains(t, err, setting)
		}
	}
	// A usable window of one hour: the key lifetime minus the rotate interval.
	capped := func(t *testing.T) signingkey.KeySource {
		t.Helper()

		return reportingKeys{KeySource: plainKeys(t), lifetime: 2 * time.Hour, rotate: time.Hour}
	}

	cases := []testCase{
		{
			name:   "an algorithm the keys cannot produce",
			client: func(c *oidcprovider.Client) { c.IDTokenAlg = signingkey.ES256 },
			assert: refused("IDTokenAlg"),
		},
		{
			name:   "an ID token lifetime past the key cap",
			client: func(c *oidcprovider.Client) { c.IDTokenLifetime = 61 * time.Minute },
			keys:   capped,
			assert: refused("IDTokenLifetime"),
		},
		{
			name:   "an access token lifetime past the key cap",
			client: func(c *oidcprovider.Client) { c.AccessTokenLifetime = 61 * time.Minute },
			keys:   capped,
			assert: refused("AccessTokenLifetime"),
		},
		{
			name:   "lifetimes within the key cap",
			client: func(c *oidcprovider.Client) { c.AccessTokenLifetime = time.Hour },
			keys:   capped,
			assert: func(t *testing.T, err error) {
				t.Helper()
				assert.NoError(t, err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c := webClient()
			tc.client(&c)
			r, err := oidcprovider.NewMemoryRegistry([]oidcprovider.Client{c})
			require.NoError(t, err)

			d := validDeps(t)
			d.Clients = nil
			d.Registry = r
			if tc.keys != nil {
				d.Keys = tc.keys(t)
			}

			_, err = oidcprovider.New(d)
			tc.assert(t, err)
		})
	}
}

func TestMemoryRegistry_Concurrent(t *testing.T) {
	t.Parallel()

	r, err := oidcprovider.NewMemoryRegistry([]oidcprovider.Client{webClient()})
	require.NoError(t, err)

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			_, genErr := r.GenerateSecret(t.Context(), "billing-web")
			assert.NoError(t, genErr)
			got, readErr := r.Client(t.Context(), "billing-web")
			assert.NoError(t, readErr)
			assert.Len(t, got.Secrets, 1)
			assert.NoError(t, r.Put(t.Context(), webClient()))
		})
	}
	wg.Wait()
}

func TestRegistry_Secrets(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	other := []byte("fedcba9876543210fedcba9876543210")

	secret := func(raw []byte, expiresAt time.Time) oidcprovider.ClientSecret {
		s, err := oidcprovider.NewClientSecret(raw, expiresAt)
		require.NoError(t, err)

		return s
	}
	read := func(t *testing.T, r *oidcprovider.MemoryRegistry) *oidcprovider.RegisteredClient {
		t.Helper()
		got, err := r.Client(t.Context(), "billing-web")
		require.NoError(t, err)

		return got
	}
	generate := func(n int) func(context.Context, *oidcprovider.MemoryRegistry) ([]string, error) {
		return func(ctx context.Context, r *oidcprovider.MemoryRegistry) ([]string, error) {
			out := make([]string, 0, n)
			for range n {
				value, err := r.GenerateSecret(ctx, "billing-web")
				if err != nil {
					return nil, err
				}
				out = append(out, value)
			}

			return out, nil
		}
	}
	register := func(secrets ...oidcprovider.ClientSecret) func(context.Context, *oidcprovider.MemoryRegistry) ([]string, error) {
		return func(ctx context.Context, r *oidcprovider.MemoryRegistry) ([]string, error) {
			c := webClient()
			c.Secret = nil

			return nil, r.PutRegistered(ctx, oidcprovider.RegisteredClient{Client: c, Secrets: secrets})
		}
	}

	type testCase struct {
		name string
		// act runs against a registry holding billing-web with no secret.
		act    func(ctx context.Context, r *oidcprovider.MemoryRegistry) ([]string, error)
		assert func(t *testing.T, r *oidcprovider.MemoryRegistry, generated []string, err error)
	}

	short := []byte("short-secret-value-1")
	third := secret([]byte("abcdefghabcdefghabcdefghabcdefgh"), time.Time{})

	cases := []testCase{
		{
			name: "a generated secret is 256 bits, and only its digest is held",
			act:  generate(1),
			assert: func(t *testing.T, r *oidcprovider.MemoryRegistry, generated []string, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Len(t, generated[0], 43)
				raw, err := base64.RawURLEncoding.DecodeString(generated[0])
				require.NoError(t, err)
				assert.Len(t, raw, 32)

				got := read(t, r)
				assert.Nil(t, got.Secret)
				require.Len(t, got.Secrets, 1)
				assert.Equal(t, digest([]byte(generated[0])), []byte(got.Secrets[0].Digest))
				assert.True(t, got.Secrets[0].ExpiresAt.IsZero())
				assert.True(t, got.MatchesSecretForTest([]byte(generated[0]), now))
			},
		},
		{
			name: "two generated secrets differ, and the second replaces the first",
			act:  generate(2),
			assert: func(t *testing.T, r *oidcprovider.MemoryRegistry, generated []string, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.NotEqual(t, generated[0], generated[1])

				got := read(t, r)
				assert.Len(t, got.Secrets, 1)
				assert.False(t, got.MatchesSecretForTest([]byte(generated[0]), now))
				assert.True(t, got.MatchesSecretForTest([]byte(generated[1]), now))
			},
		},
		{
			name: "generating for an unknown client",
			act: func(ctx context.Context, r *oidcprovider.MemoryRegistry) ([]string, error) {
				_, err := r.GenerateSecret(ctx, "nobody")

				return nil, err
			},
			assert: func(t *testing.T, _ *oidcprovider.MemoryRegistry, _ []string, err error) {
				t.Helper()
				assert.ErrorIs(t, err, oidcprovider.ErrClientNotFound)
			},
		},
		{
			name: "generating for a client that uses no secret",
			act: func(ctx context.Context, r *oidcprovider.MemoryRegistry) ([]string, error) {
				err := r.Put(ctx, oidcprovider.Client{
					ID: "spa", Type: oidcprovider.Public, RedirectURIs: []string{"https://rp.example.com/cb"},
				})
				if err != nil {
					return nil, err
				}
				_, err = r.GenerateSecret(ctx, "spa")

				return nil, err
			},
			assert: func(t *testing.T, _ *oidcprovider.MemoryRegistry, _ []string, err error) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrConfig)
				assert.ErrorContains(t, err, "spa")
			},
		},
		{
			name: "a supplied secret is held only as a digest",
			act: func(ctx context.Context, r *oidcprovider.MemoryRegistry) ([]string, error) {
				return nil, r.Put(ctx, webClient())
			},
			assert: func(t *testing.T, r *oidcprovider.MemoryRegistry, _ []string, err error) {
				t.Helper()
				require.NoError(t, err)
				got := read(t, r)
				assert.Nil(t, got.Secret)
				require.Len(t, got.Secrets, 1)
				assert.Equal(t, digest(suppliedSecret), []byte(got.Secrets[0].Digest))
			},
		},
		{
			name: "a short supplied secret, not repeated in the error",
			act: func(_ context.Context, _ *oidcprovider.MemoryRegistry) ([]string, error) {
				_, err := oidcprovider.NewClientSecret(short, time.Time{})

				return nil, err
			},
			assert: func(t *testing.T, _ *oidcprovider.MemoryRegistry, _ []string, err error) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrConfig)
				assert.NotContains(t, err.Error(), string(short))
				assert.NotContains(t, err.Error(), hex.EncodeToString(digest(short)))
			},
		},
		{
			name: "a short secret on a client, not repeated in the error",
			act: func(ctx context.Context, r *oidcprovider.MemoryRegistry) ([]string, error) {
				c := webClient()
				c.Secret = short

				return nil, r.Put(ctx, c)
			},
			assert: func(t *testing.T, _ *oidcprovider.MemoryRegistry, _ []string, err error) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrConfig)
				assert.NotContains(t, err.Error(), string(short))
				assert.NotContains(t, err.Error(), hex.EncodeToString(digest(short)))
			},
		},
		{
			name: "the wrong secret, and none at all",
			act:  register(secret(suppliedSecret, time.Time{})),
			assert: func(t *testing.T, r *oidcprovider.MemoryRegistry, _ []string, err error) {
				t.Helper()
				require.NoError(t, err)
				got := read(t, r)
				assert.True(t, got.MatchesSecretForTest(suppliedSecret, now))
				assert.False(t, got.MatchesSecretForTest(other, now))
				assert.False(t, got.MatchesSecretForTest(nil, now))
			},
		},
		{
			name: "a client holding no secret matches nothing",
			act:  register(),
			assert: func(t *testing.T, r *oidcprovider.MemoryRegistry, _ []string, err error) {
				t.Helper()
				require.NoError(t, err)
				got := read(t, r)
				assert.False(t, got.MatchesSecretForTest(nil, now))
				assert.False(t, got.MatchesSecretForTest(suppliedSecret, now))
			},
		},
		{
			name: "either of two live secrets authenticates",
			act:  register(secret(suppliedSecret, now.Add(24*time.Hour)), secret(other, time.Time{})),
			assert: func(t *testing.T, r *oidcprovider.MemoryRegistry, _ []string, err error) {
				t.Helper()
				require.NoError(t, err)
				got := read(t, r)
				assert.True(t, got.MatchesSecretForTest(suppliedSecret, now))
				assert.True(t, got.MatchesSecretForTest(other, now))
			},
		},
		{
			name: "an expired secret does not, from the instant it expires",
			act:  register(secret(suppliedSecret, now), secret(other, time.Time{})),
			assert: func(t *testing.T, r *oidcprovider.MemoryRegistry, _ []string, err error) {
				t.Helper()
				require.NoError(t, err)
				got := read(t, r)
				assert.True(t, got.MatchesSecretForTest(suppliedSecret, now.Add(-time.Nanosecond)))
				assert.False(t, got.MatchesSecretForTest(suppliedSecret, now))
				assert.True(t, got.MatchesSecretForTest(other, now))
			},
		},
		{
			name: "a third secret is refused at registration, with no digest in the error",
			act:  register(secret(suppliedSecret, time.Time{}), secret(other, time.Time{}), third),
			assert: func(t *testing.T, r *oidcprovider.MemoryRegistry, _ []string, err error) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrConfig)
				assert.ErrorContains(t, err, "billing-web")
				assert.ErrorContains(t, err, "Secrets")
				assert.NotContains(t, err.Error(), hex.EncodeToString(third.Digest))
				assert.Empty(t, read(t, r).Secrets)
			},
		},
		{
			name: "a digest on a client that uses no secret is refused",
			act: func(ctx context.Context, r *oidcprovider.MemoryRegistry) ([]string, error) {
				c := webClient()
				c.Secret = nil
				c.AuthMethod = oidcprovider.PrivateKeyJWT
				c.JWKS = []byte(rfc7517Key)

				return nil, r.PutRegistered(ctx, oidcprovider.RegisteredClient{
					Client: c, Secrets: []oidcprovider.ClientSecret{secret(suppliedSecret, time.Time{})},
				})
			},
			assert: func(t *testing.T, _ *oidcprovider.MemoryRegistry, _ []string, err error) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrConfig)
				assert.ErrorContains(t, err, "Secrets")
			},
		},
		{
			name: "a registration carrying a raw secret is refused",
			act: func(ctx context.Context, r *oidcprovider.MemoryRegistry) ([]string, error) {
				return nil, r.PutRegistered(ctx, oidcprovider.RegisteredClient{Client: webClient()})
			},
			assert: func(t *testing.T, _ *oidcprovider.MemoryRegistry, _ []string, err error) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrConfig)
				assert.NotContains(t, err.Error(), string(suppliedSecret))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c := webClient()
			c.Secret = nil
			r, err := oidcprovider.NewMemoryRegistry([]oidcprovider.Client{c})
			require.NoError(t, err)

			generated, err := tc.act(t.Context(), r)
			tc.assert(t, r, generated, err)
		})
	}
}

func TestProvider_ClientFromRegistryValidated(t *testing.T) {
	t.Parallel()

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	privateKeySet := keySet(t, ecKey)

	type testCase struct {
		name string
		// client changes what the consumer's registry holds.
		client func(rc *oidcprovider.RegisteredClient)
		// assert gets what the registry held, and what the provider made of it.
		assert func(t *testing.T, held, got *oidcprovider.RegisteredClient, err error, logs string)
	}

	// unknown holds that the client is answered as unknown, with one log line
	// naming the setting and leaking no secret.
	unknown := func(setting string) func(*testing.T, *oidcprovider.RegisteredClient, *oidcprovider.RegisteredClient, error, string) {
		return func(t *testing.T, _, got *oidcprovider.RegisteredClient, err error, logs string) {
			t.Helper()
			require.ErrorIs(t, err, oidcprovider.ErrClientNotFound)
			assert.Nil(t, got)

			assert.Equal(t, 1, strings.Count(logs, "\n"), "one log line: %s", logs)
			assert.Contains(t, logs, setting)
			assert.NotContains(t, logs, string(suppliedSecret))
			assert.NotContains(t, logs, hex.EncodeToString(digest(suppliedSecret)))
		}
	}

	cases := []testCase{
		{
			name: "a wildcard redirect URI",
			client: func(rc *oidcprovider.RegisteredClient) {
				rc.RedirectURIs = []string{"https://*.example.com/cb"}
			},
			assert: unknown("RedirectURIs"),
		},
		{
			name:   "an algorithm the keys cannot produce",
			client: func(rc *oidcprovider.RegisteredClient) { rc.IDTokenAlg = signingkey.ES256 },
			assert: unknown("IDTokenAlg"),
		},
		{
			name:   "a raw secret held by the registry",
			client: func(rc *oidcprovider.RegisteredClient) { rc.Secret = suppliedSecret },
			assert: unknown("Secret"),
		},
		{
			name: "a third secret",
			client: func(rc *oidcprovider.RegisteredClient) {
				rc.Secrets = make([]oidcprovider.ClientSecret, 3)
				for i := range rc.Secrets {
					rc.Secrets[i].Digest = digest(suppliedSecret)
				}
			},
			assert: unknown("Secrets"),
		},
		{
			name: "a digest of the wrong size",
			client: func(rc *oidcprovider.RegisteredClient) {
				rc.Secrets = []oidcprovider.ClientSecret{{Digest: suppliedSecret[:8]}}
			},
			assert: unknown("Secrets"),
		},
		{
			name: "a digest on a client that uses no secret",
			client: func(rc *oidcprovider.RegisteredClient) {
				rc.AuthMethod = oidcprovider.PrivateKeyJWT
				rc.JWKS = []byte(rfc7517Key)
			},
			assert: unknown("Secrets"),
		},
		{
			name: "a private key in the key set",
			client: func(rc *oidcprovider.RegisteredClient) {
				rc.AuthMethod, rc.Secrets = oidcprovider.PrivateKeyJWT, nil
				rc.JWKS = privateKeySet
			},
			assert: unknown("JWKS"),
		},
		{
			name:   "another client than the one asked for",
			client: func(rc *oidcprovider.RegisteredClient) { rc.ID = "crm-web" },
			assert: unknown("ID"),
		},
		{
			name:   "a valid client gets its defaults, and the registry's value is left alone",
			client: func(rc *oidcprovider.RegisteredClient) { rc.Secrets = nil },
			assert: func(t *testing.T, held, got *oidcprovider.RegisteredClient, err error, _ string) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, oidcprovider.ClientSecretBasic, got.AuthMethod)
				assert.Empty(t, held.AuthMethod)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c := webClient()
			c.Secret = nil
			rc := oidcprovider.RegisteredClient{
				Client:  c,
				Secrets: []oidcprovider.ClientSecret{{Digest: digest(suppliedSecret)}},
			}
			tc.client(&rc)

			var logs bytes.Buffer
			p := providerOver(t, &logs, func(m *MockClientRegistry) {
				m.EXPECT().Client(gomock.Any(), "billing-web").Return(&rc, nil)
			})

			got, err := p.ClientForTest(t.Context(), "billing-web")
			tc.assert(t, &rc, got, err, logs.String())
		})
	}
}

// Every way a secret or a digest could reach a log line, an error or a response
// body: the formatting verbs, and encoding/json.
func TestSecrets_NeverPrinted(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// value is what gets printed and marshalled.
		value any
		// hidden are the secrets it must not show, whatever their encoding.
		hidden [][]byte
		assert func(t *testing.T, printed []string)
	}

	forms := func(raw []byte) []string {
		return []string{
			string(raw),
			hex.EncodeToString(raw),
			strings.ToUpper(hex.EncodeToString(raw)),
			base64.StdEncoding.EncodeToString(raw),
			base64.RawStdEncoding.EncodeToString(raw),
			base64.URLEncoding.EncodeToString(raw),
			base64.RawURLEncoding.EncodeToString(raw),
			fmt.Sprintf("%v", []byte(raw))[:20],
		}
	}
	clean := func(hidden ...[]byte) func(t *testing.T, printed []string) {
		return func(t *testing.T, printed []string) {
			t.Helper()
			for _, out := range printed {
				for _, raw := range hidden {
					for _, form := range forms(raw) {
						assert.NotContains(t, out, form)
					}
				}
			}
		}
	}

	held := digest(suppliedSecret)
	registered := oidcprovider.RegisteredClient{
		Client:  oidcprovider.Client{ID: "billing-web", Secret: suppliedSecret},
		Secrets: []oidcprovider.ClientSecret{{Digest: held}},
	}

	cases := []testCase{
		{name: "a client", value: oidcprovider.Client{ID: "billing-web", Secret: suppliedSecret}, hidden: [][]byte{suppliedSecret}},
		{name: "a client by pointer", value: &oidcprovider.Client{ID: "billing-web", Secret: suppliedSecret}, hidden: [][]byte{suppliedSecret}},
		{name: "a registered client", value: registered, hidden: [][]byte{suppliedSecret, held}},
		{name: "a registered client by pointer", value: &registered, hidden: [][]byte{suppliedSecret, held}},
		{name: "a client secret", value: oidcprovider.ClientSecret{Digest: held}, hidden: [][]byte{held}},
		{name: "a list of client secrets", value: []oidcprovider.ClientSecret{{Digest: held}}, hidden: [][]byte{held}},
		{name: "a secret on a client, in a map", value: map[string]oidcprovider.Client{"a": {Secret: suppliedSecret}}, hidden: [][]byte{suppliedSecret}},
	}
	for i := range cases {
		cases[i].assert = clean(cases[i].hidden...)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var printed []string
			for _, verb := range []string{"%s", "%v", "%+v", "%#v", "%q", "%x", "%X", "%d"} {
				printed = append(printed, fmt.Sprintf(verb, tc.value))
			}
			printed = append(printed, fmt.Sprint(tc.value))

			encoded, err := json.Marshal(tc.value)
			require.NoError(t, err)
			printed = append(printed, string(encoded))

			tc.assert(t, printed)
		})
	}
}
