package oidc_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/oidc"
)

// authorizeParams parses an authorization redirect, requiring it to be
// addressed to endpoint.
func authorizeParams(t *testing.T, redirect, endpoint string) url.Values {
	t.Helper()

	u, err := url.Parse(redirect)
	require.NoError(t, err)
	want, err := url.Parse(endpoint)
	require.NoError(t, err)
	assert.Equal(t, want.Scheme+"://"+want.Host+want.Path, u.Scheme+"://"+u.Host+u.Path,
		"the redirect must go to the provider's authorization endpoint")

	return u.Query()
}

// authorizeFlow returns the flow the manager's default store holds under
// handle.
func authorizeFlow(t *testing.T, m *oidc.Manager, handle string) oidc.Flow {
	t.Helper()

	store, ok := oidc.WiringOf(m).Flows.(*oidc.MemoryFlowStore)
	require.True(t, ok, "the manager must hold the default in-memory store")
	f, found := oidc.FlowForTest(store, handle)
	require.True(t, found, "the handle must name a stored flow")

	return f
}

// authorizeNoFlowStore is a flow store that fails the test if touched.
func authorizeNoFlowStore(t *testing.T) oidc.ManagerOption {
	t.Helper()
	return oidc.WithFlowStore(NewMockFlowStore(gomock.NewController(t)))
}

func TestManagerAuthorize(t *testing.T) {
	t.Parallel()

	sevens := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	past := time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)

	type testCase struct {
		name     string
		provider string
		next     string
		// opts are extra manager options; the provider's outbound client is
		// always given.
		opts   func(t *testing.T, p *testProvider) []oidc.ManagerOption
		setup  func(p *testProvider)
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, m *oidc.Manager, p *testProvider, got oidc.Authorization, err error)
	}

	cases := []testCase{
		{
			name: "the redirect carries PKCE, state and nonce", provider: "corp", next: "/after?x=1",
			assert: func(t *testing.T, m *oidc.Manager, p *testProvider, got oidc.Authorization, err error) {
				require.NoError(t, err)
				q := authorizeParams(t, got.RedirectURL, p.Issuer()+"/authorize")
				f := authorizeFlow(t, m, got.Handle)

				assert.Equal(t, "code", q.Get("response_type"))
				assert.Equal(t, "client-corp", q.Get("client_id"))
				assert.Equal(t, "https://app.example/login/oauth2/callback/corp", q.Get("redirect_uri"))
				assert.Equal(t, "openid profile email", q.Get("scope"))
				assert.Equal(t, "S256", q.Get("code_challenge_method"))
				sum := sha256.Sum256([]byte(f.Verifier))
				assert.Equal(t, base64.RawURLEncoding.EncodeToString(sum[:]), q.Get("code_challenge"))
				assert.Equal(t, f.State, q.Get("state"))
				assert.Equal(t, f.Nonce, q.Get("nonce"))
				assert.False(t, q.Has("code_verifier"), "the verifier never goes to the authorization endpoint")
				assert.NotContains(t, got.RedirectURL, f.Verifier)
				assert.NotContains(t, got.RedirectURL, "client_secret")
				assert.NotContains(t, got.RedirectURL, "secret-corp")

				for _, v := range []string{f.State, f.Nonce, f.Verifier, got.Handle} {
					raw, err := base64.RawURLEncoding.DecodeString(v)
					require.NoError(t, err)
					assert.Len(t, raw, 32, "every flow secret carries 256 bits")
				}
				assert.Equal(t, "corp", f.Provider)
				assert.Equal(t, "/after?x=1", f.Next, "next is stored verbatim")
			},
		},
		{
			name: "two attempts carry different values", provider: "corp",
			assert: func(t *testing.T, m *oidc.Manager, p *testProvider, first oidc.Authorization, err error) {
				require.NoError(t, err)
				second, err := m.Authorize(t.Context(), "corp", "")
				require.NoError(t, err)

				q1 := authorizeParams(t, first.RedirectURL, p.Issuer()+"/authorize")
				q2 := authorizeParams(t, second.RedirectURL, p.Issuer()+"/authorize")
				for _, k := range []string{"state", "nonce", "code_challenge"} {
					assert.NotEqual(t, q1.Get(k), q2.Get(k), k)
				}
				assert.NotEqual(t, first.Handle, second.Handle)
			},
		},
		{
			name: "consumer scopes are requested exactly", provider: "groups",
			assert: func(t *testing.T, _ *oidc.Manager, p *testProvider, got oidc.Authorization, err error) {
				require.NoError(t, err)
				q := authorizeParams(t, got.RedirectURL, p.Issuer()+"/authorize")
				assert.Equal(t, "openid groups", q.Get("scope"))
				assert.Equal(t, "client-groups", q.Get("client_id"))
			},
		},
		{
			name: "the flow is stored for the default TTL", provider: "corp",
			opts: func(*testing.T, *testProvider) []oidc.ManagerOption {
				return []oidc.ManagerOption{oidc.WithClock(clockwork.NewFakeClockAt(past))}
			},
			assert: func(t *testing.T, m *oidc.Manager, _ *testProvider, got oidc.Authorization, err error) {
				require.NoError(t, err)
				assert.Equal(t, past.Add(10*time.Minute), got.ExpiresAt)
				f := authorizeFlow(t, m, got.Handle)
				assert.Equal(t, past.Add(10*time.Minute), f.ExpiresAt)

				// The default store judges expiry by the manager's clock: by
				// time.Now this flow expired long ago.
				_, err = oidc.WiringOf(m).Flows.Complete(t.Context(), got.Handle, "corp", f.State)
				require.NoError(t, err, "the default store must share the manager's clock")
			},
		},
		{
			name: "the flow is stored for the consumer's TTL", provider: "corp",
			opts: func(*testing.T, *testProvider) []oidc.ManagerOption {
				return []oidc.ManagerOption{
					oidc.WithClock(clockwork.NewFakeClockAt(past)),
					oidc.WithFlowTTL(3 * time.Minute),
				}
			},
			assert: func(t *testing.T, m *oidc.Manager, _ *testProvider, got oidc.Authorization, err error) {
				require.NoError(t, err)
				assert.Equal(t, past.Add(3*time.Minute), got.ExpiresAt)
				assert.Equal(t, past.Add(3*time.Minute), authorizeFlow(t, m, got.Handle).ExpiresAt)
			},
		},
		{
			name: "the configured random source is used", provider: "corp",
			opts: func(*testing.T, *testProvider) []oidc.ManagerOption {
				return []oidc.ManagerOption{oidc.WithRandom(bytes.NewReader(bytes.Repeat([]byte{7}, 4096)))}
			},
			assert: func(t *testing.T, m *oidc.Manager, p *testProvider, got oidc.Authorization, err error) {
				require.NoError(t, err)
				q := authorizeParams(t, got.RedirectURL, p.Issuer()+"/authorize")
				assert.Equal(t, sevens, q.Get("state"))
				assert.Equal(t, sevens, q.Get("nonce"))
				sum := sha256.Sum256([]byte(sevens))
				assert.Equal(t, base64.RawURLEncoding.EncodeToString(sum[:]), q.Get("code_challenge"))
				assert.Equal(t, sevens, got.Handle, "the default store must share the manager's random source")
				assert.Equal(t, sevens, authorizeFlow(t, m, got.Handle).Verifier)
			},
		},
		{
			name: "a consumer flow store receives the flow", provider: "corp", next: "/n",
			opts: func(t *testing.T, _ *testProvider) []oidc.ManagerOption {
				store := NewMockFlowStore(gomock.NewController(t))
				store.EXPECT().Begin(gomock.Any(), gomock.Any()).
					DoAndReturn(func(_ context.Context, f oidc.Flow) (string, error) {
						assert.Equal(t, "corp", f.Provider)
						assert.Equal(t, "/n", f.Next)
						assert.NotEmpty(t, f.State)
						assert.NotEmpty(t, f.Nonce)
						assert.NotEmpty(t, f.Verifier)
						return "consumer-handle", nil
					})
				return []oidc.ManagerOption{oidc.WithFlowStore(store)}
			},
			assert: func(t *testing.T, _ *oidc.Manager, _ *testProvider, got oidc.Authorization, err error) {
				require.NoError(t, err)
				assert.Equal(t, "consumer-handle", got.Handle)
			},
		},
		{
			name: "a store refusal fails the authorization", provider: "corp",
			opts: func(t *testing.T, _ *testProvider) []oidc.ManagerOption {
				store := NewMockFlowStore(gomock.NewController(t))
				store.EXPECT().Begin(gomock.Any(), gomock.Any()).Return("", oidc.ErrFlowStoreFull)
				return []oidc.ManagerOption{oidc.WithFlowStore(store)}
			},
			assert: func(t *testing.T, _ *oidc.Manager, _ *testProvider, got oidc.Authorization, err error) {
				require.ErrorIs(t, err, oidc.ErrFlowStoreFull)
				assert.Empty(t, got.RedirectURL)
				assert.Empty(t, got.Handle)
			},
		},
		{
			name: "the authorization endpoint's own query is kept", provider: "pinned",
			assert: func(t *testing.T, _ *oidc.Manager, p *testProvider, got oidc.Authorization, err error) {
				require.NoError(t, err)
				q := authorizeParams(t, got.RedirectURL, p.Issuer()+"/pinned/authorize")
				assert.Equal(t, "login", q.Get("prompt"))
				assert.Equal(t, "code", q.Get("response_type"))
				assert.Equal(t, int64(0), p.discoveryCalls.Load(), "pinned endpoints are never discovered")
			},
		},
		{
			name: "an unknown provider stores no flow", provider: "nope",
			opts: func(t *testing.T, _ *testProvider) []oidc.ManagerOption {
				return []oidc.ManagerOption{authorizeNoFlowStore(t)}
			},
			assert: func(t *testing.T, _ *oidc.Manager, p *testProvider, got oidc.Authorization, err error) {
				require.ErrorIs(t, err, oidc.ErrUnknownProvider)
				assert.Equal(t, oidc.Authorization{}, got)
				assert.Equal(t, int64(0), p.discoveryCalls.Load())
			},
		},
		{
			name: "an encoded slash is an unknown provider", provider: "corp%2F..",
			opts: func(t *testing.T, _ *testProvider) []oidc.ManagerOption {
				return []oidc.ManagerOption{authorizeNoFlowStore(t)}
			},
			assert: func(t *testing.T, _ *oidc.Manager, _ *testProvider, _ oidc.Authorization, err error) {
				require.ErrorIs(t, err, oidc.ErrUnknownProvider)
			},
		},
		{
			name: "a trailing slash is an unknown provider", provider: "corp/",
			opts: func(t *testing.T, _ *testProvider) []oidc.ManagerOption {
				return []oidc.ManagerOption{authorizeNoFlowStore(t)}
			},
			assert: func(t *testing.T, _ *oidc.Manager, _ *testProvider, _ oidc.Authorization, err error) {
				require.ErrorIs(t, err, oidc.ErrUnknownProvider)
			},
		},
		{
			name: "a discovery failure is a provider failure and stores no flow", provider: "corp",
			setup: func(p *testProvider) { p.failDiscovery.Store(true) },
			opts: func(t *testing.T, _ *testProvider) []oidc.ManagerOption {
				return []oidc.ManagerOption{authorizeNoFlowStore(t)}
			},
			assert: func(t *testing.T, _ *oidc.Manager, _ *testProvider, got oidc.Authorization, err error) {
				require.ErrorIs(t, err, oidc.ErrDiscoveryFailed)
				assert.Equal(t, oidc.Authorization{}, got)
			},
		},
		{
			name: "a failing random source stores no flow", provider: "corp",
			opts: func(t *testing.T, _ *testProvider) []oidc.ManagerOption {
				return []oidc.ManagerOption{oidc.WithRandom(errReader{}), authorizeNoFlowStore(t)}
			},
			assert: func(t *testing.T, _ *oidc.Manager, _ *testProvider, got oidc.Authorization, err error) {
				require.ErrorIs(t, err, errFlowRandom)
				assert.Equal(t, oidc.Authorization{}, got)
			},
		},
		{
			name: "a canceled context stores no flow", provider: "corp",
			ctx: func(ctx context.Context) context.Context {
				c, cancel := context.WithCancel(ctx)
				cancel()
				return c
			},
			opts: func(t *testing.T, _ *testProvider) []oidc.ManagerOption {
				return []oidc.ManagerOption{authorizeNoFlowStore(t)}
			},
			assert: func(t *testing.T, _ *oidc.Manager, _ *testProvider, got oidc.Authorization, err error) {
				require.Error(t, err)
				assert.Equal(t, oidc.Authorization{}, got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := newTestProvider(t)
			if tc.setup != nil {
				tc.setup(p)
			}
			groups := p.Provider("groups")
			groups.Scopes = []string{"openid", "groups"}
			pinned := p.Provider("pinned")
			pinned.AuthorizationEndpoint = p.Issuer() + "/pinned/authorize?prompt=login"
			pinned.TokenEndpoint = p.Issuer() + "/token"
			pinned.JWKSURI = p.Issuer() + "/jwks"
			reg, err := oidc.NewRegistry(p.Provider("corp"), groups, pinned)
			require.NoError(t, err)

			opts := []oidc.ManagerOption{oidc.WithOutboundClient(p.Outbound(t))}
			if tc.opts != nil {
				opts = append(opts, tc.opts(t, p)...)
			}
			m, err := oidc.NewManager(reg, stubBroker{}, opts...)
			require.NoError(t, err)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}
			got, err := m.Authorize(ctx, tc.provider, tc.next)
			tc.assert(t, m, p, got, err)
		})
	}
}
