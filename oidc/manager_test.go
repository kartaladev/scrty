package oidc_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/outbound"
)

// stubBroker resolves every identity to one fixed principal. Where a test must
// verify calls, it uses the generated MockIdentityBroker instead.
type stubBroker struct{}

func (stubBroker) Broker(context.Context, oidc.ExternalIdentity) (*identity.Principal, error) {
	return &identity.Principal{ID: "user-1"}, nil
}

// scopedStubBroker is a broker whose options name providers, as the library's
// own broker does when provisioning or role derivation is configured.
type scopedStubBroker struct {
	stubBroker
	providers []string
}

func (b scopedStubBroker) ConfiguredProviders() []string { return b.providers }

// linkedStubBroker is a broker backed by a link store that syncs roles for
// some providers.
type linkedStubBroker struct {
	stubBroker
	links    oidc.LinkStore
	roleSync []string
}

func (b linkedStubBroker) Links() oidc.LinkStore       { return b.links }
func (b linkedStubBroker) RoleSyncProviders() []string { return b.roleSync }

func TestNewManagerOptions(t *testing.T) {
	t.Parallel()

	p := newTestProvider(t)
	second := p.Provider("partner")
	reg, err := oidc.NewRegistry(p.Provider("corp"), second)
	require.NoError(t, err)

	links := NewMockLinkStore(gomock.NewController(t))

	// plainText registers a provider "corp" whose URLs are https except where
	// fn makes them http; the registry leaves the scheme to the manager.
	plainText := func(t *testing.T, fn func(p *oidc.Provider)) *oidc.Registry {
		t.Helper()
		pr := oidc.Provider{
			Name: "corp", Issuer: "https://idp.example", ClientID: "client",
			ClientSecret: "s3cr3t-value", RedirectURL: "https://app.example/login/oauth2/callback/corp",
		}
		fn(&pr)
		r, err := oidc.NewRegistry(pr)
		require.NoError(t, err)
		return r
	}
	httpIssuer := plainText(t, func(p *oidc.Provider) { p.Issuer = "http://localhost:8080/realms/dev" })
	httpRedirect := plainText(t, func(p *oidc.Provider) { p.RedirectURL = "http://localhost:3000/cb" })
	httpEndSession := plainText(t, func(p *oidc.Provider) { p.EndSessionEndpoint = "http://idp.example/logout" })
	httpPinned := plainText(t, func(p *oidc.Provider) {
		p.AuthorizationEndpoint = "https://idp.example/authorize"
		p.TokenEndpoint = "http://idp.example/token"
		p.JWKSURI = "https://idp.example/jwks"
	})
	allowHTTP, err := outbound.New(outbound.WithAllowedSchemes("http"))
	require.NoError(t, err)

	var (
		typedNilBroker *MockIdentityBroker
		typedNilFlows  *MockFlowStore
		typedNilRandom *bytes.Reader
	)

	type testCase struct {
		name     string
		registry *oidc.Registry
		broker   oidc.IdentityBroker
		opts     []oidc.ManagerOption
		assert   func(t *testing.T, m *oidc.Manager, err error)
	}

	fixed := bytes.NewReader(bytes.Repeat([]byte{7}, 4096))
	client := p.Outbound(t)
	flows := NewMockFlowStore(gomock.NewController(t))
	logger := slog.New(slog.DiscardHandler)
	epoch := time.Unix(0, 0)
	refusedConfig := func(fragments ...string) func(t *testing.T, m *oidc.Manager, err error) {
		return func(t *testing.T, m *oidc.Manager, err error) {
			require.ErrorIs(t, err, oidc.ErrConfig)
			assert.Nil(t, m)
			for _, f := range fragments {
				assert.Contains(t, err.Error(), f)
			}
		}
	}

	cases := []testCase{
		{name: "defaults construct with no options", registry: reg, broker: stubBroker{},
			assert: func(t *testing.T, m *oidc.Manager, err error) {
				require.NoError(t, err)
				require.NotNil(t, m)
				assert.Equal(t, []string{"corp", "partner"}, m.Providers())
				assert.Nil(t, m.Links(), "a broker that is not link-backed offers no link store")
				assert.Nil(t, m.RoleSyncProviders(), "a broker that does not sync roles names no provider")

				w := oidc.WiringOf(m)
				assert.NotNil(t, w.Out, "the default outbound client is built")
				assert.Equal(t, rand.Reader, w.Random, "the default random source is crypto/rand")
				assert.Same(t, slog.Default(), w.Log, "the default logger is slog.Default()")
				require.NotNil(t, w.Now)
				assert.WithinDuration(t, time.Now(), w.Now(), time.Minute, "the default clock is time.Now")
				assert.IsType(t, &oidc.MemoryFlowStore{}, w.Flows, "the default flow store is in memory")
				assert.Equal(t, oidc.DefaultFlowTTL, w.FlowTTL, "the default flow TTL is DefaultFlowTTL")
				assert.Equal(t, 10*time.Minute, oidc.DefaultFlowTTL)
			}},
		{name: "a zero flow TTL is refused", registry: reg, broker: stubBroker{},
			opts: []oidc.ManagerOption{oidc.WithFlowTTL(0)}, assert: refusedConfig("WithFlowTTL")},
		{name: "a negative flow TTL is refused", registry: reg, broker: stubBroker{},
			opts: []oidc.ManagerOption{oidc.WithFlowTTL(-time.Second)}, assert: refusedConfig("WithFlowTTL")},
		{name: "a negative clock skew is refused", registry: reg, broker: stubBroker{},
			opts: []oidc.ManagerOption{oidc.WithClockSkew(-time.Second)}, assert: refusedConfig("WithClockSkew")},
		{name: "a zero clock skew is accepted", registry: reg, broker: stubBroker{},
			opts: []oidc.ManagerOption{oidc.WithClockSkew(0)},
			assert: func(t *testing.T, m *oidc.Manager, err error) {
				require.NoError(t, err)
				require.NotNil(t, m)
			}},
		{name: "a zero logout-token max age is refused", registry: reg, broker: stubBroker{},
			opts: []oidc.ManagerOption{oidc.WithLogoutTokenMaxAge(0)}, assert: refusedConfig("WithLogoutTokenMaxAge")},
		{name: "a negative logout-token max age is refused", registry: reg, broker: stubBroker{},
			opts:   []oidc.ManagerOption{oidc.WithLogoutTokenMaxAge(-time.Second)},
			assert: refusedConfig("WithLogoutTokenMaxAge")},
		{name: "a nil registry is refused", registry: nil, broker: stubBroker{},
			assert: refusedConfig("registry")},
		{name: "a zero-value registry with no providers is refused", registry: &oidc.Registry{}, broker: stubBroker{},
			assert: refusedConfig("registry")},
		{name: "a missing broker is refused as a missing port", registry: reg, broker: nil,
			assert: func(t *testing.T, m *oidc.Manager, err error) {
				require.ErrorIs(t, err, oidc.ErrConfig)
				require.ErrorIs(t, err, identity.ErrMissingPort)
				assert.Nil(t, m)
			}},
		{name: "a typed-nil broker is refused as a missing port", registry: reg, broker: typedNilBroker,
			assert: func(t *testing.T, m *oidc.Manager, err error) {
				require.ErrorIs(t, err, oidc.ErrConfig)
				require.ErrorIs(t, err, identity.ErrMissingPort)
				assert.Nil(t, m)
			}},
		{name: "a typed-nil flow store is refused", registry: reg, broker: stubBroker{},
			opts: []oidc.ManagerOption{oidc.WithFlowStore(typedNilFlows)}, assert: refusedConfig("WithFlowStore")},
		{name: "a typed-nil random source is refused", registry: reg, broker: stubBroker{},
			opts: []oidc.ManagerOption{oidc.WithRandom(typedNilRandom)}, assert: refusedConfig("WithRandom")},
		{name: "an http issuer is refused with the default client", registry: httpIssuer, broker: stubBroker{},
			assert: refusedConfig("corp", "issuer", "http")},
		{name: "an http redirect URL is refused with the default client", registry: httpRedirect, broker: stubBroker{},
			assert: refusedConfig("corp", "redirect URL", "http")},
		{name: "an http end-session endpoint is refused with the default client", registry: httpEndSession, broker: stubBroker{},
			assert: refusedConfig("corp", "end-session", "http")},
		{name: "an http pinned endpoint is refused with the default client", registry: httpPinned, broker: stubBroker{},
			assert: refusedConfig("corp", "token endpoint", "http")},
		{name: "an http issuer is accepted with a client allowing http", registry: httpIssuer, broker: stubBroker{},
			opts: []oidc.ManagerOption{oidc.WithOutboundClient(allowHTTP)},
			assert: func(t *testing.T, m *oidc.Manager, err error) {
				require.NoError(t, err)
				assert.NotNil(t, m)
			}},
		{name: "a nil outbound client is refused", registry: reg, broker: stubBroker{},
			opts: []oidc.ManagerOption{oidc.WithOutboundClient(nil)}, assert: refusedConfig("WithOutboundClient")},
		{name: "a nil random source is refused", registry: reg, broker: stubBroker{},
			opts: []oidc.ManagerOption{oidc.WithRandom(nil)}, assert: refusedConfig("WithRandom")},
		{name: "a nil clock is refused", registry: reg, broker: stubBroker{},
			opts: []oidc.ManagerOption{oidc.WithClock(nil)}, assert: refusedConfig("WithClock")},
		{name: "a nil flow store is refused", registry: reg, broker: stubBroker{},
			opts: []oidc.ManagerOption{oidc.WithFlowStore(nil)}, assert: refusedConfig("WithFlowStore")},
		{name: "a nil logger is refused", registry: reg, broker: stubBroker{},
			opts: []oidc.ManagerOption{oidc.WithLogger(nil)}, assert: refusedConfig("WithLogger")},
		{name: "a nil option is ignored", registry: reg, broker: stubBroker{},
			opts: []oidc.ManagerOption{nil},
			assert: func(t *testing.T, m *oidc.Manager, err error) {
				require.NoError(t, err)
				assert.NotNil(t, m)
			}},
		{name: "a broker option naming an unregistered provider is refused", registry: reg,
			broker: scopedStubBroker{providers: []string{"corp", "corpp"}},
			assert: refusedConfig("corpp")},
		{name: "a broker option naming registered providers is accepted", registry: reg,
			broker: scopedStubBroker{providers: []string{"partner", "corp"}},
			assert: func(t *testing.T, m *oidc.Manager, err error) {
				require.NoError(t, err)
				assert.NotNil(t, m)
			}},
		{name: "a link-backed, role-syncing broker is exposed", registry: reg,
			broker: linkedStubBroker{links: links, roleSync: []string{"partner"}},
			assert: func(t *testing.T, m *oidc.Manager, err error) {
				require.NoError(t, err)
				assert.Same(t, links, m.Links())
				assert.Equal(t, []string{"partner"}, m.RoleSyncProviders())
			}},
		{name: "role sync for an unregistered provider is refused", registry: reg,
			broker: linkedStubBroker{links: links, roleSync: []string{"corpp"}},
			assert: refusedConfig("corpp")},
		{name: "consumer replacements are accepted", registry: reg, broker: stubBroker{},
			opts: []oidc.ManagerOption{
				oidc.WithRandom(fixed),
				oidc.WithOutboundClient(client),
				oidc.WithClock(func() time.Time { return epoch }),
				oidc.WithFlowStore(flows),
				oidc.WithLogger(logger),
				oidc.WithFlowTTL(3 * time.Minute),
			},
			assert: func(t *testing.T, m *oidc.Manager, err error) {
				require.NoError(t, err)
				w := oidc.WiringOf(m)
				assert.Equal(t, 3*time.Minute, w.FlowTTL)
				assert.Same(t, client, w.Out)
				assert.Same(t, fixed, w.Random)
				assert.Same(t, flows, w.Flows)
				assert.Same(t, logger, w.Log)
				require.NotNil(t, w.Now)
				assert.Equal(t, epoch, w.Now())
				// That each is the one actually used is proven where it is
				// first consumed: discovery, Authorize, expiry.
			}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m, err := oidc.NewManager(tc.registry, tc.broker, tc.opts...)
			tc.assert(t, m, err)
		})
	}
}

// TestManagerProvidersIsTheCallersCopy pins that the accessor cannot be used
// to rewrite the registry's order.
func TestManagerProvidersIsTheCallersCopy(t *testing.T) {
	t.Parallel()

	reg, err := oidc.NewRegistry(newTestProvider(t).Provider("corp"))
	require.NoError(t, err)
	m, err := oidc.NewManager(reg, stubBroker{})
	require.NoError(t, err)

	names := m.Providers()
	require.Equal(t, []string{"corp"}, names)
	names[0] = "mutated"
	assert.Equal(t, []string{"corp"}, m.Providers())
}
