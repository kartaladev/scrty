package oidc_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/outbound"
	"github.com/kartaladev/scrty/pkg/clock"
)

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
	cacheReg, err := oidc.NewRegistry(p.Provider("corp"))
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
		typedNilEval   *MockAssuranceEvaluator
	)

	type testCase struct {
		name     string
		registry *oidc.Registry
		broker   oidc.IdentityBroker
		opts     []oidc.Option
		assert   func(t *testing.T, m *oidc.RelyingParty, err error)
	}

	fixed := bytes.NewReader(bytes.Repeat([]byte{7}, 4096))
	client := p.Outbound(t)
	flows := NewMockFlowStore(gomock.NewController(t))
	logger := slog.New(slog.DiscardHandler)
	epoch := time.Unix(0, 0)
	refusedConfig := func(fragments ...string) func(t *testing.T, m *oidc.RelyingParty, err error) {
		return func(t *testing.T, m *oidc.RelyingParty, err error) {
			require.ErrorIs(t, err, oidc.ErrConfig)
			assert.Nil(t, m)
			for _, f := range fragments {
				assert.Contains(t, err.Error(), f)
			}
		}
	}

	// cacheRefused and cacheAccepted judge the discovery and key-set cache
	// options, given alone against a corp-only registry.
	cacheRefused := func(t *testing.T, _ *oidc.RelyingParty, err error) { require.ErrorIs(t, err, oidc.ErrConfig) }
	cacheAccepted := func(t *testing.T, _ *oidc.RelyingParty, err error) { require.NoError(t, err) }

	cases := []testCase{
		{name: "defaults construct with no options", registry: reg, broker: stubBroker{},
			assert: func(t *testing.T, m *oidc.RelyingParty, err error) {
				require.NoError(t, err)
				require.NotNil(t, m)
				assert.Equal(t, []string{"corp", "partner"}, m.Providers())
				assert.Nil(t, m.Links(), "a broker that is not link-backed offers no link store")
				assert.Nil(t, m.RoleSyncProviders(), "a broker that does not sync roles names no provider")

				w := oidc.WiringOf(m)
				assert.NotNil(t, w.Out, "the default outbound client is built")
				assert.Equal(t, rand.Reader, w.Random, "the default random source is crypto/rand")
				assert.Same(t, slog.Default(), w.Log, "the default logger is slog.Default()")
				assert.Equal(t, clock.System(), w.Clock, "the default clock is clock.System()")
				assert.IsType(t, &oidc.MemoryFlowStore{}, w.Flows, "the default flow store is in memory")
				assert.Equal(t, oidc.DefaultFlowTTL, w.FlowTTL, "the default flow TTL is DefaultFlowTTL")
				assert.Equal(t, 10*time.Minute, oidc.DefaultFlowTTL)
			}},
		{name: "a zero flow TTL is refused", registry: reg, broker: stubBroker{},
			opts: []oidc.Option{oidc.WithFlowTTL(0)}, assert: refusedConfig("WithFlowTTL")},
		{name: "a negative flow TTL is refused", registry: reg, broker: stubBroker{},
			opts: []oidc.Option{oidc.WithFlowTTL(-time.Second)}, assert: refusedConfig("WithFlowTTL")},
		{name: "a negative clock skew is refused", registry: reg, broker: stubBroker{},
			opts: []oidc.Option{oidc.WithClockSkew(-time.Second)}, assert: refusedConfig("WithClockSkew")},
		{name: "a zero clock skew is accepted", registry: reg, broker: stubBroker{},
			opts: []oidc.Option{oidc.WithClockSkew(0)},
			assert: func(t *testing.T, m *oidc.RelyingParty, err error) {
				require.NoError(t, err)
				require.NotNil(t, m)
			}},
		{name: "a clock skew above 5 minutes is refused", registry: reg, broker: stubBroker{},
			opts: []oidc.Option{oidc.WithClockSkew(5*time.Minute + time.Nanosecond)}, assert: refusedConfig("WithClockSkew")},
		{name: "a clock skew of exactly 5 minutes is accepted", registry: reg, broker: stubBroker{},
			opts: []oidc.Option{oidc.WithClockSkew(5 * time.Minute)},
			assert: func(t *testing.T, m *oidc.RelyingParty, err error) {
				require.NoError(t, err)
				require.NotNil(t, m)
			}},
		{name: "a logout-token max age above one hour is refused", registry: reg, broker: stubBroker{},
			opts:   []oidc.Option{oidc.WithLogoutTokenMaxAge(time.Hour + time.Nanosecond)},
			assert: refusedConfig("WithLogoutTokenMaxAge")},
		{name: "a logout-token max age of exactly one hour is accepted", registry: reg, broker: stubBroker{},
			opts: []oidc.Option{oidc.WithLogoutTokenMaxAge(time.Hour)},
			assert: func(t *testing.T, m *oidc.RelyingParty, err error) {
				require.NoError(t, err)
				require.NotNil(t, m)
			}},
		{name: "a zero logout-token max age is refused", registry: reg, broker: stubBroker{},
			opts: []oidc.Option{oidc.WithLogoutTokenMaxAge(0)}, assert: refusedConfig("WithLogoutTokenMaxAge")},
		{name: "a negative logout-token max age is refused", registry: reg, broker: stubBroker{},
			opts:   []oidc.Option{oidc.WithLogoutTokenMaxAge(-time.Second)},
			assert: refusedConfig("WithLogoutTokenMaxAge")},
		{name: "a nil registry is refused", registry: nil, broker: stubBroker{},
			assert: refusedConfig("registry")},
		{name: "a zero-value registry with no providers is refused", registry: &oidc.Registry{}, broker: stubBroker{},
			assert: refusedConfig("registry")},
		{name: "a missing broker is refused as a missing port", registry: reg, broker: nil,
			assert: func(t *testing.T, m *oidc.RelyingParty, err error) {
				require.ErrorIs(t, err, oidc.ErrConfig)
				require.ErrorIs(t, err, identity.ErrMissingPort)
				assert.Nil(t, m)
			}},
		{name: "a typed-nil broker is refused as a missing port", registry: reg, broker: typedNilBroker,
			assert: func(t *testing.T, m *oidc.RelyingParty, err error) {
				require.ErrorIs(t, err, oidc.ErrConfig)
				require.ErrorIs(t, err, identity.ErrMissingPort)
				assert.Nil(t, m)
			}},
		{name: "a typed-nil flow store is refused", registry: reg, broker: stubBroker{},
			opts: []oidc.Option{oidc.WithFlowStore(typedNilFlows)}, assert: refusedConfig("WithFlowStore")},
		{name: "a typed-nil random source is refused", registry: reg, broker: stubBroker{},
			opts: []oidc.Option{oidc.WithRandom(typedNilRandom)}, assert: refusedConfig("WithRandom")},
		{name: "an http issuer is refused with the default client", registry: httpIssuer, broker: stubBroker{},
			assert: refusedConfig("corp", "issuer", "http")},
		{name: "an http redirect URL is refused with the default client", registry: httpRedirect, broker: stubBroker{},
			assert: refusedConfig("corp", "redirect URL", "http")},
		{name: "an http end-session endpoint is refused with the default client", registry: httpEndSession, broker: stubBroker{},
			assert: refusedConfig("corp", "end-session", "http")},
		{name: "an http pinned endpoint is refused with the default client", registry: httpPinned, broker: stubBroker{},
			assert: refusedConfig("corp", "token endpoint", "http")},
		{name: "an http issuer is accepted with a client allowing http", registry: httpIssuer, broker: stubBroker{},
			opts: []oidc.Option{oidc.WithOutboundClient(allowHTTP)},
			assert: func(t *testing.T, m *oidc.RelyingParty, err error) {
				require.NoError(t, err)
				assert.NotNil(t, m)
			}},
		{name: "a nil outbound client is refused", registry: reg, broker: stubBroker{},
			opts: []oidc.Option{oidc.WithOutboundClient(nil)}, assert: refusedConfig("WithOutboundClient")},
		{name: "a nil random source is refused", registry: reg, broker: stubBroker{},
			opts: []oidc.Option{oidc.WithRandom(nil)}, assert: refusedConfig("WithRandom")},
		{name: "a nil clock is refused", registry: reg, broker: stubBroker{},
			opts: []oidc.Option{oidc.WithClock(nil)}, assert: refusedConfig("WithClock")},
		{name: "a typed-nil clock is refused like an untyped one", registry: reg, broker: stubBroker{},
			opts: []oidc.Option{oidc.WithClock((*nilClock)(nil))}, assert: refusedConfig("WithClock")},
		{name: "a consumer clock with only Now is accepted", registry: reg, broker: stubBroker{},
			opts: []oidc.Option{oidc.WithClock(fixedClock{at: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)})},
			assert: func(t *testing.T, m *oidc.RelyingParty, err error) {
				require.NoError(t, err)
				assert.NotNil(t, m)
			}},
		{name: "a nil flow store is refused", registry: reg, broker: stubBroker{},
			opts: []oidc.Option{oidc.WithFlowStore(nil)}, assert: refusedConfig("WithFlowStore")},
		{name: "a nil logger is refused", registry: reg, broker: stubBroker{},
			opts: []oidc.Option{oidc.WithLogger(nil)}, assert: refusedConfig("WithLogger")},
		{name: "a nil option is ignored", registry: reg, broker: stubBroker{},
			opts: []oidc.Option{nil},
			assert: func(t *testing.T, m *oidc.RelyingParty, err error) {
				require.NoError(t, err)
				assert.NotNil(t, m)
			}},
		{name: "a broker option naming an unregistered provider is refused", registry: reg,
			broker: scopedStubBroker{providers: []string{"corp", "corpp"}},
			assert: refusedConfig("corpp")},
		{name: "a broker option naming registered providers is accepted", registry: reg,
			broker: scopedStubBroker{providers: []string{"partner", "corp"}},
			assert: func(t *testing.T, m *oidc.RelyingParty, err error) {
				require.NoError(t, err)
				assert.NotNil(t, m)
			}},
		{name: "a link-backed, role-syncing broker is exposed", registry: reg,
			broker: linkedStubBroker{links: links, roleSync: []string{"partner"}},
			assert: func(t *testing.T, m *oidc.RelyingParty, err error) {
				require.NoError(t, err)
				assert.Same(t, links, m.Links())
				assert.Equal(t, []string{"partner"}, m.RoleSyncProviders())
			}},
		{name: "role sync for an unregistered provider is refused", registry: reg,
			broker: linkedStubBroker{links: links, roleSync: []string{"corpp"}},
			assert: refusedConfig("corpp")},
		{name: "consumer replacements are accepted", registry: reg, broker: stubBroker{},
			opts: []oidc.Option{
				oidc.WithRandom(fixed),
				oidc.WithOutboundClient(client),
				oidc.WithClock(clockwork.NewFakeClockAt(epoch)),
				oidc.WithFlowStore(flows),
				oidc.WithLogger(logger),
				oidc.WithFlowTTL(3 * time.Minute),
			},
			assert: func(t *testing.T, m *oidc.RelyingParty, err error) {
				require.NoError(t, err)
				w := oidc.WiringOf(m)
				assert.Equal(t, 3*time.Minute, w.FlowTTL)
				assert.Same(t, client, w.Out)
				assert.Same(t, fixed, w.Random)
				assert.Same(t, flows, w.Flows)
				assert.Same(t, logger, w.Log)
				require.NotNil(t, w.Clock)
				assert.Equal(t, epoch, w.Clock.Now())
				// That each is the one actually used is proven where it is
				// first consumed: discovery, Authorize, expiry.
			}},
		{name: "assurance for an unregistered provider is refused, naming it", registry: reg, broker: stubBroker{},
			opts: []oidc.Option{
				oidc.WithProviderAssurance("corpp", oidc.Assurance{AcceptedAMR: []string{"mfa"}}),
			},
			assert: refusedConfig("corpp")},
		{name: "an empty accepted amr value is refused without repeating the others", registry: reg, broker: stubBroker{},
			opts: []oidc.Option{
				oidc.WithProviderAssurance("corp", oidc.Assurance{AcceptedAMR: []string{"mfa-value-x", ""}}),
			},
			assert: func(t *testing.T, m *oidc.RelyingParty, err error) {
				refusedConfig("corp", "AcceptedAMR")(t, m, err)
				assert.NotContains(t, err.Error(), "mfa-value-x", "no configured value reaches error text")
			}},
		{name: "an empty accepted acr value is refused", registry: reg, broker: stubBroker{},
			opts: []oidc.Option{
				oidc.WithProviderAssurance("corp", oidc.Assurance{AcceptedACR: []string{""}}),
			},
			assert: refusedConfig("corp", "AcceptedACR")},
		{name: "an empty requested acr value is refused", registry: reg, broker: stubBroker{},
			opts: []oidc.Option{
				oidc.WithProviderAssurance("corp", oidc.Assurance{AcceptedAMR: []string{"mfa"}, RequestACR: []string{"gold", ""}}),
			},
			assert: refusedConfig("corp", "RequestACR")},
		{name: "a requested acr value containing a space is refused without repeating it", registry: reg, broker: stubBroker{},
			opts: []oidc.Option{
				oidc.WithProviderAssurance("corp", oidc.Assurance{AcceptedAMR: []string{"mfa"}, RequestACR: []string{"urn:corp:loa 2"}}),
			},
			assert: func(t *testing.T, m *oidc.RelyingParty, err error) {
				refusedConfig("corp", "RequestACR")(t, m, err)
				assert.NotContains(t, err.Error(), "urn:corp:loa 2", "no configured value reaches error text")
			}},
		{name: "a requested acr value containing a tab is refused without repeating it", registry: reg, broker: stubBroker{},
			opts: []oidc.Option{
				oidc.WithProviderAssurance("corp", oidc.Assurance{AcceptedAMR: []string{"mfa"}, RequestACR: []string{"a\tb"}}),
			},
			assert: func(t *testing.T, m *oidc.RelyingParty, err error) {
				refusedConfig("corp", "RequestACR")(t, m, err)
				assert.NotContains(t, err.Error(), "a\tb", "no configured value reaches error text")
			}},
		{name: "a requested acr value containing a newline is refused without repeating it", registry: reg, broker: stubBroker{},
			opts: []oidc.Option{
				oidc.WithProviderAssurance("corp", oidc.Assurance{AcceptedAMR: []string{"mfa"}, RequestACR: []string{"a\nb"}}),
			},
			assert: func(t *testing.T, m *oidc.RelyingParty, err error) {
				refusedConfig("corp", "RequestACR")(t, m, err)
				assert.NotContains(t, err.Error(), "a\nb", "no configured value reaches error text")
			}},
		{name: "an undefined match mode is refused", registry: reg, broker: stubBroker{},
			opts: []oidc.Option{
				oidc.WithProviderAssurance("corp", oidc.Assurance{AcceptedAMR: []string{"mfa"}, Match: 7}),
			},
			assert: func(t *testing.T, m *oidc.RelyingParty, err error) {
				refusedConfig("corp", "Match")(t, m, err)
				assert.NotContains(t, err.Error(), "7", "no configured value reaches error text")
			}},
		{name: "a negative match mode is refused", registry: reg, broker: stubBroker{},
			opts: []oidc.Option{
				oidc.WithProviderAssurance("corp", oidc.Assurance{AcceptedAMR: []string{"mfa"}, Match: -1}),
			},
			assert: refusedConfig("corp", "Match")},
		{name: "requesting an acr while accepting none is valid", registry: reg, broker: stubBroker{},
			opts: []oidc.Option{
				oidc.WithProviderAssurance("corp", oidc.Assurance{AcceptedAMR: []string{"mfa"}, RequestACR: []string{"gold"}}),
			},
			assert: func(t *testing.T, m *oidc.RelyingParty, err error) {
				require.NoError(t, err)
				assert.NotNil(t, m)
			}},
		{name: "a nil assurance evaluator is refused", registry: reg, broker: stubBroker{},
			opts: []oidc.Option{oidc.WithAssuranceEvaluator(nil)}, assert: refusedConfig("WithAssuranceEvaluator")},
		{name: "a typed-nil assurance evaluator is refused", registry: reg, broker: stubBroker{},
			opts: []oidc.Option{oidc.WithAssuranceEvaluator(typedNilEval)}, assert: refusedConfig("WithAssuranceEvaluator")},
		{name: "configured with nothing accepted is valid", registry: reg, broker: stubBroker{},
			opts: []oidc.Option{
				oidc.WithProviderAssurance("corp", oidc.Assurance{}),
			},
			assert: func(t *testing.T, m *oidc.RelyingParty, err error) {
				require.NoError(t, err)
				assert.NotNil(t, m)
			}},
		{name: "a zero TTL is refused", registry: cacheReg, broker: stubBroker{}, opts: []oidc.Option{oidc.WithDiscoveryTTL(0)}, assert: cacheRefused},
		{name: "a negative TTL is refused", registry: cacheReg, broker: stubBroker{}, opts: []oidc.Option{oidc.WithDiscoveryTTL(-time.Minute)}, assert: cacheRefused},
		{name: "a positive TTL is accepted", registry: cacheReg, broker: stubBroker{}, opts: []oidc.Option{oidc.WithDiscoveryTTL(time.Hour)}, assert: cacheAccepted},
		{name: "a zero backoff base is refused", registry: cacheReg, broker: stubBroker{}, opts: []oidc.Option{oidc.WithDiscoveryFailureBackoff(0, time.Second)}, assert: cacheRefused},
		{name: "a negative backoff base is refused", registry: cacheReg, broker: stubBroker{}, opts: []oidc.Option{oidc.WithDiscoveryFailureBackoff(-time.Second, time.Second)}, assert: cacheRefused},
		{name: "a backoff cap below the base is refused", registry: cacheReg, broker: stubBroker{}, opts: []oidc.Option{oidc.WithDiscoveryFailureBackoff(2*time.Second, time.Second)}, assert: cacheRefused},
		{name: "a zero cooldown is refused", registry: cacheReg, broker: stubBroker{}, opts: []oidc.Option{oidc.WithJWKSRefetchCooldown(0)}, assert: cacheRefused},
		{name: "a negative cooldown is refused", registry: cacheReg, broker: stubBroker{}, opts: []oidc.Option{oidc.WithJWKSRefetchCooldown(-time.Second)}, assert: cacheRefused},
		{name: "a positive cooldown is accepted", registry: cacheReg, broker: stubBroker{}, opts: []oidc.Option{oidc.WithJWKSRefetchCooldown(time.Minute)}, assert: cacheAccepted},
		{name: "a negative stale window is refused", registry: cacheReg, broker: stubBroker{}, opts: []oidc.Option{oidc.WithDiscoveryStaleWhileError(-time.Second)}, assert: cacheRefused},
		{name: "a zero stale window is accepted", registry: cacheReg, broker: stubBroker{}, opts: []oidc.Option{oidc.WithDiscoveryStaleWhileError(0)}, assert: cacheAccepted},
		{name: "a positive stale window is accepted", registry: cacheReg, broker: stubBroker{}, opts: []oidc.Option{oidc.WithDiscoveryStaleWhileError(time.Minute)}, assert: cacheAccepted},
		{name: "a backoff cap equal to the base is accepted", registry: cacheReg, broker: stubBroker{}, opts: []oidc.Option{oidc.WithDiscoveryFailureBackoff(time.Second, time.Second)}, assert: cacheAccepted},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m, err := oidc.NewRelyingParty(tc.registry, tc.broker, tc.opts...)
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
	m, err := oidc.NewRelyingParty(reg, stubBroker{})
	require.NoError(t, err)

	names := m.Providers()
	require.Equal(t, []string{"corp"}, names)
	names[0] = "mutated"
	assert.Equal(t, []string{"corp"}, m.Providers())
}

// flushProvider is a minimal, statically valid provider: nothing in these
// tests ever reaches discovery or the network.
func flushProvider() oidc.Provider {
	return oidc.Provider{
		Name: "corp", Issuer: "https://idp.example",
		ClientID: "client-corp", ClientSecret: "secret-corp",
		RedirectURL: "https://app.example/callback",
	}
}

// TestManagerFlushRefusalLogs pins spec oidc-login scenario "Manager flushes
// its broker": flushing the manager reports its own pending count and, when
// its broker can flush, the broker's; a broker that cannot flush is skipped
// without error.
func TestManagerFlushRefusalLogs(t *testing.T) {
	t.Parallel()

	// flowFault is a flow-store failure the manager's own sampler records
	// (logCallbackFailure), unlike ErrInvalidState, which is never logged.
	flowFault := errors.New("oidc_test: flow store fault fixture")

	type testCase struct {
		name  string
		build func(t *testing.T) (m *oidc.RelyingParty, logs *bytes.Buffer)

		// afterFlush runs after FlushRefusalLogs, only for the row proving the
		// manager still works afterward; nil for every other row.
		afterFlush func(t *testing.T, m *oidc.RelyingParty)

		assert func(t *testing.T, err error, logs string)
	}

	cases := []testCase{
		{
			name: "the manager's own pending count is reported",
			build: func(t *testing.T) (*oidc.RelyingParty, *bytes.Buffer) {
				t.Helper()

				logs := &bytes.Buffer{}
				reg, err := oidc.NewRegistry(flushProvider())
				require.NoError(t, err)

				flows := NewMockFlowStore(gomock.NewController(t))
				flows.EXPECT().Complete(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(oidc.Flow{}, flowFault).Times(3)

				m, err := oidc.NewRelyingParty(reg, NewMockIdentityBroker(gomock.NewController(t)),
					oidc.WithFlowStore(flows), oidc.WithClock(flushFixedClock()), oidc.WithLogger(testTextLogger(logs)))
				require.NoError(t, err)

				for range 3 {
					_, err := m.Callback(t.Context(), "corp", "the-code", "the-state", "the-handle")
					require.Error(t, err)
				}

				return m, logs
			},
			assert: func(t *testing.T, err error, logs string) {
				require.NoError(t, err)

				sums := flushSummaries(t, logs, "oidc refusals suppressed")
				require.Len(t, sums, 1, "three refusals of one reason must flush to exactly one summary record")
				assert.Equal(t, 2, sums[0], "the first refusal was already written; the flush owes the other two")
			},
		},
		{
			name: "a broker's pending count is reached through the manager",
			build: func(t *testing.T) (*oidc.RelyingParty, *bytes.Buffer) {
				t.Helper()

				brokerLogs := &bytes.Buffer{}
				broker, err := oidc.NewBroker(oidc.NewMemoryLinkStore(), NewMockUserLoader(gomock.NewController(t)),
					oidc.WithBrokerClock(flushFixedClock()), oidc.WithBrokerLogger(testTextLogger(brokerLogs)))
				require.NoError(t, err)

				ext := brokerCorpIdentity()
				for range 3 {
					_, err := broker.Broker(t.Context(), ext)
					require.ErrorIs(t, err, oidc.ErrNoLinkedAccount)
				}

				reg, err := oidc.NewRegistry(flushProvider())
				require.NoError(t, err)
				m, err := oidc.NewRelyingParty(reg, broker)
				require.NoError(t, err)

				return m, brokerLogs
			},
			assert: func(t *testing.T, err error, logs string) {
				require.NoError(t, err)

				sums := flushSummaries(t, logs, "oidc broker refusals suppressed")
				require.Len(t, sums, 1, "the manager must reach its broker's flush")
				assert.Equal(t, 2, sums[0])
			},
		},
		{
			name: "a consumer broker without a flush is skipped without error",
			build: func(t *testing.T) (*oidc.RelyingParty, *bytes.Buffer) {
				t.Helper()

				reg, err := oidc.NewRegistry(flushProvider())
				require.NoError(t, err)

				m, err := oidc.NewRelyingParty(reg, NewMockIdentityBroker(gomock.NewController(t)))
				require.NoError(t, err)

				return m, &bytes.Buffer{}
			},
			assert: func(t *testing.T, err error, _ string) {
				require.NoError(t, err, "a broker with no flush of its own must not turn the manager's flush into an error")
			},
		},
		{
			name: "the manager still works after a flush",
			build: func(t *testing.T) (*oidc.RelyingParty, *bytes.Buffer) {
				t.Helper()

				logs := &bytes.Buffer{}
				reg, err := oidc.NewRegistry(flushProvider())
				require.NoError(t, err)

				flows := NewMockFlowStore(gomock.NewController(t))
				flows.EXPECT().Complete(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(oidc.Flow{}, flowFault).Times(4)

				m, err := oidc.NewRelyingParty(reg, NewMockIdentityBroker(gomock.NewController(t)),
					oidc.WithFlowStore(flows), oidc.WithClock(flushFixedClock()), oidc.WithLogger(testTextLogger(logs)))
				require.NoError(t, err)

				for range 3 {
					_, err := m.Callback(t.Context(), "corp", "the-code", "the-state", "the-handle")
					require.Error(t, err)
				}

				return m, logs
			},
			afterFlush: func(t *testing.T, m *oidc.RelyingParty) {
				t.Helper()

				// One more callback failure of the same reason, after the
				// flush, must be written again rather than counted as still
				// suppressed.
				_, err := m.Callback(t.Context(), "corp", "the-code", "the-state", "the-handle")
				require.Error(t, err)
			},
			assert: func(t *testing.T, err error, logs string) {
				require.NoError(t, err)

				sums := flushSummaries(t, logs, "oidc refusals suppressed")
				require.Len(t, sums, 1)
				assert.Equal(t, 2, sums[0])

				assert.Equal(t, 2, strings.Count(logs, `msg="oidc callback failed"`),
					"the refusal after the flush must be written again, not suppressed")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m, logs := tc.build(t)
			err := m.FlushRefusalLogs()

			if tc.afterFlush != nil {
				tc.afterFlush(t, m)
			}

			tc.assert(t, err, logs.String())
		})
	}
}
