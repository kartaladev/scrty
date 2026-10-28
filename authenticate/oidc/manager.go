package oidc

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"slices"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/outbound"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/logsample"
)

// refusalLogInterval is how long one written refusal record suppresses
// further records for the same key.
const refusalLogInterval = time.Minute

// Manager drives OpenID Connect logins against the providers of a Registry:
// discovery, authorization, the callback and token verification. It resolves
// verified identities through an IdentityBroker and creates no session itself.
//
// Build one with NewManager. A Manager is safe for concurrent use.
type Manager struct {
	registry *Registry
	out      *outbound.Client
	random   io.Reader
	clock    clock.Clock
	flows    FlowStore
	flowTTL  time.Duration
	broker   IdentityBroker
	log      *slog.Logger
	sampler  *logsample.Sampler
	cache    keyCache

	skew    time.Duration // leeway on token times; see WithClockSkew
	skewSet bool          // whether WithClockSkew chose skew, zero included

	logoutMaxAge       time.Duration // see WithLogoutTokenMaxAge
	postLogoutRedirect string        // see WithPostLogoutRedirect; empty for none

	// assurance holds each provider's WithProviderAssurance configuration.
	// A provider with no entry uses the default; see assuranceFor.
	assurance map[string]Assurance

	// evaluator replaces the per-provider matching when set; see
	// WithAssuranceEvaluator.
	evaluator AssuranceEvaluator
}

// providerScoped is implemented by a broker whose options name providers,
// such as the ones just-in-time provisioning or role derivation apply to.
type providerScoped interface{ ConfiguredProviders() []string }

// linkBacked is implemented by a broker that resolves identities through a
// link store, which back-channel logout reuses for subject-only tokens.
type linkBacked interface{ Links() LinkStore }

// roleSyncing is implemented by a broker that can sync roles per provider.
type roleSyncing interface{ RoleSyncProviders() []string }

// NewManager returns a manager for the registry's providers that resolves
// identities through broker.
//
// Both are required: a manager with no provider or no way to resolve an
// identity cannot complete a login, so a nil registry, or a nil broker
// (identity.MissingPort), is a wiring mistake. A nil pointer inside a non-nil
// interface counts as nil. With no options it sends every
// request through outbound.New(), draws secrets from crypto/rand.Reader, reads
// time from clock.System(), logs to slog.Default(), and holds login flows for
// DefaultFlowTTL in a NewMemoryFlowStore sharing its clock and random source,
// judges provider token times within DefaultClockSkew (WithClockSkew), and
// accepts logout tokens issued up to DefaultLogoutTokenMaxAge ago
// (WithLogoutTokenMaxAge), and gives every provider the default Assurance,
// accepting amr "mfa" only (WithProviderAssurance), matched per provider
// unless WithAssuranceEvaluator replaces the matching.
//
// It sends no request. Provider metadata and key sets are fetched on first
// use, or by Prefetch, and cached for DefaultDiscoveryTTL, with a failure
// backoff of DefaultDiscoveryBackoffBase doubling to
// DefaultDiscoveryBackoffMax, an unknown-key-id refetch cooldown of
// DefaultJWKSRefetchCooldown, and no stale window; the options named after
// each replace them. Nothing runs in the background, so there is nothing to
// start or stop.
//
// Every error it returns wraps ErrConfig: an option given nil, a default
// outbound client that cannot be built, a provider URL (issuer, redirect URL,
// end-session or pinned endpoint) or post-logout redirect whose scheme the
// outbound client does not allow, a broker whose own configuration names a
// provider the registry does not hold, or an assurance configuration that
// names an unregistered provider, holds an empty value, holds a RequestACR
// value containing whitespace or names an undefined match mode. With the
// default client only https is allowed; a consumer who needs http for a
// development provider supplies a client built with
// outbound.WithAllowedSchemes("http") through WithOutboundClient.
//
// A record of a failed flow store carries a fixed reason and the error's Go
// type, never the store's own text; a consumer who wants that detail logs it
// inside their own implementation of FlowStore. Kept on purpose, and stated
// here so an operator does not have to read the code: the library's own
// protocol-failure text (token verification, provider discovery, key-set
// retrieval and the token endpoint's response), and — in the broker's
// identity-linking records — the email_domain of the identity being linked.
func NewManager(registry *Registry, broker IdentityBroker, opts ...ManagerOption) (*Manager, error) {
	if registry == nil || len(registry.names) == 0 {
		return nil, fmt.Errorf("%w: a provider registry built by NewRegistry is required", ErrConfig)
	}
	if nilcheck.IsNil(broker) {
		return nil, fmt.Errorf("%w: %w", ErrConfig, identity.MissingPort("identity broker"))
	}

	m := &Manager{registry: registry, broker: broker}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(m); err != nil {
			return nil, err
		}
	}

	if m.out == nil {
		out, err := outbound.New()
		if err != nil {
			return nil, fmt.Errorf("%w: default outbound client: %w", ErrConfig, err)
		}
		m.out = out
	}
	if m.random == nil {
		m.random = rand.Reader
	}
	if m.clock == nil {
		m.clock = clock.System()
	}
	if m.log == nil {
		m.log = slog.Default()
	}
	if m.flows == nil {
		s, err := NewMemoryFlowStore(WithMemoryFlowStoreClock(m.clock), WithMemoryFlowStoreRandom(m.random))
		if err != nil {
			return nil, fmt.Errorf("%w: default flow store: %w", ErrConfig, err)
		}
		m.flows = s
	}
	if !m.skewSet {
		m.skew = DefaultClockSkew
	}
	if m.logoutMaxAge == 0 {
		m.logoutMaxAge = DefaultLogoutTokenMaxAge
	}
	if m.flowTTL == 0 {
		m.flowTTL = DefaultFlowTTL
	}
	if m.cache.ttl == 0 {
		m.cache.ttl = DefaultDiscoveryTTL
	}
	if m.cache.backoffBase == 0 {
		m.cache.backoffBase, m.cache.backoffMax = DefaultDiscoveryBackoffBase, DefaultDiscoveryBackoffMax
	}
	if m.cache.cooldown == 0 {
		m.cache.cooldown = DefaultJWKSRefetchCooldown
	}
	m.sampler = logsample.New(refusalLogInterval, logsample.WithReporter(m.reportSuppressed))

	if err := m.checkSchemes(); err != nil {
		return nil, err
	}
	if err := m.checkBrokerProviders(); err != nil {
		return nil, err
	}
	if err := m.checkAssuranceProviders(); err != nil {
		return nil, err
	}
	return m, nil
}

// checkSchemes refuses a provider URL whose scheme the outbound client would
// refuse at request time, so the mistake surfaces at wiring rather than on the
// first login. The registry has already required every set URL to parse as
// absolute; the redirect URL and the post-logout redirect are checked too,
// although the client never fetches them, so that plain-text redirects need
// the same deliberate opt-in.
func (m *Manager) checkSchemes() error {
	for _, name := range m.registry.Names() {
		p, _ := m.registry.Lookup(name)
		urls := []struct{ field, value string }{
			{"issuer", p.Issuer},
			{"redirect URL", p.RedirectURL},
			{"authorization endpoint", p.AuthorizationEndpoint},
			{"token endpoint", p.TokenEndpoint},
			{"key-set URI", p.JWKSURI},
			{"end-session endpoint", p.EndSessionEndpoint},
		}
		for _, f := range urls {
			if f.value == "" {
				continue
			}
			u, err := url.Parse(f.value)
			if err != nil {
				return fmt.Errorf("%w: provider %q: %s is not a valid URL", ErrConfig, name, f.field)
			}
			if !m.out.AllowsScheme(u.Scheme) {
				return fmt.Errorf("%w: provider %q: %s scheme %q is not allowed by the outbound client",
					ErrConfig, name, f.field, u.Scheme)
			}
		}
	}
	if m.postLogoutRedirect != "" {
		u, _ := url.Parse(m.postLogoutRedirect) // WithPostLogoutRedirect parsed it
		if !m.out.AllowsScheme(u.Scheme) {
			return fmt.Errorf("%w: WithPostLogoutRedirect scheme %q is not allowed by the outbound client",
				ErrConfig, u.Scheme)
		}
	}
	return nil
}

// checkBrokerProviders refuses a broker whose configuration names a provider
// the registry lacks, which would otherwise never apply and never say so.
func (m *Manager) checkBrokerProviders() error {
	var named []string
	if s, ok := m.broker.(providerScoped); ok {
		named = append(named, s.ConfiguredProviders()...)
	}
	if r, ok := m.broker.(roleSyncing); ok {
		named = append(named, r.RoleSyncProviders()...)
	}
	for _, name := range named {
		if _, ok := m.registry.Lookup(name); !ok {
			return fmt.Errorf("%w: the identity broker is configured for provider %q, which is not registered",
				ErrConfig, name)
		}
	}
	return nil
}

// reportSuppressed writes the count of refusal records the sampler held back.
func (m *Manager) reportSuppressed(key string, suppressed int) {
	m.log.LogAttrs(context.Background(), slog.LevelInfo, "oidc refusals suppressed",
		slog.String("reason", key),
		slog.Int("suppressed", suppressed))
}

// FlushRefusalLogs reports every refusal record the manager's own sampler has
// suppressed but not yet counted, then forgets every key. When the identity
// broker the manager was built with can flush its own refusal logs, this
// reaches it too and returns what its flush returns; a broker that cannot
// flush is skipped, and the call still returns nil.
//
// It is safe to call at shutdown, including while logins are still in
// flight, and safe to call more than once: a second flush with nothing new
// pending reports nothing. Call it directly, or let
// httpsec.Chain.FlushRefusalLogs reach it through EnableOIDCLogin.
func (m *Manager) FlushRefusalLogs() error {
	m.sampler.Flush()

	if f, ok := m.broker.(interface{ FlushRefusalLogs() error }); ok {
		return f.FlushRefusalLogs()
	}

	return nil
}

// Providers returns the registered provider names in registration order. The
// returned slice is the caller's own.
func (m *Manager) Providers() []string { return m.registry.Names() }

// Links returns the link store the broker resolves identities through, or nil
// when the broker is not backed by one.
func (m *Manager) Links() LinkStore {
	if l, ok := m.broker.(linkBacked); ok {
		return l.Links()
	}
	return nil
}

// RoleSyncProviders returns the providers the broker syncs roles for, or nil
// when the broker does not sync roles. The returned slice is the caller's own.
func (m *Manager) RoleSyncProviders() []string {
	if r, ok := m.broker.(roleSyncing); ok {
		return slices.Clone(r.RoleSyncProviders())
	}
	return nil
}

// PurgeExpiredFlows deletes the login flows that expired before the manager's
// own now, read from its clock (WithClock), and returns how many the flow store
// removed.
//
// The cutoff is the manager's and is not configurable: nothing counts expired
// flows, so there is no window to wait out, and a flow that has not yet expired
// is never deleted. A flow store error is returned with whatever count the
// store reported. FlowExpiryTask wraps it as a task.
func (m *Manager) PurgeExpiredFlows(ctx context.Context) (int, error) {
	return m.flows.DeleteExpired(ctx, m.clock.Now())
}
