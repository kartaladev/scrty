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

// RelyingParty drives OpenID Connect logins against the providers of a Registry:
// discovery, authorization, the callback and token verification. It resolves
// verified identities through an IdentityBroker and creates no session itself.
//
// Build one with NewRelyingParty. A RelyingParty is safe for concurrent use.
type RelyingParty struct {
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

// NewRelyingParty returns a manager for the registry's providers that resolves
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
func NewRelyingParty(registry *Registry, broker IdentityBroker, opts ...Option) (*RelyingParty, error) {
	if registry == nil || len(registry.names) == 0 {
		return nil, fmt.Errorf("%w: a provider registry built by NewRegistry is required", ErrConfig)
	}
	if nilcheck.IsNil(broker) {
		return nil, fmt.Errorf("%w: %w", ErrConfig, identity.MissingPort("identity broker"))
	}

	m := &RelyingParty{registry: registry, broker: broker}
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
func (m *RelyingParty) checkSchemes() error {
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
func (m *RelyingParty) checkBrokerProviders() error {
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
func (m *RelyingParty) reportSuppressed(key string, suppressed int) {
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
func (m *RelyingParty) FlushRefusalLogs() error {
	m.sampler.Flush()

	if f, ok := m.broker.(interface{ FlushRefusalLogs() error }); ok {
		return f.FlushRefusalLogs()
	}

	return nil
}

// Providers returns the registered provider names in registration order. The
// returned slice is the caller's own.
func (m *RelyingParty) Providers() []string { return m.registry.Names() }

// Links returns the link store the broker resolves identities through, or nil
// when the broker is not backed by one.
func (m *RelyingParty) Links() LinkStore {
	if l, ok := m.broker.(linkBacked); ok {
		return l.Links()
	}
	return nil
}

// RoleSyncProviders returns the providers the broker syncs roles for, or nil
// when the broker does not sync roles. The returned slice is the caller's own.
func (m *RelyingParty) RoleSyncProviders() []string {
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
func (m *RelyingParty) PurgeExpiredFlows(ctx context.Context) (int, error) {
	return m.flows.DeleteExpired(ctx, m.clock.Now())
}

// Option customises a RelyingParty at construction.
//
// Every option replaces a default that already works. An option given nil
// fails construction with ErrConfig rather than silently keeping the default:
// a consumer who passed one meant to replace it. A nil option is ignored.
type Option func(*RelyingParty) error

// WithOutboundClient replaces the client every request to a provider is sent
// through: discovery, key sets and the code exchange.
//
// The default is outbound.New() with its own defaults: https only, bounded
// time, size and redirects. A consumer supplies one to trust a test
// certificate authority, to allow http for a development provider, or to
// change those bounds. Confinement is then whatever the supplied client
// configures; no option here can weaken it past what package outbound allows.
func WithOutboundClient(c *outbound.Client) Option {
	return func(m *RelyingParty) error {
		if c == nil {
			return fmt.Errorf("%w: WithOutboundClient was given nil", ErrConfig)
		}
		m.out = c
		return nil
	}
}

// WithRandom replaces the source that state, nonce, PKCE verifier and flow
// handles are drawn from. The default is crypto/rand.Reader. A nil reader,
// including a nil pointer inside a non-nil interface, is refused. The reader
// must be safe for concurrent use, as crypto/rand.Reader is.
//
// It exists so a test can fix or fail the source; production code has no
// reason to replace it.
func WithRandom(r io.Reader) Option {
	return func(m *RelyingParty) error {
		if nilcheck.IsNil(r) {
			return fmt.Errorf("%w: WithRandom was given nil", ErrConfig)
		}
		m.random = r
		return nil
	}
}

// WithClock replaces the clock every expiry, TTL, cooldown and backoff
// decision reads. The default is clock.System(). The default in-memory flow
// store reads the same clock. A nil clock, typed nil included, is a
// configuration error.
func WithClock(clk clock.Clock) Option {
	return func(m *RelyingParty) error {
		if nilcheck.IsNil(clk) {
			return fmt.Errorf("%w: WithClock was given nil", ErrConfig)
		}
		m.clock = clk
		return nil
	}
}

// WithFlowStore sets where login flows are held between Authorize and
// Callback. A deployment of several instances supplies a shared store, since
// a flow begun on one instance may complete on another.
//
// The default is NewMemoryFlowStore with the manager's clock and random
// source: it holds at most DefaultMaxFlows unexpired flows for one process
// only, so behind several instances without sticky routing a callback that
// lands on another instance fails. A consumer who needs another maximum
// builds their own store, for example:
//
//	s, err := oidc.NewMemoryFlowStore(oidc.WithMemoryFlowStoreMaxFlows(n))
//
// and passes it here. A store the consumer builds this way does not share
// the manager's WithClock or WithRandom: it draws its own defaults (clock.System()
// and crypto/rand.Reader) unless the consumer also passes
// WithMemoryFlowStoreClock and WithMemoryFlowStoreRandom to it, matching
// whatever WithClock or WithRandom the manager itself was given. A nil store,
// including a nil pointer inside a non-nil interface, is refused.
func WithFlowStore(s FlowStore) Option {
	return func(m *RelyingParty) error {
		if nilcheck.IsNil(s) {
			return fmt.Errorf("%w: WithFlowStore was given nil", ErrConfig)
		}
		m.flows = s
		return nil
	}
}

// WithFlowTTL sets how long a login flow stays completable after Authorize,
// and so the longest a user may take at the provider. The default is
// DefaultFlowTTL (10 minutes). A TTL of zero or less is refused: no login
// could complete.
func WithFlowTTL(d time.Duration) Option {
	return func(m *RelyingParty) error {
		if d <= 0 {
			return fmt.Errorf("%w: WithFlowTTL must be positive, got %s", ErrConfig, d)
		}
		m.flowTTL = d
		return nil
	}
}

// WithLogger replaces the logger refusals and provider failures are reported
// to. The default is slog.Default().
//
// No record this package writes carries a token, a client secret, a PKCE
// verifier, a state, a nonce, a handoff code or a claim value.
func WithLogger(l *slog.Logger) Option {
	return func(m *RelyingParty) error {
		if l == nil {
			return fmt.Errorf("%w: WithLogger was given nil", ErrConfig)
		}
		m.log = l
		return nil
	}
}

// WithDiscoveryTTL sets how long a provider's discovery document and key set
// are served from the cache, with no request, before the next use refetches
// them. The default is DefaultDiscoveryTTL (15 minutes). A TTL of zero or
// less is refused: it would send a request on every login.
func WithDiscoveryTTL(d time.Duration) Option {
	return func(m *RelyingParty) error {
		if d <= 0 {
			return fmt.Errorf("%w: WithDiscoveryTTL must be positive, got %s", ErrConfig, d)
		}
		m.cache.ttl = d
		return nil
	}
}

// WithDiscoveryFailureBackoff sets the window during which a provider's
// discovery document or key set is not refetched after a failed fetch: later
// callers receive the recorded failure with no request. The window starts at
// base, doubles with each consecutive failure up to maxWindow, and resets on
// a success. The defaults are DefaultDiscoveryBackoffBase (1 second) and
// DefaultDiscoveryBackoffMax (30 seconds). A base of zero or less, or a
// maxWindow below the base, is refused.
func WithDiscoveryFailureBackoff(base, maxWindow time.Duration) Option {
	return func(m *RelyingParty) error {
		if base <= 0 || maxWindow < base {
			return fmt.Errorf("%w: WithDiscoveryFailureBackoff needs 0 < base <= max, got %s and %s",
				ErrConfig, base, maxWindow)
		}
		m.cache.backoffBase, m.cache.backoffMax = base, maxWindow
		return nil
	}
}

// WithJWKSRefetchCooldown sets how long after a refetch for an unknown key id
// further unknown key ids for the same provider are refused from the cache,
// with no request. The default is DefaultJWKSRefetchCooldown (30 seconds). The
// cooldown is tracked per provider. A cooldown of zero or less is refused: it
// would let every forged key id reach the provider.
func WithJWKSRefetchCooldown(d time.Duration) Option {
	return func(m *RelyingParty) error {
		if d <= 0 {
			return fmt.Errorf("%w: WithJWKSRefetchCooldown must be positive, got %s", ErrConfig, d)
		}
		m.cache.cooldown = d
		return nil
	}
}

// WithDiscoveryStaleWhileError lets a provider's discovery document or key
// set be served for up to window past its TTL when its refetch fails, with a
// warning logged for every such use naming the provider and the entry's age.
//
// The default is zero: an expired entry whose refetch fails is refused, so a
// provider outage fails logins rather than trusting keys the provider may have
// revoked. Even with a window, a stale key set is never served to a token
// whose key id it lacks, and a fresh set is never served in place of a failed
// refetch for an unknown key id. A negative window is refused.
func WithDiscoveryStaleWhileError(window time.Duration) Option {
	return func(m *RelyingParty) error {
		if window < 0 {
			return fmt.Errorf("%w: WithDiscoveryStaleWhileError must not be negative, got %s", ErrConfig, window)
		}
		m.cache.stale = window
		return nil
	}
}

// DefaultClockSkew is the leeway allowed on a provider token's exp, iat and
// nbf when WithClockSkew is not given.
const DefaultClockSkew = 60 * time.Second

// MaxClockSkew is the longest leeway WithClockSkew accepts. A longer one
// accepts a token that expired that long ago, so it is refused at construction
// rather than honoured.
const MaxClockSkew = 5 * time.Minute

// LongestLogoutTokenMaxAge is the longest age WithLogoutTokenMaxAge accepts. The
// maximum age is the replay window of a captured logout token, so a longer one
// is refused at construction rather than honoured.
const LongestLogoutTokenMaxAge = time.Hour

// WithClockSkew sets the leeway allowed between the manager's clock and a
// provider's when judging a token's expiry (exp), issued-at (iat) and
// not-before (nbf) times. The default is DefaultClockSkew (60 seconds). Zero
// tolerates no difference at all; a negative leeway is refused, since it would
// refuse tokens that are valid now, and so is one above MaxClockSkew (5
// minutes), since it would accept tokens expired by that much. There is no way
// to exceed the bound: it is the line past which the manager's expiry guarantee
// stops holding.
func WithClockSkew(d time.Duration) Option {
	return func(m *RelyingParty) error {
		if d < 0 {
			return fmt.Errorf("%w: WithClockSkew must not be negative, got %s", ErrConfig, d)
		}
		if d > MaxClockSkew {
			return fmt.Errorf("%w: WithClockSkew must not exceed %s, got %s", ErrConfig, MaxClockSkew, d)
		}
		m.skew, m.skewSet = d, true
		return nil
	}
}

// WithLogoutTokenMaxAge sets how old a back-channel logout token's issued-at
// time may be, beyond the clock leeway (WithClockSkew), before the token is
// refused. The default is DefaultLogoutTokenMaxAge (2 minutes).
//
// The maximum age is also the replay window: no jti is recorded, so a captured
// token is accepted again until its issued-at is older than the maximum age
// plus the leeway, and widening one widens the other. A maximum age of zero or
// less is refused: no token could be accepted. One above LongestLogoutTokenMaxAge
// (one hour) is refused too, because it would keep a captured token replayable
// for that long; the bound cannot be exceeded.
func WithLogoutTokenMaxAge(d time.Duration) Option {
	return func(m *RelyingParty) error {
		if d <= 0 {
			return fmt.Errorf("%w: WithLogoutTokenMaxAge must be positive, got %s", ErrConfig, d)
		}
		if d > LongestLogoutTokenMaxAge {
			return fmt.Errorf("%w: WithLogoutTokenMaxAge must not exceed %s, got %s", ErrConfig, LongestLogoutTokenMaxAge, d)
		}
		m.logoutMaxAge = d
		return nil
	}
}

// WithPostLogoutRedirect sets the URL a provider is asked to send the browser
// back to after RP-initiated logout, as post_logout_redirect_uri in
// EndSessionURL. The default is none: the parameter is omitted and the
// provider shows its own page.
//
// It must be an absolute URL with a host and no user information, whose scheme
// the outbound client allows, as every provider URL must: with the default
// client that means https, and a consumer who needs http for development
// supplies a client built with outbound.WithAllowedSchemes("http") through
// WithOutboundClient. Anything else, the empty string included, fails
// construction with ErrConfig. The URL is sent exactly as given, since
// providers compare it byte for byte with the one registered.
func WithPostLogoutRedirect(u string) Option {
	return func(m *RelyingParty) error {
		parsed, err := url.Parse(u)
		if err != nil || !parsed.IsAbs() || parsed.Host == "" || parsed.User != nil {
			return fmt.Errorf("%w: WithPostLogoutRedirect needs an absolute URL with a host and no user information",
				ErrConfig)
		}
		m.postLogoutRedirect = u
		return nil
	}
}

// WithProviderAssurance replaces the whole assurance configuration of the
// named provider: which amr and acr values its verified ID token must assert
// for the login to meet assurance, which acr values to request, and how the
// criteria combine.
//
// It replaces the default Assurance{AcceptedAMR: []string{"mfa"}}: amr "mfa"
// accepted, no acr accepted, none requested, AssuranceMatchAny. Nothing of the default
// survives a replacement, so a configuration with empty accepted sets never
// meets assurance, which is valid and means "always use the local second
// factor". The configuration is copied; changing the caller's slices later
// changes nothing. When the option is given more than once for one provider,
// the last one wins.
//
// Construction fails with ErrConfig when the provider is not registered, when
// any set contains the empty string, when a RequestACR value contains
// whitespace (acr_values is space-separated, so it would be sent as two
// values), or when Match is not AssuranceMatchAny or AssuranceMatchAll.
func WithProviderAssurance(provider string, a Assurance) Option {
	return func(m *RelyingParty) error {
		if err := a.validate(provider); err != nil {
			return err
		}
		if m.assurance == nil {
			m.assurance = make(map[string]Assurance)
		}
		m.assurance[provider] = a.clone()
		return nil
	}
}

// WithAssuranceEvaluator replaces how the manager, as the MFA policies'
// policy.FederatedAssuranceSource, decides whether a federated login's
// asserted values meet assurance. It is the port for rules the per-provider
// configuration cannot state, such as "administrators need hwk".
//
// It replaces the default, which matches the asserted amr and acr against the
// provider's Assurance (WithProviderAssurance, or the default accepting amr
// "mfa" only). The evaluator replaces only that matching step: the library
// still reads the values from the verified ID token alone, and still decides,
// without asking the evaluator, that evidence asserting nothing, naming an
// unregistered provider, or naming an issuer other than the provider's
// registered one is not met. An evaluator cannot widen where assurance comes
// from.
//
// The evaluator is called on every policy evaluation of a federated login,
// at redemption and on each request of a federated session, so it must be
// fast and free of side effects. Its error is returned unchanged, and the MFA
// policies deny with it as the reason.
//
// A nil evaluator, including a nil pointer inside a non-nil interface, fails
// construction with ErrConfig.
func WithAssuranceEvaluator(e AssuranceEvaluator) Option {
	return func(m *RelyingParty) error {
		if nilcheck.IsNil(e) {
			return fmt.Errorf("%w: WithAssuranceEvaluator was given nil", ErrConfig)
		}
		m.evaluator = e
		return nil
	}
}
