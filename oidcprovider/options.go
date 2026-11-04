package oidcprovider

import (
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/internal/oplineage"
	"github.com/kartaladev/scrty/outbound"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/token/onetime"
)

// AudienceRule selects which audience a client assertion may name.
type AudienceRule uint8

const (
	// AudienceIssuerOnly accepts the provider's issuer identifier as the sole
	// audience. It is the default.
	AudienceIssuerOnly AudienceRule = iota

	// AudienceIssuerOrTokenEndpoint also accepts the token endpoint URL, the issuer
	// followed by /oauth2/token (or the URL WithAssertionTokenEndpoint names), for
	// clients built to OIDC Core's older recommendation. It accepts the ambiguity CVE-2025-27370 describes.
	AudienceIssuerOrTokenEndpoint
)

// RequestBounds limits the size in bytes of authorization parameters, which
// anyone can park, and which are stored and reflected in redirects. A zero field
// keeps its default, and a negative one fails construction. Every other parameter the
// provider reads is held to a fixed 4 KiB, and at most 10 resource values are read.
type RequestBounds struct {
	// State bounds state. The default is 2048.
	State int
	// Nonce bounds nonce. The default is 2048.
	Nonce int
	// LoginHint bounds login_hint. The default is 2048.
	LoginHint int
	// Resource bounds each resource. The default is 2048.
	Resource int
	// Scope bounds scope. The default is 4096.
	Scope int
	// IDTokenHint bounds id_token_hint, a signed token that grows with the claims its
	// issuer adds. The default is 8192, a proposed value that has not been measured
	// against real claim sets; widen it if a genuine hint is refused.
	IDTokenHint int
}

type config struct {
	loopbackHTTPIssuer bool
	browserSessions    bool
	logoutConfirmation bool
	// dpopEnabled says the chain verifies DPoP proofs, so a request's dpop_jkt can be honoured.
	dpopEnabled       bool
	bounds            RequestBounds
	pendingLifetime   time.Duration
	codeLifetime      time.Duration
	assertionAudience AudienceRule
	// assertionTokenEndpoint is the audience URL AudienceIssuerOrTokenEndpoint accepts.
	// New fills it in from the issuer when the option is not given.
	assertionTokenEndpoint    string
	assertionTokenEndpointSet bool
	assertionMax              time.Duration
	keysRefetchCooldown       time.Duration
	keysTTL                   time.Duration
	assertionIDs              AssertionIDStore
	assertionIDsSet           bool
	pendingRequests           PendingRequestStore
	pendingRequestsSet        bool
	codes                     CodeStore
	codesSet                  bool
	consents                  ConsentStore
	consentsSet               bool
	grants                    GrantStore
	grantsSet                 bool
	codeTokens                onetime.Store
	codeTokensSet             bool
	accessTokens              AccessTokenStore
	accessTokensSet           bool
	browserStore              BrowserSessionStore
	browserStoreSet           bool
	lineage                   RefreshTokenStore
	lineageSet                bool
	outbound                  *outbound.Client
	outboundSet               bool
	clock                     clock.Clock
	logger                    *slog.Logger
	random                    io.Reader
	// ids names the records the provider creates. validate builds it, over the clock and
	// randomness the options gave.
	ids id.Generator
}

// The defaults New applies and the bounds it enforces, each named on its option.
const (
	defaultPendingLifetime     = 10 * time.Minute
	maxPendingLifetime         = 30 * time.Minute
	defaultCodeLifetime        = 60 * time.Second
	maxCodeLifetime            = 10 * time.Minute
	defaultAssertionMax        = 5 * time.Minute
	maxAssertionMax            = time.Hour
	defaultKeysRefetchCooldown = 30 * time.Second
	defaultKeysTTL             = 15 * time.Minute
	defaultParamBound          = 2048
	defaultScopeBound          = 4096
	defaultIDTokenHintBound    = 8192
)

func defaultConfig() config {
	return config{
		browserSessions:     true,
		pendingLifetime:     defaultPendingLifetime,
		codeLifetime:        defaultCodeLifetime,
		assertionAudience:   AudienceIssuerOnly,
		assertionMax:        defaultAssertionMax,
		keysRefetchCooldown: defaultKeysRefetchCooldown,
		keysTTL:             defaultKeysTTL,
		clock:               clock.System(),
		logger:              slog.Default(),
		random:              rand.Reader,
	}
}

// validate refuses a setting that cannot work, and fills in the bounds left at
// zero.
func (c *config) validate() error {
	if err := checkBound("WithPendingRequestLifetime", c.pendingLifetime, maxPendingLifetime); err != nil {
		return err
	}
	if err := checkBound("WithCodeLifetime", c.codeLifetime, maxCodeLifetime); err != nil {
		return err
	}
	if err := checkBound("WithClientAssertionMaxLifetime", c.assertionMax, maxAssertionMax); err != nil {
		return err
	}
	if c.assertionAudience > AudienceIssuerOrTokenEndpoint {
		return fmt.Errorf("%w: WithClientAssertionAudience: unknown rule %d", ErrConfig, c.assertionAudience)
	}
	if c.assertionTokenEndpointSet && c.assertionAudience != AudienceIssuerOrTokenEndpoint {
		return fmt.Errorf("%w: WithAssertionTokenEndpoint: has no meaning unless WithClientAssertionAudience(AudienceIssuerOrTokenEndpoint) is given", ErrConfig)
	}
	if c.keysRefetchCooldown <= 0 {
		return fmt.Errorf("%w: WithClientKeysRefetchCooldown: must be positive", ErrConfig)
	}
	if c.keysTTL <= 0 {
		return fmt.Errorf("%w: WithClientKeysTTL: must be positive", ErrConfig)
	}
	if c.assertionIDsSet && nilcheck.IsNil(c.assertionIDs) {
		return fmt.Errorf("%w: WithAssertionIDStore: must not be nil", ErrConfig)
	}
	if c.pendingRequestsSet && nilcheck.IsNil(c.pendingRequests) {
		return fmt.Errorf("%w: WithPendingRequestStore: must not be nil", ErrConfig)
	}
	if c.codesSet && nilcheck.IsNil(c.codes) {
		return fmt.Errorf("%w: WithCodeStore: must not be nil", ErrConfig)
	}
	if c.consentsSet && nilcheck.IsNil(c.consents) {
		return fmt.Errorf("%w: WithConsentStore: must not be nil", ErrConfig)
	}
	if c.grantsSet && nilcheck.IsNil(c.grants) {
		return fmt.Errorf("%w: WithGrantStore: must not be nil", ErrConfig)
	}
	if c.codeTokensSet && nilcheck.IsNil(c.codeTokens) {
		return fmt.Errorf("%w: WithCodeTokenStore: must not be nil", ErrConfig)
	}
	if c.accessTokensSet && nilcheck.IsNil(c.accessTokens) {
		return fmt.Errorf("%w: WithAccessTokenStore: must not be nil", ErrConfig)
	}
	if c.browserStoreSet && nilcheck.IsNil(c.browserStore) {
		return fmt.Errorf("%w: WithBrowserSessionStore: must not be nil", ErrConfig)
	}
	if c.browserStoreSet && !c.browserSessions {
		return fmt.Errorf("%w: WithBrowserSessionStore: has no meaning under WithoutBrowserSessions", ErrConfig)
	}
	if c.lineageSet && oplineage.Sessions(c.lineage) == nil {
		return fmt.Errorf("%w: WithRefreshTokenStore: must be built by a scrty store adapter, and not be the zero value", ErrConfig)
	}
	if c.outboundSet && c.outbound == nil {
		return fmt.Errorf("%w: WithOutbound: must not be nil", ErrConfig)
	}
	if nilcheck.IsNil(c.clock) {
		return fmt.Errorf("%w: WithClock: must not be nil", ErrConfig)
	}
	if c.logger == nil {
		return fmt.Errorf("%w: WithLogger: must not be nil", ErrConfig)
	}
	if nilcheck.IsNil(c.random) {
		return fmt.Errorf("%w: WithRandom: must not be nil", ErrConfig)
	}
	c.ids = id.NewV7Generator(id.WithClock(c.clock), id.WithRandom(c.random))

	return c.bounds.resolve()
}

func checkBound(option string, d, limit time.Duration) error {
	if d <= 0 || d > limit {
		return fmt.Errorf("%w: %s: must be positive and at most %s, got %s", ErrConfig, option, limit, d)
	}

	return nil
}

// resolve fills in the fields left at zero, and refuses a negative one.
func (b *RequestBounds) resolve() error {
	fields := []struct {
		value *int
		def   int
	}{
		{&b.State, defaultParamBound},
		{&b.Nonce, defaultParamBound},
		{&b.LoginHint, defaultParamBound},
		{&b.Resource, defaultParamBound},
		{&b.Scope, defaultScopeBound},
		{&b.IDTokenHint, defaultIDTokenHintBound},
	}
	for _, f := range fields {
		switch {
		case *f.value < 0:
			return fmt.Errorf("%w: WithRequestBounds: a bound must not be negative", ErrConfig)
		case *f.value == 0:
			*f.value = f.def
		}
	}

	return nil
}

// Option customises New. A nil option is skipped, so a consumer may build the
// slice conditionally.
type Option func(*config)

// WithLoopbackHTTPIssuer permits an http issuer on a loopback host, for local
// development. The default requires https, and no non-loopback host is ever
// accepted over http. It is not for production: a plain http issuer sends tokens
// and credentials in the clear, and the OpenID conformance Config plan refuses
// one, so a provider using this option cannot be certified.
func WithLoopbackHTTPIssuer() Option {
	return func(c *config) { c.loopbackHTTPIssuer = true }
}

// WithoutBrowserSessions turns off the provider's browser session, which is on
// by default. Every request then shows the login page, prompt=none always
// answers login_required, and every logout asks. This fails the Basic OP plan.
func WithoutBrowserSessions() Option {
	return func(c *config) { c.browserSessions = false }
}

// WithLogoutConfirmation asks the user at every logout. The default skips the
// question when a valid hint names the browser's own sign-in.
func WithLogoutConfirmation() Option {
	return func(c *config) { c.logoutConfirmation = true }
}

// WithDPoP states that the chain verifies DPoP proofs (httpsec.EnableDPoP), so an
// authorization request may name a dpop_jkt. The default is off, and such a request is
// answered invalid_request, because ignoring the parameter would leave a client holding an
// unbound code it believes is bound.
func WithDPoP() Option {
	return func(c *config) { c.dpopEnabled = true }
}

// WithRequestBounds replaces the default parameter bounds. See RequestBounds.
func WithRequestBounds(b RequestBounds) Option {
	return func(c *config) { c.bounds = b }
}

// WithPendingRequestLifetime replaces how long a parked authorization request
// lives. The default is 10 minutes, and the value must be positive and at most
// 30 minutes.
func WithPendingRequestLifetime(d time.Duration) Option {
	return func(c *config) { c.pendingLifetime = d }
}

// WithCodeLifetime replaces how long an authorization code lives. The default is
// 60 seconds, and the value must be positive and at most 10 minutes.
func WithCodeLifetime(d time.Duration) Option {
	return func(c *config) { c.codeLifetime = d }
}

// WithClientAssertionAudience replaces the assertion audience rule. The default
// is AudienceIssuerOnly. An unknown rule fails construction. Under every rule an
// assertion names one audience.
func WithClientAssertionAudience(r AudienceRule) Option {
	return func(c *config) { c.assertionAudience = r }
}

// WithClientAssertionMaxLifetime replaces how far ahead an assertion's exp may
// lie. The default is 5 minutes, and the value must be positive and at most 1
// hour.
func WithClientAssertionMaxLifetime(d time.Duration) Option {
	return func(c *config) { c.assertionMax = d }
}

// WithClientKeysRefetchCooldown replaces how often an unknown kid may refetch a
// client's jwks_uri, and how long a failed fetch is answered before it is tried again.
// The default is 30 seconds, and the value must be positive.
func WithClientKeysRefetchCooldown(d time.Duration) Option {
	return func(c *config) { c.keysRefetchCooldown = d }
}

// WithOutbound replaces the client that fetches clients' key sets, and so what confines
// those fetches. The default is outbound.New with no options: https only, redirects
// staying on the origin, and the time and size bounds it names. It must not be nil.
func WithOutbound(o *outbound.Client) Option {
	return func(c *config) { c.outbound, c.outboundSet = o, true }
}

// WithClock replaces the time source. The default is clock.System(), and it must
// not be nil.
func WithClock(clk clock.Clock) Option {
	return func(c *config) { c.clock = clk }
}

// WithLogger replaces the logger. The default is slog.Default(), and it must not
// be nil.
func WithLogger(l *slog.Logger) Option {
	return func(c *config) { c.logger = l }
}

// WithRandom replaces the source of random bytes. The default is crypto/rand's
// Reader, and it must not be nil.
func WithRandom(r io.Reader) Option {
	return func(c *config) { c.random = r }
}

// WithAssertionIDStore replaces where accepted client assertion identifiers are
// recorded. The default is a MemoryAssertionIDStore of the provider's own, which forgets
// what has expired by the provider's clock on a write, at most once per minute. It is
// lost with the process and not shared between instances, so a deployment of more than
// one instance needs a shared store to refuse a replay across them. A store given here is
// the consumer's to sweep, through DeleteExpired. It must not be nil.
func WithAssertionIDStore(s AssertionIDStore) Option {
	return func(c *config) { c.assertionIDs, c.assertionIDsSet = s, true }
}

// WithClientKeysTTL replaces how long a key set fetched from a client's jwks_uri is
// used before it is fetched again, which bounds how long a key the client has
// withdrawn keeps authenticating it. The default is 15 minutes, and the value must be
// positive.
func WithClientKeysTTL(d time.Duration) Option {
	return func(c *config) { c.keysTTL = d }
}

// WithAssertionTokenEndpoint replaces the token endpoint URL that
// AudienceIssuerOrTokenEndpoint accepts as an assertion's audience. The default is the
// issuer followed by /oauth2/token, which holds only while the chain serves the token
// endpoint there; a chain that moves it must say so here, or its clients' assertions
// are refused. The chain checks the two agree: httpsec.EnableOIDCProvider compares
// AssertionTokenEndpoint with the path it serves.
//
// The value must be an absolute URL on the issuer's origin with no query, fragment or
// user information, and it is meaningful only under AudienceIssuerOrTokenEndpoint.
// Given under the default issuer-only rule, it fails construction rather than being
// ignored.
func WithAssertionTokenEndpoint(url string) Option {
	return func(c *config) { c.assertionTokenEndpoint, c.assertionTokenEndpointSet = url, true }
}

// WithPendingRequestStore replaces where parked requests are kept. The default is a
// MemoryPendingRequestStore, which is lost with the process and not shared between
// instances. It must not be nil.
func WithPendingRequestStore(s PendingRequestStore) Option {
	return func(c *config) { c.pendingRequests, c.pendingRequestsSet = s, true }
}

// WithCodeStore replaces where code records are kept. The default is a MemoryCodeStore,
// which is lost with the process and not shared between instances, and which keeps a code
// until a minute past its expiry. It must not be nil.
// New gives it to the grant store through GrantStore.UseCodes.
//
// A valid replay's detection and an end's reach to an exchange in flight need a code kept
// until a minute past its expiry. A store, or a consumer sweeping it through DeleteExpired
// sooner, gives that up. To retain longer, WithCodeTokenStore's store must retain as long too.
func WithCodeStore(s CodeStore) Option {
	return func(c *config) { c.codes, c.codesSet = s, true }
}

// WithConsentStore replaces where consents are kept. The default is a
// MemoryConsentStore, which is lost with the process and not shared between instances.
// It must not be nil.
func WithConsentStore(s ConsentStore) Option {
	return func(c *config) { c.consents, c.consentsSet = s, true }
}

// WithGrantStore replaces where grants are kept. The default is a MemoryGrantStore,
// which is lost with the process and not shared between instances. It must not be nil.
// New calls its UseCodes with the provider's code store, and returns its refusal: a grant
// store reads one code store for good, so providers sharing a grant store must share a
// code store too, through WithCodeStore, or New fails with an error matching ErrConfig.
func WithGrantStore(s GrantStore) Option {
	return func(c *config) { c.grants, c.grantsSet = s, true }
}

// WithCodeTokenStore replaces where authorization codes' one-time tokens are kept, which
// is what decides a code's single spend. The default is an onetime.MemoryStore of the
// provider's own, which is lost with the process and not shared between instances, and
// which keeps a code until a minute past its expiry, forgetting it after that on a write,
// at most once per minute. A store given here is the consumer's to purge. It must not be nil.
//
// A valid replay's detection and an end's reach to an exchange in flight need a code kept
// until a minute past its expiry. A consumer purging sooner gives that up. The code store
// given through WithCodeStore must retain the same window, so for a longer one both stores
// must retain together.
func WithCodeTokenStore(s onetime.Store) Option {
	return func(c *config) { c.codeTokens, c.codeTokensSet = s, true }
}

// WithAccessTokenStore replaces where opaque access tokens are kept. The default is a
// MemoryAccessTokenStore, which is lost with the process and not shared between
// instances. It must not be nil.
func WithAccessTokenStore(s AccessTokenStore) Option {
	return func(c *config) { c.accessTokens, c.accessTokensSet = s, true }
}

// WithBrowserSessionStore replaces where browser sessions are kept. The default is a
// MemoryBrowserSessionStore, which is lost with the process and not shared between
// instances. It must not be nil, and given with WithoutBrowserSessions, which uses no
// such store, it fails construction rather than being ignored.
func WithBrowserSessionStore(s BrowserSessionStore) Option {
	return func(c *config) { c.browserStore, c.browserStoreSet = s, true }
}

// WithRefreshTokenStore replaces where refresh-token lineages are kept. The default is
// a private session.MemoryStore of the provider's own, which is lost with the process
// and not shared between instances. A SQL adapter's NewRefreshTokenStore builds a
// durable one, and nothing outside scrty can build one from a session.Store. The zero
// RefreshTokenStore holds nothing, and fails construction.
func WithRefreshTokenStore(s RefreshTokenStore) Option {
	return func(c *config) { c.lineage, c.lineageSet = s, true }
}
