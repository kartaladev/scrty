package oidcprovider

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"time"

	"github.com/kartaladev/scrty/internal/eventsink"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/internal/oplineage"
	"github.com/kartaladev/scrty/outbound"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
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
	// successorKey is what a refresh token's successor is derived under, behind a pointer so that
	// a provider printed prints no key. It is nil only with a window of zero, which reads no key.
	successorKey    *successorKey
	successorKeySet bool
	// successorWindow is how long after its rotation a token presented again is answered the same
	// successor, and zero means never.
	successorWindow time.Duration
	outbound        *outbound.Client
	outboundSet     bool
	claimSource     ClaimSource
	claimSourceSet  bool
	// logoutNotices watches the clients of each ended sign-in leave for delivery, and nothing but a test
	// sets it.
	logoutNotices     func(context.Context, []ClientToNotify)
	logoutDelivery    LogoutDelivery
	logoutDeliverySet bool
	logoutOutbound    []outbound.Option
	logoutOutboundSet bool
	logoutWorkers     int
	logoutQueue       int
	logoutTimeout     time.Duration
	// logoutFailed is told each failed delivery, before its security event is reported, and nothing but a
	// test sets it.
	logoutFailed func(context.Context, logoutFailure)
	// events is the provider's own security-event sink, which a chain's delivery replaces on a request
	// the chain reports for.
	events eventsink.Own
	clock  clock.Clock
	logger *slog.Logger
	random io.Reader
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
		successorWindow:     defaultSuccessorWindow,
		logoutWorkers:       defaultLogoutWorkers,
		logoutQueue:         defaultLogoutQueue,
		logoutTimeout:       defaultLogoutTimeout,
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
	if c.successorKeySet && len(c.successorKey.key) < minSuccessorKeyBytes {
		return fmt.Errorf("%w: WithRefreshSuccessorKey: must be at least %d bytes", ErrConfig, minSuccessorKeyBytes)
	}
	if c.successorWindow < 0 || c.successorWindow > session.MaxRenewalGrace {
		return fmt.Errorf("%w: WithRefreshSuccessorWindow: must be between 0 and %s", ErrConfig, session.MaxRenewalGrace)
	}
	if c.successorKeySet && c.successorWindow == 0 {
		return fmt.Errorf("%w: WithRefreshSuccessorKey: has no meaning under WithRefreshSuccessorWindow(0), which derives nothing", ErrConfig)
	}
	if c.outboundSet && c.outbound == nil {
		return fmt.Errorf("%w: WithOutbound: must not be nil", ErrConfig)
	}
	if err := c.validateLogoutDelivery(); err != nil {
		return err
	}
	if c.claimSourceSet && nilcheck.IsNil(c.claimSource) {
		return fmt.Errorf("%w: WithClaimSource: must not be nil", ErrConfig)
	}
	if err := c.events.Err("WithSecurityEvents"); err != nil {
		return fmt.Errorf("%w: %w", ErrConfig, err)
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
	if err := c.drawSuccessorKey(); err != nil {
		return err
	}

	return c.bounds.resolve()
}

func (c *config) validateLogoutDelivery() error {
	if c.logoutDeliverySet && nilcheck.IsNil(c.logoutDelivery) {
		return fmt.Errorf("%w: WithLogoutDelivery: must not be nil", ErrConfig)
	}
	if c.logoutDeliverySet && c.logoutOutboundSet {
		return fmt.Errorf("%w: WithLogoutOutbound: has no meaning beside WithLogoutDelivery, which posts nothing through it", ErrConfig)
	}
	if c.logoutWorkers <= 0 || c.logoutQueue <= 0 {
		return fmt.Errorf("%w: WithLogoutDeliveryPool: workers and queue must be positive, got %d and %d", ErrConfig, c.logoutWorkers, c.logoutQueue)
	}
	if c.logoutTimeout <= 0 {
		return fmt.Errorf("%w: WithLogoutDeliveryTimeout: must be positive, got %s", ErrConfig, c.logoutTimeout)
	}

	return nil
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
//
// It also posts logout tokens, so that they stay inside what it confines, unless WithLogoutOutbound
// gives delivery a client of its own. The limit: a client built elsewhere cannot be told to follow no
// redirect, so one that may redirect follows a relying party's redirect on its own origin, and the
// delivery counts as the final answer does. Build it with outbound.WithMaxRedirects(0), or use
// WithLogoutOutbound, to keep what delivery otherwise guarantees.
func WithOutbound(o *outbound.Client) Option {
	return func(c *config) { c.outbound, c.outboundSet = o, true }
}

// WithClaimSource replaces where UserInfo reads a user's claims. The default reads the user just
// loaded from Deps.Users, releasing name and preferred_username for the scope profile, and for the
// scope email a username that is exactly an email address (mail.ParseAddress accepts it and returns
// it unchanged, so a display form such as "Ada <ada@example.com>" does not count) as email, with
// email_verified always false, because a username proves nothing about who controls that address.
// The address is never used to look up a user. A consumer with a verified email, phone, address or
// claims of its own supplies them here, and its values, email_verified true included, are answered
// unchanged. See ClaimSource. It must not be nil.
func WithClaimSource(s ClaimSource) Option {
	return func(c *config) { c.claimSource, c.claimSourceSet = s, true }
}

// WithLogoutDelivery replaces how a logout token reaches a client, such as with a queue that retries.
// The default posts it to the client's BackChannelLogoutURI as a form, once, through a client that
// follows no redirect, and counts 200 and 204 as success. A consumer's delivery still runs on the
// provider's pool and within its bound. It must not be nil, and given with WithLogoutOutbound, which it
// would not use, it fails construction.
func WithLogoutDelivery(d LogoutDelivery) Option {
	return func(c *config) { c.logoutDelivery, c.logoutDeliverySet = d, true }
}

// WithLogoutOutbound confines the default delivery, with the options of the outbound client it builds
// for itself: a transport (outbound.WithHTTPClient), the origins it may reach, a response bound. The
// default is outbound.New with a transport keeping no connection, and with WithOutbound given, that
// client instead. A follow-no-redirect cap is applied last, so outbound.WithMaxRedirects given here
// cannot bring redirects back. Options the outbound client refuses fail construction.
func WithLogoutOutbound(opts ...outbound.Option) Option {
	return func(c *config) { c.logoutOutbound, c.logoutOutboundSet = opts, true }
}

// WithLogoutDeliveryPool replaces how many deliveries run at once and how many may wait. The defaults
// are 8 and 1024, and both must be positive. A delivery finding the queue full is dropped, logged and
// reported as failed, and its logout is unaffected. A client that registered no URI takes a place too,
// because what a client registered is read only when it is told.
func WithLogoutDeliveryPool(workers, queue int) Option {
	return func(c *config) { c.logoutWorkers, c.logoutQueue = workers, queue }
}

// WithLogoutDeliveryTimeout replaces the bound on one delivery, reading the client and signing the token
// included. The default is 5 seconds, and it must be positive. At the bound the delivery is reported as
// failed, and its worker takes the next. A consumer's call ignoring its context keeps a goroutine until
// it returns, of at most as many as there are workers: with that many left behind, a delivery fails at
// once, reported as busy, rather than start another.
func WithLogoutDeliveryTimeout(d time.Duration) Option {
	return func(c *config) { c.logoutTimeout = d }
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

// WithRefreshSuccessorKey sets the key a rotated refresh token's successor is derived under, as
// HMAC-SHA256(key, family, presented secret), so that a token presented again inside the
// same-successor window (WithRefreshSuccessorWindow) is answered the one successor it already has,
// with no write. Two tabs presenting one token at once therefore both hold a live token. It must be
// at least 32 bytes, or New fails with an error matching ErrConfig, and it is copied. It is a secret:
// under it, a successor can only be had by presenting the token to the provider, and its holder can
// compute the live head from any past token, offline, with nothing fired.
//
// The default is 32 random bytes drawn once in New from the provider's random source (WithRandom),
// which needs no configuration and fits a provider alone over its stores. A source that cannot supply
// them fails New with an error matching ErrConfig. Replicas sharing their stores share this key too,
// or the limit below is theirs. With a window of zero, no successor is derived and no default drawn,
// so a key given together with WithRefreshSuccessorWindow(0) is a contradiction: New fails with an
// error matching ErrConfig, whichever option comes first.
//
// The limit: with no shared key, or after the key changes, a provider derives a different successor,
// finds no match, and rotates the token again: the client receives tokens with the grant live, under a
// successor drawn at random, and the successor issued before is knocked out, so a holder presenting it
// next reads as reuse. Nothing is refused, because a provider cannot know how many replicas it has.
func WithRefreshSuccessorKey(key []byte) Option {
	return func(c *config) {
		c.successorKey, c.successorKeySet = &successorKey{key: slices.Clone(key)}, true
	}
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

// WithRefreshSuccessorWindow sets how long after its rotation a refresh token presented again is
// answered the same successor, or the head that successor has rotated to, with no write. Measured on
// the provider's clock, it is what lets two tabs racing one token both hold a live one.
//
// The default is 10 seconds, a proposed value: the race it answers had faded by 100 ms in the
// measurements, and a tab with shared storage holds the new token after that. It is short on purpose.
// The same successor removes the divergence reuse detection relies on, so a wider window lets a thief
// staying inside it go undetected, for as long as it stays. One missing it diverges, and is caught.
//
// After the window, inside the client's grace, a token presented again is rotated again under a
// random successor, with the grant live, and the one issued before is knocked out. A client's grace
// (Client.RefreshGrace) still bounds the window: past it the token is reuse, whatever this says.
//
// Zero turns the same successor off, so that every rotation may use a random successor, and two tabs
// racing one token must then keep the one answered last. It derives nothing, so a key given with it
// (WithRefreshSuccessorKey) makes New fail with an error matching ErrConfig, whichever option comes
// first. A negative value, or one over session.MaxRenewalGrace, makes New fail with an error
// matching ErrConfig.
//
// A replica whose clock lags the one that rotated by the window or more does not stretch it: a
// rotation stamped that far from the provider's clock, either way, ends the window.
//
// The limit: a token's own idle deadline still rules. A superseded token presented inside the window
// or its grace that also falls past the idle deadline stored with it is refused, with nothing
// revoked, so a retry or a second tab loses out there. It needs a client dormant for about the idle
// timeout, 30 days by default, and this option does not reach it.
func WithRefreshSuccessorWindow(d time.Duration) Option {
	return func(c *config) { c.successorWindow = d }
}
