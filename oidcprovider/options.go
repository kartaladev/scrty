package oidcprovider

import (
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/kartaladev/scrty/internal/nilcheck"

	"github.com/kartaladev/scrty/outbound"
	"github.com/kartaladev/scrty/pkg/clock"
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
// keeps its default, and a negative one fails construction.
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
}

type config struct {
	loopbackHTTPIssuer bool
	browserSessions    bool
	logoutConfirmation bool
	bounds             RequestBounds
	pendingLifetime    time.Duration
	codeLifetime       time.Duration
	assertionAudience  AudienceRule
	// assertionTokenEndpoint is the audience URL AudienceIssuerOrTokenEndpoint accepts.
	// New fills it in from the issuer when the option is not given.
	assertionTokenEndpoint    string
	assertionTokenEndpointSet bool
	assertionMax              time.Duration
	keysRefetchCooldown       time.Duration
	keysTTL                   time.Duration
	assertionIDs              AssertionIDStore
	assertionIDsSet           bool
	outbound                  *outbound.Client
	outboundSet               bool
	clock                     clock.Clock
	logger                    *slog.Logger
	random                    io.Reader
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
// recorded. The default keeps them in memory, which is lost with the process and not
// shared between instances, so a deployment of more than one instance needs a shared
// store to refuse a replay across them. It must not be nil.
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
