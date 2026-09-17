package token

import (
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwt"

	"github.com/kartaladev/scrty/signingkey"
)

// ErrConfig is wrapped by every error NewGenerator and NewVerifier return for a
// wiring mistake, so a consumer can tell a contradictory configuration from a
// failure at issue or verification time without matching on message text.
var ErrConfig = errors.New("token: invalid configuration")

// Clock is the time source a generator stamps iat and exp from and a verifier
// runs every time check against.
//
// With no clock configured both use the system clock. A consumer replaces it
// through WithClock or VerifyWithClock, which is how a test moves time without
// waiting.
//
// It is declared here rather than shared with signingkey's clock on purpose:
// Go interfaces are structural, so one implementation satisfies both with no
// adapter, and signingkey's comes with a ticker companion for pacing its
// background loops. This package runs no loop, so that vocabulary has no place
// on its surface.
type Clock interface {
	Now() time.Time
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// defaultLifetime is how long an issued token is valid with no lifetime
// configured.
const defaultLifetime = 15 * time.Minute

// config is the shared state of a generator and a verifier. Both are built
// from it so that a generator verifies under exactly the rules it issues
// under.
type config struct {
	keys     signingkey.KeySource
	issuer   string
	audience string
	lifetime time.Duration
	alg      signingkey.Alg
	clock    Clock

	// signature is alg resolved once, at construction, so an unknown
	// algorithm is a wiring error rather than a surprise at the first token.
	signature jwa.SignatureAlgorithm

	// parseOpts are the validation rules, built once at construction and
	// thereafter read-only: every verification shares this slice, so nothing
	// may append to it.
	parseOpts []jwt.ParseOption

	// hasIssuer and hasAudience record that the consumer configured the claim,
	// so enforcement never depends on the configured value being non-empty.
	hasIssuer   bool
	hasAudience bool
}

func newConfig() *config {
	return &config{
		lifetime: defaultLifetime,
		alg:      signingkey.RS256,
		clock:    systemClock{},
	}
}

// The setters below exist once and are wrapped by both option types, so the
// rule that configuring a claim also records that it was configured cannot be
// honoured on one path and forgotten on the other.

func setIssuer(iss string) func(*config) {
	return func(c *config) {
		c.issuer = iss
		c.hasIssuer = true
	}
}

func setAudience(aud string) func(*config) {
	return func(c *config) {
		c.audience = aud
		c.hasAudience = true
	}
}

func setClock(clock Clock) func(*config) {
	return func(c *config) { c.clock = clock }
}

// GenerateOption configures a Generator. Every default NewGenerator applies has
// an option here that replaces it.
type GenerateOption func(*config)

// WithIssuer sets the iss claim of issued tokens, and the issuer the generator
// enforces when it verifies. Default: none, and iss is then neither set nor
// checked.
func WithIssuer(iss string) GenerateOption { return GenerateOption(setIssuer(iss)) }

// WithAudience sets the aud claim of issued tokens, and the audience the
// generator enforces when it verifies. Default: none, and aud is then neither
// set nor checked.
func WithAudience(aud string) GenerateOption { return GenerateOption(setAudience(aud)) }

// WithLifetime sets how long an issued token is valid. Default: 15 minutes.
//
// A lifetime of zero or less fails construction, and so does one longer than
// the window a key source that reports its own lifetimes can cover, because a
// token must not outlive the key that signed it.
func WithLifetime(d time.Duration) GenerateOption {
	return func(c *config) { c.lifetime = d }
}

// WithSigningAlg sets the algorithm to sign with. Default: RS256. The key
// source must hold a current key for it at issue time; there is no fallback to
// another algorithm and none to an unsigned token.
func WithSigningAlg(alg signingkey.Alg) GenerateOption {
	return func(c *config) { c.alg = alg }
}

// WithClock sets the time source for iat, exp and the generator's own
// verification. Default: the system clock.
func WithClock(clock Clock) GenerateOption { return GenerateOption(setClock(clock)) }

// VerifyOption configures a Verifier. Every default NewVerifier applies has an
// option here that replaces it, except the key source, which has no default.
type VerifyOption func(*config)

// VerifyWithKeySource sets where verification keys come from. Required: there
// is no default, because something has to hold the keys, so constructing a
// verifier without it is a configuration error.
func VerifyWithKeySource(keys signingkey.KeySource) VerifyOption {
	return func(c *config) { c.keys = keys }
}

// VerifyWithIssuer enforces iss. Default: none, and iss is then not checked.
// When set, a token whose issuer is absent or different is rejected.
//
// Enforcement depends on this option having been given, never on the
// configured value being non-empty.
func VerifyWithIssuer(iss string) VerifyOption { return VerifyOption(setIssuer(iss)) }

// VerifyWithAudience enforces aud. Default: none, and aud is then not checked.
// When set, a token whose audience is absent or does not contain it is
// rejected.
//
// Enforcement depends on this option having been given, never on the
// configured value being non-empty.
func VerifyWithAudience(aud string) VerifyOption { return VerifyOption(setAudience(aud)) }

// VerifyWithClock sets the time source for every time check. Default: the
// system clock. No clock skew is tolerated, so this is the only way to move
// the instant a token is judged against.
func VerifyWithClock(clock Clock) VerifyOption { return VerifyOption(setClock(clock)) }

// validateOptions builds the validation rules every verification runs.
//
// The expiry requirement is registered here, exactly once. Registered twice, a
// later change to the rule would silently take effect in only one of the two
// places, which options_internal_test.go guards against.
func (c *config) validateOptions() []jwt.ParseOption {
	// A jwt.ValidateOption is also a jwt.ParseOption, so these travel to
	// jwt.Parse without being copied into a second slice.
	opts := []jwt.ParseOption{
		// exp must be present. Its own value is then checked by the default
		// time validators, which tolerate no skew.
		jwt.WithRequiredClaim(jwt.ExpirationKey),
		jwt.WithClock(jwt.ClockFunc(c.clock.Now)),
	}
	if c.hasIssuer {
		opts = append(opts, jwt.WithIssuer(c.issuer))
	}
	if c.hasAudience {
		opts = append(opts, jwt.WithAudience(c.audience))
	}

	return opts
}

// validate reports a configuration that cannot work, so a wiring mistake fails
// at construction rather than at the first issue or verification.
func (c *config) validate() error {
	if c.keys == nil {
		return fmt.Errorf("%w: a key source is required", ErrConfig)
	}
	if c.clock == nil {
		return fmt.Errorf("%w: clock must not be nil", ErrConfig)
	}

	// Resolving the algorithm here is what makes a typo a construction error.
	// It narrows to what the JOSE stack knows; whether the key source can hold
	// a key for it is the key source's own decision, reported at issue time.
	signature, ok := jwa.LookupSignatureAlgorithm(c.alg)
	if !ok {
		return fmt.Errorf("%w: unknown signing algorithm %q", ErrConfig, c.alg)
	}
	c.signature = signature
	c.parseOpts = c.validateOptions()

	return nil
}

// validateLifetime refuses a token lifetime that cannot be honoured.
func (c *config) validateLifetime() error {
	if c.lifetime <= 0 {
		return fmt.Errorf("%w: lifetime must be positive, got %s", ErrConfig, c.lifetime)
	}

	// A key source that reports its own lifetimes lets the cap be checked here.
	// A replaced key stays published for the rest of its lifetime, so the
	// usable window for a token signed just before a rotation is the key
	// lifetime minus one rotation interval. One that cannot report gets no
	// check; nothing else about it changes.
	reporter, ok := c.keys.(signingkey.LifetimeReporter)
	if !ok {
		return nil
	}
	window := reporter.KeyLifetime() - reporter.RotateInterval()
	if c.lifetime > window {
		return fmt.Errorf(
			"%w: lifetime %s exceeds the key source's usable window %s "+
				"(key lifetime %s minus rotate interval %s); "+
				"tokens would outlive the key that signed them",
			ErrConfig, c.lifetime, window,
			reporter.KeyLifetime(), reporter.RotateInterval())
	}

	return nil
}
