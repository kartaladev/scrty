package token

import (
	"errors"
	"fmt"
	"reflect"
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

// defaultMaxTokenSize is the largest string Verify will look at with no
// ceiling configured. A compact JWS carrying the claims this package issues
// and an RS256 signature is a few hundred bytes, so 8 KiB leaves ample room
// for a consumer's own key source and its own claims while keeping the work an
// unauthenticated request can buy bounded.
const defaultMaxTokenSize = 8 << 10

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

	// maxTokenSize bounds the string Verify will look at, in bytes.
	maxTokenSize int

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
		lifetime:     defaultLifetime,
		alg:          signingkey.RS256,
		clock:        systemClock{},
		maxTokenSize: defaultMaxTokenSize,
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

// VerifyWithMaxTokenSize sets the largest token, in bytes, that Verify will
// look at. Default: 8192, which is generous for a compact JWS carrying an
// RS256 signature.
//
// A longer string is refused as an invalid token before anything is decoded
// and before the key source is consulted, so the work an unauthenticated
// request can buy stays bounded. Raise it for a consumer whose own claims are
// large; a size of zero or less fails construction, because a verifier that
// accepts nothing is a wiring mistake rather than a policy.
func VerifyWithMaxTokenSize(size int) VerifyOption {
	return func(c *config) { c.maxTokenSize = size }
}

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

		// Every time comparison is made at the resolution the clock reports.
		// Unpinned, both of its operands are rounded by a process-global
		// truncation in the JOSE stack that any package in the consumer's
		// binary — a transitive dependency's init included — can widen, and an
		// nbf or iat that far in the future is then accepted.
		//
		// Pinned to no truncation rather than to the stack's own one-second
		// granularity: for the whole-second numeric dates it parses by default
		// the two agree exactly, and should a consumer ever widen the parse
		// precision, rounding to the second would grant up to a second of nbf
		// and iat leniency that this package documents as unavailable.
		jwt.WithTruncation(0),
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
	// nilPort rather than == nil: an unchecked constructor error, or a field
	// on a wiring struct nobody set, hands over a non-nil interface holding a
	// nil pointer. == nil lets that through, and validateLifetime's
	// LifetimeReporter assertion then succeeds on it and reads the report off
	// a nil receiver, inside this constructor.
	if nilPort(c.keys) {
		return fmt.Errorf("%w: a key source is required", ErrConfig)
	}
	if nilPort(c.clock) {
		return fmt.Errorf("%w: clock must not be nil", ErrConfig)
	}
	if c.maxTokenSize <= 0 {
		return fmt.Errorf("%w: maximum token size must be positive, got %d",
			ErrConfig, c.maxTokenSize)
	}

	// Resolving the algorithm here is what makes a typo a construction error.
	//
	// signingkey is the authority on which algorithms exist for this library,
	// not the JOSE stack: the stack knows the name "none" and resolves it, and
	// it knows the symmetric family, whose verification key is the signing
	// key. Asking it whether a name exists would leave "no option enables
	// unsigned tokens" resting on what a dependency refuses at the first
	// signature rather than on a rule this package tests at construction.
	if !signingkey.SupportedAlg(c.alg) {
		return fmt.Errorf("%w: unsupported signing algorithm %q", ErrConfig, c.alg)
	}

	// Whether the key source holds a key for it is the key source's own
	// decision, reported at issue time.
	signature, ok := jwa.LookupSignatureAlgorithm(c.alg)
	if !ok {
		return fmt.Errorf("%w: the JOSE stack does not know signing algorithm %q",
			ErrConfig, c.alg)
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

// nilPort reports whether port is nil, or a non-nil interface holding a nil
// pointer, map, slice, channel or function.
//
// Every port this package accepts goes through it, because == nil answers only
// the first shape and a consumer's wiring mistake almost always produces the
// second.
func nilPort(port any) bool {
	if port == nil {
		return true
	}

	value := reflect.ValueOf(port)
	switch value.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Chan, reflect.Func, reflect.Interface:
		return value.IsNil()
	default:
		return false
	}
}
