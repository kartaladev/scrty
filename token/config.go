package token

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwt"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/token/signingkey"
)

// ErrConfig is wrapped by every error NewGenerator, NewVerifier and NewIssuer
// return for a wiring mistake, so a consumer can tell a contradictory
// configuration from a failure at issue or verification time without matching on
// message text. Issuer.Issue wraps it too for a request that cannot be honoured.
var ErrConfig = errors.New("token: invalid configuration")

// The types a token declares in its typ header, one per kind of token. A
// verifier accepts only the one it is for, so a token of one kind never
// validates as another, even under the same keys, issuer and audience.
const (
	// TypeFirstParty is the type of a token a Generator issues, and the one a
	// Verifier accepts, by default. WithTokenType and WithVerifyTokenType replace
	// it.
	TypeFirstParty = "scrty+jwt"

	// TypeAccessToken is the type of an OAuth access token (RFC 9068).
	TypeAccessToken = "at+jwt"

	// TypeIDToken is the type of an OpenID Connect ID token.
	TypeIDToken = "JWT"

	// TypeLogoutToken is the type of a back-channel logout token.
	TypeLogoutToken = "logout+jwt" //nolint:gosec // G101: a media type, not a credential
)

// defaultLifetime is how long an issued token is valid with no lifetime
// configured.
const defaultLifetime = 15 * time.Minute

// defaultMaxTokenSize is the largest string Verify will look at with no
// ceiling configured. A compact JWS carrying the claims this package issues
// and an RS256 signature is a few hundred bytes, so 8 KiB leaves ample room
// for a consumer's own key source and its own claims while keeping the work an
// unauthenticated request can buy bounded.
const defaultMaxTokenSize = 8 << 10

// config is the shared state of a generator, a verifier and an issuer. They are
// built from it so that a generator verifies under exactly the rules it issues
// under, and an issuer signs as a generator does.
type config struct {
	keys     signingkey.KeySource
	issuer   string
	audience string
	lifetime time.Duration
	alg      signingkey.Alg
	clock    clock.Clock

	// subject is which of the principal's values a generator writes as sub.
	// A verifier reads no principal, and leaves it at its zero value.
	subject SubjectMode

	// tokenType is the typ a generator declares and the type a verification
	// accepts.
	tokenType string

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
	// so a claim configured as the empty string, or as white space alone, is
	// refused at construction rather than mistaken for one never configured.
	hasIssuer   bool
	hasAudience bool

	// issuerWaived and audienceWaived record that the consumer waived the
	// claim by name. Both constructors require each claim to be either
	// configured or waived, and never both.
	issuerWaived   bool
	audienceWaived bool

	// algSet, subjectSet and tokenTypeSet record that the consumer applied
	// WithSigningAlg, WithUsernameSubject and WithTokenType, so NewIssuer can
	// refuse them whatever value they carry, including the default's.
	algSet       bool
	subjectSet   bool
	tokenTypeSet bool
}

func newConfig() *config {
	return &config{
		lifetime:     defaultLifetime,
		alg:          signingkey.RS256,
		clock:        clock.System(),
		tokenType:    TypeFirstParty,
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

func setClock(clk clock.Clock) func(*config) {
	return func(c *config) { c.clock = clk }
}

// subjectOf is the value of p the configured subject mode writes as sub.
func (c *config) subjectOf(p *identity.Principal) string {
	if c.subject == SubjectUsername {
		return p.Username
	}

	return string(p.ID)
}

func waiveIssuer() func(*config) {
	return func(c *config) { c.issuerWaived = true }
}

func waiveAudience() func(*config) {
	return func(c *config) { c.audienceWaived = true }
}

// claimOptions names the options that configure and waive one claim on one
// constructor, so a refusal tells the consumer which of its own options fix the
// wiring.
type claimOptions struct {
	claim, configure, waive string
}

var (
	verifierClaims = [2]claimOptions{
		{claim: "issuer", configure: "WithVerifyIssuer", waive: "WithoutVerifyIssuer"},
		{claim: "audience", configure: "WithVerifyAudience", waive: "WithoutVerifyAudience"},
	}
	generatorClaims = [2]claimOptions{
		{claim: "issuer", configure: "WithIssuer", waive: "WithoutIssuer"},
		{claim: "audience", configure: "WithAudience", waive: "WithoutAudience"},
	}
)

// validateClaims refuses a configuration that neither configures nor waives
// the issuer or the audience, one that both configures and waives the same
// claim, and one that configures a claim as the empty string or as white space
// alone. A generator and a verifier share the rule and differ only in the
// option names, given issuer first, then audience.
func (c *config) validateClaims(names [2]claimOptions) error {
	if err := requireCheckOrWaiver(names[0], c.hasIssuer, c.issuer, c.issuerWaived); err != nil {
		return err
	}

	return requireCheckOrWaiver(names[1], c.hasAudience, c.audience, c.audienceWaived)
}

// requireCheckOrWaiver reports a claim that is neither configured nor waived,
// or both, or configured as the empty string or as white space alone, naming
// the two options so the error says how to fix the wiring.
//
// An empty or blank value is refused rather than enforced: two services that
// each pass a setting left unset would mint and accept the same empty claim,
// and so accept each other's tokens, and a setting that holds only a stray
// space or newline is the same mistake. A value that merely has white space
// around other text is the consumer's own string, and is enforced exactly as
// given, never trimmed.
func requireCheckOrWaiver(names claimOptions, configured bool, value string, waived bool) error {
	switch {
	case configured && waived:
		return fmt.Errorf("%w: the %s is both configured (%s) and waived (%s)",
			ErrConfig, names.claim, names.configure, names.waive)
	case configured && strings.TrimSpace(value) == "":
		return fmt.Errorf("%w: the %s given to %s is empty or blank: configure a non-blank %s, or waive it with %s",
			ErrConfig, names.claim, names.configure, names.claim, names.waive)
	case !configured && !waived:
		return fmt.Errorf("%w: an %s is required: configure it with %s, or waive it with %s",
			ErrConfig, names.claim, names.configure, names.waive)
	default:
		return nil
	}
}

// validateOptions builds the validation rules every verification runs.
//
// The expiry requirement is registered here, exactly once. Registered twice, a
// later change to the rule would silently take effect in only one of the two
// places, which config_internal_test.go guards against.
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
	if nilcheck.IsNil(c.clock) {
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
	return c.checkLifetime(c.lifetime)
}

// checkLifetime refuses lifetime when a token cannot be issued for that long.
func (c *config) checkLifetime(lifetime time.Duration) error {
	if lifetime <= 0 {
		return fmt.Errorf("%w: lifetime must be positive, got %s", ErrConfig, lifetime)
	}

	// Expiry is recorded in whole seconds, so a fractional lifetime would issue
	// tokens that expire at an instant the consumer did not ask for.
	if lifetime%time.Second != 0 {
		return fmt.Errorf("%w: lifetime must be a whole number of seconds, at least 1s, got %s",
			ErrConfig, lifetime)
	}

	// A key source that reports its own lifetimes lets the cap be checked here.
	// A replaced key stays published for at least the rest of its lifetime, so
	// the usable window for a token signed just before a rotation is the key
	// lifetime minus one rotation interval. A key replaced late stays for that
	// window from its replacement, and either way a margin of one reload interval
	// covers a replica still signing with it until it reloads, so a token at the
	// window verifies in both cases. One that cannot report gets no check; nothing
	// else about it changes.
	reporter, ok := c.keys.(signingkey.LifetimeReporter)
	if !ok {
		return nil
	}
	window := reporter.KeyLifetime() - reporter.RotateInterval()
	if lifetime > window {
		return fmt.Errorf(
			"%w: lifetime %s exceeds the key source's usable window %s "+
				"(key lifetime %s minus rotate interval %s); "+
				"tokens would outlive the key that signed them",
			ErrConfig, lifetime, window,
			reporter.KeyLifetime(), reporter.RotateInterval())
	}

	return nil
}

// validateFirstPartyType refuses a type a first-party token cannot declare: a
// blank one, and the type of another kind of token.
func (c *config) validateFirstPartyType() error {
	wanted := normalizeTokenType(c.tokenType)
	if strings.TrimSpace(wanted) == "" {
		return fmt.Errorf("%w: the token type given to WithTokenType is empty or blank", ErrConfig)
	}
	for _, reserved := range []string{TypeAccessToken, TypeIDToken, TypeLogoutToken} {
		if wanted == normalizeTokenType(reserved) {
			return fmt.Errorf("%w: the token type %q given to WithTokenType is reserved for another kind of token",
				ErrConfig, c.tokenType)
		}
	}

	return nil
}

// normalizeTokenType is the form two types are compared in: ASCII lower case,
// with an "application/" prefix dropped, as RFC 7515 section 4.1.9 lets a type
// be written either way. Only ASCII letters fold: Unicode folding would equate
// a dotted capital I with i and the Kelvin sign with k, so a type spelled with
// them would pass for one it is not.
func normalizeTokenType(typ string) string {
	return strings.TrimPrefix(asciiLower(typ), "application/")
}

// asciiLower lower-cases the ASCII letters of s and leaves every other byte as
// it is.
func asciiLower(s string) string {
	return strings.Map(func(r rune) rune {
		if 'A' <= r && r <= 'Z' {
			return r + ('a' - 'A')
		}

		return r
	}, s)
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
