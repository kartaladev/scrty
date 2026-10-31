package token

import (
	"context"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/token/signingkey"
)

// Generator issues tokens and verifies them with its own key source, issuer and
// audience, so a service that issues can verify without a second construction.
//
// Because it verifies, it follows a Verifier's rule: NewGenerator refuses to
// construct one that neither configures nor waives the issuer, and likewise
// the audience. A configured claim goes into every token it issues and is
// checked by its Verify; a waived claim is neither issued nor checked.
type Generator interface {
	// Generate returns a signed token for p, carrying id as its jti. It fails
	// rather than issuing an unsigned token or one signed with an algorithm
	// other than the configured one, and rather than issuing one that
	// identifies nobody: an empty id, a nil principal and a principal with no
	// username are each refused. No failure here matches ErrInvalid.
	// A key source's own crypto.Signer failing to sign comes back behind
	// fixed library text; the signer's own error stays reachable through
	// errors.Is and errors.As, but its text never is.
	Generate(ctx context.Context, id string, p *identity.Principal) (string, error)

	Verifier
}

// Option configures a Generator. Every default NewGenerator applies has an
// option here that replaces it. The issuer and the audience have no default:
// each must be configured or explicitly waived.
type Option func(*config)

// WithIssuer sets the iss claim of issued tokens, and the issuer the generator
// enforces when it verifies. There is no default issuer: NewGenerator fails
// with ErrConfig unless it is given either this option or WithoutIssuer, and
// fails when it is given both. An empty or blank iss (one made only of white
// space) is refused at construction with ErrConfig; any other value is minted
// and enforced exactly as given, white space around it included. A generator
// meant to issue no issuer uses WithoutIssuer.
func WithIssuer(iss string) Option { return Option(setIssuer(iss)) }

// WithAudience sets the aud claim of issued tokens, and the audience the
// generator enforces when it verifies. There is no default audience:
// NewGenerator fails with ErrConfig unless it is given either this option or
// WithoutAudience, and fails when it is given both. An empty or blank aud (one
// made only of white space) is refused at construction with ErrConfig; any
// other value is minted and enforced exactly as given, white space around it
// included. A generator meant to issue no audience uses WithoutAudience.
func WithAudience(aud string) Option { return Option(setAudience(aud)) }

// WithoutIssuer waives the issuer claim, which NewGenerator otherwise requires
// through WithIssuer. It gives the claim up on both sides: issued tokens carry
// no iss, and the generator's Verify accepts any token signed by a key in the
// source whatever its issuer, including one that carries none.
//
// Waive it only when every token signed by a key in the source is meant for
// this generator. Given together with WithIssuer, it fails construction with
// ErrConfig.
func WithoutIssuer() Option { return Option(waiveIssuer()) }

// WithoutAudience waives the audience claim, which NewGenerator otherwise
// requires through WithAudience. It gives the claim up on both sides: issued
// tokens carry no aud, and the generator's Verify accepts any token signed by a
// key in the source whatever its audience, including one that carries none, so
// a token minted for another service that shares the key source verifies here.
//
// Waive it only when every token signed by a key in the source is meant for
// this generator. Given together with WithAudience, it fails construction with
// ErrConfig.
func WithoutAudience() Option { return Option(waiveAudience()) }

// WithTokenLifetime sets how long an issued token is valid. Default: 15 minutes.
//
// A lifetime below one second, or not a whole number of seconds, fails
// construction, because expiry is recorded in whole seconds. So does one
// longer than the window a key source that reports its own lifetimes can
// cover, because a token must not outlive the key that signed it.
func WithTokenLifetime(d time.Duration) Option {
	return func(c *config) { c.lifetime = d }
}

// WithSigningAlg sets the algorithm to sign with. Default: RS256. The key
// source must hold a current key for it at issue time; there is no fallback to
// another algorithm and none to an unsigned token.
func WithSigningAlg(alg signingkey.Alg) Option {
	return func(c *config) { c.alg = alg }
}

// WithClock sets the time source for iat, exp and the generator's own
// verification. Default: clock.System().
//
// A nil clock, typed nil included, fails construction with ErrConfig: a
// generator with no clock could not stamp iat or exp at all.
func WithClock(clk clock.Clock) Option { return Option(setClock(clk)) }

type generator struct{ cfg *config }

// NewGenerator returns a Generator signing with keys.
//
// A decision on the issuer and on the audience is required: each is
// configured, with WithIssuer and WithAudience, or waived by name, with
// WithoutIssuer and WithoutAudience. There is no default that issues and checks
// neither. Defaults: a 15-minute lifetime; RS256; the system clock. Each is an
// Option naming its own default.
//
// A nil option is skipped, so a consumer may build the slice conditionally.
//
// Construction fails with ErrConfig when no key source is supplied —
// including a non-nil interface holding a nil pointer, which is what an
// unchecked constructor error hands over — when the signing algorithm is one
// this library's key sources cannot produce, when the issuer or the audience
// is neither configured nor waived, or is both, when either is configured
// empty or blank (the empty string, or white space alone; the refusal names
// the waiver to use instead), when the lifetime is zero or
// less or is not a whole number of seconds, and when a key source that reports
// its own key lifetime and rotation interval could not keep a key published for
// as long as the tokens would live.
func NewGenerator(keys signingkey.KeySource, opts ...Option) (Generator, error) {
	cfg := newConfig()
	cfg.keys = keys
	for _, opt := range opts {
		// A consumer who builds the slice conditionally leaves an entry nil
		// without thinking about it; every other constructor in this library
		// skips one rather than panicking.
		if opt != nil {
			opt(cfg)
		}
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if err := cfg.validateClaims(generatorClaims); err != nil {
		return nil, err
	}
	if err := cfg.validateLifetime(); err != nil {
		return nil, err
	}

	return &generator{cfg: cfg}, nil
}

func (g *generator) Verify(ctx context.Context, raw string) (*Claims, error) {
	return g.cfg.verify(ctx, raw)
}

func (g *generator) Generate(_ context.Context, id string, p *identity.Principal) (string, error) {
	// Never ErrInvalid: that is the verdict on a token a caller
	// presented, and there is no token here. A consumer mapping
	// ErrInvalid to "credential refused" must not see this.
	//
	// A principal that names nobody is refused alongside no principal at all.
	// identity.Principal is a plain exported struct, so a store row with a
	// blank username arrives here as a perfectly good pointer, and signing for
	// it would mint a valid token for the empty subject.
	if p == nil {
		return "", fmt.Errorf("token: generate: %w", identity.ErrNoPrincipal)
	}
	if p.Username == "" {
		return "", fmt.Errorf("token: generate: %w", ErrNoSubject)
	}
	if id == "" {
		return "", fmt.Errorf("token: generate: %w", ErrNoTokenID)
	}

	cfg := g.cfg

	kid, signer, ok := cfg.keys.Signer(cfg.alg)
	if !ok {
		// Never fall back to another algorithm, and never to an unsigned
		// token. Keys rotate, so this cannot be a construction check.
		return "", fmt.Errorf("token: no current key for algorithm %q", cfg.alg)
	}

	now := cfg.clock.Now()
	builder := jwt.NewBuilder().
		JwtID(id).
		Subject(p.Username). // the username, not the opaque identifier
		IssuedAt(now).
		Expiration(now.Add(cfg.lifetime))
	if cfg.hasIssuer {
		builder = builder.Issuer(cfg.issuer)
	}
	if cfg.hasAudience {
		builder = builder.Audience([]string{cfg.audience})
	}

	claims, err := builder.Build()
	if err != nil {
		return "", fmt.Errorf("token: build claims: %w", err)
	}

	// The kid goes into the protected header directly, so verification can
	// select the key. Signing with the crypto.Signer the key source handed
	// over avoids a round trip through a JWK, which would re-encode and
	// re-decode the private key on every call and discard its precomputed
	// values.
	headers := jws.NewHeaders()
	if err := headers.Set(jws.KeyIDKey, kid); err != nil {
		return "", fmt.Errorf("token: set key identifier: %w", err)
	}

	signed, err := jwt.Sign(claims,
		jwt.WithKey(cfg.signature, signer, jws.WithProtectedHeaders(headers)))
	if err != nil {
		// The failure may be the consumer's own crypto.Signer refusing to
		// sign — a KMS or HSM outage, say — so its error is kept reachable
		// but never rendered into the text.
		return "", diag.Wrap(err, "token: sign")
	}

	return string(signed), nil
}
