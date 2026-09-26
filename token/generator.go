package token

import (
	"context"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/signingkey"
)

// Generator issues tokens and verifies them with its own key source, issuer and
// audience, so a service that issues can verify without a second construction.
type Generator interface {
	// Generate returns a signed token for p, carrying id as its jti. It fails
	// rather than issuing an unsigned token or one signed with an algorithm
	// other than the configured one, and rather than issuing one that
	// identifies nobody: an empty id, a nil principal and a principal with no
	// username are each refused. No failure here matches ErrTokenInvalid.
	// A key source's own crypto.Signer failing to sign comes back behind
	// fixed library text; the signer's own error stays reachable through
	// errors.Is and errors.As, but its text never is.
	Generate(ctx context.Context, id string, p *identity.Principal) (string, error)

	Verifier
}

type generator struct{ cfg *config }

// NewGenerator returns a Generator signing with keys.
//
// Defaults: no issuer; no audience; a 15-minute lifetime; RS256; the system
// clock. Each is a GenerateOption naming its own default.
//
// A nil option is skipped, so a consumer may build the slice conditionally.
//
// Construction fails when no key source is supplied — including a non-nil
// interface holding a nil pointer, which is what an unchecked constructor
// error hands over — when the signing algorithm is one this library's key
// sources cannot produce, when the lifetime is zero or less, and when a key
// source that reports its own key lifetime and rotation interval could not
// keep a key published for as long as the tokens would live.
func NewGenerator(keys signingkey.KeySource, opts ...GenerateOption) (Generator, error) {
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
	if err := cfg.validateLifetime(); err != nil {
		return nil, err
	}

	return &generator{cfg: cfg}, nil
}

func (g *generator) Verify(ctx context.Context, raw string) (*Claims, error) {
	return g.cfg.verify(ctx, raw)
}

func (g *generator) Generate(_ context.Context, id string, p *identity.Principal) (string, error) {
	// Never ErrTokenInvalid: that is the verdict on a token a caller
	// presented, and there is no token here. A consumer mapping
	// ErrTokenInvalid to "credential refused" must not see this.
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

	kid, signer, ok := cfg.keys.GetSigner(cfg.alg)
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
