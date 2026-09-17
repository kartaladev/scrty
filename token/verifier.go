package token

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/v4/jwt"
)

//go:generate mockgen -destination=keysource_mock_test.go -package=token_test -typed github.com/kartaladev/scrty/signingkey KeySource

// Verifier checks a token and returns its claims.
type Verifier interface {
	// Verify reports the claims of a token that passed every check. Every
	// rejection is an error matching ErrTokenInvalid that wraps the cause; a
	// failure to obtain the key set, and a context cancelled before the check
	// finished, are returned as themselves and do not match it.
	//
	// The token must be presented exactly as it was issued: one compact JWS,
	// three unpadded base64url segments, and nothing around it. A re-encoded
	// presentation of an otherwise valid token is rejected, so one issued
	// token has one string that verifies and a consumer may key a revocation
	// list, a replay cache or a rate-limit bucket on it. No option relaxes
	// this.
	Verify(ctx context.Context, token string) (*Claims, error)
}

type verifier struct{ cfg *config }

// NewVerifier returns a Verifier.
//
// VerifyWithKeySource is required. Defaults: no issuer enforced; no audience
// enforced; the system clock; an 8192-byte maximum token size. Each is a
// VerifyOption naming its own default.
//
// A nil option is skipped, so a consumer may build the slice conditionally.
// Construction fails when no key source is supplied, when the clock is nil,
// and when the maximum token size is not positive. A port given as a non-nil
// interface holding a nil pointer — what an unchecked constructor error hands
// over — counts as absent.
func NewVerifier(opts ...VerifyOption) (Verifier, error) {
	cfg := newConfig()
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

	return &verifier{cfg: cfg}, nil
}

func (v *verifier) Verify(ctx context.Context, raw string) (*Claims, error) {
	return v.cfg.verify(ctx, raw)
}

// verify is the one verification path, shared by Verifier and Generator so a
// generator verifies under exactly the rules it issues under.
func (c *config) verify(ctx context.Context, raw string) (*Claims, error) {
	// First, and before anything is decoded: jws.Parse base64-decodes all
	// three segments before it checks a signature, so an unbounded string
	// buys roughly three times its own length in allocations per
	// unauthenticated request.
	if len(raw) > c.maxTokenSize {
		return nil, fmt.Errorf("%w: longer than the %d-byte maximum",
			ErrTokenInvalid, c.maxTokenSize)
	}

	// Before the keys, because this is decidable from the string alone and
	// says nothing about the key source.
	if !canonicalCompact(raw) {
		return nil, fmt.Errorf("%w: not a canonical compact JWS", ErrTokenInvalid)
	}

	set, err := c.keys.JWKS()
	if err != nil {
		// Not a rejection of the token: the key set could not be obtained.
		// This deliberately does not match ErrTokenInvalid, so a key-service
		// outage is never reported as a failed authentication.
		return nil, fmt.Errorf("token: obtain key set: %w", err)
	}

	// The port permits both shapes, and a KMS- or HSM-backed source may well
	// produce them while it is warming up or has lost its backend. Neither is
	// a verdict on the token: with nothing to check against, the check did not
	// happen. Reported as an outage, and never dereferenced — jwt.WithKeySet
	// on a nil set panics inside the JOSE stack.
	if set == nil || set.Len() == 0 {
		return nil, fmt.Errorf("token: obtain key set: %w", ErrNoVerificationKeys)
	}

	// The key is selected by the token's kid, and the algorithm recorded on
	// that key checks the signature, so a header naming another algorithm — or
	// none — fails. Requiring the kid is the default; it is never relaxed.
	//
	// The validation rules were built once, at construction. They are only
	// read from here, never appended to, because the slice is shared by every
	// concurrent verification.
	opts := make([]jwt.ParseOption, len(c.parseOpts)+2)
	opts[0] = jwt.WithKeySet(set)
	opts[1] = jwt.WithContext(ctx)
	copy(opts[2:], c.parseOpts)

	tok, err := jwt.Parse([]byte(raw), opts...)
	if err != nil {
		return nil, classify(err)
	}

	return &Claims{tok: tok}, nil
}

// classify turns a failed parse into the error a caller acts on.
//
// A token is only invalid when it was actually judged. A check the caller
// abandoned says nothing about the token, so a context failure is reported as
// itself — read from the error, not from whether the context happens to be
// dead by now, which would relabel a genuine rejection on a request whose
// deadline lapsed a moment later.
func classify(err error) error {
	for _, infrastructure := range []error{context.Canceled, context.DeadlineExceeded} {
		if errors.Is(err, infrastructure) {
			return fmt.Errorf("token: verify: %w", err)
		}
	}

	return fmt.Errorf("%w: %w", ErrTokenInvalid, err)
}

// canonicalCompact reports whether raw is the single presentation of a compact
// JWS this package accepts: exactly three "."-separated segments, each one
// RFC 7515 base64url with no padding, and a non-empty header and signature.
//
// It exists because jwt.Parse is lenient. It trims surrounding whitespace and
// verifies against a signing input it rebuilds from the decoded segments, so
// base64 padding, the standard "+/" alphabet and stray Unicode space all
// survive it: one issued token would otherwise have unboundedly many distinct
// strings that verify as it, and a consumer keying a revocation list, a replay
// cache, an idempotency record or a rate-limit bucket on the presented string
// would not recognise a re-encoded presentation of a token it already refused.
//
// An empty payload is left to the JOSE stack, which rejects it as it is not
// JSON. This check is about the encoding, not the content.
func canonicalCompact(raw string) bool {
	header, rest, ok := strings.Cut(raw, ".")
	if !ok {
		return false
	}
	payload, signature, ok := strings.Cut(rest, ".")
	if !ok {
		return false
	}
	if header == "" || signature == "" {
		return false
	}

	// A fourth segment lands inside signature, where its "." fails here.
	return base64URL(header) && base64URL(payload) && base64URL(signature)
}

// base64URL reports whether s is entirely RFC 7515 base64url characters. It
// reads bytes, so every byte of a multi-byte rune fails it.
func base64URL(s string) bool {
	for i := range len(s) {
		switch c := s[i]; {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '_':
		default:
			return false
		}
	}

	return true
}
