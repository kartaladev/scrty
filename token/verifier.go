package token

import (
	"context"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwt"
)

//go:generate mockgen -destination=keysource_mock_test.go -package=token_test -typed github.com/kartaladev/scrty/signingkey KeySource

// Verifier checks a token and returns its claims.
type Verifier interface {
	// Verify reports the claims of a token that passed every check. Every
	// rejection is an error matching ErrTokenInvalid that wraps the cause; a
	// failure to obtain the key set, and a context cancelled before the check
	// finished, are returned as themselves and do not match it.
	Verify(ctx context.Context, token string) (*Claims, error)
}

type verifier struct{ cfg *config }

// NewVerifier returns a Verifier.
//
// VerifyWithKeySource is required. Defaults: no issuer enforced; no audience
// enforced; the system clock. Each is a VerifyOption naming its own default.
func NewVerifier(opts ...VerifyOption) (Verifier, error) {
	cfg := newConfig()
	for _, opt := range opts {
		opt(cfg)
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
	set, err := c.keys.JWKS()
	if err != nil {
		// Not a rejection of the token: the key set could not be obtained.
		// This deliberately does not match ErrTokenInvalid, so a key-service
		// outage is never reported as a failed authentication.
		return nil, fmt.Errorf("token: obtain key set: %w", err)
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
