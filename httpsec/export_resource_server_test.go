package httpsec

import (
	"context"
	"strings"
	"sync/atomic"

	"github.com/kartaladev/scrty/identity"
)

// StubSource is a token source for the resource server's routing and construction tests: it claims
// tokens by a prefix, an issuer or the provider's own format, as the real sources do, and verifies
// with Verify. It counts the tokens offered to it.
type StubSource struct {
	Name string

	// Issuer is the issuer the source answers for: a JWT whose iss equals it is marked for it.
	Issuer string

	// Prefix marks an opaque token for it. Fallback claims every unmarked opaque token.
	Prefix   string
	Fallback bool

	// Provider claims the provider's own opaque formats.
	Provider bool

	// Unbound accepts a token bound to nothing.
	Unbound bool

	// Verify answers the token. Nil accepts every token as user "u-1", unbound.
	Verify func(ctx context.Context, raw string) (*identity.Principal, map[string]string, error)

	offered atomic.Int32
}

// Offered is how many tokens were offered to the source.
func (s *StubSource) Offered() int { return int(s.offered.Load()) }

func (s *StubSource) name() string        { return s.Name }
func (s *StubSource) issuer() string      { return s.Issuer }
func (s *StubSource) allowsUnbound() bool { return s.Unbound }

func (s *StubSource) recognises(t peeked) recognition {
	switch {
	case t.format == formatProvider && s.Provider:
		return recMarked
	case t.format == formatJWT && s.Issuer != "" && t.iss == s.Issuer:
		return recMarked
	case t.format == formatOpaque && s.Prefix != "" && strings.HasPrefix(t.raw, s.Prefix):
		return recMarked
	case t.format == formatOpaque && s.Fallback:
		return recFallback
	default:
		return recNone
	}
}

func (s *StubSource) verify(ctx context.Context, raw string) (*verifiedToken, error) {
	s.offered.Add(1)

	if s.Verify == nil {
		return &verifiedToken{principal: &identity.Principal{ID: "u-1", Kind: identity.KindUser}}, nil
	}

	p, cnf, err := s.Verify(ctx, raw)
	if err != nil {
		return nil, err
	}

	return &verifiedToken{principal: p, confirmation: cnf}, nil
}

// WithStubSource adds s to a resource server; a nil s is a typed nil source.
func WithStubSource(s *StubSource) ResourceServerOption { return withSource(s) }

// WithNilSource adds a nil source to a resource server.
func WithNilSource() ResourceServerOption { return withSource(nil) }
