package httpsec

import (
	"context"
	"strings"
	"sync/atomic"

	"github.com/kartaladev/scrty/authenticate/factor"
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

	// External says the verified caller names no local user, as a claims-only caller does.
	External bool

	// TokenScopes are the scopes the verified token states, published whatever the principal
	// Verify returns carries.
	TokenScopes []string

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

	tok := &AccessToken{Subject: "u-1", Scopes: s.TokenScopes}

	if s.Verify == nil {
		return &verifiedToken{
			principal: &identity.Principal{ID: "u-1", Kind: identity.KindUser},
			kind:      factor.ExternalAccessToken, token: tok, external: s.External,
		}, nil
	}

	p, cnf, err := s.Verify(ctx, raw)
	if err != nil {
		return nil, err
	}

	tok.Confirmation = cnf

	return &verifiedToken{principal: p, confirmation: cnf, kind: factor.ExternalAccessToken, token: tok,
		external: s.External}, nil
}

// WithStubSource adds s to a resource server; a nil s is a typed nil source.
func WithStubSource(s *StubSource) ResourceServerOption { return withSource(s) }

// WithNilSource adds a nil source to a resource server.
func WithNilSource() ResourceServerOption { return withSource(nil) }

// AudienceNamedBy says whether audience names the resource server id, or one of its aliases.
func AudienceNamedBy(id string, aliases, audience []string) bool {
	return (&resourceServer{id: id, aliases: aliases}).audienceNamed(audience)
}
