package httpsec

import (
	"context"
	"errors"
	"maps"
	"slices"
	"time"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/hangup"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/oidcprovider"
)

// SourceOption configures one token source of a resource server: FromProvider, FromIssuer or
// FromIntrospection. A nil option is skipped. An option a source does not take is a configuration
// error from New, naming the option and the source.
type SourceOption func(*sourceConfig) error

// sourceWiring is a source that checks its own wiring against the chain at New: a check that
// needs what other options configured.
type sourceWiring interface {
	checkWiring(c *config) error
}

// optionFromProvider names FromProvider in configuration errors and as a source.
const optionFromProvider = "FromProvider"

// The fixed texts a provider source answers a failure that is not a refusal with. A hang-up has
// texts of its own, so an error handler that logs by text does not report a client that left as
// an outage.
const (
	textTokenUserNotLoaded = "httpsec: the access token's user could not be loaded"            //nolint:gosec // G101: error text, not a credential
	textTokenUserLoadEnded = "httpsec: the request ended while the access token's user loaded" //nolint:gosec // G101: error text, not a credential
)

// FromProvider trusts the access tokens the chain's own provider issues, JWT and opaque alike.
// op must be the provider given to EnableOIDCProvider on the same chain.
//
// Each token is verified by the provider on every request, so a token whose grant was revoked,
// has expired, or names another client or user is refused on the next request after that. Its
// audience must name the resource server's identifier or one of its aliases; a token whose
// audience is only the issuer is meant for UserInfo, and is refused.
//
// Default: the caller is the local user the token's subject names, loaded on every request
// through the provider's own user loader (oidcprovider.Provider.UserLoader), so a role removed
// after the token was issued is not held. A user who is missing, inactive, or loaded as another
// user is refused as an invalid token; a loader that fails is a dependency failure, answered 500,
// never a refusal. The caller carries the token's scopes.
//
// Default: the token must be bound to a DPoP key or a certificate, as every source's must.
//
// A nil op, a provider that is not the chain's, and a source option FromProvider does not take
// are configuration errors from New.
func FromProvider(op *oidcprovider.Provider, opts ...SourceOption) ResourceServerOption {
	return func(rs *resourceServer) error {
		cfg, err := newSourceConfig(opts)
		if err != nil {
			return err
		}

		rs.sources = append(rs.sources, &providerSource{op: op, rs: rs, cfg: cfg})

		return nil
	}
}

// providerSource is FromProvider: the chain's own provider.
type providerSource struct {
	op  *oidcprovider.Provider
	rs  *resourceServer
	cfg *sourceConfig

	// users loads the caller, and now dates its grants: both are handed over at New.
	users identity.UserLoader
	now   func() time.Time
}

func (s *providerSource) name() string        { return optionFromProvider }
func (s *providerSource) allowsUnbound() bool { return false }

// issuer is the provider's issuer, so that a second source answering for it in the same resource
// server is refused at New. It is "" for a nil provider, which checkWiring refuses.
func (s *providerSource) issuer() string {
	if s.op == nil {
		return ""
	}

	return s.op.Issuer()
}

// recognises claims the provider's own opaque formats and a JWT naming the provider's issuer.
func (s *providerSource) recognises(t peeked) recognition {
	switch {
	case t.format == formatProvider:
		return recMarked
	case t.format == formatJWT && s.op != nil && t.iss == s.op.Issuer():
		return recMarked
	default:
		return recNone
	}
}

// checkWiring refuses a nil provider and one that is not the chain's, and takes the provider's
// user loader and the chain's clock.
func (s *providerSource) checkWiring(c *config) error {
	if s.op == nil {
		return newConfigError("%s (%s) was given a nil provider to %s", optionResourceServer, s.rs.id, optionFromProvider)
	}

	if err := s.cfg.refuseOptions(s.rs.id, optionFromProvider); err != nil {
		return err
	}

	if c.oidcProvider == nil || c.oidcProvider.provider != s.op {
		return newConfigError("%s (%s): %s was given a provider that is not the one EnableOIDCProvider serves "+
			"on this chain; a resource server trusts the chain's own provider, and another issuer through FromIssuer",
			optionResourceServer, s.rs.id, optionFromProvider)
	}

	s.users = s.op.UserLoader()
	if s.users == nil {
		return newConfigError("%s (%s): the provider given to %s has no user loader", optionResourceServer,
			s.rs.id, optionFromProvider)
	}

	s.now = c.clock.Now

	return nil
}

// verify has the provider verify raw, holds its audience to the resource server, and loads its
// local user. A refusal is ErrInvalidToken; a store or loader that failed, or the request's own
// end, is returned as the failure it is.
func (s *providerSource) verify(ctx context.Context, raw string) (*verifiedToken, error) {
	at, err := s.op.VerifyAccessToken(ctx, raw)
	if err != nil {
		var refusal *oidcprovider.Error
		if errors.As(err, &refusal) && refusal.Code == oidcprovider.CodeInvalidToken {
			return nil, ErrInvalidToken
		}

		// The provider's dependency failure behind fixed text, or the caller's own context.
		return nil, err
	}

	if !s.rs.audienceNamed(at.Audience) {
		return nil, ErrInvalidToken
	}

	principal, err := s.localUser(ctx, at.Subject)
	if err != nil {
		return nil, err
	}

	principal.Scopes = slices.Clone(at.Scopes)

	return &verifiedToken{
		principal:    principal,
		confirmation: at.Confirmation,
		kind:         factor.AccessToken,
		token: &AccessToken{
			Issuer:       at.Issuer,
			Subject:      string(at.Subject),
			ClientID:     at.ClientID,
			Audience:     slices.Clone(at.Audience),
			Scopes:       slices.Clone(at.Scopes),
			IssuedAt:     at.IssuedAt,
			ExpiresAt:    at.ExpiresAt,
			AuthTime:     at.AuthTime,
			ACR:          at.ACR,
			AMR:          slices.Clone(at.AMR),
			Confirmation: maps.Clone(at.Confirmation),
		},
	}, nil
}

// localUser loads the user subject names. A user who is missing, inactive or loaded as another is
// ErrInvalidToken.
func (s *providerSource) localUser(ctx context.Context, subject identity.UserID) (*identity.Principal, error) {
	if subject == "" {
		return nil, ErrInvalidToken
	}

	details, err := s.users.LoadByUserID(ctx, subject)
	// The loader is the consumer's, and so is its error: one whose chain cannot be walked becomes
	// a fault that matches neither ErrUserNotFound nor the request's cancellation.
	err = porterr.SanitizeTo(ctx, nil, err, porterr.ErrUnwalkable)

	switch {
	case errors.Is(err, identity.ErrUserNotFound):
		return nil, ErrInvalidToken
	case hangup.ByCaller(ctx, err):
		return nil, diag.Wrap(err, textTokenUserLoadEnded, ctx.Err())
	case err != nil:
		return nil, diag.Wrap(err, textTokenUserNotLoaded)
	case details == nil || details.ID != subject || !details.Active:
		return nil, ErrInvalidToken
	}

	principal := identity.PrincipalFromDetailsAt(details, s.now())
	principal.Kind = identity.KindUser

	return principal, nil
}

// audienceNamed says audience names the resource server's identifier or one of its aliases, by
// exact match (RFC 9068 section 4).
func (rs *resourceServer) audienceNamed(audience []string) bool {
	for _, aud := range audience {
		if aud == rs.id || slices.Contains(rs.aliases, aud) {
			return true
		}
	}

	return false
}
