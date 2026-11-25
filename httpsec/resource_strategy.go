package httpsec

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/assurance"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/hangup"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/internal/porterr"
)

// The names of the caller-strategy options, as configuration errors name them.
const (
	optionClaimsOnly   = "WithClaimsOnly"
	optionClaimsMapper = "WithClaimsMapper"
	optionLocalUsers   = "WithLocalUsers"
	optionLinkedUsers  = "WithLinkedUsers"
)

// The fixed texts a caller strategy answers a dependency failure with. A hang-up has texts of its
// own, so an error handler that logs by text does not report a client that left as an outage.
const (
	textTokenLinkNotRead   = "httpsec: the access token's identity link could not be read"              //nolint:gosec // G101: error text, not a credential
	textTokenLinkEnded     = "httpsec: the request ended while the access token's identity link loaded" //nolint:gosec // G101: error text, not a credential
	textTokenMapperFailed  = "httpsec: the access token's claims mapper failed"                         //nolint:gosec // G101: error text, not a credential
	textTokenMapperEnded   = "httpsec: the request ended while the access token's claims were mapped"   //nolint:gosec // G101: error text, not a credential
	textTokenUserLoadEnded = "httpsec: the request ended while the access token's user loaded"          //nolint:gosec // G101: error text, not a credential
	textTokenUserNotLoaded = "httpsec: the access token's user could not be loaded"                     //nolint:gosec // G101: error text, not a credential
)

// MappedCaller is what a claims mapper (WithClaimsMapper) makes of a verified token.
//
// Its zero value is a local user: a mapper that leaves External unset has its caller judged by the
// MFA requirement policy as the local user Principal names, through the federated-assurance mode
// under the mapper's provider name, so forgetting the flag fails closed. A nil Principal refuses the
// token.
type MappedCaller struct {
	// Principal is the caller. Its scopes are replaced by the token's, whatever it carries.
	Principal *identity.Principal

	// External declares that Principal names no local user (a service, or a partner's user), so
	// the MFA requirement is not looked up for it.
	External bool
}

// strategyConfig is the caller strategy a source's options chose. Every field's zero value is the
// source's default strategy.
type strategyConfig struct {
	// chosen names each strategy option given, so a source given two is refused.
	chosen []string

	mapper         func(ctx context.Context, claims map[string]any) (MappedCaller, error)
	mapperProvider string

	localUsers identity.UserLoader

	links        oidc.LinkStore
	linkProvider string
	linkUsers    identity.UserLoader
}

// resolvesLocal says the strategy can resolve a local user from an external token: linked users, or a
// claims mapper whose caller is not declared external.
func (st *strategyConfig) resolvesLocal() bool { return st.mapper != nil || st.links != nil }

// WithClaimsOnly resolves the caller from the token's claims alone: a user-kind principal whose
// identifier is the source's issuer and the token's subject joined by "#", so it is never a local
// user's identifier nor another issuer's subject, carrying the token's scopes and no role. Such a
// caller names no local user, so the MFA requirement is not looked up for it. It is taken by
// FromIssuer and FromIntrospection.
//
// Default: it is the default of FromIssuer and FromIntrospection.
func WithClaimsOnly() SourceOption {
	return func(cfg *sourceConfig) error {
		cfg.note(optionClaimsOnly)
		cfg.strategy.chosen = append(cfg.strategy.chosen, optionClaimsOnly)

		return nil
	}
}

// WithClaimsMapper resolves the caller with fn, given a copy of the token's verified claims. provider
// names the mapper's evidence: a caller fn does not declare External is judged by the MFA
// requirement policy through its federated-assurance source as a login from provider at the source's
// issuer, with the token's amr and acr. fn's error is a dependency failure (500), never a refusal;
// a nil principal refuses the token as invalid. The caller's scopes are always the token's. It is
// taken by FromIssuer and FromIntrospection; an empty provider or a nil fn is a configuration error
// from New. A panic in fn propagates, as from any consumer port.
//
// Default: claims only (WithClaimsOnly).
func WithClaimsMapper(provider string, fn func(ctx context.Context, claims map[string]any) (MappedCaller, error)) SourceOption {
	return func(cfg *sourceConfig) error {
		cfg.note(optionClaimsMapper)
		cfg.strategy.chosen = append(cfg.strategy.chosen, optionClaimsMapper)
		cfg.strategy.mapper, cfg.strategy.mapperProvider = fn, provider

		return nil
	}
}

// WithLocalUsers loads the caller of a FromProvider token from users, by the token's subject, on
// every request: the user must exist, be active, and be the user asked for, or the token is refused
// as invalid; a loader that fails is a dependency failure. It is taken by FromProvider alone: a
// remote issuer's subject is never a local user's identifier (use WithLinkedUsers). A nil users is a
// configuration error from New.
//
// Default: the provider's own user loader (oidcprovider.Provider.UserLoader).
func WithLocalUsers(users identity.UserLoader) SourceOption {
	return func(cfg *sourceConfig) error {
		cfg.note(optionLocalUsers)
		cfg.strategy.chosen = append(cfg.strategy.chosen, optionLocalUsers)
		cfg.strategy.localUsers = users

		return nil
	}
}

// WithLinkedUsers resolves the caller of an external token to the local user its identity link
// names: links.FindByExternal(provider, issuer, subject), with the source's configured issuer, then
// users.LoadByUserID. An unlinked subject, a missing or inactive user, and a loader answering for
// another user refuse the token as invalid; local user "42" is never loaded for a subject "42"
// without a link. A link store or loader that fails is a dependency failure. The caller is judged by
// the MFA requirement policy through its federated-assurance source as a login from provider, with
// the token's amr and acr. It is taken by FromIssuer and FromIntrospection; an empty provider, a nil
// links or a nil users is a configuration error from New.
//
// Default: claims only (WithClaimsOnly).
func WithLinkedUsers(links oidc.LinkStore, provider string, users identity.UserLoader) SourceOption {
	return func(cfg *sourceConfig) error {
		cfg.note(optionLinkedUsers)
		cfg.strategy.chosen = append(cfg.strategy.chosen, optionLinkedUsers)
		cfg.strategy.links, cfg.strategy.linkProvider, cfg.strategy.linkUsers = links, provider, users

		return nil
	}
}

// checkStrategy refuses a strategy that is a mistake for the source called name: two strategies, the
// local-user strategy on an external source, and an absent port or provider name.
func (st *strategyConfig) checkStrategy(rsID, name string, external bool) error {
	if len(st.chosen) > 1 {
		return newConfigError("%s (%s): %s was given two caller strategies, %s and %s; give it one",
			optionResourceServer, rsID, name, st.chosen[0], st.chosen[1])
	}

	switch {
	case external && st.localUsers != nil || external && slices.Contains(st.chosen, optionLocalUsers):
		return newConfigError("%s (%s): %s does not take %s: an external token's subject is never a local "+
			"user's identifier; use %s to resolve it through identity links", optionResourceServer, rsID, name,
			optionLocalUsers, optionLinkedUsers)
	case slices.Contains(st.chosen, optionClaimsMapper) &&
		(st.mapper == nil || strings.TrimSpace(st.mapperProvider) == ""):
		return newConfigError("%s (%s): %s was given %s with a nil mapper or an empty provider name",
			optionResourceServer, rsID, name, optionClaimsMapper)
	case slices.Contains(st.chosen, optionLinkedUsers) &&
		(nilcheck.IsNil(st.links) || nilcheck.IsNil(st.linkUsers) || strings.TrimSpace(st.linkProvider) == ""):
		return newConfigError("%s (%s): %s was given %s with a nil link store, a nil user loader or an empty "+
			"provider name", optionResourceServer, rsID, name, optionLinkedUsers)
	case slices.Contains(st.chosen, optionLocalUsers) && nilcheck.IsNil(st.localUsers):
		return newConfigError("%s (%s): %s was given %s with a nil user loader", optionResourceServer, rsID,
			name, optionLocalUsers)
	default:
		return nil
	}
}

// resolveExternal resolves the caller of an external token tok, verified at the source answering for
// iss, by the strategy. It fills vt's principal and its assurance facts. A refusal is
// ErrInvalidToken; a port that failed, or the request's own end, is returned as the failure it is.
func (st *strategyConfig) resolveExternal(ctx context.Context, iss string, tok *AccessToken, now time.Time,
	vt *verifiedToken,
) error {
	switch {
	case st.mapper != nil:
		mc, err := st.mapper(ctx, maps.Clone(tok.Claims))
		err = porterr.SanitizeTo(ctx, nil, err, porterr.ErrUnwalkable)

		switch {
		case err != nil && hangup.ByCaller(ctx, err):
			return diag.Wrap(err, textTokenMapperEnded, ctx.Err())
		case err != nil:
			return diag.Wrap(err, textTokenMapperFailed)
		case mc.Principal == nil:
			return ErrInvalidToken
		}

		vt.principal = clonePrincipal(mc.Principal)
		vt.external = mc.External

		if !vt.external {
			vt.evidence = assurance.NewFederated(st.mapperProvider, iss, tok.AMR, tok.ACR)
		}

		return nil

	case st.links != nil:
		link, err := st.links.FindByExternal(ctx, st.linkProvider, iss, tok.Subject)
		err = porterr.SanitizeTo(ctx, nil, err, porterr.ErrUnwalkable)

		switch {
		case errors.Is(err, oidc.ErrLinkNotFound):
			return ErrInvalidToken
		case err != nil && hangup.ByCaller(ctx, err):
			return diag.Wrap(err, textTokenLinkEnded, ctx.Err())
		case err != nil:
			return diag.Wrap(err, textTokenLinkNotRead)
		case link == nil || link.UserID == "":
			return ErrInvalidToken
		}

		p, err := loadLocalUser(ctx, st.linkUsers, link.UserID, now)
		if err != nil {
			return err
		}

		vt.principal = p
		vt.external = false
		vt.evidence = assurance.NewFederated(st.linkProvider, iss, tok.AMR, tok.ACR)

		return nil

	default:
		vt.external = true
		vt.principal = &identity.Principal{
			ID:     identity.UserID(iss + "#" + tok.Subject),
			Kind:   identity.KindUser,
			Scopes: slices.Clone(tok.Scopes),
		}

		return nil
	}
}

// loadLocalUser loads the user id names through users. A user who is missing, inactive or loaded as
// another is ErrInvalidToken; a loader that failed, or the request's own end, is the failure it is.
func loadLocalUser(ctx context.Context, users identity.UserLoader, id identity.UserID, now time.Time,
) (*identity.Principal, error) {
	if id == "" {
		return nil, ErrInvalidToken
	}

	details, err := users.LoadByUserID(ctx, id)
	// The loader is the consumer's, and so is its error: one whose chain cannot be walked becomes
	// a fault that matches neither ErrUserNotFound nor the request's cancellation.
	err = porterr.SanitizeTo(ctx, nil, err, porterr.ErrUnwalkable)

	switch {
	case errors.Is(err, identity.ErrUserNotFound):
		return nil, ErrInvalidToken
	case err != nil && hangup.ByCaller(ctx, err):
		return nil, diag.Wrap(err, textTokenUserLoadEnded, ctx.Err())
	case err != nil:
		return nil, diag.Wrap(err, textTokenUserNotLoaded)
	case details == nil || details.ID != id || !details.Active:
		return nil, ErrInvalidToken
	}

	principal := identity.PrincipalFromDetailsAt(details, now)
	principal.Kind = identity.KindUser

	return principal, nil
}

// clonePrincipal copies p and everything it points to, so the principal a mapper returned, which
// the mapper may keep, shares no memory with the caller published for the request. A role that is
// also the active role stays the same role in the copy.
func clonePrincipal(p *identity.Principal) *identity.Principal {
	out := *p
	out.Scopes = slices.Clone(p.Scopes)

	copies := make(map[*identity.AssignedRole]*identity.AssignedRole, len(p.Roles))
	clone := func(r *identity.AssignedRole) *identity.AssignedRole {
		if r == nil {
			return nil
		}

		if c, ok := copies[r]; ok {
			return c
		}

		c := *r
		copies[r] = &c

		return &c
	}

	if p.Roles != nil {
		out.Roles = make([]*identity.AssignedRole, len(p.Roles))
		for i, r := range p.Roles {
			out.Roles[i] = clone(r)
		}
	}

	out.ActiveRole = clone(p.ActiveRole)

	if o := p.Organization; o != nil {
		org := *o
		if o.Group != nil {
			g := *o.Group
			org.Group = &g
		}

		out.Organization = &org
	}

	return &out
}
