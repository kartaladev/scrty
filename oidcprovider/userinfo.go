package oidcprovider

import (
	"context"
	"errors"
	"slices"

	"github.com/kartaladev/scrty/identity"
)

// claimSub is the one claim every UserInfo answer holds.
const claimSub = "sub"

// UserInfo answers what the token at, read by VerifyAccessToken, may know of its user.
//
// It takes only a token for the issuer (R4), so an API a token was also meant for cannot replay one
// meant for it alone here, and a token asked for a named resource has no issuer and is refused
// (R15). A token past its expiry, and one whose grant is revoked, expired or gone, read again here
// as a token verified a moment ago may have lost it, is refused too. Each of those is invalid_token.
// A token good in every other way lacking openid is insufficient_scope. A missing or disabled user
// is invalid_token, and nothing is revoked: this answers a read, and a refresh is what revokes.
//
// The answer always holds sub, the token's subject, which is the ID token's for the same grant. The
// rest comes from the ClaimSource given to WithClaimSource, or by default from the user just loaded.
// A claim whose value is null or the empty string is left out, never sent as either; an empty list
// or object, false and zero are values and stay.
//
// None of this has an override apart from the source: RFC 9068 §4 is why the audience has none. A
// store or claim source that cannot answer is no verdict on the token: it matches ErrDependency
// behind fixed text, and a caller who left matches its own context's error.
func (p *Provider) UserInfo(ctx context.Context, at *AccessToken) (map[string]any, error) {
	if at == nil || !slices.Contains(at.Audience, p.issuer) || !p.cfg.clock.Now().Before(at.ExpiresAt) {
		return nil, refuseToken()
	}
	if err := p.requireGrantHolds(ctx, at); err != nil {
		return nil, err
	}
	if !slices.Contains(at.Scopes, scopeOpenID) {
		return nil, &Error{Code: CodeInsufficientScope}
	}

	details, err := p.users.LoadByUserID(ctx, at.Subject)
	switch {
	case errors.Is(err, identity.ErrUserNotFound):
		return nil, refuseToken()
	case err != nil:
		return nil, dependencyFailure(ctx, err, "oidcprovider: load the token's user")
	case details == nil || details.ID != at.Subject || !details.Active:
		return nil, refuseToken()
	}

	claims := identityClaims(details, at.Scopes)
	if p.cfg.claimSource != nil {
		claims, err = p.cfg.claimSource.Claims(ctx, at.Subject, slices.Clone(at.Scopes))
		if err != nil {
			return nil, dependencyFailure(ctx, err, "oidcprovider: read the user's claims")
		}
	}

	answer := make(map[string]any, len(claims)+1)
	for name, value := range claims {
		if !absentClaim(value) {
			answer[name] = value
		}
	}
	answer[claimSub] = string(at.Subject)

	return answer, nil
}
