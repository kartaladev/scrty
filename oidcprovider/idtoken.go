package oidcprovider

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/token"
	"github.com/kartaladev/scrty/token/signingkey"
)

// errNoIssuer stands for a client asking for an algorithm no issuer was built for, which a
// client's validation against the keys leaves no way to reach.
var errNoIssuer = errors.New("oidcprovider: no issuer for the client's algorithm")

// buildIssuers returns an issuer per algorithm the keys hold, all under the provider's
// identifier and clock (R6). Building them here is what keeps a generator's subject mode out:
// sub is whatever a mint names, which is the grant's user identifier. An algorithm no client
// could register is left out, so a source listing one does not fail construction for it.
//
// An issuer's own default lifetime is never used, because every mint names the client's. So it
// is set no higher than the keys allow, in whole seconds, and cannot refuse keys that the
// clients fit: a client over the window is refused by name when it is registered, and keys
// with no window at all fail here, naming Keys.
func buildIssuers(
	keys signingkey.KeySource, limits keyLimits, issuer string, clk clock.Clock,
) (map[signingkey.Alg]*token.Issuer, error) {
	lifetime := defaultTokenLifetime
	if limits.capped {
		lifetime = min(lifetime, limits.window.Truncate(time.Second))
	}
	issuers := make(map[signingkey.Alg]*token.Issuer, len(limits.algs))
	for _, alg := range limits.algs {
		if !signingkey.SupportedAlg(alg) {
			continue
		}
		built, err := token.NewIssuer(keys, alg, issuer,
			token.WithTokenLifetime(lifetime), token.WithClock(clk))
		if err != nil {
			return nil, fmt.Errorf("%w: Keys: %w", ErrConfig, err)
		}
		issuers[alg] = built
	}

	return issuers, nil
}

// issue signs in with the key the client's algorithm names. Its jti is a fresh identifier,
// and a failure is the key source's or the random source's, never the request's.
func (p *Provider) issue(ctx context.Context, rc *RegisteredClient, in token.Issue) (string, error) {
	issuer, ok := p.issuers[rc.IDTokenAlg]
	if !ok {
		return "", errNoIssuer
	}
	jti, err := p.cfg.ids.NewID()
	if err != nil {
		return "", err
	}
	in.ID = jti.String()

	return issuer.Issue(ctx, in)
}

// mintIDToken signs grant's ID token. Everything it states of the authentication comes from
// the grant, which copied it from the sign-in, so auth_time is never the exchange's time (H3)
// and sid stays the sign-in's family across its renewals. nonce is what the code's request
// sent, and a refresh, which has none to repeat, leaves it empty. sub is the grant's user
// identifier, whatever a chain reads usernames as (R6).
func (p *Provider) mintIDToken(ctx context.Context, grant *Grant, nonce string, rc *RegisteredClient) (string, error) {
	claims := authenticationClaims(grant)
	claims[claimAZP] = rc.ID
	claims[claimSID] = grant.SignInFamily.String()
	if nonce != "" {
		claims[claimNonce] = nonce
	}

	raw, err := p.issue(ctx, rc, token.Issue{
		Type:     token.TypeIDToken,
		Subject:  string(grant.User),
		Audience: []string{rc.ID},
		Lifetime: rc.IDTokenLifetime,
		Claims:   claims,
	})
	if err != nil {
		return "", dependencyFailure(ctx, err, "oidcprovider: sign the ID token")
	}

	return raw, nil
}

// authenticationClaims states how the grant's sign-in authenticated, omitting what it did not
// record.
func authenticationClaims(grant *Grant) map[string]any {
	claims := map[string]any{claimAuthTime: grant.AuthTime.Unix()}
	if len(grant.AMR) > 0 {
		claims[claimAMR] = slices.Clone(grant.AMR)
	}
	if grant.ACR != "" {
		claims[claimACR] = grant.ACR
	}

	return claims
}

// The claims the provider's tokens carry besides a token's own.
const (
	claimAZP      = "azp"
	claimSID      = "sid"
	claimNonce    = "nonce"
	claimAuthTime = "auth_time"
	claimAMR      = "amr"
	claimACR      = "acr"
	claimClientID = "client_id"
	claimScope    = "scope"
	claimGID      = "gid"
	claimCNF      = "cnf"
)
