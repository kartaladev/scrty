package oidcprovider

import (
	"context"
	"net/url"
	"slices"

	"github.com/kartaladev/scrty/token/onetime"
)

//go:generate mockgen -destination=code_mock_test.go -package=oidcprovider_test -typed github.com/kartaladev/scrty/oidcprovider CodeStore,BrowserSessionStore
//go:generate mockgen -destination=codetoken_mock_test.go -package=oidcprovider_test -typed -mock_names=Store=MockCodeTokenStore github.com/kartaladev/scrty/token/onetime Store

// paramCode is the parameter a success response carries the code in.
const paramCode = "code"

// codeTokens is the manager of the provider's code tokens. It holds nothing but what New
// settled, all of which onetime.New accepts, so it is built where it is used.
func (p *Provider) codeTokens() (*onetime.Tokens, error) {
	return onetime.New(codeTokenPurpose,
		onetime.WithStore(p.stores.codeTokens),
		onetime.WithTokenTTL(p.cfg.codeLifetime),
		onetime.WithIDGenerator(p.cfg.ids),
		onetime.WithClock(p.cfg.clock),
		onetime.WithLogger(p.cfg.logger),
		onetime.WithRandom(p.cfg.random),
	)
}

// issueCode writes a code for the sign-in and the scopes granted, and returns the
// authorization response that carries it, with state and iss. It records the request's
// bindings, the sign-in's facts as they were presented, and the grant's family, chosen now
// so that an end of the sign-in can reach a grant not stored yet (R7).
//
// The token is issued unbound, because a code another client presents must count as used,
// which a binding would refuse without spending. The secret exists only in what this
// returns, so a token written with no record behind it is a code no one can ever present.
// The caller shows the answer only once the stage is spent.
func (p *Provider) issueCode(
	ctx context.Context, r *PendingRequest, rc *RegisteredClient, s SignIn, scopes []string,
) (string, error) {
	family, err := p.cfg.ids.NewID()
	if err != nil {
		return "", dependencyFailure(ctx, err, "oidcprovider: mint a grant family")
	}
	tokens, err := p.codeTokens()
	if err != nil {
		return "", dependencyFailure(ctx, err, "oidcprovider: build the code tokens")
	}
	code, tok, err := tokens.Issue(ctx, string(s.User))
	if err != nil {
		return "", dependencyFailure(ctx, err, "oidcprovider: issue a code")
	}

	err = p.stores.codes.Create(ctx, &CodeRecord{
		TokenID:        tok.ID,
		ClientID:       r.ClientID,
		RedirectURI:    r.RedirectURI,
		Challenge:      r.Challenge,
		Nonce:          r.Nonce,
		DPoPJKT:        r.DPoPJKT,
		Scopes:         slices.Clone(scopes),
		Resources:      slices.Clone(r.Resources),
		SignIn:         cloneSignIn(s),
		GrantFamily:    family,
		Offline:        slices.Contains(scopes, scopeOffline),
		EndsWithSignIn: rc.EndGrantsWithSignIn,
		ExpiresAt:      tok.ExpiresAt,
	})
	if err != nil {
		return "", dependencyFailure(ctx, err, "oidcprovider: store the code record")
	}

	answer := url.Values{paramCode: {code}, "iss": {p.issuer}}
	if r.State != "" {
		answer.Set(paramState, r.State)
	}

	return withQuery(r.RedirectURI, answer), nil
}
