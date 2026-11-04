package httpsec

import (
	"context"

	"github.com/kartaladev/scrty/oidcprovider"
)

// PendingOIDCRequest reads the pending request handle names, for the consumer's login and
// consent pages, taking the browser's flow cookie from r. The view holds what a page shows
// and no secret: no PKCE challenge, nonce, state or redirect URI. It looks up no account,
// and spends nothing, so a page may read a request any number of times before it resumes.
//
// A handle that is unknown, expired, already answered or bound to another browser, and a
// request with no flow cookie, all answer ErrOIDCUnknownHandle alike. A failing store or
// registry answers an error matching oidcprovider.ErrDependency, which is a 500 by default.
//
// p must be the provider on the chain, because it says which name the flow cookie goes by.
func PendingOIDCRequest(ctx context.Context, p *oidcprovider.Provider, r Request, handle string) (*oidcprovider.PendingView, error) {
	flow, _ := r.Cookie(oidcCookieName(p, OIDCFlowCookie))

	view, err := p.PendingRequest(ctx, handle, flow)
	if err != nil {
		return nil, oidcResumeRefusal(err)
	}

	return view, nil
}
