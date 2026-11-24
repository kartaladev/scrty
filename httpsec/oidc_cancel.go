package httpsec

import (
	"github.com/kartaladev/scrty/oidcprovider"
)

//go:generate mockgen -destination=pendingrequeststore_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/oidcprovider PendingRequestStore

// oidcCancelRequest is the document a cancel takes: the parked request's handle.
type oidcCancelRequest struct {
	Handle string `json:"req"`
}

// serveCancel ends a parked request's login stage with access_denied and answers 200
// {"redirect_to": "..."}, the client's redirect URI with error, state and iss. It takes no
// sign-in. A handle that is unknown, expired, spent, bound to another browser or past its
// login stage is refused as ErrOIDCUnknownHandle (400); a failing store is answered with no
// redirect, and the request stays parked so the page may post again.
func (g *oidcResumeGroup) serveCancel(ex *Exchange, _ Next) error {
	src, answered, err := g.admitPage(ex)
	if answered || err != nil {
		return err
	}

	ctx := ex.Context()

	doc, err := readOIDCPageDocument[oidcCancelRequest](ctx, ex.Request, g.bodyLimit, ErrOIDCUnknownHandle)
	if err != nil {
		return err
	}

	// The end's only write is the spend. A caller that has already left would hear no answer,
	// and spending would only cost the user a request their page could still end on a retry,
	// so nothing is ended for it. A caller leaving after this check is the race no check
	// closes: the request is then ended, and a retry is an unknown handle.
	if err := ctx.Err(); err != nil {
		return err
	}

	flow, _ := ex.Request.Cookie(oidcCookieName(g.op.provider, OIDCFlowCookie))

	res, err := g.op.provider.EndPending(ctx, oidcprovider.EndPendingInput{
		Handle:     doc.Handle,
		FlowSecret: flow,
		Code:       oidcprovider.CodeAccessDenied,
	})
	if err != nil {
		return g.refusal(ctx, src, err)
	}

	return writeSuccessDocument(ex, oidcResumeDocument{RedirectTo: res.RedirectTo})
}
