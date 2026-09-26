package httpsec

import (
	"math"
	"net/http"
	"time"
)

//go:generate mockgen -destination=flowstore_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/oidc FlowStore

// authorize answers a GET on the authorize prefix followed by a provider's
// name: it starts a flow with that provider and redirects the browser to it.
//
// The browser is handed only the flow's opaque handle, in a cookie scoped to
// the callback prefix, so it is sent back to the callback and nowhere else.
// SameSite=Lax is required rather than chosen: the provider's redirect back is
// a cross-site top-level navigation, on which a Strict cookie is not sent.
//
// The requested destination is passed to the manager as the client gave it and
// is stored untrusted; the callback resolves it against the allowlist when it
// is used. An unregistered name is the manager's ErrUnknownProvider, returned
// unchanged, which the status table answers as not found. A flow store that
// cannot begin the flow is refused with the manager's error, whose text is
// fixed and never the store's; the store's error still matches by identity.
func (i *oidcInterceptor) authorize(ex *Exchange, provider string) error {
	auth, err := i.manager.Authorize(ex.Context(), provider, ex.Request.Query(DefaultOIDCNextParam))
	if err != nil {
		return err
	}

	ex.Writer.SetCookie(&Cookie{
		Name:     i.cookieName,
		Value:    auth.Handle,
		Path:     i.callbackPath,
		MaxAge:   flowCookieMaxAge(auth.ExpiresAt, i.now()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	// The provider's page must not learn which page of the application the
	// browser left from.
	ex.Writer.SetHeader("Referrer-Policy", "no-referrer")
	ex.Writer.SetHeader("Location", auth.RedirectURL)
	ex.Writer.WriteHeader(http.StatusFound)

	return nil
}

// flowCookieMaxAge is the flow cookie's lifetime in seconds: the time left
// until the flow expires, rounded up so the cookie never lapses before a flow
// that could still complete, and never less than 1.
//
// The floor matters because a Max-Age of 0 or less deletes the cookie: a flow
// whose expiry has already passed by this clock, through skew between this
// process and the one that stored it, would otherwise hand the browser a
// cookie-clearing header in place of its handle. A one-second cookie naming an
// expired flow is refused at the callback like any other expired flow.
func flowCookieMaxAge(expiresAt, now time.Time) int {
	left := math.Ceil(expiresAt.Sub(now).Seconds())
	if left < 1 {
		return 1
	}

	if left > math.MaxInt32 {
		return math.MaxInt32
	}

	return int(left)
}
