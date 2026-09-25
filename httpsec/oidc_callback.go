package httpsec

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/kartaladev/scrty/oidc"
)

// maxLoggedProviderError bounds each piece of a provider's error text written
// to the log, so a provider cannot fill it.
const maxLoggedProviderError = 256

// The reasons the callback's own refusal records are keyed by. Failures the
// manager already logs (an invalid ID token, a flow store fault, a failed
// exchange or discovery, a broker refusal) are not logged again here.
const (
	callbackReasonInvalidState  = "invalid-state"
	callbackReasonProviderError = "provider-error"
	callbackReasonUnboundError  = "unbound-provider-error"
	callbackReasonNotLinked     = "not-linked"
	callbackReasonIssueFailed   = "handoff-issue-failed"
)

// callback answers a GET on the callback prefix followed by a provider's name:
// the provider's redirect back, carrying either a code or an error.
//
// A callback is bound to the browser's flow by the flow cookie and to the flow
// itself by the echoed state. One that cannot present the cookie, a code and a
// state, or that sends any of code, state or error more than once, is refused as an invalid state before the manager is asked, so
// it causes no store operation and sends no cookie-clearing header: a forged
// callback riding the victim's cookie cannot end the victim's login.
//
// The flow cookie is cleared only once the flow is spent, which the manager
// signals by the absence of oidc.ErrFlowUnspent on its error. On success the
// login is conveyed by the consumer's CallbackSuccess when there is one, or by
// a handoff code on a redirect to the allowlist-resolved destination. No
// session is created here. Every error is returned, never written.
func (i *oidcInterceptor) callback(ex *Exchange, provider string) error {
	// Checked first, so a path naming no registered provider is not found
	// whatever else the request carries, and every name logged below is one
	// the consumer registered rather than one a client typed.
	if !slices.Contains(i.manager.Providers(), provider) {
		return oidc.ErrUnknownProvider
	}

	handle, _ := ex.Request.Cookie(i.cookieName)

	// RFC 6749 §3.1 forbids sending a parameter twice. A repeated code, state
	// or error is refused outright rather than judged by whichever value comes
	// first, so a forged value cannot ride beside a genuine one.
	if repeatedQuery(ex.Request, "code", "state", "error") {
		i.logCallbackRefusal(ex, slog.LevelWarn, callbackReasonInvalidState, provider)

		return oidc.ErrInvalidState
	}

	if ex.Request.Query("error") != "" {
		return i.providerError(ex, provider, handle)
	}

	code, state := ex.Request.Query("code"), ex.Request.Query("state")
	if handle == "" || code == "" || state == "" {
		i.logCallbackRefusal(ex, slog.LevelWarn, callbackReasonInvalidState, provider)

		return oidc.ErrInvalidState
	}

	res, err := i.manager.Callback(ex.Context(), provider, code, state, handle)
	if !errors.Is(err, oidc.ErrFlowUnspent) {
		i.clearFlowCookie(ex)
	}

	if err != nil {
		i.logCallbackFailure(ex, provider, err)

		return err
	}

	// The destination the client asked for when the login started is untrusted
	// until it is resolved here, at use.
	next := i.redirects.Resolve(res.Next)

	if i.callbackSuccess != nil {
		return i.callbackSuccess(ex, res, next)
	}

	return i.conveyHandoff(ex, provider, res, next)
}

// providerError answers the error branch of the callback.
//
// The flow is ended only when the echoed state completes it, and only then is
// the cookie cleared and the provider's error text logged: an error link
// carrying no state, or a wrong one, changes nothing, so it cannot cancel
// someone else's login or write text of its choosing into the log. Either way
// the answer is an invalid state; the provider's text is never returned.
func (i *oidcInterceptor) providerError(ex *Exchange, provider, handle string) error {
	state := ex.Request.Query("state")
	if handle == "" || state == "" {
		i.logCallbackRefusal(ex, slog.LevelWarn, callbackReasonUnboundError, provider)

		return oidc.ErrInvalidState
	}

	ended, err := i.manager.AbortFlow(ex.Context(), provider, state, handle)
	if err != nil {
		// A store fault, which the manager has already logged.
		return err
	}

	if !ended {
		i.logCallbackRefusal(ex, slog.LevelWarn, callbackReasonUnboundError, provider)

		return oidc.ErrInvalidState
	}

	i.clearFlowCookie(ex)
	i.logCallbackRefusal(ex, slog.LevelInfo, callbackReasonProviderError, provider,
		slog.String("provider_error", boundedText(ex.Request.Query("error"))),
		slog.String("provider_error_description", boundedText(ex.Request.Query("error_description"))))

	return oidc.ErrInvalidState
}

// conveyHandoff issues a handoff code for the completed login and redirects the
// browser to next with the code set on it.
//
// The code is set with url.Values.Set, so a destination that already carries a
// parameter of that name cannot smuggle a second value beside it. Adding it
// normalises the allowlisted destination's query: it is re-encoded with its
// keys sorted, so the Location may differ textually from the configured entry
// while carrying the same parameters and values. The redirect
// is not cached and sends no referrer, because the URL carries a live
// credential.
func (i *oidcInterceptor) conveyHandoff(ex *Exchange, provider string, res oidc.CallbackResult, next string) error {
	code, err := i.handoffs.Issue(ex.Context(), res)
	if err != nil {
		i.logCallbackRefusal(ex, slog.LevelError, callbackReasonIssueFailed, provider,
			slog.String("error", err.Error()))

		return err
	}

	target, err := url.Parse(next)
	if err != nil {
		// Resolve only returns configured entries, each of which parsed at
		// construction, or "/": this is unreachable short of a broken
		// allowlist, and the safe landing is the root.
		target = &url.URL{Path: "/"}
	}

	values := target.Query()
	values.Set(DefaultOIDCHandoffParam, code)
	target.RawQuery = values.Encode()

	ex.Writer.SetHeader("Referrer-Policy", "no-referrer")
	ex.Writer.SetHeader("Cache-Control", "no-store")
	ex.Writer.SetHeader("Location", target.String())
	ex.Writer.WriteHeader(http.StatusFound)

	return nil
}

// repeatedQuery reports whether any of the named query parameters was sent
// more than once.
func repeatedQuery(r Request, names ...string) bool {
	for _, name := range names {
		if len(r.QueryValues(name)) > 1 {
			return true
		}
	}

	return false
}

// clearFlowCookie deletes the flow cookie, with the attributes it was set with
// so every browser matches it.
func (i *oidcInterceptor) clearFlowCookie(ex *Exchange) {
	ex.Writer.SetCookie(&Cookie{
		Name:     i.cookieName,
		Value:    "",
		Path:     i.callbackPath,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// logCallbackFailure logs a failed Callback the manager did not log itself.
//
// The manager logs an invalid ID token, a flow store fault, a failed exchange
// or discovery and the broker's own refusals, so those are left alone. A plain
// invalid state and an unlinked identity are recorded here.
func (i *oidcInterceptor) logCallbackFailure(ex *Exchange, provider string, err error) {
	switch {
	case errors.Is(err, oidc.ErrInvalidState):
		i.logCallbackRefusal(ex, slog.LevelWarn, callbackReasonInvalidState, provider)
	case errors.Is(err, oidc.ErrNoLinkedAccount):
		i.logCallbackRefusal(ex, slog.LevelInfo, callbackReasonNotLinked, provider)
	}
}

// logCallbackRefusal writes one sampled record through the chain's sampler,
// keyed by the callback flow and reason.
//
// The provider is always a registered provider's name, never an arbitrary
// path segment, and is written as an attribute, not into the key, so the keys
// stay bounded. No record carries a code, a state, a handle or a token.
func (i *oidcInterceptor) logCallbackRefusal(
	ex *Exchange, level slog.Level, reason, provider string, attrs ...slog.Attr,
) {
	attrs = append([]slog.Attr{
		slog.String("flow", oidcCallbackFlow),
		slog.String("reason", reason),
		slog.String("provider", provider),
	}, attrs...)

	logSampled(ex.Context(), i.sampler, i.log, level, i.now(),
		oidcCallbackFlow+sampleKeySeparator+reason, "httpsec: oidc callback refused", attrs...)
}

// boundedText cuts s to maxLoggedProviderError bytes and replaces any invalid
// UTF-8, including a character the cut split.
func boundedText(s string) string {
	if len(s) > maxLoggedProviderError {
		s = s[:maxLoggedProviderError]
	}

	return strings.ToValidUTF8(s, "\uFFFD")
}
