package httpsec

import (
	"context"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/hangup"
	"github.com/kartaladev/scrty/oidcprovider"
)

//go:generate mockgen -destination=flowstore_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/authenticate/oidc FlowStore

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
// With completion on, a provider that cannot be discovered for a login whose
// destination is a parked request's login page returns there instead
// (returnParked), with temporarily_unavailable.
func (i *oidcInterceptor) authorize(ex *Exchange, provider string) error {
	next := ex.Request.Query(DefaultOIDCNextParam)

	auth, err := i.manager.Authorize(ex.Context(), provider, next)
	if err != nil {
		// A parked request's login page is told its provider cannot be reached
		// (D3). No flow was stored, so no cookie is set.
		if handle, ok := i.parkedDestination(next); ok {
			if code, ok := startFailureCode(ex.Context(), err); ok {
				return i.returnParked(ex, parkedAtStart, provider, handle, code, err)
			}
		}

		return err
	}

	ex.Writer.SetCookie(&Cookie{
		Name:     i.cookieName,
		Value:    auth.Handle,
		Path:     i.callbackPath.at(),
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
	callbackReasonIssueFailed   = "handoff-issue"
	callbackReasonServerError   = "server-error"
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
// a handoff code on a redirect to the allowlist-resolved destination. With
// WithOIDCProviderCompletion, a login whose destination is the provider's login
// page carrying one parked request's handle is completed on the server instead
// (completeProviderSignIn); every other login is conveyed as without it. Every
// error is returned, never written, except a mapped failure (D4) of a login
// whose stored destination is a parked request's login page, which returns
// there instead (returnParked).
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

	// The failure may be the consumer's broker's, so it is read once,
	// through the bounded walk (readCallbackFailure). One the walk gives up
	// on ends the flow, logs and reports nothing of its own, and its abort is
	// reported as the quiet sites report one (reportQuietly).
	failure := readCallbackFailure(ex.Context(), err)
	if !failure.flowUnspent {
		i.clearFlowCookie(ex)
	}

	if err != nil {
		if failure.abort != nil {
			ex.answeringChain().reportQuietly(ex.Context(), err, failure.abort)

			return err
		}

		i.logCallbackFailure(ex, provider, failure)
		emitCallbackRefused(ex.Context(), failure)

		// A mapped failure of a login for a parked request returns to the login
		// page (D3). res.Next is read from the stored flow, never from err (D5).
		if code, ok := parkedFailureCode(failure); ok {
			if handle, ok := i.parkedDestination(res.Next); ok {
				answered, perr := i.returnParkedAnswering(ex, parkedAtCallback, provider, handle, code, err)

				// A server_error answer hides the fault behind a redirect, so it
				// is logged here (D7), once it is committed: a return that failed
				// answered the original error and has its own record. The record
				// holds the reason and the cause's type, never the handle, state,
				// redirect target or error text.
				if perr == nil && answered == oidcprovider.CodeServerError {
					i.logLoginRecord(ex, oidcCallbackFlow, msgCallbackFailed, slog.LevelError,
						callbackReasonServerError, provider, diag.Failure(callbackReasonServerError, err)...)
				}

				return perr
			}
		}

		return err
	}

	// With completion on, a login started from the provider's login page for a
	// parked request is completed here (D7). The destination is recognised
	// exactly, before the allowlist sees it: it is the carve-out from the
	// allowlist, and anything short of it is conveyed as any other login.
	if handle, ok := i.parkedDestination(res.Next); ok {
		return i.completeProviderSignIn(ex, provider, res, handle)
	}

	// The destination the client asked for when the login started is untrusted
	// until it is resolved here, at use.
	next := i.redirects.Resolve(res.Next)

	if i.callbackSuccess != nil {
		return i.callbackSuccess(ex, res, next)
	}

	return i.conveyHandoff(ex, provider, res, next)
}

// emitCallbackRefused reports err, a callback's failure, as
// event.AuthnLoginFail when it refuses the external identity the provider
// asserted: an ID token that failed verification (oidc.ErrInvalidIDToken), an
// identity linked to no account (oidc.ErrNoLinkedAccount), or one whose
// provisioning was refused (oidc.ErrProvisioningRefused). An error that is
// both a refusal and an outage counts as the refusal, as callbackCode answers
// it, so the failed login is always recorded. A provider that could not be
// reached (oidc.ErrExchangeFailed, oidc.ErrDiscoveryFailed,
// oidc.ErrUserInfoFailed) on its own, a
// flow store fault, an invalid state, which is a forged or stale callback
// rather than a login attempt, and a request whose own context ended before
// the verdict report nothing.
//
// failure is the callback's error as readCallbackFailure read it.
func emitCallbackRefused(ctx context.Context, failure callbackFailure) {
	if !failure.refusal || failure.hungUp {
		return
	}

	emitEvent(ctx, userEvent(event.AuthnLoginFail, event.OutcomeFailure, "", factor.OIDC))
}

// callbackFailure is a callback's error, read once: what the callback's
// handling asks of it, as errors.Is would answer each question, or the abort
// that stopped the walk, when every answer is false.
type callbackFailure struct {
	// flowUnspent is set when the manager left the flow unspent
	// (oidc.ErrFlowUnspent), so the flow cookie is kept.
	flowUnspent bool

	// invalidState and notLinked are the failures the interceptor logs.
	invalidState, notLinked bool

	// refusal and hungUp decide the refusal event (emitCallbackRefused);
	// outage decides the code only when refusal is unset.
	refusal, outage, hungUp bool

	// reauthenticate and unknownProvider are answers the callback keeps plain:
	// a sign-in to repeat is a deliberate answer, and a bare unknown provider
	// names no fault.
	reauthenticate, unknownProvider bool

	// code is the error a parked request's login page is answered with, empty
	// for a failure that keeps its answer (parkedFailureCode).
	code string

	abort error
}

// readCallbackFailure reads err, a callback's failure, through one bounded
// walk, the hang-up check included. A nil err reads as no failure. The
// broker behind the manager is the consumer's, so err may be cyclic, fanned
// out or carry a panicking method; such an err answers false to everything,
// and its abort is returned for the caller to report.
func readCallbackFailure(ctx context.Context, err error) callbackFailure {
	if err == nil {
		return callbackFailure{}
	}

	walk := walkRefusal(err)

	f := callbackFailure{
		flowUnspent:  walk.is(oidc.ErrFlowUnspent),
		invalidState: walk.is(oidc.ErrInvalidState),
		notLinked:    walk.is(oidc.ErrNoLinkedAccount),
		refusal:      walk.is(oidc.ErrInvalidIDToken, oidc.ErrNoLinkedAccount, oidc.ErrProvisioningRefused),
		outage:       walk.is(oidc.ErrExchangeFailed, oidc.ErrDiscoveryFailed, oidc.ErrUserInfoFailed),

		reauthenticate:  walk.is(ErrOIDCReauthenticate),
		unknownProvider: walk.is(oidc.ErrUnknownProvider),
	}

	if walk.abort != nil {
		return callbackFailure{abort: walk.abort}
	}

	hungUp, abort := hangup.ByCallerWalk(ctx, err)
	if abort != nil {
		return callbackFailure{abort: abort}
	}

	f.hungUp = hungUp
	f.code = callbackCode(f)

	return f
}

// callbackCode is D4's allow-list for a callback's failure, with D5's default,
// from the answers of readCallbackFailure's one walk. A failure before the flow
// is spent, an invalid state, a hung-up caller, a sign-in to repeat and a bare
// unknown provider have no code and keep their plain answer. Of the rest, a
// refusal is access_denied (it wins over an outage) and an outage is
// temporarily_unavailable. Anything else after the flow is spent, a broker's or a
// store's unclassified failure, is server_error, which names nothing about the
// account.
func callbackCode(f callbackFailure) string {
	switch {
	case f.flowUnspent, f.invalidState, f.hungUp, f.reauthenticate, f.unknownProvider:
		return ""
	case f.refusal:
		return oidcprovider.CodeAccessDenied
	case f.outage:
		return oidcprovider.CodeTemporarilyUnavailable
	default:
		return oidcprovider.CodeServerError
	}
}

// providerError answers the error branch of the callback.
//
// The flow is ended only when the echoed state completes it, and only then is
// the cookie cleared and the provider's error text logged: an error link
// carrying no state, or a wrong one, changes nothing, so it cannot cancel
// someone else's login or write text of its choosing into the log. Either way
// the answer is an invalid state; the provider's text is never returned. A flow
// store that cannot end the flow is refused with the manager's error, whose
// text is fixed and never the store's. With completion on, an ended flow whose
// destination is a parked request's login page returns there with
// access_denied instead (returnParked).
func (i *oidcInterceptor) providerError(ex *Exchange, provider, handle string) error {
	state := ex.Request.Query("state")
	if handle == "" || state == "" {
		i.logCallbackRefusal(ex, slog.LevelWarn, callbackReasonUnboundError, provider)

		return oidc.ErrInvalidState
	}

	aborted, err := i.manager.AbortFlowNext(ex.Context(), provider, state, handle)
	if err != nil {
		// A store fault, which the manager has already logged.
		return err
	}

	if !aborted.Ended {
		i.logCallbackRefusal(ex, slog.LevelWarn, callbackReasonUnboundError, provider)

		return oidc.ErrInvalidState
	}

	i.clearFlowCookie(ex)
	i.logCallbackRefusal(ex, slog.LevelInfo, callbackReasonProviderError, provider,
		slog.String("provider_error", boundedText(ex.Request.Query("error"))),
		slog.String("provider_error_description", boundedText(ex.Request.Query("error_description"))))

	// Whatever the provider's error, a parked request's login page is told
	// access_denied (D4). aborted.Next is the ended flow's, never the request's.
	if parked, ok := i.parkedDestination(aborted.Next); ok {
		return i.returnParked(ex, parkedAtCallback, provider, parked, oidcprovider.CodeAccessDenied, oidc.ErrInvalidState)
	}

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
//
// A handoff store that refuses to issue the code is recorded by a fixed
// reason and its error's Go type, never its text: a consumer's store may word
// a failure with the row it tried to write. A consumer who wants that detail
// logs it inside their own implementation of oidc.HandoffStore. The error
// returned is the handoff manager's, whose text is fixed too, with the store's
// error still reachable through errors.Is and errors.As.
func (i *oidcInterceptor) conveyHandoff(ex *Exchange, provider string, res oidc.CallbackResult, next string) error {
	code, err := i.handoffs.Issue(ex.Context(), res)
	if err != nil {
		// diag.Failure supplies the reason itself, so the record is written
		// without logCallbackRefusal's own, which would name it twice.
		i.logCallbackRecord(ex, slog.LevelError, callbackReasonIssueFailed, provider,
			diag.Failure(callbackReasonIssueFailed, err)...)

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
		Path:     i.callbackPath.at(),
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
//
// failure is the callback's error as readCallbackFailure read it.
func (i *oidcInterceptor) logCallbackFailure(ex *Exchange, provider string, failure callbackFailure) {
	switch {
	case failure.invalidState:
		i.logCallbackRefusal(ex, slog.LevelWarn, callbackReasonInvalidState, provider)
	case failure.notLinked:
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
	i.logCallbackRecord(ex, level, reason, provider,
		append([]slog.Attr{slog.String("reason", reason)}, attrs...)...)
}

// logCallbackRecord is logCallbackRefusal without the reason attribute: the
// record is still sampled by reason, and attrs must carry the reason
// themselves, as diag.Failure's do.
func (i *oidcInterceptor) logCallbackRecord(
	ex *Exchange, level slog.Level, reason, provider string, attrs ...slog.Attr,
) {
	i.logLoginRecord(ex, oidcCallbackFlow, msgCallbackRefused, level, reason, provider, attrs...)
}

// msgCallbackRefused is the message of the callback's own records.
const msgCallbackRefused = "httpsec: oidc callback refused"

// msgCallbackFailed is the message of the record of a failure answered with
// server_error, which no caller sees as a refusal.
const msgCallbackFailed = "httpsec: oidc callback failed"

// logLoginRecord writes one sampled record with msg, keyed by flow and reason,
// naming flow and provider; attrs must carry the reason themselves.
func (i *oidcInterceptor) logLoginRecord(
	ex *Exchange, flow, msg string, level slog.Level, reason, provider string, attrs ...slog.Attr,
) {
	attrs = append([]slog.Attr{
		slog.String("flow", flow),
		slog.String("provider", provider),
	}, attrs...)

	logSampled(ex.Context(), i.sampler, i.log, level, i.now(), flow+sampleKeySeparator+reason, msg, attrs...)
}

// boundedText cuts s to maxLoggedProviderError bytes and replaces any invalid
// UTF-8, including a character the cut split.
func boundedText(s string) string {
	if len(s) > maxLoggedProviderError {
		s = s[:maxLoggedProviderError]
	}

	return strings.ToValidUTF8(s, "\uFFFD")
}
