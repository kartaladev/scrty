package httpsec

import (
	"context"
	"errors"
	"log/slog"
	"net/url"

	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/hangup"
	"github.com/kartaladev/scrty/oidcprovider"
)

// parkedFailureConfig is what WithOIDCLoginErrorParam and WithOIDCFailToClient set.
type parkedFailureConfig struct {
	// param names the code on the login page's query.
	param string
	// paramSet records that WithOIDCLoginErrorParam was given, which needs completion.
	paramSet bool
	// toClient ends the parked request and answers the client instead.
	toClient bool
}

// parkedFailureCode is the code a callback's failure returns to the login page
// with, and false for a failure that keeps its answer.
func parkedFailureCode(f callbackFailure) (string, bool) {
	return f.code, f.code != ""
}

// completionStage names where completion refused, which decides its code: a
// consumer's denial reason or a store's failure can be any error, so the code is
// read from where it arose, not from its value.
type completionStage uint8

const (
	// completionStageUser is loading the user: the bare oidc.ErrInvalidHandoff
	// refuses, anything else is the loader failing.
	completionStageUser completionStage = iota + 1
	// completionStageRefusal is a post-authentication or per-request denial.
	completionStageRefusal
	// completionStageSession is storing the session.
	completionStageSession
)

// completionFailureCode is the code completion's refusal err at stage returns to
// the login page with (D4), and false for one that keeps its answer: no error,
// an unnamed stage, a walk that aborted, a hung-up caller, and completion's own
// transport, throttle, unknown-handle and re-authentication refusals.
func completionFailureCode(ctx context.Context, stage completionStage, err error) (string, bool) {
	if err == nil {
		return "", false
	}

	walk := walkRefusal(err)
	if walk.is(ErrOIDCUnknownHandle, ErrOIDCThrottled, ErrOIDCReauthenticate) || walk.abort != nil {
		return "", false
	}

	if hungUp, abort := hangup.ByCallerWalk(ctx, err); hungUp || abort != nil {
		return "", false
	}

	switch stage {
	case completionStageUser:
		// A refused user is the bare sentinel (loadCompleting); a loader's
		// failure is wrapped, and may carry any value, the sentinel included.
		if err == oidc.ErrInvalidHandoff { //nolint:errorlint // identity: a wrapped sentinel is the loader's failure
			return oidcprovider.CodeAccessDenied, true
		}

		return oidcprovider.CodeServerError, true
	case completionStageRefusal:
		return oidcprovider.CodeAccessDenied, true
	case completionStageSession:
		return oidcprovider.CodeServerError, true
	default:
		return "", false
	}
}

// oidcStartFlow keys the records of a federated login's start.
const oidcStartFlow = "oidc.authorize"

// parkedSite is where a failed login for a parked request is answered from: the
// flow and message its records carry.
type parkedSite struct{ flow, msg string }

var (
	parkedAtStart    = parkedSite{flow: oidcStartFlow, msg: "httpsec: oidc login start refused"}
	parkedAtCallback = parkedSite{flow: oidcCallbackFlow, msg: msgCallbackRefused}
)

// The reasons the records of a failed parked login are keyed by. None carries a
// handle, a state, a flow secret or a redirect target.
const (
	// parkedReasonReturned: returned to the login page, with the code.
	parkedReasonReturned = "parked-returned"
	// parkedReasonAnswered: the request was ended and the client answered, with the code.
	parkedReasonAnswered = "parked-answered"
	// parkedReasonNotEnded: the request could not be ended; the original error is answered.
	parkedReasonNotEnded = "parked-not-ended"
	// parkedReasonUnchecked: the request could not be checked; the original error is answered.
	parkedReasonUnchecked = "parked-unchecked"
)

// errParkedNotAnswered stands for an end that succeeded without an answer for
// the client, in the record of it.
var errParkedNotAnswered = errors.New("httpsec: the parked request was ended without an answer for the client")

// returnParked answers original, a failed login for the parked request handle,
// met at site (D3).
//
// It first runs completion's checks (precheckParked, D6). A request failing them
// gets original, unchanged, with no redirect; a store that cannot answer is
// recorded once at ERROR. A request expired within its grace window has been
// answered at the client, and the browser is sent there (D7). Otherwise the
// browser is sent by 303 to the provider's configured login URL carrying the
// handle and code, never anywhere the request names; under WithOIDCFailToClient
// the request is ended with code and the browser sent to the client instead
// (a device request has no client to answer, and still returns to the login page),
// and an end that fails is recorded once at ERROR and answered with original
// (F7). code must be one of D4's.
func (i *oidcInterceptor) returnParked(ex *Exchange, site parkedSite, provider, handle, code string, original error) error {
	_, err := i.returnParkedAnswering(ex, site, provider, handle, code, original)

	return err
}

// returnParkedAnswering is returnParked, also reporting the code the browser was
// answered with: empty when original is returned with no redirect, otherwise the
// code of the redirect, which an expired request or an end may have changed from
// the one asked for.
func (i *oidcInterceptor) returnParkedAnswering(
	ex *Exchange, site parkedSite, provider, handle, code string, original error,
) (string, error) {
	if !ex.Request.Secure() && !i.provider.plainHTTPAllowed() {
		return "", original
	}

	check := i.precheckParked(ex, provider, handle)
	if check.err != nil {
		// A caller that hung up cut the check short: nothing failed that anyone
		// can fix, so no record.
		if check.failure && ex.Context().Err() == nil {
			i.logParkedRecord(ex, site, slog.LevelError, parkedReasonUnchecked, provider,
				diag.Failure(parkedReasonUnchecked, check.err)...)
		}

		return "", original
	}

	if check.answeredAt != "" {
		i.answerParkedAtClient(ex, site, provider, oidcprovider.CodeAccessDenied, check.answeredAt)

		return oidcprovider.CodeAccessDenied, nil
	}

	// A device request has no client redirect URI to answer at, and EndPending refuses it.
	if i.parked.toClient && !check.device {
		return i.endParked(ex, site, provider, handle, code, original)
	}

	target := *i.loginURL
	target.RawQuery = oidcprovider.HandleParam + "=" + url.QueryEscape(handle) + "&" + i.parked.param + "=" + code

	i.logParkedRecord(ex, site, slog.LevelInfo, parkedReasonReturned, provider,
		slog.String("reason", parkedReasonReturned), slog.String("code", code))

	redirectCompleted(ex, target.String())

	return code, nil
}

// endParked is WithOIDCFailToClient's answer: the parked request is ended with
// code and the browser sent to the client's redirect URI; the record names the
// code the client received, which the end may have changed. An end that fails, or
// that names no answer for the client, is recorded once at ERROR by its Go type,
// and original is returned (F7).
func (i *oidcInterceptor) endParked(ex *Exchange, site parkedSite, provider, handle, code string, original error) (string, error) {
	op := i.provider
	flow, _ := ex.Request.Cookie(oidcCookieName(op.provider, OIDCFlowCookie))

	res, err := op.provider.EndPending(ex.Context(), oidcprovider.EndPendingInput{
		Handle: handle, FlowSecret: flow, Code: code,
	})

	target, ok := answeredAtClient(res)
	if err != nil || !ok {
		if err == nil {
			err = errParkedNotAnswered
		}

		i.logParkedRecord(ex, site, slog.LevelError, parkedReasonNotEnded, provider,
			diag.Failure(parkedReasonNotEnded, err)...)

		return "", original
	}

	answered := answeredCode(target, code)
	i.answerParkedAtClient(ex, site, provider, answered, target)

	return answered, nil
}

// answeredCode is the code the client's error response at target carries: the end
// answers its own when it is not the one asked for (access_denied within the grace
// window, unauthorized_client or invalid_scope after a rejudge). asked stands when
// target names none.
func answeredCode(target, asked string) string {
	u, err := url.Parse(target)
	if err != nil {
		return asked
	}

	if code := u.Query().Get("error"); code != "" {
		return code
	}

	return asked
}

// answeredAtClient reports where res, an ended parked request, answered the
// client: only the client's error response, with a target, counts.
func answeredAtClient(res oidcprovider.ResumeResult) (string, bool) {
	if res.Outcome != oidcprovider.ResumeOutcomeClientError || res.RedirectTo == "" {
		return "", false
	}

	return res.RedirectTo, true
}

// answerParkedAtClient sends the browser to target, where ending a parked request
// answered the client with code, and records the code.
func (i *oidcInterceptor) answerParkedAtClient(ex *Exchange, site parkedSite, provider, code, target string) {
	i.logParkedRecord(ex, site, slog.LevelInfo, parkedReasonAnswered, provider,
		slog.String("reason", parkedReasonAnswered), slog.String("code", code))

	redirectCompleted(ex, target)
}

// logParkedRecord writes one sampled record of a failed parked login met at
// site, keyed by reason; attrs carry the reason themselves.
func (i *oidcInterceptor) logParkedRecord(
	ex *Exchange, site parkedSite, level slog.Level, reason, provider string, attrs ...slog.Attr,
) {
	i.logLoginRecord(ex, site.flow, site.msg, level, reason, provider, attrs...)
}

// parkedCheck is what precheckParked found of a parked request: live at its login
// stage, and answering no device authorization, when every field is zero.
type parkedCheck struct {
	// answeredAt is where a request expired within its grace window was answered.
	answeredAt string
	// err refuses the request; failure says it is a dependency's, not a refusal.
	err     error
	failure bool
	// device says the request answers a device authorization, which has no client
	// redirect URI.
	device bool
}

// parkedDestination reports the handle next names when completion is on and next
// is the provider's login URL carrying one parked request's handle (parkedHandle).
func (i *oidcInterceptor) parkedDestination(next string) (string, bool) {
	if !i.completion {
		return "", false
	}

	return parkedHandle(next, i.loginURL)
}

// startFailureCode is the code a login start's failure returns to the login page
// with: temporarily_unavailable for a provider that cannot be discovered, and
// false for anything else, a walk that aborted and a hung-up caller included.
func startFailureCode(ctx context.Context, err error) (string, bool) {
	if err == nil {
		return "", false
	}

	walk := walkRefusal(err)
	if !walk.is(oidc.ErrDiscoveryFailed) {
		return "", false
	}

	if hungUp, abort := hangup.ByCallerWalk(ctx, err); hungUp || abort != nil {
		return "", false
	}

	return oidcprovider.CodeTemporarilyUnavailable, true
}
