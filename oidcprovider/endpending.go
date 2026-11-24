package oidcprovider

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/kartaladev/scrty/pkg/id"
)

// EndPendingInput is what a caller hands EndPending. It holds the handle and the browser's
// flow secret, so it prints and logs redacted; read its fields to use it.
type EndPendingInput struct {
	// Handle is the pending request's handle, from the consumer's page.
	Handle string

	// FlowSecret is the value of the browser's flow cookie.
	FlowSecret string

	// Code is the error the client is answered with.
	Code string
}

// Format writes the redacted form under every verb.
func (EndPendingInput) Format(state fmt.State, _ rune) { _, _ = state.Write([]byte(redacted)) }

// LogValue is the redacted form.
func (EndPendingInput) LogValue() slog.Value { return slog.StringValue(redacted) }

// EndPending ends a parked login-stage request by answering the client's redirect URI with
// error in.Code, the request's state and iss. The result's Outcome is ResumeOutcomeClientError.
//
// in.Code must be CodeAccessDenied, CodeTemporarilyUnavailable or CodeServerError, or it fails
// matching ErrConfig before the request is read. A request expired within the grace window
// (WithPendingRequestGrace) is answered with CodeAccessDenied whatever in.Code says. When the
// client changed since the request was parked, the answer may carry CodeUnauthorizedClient or
// CodeInvalidScope instead.
//
// It fails with ErrUnknownHandle, leaving the request as it was, when the handle is unknown,
// expired past the grace window, spent, not bound to the flow secret, at its consent stage, or a
// device request, and likewise when the client was removed or the redirect URI is no longer
// registered. Racing a Resume, one is answered and the other gets ErrUnknownHandle. A failing
// store fails matching ErrDependency and the request stays parked.
//
// Nothing calls it by default; the chain's cancel endpoint and completion do when in use.
func (p *Provider) EndPending(ctx context.Context, in EndPendingInput) (ResumeResult, error) {
	if !endCode(in.Code) {
		return ResumeResult{}, fmt.Errorf("%w: EndPendingInput.Code: must be %s, %s or %s",
			ErrConfig, CodeAccessDenied, CodeTemporarilyUnavailable, CodeServerError)
	}

	r, age, err := p.loadPendingInGrace(ctx, in.Handle, in.FlowSecret)
	if err != nil {
		return ResumeResult{}, err
	}
	// A device request has no redirect URI, so an answer would be a relative Location. The
	// stage is checked here as well as by the spend, so a request at its consent stage costs
	// no client read.
	if r.Stage != StageLogin || r.DeviceAuthorizationID != id.Nil {
		return ResumeResult{}, ErrUnknownHandle
	}

	rc, err := p.client(ctx, r.ClientID)
	switch {
	case errors.Is(err, ErrClientNotFound):
		return ResumeResult{}, ErrUnknownHandle
	case err != nil:
		return ResumeResult{}, err
	}

	judged, _, verdict := rejudge(r, rc)
	switch {
	case age == pendingExpiredInGrace:
		return p.answerExpired(ctx, r, verdict)
	case verdict != rejudgeOK:
		return p.answerVerdict(ctx, r, verdict)
	}
	r = judged

	return p.refuseRequest(ctx, r, StageLogin, in.Code)
}

// endCode reports whether code is one EndPending may end a request with.
func endCode(code string) bool {
	switch code {
	case CodeAccessDenied, CodeTemporarilyUnavailable, CodeServerError:
		return true
	}

	return false
}
