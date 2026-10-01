package recovery

//go:generate mockgen -destination=sender_mock_test.go -package=recovery_test -typed github.com/kartaladev/scrty/notify Sender,NonBlocking

import (
	"context"
	"errors"
	"log/slog"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/notify"
)

// The messages Start writes. They are constants because a consumer may route
// on them. None carries the username, the address or the code.
const (
	msgStartDisabled      = "recovery: start ignored: issued codes are not enabled"
	msgStartNoUsername    = "recovery: start ignored: no username"
	msgStartUnknown       = "recovery: start ignored: no account for the submitted username"
	msgStartLookupFailed  = "recovery: start failed: the username could not be resolved"
	msgStartInactive      = "recovery: start ignored: the account is not active"
	msgStartNoReference   = "recovery: start failed: the resolved account carries no user reference"
	msgStartCountFailed   = "recovery: start failed: issuance count unavailable"
	msgStartLimitReached  = "recovery: start ignored: issuance limit reached"
	msgStartContactFailed = "recovery: start failed: the contact address could not be resolved"
	msgStartIssueFailed   = "recovery: start failed: the code could not be issued"
	msgStartSendFailed    = "recovery: start failed: the code could not be sent"
)

// Start issues a recovery code for username and emails it to the user's
// contact address.
//
// It returns nothing, by design. A code sent, an unknown username, a disabled
// user, a lookup failure, a reached issuance limit, a token store or random
// source failure and a sender that refuses are indistinguishable to the caller,
// so the caller cannot leak the difference to the client even by accident.
// Each cause is logged server-side, and no record carries the username, the
// address or the code.
//
// The code is a one-time token of purpose IssuedCodePurpose whose subject is
// the user reference, valid for the issued-code lifetime and spent only as the
// last step of a recovery that succeeds. With issued codes not enabled, Start
// does nothing.
//
// A small timing difference remains: the issuance count and the token insert
// run only for a username that resolves. The non-blocking sender removes the
// largest part — the delivery — and the rest is stated rather than closed.
func (r *Recoverer) Start(ctx context.Context, username string) {
	if r.issued == nil {
		r.logger.LogAttrs(ctx, slog.LevelDebug, msgStartDisabled)

		return
	}

	details, ok := r.resolveForStart(ctx, username)
	if !ok {
		return
	}

	subject := string(details.ID)

	count, err := r.issued.IssuedCount(ctx, subject)
	if err != nil {
		r.logger.LogAttrs(ctx, slog.LevelError, msgStartCountFailed, diag.Failure("token-count", err)...)

		return
	}
	if count >= r.issuedLimit {
		r.logger.LogAttrs(ctx, slog.LevelDebug, msgStartLimitReached, slog.Int("limit", r.issuedLimit))

		return
	}

	address, err := r.resolver(ctx, details)
	if err != nil {
		r.logger.LogAttrs(ctx, slog.LevelError, msgStartContactFailed, diag.Failure("contact-resolver", err)...)

		return
	}
	if address == "" {
		r.logger.LogAttrs(ctx, slog.LevelError, msgStartContactFailed, slog.String("reason", "contact-resolver"))

		return
	}

	code, tok, err := r.issued.Issue(ctx, subject)
	if err != nil {
		r.logger.LogAttrs(ctx, slog.LevelError, msgStartIssueFailed, diag.Failure("token-issue", err)...)

		return
	}

	subjectLine, body := r.messages.IssuedCode(code, tok.ExpiresAt)

	// The recipient is forced whatever the builder wrote: a builder is for
	// wording, and one that chose the recipient could mail a live code for one
	// account to another address.
	msg := notify.Message{To: address, Subject: subjectLine, TextBody: body}

	if err := r.sender.Send(ctx, msg); err != nil {
		r.logger.LogAttrs(ctx, slog.LevelError, msgStartSendFailed, diag.Failure("sender", err)...)
	}
}

// resolveForStart turns a submitted username into an active user's details,
// or logs why the start goes no further.
func (r *Recoverer) resolveForStart(ctx context.Context, username string) (*identity.Details, bool) {
	if username == "" {
		r.logger.LogAttrs(ctx, slog.LevelDebug, msgStartNoUsername)

		return nil, false
	}

	details, err := r.users.LoadByUsername(ctx, username)

	switch {
	case errors.Is(err, identity.ErrUserNotFound):
		r.logger.LogAttrs(ctx, slog.LevelDebug, msgStartUnknown)
	case err != nil:
		level := slog.LevelError
		if causedByCaller(ctx, err) {
			level = slog.LevelDebug
		}

		r.logger.LogAttrs(ctx, level, msgStartLookupFailed, diag.Failure("user-loader", err)...)
	case details == nil || !details.Active:
		r.logger.LogAttrs(ctx, slog.LevelDebug, msgStartInactive)
	case details.ID == "":
		r.logger.LogAttrs(ctx, slog.LevelError, msgStartNoReference)
	default:
		return details, true
	}

	return nil, false
}
