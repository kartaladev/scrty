// Package porterr keeps a hostile error returned by a consumer's port from
// travelling into the library.
//
// A port (a session store, a rate limiter, an authenticator, a login or
// recovery store) is the consumer's code, and so is every error it returns.
// The library promises that inspecting an error it is handed never hangs,
// crashes or panics, but stdlib errors.Is and errors.As have no bound and no
// recovery: a cycle loops forever or overflows the stack, a join that fans
// out takes seconds, and a panicking Unwrap escapes. [Sanitize] stands where
// a port's error enters a flow, so that every check behind it reads only an
// error whose chain is known to be finite and within budget.
//
// The package is internal because it is a rule the library applies to itself,
// not an API consumers need.
package porterr

import (
	"context"
	"errors"
	"log/slog"

	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/errwalk"
)

// MsgClassificationAborted is the message of the record Sanitize writes for a
// walk it aborted. It is the text every other aborted classification in the
// library writes, so one search finds every such record.
const MsgClassificationAborted = "httpsec: error classification aborted"

// faultText is a Fault's whole text. It quotes nothing of the consumer's.
const faultText = "scrty: a dependency returned an error that could not be inspected"

// walkBuffer is how many nodes of a chain Sanitize's walk holds on its own
// stack. A chain that fits is walked without a heap allocation.
const walkBuffer = 16

// ErrUnwalkable is the sentinel a call site passes to [Sanitize] as
// unavailable when its port has no unavailable sentinel of its own, such as
// the session Store, the UserLoader reload path or apikey.Store management.
// The fault then matches no library refusal, so the site's catch-all branch
// answers it as a dependency failure. Every [Fault] matches it, whatever
// unavailable it was built with, so a flow can ask whether an error came from
// an uninspectable port error. It is named after prblm's ErrUnwalkableError.
var ErrUnwalkable = errors.New("scrty: a dependency returned an error that could not be inspected")

// Fault is the error [Sanitize] returns in place of a port's error whose chain
// could not be walked. Its text is fixed. It unwraps to the port's unavailable
// sentinel only, so errors.Is and errors.As match it as they match that
// sentinel, and it also matches [ErrUnwalkable] through its Is method. It
// reaches nothing of the consumer's error: not its text, its
// chain or its methods. It carries the walk's abort, for a caller that needs
// the reason or the panic's frames.
//
// Only Sanitize builds one. No fmt verb prints more than its text.
type Fault struct {
	unavailable error
	abort       error
}

// Error returns fixed text, never the consumer's.
func (*Fault) Error() string { return faultText }

// GoString returns the fixed text, so %#v prints it rather than the fault's
// fields, whose abort can hold a consumer's panic value.
func (*Fault) GoString() string { return faultText }

// Unwrap returns the port's unavailable sentinel the fault stands for. A nil
// fault unwraps to nothing.
func (f *Fault) Unwrap() error {
	if f == nil {
		return nil
	}

	return f.unavailable
}

// Is reports whether target is [ErrUnwalkable]. It is how every fault matches
// that sentinel besides the unavailable one it unwraps to, so the fault's
// chain stays the two links it always was, and a fault built with
// ErrUnwalkable as its unavailable sentinel has no second entry for it. Is
// reads only the identity of target.
func (*Fault) Is(target error) bool { return target == ErrUnwalkable } //nolint:errorlint // identity of a sentinel

// Abort returns the walk's abort: an error errwalk.Reason names "budget" or
// "panic", and for a panic an *errwalk.PanicError with the frames captured
// where it panicked. A nil fault has none.
func (f *Fault) Abort() error {
	if f == nil {
		return nil
	}

	return f.abort
}

// Sanitize walks err once with the library's bounded, recovering walk
// (internal/errwalk) and returns:
//
//   - nil, when err is nil;
//   - err itself, the same value, when the walk reads its chain to the end.
//     Checks downstream may then use stdlib errors.Is and errors.As on it,
//     since its chain has just been shown finite and within budget;
//   - otherwise a new *[Fault], when the walk aborts: a cycle, a fan-out or a
//     huge Unwrap() []error past the walk's budget, or an Unwrap that panics,
//     panic(nil) included. The fault matches unavailable through errors.Is,
//     so the flow takes its existing branch for a failing port.
//
// An aborted walk writes exactly one Error record to slog.Default(), with the
// message [MsgClassificationAborted], the reason ("budget" or "panic") and,
// for a panic, its Go type and the frames where it panicked, never the panic's
// value or the error's text. A walk that completes writes nothing. Sanitize
// has no options: the default logger is the consumer's to route, through
// slog.SetDefault. A caller that holds a request context or its own logger
// uses [SanitizeTo]; Sanitize is SanitizeTo with context.Background() and the
// default logger. A fault handed to Sanitize again passes through, with no
// second record.
//
// unavailable is the port's own unavailable sentinel, a package-level value at
// every call site. A nil one is a wiring mistake: Sanitize panics on every
// call, a nil err included, so the mistake fails the first test that reaches
// the call site rather than waiting for a hostile error.
//
// The accepted limit: the walk calls Unwrap only, never Is or As. An error
// whose Is or As method panics, or panics only when asked about one
// particular sentinel, passes through unchanged, and panics later at the
// stdlib check that asks it. net/http recovers that panic per request, so it
// neither hangs nor crashes the process.
//
// Sanitize keeps no state and is safe for concurrent use. A chain that fits
// its stack buffer is walked without a heap allocation.
func Sanitize(err, unavailable error) error {
	return SanitizeTo(context.Background(), nil, err, unavailable)
}

// SanitizeTo is [Sanitize] with the destination of the abort record chosen by
// the caller: the one record goes to logger, handed ctx, so a handler that
// reads the context (a request id, a trace) tags it. A nil logger is
// slog.Default(), the one Sanitize writes to. A nil ctx is
// context.Background(): a logging path does not panic over it. Everything else
// is as for Sanitize, including that a nil unavailable panics on every call
// and that a walk that completes writes nothing.
//
// A cancelled ctx does not stop the record: slog hands it to the handler, and
// the record is written unless the handler itself drops it. A handler that
// panics is the consumer's own code: its panic escapes SanitizeTo, as it would
// escape any slog call, and is not recovered. SanitizeTo keeps no state and is
// safe for concurrent use as far as logger is.
func SanitizeTo(ctx context.Context, logger *slog.Logger, err, unavailable error) error {
	if unavailable == nil {
		panic("porterr: Sanitize needs the port's unavailable sentinel, got nil")
	}

	if err == nil {
		return nil
	}

	var buf [walkBuffer]error

	_, abort := errwalk.FlattenInto(buf[:], err)
	if abort == nil {
		return err
	}

	report(ctx, logger, abort)

	return &Fault{unavailable: unavailable, abort: abort}
}

// report writes the one record of an aborted walk to logger, or to
// slog.Default() when logger is nil, with ctx, or context.Background() when
// ctx is nil. Nothing is read from abort but its type, a panic's captured
// frames and the Go type of its recovered value.
func report(ctx context.Context, logger *slog.Logger, abort error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if logger == nil {
		logger = slog.Default()
	}

	attrs := []slog.Attr{slog.String("reason", errwalk.Reason(abort))}

	if p, ok := abort.(*errwalk.PanicError); ok && p != nil { //nolint:errorlint // errwalk's own value, never wrapped
		attrs = append(attrs, diag.PanicAttrsFrom(p.Value, p.Frames)...)
	}

	logger.LogAttrs(ctx, slog.LevelError, MsgClassificationAborted, attrs...)
}
