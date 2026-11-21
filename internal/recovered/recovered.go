// Package recovered runs consumer code on a goroutine the library started, so
// that a panic in it cannot take the process down.
//
// net/http recovers a panic per request, but only on the request's own
// goroutine. A goroutine the library starts itself (a refresh flight, a
// rotation loop, a housekeeping cycle) has no such recovery: a consumer's port
// that panics there ends the process. Call is the recovery for those sites.
// Each site wraps only the consumer's call, not the goroutine's whole body, so
// a loop survives a panic and keeps its state.
//
// The package is internal because it is a rule the library applies to itself.
package recovered

import (
	"context"
	"errors"
	"log/slog"

	"github.com/kartaladev/scrty/internal/ctxlog"
	"github.com/kartaladev/scrty/internal/diag"
)

// ErrPanicked is what Call returns when the consumer's code panicked. It is
// fixed text: the panic value, which can quote a secret, is never part of it.
// A site maps it to the site's own outage with errors.Is.
var ErrPanicked = errors.New("recovered: the consumer's code panicked")

// errNilFunc is what Call returns for a nil f. Passing nil is a programming
// error inside the library, not consumer input.
var errNilFunc = errors.New("recovered: no function to call")

// routing is the logger a nil log stands for. It holds no state of its own, so
// one serves every call.
var routing = ctxlog.Routing()

const panicMessage = "consumer code panicked"

// Call runs f and returns f's error unchanged, nil included.
//
// If f panics, Call recovers it, writes exactly one Error-level record and
// returns ErrPanicked. A panic(nil) counts: Call decides by whether f returned,
// not by whether recover found a value, so it holds under GODEBUG=panicnil=1
// too. Call never re-panics: if the logger's own handler panics while writing
// the record, that is swallowed and the result is still ErrPanicked.
//
// The record's message is the constant "consumer code panicked". It carries the
// attribute what (the caller's fixed word for the call being made) and
// diag.PanicAttrs of the value: the value's Go type and the frames where it
// happened, never the value's text.
//
// log is where the record goes. A nil log routes the record: to the logger of
// the chain ctx carries, else to slog.Default() as it is when the record is
// written. A nil ctx is replaced by context.Background() for the record.
//
// A nil f is a programming error in the library. Call refuses it by returning
// an error (which is not ErrPanicked) and writes no record, instead of
// panicking on the library's own goroutine.
//
// Accepted: a call to runtime.Goexit inside f (t.FailNow does one) is not a
// panic, but Call cannot tell it from one by what it sees: f did not return
// and recover() is nil. In the default mode that is Goexit alone; under
// GODEBUG=panicnil=1 a panic(nil) looks the same. In either mode Call writes
// the same one "panicked" record, so a t.FailNow or runtime.Goexit inside f
// writes such a record. The goroutine still exits as Goexit requires, so Call
// returns nothing to its caller.
func Call(ctx context.Context, log *slog.Logger, what string, f func() error) (err error) {
	if f == nil {
		return errNilFunc
	}
	returned := false
	defer func() {
		value := recover()
		if returned {
			return
		}
		// Reached with value == nil for runtime.Goexit, and for panic(nil) under panicnil=1.
		err = ErrPanicked
		report(ctx, log, what, value)
	}()
	err = f()
	returned = true
	return err
}

// report writes the one record. Call's deferred function calls it while the
// panicking stack still exists, so diag.PanicAttrs sees the frames.
func report(ctx context.Context, log *slog.Logger, what string, value any) { //nolint:contextcheck // the caller's ctx is used; only a nil one is replaced, as the record still needs a context
	// A consumer's slog handler can panic too; the guarantee is that Call
	// never re-panics, and there is nowhere left to report this one.
	defer func() { _ = recover() }()
	if ctx == nil {
		ctx = context.Background()
	}
	if log == nil {
		log = routing
	}
	attrs := append([]slog.Attr{slog.String("what", what)}, diag.PanicAttrs(value)...)
	log.LogAttrs(ctx, slog.LevelError, panicMessage, attrs...)
}
