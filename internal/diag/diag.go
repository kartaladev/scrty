// Package diag keeps a dependency's error text out of what scrty writes.
//
// The rule it applies: the text of an error returned by a consumer's
// dependency — a store, a loader, a sender, a limiter — never reaches a log
// record or the text of an error the library returns. That text is written by
// code the library does not know, and can quote values the library never saw:
// another column of a row, a server's rewording of an address, a key the
// consumer built. Scrubbing known values out of it cannot be made safe, so the
// library writes fixed text of its own instead.
//
// A record says what failed through [Failure]: a fixed reason and the error's
// Go type. A returned error says it through [Wrap]: fixed text, with the
// library sentinels it stands for and the dependency's error still reachable
// through errors.Is and errors.As, so statuses and a consumer's own matching
// are unchanged.
//
// A consumer who wants the dependency's full error logs it inside their own
// implementation of the port, where they know what its text may contain.
//
// The package is internal because it is a rule the library applies to itself,
// not an API consumers need.
package diag

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"slices"
)

// Failure returns the attributes a log record carries for a failed dependency:
// reason, the fixed word naming what failed; error_type, the error's Go type;
// and cancelled=true when err is or wraps a context cancellation or deadline,
// so an operator can tell a caller hanging up from an outage. It never carries
// err's text.
//
// The type is the outermost one only: a dependency that wraps its error with
// fmt.Errorf is recorded as *fmt.wrapError. The exception is a *[Fault]: when
// err is or wraps one (as errors.As finds it), the type recorded is that of
// the fault's cause, looked through again while the cause is itself a fault.
// A fault's own type says only that the library wrapped a failure, not what
// failed, and whatever wraps a fault adds nothing about the dependency either.
func Failure(reason string, err error) []slog.Attr {
	attrs := []slog.Attr{
		slog.String("reason", reason),
		slog.String("error_type", fmt.Sprintf("%T", causeOf(err))),
	}

	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		attrs = append(attrs, slog.Bool("cancelled", true))
	}

	return attrs
}

// causeOf returns the error whose type a record names: the cause of the
// innermost [Fault] in err's chain, or err itself when it holds no fault. A
// fault built without a cause is its own answer.
func causeOf(err error) error {
	var fault *Fault
	for errors.As(err, &fault) && fault.cause != nil {
		err = fault.cause
	}

	return err
}

// Fault is an error whose text is fixed library text, and which unwraps to the
// library sentinels it stands for and to the dependency's error that caused
// it. A handler that logs it by its text logs no dependency text; one that
// unwraps it and prints the cause prints what the consumer's own dependency
// wrote.
//
// Build it with [Wrap]; a Fault built any other way, the zero value included,
// has empty text and no cause. No fmt verb prints more than its text.
type Fault struct {
	text  string
	kinds []error
	cause error
}

// Error returns the fixed text, never the cause's.
func (f *Fault) Error() string { return f.text }

// GoString returns the fixed text, so %#v prints it rather than the fault's
// fields, which would print a value-typed cause's contents.
func (f *Fault) GoString() string { return f.text }

// Unwrap returns the sentinels the fault stands for, in the order given, then
// the cause. The slice is the caller's own.
func (f *Fault) Unwrap() []error {
	return append(append(make([]error, 0, len(f.kinds)+1), f.kinds...), f.cause)
}

// Wrap returns err with text in place of its own: nil when err is nil; err
// itself when it is exactly one of kinds, since a bare library sentinel
// carries no dependency text; and otherwise a *[Fault] with text, kinds and
// err. kinds are the library sentinels the failure is answered as; an err that
// only wraps one of them is not bare, and gets the fixed text, as does an err
// whose value cannot be compared. The fault keeps its own copy of kinds.
func Wrap(err error, text string, kinds ...error) error {
	if err == nil {
		return nil
	}

	for _, kind := range kinds {
		if same(err, kind) {
			return err
		}
	}

	return &Fault{text: text, kinds: slices.Clone(kinds), cause: err}
}

// same reports whether err is kind itself. It compares only values of one
// dynamic type that are both comparable, so an error type holding a slice, a
// map or a func — directly or through an interface field — is never
// compared and cannot panic; such an error is never taken for a sentinel.
func same(err, kind error) bool {
	if reflect.TypeOf(err) != reflect.TypeOf(kind) {
		return false
	}

	if !reflect.ValueOf(err).Comparable() || !reflect.ValueOf(kind).Comparable() {
		return false
	}

	return err == kind //nolint:errorlint // identity: only a bare sentinel is known to carry no dependency text
}
