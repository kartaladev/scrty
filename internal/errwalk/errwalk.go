package errwalk

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
)

// Budget is the most entries Flatten examines. Examining one more aborts the
// walk with an error wrapping ErrBudget.
const Budget = 1000

var (
	// ErrBudget is wrapped by the abort Flatten returns when a walk would
	// examine more than Budget entries, nil entries and repeats included.
	ErrBudget = errors.New("errwalk: walk budget exhausted")

	// ErrPanic is what a *PanicError unwraps to.
	ErrPanic = errors.New("errwalk: panic during walk")
)

// budgetError is the abort for an exhausted budget. It is unexported so that
// Reason can recognise this package's aborts by type.
type budgetError struct{}

func (budgetError) Error() string {
	return fmt.Sprintf("%v: more than %d entries", ErrBudget, Budget)
}

func (budgetError) Unwrap() error { return ErrBudget }

// PanicError is the abort returned when a node's Unwrap, Is or As method, or a
// comparison with the target, panics. Value holds the recovered value, which
// is nil for panic(nil) under GODEBUG=panicnil=1. Error returns fixed text
// that never includes Value, so the abort is safe to log; a caller that
// reports Value redacts it itself.
type PanicError struct{ Value any }

// Error returns fixed text, without the recovered value.
func (*PanicError) Error() string { return "errwalk: panic during walk" }

// Unwrap returns ErrPanic.
func (*PanicError) Unwrap() error { return ErrPanic }

// Chain is a flattened error chain, in walk order. It holds no nil interface
// and no nil pointer.
type Chain []error

// Flatten walks err once and returns its nodes in the order errors.Is and
// errors.As visit them. The abort is nil, wraps ErrBudget, or is a
// *PanicError; on an abort the Chain is nil. A nil err, or a nil pointer err,
// gives an empty Chain and no abort. See the package doc for the rules.
func Flatten(err error) (Chain, error) {
	var (
		chain Chain
		// stack holds the entries not yet examined, nil entries included.
		stack    = []error{err}
		examined int
	)

	for len(stack) > 0 {
		node := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		examined++

		if node == nil || isNilPointer(node) {
			continue
		}

		chain = append(chain, node)

		switch u := node.(type) {
		case interface{ Unwrap() error }:
			next, abort := recovering(u.Unwrap)
			if abort != nil {
				return nil, abort
			}

			if next == nil {
				continue
			}

			if examined+len(stack)+1 > Budget {
				return nil, budgetError{}
			}

			stack = append(stack, next)
		case interface{ Unwrap() []error }:
			kids, abort := recovering(u.Unwrap)
			if abort != nil {
				return nil, abort
			}

			// Every pending entry is examined later and counts 1, so the
			// walk is over budget as soon as the pending ones would be.
			if examined+len(stack)+len(kids) > Budget {
				return nil, budgetError{}
			}

			// Pushed in reverse, so they pop in slice order.
			for _, kid := range slices.Backward(kids) {
				stack = append(stack, kid)
			}
		}
	}

	return chain, nil
}

// Is reports whether a node of c matches target, scanning c in order: by ==
// when target's type is comparable, or by the node's own Is(error) bool
// method. A panicking Is method, or a == that panics, aborts with a
// *PanicError. A nil target matches nothing, since a Chain holds no nil.
func Is(c Chain, target error) (bool, error) {
	if target == nil {
		return false, nil
	}

	comparable := reflect.TypeOf(target).Comparable()

	for _, node := range c {
		if comparable {
			eq, abort := recovering(func() bool { return node == target })
			if abort != nil {
				return false, abort
			}

			if eq {
				return true, nil
			}
		}

		if x, ok := node.(interface{ Is(error) bool }); ok {
			matched, abort := recovering(func() bool { return x.Is(target) })
			if abort != nil {
				return false, abort
			}

			if matched {
				return true, nil
			}
		}
	}

	return false, nil
}

// As returns the first node of c, in order, that is a T: by type assertion,
// or through the node's own As(any) bool method with a *T target. For a
// pointer or interface T, a nil result is no match, and the scan continues. A
// panicking As method aborts with a *PanicError.
func As[T error](c Chain) (T, bool, error) {
	var zero T

	for _, node := range c {
		if v, ok := node.(T); ok && !isNil(v) {
			return v, true, nil
		}

		if x, ok := node.(interface{ As(any) bool }); ok {
			var v T

			matched, abort := recovering(func() bool { return x.As(&v) })
			if abort != nil {
				return zero, false, abort
			}

			if matched && !isNil(v) {
				return v, true, nil
			}
		}
	}

	return zero, false, nil
}

// Reason names an abort for reporting: "budget", "panic", or "" for a nil
// error or any error this package did not return. It recognises aborts by
// type and calls no method of a foreign error.
func Reason(abort error) string {
	switch abort.(type) {
	case budgetError:
		return "budget"
	case *PanicError:
		return "panic"
	default:
		return ""
	}
}

// recovering calls f and turns a panic into a *PanicError. It tells a panic
// from a return with a flag, because recover returns nil for panic(nil) under
// GODEBUG=panicnil=1.
func recovering[R any](f func() R) (r R, abort error) {
	done := false

	defer func() {
		if v := recover(); !done {
			abort = &PanicError{Value: v}
		}
	}()

	r = f()
	done = true

	return r, nil
}

// isNilPointer reports whether err's dynamic value is a nil pointer. Nil maps,
// slices, funcs and chans are deliberately not reported.
func isNilPointer(err error) bool {
	v := reflect.ValueOf(err)

	return v.Kind() == reflect.Pointer && v.IsNil()
}

// isNil reports whether v is a nil interface or a nil pointer.
func isNil(v error) bool {
	return v == nil || isNilPointer(v)
}
