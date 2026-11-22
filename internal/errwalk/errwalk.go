package errwalk

import (
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"slices"
	"sync/atomic"
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
//
// Frames are the program counters of the panicking stack, captured inside the
// deferred recover while that stack still exists, as runtime.Callers gives
// them: the first is runtime.gopanic, or the runtime frame that raised a
// runtime error, and the panicking function follows it. At most FrameLimit
// are kept, innermost first; it is empty when the runtime gave none. Resolve
// them with runtime.CallersFrames.
type PanicError struct {
	Value  any
	Frames []uintptr
}

// FrameLimit bounds the program counters a *PanicError keeps.
const FrameLimit = 32

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
//
// It is FlattenInto with no buffer, so a non-empty Chain is on the heap.
func Flatten(err error) (Chain, error) {
	return FlattenInto(nil, err)
}

// pendingSize is how many entries still to examine FlattenInto holds on its
// own stack before it grows that list onto the heap. A wrap holds 1 at a time,
// and a join as many as it has members, so short chains stay well under it.
const pendingSize = 16

// FlattenInto is Flatten that appends the nodes into buf[:0], and returns
// that slice: a chain that fits cap(buf) takes no heap allocation, and only a
// longer one grows onto the heap, as append grows. Every Flatten rule holds
// unchanged, and on an abort the Chain is nil, not buf.
//
// The walk overwrites buf's elements from index 0, up to the chain's length
// or cap(buf), whichever is less, even when it aborts; whatever buf held is
// ignored. The returned Chain shares buf's array while it fits, so it is valid
// only while buf is, and buf must not be written while the Chain is in use. A
// caller passes a fixed array on its own stack:
//
//	var buf [16]error
//	chain, abort := errwalk.FlattenInto(buf[:], err)
//
// One deferred recover covers the whole walk, not one per Unwrap call: a panic
// in any Unwrap aborts the whole walk either way.
func FlattenInto(buf []error, err error) (chain Chain, abort error) {
	done := false

	noteArmed()

	defer func() {
		// done is read first, so a walk that returned never calls recover.
		if !done {
			chain, abort = nil, &PanicError{Value: recover(), Frames: panicFrames()}
		}
	}()

	chain, abort = flatten(buf, err)
	done = true

	return chain, abort
}

// flatten is FlattenInto's walk, run under FlattenInto's recover.
func flatten(buf []error, err error) (Chain, error) {
	var (
		chain = Chain(buf[:0])
		// stack holds the entries not yet examined, nil entries included. It
		// starts in a fixed array on this frame, so a chain whose pending
		// entries fit allocates nothing for them.
		pending  [pendingSize]error
		stack    = append(pending[:0], err)
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

		switch u := node.(type) { //nolint:errorlint // the walk is the unwrapping
		case interface{ Unwrap() error }:
			next := u.Unwrap()
			if next == nil {
				continue
			}

			if examined+len(stack)+1 > Budget {
				return nil, budgetError{}
			}

			stack = append(stack, next)
		case interface{ Unwrap() []error }:
			kids := u.Unwrap()

			// Every pending entry is examined later and counts 1, so the
			// walk is over budget as soon as the pending ones would be.
			if examined+len(stack)+len(kids) > Budget {
				return nil, budgetError{}
			}

			// Pushed in reverse, so they pop in slice order.
			for i := len(kids) - 1; i >= 0; i-- {
				stack = append(stack, kids[i])
			}
		}
	}

	return chain, nil
}

// Is reports whether a node of c matches target, scanning c in order: by ==
// when target's type is comparable, or by the node's own Is(error) bool
// method. A panicking Is method, or a == that panics, aborts with a
// *PanicError. A nil target matches nothing, since a Chain holds no nil.
//
// One deferred recover covers the whole scan, not one per node: any panic
// aborts the whole call either way, and arming a recover per node was most of
// a classification's time.
func Is(c Chain, target error) (matched bool, abort error) {
	if target == nil {
		return false, nil
	}

	// == is taken only when target's type is comparable, so a target of an
	// incomparable type never panics for it. Between interface values, ==
	// first compares their dynamic types and is false, without calling any
	// type's equality, when they differ: that is the same-type guard, at the
	// cost of one word compare. A node of target's own comparable type that
	// holds an incomparable value can still panic, which the recover catches.
	compare := reflect.TypeOf(target).Comparable()
	done := false

	noteArmed()

	defer func() {
		// done is read first, so a scan that returned never calls recover.
		if !done {
			matched, abort = false, &PanicError{Value: recover(), Frames: panicFrames()}
		}
	}()

	for _, node := range c {
		if compare && node == target { //nolint:errorlint // the == step errors.Is takes on each node
			matched = true

			break
		}

		if x, ok := node.(interface{ Is(error) bool }); ok && x.Is(target) {
			matched = true

			break
		}
	}

	done = true

	return matched, nil
}

// Targets is an ordered list of Is targets, prepared once for Index: each
// target's comparability is read when the list is built, not on every scan.
// The zero value is an empty list.
type Targets struct {
	errs    []error
	compare []bool
}

// NewTargets prepares errs, in order, for Index. It copies errs, so a later
// change to the caller's slice does not change the list. A nil entry keeps its
// position and matches nothing, as a nil target of Is matches nothing.
func NewTargets(errs ...error) Targets {
	t := Targets{
		errs:    slices.Clone(errs),
		compare: make([]bool, len(errs)),
	}

	for i, target := range t.errs {
		t.compare[i] = target != nil && reflect.TypeOf(target).Comparable()
	}

	return t
}

// Len is the number of targets, nil entries included.
func (t Targets) Len() int { return len(t.errs) }

// Index returns the position in t of the first target, in t's order, that a
// node of c matches, or -1 when none does. Each target is tried over every node
// of c before the next target is tried, so the result is exactly that of
// calling Is once per target in t's order and stopping at the first match: a
// later target never wins over an earlier one, even when it matches an earlier
// node. A node matches a target as Is says.
//
// One deferred recover covers the whole scan, every target and every node. A
// panicking Is method, or a == that panics, aborts with a *PanicError and -1,
// as Is does; a panic reached before any target matched aborts even though a
// later target would have matched.
func Index(c Chain, t Targets) (index int, abort error) {
	index = -1
	done := false

	noteArmed()

	defer func() {
		// done is read first, so a scan that returned never calls recover.
		if !done {
			index, abort = -1, &PanicError{Value: recover(), Frames: panicFrames()}
		}
	}()

	// Target by target, each over every node: the order of one Is per
	// target. compare is the guard Is computes per call, read once by
	// NewTargets.
scan:
	for j, target := range t.errs {
		if target == nil {
			continue
		}

		compare := t.compare[j]

		for _, node := range c {
			if compare && node == target { //nolint:errorlint // the == step errors.Is takes on each node
				index = j

				break scan
			}

			if x, ok := node.(interface{ Is(error) bool }); ok && x.Is(target) {
				index = j

				break scan
			}
		}
	}

	done = true

	return index, nil
}

// As returns the first node of c, in order, that is a T: by type assertion,
// or through the node's own As(any) bool method with a *T target. For a
// pointer or interface T, a nil result is no match, and the scan continues. A
// panicking As method aborts with a *PanicError. As Is does, it arms one
// deferred recover for the whole scan.
func As[T error](c Chain) (found T, matched bool, abort error) {
	done := false

	noteArmed()

	defer func() {
		// done is read first, so a scan that returned never calls recover.
		if !done {
			var zero T

			found, matched, abort = zero, false, &PanicError{Value: recover(), Frames: panicFrames()}
		}
	}()

	for _, node := range c {
		if v, ok := node.(T); ok && !isNil(v) { //nolint:errorlint // the direct type match errors.As makes on each node
			found, matched = v, true

			break
		}

		if x, ok := node.(interface{ As(any) bool }); ok {
			var v T

			if x.As(&v) && !isNil(v) {
				found, matched = v, true

				break
			}
		}
	}

	done = true

	return found, matched, nil
}

// Reason names an abort for reporting: "budget", "panic", or "" for a nil
// error or any error this package did not return. It recognises aborts by
// type and calls no method of a foreign error.
func Reason(abort error) string {
	switch abort.(type) { //nolint:errorlint // only errwalk's own unwrapped abort values reach here; must not call a foreign error's methods
	case budgetError:
		return "budget"
	case *PanicError:
		return "panic"
	default:
		return ""
	}
}

// armHook, when set, is called each time a deferred recover is armed. It is
// nil outside tests. It is atomic so that a goroutine still classifying when a
// test sets or clears it is not a data race.
var armHook atomic.Pointer[func()]

// SetArmHook makes f be called each time Flatten, FlattenInto, Is, As or
// Index arms its deferred recover, and returns the function that restores the
// hook it replaced. A nil f removes the hook. It exists for this module's tests
// that pin how many recovers one classification arms; production code never
// sets it. The hook is process-wide, so a test that sets it must not run in
// parallel with others that classify, and f must be safe to call from any
// goroutine.
func SetArmHook(f func()) (restore func()) {
	var next *func()
	if f != nil {
		next = &f
	}

	prev := armHook.Swap(next)

	return func() { armHook.Store(prev) }
}

// noteArmed calls the arm hook, if one is set.
func noteArmed() {
	if h := armHook.Load(); h != nil {
		(*h)()
	}
}

// panicFrames returns the program counters of the panicking stack. It must be
// called directly from the deferred function that recovered, while that stack
// still exists. The skip of 3 leaves out runtime.Callers, panicFrames and the
// deferred function, so the first frame is runtime.gopanic (or the runtime
// frame that raised a runtime error) and the panicking function follows it.
// At most FrameLimit are kept; nil when the runtime gives none.
//
//go:noinline
func panicFrames() []uintptr {
	var pcs [FrameLimit]uintptr

	n := runtime.Callers(3, pcs[:])
	if n == 0 {
		return nil
	}

	return slices.Clone(pcs[:n])
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
