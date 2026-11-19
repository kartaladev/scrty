// Package errwalk classifies an error chain with one bounded walk that
// recovers from panics.
//
// The standard library's errors.Is and errors.As have no bound and no
// recovery. On an error a consumer built, a cycle through Unwrap() error
// loops forever, a cycle through Unwrap() []error overflows the stack, a
// nested errors.Join fans out to exponential cost, an Is or As method may
// panic, and a typed nil stops errors.As or panics a value-receiver Is.
// errwalk flattens the chain once, under fixed rules, and the matchers scan
// that flat list instead of walking the chain again.
//
// # Order
//
// Flatten visits the root first, then depth first, in the order errors.Is
// and errors.As visit. Unwrap() error is preferred over Unwrap() []error when
// a node has both, as the standard library does. Each node's Unwrap is called
// exactly once. A nil result from Unwrap() error ends that branch. A nil
// entry in an Unwrap() []error result is skipped, but it counts toward the
// budget.
//
// # Typed nil
//
// A node whose dynamic value is a nil pointer (reflect Kind Pointer and
// IsNil) is skipped: none of its methods is called and it is not in the list,
// but it counts toward the budget. Nil maps, slices, funcs and chans are not
// treated as nil; their methods are called as for any other node.
//
// # Budget
//
// Every examined entry costs 1: the root, real nodes, repeats, nil entries in
// an Unwrap() []error result, and typed nils. The count is taken before any
// method of the entry is called, and entries still pending count too, so the
// walk aborts with an error wrapping ErrBudget as soon as it would examine
// entry Budget+1, and its memory stays bounded by Budget. A walk of exactly
// Budget entries succeeds. This bounds cycles and fan-out alike. The bound has no option: a configurable budget could reopen the
// hang it exists to prevent.
//
// # Panic
//
// A panic in a node's Unwrap, Is or As method, or in the == of Is, is
// recovered, and the walk or match aborts with a *PanicError carrying the
// recovered value, which is nil for panic(nil) under GODEBUG=panicnil=1. The
// error's text never includes the value.
//
// # Matching
//
// Is and As scan the list in order and do not unwrap further. Is matches a
// node that is == to the target (only when the target's type is comparable;
// a comparison that panics aborts) or whose Is(error) bool method reports
// true. As matches a node that asserts to T, or whose As(any) bool method
// sets a *T. For a pointer or interface T, a nil result, whether a nil node or
// an As that reports true without setting the target, is no match, and the
// scan continues. "First match" means first in list order.
//
// Index matches many targets, prepared once with NewTargets, in one scan. It
// tries each target over every node before the next target, so it answers
// exactly as one Is per target in order would, stopping at the first that
// matches.
//
// Flatten, Is, As and Index each arm one deferred recover for the whole walk
// or scan, never one per node, method call or target.
//
// # Aborts
//
// An abort means the classification failed and must fail closed. Flatten
// returns a nil Chain with an abort; nothing guesses what an unreached or
// panicking link would have said. Reason maps an abort this package returned
// to "budget" or "panic" for reporting, and any other error to "". ErrBudget, ErrPanic and *PanicError are internal and
// never returned to a consumer. This package never logs; the caller reports
// the abort.
package errwalk
