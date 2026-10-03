package ratelimittest

import (
	"testing"
	"time"

	"github.com/kartaladev/scrty/ratelimit"
)

// Harness adapts one limiter implementation to the suite.
type Harness struct {
	// New builds a limiter over a backend scope for namespace. Calling New
	// again for the same namespace starts that namespace afresh, and only that
	// one.
	//
	// The namespaces one subtest asks for must share one backend scope, such
	// as one key prefix, so that a limiter which ignores its namespace counts
	// two of them together and the suite catches it. New therefore resets only
	// its own namespace within that scope, and leaves the subtest's other
	// namespaces as they are. A harness over an in-memory limiter, which keeps
	// no namespace, meets this by building a fresh limiter per call.
	//
	// A harness over a shared backend meets "afresh" by deleting what the
	// namespace held. The suite calls New many times for the same namespace
	// with different limits and windows, so a harness built on a factory that
	// rejects conflicting policies must use a fresh factory per New.
	New func(t *testing.T, namespace string, limit int, window time.Duration) ratelimit.Limiter

	// Advance moves the clock every limiter from New reads. The suite never
	// advances by less than a microsecond, and the clock must read on whole
	// microseconds, because a shared limiter may store microseconds.
	Advance func(d time.Duration)

	// SecondInstance, when set, builds another instance over the same backend
	// scope as the last New for that namespace, standing in for another
	// replica, as another process would: it must not share the first
	// instance's policy registry, because the cross-instance scenarios give
	// it a different window on purpose. A harness for a shared limiter must
	// set it, or the cross-instance scenarios do not run. When nil they are
	// skipped.
	SecondInstance func(t *testing.T, namespace string, limit int, window time.Duration) ratelimit.Limiter
}
