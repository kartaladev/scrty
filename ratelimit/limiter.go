package ratelimit

import "context"

//go:generate mockgen -source=limiter.go -package=ratelimit_test -destination=mocks_test.go -typed

// Limiter counts failures per key and reports whether a key is over its limit.
//
// MemoryLimiter is the default implementation and needs nothing wired. A
// consumer supplies its own — over Redis, a database, or anything else its
// replicas share — when one limit has to hold across a fleet rather than per
// process; SourceGuard then uses it for every check and record, and nothing of
// the default remains.
//
// An implementation must be safe for concurrent use: a guard is called from
// whatever goroutine is serving a request.
//
// The key is composed by the guard and is opaque to the limiter: it identifies a
// flow and a canonical source, and carries nothing the limiter is expected to
// parse.
type Limiter interface {
	// Exceeded reports whether key has reached its limit, without recording
	// anything. A caller may ask as often as it likes; only recorded failures
	// spend a source's allowance.
	//
	// An error means the question could not be answered — the store is
	// unreachable, or the context has ended — and a guard treats it as
	// exceeded and refuses the attempt. An implementation therefore returns an
	// error rather than a false when it cannot decide: a false would lift the
	// limit at exactly the moment something is wrong, which is how an attacker
	// disables rate limiting. Returning true alongside the error is the safer
	// habit, so that a caller reading only the bool still fails closed.
	Exceeded(ctx context.Context, key string) (bool, error)

	// RecordFailure counts one failure for key.
	//
	// The context may have had its cancellation stripped, because a client
	// that hangs up mid-attempt must still be charged for the guess it made.
	// An implementation that reaches a remote store therefore bounds its own
	// I/O — with its own timeout — rather than relying on a deadline that may
	// no longer be there.
	//
	// An error is an outage, not a judgement about the attempt: a guard logs
	// it and returns nothing to the flow that failed.
	RecordFailure(ctx context.Context, key string) error
}
