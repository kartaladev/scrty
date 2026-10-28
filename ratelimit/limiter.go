package ratelimit

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/kartaladev/scrty/expiry"
)

//go:generate mockgen -source=limiter.go -package=ratelimit_test -destination=limiter_mock_test.go -exclude_interfaces=LimiterFactory,Verifier,PolicyReporter,Pruner -typed

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

// ErrConfig is wrapped by every error this package's constructors return for a
// wiring mistake, so a consumer can tell a contradictory configuration from a
// runtime failure without matching on message text. A configuration that cannot
// work is refused at construction, before any traffic depends on it.
var ErrConfig = errors.New("ratelimit: invalid configuration")

// LimiterFactory builds the limiter a flow counts its failures through.
//
// Each built-in flow asks for its own namespace, limit and window, so a
// consumer who replaces the storage keeps every flow's own policy. Default:
// MemoryLimiterFactory, which gives each call a limiter of its own in this
// process.
type LimiterFactory interface {
	NewLimiter(namespace string, limit int, window time.Duration) (Limiter, error)
}

// Verifier is implemented by factories and limiters whose backend can be
// checked before traffic. Constructors never perform I/O; a consumer calls
// Verify at startup. It is optional: a factory or limiter with nothing to
// check, such as the in-memory default, does not implement it.
type Verifier interface {
	Verify(ctx context.Context) error
}

// PolicyReporter is implemented by a Limiter that can say the limit and window
// it counts with.
//
// It is optional. A component that needs a limiter's policy, such as the
// httpsec chain sizing a flow's IPv6 aggregate, asks for it with a type
// assertion, and treats a limiter without it as one whose policy is unknown
// rather than guessing one. MemoryLimiter and the shared limiters scrty ships
// implement it; a consumer's own Limiter may, to get the same treatment.
//
// A limiter's policy is fixed when it is built, so Policy reports the same
// pair on every call, and a caller may read it once.
type PolicyReporter interface {
	// Policy returns the number of failures a key may accumulate, and the
	// window they are counted over.
	Policy() (limit int, window time.Duration)
}

// Pruner removes the keys a limiter no longer counts, by the window recorded for
// each key, and reports how many it removed. It accepts no cutoff, so a sweep
// can never shorten a limit: the only keys it can remove are those that window
// has already released.
//
// There are two built-in pruners: the in-memory limiter, *MemoryLimiter, and the
// PostgreSQL limiter factories of the sqlstore and pgxstore packages.
// A consumer may implement Pruner for a limiter of its own and hand it to
// ExpiryTask.
type Pruner interface {
	Prune(ctx context.Context) (removed int, err error)
}

var _ Pruner = (*MemoryLimiter)(nil)

// ExpiryTask returns the expiry task for p, to run in an expiry.Runner beside
// the tasks of the stores that hold expired state. The built-in pruners are the
// in-memory limiter and the PostgreSQL limiter factories of the sqlstore and
// pgxstore packages. p must not be nil.
//
// The task is named "ratelimit" and has no Interval, so a scheduler uses its
// own default and a manual run ignores it. A deployment with two pruners
// renames each copy so their results and any scheduler lock keys stay apart:
//
//	t := ratelimit.ExpiryTask(f)
//	t.Name = "ratelimit:postgres"
//
// It takes no cutoff: what Prune removes is decided by the window recorded for
// each key, so a sweep can never shorten a limit. The inline sweep of the
// in-memory limiter already bounds memory while traffic arrives, so this task
// matters for a limiter that goes quiet after a burst, whose keys would
// otherwise stay held until its next call. Run returns the count and the error
// the pruner reports; the in-memory limiter never fails.
func ExpiryTask(p Pruner) expiry.Task {
	return expiry.Task{Name: "ratelimit", Run: p.Prune}
}

// UnavailableMode is what a shared limiter does while the store it counts in
// cannot be reached: an error, a timeout or an exhausted pool while the
// caller's context is still live.
//
// The in-memory limiter has no outage and ignores it. A limiter over shared
// storage takes it through its own constructor's options; each of scrty's
// backend modules does, and a consumer's own Limiter may honour it the same way.
//
// Whatever the mode, a check whose caller context has already ended returns
// true and an error: a hung-up caller is not an outage, and is never answered
// from a degraded mode.
//
// The zero value is UnavailableRefuse, so a consumer who chooses nothing fails
// closed. Any value other than the three declared here is a configuration
// error wherever a mode is accepted.
type UnavailableMode int

const (
	// UnavailableRefuse is the default. While the backend is unavailable a
	// check reports the key as exceeded, with an error wrapping
	// ErrBackendUnavailable, so a guard refuses the attempt as throttled; a
	// record returns that error, and the key it could not record is refused on
	// this instance for one window, even once checks reach the backend again.
	//
	// That memory is bounded: it holds at most [DefaultMemoryLimiterMaxKeys]
	// keys, and a key longer than 64 bytes is held as a digest of it, so its
	// size in bytes is bounded too. Once it is full, every source, held or not,
	// is refused for one window from the latest key it had no room for, so a
	// spray of distinct keys during an outage cannot grow it or slip past it.
	// There is no option for the cap: the memory only bounds what an outage can
	// make the limiter remember, and a larger or unbounded one would let an
	// attacker who causes the outage grow it.
	//
	// What it costs, stated: during an outage every flow guarded by the
	// limiter refuses, including second-factor verification, so a user who
	// needs a second factor cannot complete sign-in until the backend returns.
	// It is the default because a limiter that fails open is one an attacker
	// disables by causing the outage.
	UnavailableRefuse UnavailableMode = iota

	// UnavailableFallbackToLocal counts in an in-memory limiter with the same
	// limit and window while the backend is unavailable, and a record that
	// cannot reach the backend is counted there instead. Once the backend is
	// back, a key is exceeded when either the shared count or the local one is.
	//
	// What it gives up, stated: during the outage each replica counts only its
	// own failures, so behind N replicas the effective limit is N times the
	// configured one — the in-memory limiter's own documented bound. Entering
	// and leaving this state is logged at ERROR and WARN. It suits
	// second-factor flows, which keep a per-replica bound without locking
	// users out of sign-in during an outage.
	UnavailableFallbackToLocal

	// UnavailableAllow reports every key as not exceeded and drops every
	// record while the backend is unavailable, logging an ERROR sampled per
	// namespace, and a WARN when the backend is back.
	//
	// What it gives up, stated: there is no limit at all during the outage.
	// It is for a flow whose consumer has another bound in front of it, such as
	// an edge rate limiter.
	UnavailableAllow
)

// ErrBackendUnavailable is wrapped by the error a shared limiter returns,
// in UnavailableRefuse mode, when it could not reach its backend or is not
// trying to because a recent attempt failed. A guard already refuses on any
// limiter error; a caller matches on this one to tell an outage from a check
// its own context abandoned.
var ErrBackendUnavailable = errors.New("ratelimit: backend unavailable")

// String names the mode in lower case, as a log record or an error message
// prints it: "refuse", "fall-back" or "allow". A value that names no mode
// prints as UnavailableMode(n) rather than passing itself off as one of them.
func (m UnavailableMode) String() string {
	switch m {
	case UnavailableRefuse:
		return "refuse"
	case UnavailableFallbackToLocal:
		return "fall-back"
	case UnavailableAllow:
		return "allow"
	default:
		return "UnavailableMode(" + strconv.Itoa(int(m)) + ")"
	}
}
