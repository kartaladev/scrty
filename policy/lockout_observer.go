package policy

import (
	"context"
	"log/slog"
	"time"

	"github.com/kartaladev/scrty/internal/diag"
)

// LockoutReportKind says which lockout transition a LockoutReport describes.
// The zero value is not a kind; every report carries one of the constants.
type LockoutReportKind int

const (
	// LockoutLocked reports a recorded failure that leaves its identifier
	// locked: owing a wait under the escalating wait, or refused under the
	// sliding lock. Every such failure is reported, not only the one that
	// reached the threshold.
	LockoutLocked LockoutReportKind = iota + 1

	// LockoutAtCeiling reports a recorded failure that leaves its identifier
	// at the ceiling, refused however long it waits. The sliding lock has no
	// ceiling, so under it a locking failure is always LockoutLocked.
	LockoutAtCeiling

	// LockoutCleared reports a reset that removed failures from the window.
	// Its count is read just before the reset, so a failure recorded
	// concurrently with the reset may or may not be in it: under concurrency
	// the count can be stale, and the report is a record of the clearing, not
	// an exact tally of what it removed. A reset that found nothing to clear
	// is not reported.
	LockoutCleared
)

// String returns "locked", "at-ceiling" or "cleared", and "unknown" for a
// value that is none of them.
func (k LockoutReportKind) String() string {
	switch k {
	case LockoutLocked:
		return "locked"
	case LockoutAtCeiling:
		return "at-ceiling"
	case LockoutCleared:
		return "cleared"
	default:
		return "unknown"
	}
}

// LockoutReport is what a LockoutObserver is told about one lockout
// transition. A failure recorded straight into the store, rather than through
// the policy's view, is not reported.
type LockoutReport struct {
	// Identifier is the identifier exactly as it was submitted, never folded
	// or normalised. An identifier that names no account is reported in the
	// same form as one that does: the policy does not know the difference,
	// and a report must not let anyone learn it.
	Identifier string

	// Kind is the transition.
	Kind LockoutReportKind

	// Failures is how many failures were in the window: after the recorded
	// failure, or, for LockoutCleared, just before the reset removed them.
	Failures int

	// At is the instant of the recorded failure, or the policy clock's
	// instant at the reset.
	At time.Time
}

// LockoutObserver is told of lockout transitions, for a consumer's audit
// trail, alerting or metrics. It has no return value and cannot change a
// decision or an error: the lockout outcome belongs to the store and the
// policy.
//
// It is called synchronously, on the caller's goroutine, after the store has
// accepted the write, so a slow observer slows the login that recorded the
// failure; one that must do slow work hands it off. It may be called
// concurrently, once per concurrent failure or reset.
//
// It sees only what goes through the policy's view, AccountLockoutPolicy.Attempts,
// and the policy's own RecordFailure and Reset. A failure recorded straight
// into the store, bypassing the view, locks just the same but is never
// reported.
//
// It is told of every recorded failure that leaves its identifier locked, not
// only the first, so a concurrent burst of failures loses no report even
// though no single one of them can tell that it was the one that crossed the
// threshold. A failure the store could not record is not reported, and
// neither is one recorded but then not countable: that failure still counts,
// and only its report is lost, which the policy logs through
// WithLockoutLogger. The same holds for a reset: if the failures could not be
// counted before it, the reset still clears them, and only the LockoutCleared
// report is lost and logged.
//
// ctx is the caller's context, which may already be cancelled; an observer
// that hands work off detaches it first (context.WithoutCancel).
//
// A panic in the observer is recovered and logged through WithLockoutLogger,
// and the call that triggered the report returns as it would have without
// it.
type LockoutObserver func(ctx context.Context, r LockoutReport)

// WithLockoutObserver supplies an observer told of lockout transitions (see
// LockoutObserver). The default is none: nothing is reported, and the policy's
// view is the store itself, so recording costs nothing beyond the store's
// write.
//
// With an observer, recording a failure also counts the identifier's failures
// in the window, and a reset counts them before clearing, which is one extra
// store read on each.
//
// A nil observer is a configuration error rather than "none": a consumer who
// passed one meant to be told, and would hear nothing.
func WithLockoutObserver(o LockoutObserver) LockoutOption {
	return func(p *AccountLockoutPolicy) {
		p.observer = o
		p.setObserver = true
	}
}

// WithLockoutLogger replaces where the policy writes the records about its
// observer: a report lost because the store could not count a failure it had
// recorded or a reset that could not count what it cleared, and an observer
// that panicked. The default is slog.Default. A nil
// logger is ignored rather than refused: it has an obvious safe reading, that
// the caller does not want to choose this policy's logger.
//
// Its records carry fixed text, the report's kind and the dependency's error
// type; never a dependency's error text, and never the submitted identifier.
func WithLockoutLogger(l *slog.Logger) LockoutOption {
	return func(p *AccountLockoutPolicy) {
		if l != nil {
			p.logger = l
		}
	}
}

// Attempts returns the policy's view of its attempt store, which records into
// the store the policy reads and reports lockout transitions to the observer
// given by WithLockoutObserver. It is the store to hand to
// httpsec.FormLoginDeps.Attempts and httpsec.BasicAuthDeps.Attempts, so that
// failures recorded by the library's login endpoints are reported.
//
// It returns the same value on every call, so a consumer that hands it to
// several endpoints hands them one store, and anything that deduplicates
// stores sees one. Without an observer it is the store itself. A failure
// recorded straight into the store, rather than through this view, is not
// reported.
func (p *AccountLockoutPolicy) Attempts() AttemptStore { return p.attempts }

// observedAttempts is the view Attempts hands out when the policy has an
// observer: it forwards every call to the policy's store and reports the
// transitions its writes cause.
type observedAttempts struct {
	p *AccountLockoutPolicy
}

// msgReportLost is the record for a failure that was recorded but could not
// be counted afterwards: the lockout is intact, and only its report is gone.
const msgReportLost = "policy: a lockout report was lost: the attempt store recorded the failure but could not count it"

func (o *observedAttempts) RecordFailure(ctx context.Context, username string, at time.Time) error {
	p := o.p
	if err := p.store.RecordFailure(ctx, username, at); err != nil {
		return err
	}

	count, err := p.store.FailureCount(ctx, username, at.Add(-p.window))
	if err != nil {
		p.logger.LogAttrs(ctx, slog.LevelError, msgReportLost, diag.Failure("attempt-store", err)...)

		return nil
	}

	switch {
	case !p.sliding && count >= p.ceiling:
		p.report(ctx, LockoutReport{Identifier: username, Kind: LockoutAtCeiling, Failures: count, At: at})
	case count >= p.threshold:
		p.report(ctx, LockoutReport{Identifier: username, Kind: LockoutLocked, Failures: count, At: at})
	}

	return nil
}

// msgClearReportLost is the record for a reset that succeeded but whose
// failures could not be counted beforehand: the identifier is cleared, and only
// the report of it is gone.
const msgClearReportLost = "policy: a lockout report was lost: the attempt store could not count the failures before a reset"

// msgObserverPanicked is the record for an observer that panicked. The
// lockout outcome is the store's and the policy's, never the observer's.
const msgObserverPanicked = "policy: the lockout observer panicked; the lockout outcome is unchanged"

// report tells the observer of r. A panic in the observer is recovered and
// logged with fixed text and the report's kind, never the identifier or the
// panic value, which may carry either.
func (p *AccountLockoutPolicy) report(ctx context.Context, r LockoutReport) {
	defer func() {
		if recover() != nil {
			p.logger.LogAttrs(ctx, slog.LevelError, msgObserverPanicked, slog.String("kind", r.Kind.String()))
		}
	}()

	p.observer(ctx, r)
}

func (o *observedAttempts) Reset(ctx context.Context, username string) error {
	p := o.p
	now := p.clock.Now()

	// Read first, so a report can say what the reset removed. A count that
	// cannot be read does not stop the reset: clearing is what the caller
	// asked for, and only the report depends on the count.
	count, countErr := p.store.FailureCount(ctx, username, now.Add(-p.window))

	if err := p.store.Reset(ctx, username); err != nil {
		return err
	}

	if countErr != nil {
		p.logger.LogAttrs(ctx, slog.LevelError, msgClearReportLost, diag.Failure("attempt-store", countErr)...)

		return nil
	}

	if count > 0 {
		p.report(ctx, LockoutReport{Identifier: username, Kind: LockoutCleared, Failures: count, At: now})
	}

	return nil
}

func (o *observedAttempts) FailureCount(ctx context.Context, username string, since time.Time) (int, error) {
	return o.p.store.FailureCount(ctx, username, since)
}
