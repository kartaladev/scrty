package lockout

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/policy"
)

// ReportKind says which lockout transition a Report describes.
// The zero value is not a kind; every report carries one of the constants.
type ReportKind int

const (
	// ReportLocked reports a recorded failure that leaves its identifier
	// locked: owing a wait under the escalating wait, or refused under the
	// sliding lock. Every such failure is reported, not only the one that
	// reached the threshold.
	ReportLocked ReportKind = iota + 1

	// ReportAtWindowFailureLimit reports a recorded failure that leaves its identifier
	// at the window failure limit, refused however long it waits. The sliding lock has no
	// window failure limit, so under it a locking failure is always ReportLocked.
	ReportAtWindowFailureLimit

	// ReportCleared reports a reset that removed failures from the window.
	// Its count is read just before the reset, so a failure recorded
	// concurrently with the reset may or may not be in it: under concurrency
	// the count can be stale, and the report is a record of the clearing, not
	// an exact tally of what it removed. A reset that found nothing to clear
	// is not reported.
	ReportCleared

	// ReportHeld reports the failure that made its identifier held by the
	// failure-streak limit (WithFailureStreakLimit). It is reported once per hold,
	// by the one write the store reports as having set it, so it is exact
	// even under a concurrent burst, and including when a lowered failure-streak limit, now below an
	// existing count, is reached by the next failure. That write is reported
	// only as ReportHeld; later failures are reported by the window, as
	// before.
	ReportHeld

	// ReportReleased reports a reset that lifted a hold, in place of
	// ReportCleared, whether or not the window held any failures. The reset
	// reads the streak before it resets, so a concurrent failure that sets the
	// hold in between is reported as ReportCleared, and two concurrent resets
	// of one held identifier may both report a release.
	ReportReleased
)

// String returns "locked", "at-ceiling", "cleared", "held" or "released", and
// "unknown" for a value that is none of them.
func (k ReportKind) String() string {
	switch k {
	case ReportLocked:
		return "locked"
	case ReportAtWindowFailureLimit:
		return "at-ceiling"
	case ReportCleared:
		return "cleared"
	case ReportHeld:
		return "held"
	case ReportReleased:
		return "released"
	default:
		return "unknown"
	}
}

// Report is what an Observer is told about one lockout
// transition. A failure recorded straight into the store, rather than through
// the policy's view, is not reported.
type Report struct {
	// Identifier is the identifier exactly as it was submitted, never folded
	// or normalised. An identifier that names no account is reported in the
	// same form as one that does: the policy does not know the difference,
	// and a report must not let anyone learn it.
	Identifier string

	// Kind is the transition.
	Kind ReportKind

	// Failures is how many failures were in the window: after the recorded
	// failure, or, for ReportCleared, just before the reset removed them. For
	// ReportHeld it is the consecutive count after the failure that set the
	// hold, and for ReportReleased the consecutive count the reset cleared.
	Failures int

	// At is the instant of the recorded failure, or the policy clock's
	// instant at the reset.
	At time.Time
}

// Observer is told of lockout transitions, for a consumer's audit
// trail, alerting or metrics. It has no return value and cannot change a
// decision or an error: the lockout outcome belongs to the store and the
// policy.
//
// It is called synchronously, on the caller's goroutine, after the store has
// accepted the write, so a slow observer slows the login that recorded the
// failure; one that must do slow work hands it off. It may be called
// concurrently, once per concurrent failure or reset.
//
// It sees only what goes through the policy's view, Policy.Attempts,
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
// WithLogger. The same holds for a reset: if the failures could not be
// counted before it, the reset still clears them, and only the ReportCleared
// report is lost and logged; with a failure-streak limit, a reset whose consecutive count could
// not be read loses its report the same way, since the policy cannot tell a
// release from a clearing without it.
//
// With a failure-streak limit (WithFailureStreakLimit) it is also told of the failure that sets a hold,
// ReportHeld, even when the failure log could not record that failure: the
// hold is in the store and no later write sets it again. A reset that lifts a
// hold is reported as ReportReleased.
//
// ctx is the caller's context, which may already be cancelled; an observer
// that hands work off detaches it first (context.WithoutCancel).
//
// A panic in the observer is recovered and logged through WithLogger,
// and the call that triggered the report returns as it would have without
// it.
type Observer func(ctx context.Context, r Report)

// WithObserver supplies an observer told of lockout transitions (see
// Observer). The default is none: nothing is reported to an observer, and
// recording through the policy's view costs nothing beyond the store's write
// unless a security-event sink watches (see Attempts).
//
// With an observer, recording a failure also counts the identifier's failures
// in the window, and a reset counts them before clearing, which is one extra
// store read on each. With a failure-streak limit as well, a reset also reads the
// consecutive count, a second read; the failure that sets a hold needs no
// read.
//
// A reset reads the consecutive count before it resets, so a report is a
// reading taken just before the reset, not a lock on the identifier. A failure
// that sets the hold in between leaves the reset reported as ReportCleared
// rather than ReportReleased, and two concurrent resets of one held
// identifier may both report ReportReleased. Reports are advisory; the reset
// itself is unaffected.
//
// A nil observer is a configuration error rather than "none": a consumer who
// passed one meant to be told, and would hear nothing.
func WithObserver(o Observer) Option {
	return func(p *Policy) {
		p.observer = o
		p.setObserver = true
	}
}

// WithLogger replaces where the policy writes the records about its
// observer: a report lost because the store could not count a failure it had
// recorded or a reset that could not count what it cleared, and an observer
// that panicked. The default is slog.Default. A nil
// logger is ignored rather than refused: it has an obvious safe reading, that
// the caller does not want to choose this policy's logger.
//
// Its records carry fixed text, the report's kind and the dependency's error
// type; never a dependency's error text, and never the submitted identifier.
func WithLogger(l *slog.Logger) Option {
	return func(p *Policy) {
		if l != nil {
			p.logger = l
		}
	}
}

// Attempts returns the policy's view of its attempt store, which records into
// the store the policy reads, reports lockout transitions to the observer
// given by WithObserver, and reports the locks it decides as security events.
// It is the store to hand to httpsec.FormLoginDeps.Attempts and
// httpsec.BasicAuthDeps.Attempts, so that failures recorded by the library's
// login endpoints are reported.
//
// It returns the same value on every call, so a consumer that hands it to
// several endpoints hands them one store, and anything that deduplicates
// stores sees one. With no observer, no failure-streak limit and no sink
// watching, it forwards each call to the store and does nothing else. A
// failure recorded straight into the store, rather than through this view, is
// neither told to the observer nor reported as an event.
//
// A lock is reported where it is decided. On a failure a sink watches, the
// chain's (httpsec.EnableSecurityEvents) or the policy's own
// (WithSecurityEvents), the view reads, before it records the failure,
// whether the identifier is locked by the rule Evaluate judges by, and the
// failure that takes it from allowed to locked, or under the escalating wait
// takes its count to the window failure limit, or that sets a hold, reports
// event.AuthnLoginFailMax and then event.AuthnLoginLock. Under the
// escalating wait an identifier is allowed again once its wait has run out,
// so the failure after that locks it again, for longer, and reports again.
// The failures that find it still locked lock nothing new and report no
// further lock; the observer is still told of each as before. Within one
// process the failures of one identifier are recorded one at a time while a
// sink watches, so concurrent failures that lock it together report one
// lock. With a store several processes share, failures on different
// processes at the same moment may each report it: a lock is reported at
// least once, and once within a process.
//
// Deciding it costs store reads, paid only while a sink watches. Under a
// failure-streak limit the first is the identifier's streak, since a held
// identifier is locked whatever its window holds, and a failure for one
// reports no further lock, however its window stands. An identifier not
// held, or any under no such limit, has the window's count read before the
// failure and, under the escalating wait for a count between the threshold
// and the window failure limit, whether any failure is more recent than the
// wait that count owes, since the count alone cannot tell a wait still
// running from one that has run out. The count after the failure is read too,
// and shared with the observer when there is one.
//
// So a failure a sink watches reads the window two or three times besides its
// write, with or without an observer, and the streak once more under a
// failure-streak limit. Some read less. One that sets a hold, or
// whose write to the failure log failed, reads no count after the write, so
// the window one or two times. One for an identifier already held reads the
// streak and counts the window only after the write. A failure with only an
// observer reads the window once, after the write, and none when it sets a
// hold or its write failed; one with neither, none. A store that cannot
// answer a read before the write loses the event, which the policy logs
// through WithLogger, and never the failure.
//
// A zero instant given to the view's RecordFailure is recorded at the
// policy's clock, always, whatever the policy is configured with; an instant
// that is given is kept as it is. With a failure-streak limit
// (WithFailureStreakLimit) the view's RecordFailure writes the identifier's
// consecutive-failure streak and then the failure log, and always attempts the
// log even when the streak write failed; it returns both errors joined.
func (p *Policy) Attempts() policy.AttemptStore { return p.attempts }

// observedAttempts is the view Attempts hands out: it forwards every call to
// the policy's store, advances the identifier's consecutive-failure streak
// when there is a failure-streak limit, reports the transitions its writes
// cause when there is an observer, and reports a lock its write decides when
// a sink watches.
type observedAttempts struct {
	p *Policy

	// locks serializes one identifier's failures while a sink watches, so
	// one lock is reported once in this process.
	locks identifierLocks
}

// msgReportLost is the record for a failure that was recorded but could not
// be counted afterwards: the lockout is intact, and only its report is gone.
const msgReportLost = "lockout: a lockout report was lost: the attempt store recorded the failure but could not count it"

func (o *observedAttempts) RecordFailure(ctx context.Context, username string, at time.Time) error {
	p := o.p

	// A zero instant is recorded at the policy's clock, for the streak and the
	// log alike: Evaluate reads a zero instant as now, and a failure stored at
	// the zero instant falls outside every window, so it would never count and
	// a hold set at it would read as no hold at all.
	if at.IsZero() {
		at = p.clock.Now()
	}

	// A lock is reported where it is decided, by reading whether the
	// identifier was locked before this failure and counting the window after
	// it, and only on a failure some sink watches. The identifier's failures
	// in this process are recorded one at a time meanwhile, so one of them
	// sees the transition; the observer and the sink are told after the lock
	// is released, so neither holds the next failure.
	watched := p.eventsWatched(ctx)
	unlock := func() {}
	if watched {
		unlock = o.locks.lock(username)
	}

	// The release is deferred, so a store that panics leaves the identifier
	// free for its next failure rather than held for good.
	out := func() recorded {
		defer unlock()

		return o.record(ctx, username, at, watched)
	}()

	if out.report != nil {
		p.report(ctx, *out.report)
	}
	if out.locked {
		p.reportLock(ctx, at)
	}

	return out.err
}

// recorded is what recording one failure decided: the error to return, the
// report to tell the observer, if any, and whether the failure locked its
// identifier, for the security events.
type recorded struct {
	err    error
	report *Report
	locked bool
}

// record writes one failure and decides what it reports. watched is whether a
// sink watches, so whether the identifier was locked is read before the write
// as well as the window counted after.
func (o *observedAttempts) record(ctx context.Context, username string, at time.Time, watched bool) recorded {
	p := o.p

	// Whether the identifier was locked before this failure, by the policy's
	// own rule, read only while a sink watches.
	var lockedBefore lockState
	if watched {
		lockedBefore = p.lockedAt(ctx, username, at)
	}

	// The streak goes first: it is the record that cannot be rebuilt from the
	// log. A failed streak write does not skip the log, though: the log entry
	// alone keeps the windowed lock counting while the streak store is failing.
	// When both writes fail both errors are returned, joined; when only one
	// does, that error is returned as it is.
	var (
		streak    FailureStreak
		setHold   bool
		streakErr error
	)
	if p.streaks != nil {
		streak, setHold, streakErr = p.streaks.AddStreakFailure(ctx, username, at, at.Add(-p.capRetention), p.capLimit)
	}
	logErr := p.store.RecordFailure(ctx, username, at)

	// The hold is reported by the one write the store says set it, whatever
	// became of the log: no later write sets it again, so a report lost here
	// would be lost for good. That write is reported as the hold and not also
	// by the window.
	if setHold {
		out := recorded{err: joinWriteErrors(streakErr, logErr), locked: watched}
		if p.observer != nil {
			out.report = &Report{Identifier: username, Kind: ReportHeld, Failures: streak.Failures, At: at}
		}

		return out
	}
	if logErr != nil {
		return recorded{err: joinWriteErrors(streakErr, logErr)}
	}
	if p.observer == nil && !watched {
		return recorded{err: streakErr}
	}

	count, err := p.store.FailureCount(ctx, username, at.Add(-p.window))
	if err != nil {
		p.logger.LogAttrs(ctx, slog.LevelError, msgReportLost, diag.Failure("attempt-store", err)...)

		return recorded{err: streakErr}
	}

	out := recorded{err: streakErr}

	if p.observer != nil {
		switch {
		case !p.sliding && count >= p.ceiling:
			out.report = &Report{Identifier: username, Kind: ReportAtWindowFailureLimit, Failures: count, At: at}
		case count >= p.threshold:
			out.report = &Report{Identifier: username, Kind: ReportLocked, Failures: count, At: at}
		}
	}

	if watched {
		switch {
		case lockedBefore.err != nil:
			p.logger.LogAttrs(ctx, slog.LevelError, msgEventLost, diag.Failure("attempt-store", lockedBefore.err)...)
		case p.locks(lockedBefore, count):
			out.locked = true
		}
	}

	return out
}

// msgEventLost is the record for a failure whose lock event could not be
// decided because the store could not answer one of the reads that say,
// before the failure was recorded, whether the identifier was already locked:
// its failure streak, the window's count, or the recency of its newest
// failure. The failure is recorded and counts, and only its event is gone.
const msgEventLost = "lockout: a lock event was lost: the attempt store could not answer a read made before the failure was recorded"

// joinWriteErrors returns the one error that is set as itself, so a caller
// that compares the store's error by identity still can, and joins the two
// only when both writes failed.
func joinWriteErrors(streakErr, logErr error) error {
	if streakErr == nil {
		return logErr
	}
	if logErr == nil {
		return streakErr
	}

	return errors.Join(streakErr, logErr)
}

// msgClearReportLost is the record for a reset that succeeded but whose
// failures could not be counted beforehand: the identifier is cleared, and only
// the report of it is gone.
const msgClearReportLost = "lockout: a lockout report was lost: the attempt store could not count the failures before a reset"

// msgObserverPanicked is the record for an observer that panicked. The
// lockout outcome is the store's and the policy's, never the observer's.
const msgObserverPanicked = "lockout: the lockout observer panicked; the lockout outcome is unchanged"

// report tells the observer of r. A panic in the observer is recovered and
// logged with fixed text and the report's kind, never the identifier or the
// panic value, which may carry either.
func (p *Policy) report(ctx context.Context, r Report) {
	defer func() {
		if recover() != nil {
			p.logger.LogAttrs(ctx, slog.LevelError, msgObserverPanicked, slog.String("kind", r.Kind.String()))
		}
	}()

	p.observer(ctx, r)
}

func (o *observedAttempts) Reset(ctx context.Context, username string) error {
	p := o.p
	if p.observer == nil {
		// Nothing to report, so nothing to count first. The store's Reset
		// clears the streak, hold included, with the log.
		return p.store.Reset(ctx, username)
	}
	now := p.clock.Now()

	// Read first, so a report can say what the reset removed. A count that
	// cannot be read does not stop the reset: clearing is what the caller
	// asked for, and only the report depends on the count.
	count, countErr := p.store.FailureCount(ctx, username, now.Add(-p.window))

	// With a failure-streak limit the streak is read too, to tell a release from a clearing.
	// Without it the policy cannot tell which one the reset was, so it
	// reports neither rather than the wrong one.
	var (
		streak    FailureStreak
		streakErr error
	)
	if p.streaks != nil {
		streak, streakErr = p.streaks.FailureStreak(ctx, username, now.Add(-p.capRetention))
	}

	if err := p.store.Reset(ctx, username); err != nil {
		return err
	}

	switch {
	case streakErr != nil:
		p.logger.LogAttrs(ctx, slog.LevelError, msgClearReportLost, diag.Failure("attempt-store", streakErr)...)
	case streak.Held():
		// A hold outlives the window, so its release is reported whatever
		// the window held, and in place of the clearing.
		p.report(ctx, Report{Identifier: username, Kind: ReportReleased, Failures: streak.Failures, At: now})
	case countErr != nil:
		p.logger.LogAttrs(ctx, slog.LevelError, msgClearReportLost, diag.Failure("attempt-store", countErr)...)
	case count > 0:
		p.report(ctx, Report{Identifier: username, Kind: ReportCleared, Failures: count, At: now})
	}

	return nil
}

func (o *observedAttempts) FailureCount(ctx context.Context, username string, since time.Time) (int, error) {
	return o.p.store.FailureCount(ctx, username, since)
}
