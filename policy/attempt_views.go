package policy

import (
	"context"
	"time"
)

// AttemptStore records and counts failed authentication attempts per submitted
// identifier. It is what the account lockout policy keys its decision on.
//
// With no store configured the policy uses lockout.NewMemoryAttemptStore, which counts
// within one replica only and does not survive a restart. A consumer replaces
// it through lockout.WithAttemptStore with any implementation — typically one row per
// failure in their own database, so that every replica locks the same account
// at the same time.
//
// The identifier is the string the caller submitted, stored and matched
// exactly as given: this package attaches no meaning to it and never folds its
// case, because an implementation that did would decide, on the library's
// behalf, that two logins are the same account.
//
// An implementation is called on the request path, once per login attempt, so
// it must be safe for concurrent use.
//
// Identifiers match exactly. A store compares the identifier it is given byte for byte, and must
// not fold case or normalise it: whatever folding a deployment needs is the caller's. A component
// that records one failure under two identifiers, such as an HTTP security chain's login by email,
// which records it under the account and under the identifier as typed, relies on this. A store
// that folds case is outside this contract, and counts such a failure twice whenever the two
// identifiers differ only in case, so it locks sooner than configured.
//
//go:generate mockgen -source=attempt_views.go -package=policy_test -destination=attempt_views_mock_test.go -typed -exclude_interfaces=AttemptViewRequirer,UnreportedAttemptRecorder
type AttemptStore interface {
	// RecordFailure records one failed attempt for username at the instant at,
	// which is the caller's clock rather than the store's: the same instant the
	// policy judges the window against.
	RecordFailure(ctx context.Context, username string, at time.Time) error

	// Reset clears username's recorded failures, which is what a successful
	// authentication does. Clearing an identifier that has no failures is not
	// an error: a login succeeding is the ordinary case, and it must not have
	// to ask first.
	Reset(ctx context.Context, username string) error

	// FailureCount reports how many of username's failures were recorded
	// strictly after since.
	//
	// Strictly is the contract, not an implementation detail. The policy passes
	// now minus its window, so a failure exactly as old as the window has just
	// fallen out of it; counting it would make the window one instant longer
	// than the one the deployment configured, and would keep an account locked
	// for that instant after its lockout expired.
	FailureCount(ctx context.Context, username string, since time.Time) (int, error)
}

// UnreportedAttemptRecorder is an optional interface of an attempt store that
// can record a failure, and clear failures, for an identifier without
// reporting it: nothing it writes is told to a lockout observer, reported as a
// security event, or advances a consecutive-failure streak.
//
// It exists for a second record of one attempt. A login by an identifier that
// resolves to another key, such as a verified email resolving to its account's
// username, records the failure under the key, which the lockout judges and
// reports, and again under the identifier as typed, which the automation
// challenge reads (FailureCount) so that a registered identifier accrues
// failures exactly as an unknown one does. Reporting that second record too
// would report one account's lock, hold or clearing twice, once under each
// name. The HTTP security chain therefore writes the typed identifier's record
// through this interface when the store it was given implements it, and
// through RecordFailure and Reset otherwise: a store that reports nothing has
// nothing to report twice.
//
// A consumer's wrapper around a lockout policy's view (Policy.Attempts) must
// forward this interface as well as AttemptStore. One that hides it receives
// plain writes, which the view reports, so the identifier as typed is
// reported a second time, as before this interface existed.
//
// The failures it writes land in the same store as any other, so FailureCount
// counts them, and a lockout judging that identifier as a key would count them
// too. What it skips is the reporting and the streak, not the record. The
// lockout policy's view (lockout.Policy.Attempts) implements it; with no
// observer, streak limit or sink, the result is the same as RecordFailure and
// Reset.
type UnreportedAttemptRecorder interface {
	// RecordFailureUnreported records one failed attempt for identifier at the
	// instant at, as AttemptStore.RecordFailure does, and reports nothing.
	RecordFailureUnreported(ctx context.Context, identifier string, at time.Time) error

	// ResetUnreported clears identifier's recorded failures, as
	// AttemptStore.Reset does, and reports nothing. It clears the identifier's
	// window and any hold or streak the store keeps under it without a
	// report, so a hold that identifier earned while it named no account
	// (reported then as ReportHeld) is lifted with no ReportReleased.
	ResetUnreported(ctx context.Context, identifier string) error
}

// AttemptViewRequirer is implemented by a policy whose decisions depend on
// failures being recorded through a view of its attempt store that it hands
// out, rather than through the store itself.
//
// It is the optional interface a wiring check reads. A component that records
// failures, such as an HTTP security chain's password logins, asks the engine
// for every view it must record into (Engine.RequiredAttemptViews) and refuses
// construction when it was given another store. A policy that does not
// implement it is taken to accept failures recorded into any store.
type AttemptViewRequirer interface {
	// RequiredAttemptView returns the view and true when failures must be
	// recorded through it, and false when any attempt store will do.
	RequiredAttemptView() (AttemptStore, bool)
}

// RequiredAttemptView names a registered policy, by its Name, and the view
// failures must be recorded through for it to decide correctly.
type RequiredAttemptView struct {
	Policy string
	View   AttemptStore
}
