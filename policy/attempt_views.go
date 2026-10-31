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
//go:generate mockgen -source=attempt_views.go -package=policy_test -destination=attempt_views_mock_test.go -typed -exclude_interfaces=AttemptViewRequirer
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
