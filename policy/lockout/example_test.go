package lockout_test

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jonboulle/clockwork"

	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/policy/lockout"
)

// A lock of fixed duration: once five failures fall in the day, the
// identifier is refused for exactly fifteen minutes after its newest one.
func ExampleWithWait_fixedDuration() {
	clock := clockwork.NewFakeClockAt(time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC))
	store, err := lockout.NewMemoryAttemptStore()
	if err != nil {
		fmt.Println(err)

		return
	}

	lockPolicy, err := lockout.New(
		lockout.WithWait(15*time.Minute, 15*time.Minute),
		lockout.WithAttemptStore(store),
		lockout.WithClock(clock),
	)
	if err != nil {
		fmt.Println(err)

		return
	}

	ctx := context.Background()
	for range 5 {
		if err := store.RecordFailure(ctx, "ada", clock.Now()); err != nil {
			fmt.Println(err)

			return
		}
	}

	decision := lockPolicy.Evaluate(ctx, &policy.Input{Username: "ada"})

	var locked *lockout.Error
	if errors.As(decision.Reason, &locked) {
		fmt.Println(decision.Outcome, locked.Wait)
	}

	clock.Advance(15 * time.Minute)
	fmt.Println(lockPolicy.Evaluate(ctx, &policy.Input{Username: "ada"}).Outcome)
	// Output:
	// Deny 15m0s
	// Allow
}

// Reports go to the consumer's observer. The policy's view records failures and
// reports them, so the chain is handed lockPolicy.Attempts() rather than the bare
// store.
func ExampleWithObserver() {
	lockPolicy, err := lockout.New(
		lockout.WithObserver(func(_ context.Context, r lockout.Report) {
			fmt.Println(r.Identifier, r.Kind, r.Failures)
		}),
	)
	if err != nil {
		fmt.Println(err)

		return
	}

	ctx := context.Background()
	for range 5 {
		_ = lockPolicy.RecordFailure(ctx, "ada")
	}
	_ = lockPolicy.Reset(ctx, "ada")

	// Output:
	// ada locked 5
	// ada cleared 5
}

// A cap at NIST's limit: one hundred consecutive failures hold the identifier,
// spaced so that each failure's wait has passed by the next, and the hold outlasts any
// wait. Only clearing its failures lifts it; here, the policy's Reset, which
// is the unlock an administrator or support tool calls.
func ExampleWithFailureStreakLimit() {
	clock := clockwork.NewFakeClockAt(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	lockPolicy, err := lockout.New(
		lockout.WithClock(clock),
		lockout.WithFailureStreakLimit(lockout.NISTFailureStreakLimit),
	)
	if err != nil {
		fmt.Println(err)

		return
	}

	ctx := context.Background()
	for range lockout.NISTFailureStreakLimit {
		if err := lockPolicy.Attempts().RecordFailure(ctx, "ada", clock.Now()); err != nil {
			fmt.Println(err)

			return
		}
		clock.Advance(2 * time.Hour)
	}

	decision := lockPolicy.Evaluate(ctx, &policy.Input{Username: "ada"})
	fmt.Println(decision.Outcome, errors.Is(decision.Reason, lockout.ErrAccountHeld))

	if err := lockPolicy.Reset(ctx, "ada"); err != nil {
		fmt.Println(err)

		return
	}
	fmt.Println(lockPolicy.Evaluate(ctx, &policy.Input{Username: "ada"}).Outcome)
	// Output:
	// Deny true
	// Allow
}
