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
	clk := clockwork.NewFakeClockAt(time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC))
	store := lockout.NewMemoryAttemptStore()

	p, err := lockout.New(
		lockout.WithWait(15*time.Minute, 15*time.Minute),
		lockout.WithAttemptStore(store),
		lockout.WithClock(clk),
	)
	if err != nil {
		fmt.Println(err)

		return
	}

	ctx := context.Background()
	for range 5 {
		if err := store.RecordFailure(ctx, "ada", clk.Now()); err != nil {
			fmt.Println(err)

			return
		}
	}

	d := p.Evaluate(ctx, &policy.Input{Username: "ada"})

	var locked *lockout.Error
	if errors.As(d.Reason, &locked) {
		fmt.Println(d.Outcome, locked.Wait)
	}

	clk.Advance(15 * time.Minute)
	fmt.Println(p.Evaluate(ctx, &policy.Input{Username: "ada"}).Outcome)
	// Output:
	// Deny 15m0s
	// Allow
}

// Reports go to the consumer's observer. The policy's view records failures and
// reports them, so the chain is handed p.Attempts() rather than the bare
// store.
func ExampleWithObserver() {
	p, err := lockout.New(
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
		_ = p.RecordFailure(ctx, "ada")
	}
	_ = p.Reset(ctx, "ada")

	// Output:
	// ada locked 5
	// ada cleared 5
}

// A cap at NIST's limit: one hundred consecutive failures hold the identifier,
// spaced so that each failure's wait has passed by the next, and the hold outlasts any
// wait. Only clearing its failures lifts it; here, the policy's Reset, which
// is the unlock an administrator or support tool calls.
func ExampleWithCap() {
	clk := clockwork.NewFakeClockAt(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	p, err := lockout.New(
		lockout.WithClock(clk),
		lockout.WithCap(lockout.NISTCap),
	)
	if err != nil {
		fmt.Println(err)

		return
	}

	ctx := context.Background()
	for range lockout.NISTCap {
		if err := p.Attempts().RecordFailure(ctx, "ada", clk.Now()); err != nil {
			fmt.Println(err)

			return
		}
		clk.Advance(2 * time.Hour)
	}

	d := p.Evaluate(ctx, &policy.Input{Username: "ada"})
	fmt.Println(d.Outcome, errors.Is(d.Reason, lockout.ErrAccountHeld))

	if err := p.Reset(ctx, "ada"); err != nil {
		fmt.Println(err)

		return
	}
	fmt.Println(p.Evaluate(ctx, &policy.Input{Username: "ada"}).Outcome)
	// Output:
	// Deny true
	// Allow
}
