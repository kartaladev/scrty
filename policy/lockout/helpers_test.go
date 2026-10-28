package lockout_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/policy/lockout"
)

// lockoutNow is the instant every lockout test judges against, so a case can
// name a failure's age rather than a wall-clock time.
var lockoutNow = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

// lockoutCutoff is the cutoff a 15-minute window puts behind lockoutNow, which
// is where the strictness of the window is decided.
var lockoutCutoff = lockoutNow.Add(-15 * time.Minute)

// errAttemptStoreDown is what a store that cannot answer reports, so a test can
// follow the cause through the decision it produced.
var errAttemptStoreDown = errors.New("the attempt store is unreachable")

// lockoutWith builds a policy over a fresh in-memory store and the tests'
// fixed clock, with opts applied after both, so a case can replace either.
func lockoutWith(t *testing.T, opts ...lockout.Option) *lockout.Policy {
	t.Helper()

	all := append([]lockout.Option{lockout.WithClock(clockwork.NewFakeClockAt(lockoutNow))}, opts...)
	p, err := lockout.New(all...)
	require.NoError(t, err)

	return p
}

// lockoutInput is a pre-authentication input naming username and nothing else:
// before credentials are checked, the submitted identifier is all there is.
func lockoutInput(username string) *policy.Input {
	return &policy.Input{Username: username}
}

// failuresEndingAt records n failures for username, the newest exactly newest
// before lockoutNow and each earlier one a second before the next, so a case
// pins both the count and the age of the newest failure.
func failuresEndingAt(username string, n int, newest time.Duration) func(*testing.T, *lockout.MemoryAttemptStore) {
	return func(t *testing.T, store *lockout.MemoryAttemptStore) {
		t.Helper()

		for i := range n {
			failuresAt(t, store, username, lockoutNow.Add(-newest-time.Duration(i)*time.Second))
		}
	}
}

// failuresAt records one failure per instant directly in the store, for the
// cases that pin a failure to the edge of the window.
func failuresAt(t *testing.T, store *lockout.MemoryAttemptStore, username string, at ...time.Time) {
	t.Helper()

	for _, instant := range at {
		require.NoError(t, store.RecordFailure(t.Context(), username, instant))
	}
}

// defaultCapRetention is the retention a cap takes when no
// WithCapRetention is given.
const defaultCapRetention = 30 * 24 * time.Hour

// failDaily records perDay[d] failures for username through the policy's view
// on the d-th day after the clock's current instant, a minute apart, advancing
// the fake clock to each failure so every add takes the cutoff of its own
// instant. It leaves the clock at the newest failure.
func failDaily(
	t *testing.T, p *lockout.Policy, clk *clockwork.FakeClock, username string, perDay ...int,
) {
	t.Helper()

	start := clk.Now()
	for d, n := range perDay {
		for i := range n {
			at := start.Add(time.Duration(d)*24*time.Hour + time.Duration(i)*time.Minute)
			clk.Advance(at.Sub(clk.Now()))
			require.NoError(t, p.Attempts().RecordFailure(t.Context(), username, clk.Now()))
		}
	}
}

// heldText is the text of a held refusal after n consecutive failures.
func heldText(n int) string {
	return fmt.Sprintf("lockout: account locked after repeated failures: held after %d consecutive failures", n)
}

// deniedAsHeld asserts the refusal of a held identifier: the account-locked
// refusal, identifiable as a hold, carrying no wait, in the library's words.
func deniedAsHeld(t *testing.T, d policy.Decision, failures int) {
	t.Helper()

	require.Equal(t, policy.Deny, d.Outcome, "a held identifier was allowed")
	require.ErrorIs(t, d.Reason, lockout.ErrAccountLocked)
	require.ErrorIs(t, d.Reason, lockout.ErrAccountHeld, "the refusal is not identifiable as a hold")

	var locked *lockout.Error
	require.ErrorAs(t, d.Reason, &locked)
	assert.Zero(t, locked.Wait, "a hold carries a wait, which no amount of waiting serves")
	assert.Equal(t, heldText(failures), d.Reason.Error())
	assert.NotErrorIs(t, d.Reason, policy.ErrDenied, "a hold was reported as a policy outage")
}

// streakAttemptStore is an attempt store that also keeps consecutive
// failures, as the in-memory and durable stores do, built from the two
// generated mocks so a test can expect calls on either half and order them
// across both.
type streakAttemptStore struct {
	*MockAttemptStore
	*MockFailureStreakStore
}

func newStreakAttemptStore(t *testing.T) *streakAttemptStore {
	t.Helper()

	ctrl := gomock.NewController(t)

	return &streakAttemptStore{
		MockAttemptStore:       NewMockAttemptStore(ctrl),
		MockFailureStreakStore: NewMockFailureStreakStore(ctrl),
	}
}

var (
	_ policy.AttemptStore        = (*streakAttemptStore)(nil)
	_ lockout.FailureStreakStore = (*streakAttemptStore)(nil)
)

// reportLog collects what an observer is told, safe for concurrent reports.
type reportLog struct {
	mu  sync.Mutex
	got []lockout.Report
}

func (l *reportLog) observe(_ context.Context, r lockout.Report) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.got = append(l.got, r)
}

func (l *reportLog) all() []lockout.Report {
	l.mu.Lock()
	defer l.mu.Unlock()

	return slices.Clone(l.got)
}
