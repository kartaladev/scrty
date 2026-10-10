package policy_test

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/policy"
)

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
	_ policy.AttemptStore       = (*streakAttemptStore)(nil)
	_ policy.FailureStreakStore = (*streakAttemptStore)(nil)
)

// errLogDown is the failure log's own outage, distinct from the streak's.
var errLogDown = errors.New("failure log down")

// defaultCapRetention is the retention a cap takes when no
// WithLockoutCapRetention is given.
const defaultCapRetention = 30 * 24 * time.Hour

// TestLockoutCapView pins what the policy's view writes when a failure is
// recorded or cleared: without a cap the view never touches the streak, and
// with one the streak is advanced first, with the policy's cutoff and cap,
// and then the failure log.
func TestLockoutCapView(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []policy.LockoutOption
		expect func(s *streakAttemptStore)
		act    func(t *testing.T, p *policy.AccountLockoutPolicy) error
		assert func(t *testing.T, p *policy.AccountLockoutPolicy, s *streakAttemptStore, err error)
	}

	recordAda := func(t *testing.T, p *policy.AccountLockoutPolicy) error {
		t.Helper()

		return p.RecordFailure(t.Context(), "ada")
	}

	cases := []testCase{
		{
			name: "without a cap the view is the store and never touches the streak",
			expect: func(s *streakAttemptStore) {
				s.MockAttemptStore.EXPECT().RecordFailure(gomock.Any(), "ada", lockoutNow).Return(nil)
			},
			act: recordAda,
			assert: func(t *testing.T, p *policy.AccountLockoutPolicy, s *streakAttemptStore, err error) {
				require.NoError(t, err)
				assert.Same(t, s, p.Attempts(), "a policy without a cap or observer wrapped its store")
			},
		},
		{
			name: "with a cap the streak is written before the log",
			opts: []policy.LockoutOption{policy.WithLockoutCap(policy.NISTLockoutCap)},
			expect: func(s *streakAttemptStore) {
				gomock.InOrder(
					s.MockFailureStreakStore.EXPECT().
						AddStreakFailure(gomock.Any(), "ada", lockoutNow, lockoutNow.Add(-defaultCapRetention), 100).
						Return(policy.FailureStreak{Failures: 1, Newest: lockoutNow}, false, nil),
					s.MockAttemptStore.EXPECT().RecordFailure(gomock.Any(), "ada", lockoutNow).Return(nil),
				)
			},
			act: recordAda,
			assert: func(t *testing.T, _ *policy.AccountLockoutPolicy, _ *streakAttemptStore, err error) {
				require.NoError(t, err)
			},
		},
		{
			// A login endpoint records through the view at its own instant,
			// and the cutoff is taken from that instant, not the policy's
			// clock.
			name: "the view handed to an endpoint advances the streak with a consumer cap and retention",
			opts: []policy.LockoutOption{
				policy.WithLockoutCap(20),
				policy.WithLockoutCapRetention(7 * 24 * time.Hour),
			},
			expect: func(s *streakAttemptStore) {
				at := lockoutNow.Add(-time.Hour)
				gomock.InOrder(
					s.MockFailureStreakStore.EXPECT().
						AddStreakFailure(gomock.Any(), "ada", at, at.Add(-7*24*time.Hour), 20).
						Return(policy.FailureStreak{Failures: 1, Newest: at}, false, nil),
					s.MockAttemptStore.EXPECT().RecordFailure(gomock.Any(), "ada", at).Return(nil),
				)
			},
			act: func(t *testing.T, p *policy.AccountLockoutPolicy) error {
				t.Helper()

				return p.Attempts().RecordFailure(t.Context(), "ada", lockoutNow.Add(-time.Hour))
			},
			assert: func(t *testing.T, _ *policy.AccountLockoutPolicy, _ *streakAttemptStore, err error) {
				require.NoError(t, err)
			},
		},
		{
			// The streak goes first because it cannot be rebuilt, but a failure
			// to write it does not skip the log: the log entry alone keeps the
			// windowed lock counting while the streak store is failing.
			name: "a failed streak write is returned and the log is still written",
			opts: []policy.LockoutOption{policy.WithLockoutCap(policy.NISTLockoutCap)},
			expect: func(s *streakAttemptStore) {
				gomock.InOrder(
					s.MockFailureStreakStore.EXPECT().
						AddStreakFailure(gomock.Any(), "ada", lockoutNow, lockoutNow.Add(-defaultCapRetention), 100).
						Return(policy.FailureStreak{}, false, errAttemptStoreDown),
					s.MockAttemptStore.EXPECT().RecordFailure(gomock.Any(), "ada", lockoutNow).Return(nil),
				)
			},
			act: recordAda,
			assert: func(t *testing.T, _ *policy.AccountLockoutPolicy, _ *streakAttemptStore, err error) {
				require.ErrorIs(t, err, errAttemptStoreDown)
				assert.NotContains(t, err.Error(), errAttemptStoreDown.Error(),
					"the store's own text reached the caller")
			},
		},
		{
			name: "when both writes fail both errors are returned",
			opts: []policy.LockoutOption{policy.WithLockoutCap(policy.NISTLockoutCap)},
			expect: func(s *streakAttemptStore) {
				gomock.InOrder(
					s.MockFailureStreakStore.EXPECT().
						AddStreakFailure(gomock.Any(), "ada", lockoutNow, lockoutNow.Add(-defaultCapRetention), 100).
						Return(policy.FailureStreak{}, false, errAttemptStoreDown),
					s.MockAttemptStore.EXPECT().RecordFailure(gomock.Any(), "ada", lockoutNow).Return(errLogDown),
				)
			},
			act: recordAda,
			assert: func(t *testing.T, _ *policy.AccountLockoutPolicy, _ *streakAttemptStore, err error) {
				require.ErrorIs(t, err, errAttemptStoreDown)
				require.ErrorIs(t, err, errLogDown)
			},
		},
		{
			name: "a failed log write after the streak is returned",
			opts: []policy.LockoutOption{policy.WithLockoutCap(policy.NISTLockoutCap)},
			expect: func(s *streakAttemptStore) {
				gomock.InOrder(
					s.MockFailureStreakStore.EXPECT().
						AddStreakFailure(gomock.Any(), "ada", lockoutNow, lockoutNow.Add(-defaultCapRetention), 100).
						Return(policy.FailureStreak{Failures: 1, Newest: lockoutNow}, false, nil),
					s.MockAttemptStore.EXPECT().RecordFailure(gomock.Any(), "ada", lockoutNow).Return(errAttemptStoreDown),
				)
			},
			act: recordAda,
			assert: func(t *testing.T, _ *policy.AccountLockoutPolicy, _ *streakAttemptStore, err error) {
				require.ErrorIs(t, err, errAttemptStoreDown)
			},
		},
		{
			// With a cap and no observer there is nothing to report, so a
			// reset is the store's Reset, which clears the streak with the log.
			name: "with a cap and no observer a reset only clears through the store",
			opts: []policy.LockoutOption{policy.WithLockoutCap(policy.NISTLockoutCap)},
			expect: func(s *streakAttemptStore) {
				s.MockAttemptStore.EXPECT().Reset(gomock.Any(), "ada").Return(nil)
			},
			act: func(t *testing.T, p *policy.AccountLockoutPolicy) error {
				t.Helper()

				return p.Reset(t.Context(), "ada")
			},
			assert: func(t *testing.T, _ *policy.AccountLockoutPolicy, _ *streakAttemptStore, err error) {
				require.NoError(t, err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := newStreakAttemptStore(t)
			tc.expect(s)

			p, err := policy.NewAccountLockoutPolicy(append([]policy.LockoutOption{
				policy.WithAttemptStore(s),
				policy.WithLockoutClock(clockwork.NewFakeClockAt(lockoutNow)),
			}, tc.opts...)...)
			require.NoError(t, err)

			tc.assert(t, p, s, tc.act(t, p))
		})
	}
}

// failDaily records perDay[d] failures for username through the policy's view
// on the d-th day after the clock's current instant, a minute apart, advancing
// the fake clock to each failure so every add takes the cutoff of its own
// instant. It leaves the clock at the newest failure.
func failDaily(
	t *testing.T, p *policy.AccountLockoutPolicy, clk *clockwork.FakeClock, username string, perDay ...int,
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
	return fmt.Sprintf("policy: account locked after repeated failures: held after %d consecutive failures", n)
}

// deniedAsHeld asserts the refusal of a held identifier: the account-locked
// refusal, identifiable as a hold, carrying no wait, in the library's words.
func deniedAsHeld(t *testing.T, d policy.Decision, failures int) {
	t.Helper()

	require.Equal(t, policy.Deny, d.Outcome, "a held identifier was allowed")
	require.ErrorIs(t, d.Reason, policy.ErrAccountLocked)
	require.ErrorIs(t, d.Reason, policy.ErrAccountHeld, "the refusal is not identifiable as a hold")

	var locked *policy.LockoutError
	require.ErrorAs(t, d.Reason, &locked)
	assert.Zero(t, locked.Wait, "a hold carries a wait, which no amount of waiting serves")
	assert.Equal(t, heldText(failures), d.Reason.Error())
	assert.NotErrorIs(t, d.Reason, policy.ErrPolicyDenied, "a hold was reported as a policy outage")
}

// TestLockoutCapEvaluate pins pre-authentication under a cap: a held
// identifier is refused first, however old its failures, and otherwise the
// windowed evaluation decides as it always has.
func TestLockoutCapEvaluate(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		opts []policy.LockoutOption
		// store builds the attempt store; nil means a fresh in-memory one.
		store func(t *testing.T) policy.AttemptStore
		// seed records failures through the policy and moves the clock to
		// the instant pre-authentication runs at.
		seed   func(t *testing.T, p *policy.AccountLockoutPolicy, clk *clockwork.FakeClock)
		assert func(t *testing.T, p *policy.AccountLockoutPolicy, d policy.Decision)
	}

	twentyADayForFiveDays := []int{20, 20, 20, 20, 20}

	cases := []testCase{
		{
			// Spec: "No cap by default".
			name: "no cap by default",
			seed: func(t *testing.T, p *policy.AccountLockoutPolicy, clk *clockwork.FakeClock) {
				t.Helper()

				failDaily(t, p, clk, "ada", twentyADayForFiveDays...)
				clk.Advance(2 * time.Hour)
			},
			assert: func(t *testing.T, _ *policy.AccountLockoutPolicy, d policy.Decision) {
				assert.Equal(t, policy.Allow, d.Outcome, "a policy with no cap refused: %v", d.Reason)
			},
		},
		{
			// Spec: "Cap reached across days" and "Held refusal".
			name: "a cap of 100 reached across five days holds",
			opts: []policy.LockoutOption{policy.WithLockoutCap(policy.NISTLockoutCap)},
			seed: func(t *testing.T, p *policy.AccountLockoutPolicy, clk *clockwork.FakeClock) {
				t.Helper()

				failDaily(t, p, clk, "ada", twentyADayForFiveDays...)
				clk.Advance(3 * 24 * time.Hour)
			},
			assert: func(t *testing.T, _ *policy.AccountLockoutPolicy, d policy.Decision) {
				deniedAsHeld(t, d, 100)
			},
		},
		{
			// Spec: "Consumer cap".
			name: "a consumer cap of 20 reached over two days holds",
			opts: []policy.LockoutOption{policy.WithLockoutCap(20)},
			seed: func(t *testing.T, p *policy.AccountLockoutPolicy, clk *clockwork.FakeClock) {
				t.Helper()

				failDaily(t, p, clk, "ada", 10, 10)
				clk.Advance(2 * time.Hour)
			},
			assert: func(t *testing.T, _ *policy.AccountLockoutPolicy, d policy.Decision) {
				deniedAsHeld(t, d, 20)
			},
		},
		{
			// A failure recorded through the view at a zero instant is recorded
			// at the policy's clock: at the zero instant the hold would be set
			// at time zero, which reads as no hold at all.
			name: "failures recorded at a zero instant through the view still hold",
			opts: []policy.LockoutOption{policy.WithLockoutCap(20)},
			seed: func(t *testing.T, p *policy.AccountLockoutPolicy, _ *clockwork.FakeClock) {
				t.Helper()

				for range 25 {
					require.NoError(t, p.Attempts().RecordFailure(t.Context(), "ada", time.Time{}))
				}
			},
			assert: func(t *testing.T, _ *policy.AccountLockoutPolicy, d policy.Decision) {
				require.Equal(t, policy.Deny, d.Outcome, "a hold set at a zero instant was allowed")
				require.ErrorIs(t, d.Reason, policy.ErrAccountHeld)
			},
		},
		{
			// Spec: "Below the cap".
			name: "ninety-nine failures under a cap of 100 are allowed",
			opts: []policy.LockoutOption{policy.WithLockoutCap(policy.NISTLockoutCap)},
			seed: func(t *testing.T, p *policy.AccountLockoutPolicy, clk *clockwork.FakeClock) {
				t.Helper()

				failDaily(t, p, clk, "ada", 20, 20, 20, 20, 19)
				clk.Advance(2 * 24 * time.Hour)
			},
			assert: func(t *testing.T, _ *policy.AccountLockoutPolicy, d policy.Decision) {
				assert.Equal(t, policy.Allow, d.Outcome, "a count below the cap refused: %v", d.Reason)
			},
		},
		{
			// Spec: "Unknown identifiers are held alike". The policy cannot
			// tell them apart, and its refusal must not either.
			name: "an identifier with no account is held with the same refusal",
			opts: []policy.LockoutOption{policy.WithLockoutCap(20)},
			seed: func(t *testing.T, p *policy.AccountLockoutPolicy, clk *clockwork.FakeClock) {
				t.Helper()

				failDaily(t, p, clk, "ada", 10, 10)
				failDaily(t, p, clk, "nobody", 10, 10)
				clk.Advance(2 * time.Hour)
			},
			assert: func(t *testing.T, p *policy.AccountLockoutPolicy, d policy.Decision) {
				deniedAsHeld(t, d, 20)

				other := p.Evaluate(t.Context(), lockoutInput("nobody"))
				deniedAsHeld(t, other, 20)
				assert.Equal(t, d.Reason.Error(), other.Reason.Error(),
					"the refusal tells a known identifier from an unknown one")
			},
		},
		{
			// Spec: "A windowed lock is not a hold".
			name: "a windowed lock under a cap is not a hold",
			opts: []policy.LockoutOption{policy.WithLockoutCap(policy.NISTLockoutCap)},
			seed: func(t *testing.T, p *policy.AccountLockoutPolicy, clk *clockwork.FakeClock) {
				t.Helper()

				for range 7 {
					clk.Advance(time.Second)
					require.NoError(t, p.Attempts().RecordFailure(t.Context(), "ada", clk.Now()))
				}
				clk.Advance(10 * time.Second)
			},
			assert: func(t *testing.T, _ *policy.AccountLockoutPolicy, d policy.Decision) {
				require.Equal(t, policy.Deny, d.Outcome)
				require.ErrorIs(t, d.Reason, policy.ErrAccountLocked)
				assert.NotErrorIs(t, d.Reason, policy.ErrAccountHeld, "a windowed lock was reported as a hold")

				var locked *policy.LockoutError
				require.ErrorAs(t, d.Reason, &locked)
				assert.Equal(t, 120*time.Second, locked.Wait)
				assert.Equal(t, "policy: account locked after repeated failures: 7 failures within 24h0m0s",
					d.Reason.Error())
			},
		},
		{
			// Spec: "Unreadable hold". The windowed count is never asked: a
			// policy that cannot tell whether an identifier is held does not
			// know enough to allow it.
			name: "a streak that cannot be read denies, wrapping the store's error",
			opts: []policy.LockoutOption{policy.WithLockoutCap(policy.NISTLockoutCap)},
			store: func(t *testing.T) policy.AttemptStore {
				t.Helper()

				s := newStreakAttemptStore(t)
				s.MockFailureStreakStore.EXPECT().
					FailureStreak(gomock.Any(), "ada", lockoutNow.Add(-defaultCapRetention)).
					Return(policy.FailureStreak{}, errAttemptStoreDown)

				return s
			},
			assert: func(t *testing.T, _ *policy.AccountLockoutPolicy, d policy.Decision) {
				require.Equal(t, policy.Deny, d.Outcome, "an unreadable hold was allowed")
				require.ErrorIs(t, d.Reason, policy.ErrPolicyDenied)
				require.ErrorIs(t, d.Reason, errAttemptStoreDown)
				assert.NotErrorIs(t, d.Reason, policy.ErrAccountLocked,
					"an outage was reported as a lock the policy does not know of")
				assert.NotContains(t, d.Reason.Error(), errAttemptStoreDown.Error(),
					"the store's own text reached the reason")
			},
		},
		{
			// Spec: "A hold outlives every window".
			name: "a hold set ninety days ago still holds",
			opts: []policy.LockoutOption{policy.WithLockoutCap(policy.NISTLockoutCap)},
			seed: func(t *testing.T, p *policy.AccountLockoutPolicy, clk *clockwork.FakeClock) {
				t.Helper()

				failDaily(t, p, clk, "ada", 100)
				clk.Advance(90 * 24 * time.Hour)
			},
			assert: func(t *testing.T, _ *policy.AccountLockoutPolicy, d policy.Decision) {
				deniedAsHeld(t, d, 100)
			},
		},
		{
			// Spec: "The correct password does not lift a hold".
			// Pre-authentication runs before the password is checked, so
			// whatever the login presents, the hold refuses it; and evaluating
			// writes nothing, so the identifier is still held afterwards. The
			// mock expects the two reads and nothing else.
			name: "pre-authentication refuses a held identifier and leaves it held",
			opts: []policy.LockoutOption{policy.WithLockoutCap(policy.NISTLockoutCap)},
			store: func(t *testing.T) policy.AttemptStore {
				t.Helper()

				heldAt := lockoutNow.Add(-time.Hour)
				s := newStreakAttemptStore(t)
				s.MockFailureStreakStore.EXPECT().
					FailureStreak(gomock.Any(), "ada", lockoutNow.Add(-defaultCapRetention)).
					Return(policy.FailureStreak{Failures: 100, Newest: heldAt, HeldAt: heldAt}, nil).
					Times(2)

				return s
			},
			assert: func(t *testing.T, p *policy.AccountLockoutPolicy, d policy.Decision) {
				deniedAsHeld(t, d, 100)
				deniedAsHeld(t, p.Evaluate(t.Context(), lockoutInput("ada")), 100)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var store policy.AttemptStore = policy.NewMemoryAttemptStore()
			if tc.store != nil {
				store = tc.store(t)
			}
			clk := clockwork.NewFakeClockAt(lockoutNow)

			p, err := policy.NewAccountLockoutPolicy(append([]policy.LockoutOption{
				policy.WithAttemptStore(store),
				policy.WithLockoutClock(clk),
			}, tc.opts...)...)
			require.NoError(t, err)

			if tc.seed != nil {
				tc.seed(t, p, clk)
			}

			tc.assert(t, p, p.Evaluate(t.Context(), lockoutInput("ada")))
		})
	}
}

// TestLockoutCapRetention pins how long a consecutive count lives and what
// lifts a hold: a count below the cap restarts after the retention, a hold
// never expires, and the policy's Reset lifts it with the window.
func TestLockoutCapRetention(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		opts []policy.LockoutOption
		// seed records failures through the policy and moves the clock to
		// the instant pre-authentication runs at.
		seed   func(t *testing.T, p *policy.AccountLockoutPolicy, clk *clockwork.FakeClock)
		assert func(t *testing.T, store policy.FailureStreakStore, now time.Time, d policy.Decision)
	}

	// streakOf reads ada's streak straight from the store, with the cutoff
	// the policy would use at now under retention.
	streakOf := func(
		t *testing.T, store policy.FailureStreakStore, now time.Time, retention time.Duration,
	) policy.FailureStreak {
		t.Helper()

		s, err := store.FailureStreak(t.Context(), "ada", now.Add(-retention))
		require.NoError(t, err)

		return s
	}

	cases := []testCase{
		{
			// Spec: "Inactive count restarts".
			name: "a count inactive for longer than the retention restarts",
			opts: []policy.LockoutOption{policy.WithLockoutCap(policy.NISTLockoutCap)},
			seed: func(t *testing.T, p *policy.AccountLockoutPolicy, clk *clockwork.FakeClock) {
				t.Helper()

				failDaily(t, p, clk, "ada", 99)
				clk.Advance(31 * 24 * time.Hour)
				require.NoError(t, p.Attempts().RecordFailure(t.Context(), "ada", clk.Now()))
			},
			assert: func(t *testing.T, store policy.FailureStreakStore, now time.Time, d policy.Decision) {
				assert.Equal(t, policy.Allow, d.Outcome, "a restarted count refused: %v", d.Reason)

				s := streakOf(t, store, now, defaultCapRetention)
				assert.Equal(t, 1, s.Failures, "the inactive count did not restart")
				assert.False(t, s.Held())
			},
		},
		{
			// Spec: "Consumer retention".
			name: "a consumer retention of seven days restarts a count eight days old",
			opts: []policy.LockoutOption{
				policy.WithLockoutCap(policy.NISTLockoutCap),
				policy.WithLockoutCapRetention(7 * 24 * time.Hour),
			},
			seed: func(t *testing.T, p *policy.AccountLockoutPolicy, clk *clockwork.FakeClock) {
				t.Helper()

				failDaily(t, p, clk, "ada", 99)
				clk.Advance(8 * 24 * time.Hour)
				require.NoError(t, p.Attempts().RecordFailure(t.Context(), "ada", clk.Now()))
			},
			assert: func(t *testing.T, store policy.FailureStreakStore, now time.Time, d policy.Decision) {
				assert.Equal(t, policy.Allow, d.Outcome, "a restarted count refused: %v", d.Reason)
				assert.Equal(t, 1, streakOf(t, store, now, 7*24*time.Hour).Failures,
					"the count did not restart after the consumer's retention")
			},
		},
		{
			// The retention is the consumer's, not the default: a count six
			// days old under seven days of retention still counts.
			name: "a consumer retention of seven days keeps a count six days old",
			opts: []policy.LockoutOption{
				policy.WithLockoutCap(policy.NISTLockoutCap),
				policy.WithLockoutCapRetention(7 * 24 * time.Hour),
			},
			seed: func(t *testing.T, p *policy.AccountLockoutPolicy, clk *clockwork.FakeClock) {
				t.Helper()

				failDaily(t, p, clk, "ada", 99)
				clk.Advance(6 * 24 * time.Hour)
				require.NoError(t, p.Attempts().RecordFailure(t.Context(), "ada", clk.Now()))
				clk.Advance(2 * time.Hour)
			},
			assert: func(t *testing.T, _ policy.FailureStreakStore, _ time.Time, d policy.Decision) {
				deniedAsHeld(t, d, 100)
			},
		},
		{
			// Spec: "A hold does not expire".
			name: "a hold set thirty-one days ago still holds",
			opts: []policy.LockoutOption{policy.WithLockoutCap(policy.NISTLockoutCap)},
			seed: func(t *testing.T, p *policy.AccountLockoutPolicy, clk *clockwork.FakeClock) {
				t.Helper()

				failDaily(t, p, clk, "ada", 100)
				clk.Advance(31 * 24 * time.Hour)
			},
			assert: func(t *testing.T, _ policy.FailureStreakStore, _ time.Time, d policy.Decision) {
				deniedAsHeld(t, d, 100)
			},
		},
		{
			// Spec: "Reset unlocks". The hold, the count and the failures in
			// the window go together: with any of them left, ada would still
			// be refused, held or at the ceiling.
			name: "the policy's reset lifts a hold and clears the window",
			opts: []policy.LockoutOption{policy.WithLockoutCap(policy.NISTLockoutCap)},
			seed: func(t *testing.T, p *policy.AccountLockoutPolicy, clk *clockwork.FakeClock) {
				t.Helper()

				failDaily(t, p, clk, "ada", 100)
				clk.Advance(time.Minute)
				deniedAsHeld(t, p.Evaluate(t.Context(), lockoutInput("ada")), 100)

				require.NoError(t, p.Reset(t.Context(), "ada"))
			},
			assert: func(t *testing.T, store policy.FailureStreakStore, now time.Time, d policy.Decision) {
				assert.Equal(t, policy.Allow, d.Outcome, "a reset left ada refused: %v", d.Reason)
				assert.Zero(t, streakOf(t, store, now, defaultCapRetention), "a reset left a streak behind")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := policy.NewMemoryAttemptStore()
			clk := clockwork.NewFakeClockAt(lockoutNow)

			p, err := policy.NewAccountLockoutPolicy(append([]policy.LockoutOption{
				policy.WithAttemptStore(store),
				policy.WithLockoutClock(clk),
			}, tc.opts...)...)
			require.NoError(t, err)

			tc.seed(t, p, clk)

			tc.assert(t, store, clk.Now(), p.Evaluate(t.Context(), lockoutInput("ada")))
		})
	}
}

// streakReaperStore is an attempt store that keeps consecutive failures and
// can purge its log, as the durable stores can, built from the three
// generated mocks on one controller.
type streakReaperStore struct {
	*MockAttemptStore
	*MockFailureStreakStore
	*MockAttemptReaper
}

func newStreakReaperStore(t *testing.T) *streakReaperStore {
	t.Helper()

	ctrl := gomock.NewController(t)

	return &streakReaperStore{
		MockAttemptStore:       NewMockAttemptStore(ctrl),
		MockFailureStreakStore: NewMockFailureStreakStore(ctrl),
		MockAttemptReaper:      NewMockAttemptReaper(ctrl),
	}
}

var (
	_ policy.FailureStreakStore = (*streakReaperStore)(nil)
	_ policy.AttemptReaper      = (*streakReaperStore)(nil)
)

// TestLockoutCapPurge pins what a purge removes under a cap: the inactive
// streaks behind the policy's own retention, after the failures behind its
// window, and nothing of the streaks without a cap.
func TestLockoutCapPurge(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []policy.LockoutOption
		store  func(t *testing.T) policy.AttemptStore
		assert func(t *testing.T, removed int, err error)
	}

	windowCutoff := lockoutNow.Add(-24 * time.Hour)

	cases := []testCase{
		{
			name: "with a cap the inactive streaks behind the retention are purged too",
			opts: []policy.LockoutOption{policy.WithLockoutCap(policy.NISTLockoutCap)},
			store: func(t *testing.T) policy.AttemptStore {
				s := newStreakReaperStore(t)
				gomock.InOrder(
					s.MockAttemptReaper.EXPECT().DeleteAttemptsBefore(gomock.Any(), windowCutoff).Return(3, nil),
					s.MockFailureStreakStore.EXPECT().
						DeleteStreaksBefore(gomock.Any(), lockoutNow.Add(-defaultCapRetention)).Return(2, nil),
				)

				return s
			},
			assert: func(t *testing.T, removed int, err error) {
				require.NoError(t, err)
				assert.Equal(t, 5, removed, "the total is not the failures and the streaks together")
			},
		},
		{
			name: "the streaks are purged behind the consumer's retention",
			opts: []policy.LockoutOption{
				policy.WithLockoutCap(policy.NISTLockoutCap),
				policy.WithLockoutCapRetention(7 * 24 * time.Hour),
			},
			store: func(t *testing.T) policy.AttemptStore {
				s := newStreakReaperStore(t)
				s.MockAttemptReaper.EXPECT().DeleteAttemptsBefore(gomock.Any(), windowCutoff).Return(0, nil)
				s.MockFailureStreakStore.EXPECT().
					DeleteStreaksBefore(gomock.Any(), lockoutNow.Add(-7*24*time.Hour)).Return(4, nil)

				return s
			},
			assert: func(t *testing.T, removed int, err error) {
				require.NoError(t, err)
				assert.Equal(t, 4, removed)
			},
		},
		{
			// The mock expects no streak call: one would fail the case.
			name: "without a cap the streaks are never touched",
			store: func(t *testing.T) policy.AttemptStore {
				s := newStreakReaperStore(t)
				s.MockAttemptReaper.EXPECT().DeleteAttemptsBefore(gomock.Any(), windowCutoff).Return(3, nil)

				return s
			},
			assert: func(t *testing.T, removed int, err error) {
				require.NoError(t, err)
				assert.Equal(t, 3, removed)
			},
		},
		{
			name: "a streak purge that failed is returned behind the library's text",
			opts: []policy.LockoutOption{policy.WithLockoutCap(policy.NISTLockoutCap)},
			store: func(t *testing.T) policy.AttemptStore {
				s := newStreakReaperStore(t)
				s.MockAttemptReaper.EXPECT().DeleteAttemptsBefore(gomock.Any(), windowCutoff).Return(3, nil)
				s.MockFailureStreakStore.EXPECT().
					DeleteStreaksBefore(gomock.Any(), gomock.Any()).Return(0, errAttemptStoreDown)

				return s
			},
			assert: func(t *testing.T, _ int, err error) {
				require.ErrorIs(t, err, errAttemptStoreDown)
				assert.NotContains(t, err.Error(), errAttemptStoreDown.Error(),
					"the store's own text reached the caller")
			},
		},
		{
			name: "a failed attempt purge leaves the streaks alone",
			opts: []policy.LockoutOption{policy.WithLockoutCap(policy.NISTLockoutCap)},
			store: func(t *testing.T) policy.AttemptStore {
				s := newStreakReaperStore(t)
				s.MockAttemptReaper.EXPECT().DeleteAttemptsBefore(gomock.Any(), windowCutoff).Return(0, errAttemptStoreDown)

				return s
			},
			assert: func(t *testing.T, _ int, err error) {
				require.ErrorIs(t, err, errAttemptStoreDown)
			},
		},
		{
			// The in-memory store keeps streaks but cannot purge its log: the
			// purge is unsupported, as without a cap.
			name: "with a cap a store that cannot purge its log reports the purge unsupported",
			opts: []policy.LockoutOption{policy.WithLockoutCap(policy.NISTLockoutCap)},
			store: func(*testing.T) policy.AttemptStore {
				return policy.NewMemoryAttemptStore()
			},
			assert: func(t *testing.T, removed int, err error) {
				require.ErrorIs(t, err, policy.ErrReapUnsupported)
				assert.Zero(t, removed)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p, err := policy.NewAccountLockoutPolicy(append([]policy.LockoutOption{
				policy.WithAttemptStore(tc.store(t)),
				policy.WithLockoutClock(clockwork.NewFakeClockAt(lockoutNow)),
			}, tc.opts...)...)
			require.NoError(t, err)

			removed, err := p.PurgeExpired(t.Context())
			tc.assert(t, removed, err)
		})
	}
}

// memoryReaperStore is the in-memory store, whose streaks are real, given a
// mocked log purge, so a purge can be run over streaks it really removes.
type memoryReaperStore struct {
	*policy.MemoryAttemptStore
	*MockAttemptReaper
}

// TestLockoutCapPurgeKeepsHolds is the spec scenario "Inactive counts are
// purged, holds are kept", run over real streaks rather than mocked ones, so
// it shows what goes and what stays rather than which cutoff is passed.
func TestLockoutCapPurgeKeepsHolds(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(lockoutNow)
	store := &memoryReaperStore{
		MemoryAttemptStore: policy.NewMemoryAttemptStore(),
		MockAttemptReaper:  NewMockAttemptReaper(gomock.NewController(t)),
	}
	p, err := policy.NewAccountLockoutPolicy(
		policy.WithAttemptStore(store),
		policy.WithLockoutClock(clk),
		policy.WithLockoutCap(policy.NISTLockoutCap),
	)
	require.NoError(t, err)

	failDaily(t, p, clk, "ada", 10)
	failDaily(t, p, clk, "bob", 100)
	clk.Advance(31 * 24 * time.Hour)
	now := clk.Now()

	// Read with a cutoff old enough to see the inactive count, so its removal
	// is shown by the store and not by the read's own cutoff.
	longAgo := lockoutNow.Add(-time.Hour)
	before, err := store.FailureStreak(t.Context(), "ada", longAgo)
	require.NoError(t, err)
	require.Equal(t, 10, before.Failures, "the seed is not what the scenario needs")

	store.MockAttemptReaper.EXPECT().DeleteAttemptsBefore(gomock.Any(), now.Add(-24*time.Hour)).Return(110, nil)

	removed, err := p.PurgeExpired(t.Context())
	require.NoError(t, err)
	assert.Equal(t, 111, removed, "the purge did not count one inactive streak")

	after, err := store.FailureStreak(t.Context(), "ada", longAgo)
	require.NoError(t, err)
	assert.Zero(t, after, "the inactive count for ada was kept")

	deniedAsHeld(t, p.Evaluate(t.Context(), lockoutInput("bob")), 100)
}

// TestLockoutCapBurst is the spec scenario "Burst across the cap": twenty
// failures recorded at once from a count of 90 under a cap of 100 lose none
// of the count and set the hold exactly once, so it is reported once. A view
// that read the streak and then wrote it in two steps would let several
// writes each see the crossing and report it.
func TestLockoutCapBurst(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(lockoutNow)
	store := policy.NewMemoryAttemptStore()
	got := &reportLog{}
	p, err := policy.NewAccountLockoutPolicy(
		policy.WithAttemptStore(store),
		policy.WithLockoutClock(clk),
		policy.WithLockoutCap(policy.NISTLockoutCap),
		policy.WithLockoutObserver(got.observe),
	)
	require.NoError(t, err)

	failDaily(t, p, clk, "ada", 30, 30, 30)
	now := clk.Now()

	const burst = 20
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range burst {
		wg.Go(func() {
			<-start
			assert.NoError(t, p.Attempts().RecordFailure(t.Context(), "ada", now))
		})
	}
	close(start)
	wg.Wait()

	streak, err := store.FailureStreak(t.Context(), "ada", now.Add(-defaultCapRetention))
	require.NoError(t, err)
	assert.Equal(t, 110, streak.Failures, "the burst lost failures from the count")
	assert.True(t, streak.Held(), "the burst passed the cap without a hold")

	var held []policy.LockoutReport
	for _, r := range got.all() {
		if r.Kind == policy.LockoutHeld {
			held = append(held, r)
		}
	}
	require.Len(t, held, 1, "the hold was not reported exactly once")
	assert.Equal(t, policy.LockoutReport{Identifier: "ada", Kind: policy.LockoutHeld, Failures: 100, At: now}, held[0])
}
