package lockout_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/internal/eventsink"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/policy/lockout"
)

// unreportedOutcome is what a row of TestLockoutViewUnreported observed.
type unreportedOutcome struct {
	err     error
	policy  *lockout.Policy
	store   policy.AttemptStore
	reports []lockout.Report
	events  []event.Event
	// chainEvents are the events delivered through the request's emitter, as
	// the HTTP security chain's sink receives them.
	chainEvents []event.Event
}

// TestLockoutViewUnreported pins the view's unreported record: a failure or a
// reset written through it lands in the policy's store, counted as any other,
// but is told to no observer, reported as no security event, whether the
// policy's own sink or the request's, and advances no consecutive-failure
// streak. A zero instant is recorded at the policy's clock, and a store that
// fails is returned.
func TestLockoutViewUnreported(t *testing.T) {
	t.Parallel()

	const id = "ada@example.com"

	type testCase struct {
		name string
		// store, when set, replaces the in-memory store.
		store  func(t *testing.T) policy.AttemptStore
		run    func(ctx context.Context, r policy.UnreportedAttemptRecorder) error
		assert func(t *testing.T, got unreportedOutcome)
	}

	countOf := func(t *testing.T, got unreportedOutcome) int {
		t.Helper()

		n, err := got.store.FailureCount(t.Context(), id, lockoutCutoff)
		require.NoError(t, err)

		return n
	}

	cases := []testCase{
		{
			name: "failures past every limit are counted and report nothing",
			run: func(ctx context.Context, r policy.UnreportedAttemptRecorder) error {
				for range 6 {
					if err := r.RecordFailureUnreported(ctx, id, lockoutNow); err != nil {
						return err
					}
				}

				return nil
			},
			assert: func(t *testing.T, got unreportedOutcome) {
				require.NoError(t, got.err)
				assert.Equal(t, 6, countOf(t, got), "every failure is recorded")
				assert.Empty(t, got.reports, "nothing is told to the observer")
				assert.Empty(t, got.events, "no event reaches the policy's sink")
				assert.Empty(t, got.chainEvents, "no event reaches the request's sink")

				// Six reported failures would have held it under the limit of 6.
				streaks, ok := got.store.(lockout.FailureStreakStore)
				require.True(t, ok)
				streak, err := streaks.FailureStreak(t.Context(), id, lockoutNow.Add(-365*24*time.Hour))
				require.NoError(t, err)
				assert.Zero(t, streak.Failures, "no streak advanced")
				assert.False(t, streak.Held(), "no hold set")
			},
		},
		{
			name: "a reset clears and reports nothing",
			run: func(ctx context.Context, r policy.UnreportedAttemptRecorder) error {
				for range 3 {
					if err := r.RecordFailureUnreported(ctx, id, lockoutNow); err != nil {
						return err
					}
				}

				return r.ResetUnreported(ctx, id)
			},
			assert: func(t *testing.T, got unreportedOutcome) {
				require.NoError(t, got.err)
				assert.Zero(t, countOf(t, got), "the reset cleared the failures")
				assert.Empty(t, got.reports, "no clearing is told to the observer")
				assert.Empty(t, got.events)
				assert.Empty(t, got.chainEvents)
			},
		},
		{
			name: "a zero instant is recorded at the policy's clock",
			run: func(ctx context.Context, r policy.UnreportedAttemptRecorder) error {
				return r.RecordFailureUnreported(ctx, id, time.Time{})
			},
			assert: func(t *testing.T, got unreportedOutcome) {
				require.NoError(t, got.err)
				assert.Equal(t, 1, countOf(t, got), "counted inside the window, not at the zero instant")
			},
		},
		{
			name: "a store that cannot record is returned",
			store: func(t *testing.T) policy.AttemptStore {
				s := NewMockAttemptStore(gomock.NewController(t))
				s.EXPECT().RecordFailure(gomock.Any(), id, lockoutNow).Return(errAttemptStoreDown).Times(1)

				return s
			},
			run: func(ctx context.Context, r policy.UnreportedAttemptRecorder) error {
				return r.RecordFailureUnreported(ctx, id, lockoutNow)
			},
			assert: func(t *testing.T, got unreportedOutcome) {
				require.ErrorIs(t, got.err, errAttemptStoreDown)
				assert.Empty(t, got.reports)
				assert.Empty(t, got.events)
			},
		},
		{
			name: "a store that cannot reset is returned",
			store: func(t *testing.T) policy.AttemptStore {
				s := NewMockAttemptStore(gomock.NewController(t))
				s.EXPECT().Reset(gomock.Any(), id).Return(errAttemptStoreDown).Times(1)

				return s
			},
			run: func(ctx context.Context, r policy.UnreportedAttemptRecorder) error {
				return r.ResetUnreported(ctx, id)
			},
			assert: func(t *testing.T, got unreportedOutcome) {
				require.ErrorIs(t, got.err, errAttemptStoreDown)
				assert.Empty(t, got.reports)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var (
				reports reportLog
				events  eventLog
				chain   eventLog
			)

			opts := []lockout.Option{
				lockout.WithSliding(5, 15*time.Minute),
				lockout.WithObserver(reports.observe),
				lockout.WithSecurityEvents(events.sink),
			}

			var store policy.AttemptStore
			if tc.store != nil {
				store = tc.store(t)
			} else {
				mem, err := lockout.NewMemoryAttemptStore()
				require.NoError(t, err)
				store = mem
				// The streak limit needs a store that keeps streaks.
				opts = append(opts, lockout.WithFailureStreakLimit(6))
			}
			opts = append(opts, lockout.WithAttemptStore(store))

			p := lockoutWith(t, opts...)

			r, ok := p.Attempts().(policy.UnreportedAttemptRecorder)
			require.True(t, ok, "the policy's view records unreported")

			ctx := eventsink.With(t.Context(), chain.sink)

			got := unreportedOutcome{err: tc.run(ctx, r), policy: p, store: store}
			got.reports = reports.all()
			got.events = events.all()
			got.chainEvents = chain.all()

			tc.assert(t, got)
		})
	}
}
