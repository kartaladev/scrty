package unavailable_test

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/ratelimit"
)

// refusedUnavailable asserts a fail-closed answer that names the outage.
func refusedUnavailable(t *testing.T, exceeded bool, err error) {
	t.Helper()

	require.ErrorIs(t, err, ratelimit.ErrBackendUnavailable)
	assert.True(t, exceeded)
}

// TestUnavailable_Breaker covers task 4.2: an unavailable error opens the
// breaker, an open breaker answers without calling the backend, and after the
// probe interval exactly one call probes, closing the breaker on success and
// reopening it on failure. Scenarios "Backend down", "Refusal does not wait
// during an outage" and "Recovery after the outage", at the limiter.
//
// Every case runs in refuse mode and ends with one check of testKey; the mock
// fails any backend call a case did not expect.
func TestUnavailable_Breaker(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		arrange func(t *testing.T, h *harness)
		assert  func(t *testing.T, exceeded bool, err error)
	}

	cases := []testCase{
		{
			name: "an unavailable backend refuses, naming the outage but not the backend's text",
			arrange: func(_ *testing.T, h *harness) {
				h.backend.EXPECT().Exceeded(gomock.Any(), testKey).Return(false, errDown)
			},
			assert: func(t *testing.T, exceeded bool, err error) {
				refusedUnavailable(t, exceeded, err)
				require.ErrorIs(t, err, errDown)
				assert.NotContains(t, err.Error(), "10.0.0.1")
			},
		},
		{
			name: "within the probe interval a check is refused without the backend",
			arrange: func(t *testing.T, h *harness) {
				h.openBreaker(t)
				h.clock.Advance(defaultInterval - time.Nanosecond)
			},
			assert: refusedUnavailable,
		},
		{
			name: "after the probe interval one check probes and its answer is used",
			arrange: func(t *testing.T, h *harness) {
				h.openBreaker(t)
				h.clock.Advance(defaultInterval)
				h.backend.EXPECT().Exceeded(gomock.Any(), testKey).Return(false, nil)
			},
			assert: func(t *testing.T, exceeded bool, err error) {
				require.NoError(t, err)
				assert.False(t, exceeded)
			},
		},
		{
			name: "a successful probe closes the breaker",
			arrange: func(t *testing.T, h *harness) {
				h.openBreaker(t)
				h.clock.Advance(defaultInterval)
				h.backend.EXPECT().Exceeded(gomock.Any(), otherKey).Return(false, nil)
				_, err := h.limiter.Exceeded(t.Context(), otherKey)
				require.NoError(t, err)

				h.backend.EXPECT().Exceeded(gomock.Any(), testKey).Return(true, nil)
			},
			assert: func(t *testing.T, exceeded bool, err error) {
				require.NoError(t, err)
				assert.True(t, exceeded)
			},
		},
		{
			name: "a failed probe reopens the breaker",
			arrange: func(t *testing.T, h *harness) {
				h.openBreaker(t)
				h.clock.Advance(defaultInterval)
				h.backend.EXPECT().Exceeded(gomock.Any(), otherKey).Return(true, errDown)
				_, err := h.limiter.Exceeded(t.Context(), otherKey)
				require.ErrorIs(t, err, ratelimit.ErrBackendUnavailable)

				h.clock.Advance(defaultInterval - time.Nanosecond)
			},
			assert: refusedUnavailable,
		},
		{
			name: "a failed probe restarts the interval, after which the next check probes",
			arrange: func(t *testing.T, h *harness) {
				h.openBreaker(t)
				h.clock.Advance(defaultInterval)
				h.backend.EXPECT().Exceeded(gomock.Any(), otherKey).Return(true, errDown)
				_, _ = h.limiter.Exceeded(t.Context(), otherKey)

				h.clock.Advance(defaultInterval)
				h.backend.EXPECT().Exceeded(gomock.Any(), testKey).Return(false, nil)
			},
			assert: func(t *testing.T, exceeded bool, err error) {
				require.NoError(t, err)
				assert.False(t, exceeded)
			},
		},
		{
			name: "a failed record opens the breaker for checks",
			arrange: func(t *testing.T, h *harness) {
				h.backend.EXPECT().RecordFailure(gomock.Any(), otherKey).Return(errDown)
				require.ErrorIs(t, h.limiter.RecordFailure(t.Context(), otherKey), ratelimit.ErrBackendUnavailable)
			},
			assert: refusedUnavailable,
		},
		{
			name: "a check its caller abandons mid-call does not open the breaker",
			arrange: func(t *testing.T, h *harness) {
				ctx, cancel := context.WithCancel(t.Context())
				h.backend.EXPECT().Exceeded(gomock.Any(), otherKey).DoAndReturn(
					func(ctx context.Context, _ string) (bool, error) {
						cancel()
						return true, ctx.Err()
					})
				_, err := h.limiter.Exceeded(ctx, otherKey)
				require.ErrorIs(t, err, context.Canceled)
				require.NotErrorIs(t, err, ratelimit.ErrBackendUnavailable)

				h.backend.EXPECT().Exceeded(gomock.Any(), testKey).Return(false, nil)
			},
			assert: func(t *testing.T, exceeded bool, err error) {
				require.NoError(t, err)
				assert.False(t, exceeded)
			},
		},
		{
			name: "a probe its caller abandons lets the next check probe at once",
			arrange: func(t *testing.T, h *harness) {
				h.openBreaker(t)
				h.clock.Advance(defaultInterval)

				ctx, cancel := context.WithCancel(t.Context())
				h.backend.EXPECT().Exceeded(gomock.Any(), otherKey).DoAndReturn(
					func(ctx context.Context, _ string) (bool, error) {
						cancel()
						return true, ctx.Err()
					})
				_, err := h.limiter.Exceeded(ctx, otherKey)
				require.ErrorIs(t, err, context.Canceled)

				h.backend.EXPECT().Exceeded(gomock.Any(), testKey).Return(false, nil)
			},
			assert: func(t *testing.T, exceeded bool, err error) {
				require.NoError(t, err)
				assert.False(t, exceeded)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, ratelimit.UnavailableRefuse)
			tc.arrange(t, h)

			exceeded, err := h.limiter.Exceeded(t.Context(), testKey)
			tc.assert(t, exceeded, err)
		})
	}
}

// TestUnavailable_OneProbeUnderConcurrency covers task 4.2's concurrency rule:
// many callers arriving once the interval has passed send exactly one probe,
// and every other caller is answered from the mode without waiting for it.
func TestUnavailable_OneProbeUnderConcurrency(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		const callers = 50

		h := newHarness(t, ratelimit.UnavailableRefuse)
		h.openBreaker(t)
		h.clock.Advance(defaultInterval)

		release := make(chan struct{})
		h.backend.EXPECT().Exceeded(gomock.Any(), testKey).DoAndReturn(
			func(context.Context, string) (bool, error) {
				<-release
				return false, nil
			}).Times(1)

		type result struct {
			exceeded bool
			err      error
		}
		results := make([]result, callers)

		var wg sync.WaitGroup
		for i := range callers {
			wg.Go(func() {
				results[i].exceeded, results[i].err = h.limiter.Exceeded(t.Context(), testKey)
			})
		}

		// Every caller but the probe has now returned; the probe is still
		// inside the backend.
		synctest.Wait()
		close(release)
		wg.Wait()

		answered, refused := 0, 0
		for _, r := range results {
			switch {
			case r.err == nil && !r.exceeded:
				answered++
			default:
				refusedUnavailable(t, r.exceeded, r.err)
				refused++
			}
		}
		assert.Equal(t, 1, answered, "callers answered by the backend")
		assert.Equal(t, callers-1, refused, "callers refused without the backend")
	})
}

// TestUnavailable_ProbeTimeout covers task 4.2's timeout rule: a backend call
// that never answers is cut off at the operation timeout, opens (or reopens)
// the breaker, and the next check is refused without waiting at all.
func TestUnavailable_ProbeTimeout(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		arrange func(t *testing.T, h *harness)
		assert  func(t *testing.T, h *harness, elapsed time.Duration, exceeded bool, err error)
	}

	timedOutThenShortCircuited := func(t *testing.T, h *harness, elapsed time.Duration, exceeded bool, err error) {
		refusedUnavailable(t, exceeded, err)
		require.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Equal(t, defaultTimeout, elapsed, "the hung call was not cut off at the operation timeout")

		start := time.Now()
		exceeded, err = h.limiter.Exceeded(t.Context(), testKey)
		refusedUnavailable(t, exceeded, err)
		assert.Zero(t, time.Since(start), "a check during the outage waited")
	}

	cases := []testCase{
		{
			name:    "a call that times out opens the breaker",
			arrange: func(*testing.T, *harness) {},
			assert:  timedOutThenShortCircuited,
		},
		{
			name: "a probe that times out reopens the breaker",
			arrange: func(t *testing.T, h *harness) {
				h.openBreaker(t)
				h.clock.Advance(defaultInterval)
			},
			assert: timedOutThenShortCircuited,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				h := newHarness(t, ratelimit.UnavailableRefuse)
				tc.arrange(t, h)

				h.backend.EXPECT().Exceeded(gomock.Any(), testKey).DoAndReturn(
					func(ctx context.Context, _ string) (bool, error) {
						<-ctx.Done()
						return true, ctx.Err()
					}).Times(1)

				start := time.Now()
				exceeded, err := h.limiter.Exceeded(t.Context(), testKey)
				tc.assert(t, h, time.Since(start), exceeded, err)
			})
		})
	}
}

// TestUnavailable_PanickingProbe covers decision 5's panic rule: a probe whose
// backend call panics releases the probe slot as the panic leaves the limiter,
// so the next call probes the backend again rather than finding the breaker
// waiting on a probe that will never report. Without that, allow mode would
// answer "not exceeded" for good once a probe had panicked.
//
// Each case opens the breaker, lets the probe interval pass, and has the probe
// panic; the panic must still reach the caller. The final check of testKey must
// then reach the healthy backend.
func TestUnavailable_PanickingProbe(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name  string
		mode  ratelimit.UnavailableMode
		probe func(t *testing.T, h *harness)
	}

	panickingCheck := func(t *testing.T, h *harness) {
		h.backend.EXPECT().Exceeded(gomock.Any(), otherKey).DoAndReturn(
			func(context.Context, string) (bool, error) { panic("backend driver bug") })
		assert.PanicsWithValue(t, "backend driver bug", func() {
			_, _ = h.limiter.Exceeded(t.Context(), otherKey)
		})
	}
	panickingRecord := func(t *testing.T, h *harness) {
		h.backend.EXPECT().RecordFailure(gomock.Any(), otherKey).DoAndReturn(
			func(context.Context, string) error { panic("backend driver bug") })
		assert.PanicsWithValue(t, "backend driver bug", func() {
			_ = h.limiter.RecordFailure(t.Context(), otherKey)
		})
	}

	cases := []testCase{
		{name: "allow mode, a panicking check probe", mode: ratelimit.UnavailableAllow, probe: panickingCheck},
		{name: "allow mode, a panicking record probe", mode: ratelimit.UnavailableAllow, probe: panickingRecord},
		{name: "refuse mode, a panicking check probe", mode: ratelimit.UnavailableRefuse, probe: panickingCheck},
		{name: "fall-back mode, a panicking record probe", mode: ratelimit.UnavailableFallBackToLocal, probe: panickingRecord},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, tc.mode)
			h.openBreaker(t)
			h.clock.Advance(defaultInterval)
			tc.probe(t, h)

			// The backend is healthy again and the key is over its shared limit.
			h.backend.EXPECT().Exceeded(gomock.Any(), testKey).Return(true, nil)

			exceeded, err := h.limiter.Exceeded(t.Context(), testKey)
			require.NoError(t, err, "the check after the panic was not sent to the backend as a probe")
			assert.True(t, exceeded)
		})
	}
}

// nextOutageLoggedAtOnce asserts that allow mode has written only the first
// outage's record, and that an outage beginning now, well inside the sampling
// window, is logged at once: recovery freed the sampler's slot and nothing
// since has used it.
func nextOutageLoggedAtOnce(t *testing.T, h *harness) {
	t.Helper()

	assertRecords(t, h, slog.LevelError, msgAllow, 1)
	h.openBreaker(t)
	assertRecords(t, h, slog.LevelError, msgAllow, 2)
}

// TestUnavailable_StaleCalls covers decision 5's generation rule: only calls of
// the breaker's current generation change its state. A call admitted before
// the breaker last closed that fails afterwards cannot reopen it. In refuse
// mode a stale failed record still holds its own key, since the hold protects
// that key's count, not the breaker state, and fall-back mode still counts it
// locally. A stale failure is no outage, so it is never logged as one: allow
// mode writes no outage record for it, which would use up the sampling slot
// recovery freed and hide the next outage, and fall-back mode writes no second
// move to local counting.
//
// Each case starts one stale call that blocks inside the backend, opens the
// breaker with another call, closes it with a successful probe, then lets the
// stale call fail. The final check of testKey must reach the backend.
func TestUnavailable_StaleCalls(t *testing.T) {
	t.Parallel()

	const staleKey = "stale"

	type testCase struct {
		name   string
		mode   ratelimit.UnavailableMode
		stale  func(ctx context.Context, h *harness, release <-chan struct{})
		assert func(t *testing.T, h *harness)
	}

	staleCheck := func(ctx context.Context, h *harness, release <-chan struct{}) {
		h.backend.EXPECT().Exceeded(gomock.Any(), staleKey).DoAndReturn(
			func(context.Context, string) (bool, error) {
				<-release
				return true, errDown
			})
		_, _ = h.limiter.Exceeded(ctx, staleKey)
	}
	staleRecord := func(ctx context.Context, h *harness, release <-chan struct{}) {
		h.backend.EXPECT().RecordFailure(gomock.Any(), staleKey).DoAndReturn(
			func(context.Context, string) error {
				<-release
				return errDown
			})
		_ = h.limiter.RecordFailure(ctx, staleKey)
	}

	cases := []testCase{
		{
			name:   "refuse mode, a stale failed check",
			mode:   ratelimit.UnavailableRefuse,
			stale:  staleCheck,
			assert: func(*testing.T, *harness) {},
		},
		{
			name:  "refuse mode, a stale failed record still holds its own key",
			mode:  ratelimit.UnavailableRefuse,
			stale: staleRecord,
			assert: func(t *testing.T, h *harness) {
				exceeded, err := h.limiter.Exceeded(t.Context(), staleKey)
				refusedUnavailable(t, exceeded, err)
			},
		},
		{
			name:   "allow mode, a stale failed check writes no outage record, so the next outage is logged at once",
			mode:   ratelimit.UnavailableAllow,
			stale:  staleCheck,
			assert: nextOutageLoggedAtOnce,
		},
		{
			name:   "allow mode, a stale failed record writes no outage record, so the next outage is logged at once",
			mode:   ratelimit.UnavailableAllow,
			stale:  staleRecord,
			assert: nextOutageLoggedAtOnce,
		},
		{
			name:  "fall-back mode, a stale failed check writes no second move to local counting",
			mode:  ratelimit.UnavailableFallBackToLocal,
			stale: staleCheck,
			assert: func(t *testing.T, h *harness) {
				assertRecords(t, h, slog.LevelError, msgFallBack, 1)
			},
		},
		{
			name:  "fall-back mode, a stale failed record is still counted locally, with no second ERROR",
			mode:  ratelimit.UnavailableFallBackToLocal,
			stale: staleRecord,
			assert: func(t *testing.T, h *harness) {
				assertRecords(t, h, slog.LevelError, msgFallBack, 1)

				// The stale failure plus limit-1 more reach the local limit
				// only if the stale one was counted.
				h.down()
				for _, err := range h.recordN(t, staleKey, testLimit-1) {
					require.NoError(t, err)
				}
				exceeded, err := h.limiter.Exceeded(t.Context(), staleKey)
				require.NoError(t, err)
				assert.True(t, exceeded, "the stale failure was not counted locally")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				h := newHarness(t, tc.mode)

				release := make(chan struct{})
				var wg sync.WaitGroup
				wg.Go(func() { tc.stale(t.Context(), h, release) })
				synctest.Wait() // the stale call is now inside the backend

				h.openBreaker(t)
				h.clock.Advance(defaultInterval)
				h.backend.EXPECT().Exceeded(gomock.Any(), "probe").Return(false, nil)
				_, err := h.limiter.Exceeded(t.Context(), "probe")
				require.NoError(t, err, "the probe did not close the breaker")

				close(release)
				wg.Wait()

				h.backend.EXPECT().Exceeded(gomock.Any(), testKey).Return(false, nil)
				exceeded, err := h.limiter.Exceeded(t.Context(), testKey)
				require.NoError(t, err, "a stale failure reopened the breaker the probe had closed")
				assert.False(t, exceeded)

				tc.assert(t, h)
			})
		})
	}
}

// TestUnavailable_LateFailureWhileOpen pins decision 5's open-breaker rule: a
// call admitted while the breaker was closed, in the same generation, that
// fails after another call has opened it changes nothing. The probe stays due
// one interval after the breaker opened, not after the late failure, and the
// move to local counting is logged once.
//
// Each case blocks one call inside the backend, opens the breaker with another
// call, lets half an interval pass, then lets the blocked call fail. The final
// check of testKey, exactly one interval after the breaker opened, must probe.
func TestUnavailable_LateFailureWhileOpen(t *testing.T) {
	t.Parallel()

	const lateKey = "late"

	type testCase struct {
		name string
		late func(ctx context.Context, h *harness, release <-chan struct{})
	}

	cases := []testCase{
		{
			name: "a late failed check",
			late: func(ctx context.Context, h *harness, release <-chan struct{}) {
				h.backend.EXPECT().Exceeded(gomock.Any(), lateKey).DoAndReturn(
					func(context.Context, string) (bool, error) {
						<-release
						return true, errDown
					})
				_, _ = h.limiter.Exceeded(ctx, lateKey)
			},
		},
		{
			name: "a late failed record",
			late: func(ctx context.Context, h *harness, release <-chan struct{}) {
				h.backend.EXPECT().RecordFailure(gomock.Any(), lateKey).DoAndReturn(
					func(context.Context, string) error {
						<-release
						return errDown
					})
				_ = h.limiter.RecordFailure(ctx, lateKey)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				h := newHarness(t, ratelimit.UnavailableFallBackToLocal)

				release := make(chan struct{})
				var wg sync.WaitGroup
				wg.Go(func() { tc.late(t.Context(), h, release) })
				synctest.Wait() // the late call is now inside the backend

				h.openBreaker(t)
				h.clock.Advance(defaultInterval / 2)
				close(release)
				wg.Wait()

				// Just short of one interval since the breaker opened, the
				// check is answered locally; the mock fails a backend call.
				h.clock.Advance(defaultInterval/2 - time.Nanosecond)
				_, err := h.limiter.Exceeded(t.Context(), testKey)
				require.NoError(t, err)

				h.clock.Advance(time.Nanosecond)
				h.backend.EXPECT().Exceeded(gomock.Any(), testKey).Return(false, nil)
				exceeded, err := h.limiter.Exceeded(t.Context(), testKey)
				require.NoError(t, err)
				assert.False(t, exceeded)

				assertRecords(t, h, slog.LevelError, msgFallBack, 1)
				assertRecords(t, h, slog.LevelWarn, msgRecovered, 1)
			})
		})
	}
}

// TestUnavailable_CallerDeadlineShorterThanTimeout pins decision 5's caller
// deadline rule: a caller whose own deadline ends before the operation timeout
// is the caller ending, not the backend failing, so it never opens the breaker.
// Against a hung backend each such caller waits its own deadline, and a check
// with a live context afterwards still reaches the backend.
func TestUnavailable_CallerDeadlineShorterThanTimeout(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		const callerDeadline = 100 * time.Millisecond

		h := newHarness(t, ratelimit.UnavailableRefuse)
		h.backend.EXPECT().Exceeded(gomock.Any(), otherKey).DoAndReturn(
			func(ctx context.Context, _ string) (bool, error) {
				<-ctx.Done()
				return true, ctx.Err()
			}).Times(3)

		for range 3 {
			ctx, cancel := context.WithTimeout(t.Context(), callerDeadline)
			start := time.Now()
			exceeded, err := h.limiter.Exceeded(ctx, otherKey)
			elapsed := time.Since(start)
			cancel()

			assert.True(t, exceeded)
			require.ErrorIs(t, err, context.DeadlineExceeded)
			assert.NotErrorIs(t, err, ratelimit.ErrBackendUnavailable)
			assert.Equal(t, callerDeadline, elapsed, "the caller did not wait its own deadline")
		}

		h.backend.EXPECT().Exceeded(gomock.Any(), testKey).Return(false, nil)
		exceeded, err := h.limiter.Exceeded(t.Context(), testKey)
		require.NoError(t, err, "a caller's own deadline opened the breaker")
		assert.False(t, exceeded)
	})
}
