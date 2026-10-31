package recovery_test

import (
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/recovery"
)

// TestCodes_ConcurrentWrongCodesStayWithinLimit pins that the presentation
// limit holds under concurrency: however many presentations for one user
// arrive at once, no more codes are looked up than the limit allows, and a
// valid code spends none of the allowance.
//
// The limiter is the default policy, built by the in-memory factory and held
// behind a barrier: every caller waits after its limit decision until all of
// them have decided, so a check that is recorded later lets the whole burst
// through, as it would under real contention.
func TestCodes_ConcurrentWrongCodesStayWithinLimit(t *testing.T) {
	t.Parallel()

	const burst = 20

	type testCase struct {
		name string
		// barrier is how many callers the limiter holds after their limit
		// decision; zero holds none.
		barrier int
		ctx     func(ctx context.Context) context.Context
		// present makes the case's presentations, and returns their errors.
		present func(t *testing.T, ctx context.Context, c *recovery.Codes) []error
		assert  func(t *testing.T, errs []error, matches int64)
	}

	concurrentWrongCodes := func(t *testing.T, ctx context.Context, c *recovery.Codes) []error {
		codes := distinctWrongCodes(t, burst)
		errs := make([]error, burst)

		var wg sync.WaitGroup
		for i, code := range codes {
			wg.Go(func() { errs[i] = c.Confirm(ctx, "u-1", code) })
		}
		wg.Wait()

		return errs
	}
	withinLimit := func(t *testing.T, errs []error, matches int64) {
		require.LessOrEqual(t, matches, int64(5), "codes looked up in a burst of %d", burst)

		refused, throttled := 0, 0
		for _, err := range errs {
			switch {
			case err == nil:
				t.Error("a wrong code was accepted")
			case errors.Is(err, recovery.ErrCodeThrottled):
				throttled++
			case errors.Is(err, recovery.ErrRefused):
				refused++
			default:
				t.Errorf("a presentation failed with neither refusal: %v", err)
			}
		}
		assert.Equal(t, int(matches), refused, "every code looked up is refused as wrong")
		assert.Equal(t, burst-int(matches), throttled, "every code not looked up is throttled")
	}

	cases := []testCase{
		{
			name:    "a concurrent burst of wrong codes stays within the limit",
			barrier: burst,
			present: concurrentWrongCodes,
			assert:  withinLimit,
		},
		{
			name:    "a concurrent burst on ended contexts stays within the limit",
			barrier: burst,
			ctx: func(ctx context.Context) context.Context {
				ctx, cancel := context.WithCancel(ctx)
				cancel()

				return ctx
			},
			present: concurrentWrongCodes,
			assert:  withinLimit,
		},
		{
			name: "a valid code spends no allowance",
			present: func(t *testing.T, ctx context.Context, c *recovery.Codes) []error {
				codes, err := c.Generate(ctx, "u-1")
				require.NoError(t, err)
				require.NotEmpty(t, codes)

				valid := codes[0]
				require.NoError(t, c.Confirm(ctx, "u-1", valid))

				var errs []error
				for _, code := range distinctWrongCodes(t, 5) {
					errs = append(errs, c.Confirm(ctx, "u-1", code))
				}

				return errs
			},
			assert: func(t *testing.T, errs []error, matches int64) {
				require.Len(t, errs, 5)
				for i, err := range errs {
					assert.ErrorIs(t, err, recovery.ErrRefused, "wrong code %d of 5", i+1)
				}
				assert.Equal(t, int64(6), matches,
					"the valid code and all five wrong ones are looked up")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &matchCountingStore{MemoryCodeStore: recovery.NewMemoryCodeStore()}
			factory := &barrierFactory{
				inner: ratelimit.MemoryLimiterFactory(
					ratelimit.WithMemoryLimiterLogger(slog.New(slog.DiscardHandler))),
				callers: tc.barrier,
			}
			c := newCodes(t, recovery.WithCodesStore(store), recovery.WithCodesLimiterFactory(factory))

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			errs := tc.present(t, ctx, c)
			require.False(t, factory.timedOut(), "callers were held at the barrier and never released")
			tc.assert(t, errs, store.matches.Load())
		})
	}
}

// distinctWrongCodes returns n distinct, well-formed codes that no user holds.
func distinctWrongCodes(t *testing.T, n int) []string {
	t.Helper()

	codes := make([]string, n)
	for i := range codes {
		text, _, err := recovery.NewCode(rand.Reader)
		require.NoError(t, err)
		codes[i] = text
	}

	return codes
}

// matchCountingStore is the in-memory code store, counting its lookups.
type matchCountingStore struct {
	*recovery.MemoryCodeStore

	matches atomic.Int64
}

func (s *matchCountingStore) Match(ctx context.Context, user identity.UserID, hash []byte) (bool, error) {
	s.matches.Add(1)

	return s.MemoryCodeStore.Match(ctx, user, hash)
}

// barrierTimeout bounds how long a caller waits at the barrier, so a caller
// that never makes a limit decision fails the test rather than hanging it.
const barrierTimeout = 10 * time.Second

// barrierFactory builds the limiters of inner, each held behind a barrier of
// callers.
type barrierFactory struct {
	inner   ratelimit.LimiterFactory
	callers int

	mu    sync.Mutex
	built []*barrierLimiter
}

func (f *barrierFactory) NewLimiter(namespace string, limit int, window time.Duration) (ratelimit.Limiter, error) {
	l, err := f.inner.NewLimiter(namespace, limit, window)
	if err != nil {
		return nil, err
	}

	b := &barrierLimiter{Limiter: l, callers: int64(f.callers), released: make(chan struct{})}
	b.arrived.Add(f.callers)
	go func() { b.arrived.Wait(); close(b.released) }()

	f.mu.Lock()
	f.built = append(f.built, b)
	f.mu.Unlock()

	return b, nil
}

// timedOut reports whether any caller gave up waiting at a barrier.
func (f *barrierFactory) timedOut() bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	for _, b := range f.built {
		if b.timedOut.Load() {
			return true
		}
	}

	return false
}

// barrierLimiter holds each of its first callers after its limit decision,
// Exceeded or Charge, until all of them have decided. A later caller, and
// every caller of a barrier of none, is not held.
type barrierLimiter struct {
	ratelimit.Limiter

	callers  int64
	decided  atomic.Int64
	arrived  sync.WaitGroup
	released chan struct{}
	timedOut atomic.Bool
}

func (l *barrierLimiter) Exceeded(ctx context.Context, key string) (bool, error) {
	exceeded, err := l.Limiter.Exceeded(ctx, key)
	l.hold()

	return exceeded, err
}

func (l *barrierLimiter) Charge(ctx context.Context, key string) (ratelimit.Receipt, bool, error) {
	r, exceeded, err := l.Limiter.Charge(ctx, key)
	l.hold()

	return r, exceeded, err
}

func (l *barrierLimiter) hold() {
	if l.decided.Add(1) > l.callers {
		return
	}

	l.arrived.Done()

	select {
	case <-l.released:
	case <-time.After(barrierTimeout):
		l.timedOut.Store(true)
	}
}
