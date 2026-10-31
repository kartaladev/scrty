// The charge cases are one table where they share a fake clock and one limiter,
// and separate TestXxx functions where goroutines race at a barrier.
package ratelimit_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/ratelimit"
)

// TestReceipt pins that a receipt carries back exactly the key and stamp it
// was made with, which is what lets a limiter in another package find its
// failure again.
func TestReceipt(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		receipt ratelimit.Receipt
		assert  func(t *testing.T, r ratelimit.Receipt)
	}

	cases := []testCase{
		{
			name:    "made with a key and a stamp",
			receipt: ratelimit.NewReceipt("flow|source", epoch),
			assert: func(t *testing.T, r ratelimit.Receipt) {
				assert.Equal(t, "flow|source", r.Key())
				assert.True(t, r.Stamp().Equal(epoch), "stamp %s, want %s", r.Stamp(), epoch)
			},
		},
		{
			name:    "zero",
			receipt: ratelimit.Receipt{},
			assert: func(t *testing.T, r ratelimit.Receipt) {
				assert.Empty(t, r.Key())
				assert.True(t, r.Stamp().IsZero())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.receipt)
		})
	}
}

// TestMemoryLimiter_Charge pins the in-memory charge and refund: what a
// receipt names, what a refused charge leaves behind, the key cap, an ended
// context, and the refunds that must remove nothing.
func TestMemoryLimiter_Charge(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// maxKeys is passed with WithMemoryLimiterMaxKeys; zero passes no
		// option, so the default applies.
		maxKeys int
		ctx     func(ctx context.Context) context.Context // nil means unchanged
		setup   func(t *testing.T, l *ratelimit.MemoryLimiter, clk *clockwork.FakeClock)
		// key is the key charged.
		key    string
		assert func(t *testing.T, l *ratelimit.MemoryLimiter, clk *clockwork.FakeClock,
			r ratelimit.Receipt, exceeded bool, err error)
	}

	noSetup := func(*testing.T, *ratelimit.MemoryLimiter, *clockwork.FakeClock) {}
	fillAB := func(t *testing.T, l *ratelimit.MemoryLimiter, _ *clockwork.FakeClock) {
		recordFor(t, l, "a", "b")
	}
	ended := func(ctx context.Context) context.Context {
		ctx, cancel := context.WithCancel(ctx)
		cancel()
		return ctx
	}

	cases := []testCase{
		{
			name:  "an accepted charge returns the receipt of the stamp it recorded",
			setup: noSetup,
			key:   "k",
			assert: func(t *testing.T, l *ratelimit.MemoryLimiter, clk *clockwork.FakeClock,
				r ratelimit.Receipt, exceeded bool, err error,
			) {
				require.NoError(t, err)
				assert.False(t, exceeded)
				assert.Equal(t, "k", r.Key())
				assert.True(t, r.Stamp().Equal(clk.Now()), "stamp %s, want %s", r.Stamp(), clk.Now())
				assert.Equal(t, 1, l.StampsFor("k"))
			},
		},
		{
			name: "a charge at the limit is refused with the zero receipt",
			setup: func(t *testing.T, l *ratelimit.MemoryLimiter, _ *clockwork.FakeClock) {
				recordFor(t, l, "k", "k", "k")
			},
			key: "k",
			assert: func(t *testing.T, _ *ratelimit.MemoryLimiter, _ *clockwork.FakeClock,
				r ratelimit.Receipt, exceeded bool, err error,
			) {
				require.NoError(t, err)
				assert.True(t, exceeded)
				assert.Equal(t, ratelimit.Receipt{}, r)
			},
		},
		{
			name:    "a new key on a full limiter is refused with ErrLimiterFull and stores nothing",
			maxKeys: 2,
			setup:   fillAB,
			key:     "c",
			assert: func(t *testing.T, l *ratelimit.MemoryLimiter, _ *clockwork.FakeClock,
				r ratelimit.Receipt, exceeded bool, err error,
			) {
				require.ErrorIs(t, err, ratelimit.ErrLimiterFull)
				assert.True(t, exceeded, "a full limiter must refuse a key it does not hold")
				assert.Equal(t, ratelimit.Receipt{}, r)
				assert.Zero(t, l.StampsFor("c"), "a refused charge stored a stamp")
			},
		},
		{
			name:    "a held key on a full limiter is charged",
			maxKeys: 2,
			setup:   fillAB,
			key:     "a",
			assert: func(t *testing.T, l *ratelimit.MemoryLimiter, _ *clockwork.FakeClock,
				_ ratelimit.Receipt, exceeded bool, err error,
			) {
				require.NoError(t, err)
				assert.False(t, exceeded)
				assert.Equal(t, 2, l.StampsFor("a"))
			},
		},
		{
			// An ended context is the caller's error, and says nothing about
			// whether the limiter had room.
			name:    "an ended context is refused with its error, records nothing, and is not a full limiter",
			maxKeys: 2,
			ctx:     ended,
			setup:   fillAB,
			key:     "c",
			assert: func(t *testing.T, l *ratelimit.MemoryLimiter, _ *clockwork.FakeClock,
				r ratelimit.Receipt, exceeded bool, err error,
			) {
				require.ErrorIs(t, err, context.Canceled)
				assert.NotErrorIs(t, err, ratelimit.ErrLimiterFull, "an ended context was reported as a full limiter")
				assert.True(t, exceeded)
				assert.Equal(t, ratelimit.Receipt{}, r)
				assert.Zero(t, l.StampsFor("c"))
			},
		},
		{
			name:    "a refund removes the stamp and gives back the key's place",
			maxKeys: 1,
			setup:   noSetup,
			key:     "a",
			assert: func(t *testing.T, l *ratelimit.MemoryLimiter, _ *clockwork.FakeClock,
				r ratelimit.Receipt, _ bool, err error,
			) {
				require.NoError(t, err)
				require.NoError(t, l.Refund(t.Context(), r))
				assert.Zero(t, l.StampsFor("a"))

				_, exceeded, err := l.Charge(t.Context(), "b")
				require.NoError(t, err, "the refunded key kept its place under the cap")
				assert.False(t, exceeded)
			},
		},
		{
			name:  "a refund of the zero receipt removes nothing",
			setup: noSetup,
			key:   "k",
			assert: func(t *testing.T, l *ratelimit.MemoryLimiter, _ *clockwork.FakeClock,
				_ ratelimit.Receipt, _ bool, err error,
			) {
				require.NoError(t, err)
				require.NoError(t, l.Refund(t.Context(), ratelimit.Receipt{}))
				assert.Equal(t, 1, l.StampsFor("k"))
			},
		},
		{
			name:  "a refund of a stamp the key does not hold removes nothing",
			setup: noSetup,
			key:   "k",
			assert: func(t *testing.T, l *ratelimit.MemoryLimiter, _ *clockwork.FakeClock,
				r ratelimit.Receipt, _ bool, err error,
			) {
				require.NoError(t, err)
				other := ratelimit.NewReceipt("k", r.Stamp().Add(1))
				require.NoError(t, l.Refund(t.Context(), other))
				assert.Equal(t, 1, l.StampsFor("k"))
			},
		},
		{
			name:    "a refund for a key the limiter does not hold takes no place",
			maxKeys: 1,
			setup:   noSetup,
			key:     "a",
			assert: func(t *testing.T, l *ratelimit.MemoryLimiter, clk *clockwork.FakeClock,
				r ratelimit.Receipt, _ bool, err error,
			) {
				require.NoError(t, err)
				require.NoError(t, l.Refund(t.Context(), ratelimit.NewReceipt("ghost", clk.Now())))
				assert.Zero(t, l.StampsFor("ghost"))
				assert.Equal(t, 1, l.StampsFor("a"))
				require.NoError(t, l.Refund(t.Context(), r))

				_, exceeded, err := l.Charge(t.Context(), "b")
				require.NoError(t, err)
				assert.False(t, exceeded)
			},
		},
		{
			// The stamp is still stored, because no sweep has run, but the
			// window no longer counts it.
			name:  "a refund after the window removes nothing",
			setup: noSetup,
			key:   "k",
			assert: func(t *testing.T, l *ratelimit.MemoryLimiter, clk *clockwork.FakeClock,
				r ratelimit.Receipt, _ bool, err error,
			) {
				require.NoError(t, err)
				clk.Advance(testWindow)
				require.NoError(t, l.Refund(t.Context(), r))
				assert.Equal(t, 1, l.StampsFor("k"))
			},
		},
		{
			// The second charge is a second later. At the same instant the
			// two stamps would be equal, and Charger's godoc states that a
			// receipt refunded twice may then take the other charge's.
			name:  "a second refund of one receipt removes nothing more",
			setup: noSetup,
			key:   "k",
			assert: func(t *testing.T, l *ratelimit.MemoryLimiter, clk *clockwork.FakeClock,
				r ratelimit.Receipt, _ bool, err error,
			) {
				require.NoError(t, err)
				clk.Advance(time.Second)
				_, _, err = l.Charge(t.Context(), "k")
				require.NoError(t, err)
				require.NoError(t, l.Refund(t.Context(), r))
				require.NoError(t, l.Refund(t.Context(), r))
				assert.Equal(t, 1, l.StampsFor("k"), "one receipt refunded two charges")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(epoch)
			opts := []ratelimit.MemoryOption{
				ratelimit.WithMemoryLimiterClock(clk),
				ratelimit.WithMemoryLimiterLogger(discardLogger()),
			}
			if tc.maxKeys > 0 {
				opts = append(opts, ratelimit.WithMemoryLimiterMaxKeys(tc.maxKeys))
			}
			l, err := ratelimit.NewMemoryLimiter(testLimit, testWindow, opts...)
			require.NoError(t, err)
			tc.setup(t, l, clk)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}
			r, exceeded, err := l.Charge(ctx, tc.key)
			tc.assert(t, l, clk, r, exceeded, err)
		})
	}
}

// TestMemoryLimiter_ConcurrentChargesStopAtTheLimit releases 64 charges per key
// at one barrier, over keys in different shards, and pins that each key
// accepts exactly its limit and holds that many stamps.
func TestMemoryLimiter_ConcurrentChargesStopAtTheLimit(t *testing.T) {
	t.Parallel()

	const (
		limit   = 5
		keys    = 4
		callers = 64
	)
	l, err := ratelimit.NewMemoryLimiter(limit, testWindow,
		ratelimit.WithMemoryLimiterClock(clockwork.NewFakeClockAt(epoch)),
		ratelimit.WithMemoryLimiterLogger(discardLogger()))
	require.NoError(t, err)

	var accepted [keys]int
	var mu sync.Mutex
	start := make(chan struct{})
	var ready, done sync.WaitGroup
	for i := range keys * callers {
		ready.Add(1)
		done.Go(func() {
			ready.Done()
			<-start
			_, exceeded, err := l.Charge(t.Context(), fmt.Sprintf("k%d", i%keys))
			assert.NoError(t, err)
			if !exceeded {
				mu.Lock()
				accepted[i%keys]++
				mu.Unlock()
			}
		})
	}
	ready.Wait()
	close(start)
	done.Wait()

	for k := range keys {
		key := fmt.Sprintf("k%d", k)
		assert.Equal(t, limit, accepted[k], "charges accepted for %q", key)
		assert.Equal(t, limit, l.StampsFor(key), "stamps held for %q", key)
	}
}

// TestMemoryLimiter_ConcurrentChargeAndRefundBalance has every caller refund
// the charge it was granted, on a clock that does not move, so every stamp is
// equal. Each refund must remove exactly one, so the key ends empty and gives
// its place back.
func TestMemoryLimiter_ConcurrentChargeAndRefundBalance(t *testing.T) {
	t.Parallel()

	const callers = 64
	l, err := ratelimit.NewMemoryLimiter(testLimit, testWindow,
		ratelimit.WithMemoryLimiterClock(clockwork.NewFakeClockAt(epoch)),
		ratelimit.WithMemoryLimiterLogger(discardLogger()),
		ratelimit.WithMemoryLimiterMaxKeys(1))
	require.NoError(t, err)

	start := make(chan struct{})
	var ready, done sync.WaitGroup
	for range callers {
		ready.Add(1)
		done.Go(func() {
			ready.Done()
			<-start
			for range 10 {
				r, exceeded, err := l.Charge(t.Context(), "k")
				assert.NoError(t, err)
				if !exceeded {
					assert.NoError(t, l.Refund(t.Context(), r))
				}
			}
		})
	}
	ready.Wait()
	close(start)
	done.Wait()

	assert.Zero(t, l.StampsFor("k"), "refunds did not remove exactly the failures charged")
	_, exceeded, err := l.Charge(t.Context(), "other")
	require.NoError(t, err, "the emptied key kept its place under the cap")
	assert.False(t, exceeded)
}
