package unavailable_test

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/internal/unavailable"
	"github.com/kartaladev/scrty/ratelimit"
)

// endingHandler is a slog.Handler that ends a context, as a caller hanging up
// does, when it is handed a record, and then passes the record on.
type endingHandler struct {
	slog.Handler

	end func()
}

func (h endingHandler) Handle(ctx context.Context, rec slog.Record) error {
	h.end()

	return h.Handler.Handle(ctx, rec)
}

// chargesDown makes every backend charge and refund fail, as many times as
// they are called.
func (h *harness) chargesDown() {
	h.backend.EXPECT().Charge(gomock.Any(), gomock.Any()).Return(ratelimit.Receipt{}, true, errDown).AnyTimes()
	h.backend.EXPECT().Refund(gomock.Any(), gomock.Any()).Return(errDown).AnyTimes()
}

// chargeN charges key n times through the decorator, and fails the test
// unless every charge is accepted without an error. It returns the receipts.
func (h *harness) chargeN(t *testing.T, key string, n int) []ratelimit.Receipt {
	t.Helper()

	receipts := make([]ratelimit.Receipt, n)
	for i := range n {
		r, exceeded, err := h.limiter.Charge(t.Context(), key)
		require.NoError(t, err, "charge %d of %d", i+1, n)
		require.False(t, exceeded, "charge %d of %d was refused", i+1, n)
		require.NotZero(t, r, "charge %d of %d returned the zero receipt", i+1, n)
		receipts[i] = r
	}

	return receipts
}

// backendReceipt is a receipt the mock backend hands out.
var backendReceipt = ratelimit.NewReceipt(testKey, epoch.Add(-time.Second))

func TestUnavailable_Charge(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		mode    ratelimit.UnavailableMode
		ctx     func(ctx context.Context) context.Context
		arrange func(t *testing.T, h *harness)
		assert  func(t *testing.T, h *harness, r ratelimit.Receipt, exceeded bool, err error)
	}

	endedCharge := func(label string, mode ratelimit.UnavailableMode) testCase {
		return testCase{
			name:    "an ended caller context fails closed without the backend, " + label,
			mode:    mode,
			ctx:     cancelled,
			arrange: func(*testing.T, *harness) {}, // any backend call fails the mock
			assert: func(t *testing.T, _ *harness, r ratelimit.Receipt, exceeded bool, err error) {
				require.ErrorIs(t, err, context.Canceled)
				assert.NotErrorIs(t, err, ratelimit.ErrBackendUnavailable)
				assert.True(t, exceeded)
				assert.Zero(t, r)
			},
		}
	}

	cases := []testCase{
		{
			name: "an accepted charge passes through with the backend's receipt",
			arrange: func(_ *testing.T, h *harness) {
				h.backend.EXPECT().Charge(gomock.Any(), testKey).Return(backendReceipt, false, nil)
			},
			assert: func(t *testing.T, _ *harness, r ratelimit.Receipt, exceeded bool, err error) {
				require.NoError(t, err)
				assert.False(t, exceeded)
				assert.Equal(t, backendReceipt, r)
			},
		},
		{
			name: "a refused charge passes through",
			arrange: func(_ *testing.T, h *harness) {
				h.backend.EXPECT().Charge(gomock.Any(), testKey).Return(ratelimit.Receipt{}, true, nil)
			},
			assert: func(t *testing.T, _ *harness, r ratelimit.Receipt, exceeded bool, err error) {
				require.NoError(t, err)
				assert.True(t, exceeded)
				assert.Zero(t, r)
			},
		},
		{
			name: "a charge is bounded by the operation timeout",
			arrange: func(t *testing.T, h *harness) {
				h.backend.EXPECT().Charge(gomock.Any(), testKey).DoAndReturn(
					func(ctx context.Context, _ string) (ratelimit.Receipt, bool, error) {
						require.NoError(t, ctx.Err(), "the backend was handed an ended context")
						deadline, ok := ctx.Deadline()
						require.True(t, ok, "the backend charge carries no deadline")
						assert.LessOrEqual(t, time.Until(deadline), defaultTimeout)
						return backendReceipt, false, nil
					})
			},
			assert: func(t *testing.T, _ *harness, _ ratelimit.Receipt, exceeded bool, err error) {
				require.NoError(t, err)
				assert.False(t, exceeded)
			},
		},
		func() testCase {
			// The backend ends the caller's context while it charges.
			var cancel context.CancelFunc
			return testCase{
				name: "a caller that ends during the charge is refused, and the breaker stays closed",
				ctx: func(ctx context.Context) context.Context {
					cctx, c := context.WithCancel(ctx)
					cancel = c
					// The parent ends with the test, so the cancel function is
					// released even if the backend never calls it.
					context.AfterFunc(ctx, c)

					return cctx
				},
				arrange: func(_ *testing.T, h *harness) {
					h.backend.EXPECT().Charge(gomock.Any(), testKey).DoAndReturn(
						func(ctx context.Context, _ string) (ratelimit.Receipt, bool, error) {
							cancel()
							<-ctx.Done()
							return ratelimit.Receipt{}, true, ctx.Err()
						})
				},
				assert: func(t *testing.T, h *harness, r ratelimit.Receipt, exceeded bool, err error) {
					require.ErrorIs(t, err, context.Canceled)
					assert.NotErrorIs(t, err, ratelimit.ErrBackendUnavailable)
					assert.True(t, exceeded)
					assert.Zero(t, r)

					h.backend.EXPECT().Charge(gomock.Any(), otherKey).Return(backendReceipt, false, nil)
					_, exceeded, err = h.limiter.Charge(t.Context(), otherKey)
					require.NoError(t, err, "the next charge did not reach the backend")
					assert.False(t, exceeded)
				},
			}
		}(),
		endedCharge("refuse mode", ratelimit.UnavailableRefuse),
		endedCharge("fall-back mode", ratelimit.UnavailableFallbackToLocal),
		endedCharge("allow mode", ratelimit.UnavailableAllow),
		{
			name: "refuse: a backend error refuses as unavailable, with fixed text",
			arrange: func(_ *testing.T, h *harness) {
				h.backend.EXPECT().Charge(gomock.Any(), testKey).Return(ratelimit.Receipt{}, true, errDown)
			},
			assert: func(t *testing.T, _ *harness, r ratelimit.Receipt, exceeded bool, err error) {
				refusedUnavailable(t, exceeded, err)
				assert.ErrorIs(t, err, errDown, "the cause is kept")
				assert.NotContains(t, err.Error(), errDown.Error())
				assert.Zero(t, r)
			},
		},
		{
			name: "refuse: the open breaker refuses without the backend",
			arrange: func(t *testing.T, h *harness) {
				h.openBreaker(t)
			},
			assert: func(t *testing.T, _ *harness, r ratelimit.Receipt, exceeded bool, err error) {
				refusedUnavailable(t, exceeded, err)
				assert.Zero(t, r)
			},
		},
		{
			name: "refuse: a key whose record failed is refused without the backend",
			arrange: func(t *testing.T, h *harness) {
				h.backend.EXPECT().RecordFailure(gomock.Any(), testKey).Return(errDown)
				require.Error(t, h.limiter.RecordFailure(t.Context(), testKey))
				// The probe interval passes, so only the hold refuses.
				h.clock.Advance(defaultInterval)
			},
			assert: func(t *testing.T, _ *harness, r ratelimit.Receipt, exceeded bool, err error) {
				refusedUnavailable(t, exceeded, err)
				assert.Zero(t, r)
			},
		},
		{
			name: "fall back: an outage charges the local count, which stops at the limit",
			mode: ratelimit.UnavailableFallbackToLocal,
			arrange: func(t *testing.T, h *harness) {
				h.chargesDown()
				h.chargeN(t, testKey, testLimit-1)
			},
			assert: func(t *testing.T, h *harness, r ratelimit.Receipt, exceeded bool, err error) {
				require.NoError(t, err)
				require.False(t, exceeded, "the local count refused a charge below the limit")
				assert.NotZero(t, r)

				_, exceeded, err = h.limiter.Charge(t.Context(), testKey)
				require.NoError(t, err)
				assert.True(t, exceeded, "the local count accepted a charge past the limit")

				exceeded, err = h.limiter.Exceeded(t.Context(), testKey)
				require.NoError(t, err)
				assert.True(t, exceeded, "the local charges are not counted by the check")
				assertRecords(t, h, slog.LevelError, msgFallBack, 1)
			},
		},
		{
			name: "fall back: failures counted locally in an outage refuse a charge once the backend is back",
			mode: ratelimit.UnavailableFallbackToLocal,
			arrange: func(t *testing.T, h *harness) {
				h.openBreaker(t)
				h.chargeN(t, testKey, testLimit)
				h.clock.Advance(defaultInterval)
				// The backend is not charged: the local count already holds
				// the limit.
			},
			assert: func(t *testing.T, _ *harness, r ratelimit.Receipt, exceeded bool, err error) {
				require.NoError(t, err)
				assert.True(t, exceeded)
				assert.Zero(t, r)
			},
		},
		{
			name: "fall back: a backend charge is not refused by a full local count",
			mode: ratelimit.UnavailableFallbackToLocal,
			arrange: func(t *testing.T, h *harness) {
				fillLocal(t, h)
				h.backend.EXPECT().Charge(gomock.Any(), testKey).Return(backendReceipt, false, nil)
			},
			assert: func(t *testing.T, _ *harness, r ratelimit.Receipt, exceeded bool, err error) {
				require.NoError(t, err)
				assert.False(t, exceeded)
				assert.Equal(t, backendReceipt, r)
			},
		},
		{
			name: "fall back: in an outage, a key the full local count does not hold is refused",
			mode: ratelimit.UnavailableFallbackToLocal,
			arrange: func(t *testing.T, h *harness) {
				fillLocal(t, h)
				h.openBreaker(t)
			},
			assert: func(t *testing.T, _ *harness, r ratelimit.Receipt, exceeded bool, err error) {
				require.ErrorIs(t, err, ratelimit.ErrLimiterFull)
				assert.NotContains(t, err.Error(), `"`+testKey+`"`, "the error quotes the key")
				assert.True(t, exceeded)
				assert.Zero(t, r)
			},
		},
		func() testCase {
			// The outage opens the breaker, and the record of it ends the caller's
			// context before the local count is charged.
			var cancel context.CancelFunc
			var local *ratelimit.MemoryLimiter

			return testCase{
				name: "a fallback charge whose caller left is refused",
				mode: ratelimit.UnavailableFallbackToLocal,
				ctx: func(ctx context.Context) context.Context {
					cctx, c := context.WithCancel(ctx)
					cancel = c
					context.AfterFunc(ctx, c)

					return cctx
				},
				arrange: func(t *testing.T, h *harness) {
					var err error
					local, err = ratelimit.NewMemoryLimiter(testLimit, testWindow,
						ratelimit.WithMemoryLimiterClock(h.clock),
						ratelimit.WithMemoryLimiterLogger(slog.New(slog.DiscardHandler)))
					require.NoError(t, err)

					cfg := unavailable.DefaultConfig()
					cfg.Mode = ratelimit.UnavailableFallbackToLocal
					cfg.Clock = h.clock
					cfg.Logger = slog.New(endingHandler{Handler: h.logs, end: func() { cancel() }})
					h.limiter, err = unavailable.Wrap(h.backend, testNamespace, testLimit, testWindow, cfg)
					require.NoError(t, err)
					unavailable.ReplaceLocal(h.limiter, local)

					h.backend.EXPECT().Charge(gomock.Any(), testKey).Return(ratelimit.Receipt{}, true, errDown)
				},
				assert: func(t *testing.T, _ *harness, r ratelimit.Receipt, exceeded bool, err error) {
					require.ErrorIs(t, err, context.Canceled)
					assert.ErrorContains(t, err, "charge abandoned: the caller's context ended")
					assert.NotErrorIs(t, err, ratelimit.ErrBackendUnavailable)
					assert.True(t, exceeded)
					assert.Zero(t, r)

					// A failure in the local count would refuse the last of these.
					for i := range testLimit {
						_, exceeded, err := local.Charge(t.Context(), testKey)
						require.NoError(t, err)
						require.False(t, exceeded, "the local count holds a failure: charge %d of %d was refused", i+1, testLimit)
					}
				},
			}
		}(),
		{
			name: "allow: an outage accepts the charge, records nothing, and logs the outage",
			mode: ratelimit.UnavailableAllow,
			arrange: func(_ *testing.T, h *harness) {
				h.chargesDown()
			},
			assert: func(t *testing.T, h *harness, r ratelimit.Receipt, exceeded bool, err error) {
				require.NoError(t, err)
				assert.False(t, exceeded)
				assert.Zero(t, r, "allow mode recorded nothing, so its receipt names nothing")
				assertRecords(t, h, slog.LevelError, msgAllow, 1)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, tc.mode)
			tc.arrange(t, h)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			r, exceeded, err := h.limiter.Charge(ctx, testKey)
			tc.assert(t, h, r, exceeded, err)
		})
	}
}

// fillLocal replaces h's local count with one that holds a single key, and
// fills it with a failure for another key.
func fillLocal(t *testing.T, h *harness) {
	t.Helper()

	local, err := ratelimit.NewMemoryLimiter(testLimit, testWindow,
		ratelimit.WithMemoryLimiterClock(h.clock),
		ratelimit.WithMemoryLimiterMaxKeys(1),
		ratelimit.WithMemoryLimiterLogger(slog.New(slog.DiscardHandler)))
	require.NoError(t, err)
	require.NoError(t, local.RecordFailure(t.Context(), "filler"))
	unavailable.ReplaceLocal(h.limiter, local)
}

func TestUnavailable_Refund(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		mode    ratelimit.UnavailableMode
		ctx     func(ctx context.Context) context.Context
		arrange func(t *testing.T, h *harness) ratelimit.Receipt
		assert  func(t *testing.T, h *harness, err error)
	}

	cases := []testCase{
		{
			name: "a refund passes through",
			arrange: func(_ *testing.T, h *harness) ratelimit.Receipt {
				h.backend.EXPECT().Refund(gomock.Any(), backendReceipt).Return(nil)
				return backendReceipt
			},
			assert: func(t *testing.T, _ *harness, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "a refund on an ended caller context still reaches the backend, bounded by the timeout",
			ctx:  cancelled,
			arrange: func(t *testing.T, h *harness) ratelimit.Receipt {
				h.backend.EXPECT().Refund(gomock.Any(), backendReceipt).DoAndReturn(
					func(ctx context.Context, _ ratelimit.Receipt) error {
						require.NoError(t, ctx.Err(), "the backend was handed an ended context")
						deadline, ok := ctx.Deadline()
						require.True(t, ok, "the backend refund carries no deadline")
						assert.LessOrEqual(t, time.Until(deadline), defaultTimeout)
						return nil
					})
				return backendReceipt
			},
			assert: func(t *testing.T, _ *harness, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "the zero receipt does nothing, without the backend",
			arrange: func(*testing.T, *harness) ratelimit.Receipt {
				return ratelimit.Receipt{} // any backend call fails the mock
			},
			assert: func(t *testing.T, _ *harness, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "refuse: a backend error is unavailable, with fixed text",
			arrange: func(_ *testing.T, h *harness) ratelimit.Receipt {
				h.backend.EXPECT().Refund(gomock.Any(), backendReceipt).Return(errDown)
				return backendReceipt
			},
			assert: func(t *testing.T, _ *harness, err error) {
				require.ErrorIs(t, err, ratelimit.ErrBackendUnavailable)
				assert.ErrorIs(t, err, errDown, "the cause is kept")
				assert.NotContains(t, err.Error(), errDown.Error())
			},
		},
		{
			name: "refuse: the open breaker is unavailable without the backend",
			arrange: func(t *testing.T, h *harness) ratelimit.Receipt {
				h.openBreaker(t)
				return backendReceipt
			},
			assert: func(t *testing.T, _ *harness, err error) {
				require.ErrorIs(t, err, ratelimit.ErrBackendUnavailable)
			},
		},
		{
			name: "fall back: in an outage, a refund returns a local charge's allowance",
			mode: ratelimit.UnavailableFallbackToLocal,
			arrange: func(t *testing.T, h *harness) ratelimit.Receipt {
				h.chargesDown()
				receipts := h.chargeN(t, testKey, testLimit)
				exceeded, err := h.limiter.Exceeded(t.Context(), testKey)
				require.NoError(t, err)
				require.True(t, exceeded)
				return receipts[0]
			},
			assert: func(t *testing.T, h *harness, err error) {
				require.NoError(t, err)

				exceeded, err := h.limiter.Exceeded(t.Context(), testKey)
				require.NoError(t, err)
				assert.False(t, exceeded, "the refund left the local count at the limit")
				h.chargeN(t, testKey, 1)
			},
		},
		{
			name: "fall back: a backend refund error leaves the local count alone",
			mode: ratelimit.UnavailableFallbackToLocal,
			arrange: func(t *testing.T, h *harness) ratelimit.Receipt {
				h.openBreaker(t)
				receipts := h.chargeN(t, testKey, testLimit)
				h.clock.Advance(defaultInterval)
				h.backend.EXPECT().Refund(gomock.Any(), receipts[0]).Return(errDown)
				return receipts[0]
			},
			assert: func(t *testing.T, h *harness, err error) {
				require.ErrorIs(t, err, ratelimit.ErrBackendUnavailable)

				h.backend.EXPECT().Exceeded(gomock.Any(), testKey).Return(false, nil).AnyTimes()
				h.clock.Advance(defaultInterval)
				exceeded, err := h.limiter.Exceeded(t.Context(), testKey)
				require.NoError(t, err)
				assert.True(t, exceeded, "the failed backend refund was taken from the local count")
			},
		},
		{
			name: "allow: in an outage, a refund does nothing, without the backend",
			mode: ratelimit.UnavailableAllow,
			arrange: func(t *testing.T, h *harness) ratelimit.Receipt {
				h.openBreaker(t)
				return backendReceipt
			},
			assert: func(t *testing.T, _ *harness, err error) {
				require.NoError(t, err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, tc.mode)
			r := tc.arrange(t, h)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			tc.assert(t, h, h.limiter.Refund(ctx, r))
		})
	}
}
