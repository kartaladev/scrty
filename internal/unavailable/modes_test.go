package unavailable_test

import (
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/internal/unavailable"
	"github.com/kartaladev/scrty/ratelimit"
)

const (
	msgFallBack  = "ratelimit: backend unavailable, counting locally"
	msgAllow     = "ratelimit: backend unavailable, allowing every attempt"
	msgRecovered = "ratelimit: backend available again"
	msgAllowSupp = "ratelimit: backend unavailable records suppressed"
)

// assertRecords asserts that exactly n records were written at level, each
// with message and naming the namespace.
func assertRecords(t *testing.T, h *harness, level slog.Level, message string, n int) []record {
	t.Helper()

	recs := h.logs.at(level)
	require.Len(t, recs, n, "%s records: %+v", level, h.logs.all())
	for _, rec := range recs {
		assert.Equal(t, message, rec.message)
		assert.Equal(t, testNamespace, rec.attrs["namespace"].String())
	}

	return recs
}

// TestUnavailable_Modes covers task 4.4, scenarios "Fall back to a local
// count" and "Allow during an outage": each degrading mode answers from its
// own rule while the backend is down, the move into degraded operation is
// logged at ERROR (sampled per namespace in allow mode) and the move out of it
// at WARN. Every case ends with one check of testKey.
func TestUnavailable_Modes(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		mode    ratelimit.UnavailableMode
		cfg     func(cfg *unavailable.Config)
		arrange func(t *testing.T, h *harness)
		assert  func(t *testing.T, h *harness, exceeded bool, err error)
	}

	cases := []testCase{
		{
			name: "fall back: the limit's worth of local failures exceeds, and one ERROR says so",
			mode: ratelimit.UnavailableFallBackToLocal,
			arrange: func(t *testing.T, h *harness) {
				h.down()
				for _, err := range h.recordN(t, testKey, testLimit) {
					require.NoError(t, err)
				}
			},
			assert: func(t *testing.T, h *harness, exceeded bool, err error) {
				require.NoError(t, err)
				assert.True(t, exceeded)
				assertRecords(t, h, slog.LevelError, msgFallBack, 1)
				assert.Empty(t, h.logs.at(slog.LevelWarn))
			},
		},
		{
			name: "fall back: short of the limit is not exceeded, and the outage is logged once",
			mode: ratelimit.UnavailableFallBackToLocal,
			arrange: func(t *testing.T, h *harness) {
				h.down()
				h.recordN(t, testKey, testLimit-1)
				for range 5 {
					_, _ = h.limiter.Exceeded(t.Context(), otherKey)
				}
			},
			assert: func(t *testing.T, h *harness, exceeded bool, err error) {
				require.NoError(t, err)
				assert.False(t, exceeded)
				assertRecords(t, h, slog.LevelError, msgFallBack, 1)
			},
		},
		{
			name: "fall back: recovery is logged once at WARN",
			mode: ratelimit.UnavailableFallBackToLocal,
			arrange: func(t *testing.T, h *harness) {
				h.openBreaker(t)
				h.clock.Advance(defaultInterval)
				h.backend.EXPECT().Exceeded(gomock.Any(), testKey).Return(false, nil)
			},
			assert: func(t *testing.T, h *harness, exceeded bool, err error) {
				require.NoError(t, err)
				assert.False(t, exceeded)

				h.backend.EXPECT().Exceeded(gomock.Any(), otherKey).Return(false, nil)
				_, err = h.limiter.Exceeded(t.Context(), otherKey)
				require.NoError(t, err)

				assertRecords(t, h, slog.LevelError, msgFallBack, 1)
				assertRecords(t, h, slog.LevelWarn, msgRecovered, 1)
			},
		},
		{
			name: "allow: checks are not exceeded and records are dropped, with one ERROR per sampling window",
			mode: ratelimit.UnavailableAllow,
			arrange: func(t *testing.T, h *harness) {
				h.down()
				for range 10 {
					exceeded, err := h.limiter.Exceeded(t.Context(), otherKey)
					require.NoError(t, err)
					require.False(t, exceeded)
				}
				for _, err := range h.recordN(t, testKey, 5) {
					require.NoError(t, err)
				}
			},
			assert: func(t *testing.T, h *harness, exceeded bool, err error) {
				require.NoError(t, err)
				assert.False(t, exceeded)
				assertRecords(t, h, slog.LevelError, msgAllow, 1)

				// One sampling window later the outage, still on, is written
				// again with what the window suppressed: 10 checks, 5 records
				// and the final check, after the first event that was written.
				h.clock.Advance(ratelimit.DefaultLogInterval)
				_, err = h.limiter.Exceeded(t.Context(), testKey)
				require.NoError(t, err)

				recs := assertRecords(t, h, slog.LevelError, msgAllow, 2)
				assert.Equal(t, int64(15), recs[1].attrs["suppressed"].Int64())
			},
		},
		{
			name: "allow: recovery is logged at WARN, and a later outage is logged at once",
			mode: ratelimit.UnavailableAllow,
			arrange: func(t *testing.T, h *harness) {
				h.openBreaker(t)
				h.clock.Advance(defaultInterval)
				h.backend.EXPECT().Exceeded(gomock.Any(), "probe").Return(false, nil)
				_, err := h.limiter.Exceeded(t.Context(), "probe")
				require.NoError(t, err)

				// Well inside the sampling window, the backend fails again.
				h.openBreaker(t)
			},
			assert: func(t *testing.T, h *harness, exceeded bool, err error) {
				require.NoError(t, err)
				assert.False(t, exceeded)
				assertRecords(t, h, slog.LevelError, msgAllow, 2)
				assertRecords(t, h, slog.LevelWarn, msgRecovered, 1)
			},
		},
		{
			name: "allow: recovery reports what the last sampling window suppressed before logging the recovery",
			mode: ratelimit.UnavailableAllow,
			arrange: func(t *testing.T, h *harness) {
				h.openBreaker(t) // written, with nothing suppressed
				for range 4 {
					_, err := h.limiter.Exceeded(t.Context(), otherKey)
					require.NoError(t, err)
				}
				h.clock.Advance(defaultInterval)
				h.backend.EXPECT().Exceeded(gomock.Any(), testKey).Return(false, nil)
			},
			assert: func(t *testing.T, h *harness, exceeded bool, err error) {
				require.NoError(t, err)
				assert.False(t, exceeded)
				assertRecords(t, h, slog.LevelError, msgAllow, 1)

				warns := h.logs.at(slog.LevelWarn)
				require.Len(t, warns, 2, "records: %+v", h.logs.all())
				assert.Equal(t, msgAllowSupp, warns[0].message)
				assert.Equal(t, testNamespace, warns[0].attrs["namespace"].String())
				assert.Equal(t, int64(4), warns[0].attrs["suppressed"].Int64())
				assert.Equal(t, msgRecovered, warns[1].message)
			},
		},
		{
			name: "allow: a log interval of zero writes every outage record",
			mode: ratelimit.UnavailableAllow,
			cfg:  func(cfg *unavailable.Config) { cfg.LogInterval = 0 },
			arrange: func(t *testing.T, h *harness) {
				h.down()
				for range 4 {
					_, err := h.limiter.Exceeded(t.Context(), otherKey)
					require.NoError(t, err)
				}
			},
			assert: func(t *testing.T, h *harness, exceeded bool, err error) {
				require.NoError(t, err)
				assert.False(t, exceeded)
				for _, rec := range assertRecords(t, h, slog.LevelError, msgAllow, 5) {
					assert.Equal(t, int64(0), rec.attrs["suppressed"].Int64())
				}
			},
		},
		{
			name: "allow: a shorter log interval writes the outage again once it has passed",
			mode: ratelimit.UnavailableAllow,
			cfg:  func(cfg *unavailable.Config) { cfg.LogInterval = 10 * time.Second },
			arrange: func(t *testing.T, h *harness) {
				h.down()
				for range 3 {
					_, err := h.limiter.Exceeded(t.Context(), otherKey)
					require.NoError(t, err)
				}
				h.clock.Advance(10 * time.Second)
			},
			assert: func(t *testing.T, h *harness, exceeded bool, err error) {
				require.NoError(t, err)
				assert.False(t, exceeded)
				recs := assertRecords(t, h, slog.LevelError, msgAllow, 2)
				assert.Equal(t, int64(2), recs[1].attrs["suppressed"].Int64())
			},
		},
		{
			name: "refuse: the limiter writes no degraded-mode records, since it never degrades",
			mode: ratelimit.UnavailableRefuse,
			arrange: func(t *testing.T, h *harness) {
				h.openBreaker(t)
				h.clock.Advance(defaultInterval)
				h.backend.EXPECT().Exceeded(gomock.Any(), "probe").Return(false, nil)
				_, err := h.limiter.Exceeded(t.Context(), "probe")
				require.NoError(t, err)
				h.openBreaker(t)
			},
			assert: func(t *testing.T, h *harness, exceeded bool, err error) {
				refusedUnavailable(t, exceeded, err)
				assert.Empty(t, h.logs.all(), "refusals are the guard's to report")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newHarnessWith(t, tc.mode, tc.cfg)
			tc.arrange(t, h)

			exceeded, err := h.limiter.Exceeded(t.Context(), testKey)
			tc.assert(t, h, exceeded, err)
		})
	}
}

// TestUnavailable_GuardOverWrappedLimiter covers scenario "Consumer chose to
// allow" of the modified "Limiter errors fail closed" requirement, and
// "Backend down" at the guard: a source guard over a limiter whose backend is
// down admits the attempt only when the consumer chose allow mode, and the
// limiter logs the outage.
func TestUnavailable_GuardOverWrappedLimiter(t *testing.T) {
	t.Parallel()

	const clientAddr = "203.0.113.7"

	type testCase struct {
		name   string
		mode   ratelimit.UnavailableMode
		assert func(t *testing.T, h *harness, src ratelimit.Source, err error)
	}

	cases := []testCase{
		{
			name: "allow mode: the guard admits the attempt and the limiter logs the outage",
			mode: ratelimit.UnavailableAllow,
			assert: func(t *testing.T, h *harness, src ratelimit.Source, err error) {
				require.NoError(t, err)
				assert.NotEmpty(t, src.Key())
				assertRecords(t, h, slog.LevelError, msgAllow, 1)
			},
		},
		{
			name: "fall-back mode: the guard admits a source under its local limit",
			mode: ratelimit.UnavailableFallBackToLocal,
			assert: func(t *testing.T, h *harness, src ratelimit.Source, err error) {
				require.NoError(t, err)
				assert.NotEmpty(t, src.Key())
				assertRecords(t, h, slog.LevelError, msgFallBack, 1)
			},
		},
		{
			name: "default mode: the guard refuses the attempt as throttled",
			mode: ratelimit.UnavailableRefuse,
			assert: func(t *testing.T, _ *harness, src ratelimit.Source, err error) {
				require.ErrorIs(t, err, ratelimit.ErrThrottled)
				require.ErrorIs(t, err, ratelimit.ErrBackendUnavailable)
				assert.Empty(t, src.Key())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, tc.mode)
			h.down()

			guard, err := ratelimit.NewSourceGuard("passkey-login", h.limiter,
				ratelimit.WithSourceGuardLogger(slog.New(slog.DiscardHandler)))
			require.NoError(t, err)

			src, err := guard.Check(t.Context(), clientAddr)
			tc.assert(t, h, src, err)
		})
	}
}

// TestUnavailable_FullLocalCount pins what fall-back mode does with a local
// count an outage has filled. While the backend is down, a key the local count
// does not hold is refused, failing closed. Once the backend answers again, the
// local count holds nothing for that key, so it counts zero locally and the
// backend's answer decides.
func TestUnavailable_FullLocalCount(t *testing.T) {
	t.Parallel()

	const newKey = "new-source"

	type testCase struct {
		name    string
		arrange func(t *testing.T, h *harness)
		assert  func(t *testing.T, exceeded bool, err error)
	}

	cases := []testCase{
		{
			name:    "outage: a key the full local count does not hold is refused",
			arrange: func(*testing.T, *harness) {},
			assert: func(t *testing.T, exceeded bool, err error) {
				require.ErrorIs(t, err, ratelimit.ErrLimiterFull)
				assert.True(t, exceeded, "a full local count must fail closed while the backend is down")
				assert.NotContains(t, err.Error(), newKey)
				assert.NotContains(t, err.Error(), "context", "a full local count is not a caller that went away")
			},
		},
		{
			name: "recovered: a key the full local count does not hold is the backend's to decide",
			arrange: func(t *testing.T, h *harness) {
				t.Helper()
				h.clock.Advance(defaultInterval)
				h.backend.EXPECT().Exceeded(gomock.Any(), newKey).Return(false, nil)
			},
			assert: func(t *testing.T, exceeded bool, err error) {
				require.NoError(t, err)
				assert.False(t, exceeded, "a healthy backend's answer was overruled by a full local count")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, ratelimit.UnavailableFallBackToLocal)
			local, err := ratelimit.NewMemoryLimiter(testLimit, testWindow,
				ratelimit.WithMemoryLimiterClock(h.clock),
				ratelimit.WithMemoryLimiterLogger(slog.New(slog.DiscardHandler)),
				ratelimit.WithMemoryLimiterMaxKeys(2))
			require.NoError(t, err)
			unavailable.ReplaceLocal(h.limiter, local)

			// The outage fills the local count.
			h.openBreaker(t)
			for _, key := range []string{"a", "b"} {
				require.NoError(t, h.limiter.RecordFailure(t.Context(), key))
			}

			tc.arrange(t, h)

			exceeded, err := h.limiter.Exceeded(t.Context(), newKey)
			tc.assert(t, exceeded, err)
		})
	}
}
