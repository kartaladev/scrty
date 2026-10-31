package unavailable_test

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/internal/unavailable"
	"github.com/kartaladev/scrty/ratelimit"
)

func cancelled(ctx context.Context) context.Context {
	cctx, cancel := context.WithCancel(ctx)
	cancel()

	return cctx
}

// TestUnavailable_Construction covers task 4.1's wiring rules: every
// meaningless configuration is refused with ErrConfig before any traffic, and
// the defaults are accepted as they are.
func TestUnavailable_Construction(t *testing.T) {
	t.Parallel()

	type input struct {
		backend   func(ctrl *gomock.Controller) unavailable.Limiter
		namespace string
		limit     int
		window    time.Duration
		cfg       func(cfg *unavailable.Config)
	}

	type testCase struct {
		name   string
		input  input
		assert func(t *testing.T, l ratelimit.Limiter, err error)
	}

	valid := func() input {
		return input{
			backend:   func(ctrl *gomock.Controller) unavailable.Limiter { return newBackendDouble(ctrl) },
			namespace: testNamespace,
			limit:     testLimit,
			window:    testWindow,
		}
	}
	with := func(edit func(in *input)) input {
		in := valid()
		edit(&in)

		return in
	}
	refused := func(t *testing.T, l ratelimit.Limiter, err error) {
		require.ErrorIs(t, err, ratelimit.ErrConfig)
		assert.Nil(t, l)
	}

	cases := []testCase{
		{
			name:  "the defaults are accepted",
			input: valid(),
			assert: func(t *testing.T, l ratelimit.Limiter, err error) {
				require.NoError(t, err)
				assert.NotNil(t, l)
			},
		},
		{
			name:  "every mode is accepted",
			input: valid(),
			assert: func(t *testing.T, _ ratelimit.Limiter, _ error) {
				for _, mode := range []ratelimit.UnavailableMode{
					ratelimit.UnavailableRefuse, ratelimit.UnavailableFallbackToLocal, ratelimit.UnavailableAllow,
				} {
					cfg := unavailable.DefaultConfig()
					cfg.Mode = mode
					l, err := unavailable.Wrap(newBackendDouble(gomock.NewController(t)),
						testNamespace, testLimit, testWindow, cfg)
					require.NoError(t, err, "mode %d", mode)
					assert.NotNil(t, l, "mode %d", mode)
				}
			},
		},
		{
			name: "an unknown mode is refused",
			input: with(func(in *input) {
				in.cfg = func(cfg *unavailable.Config) { cfg.Mode = ratelimit.UnavailableMode(9) }
			}),
			assert: refused,
		},
		{
			name: "a negative mode is refused",
			input: with(func(in *input) {
				in.cfg = func(cfg *unavailable.Config) { cfg.Mode = ratelimit.UnavailableMode(-1) }
			}),
			assert: refused,
		},
		{
			name:   "a zero timeout is refused",
			input:  with(func(in *input) { in.cfg = func(cfg *unavailable.Config) { cfg.Timeout = 0 } }),
			assert: refused,
		},
		{
			name:   "a negative timeout is refused",
			input:  with(func(in *input) { in.cfg = func(cfg *unavailable.Config) { cfg.Timeout = -time.Second } }),
			assert: refused,
		},
		{
			name:   "a zero probe interval is refused",
			input:  with(func(in *input) { in.cfg = func(cfg *unavailable.Config) { cfg.ProbeInterval = 0 } }),
			assert: refused,
		},
		{
			name: "a negative probe interval is refused",
			input: with(func(in *input) {
				in.cfg = func(cfg *unavailable.Config) { cfg.ProbeInterval = -time.Second }
			}),
			assert: refused,
		},
		{
			name: "a nil backend is refused",
			input: with(func(in *input) {
				in.backend = func(*gomock.Controller) unavailable.Limiter { return nil }
			}),
			assert: refused,
		},
		{
			name: "a typed nil backend is refused",
			input: with(func(in *input) {
				in.backend = func(*gomock.Controller) unavailable.Limiter { return (*backendDouble)(nil) }
			}),
			assert: refused,
		},
		{
			name:   "an empty namespace is refused",
			input:  with(func(in *input) { in.namespace = "" }),
			assert: refused,
		},
		{
			name:   "a zero limit is refused",
			input:  with(func(in *input) { in.limit = 0 }),
			assert: refused,
		},
		{
			name:   "a zero window is refused",
			input:  with(func(in *input) { in.window = 0 }),
			assert: refused,
		},
		{
			name:   "a nil clock is refused",
			input:  with(func(in *input) { in.cfg = func(cfg *unavailable.Config) { cfg.Clock = nil } }),
			assert: refused,
		},
		{
			name: "a typed nil clock is refused",
			input: with(func(in *input) {
				in.cfg = func(cfg *unavailable.Config) { cfg.Clock = (*clockwork.FakeClock)(nil) }
			}),
			assert: refused,
		},
		{
			name:   "a nil logger is refused",
			input:  with(func(in *input) { in.cfg = func(cfg *unavailable.Config) { cfg.Logger = nil } }),
			assert: refused,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := unavailable.DefaultConfig()
			if tc.input.cfg != nil {
				tc.input.cfg(&cfg)
			}

			l, err := unavailable.Wrap(tc.input.backend(gomock.NewController(t)),
				tc.input.namespace, tc.input.limit, tc.input.window, cfg)
			tc.assert(t, l, err)
		})
	}
}

// TestUnavailable_DefaultConfig pins the documented defaults, which the backend
// modules' own option godoc names.
func TestUnavailable_DefaultConfig(t *testing.T) {
	t.Parallel()

	cfg := unavailable.DefaultConfig()

	assert.Equal(t, ratelimit.UnavailableRefuse, cfg.Mode)
	assert.Equal(t, defaultTimeout, cfg.Timeout)
	assert.Equal(t, defaultInterval, cfg.ProbeInterval)
	assert.NotNil(t, cfg.Clock)
	assert.Same(t, slog.Default(), cfg.Logger)
	assert.Equal(t, ratelimit.DefaultLogInterval, cfg.LogInterval)
}

// TestUnavailable_PassThrough covers task 4.1's healthy path and the
// ended-context rule: a live backend's answers pass through unchanged, every
// call is bounded by the operation timeout, and a check on an ended caller
// context fails closed without touching the backend, whatever the mode.
func TestUnavailable_PassThrough(t *testing.T) {
	t.Parallel()

	type call func(ctx context.Context, l ratelimit.Limiter) (bool, error)

	check := func(ctx context.Context, l ratelimit.Limiter) (bool, error) {
		return l.Exceeded(ctx, testKey)
	}
	recordFailure := func(ctx context.Context, l ratelimit.Limiter) (bool, error) {
		return false, l.RecordFailure(ctx, testKey)
	}

	// boundedByTimeout asserts the context the backend was handed is live and
	// ends within the operation timeout.
	boundedByTimeout := func(t *testing.T, ctx context.Context) {
		t.Helper()

		require.NoError(t, ctx.Err(), "the backend was handed an ended context")
		deadline, ok := ctx.Deadline()
		require.True(t, ok, "the backend call carries no deadline")
		assert.LessOrEqual(t, time.Until(deadline), defaultTimeout)
	}

	type testCase struct {
		name    string
		mode    ratelimit.UnavailableMode
		ctx     func(ctx context.Context) context.Context
		arrange func(t *testing.T, h *harness)
		call    call
		assert  func(t *testing.T, exceeded bool, err error)
	}

	endedCheck := func(label string, mode ratelimit.UnavailableMode) testCase {
		return testCase{
			name:    "an ended caller context fails closed without the backend, " + label,
			mode:    mode,
			ctx:     cancelled,
			arrange: func(*testing.T, *harness) {}, // any backend call fails the mock
			call:    check,
			assert: func(t *testing.T, exceeded bool, err error) {
				require.ErrorIs(t, err, context.Canceled)
				assert.NotErrorIs(t, err, ratelimit.ErrBackendUnavailable)
				assert.True(t, exceeded)
			},
		}
	}

	cases := []testCase{
		{
			name: "an exceeded answer passes through",
			arrange: func(_ *testing.T, h *harness) {
				h.backend.EXPECT().Exceeded(gomock.Any(), testKey).Return(true, nil)
			},
			call: check,
			assert: func(t *testing.T, exceeded bool, err error) {
				require.NoError(t, err)
				assert.True(t, exceeded)
			},
		},
		{
			name: "a not-exceeded answer passes through",
			arrange: func(_ *testing.T, h *harness) {
				h.backend.EXPECT().Exceeded(gomock.Any(), testKey).Return(false, nil)
			},
			call: check,
			assert: func(t *testing.T, exceeded bool, err error) {
				require.NoError(t, err)
				assert.False(t, exceeded)
			},
		},
		{
			name: "a record passes through",
			arrange: func(_ *testing.T, h *harness) {
				h.backend.EXPECT().RecordFailure(gomock.Any(), testKey).Return(nil)
			},
			call: recordFailure,
			assert: func(t *testing.T, _ bool, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "a check is bounded by the operation timeout",
			arrange: func(t *testing.T, h *harness) {
				h.backend.EXPECT().Exceeded(gomock.Any(), testKey).DoAndReturn(
					func(ctx context.Context, _ string) (bool, error) {
						boundedByTimeout(t, ctx)
						return false, nil
					})
			},
			call: check,
			assert: func(t *testing.T, _ bool, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "a record on an ended caller context still reaches the backend, bounded by the timeout",
			ctx:  cancelled,
			arrange: func(t *testing.T, h *harness) {
				h.backend.EXPECT().RecordFailure(gomock.Any(), testKey).DoAndReturn(
					func(ctx context.Context, _ string) error {
						boundedByTimeout(t, ctx)
						return nil
					})
			},
			call: recordFailure,
			assert: func(t *testing.T, _ bool, err error) {
				require.NoError(t, err)
			},
		},
		endedCheck("refuse mode", ratelimit.UnavailableRefuse),
		endedCheck("fall-back mode", ratelimit.UnavailableFallbackToLocal),
		endedCheck("allow mode", ratelimit.UnavailableAllow),
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

			exceeded, err := tc.call(ctx, h.limiter)
			tc.assert(t, exceeded, err)
		})
	}
}

// TestUnavailable_ErrorTextOmitsKey covers the rule that a key, which a
// consumer composes and may build from a user's identifier, never reaches the
// text of an error the decorator returns. In fall-back mode the local
// in-memory limiter's errors quote the key, so they are wrapped in fixed text;
// the caller's own error stays reachable through errors.Is.
func TestUnavailable_ErrorTextOmitsKey(t *testing.T) {
	t.Parallel()

	const key = "alice@example.com"

	type testCase struct {
		name    string
		arrange func(t *testing.T, h *harness, cancel context.CancelFunc)
	}

	cases := []testCase{
		{
			name: "the caller ends while the backend answers a fall-back check",
			arrange: func(_ *testing.T, h *harness, cancel context.CancelFunc) {
				h.backend.EXPECT().Exceeded(gomock.Any(), key).DoAndReturn(
					func(context.Context, string) (bool, error) {
						cancel()
						return false, nil
					})
			},
		},
		{
			name: "the caller has ended before a fall-back check",
			arrange: func(_ *testing.T, _ *harness, cancel context.CancelFunc) {
				cancel()
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, ratelimit.UnavailableFallbackToLocal)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			tc.arrange(t, h, cancel)

			exceeded, err := h.limiter.Exceeded(ctx, key)
			assert.True(t, exceeded)
			require.ErrorIs(t, err, context.Canceled)
			assert.NotContains(t, err.Error(), key)
		})
	}
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
			mode: ratelimit.UnavailableFallbackToLocal,
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
			mode: ratelimit.UnavailableFallbackToLocal,
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
			mode: ratelimit.UnavailableFallbackToLocal,
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
			mode: ratelimit.UnavailableFallbackToLocal,
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

			h := newHarness(t, ratelimit.UnavailableFallbackToLocal)
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

// TestUnavailable_RecordErrors covers task 4.3, scenario "Writes fail while
// reads succeed": in refuse mode a failure that could not be recorded holds its
// key as refused on this instance for one window, even once checks reach the
// backend again; in fall-back mode it is counted locally and either count
// exceeds; in allow mode it is dropped. Every case ends with one check of
// testKey.
func TestUnavailable_RecordErrors(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		mode    ratelimit.UnavailableMode
		arrange func(t *testing.T, h *harness)
		assert  func(t *testing.T, h *harness, exceeded bool, err error)
	}

	cases := []testCase{
		{
			name: "refuse: a key whose record failed is refused after reads succeed again",
			mode: ratelimit.UnavailableRefuse,
			arrange: func(t *testing.T, h *harness) {
				h.writesFailReadsSucceed()
				for _, err := range h.recordN(t, testKey, 1) {
					require.ErrorIs(t, err, ratelimit.ErrBackendUnavailable)
				}

				// The probe on another key succeeds and closes the breaker.
				h.clock.Advance(defaultInterval)
				exceeded, err := h.limiter.Exceeded(t.Context(), otherKey)
				require.NoError(t, err)
				require.False(t, exceeded)
			},
			assert: func(t *testing.T, h *harness, exceeded bool, err error) {
				refusedUnavailable(t, exceeded, err)

				exceeded, err = h.limiter.Exceeded(t.Context(), otherKey)
				require.NoError(t, err)
				assert.False(t, exceeded, "a key that never failed a record was held too")
			},
		},
		{
			name: "refuse: the hold lasts until one window has passed",
			mode: ratelimit.UnavailableRefuse,
			arrange: func(t *testing.T, h *harness) {
				h.writesFailReadsSucceed()
				h.recordN(t, testKey, 1)
				h.clock.Advance(testWindow - time.Nanosecond)
			},
			assert: func(t *testing.T, _ *harness, exceeded bool, err error) {
				refusedUnavailable(t, exceeded, err)
			},
		},
		{
			name: "refuse: the hold ends once one window has passed",
			mode: ratelimit.UnavailableRefuse,
			arrange: func(t *testing.T, h *harness) {
				h.writesFailReadsSucceed()
				h.recordN(t, testKey, 1)
				h.clock.Advance(testWindow)
			},
			assert: func(t *testing.T, _ *harness, exceeded bool, err error) {
				require.NoError(t, err)
				assert.False(t, exceeded)
			},
		},
		{
			name: "refuse: a record the open breaker turns away is held too",
			mode: ratelimit.UnavailableRefuse,
			arrange: func(t *testing.T, h *harness) {
				h.backend.EXPECT().RecordFailure(gomock.Any(), otherKey).Return(errDown)
				require.ErrorIs(t, h.limiter.RecordFailure(t.Context(), otherKey), ratelimit.ErrBackendUnavailable)

				// The breaker is open, so this record never reaches the backend.
				require.ErrorIs(t, h.limiter.RecordFailure(t.Context(), testKey), ratelimit.ErrBackendUnavailable)

				h.clock.Advance(defaultInterval)
				h.backend.EXPECT().Exceeded(gomock.Any(), "probe").Return(false, nil)
				_, err := h.limiter.Exceeded(t.Context(), "probe")
				require.NoError(t, err)
			},
			assert: func(t *testing.T, _ *harness, exceeded bool, err error) {
				refusedUnavailable(t, exceeded, err)
			},
		},
		{
			name: "refuse: held keys are swept once their window has passed",
			mode: ratelimit.UnavailableRefuse,
			arrange: func(t *testing.T, h *harness) {
				h.writesFailReadsSucceed()
				h.recordN(t, testKey, 1)
				h.recordN(t, otherKey, 1)
				require.Equal(t, 2, unavailable.HeldLen(h.limiter))

				h.clock.Advance(testWindow)
			},
			assert: func(t *testing.T, h *harness, exceeded bool, err error) {
				require.NoError(t, err)
				assert.False(t, exceeded)
				assert.Zero(t, unavailable.HeldLen(h.limiter),
					"held keys outlived their window, including one never looked up again")
			},
		},
		{
			name: "fall back: failed records reaching the limit locally exceed once reads succeed",
			mode: ratelimit.UnavailableFallbackToLocal,
			arrange: func(t *testing.T, h *harness) {
				h.writesFailReadsSucceed()
				for _, err := range h.recordN(t, testKey, testLimit) {
					require.NoError(t, err, "fall-back mode returned a record error")
				}
				h.clock.Advance(defaultInterval)
			},
			assert: func(t *testing.T, _ *harness, exceeded bool, err error) {
				require.NoError(t, err)
				assert.True(t, exceeded, "the local count was ignored once the backend answered")
			},
		},
		{
			name: "fall back: failed records short of the limit do not exceed",
			mode: ratelimit.UnavailableFallbackToLocal,
			arrange: func(t *testing.T, h *harness) {
				h.writesFailReadsSucceed()
				h.recordN(t, testKey, testLimit-1)
				h.clock.Advance(defaultInterval)
			},
			assert: func(t *testing.T, _ *harness, exceeded bool, err error) {
				require.NoError(t, err)
				assert.False(t, exceeded)
			},
		},
		{
			name: "fall back: the shared count exceeds on its own",
			mode: ratelimit.UnavailableFallbackToLocal,
			arrange: func(_ *testing.T, h *harness) {
				h.backend.EXPECT().Exceeded(gomock.Any(), testKey).Return(true, nil)
			},
			assert: func(t *testing.T, _ *harness, exceeded bool, err error) {
				require.NoError(t, err)
				assert.True(t, exceeded)
			},
		},
		{
			name: "allow: failed records are dropped and the check follows the backend",
			mode: ratelimit.UnavailableAllow,
			arrange: func(t *testing.T, h *harness) {
				h.writesFailReadsSucceed()
				for _, err := range h.recordN(t, testKey, testLimit) {
					require.NoError(t, err, "allow mode returned a record error")
				}
				h.clock.Advance(defaultInterval)
			},
			assert: func(t *testing.T, _ *harness, exceeded bool, err error) {
				require.NoError(t, err)
				assert.False(t, exceeded)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, tc.mode)
			tc.arrange(t, h)

			exceeded, err := h.limiter.Exceeded(t.Context(), testKey)
			tc.assert(t, h, exceeded, err)
		})
	}
}

// TestValidateConfig pins that the validation-only entry point refuses what
// Wrap refuses in a configuration, with Wrap's messages, and accepts the
// defaults.
func TestValidateConfig(t *testing.T) {
	t.Parallel()

	refused := func(want string) func(t *testing.T, err error) {
		return func(t *testing.T, err error) {
			t.Helper()
			require.ErrorIs(t, err, ratelimit.ErrConfig)
			assert.Contains(t, err.Error(), want)
		}
	}

	type testCase struct {
		name   string
		cfg    func(c unavailable.Config) unavailable.Config
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name: "default",
			cfg:  func(c unavailable.Config) unavailable.Config { return c },
			assert: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
		},
		{
			name:   "unknown mode",
			cfg:    func(c unavailable.Config) unavailable.Config { c.Mode = 99; return c },
			assert: refused("unknown unavailable mode 99"),
		},
		{
			name:   "zero timeout",
			cfg:    func(c unavailable.Config) unavailable.Config { c.Timeout = 0; return c },
			assert: refused("bounds nothing"),
		},
		{
			name:   "zero probe interval",
			cfg:    func(c unavailable.Config) unavailable.Config { c.ProbeInterval = 0; return c },
			assert: refused("probe interval"),
		},
		{
			name:   "nil clock",
			cfg:    func(c unavailable.Config) unavailable.Config { c.Clock = nil; return c },
			assert: refused("the clock is nil"),
		},
		{
			name:   "nil logger",
			cfg:    func(c unavailable.Config) unavailable.Config { c.Logger = nil; return c },
			assert: refused("the logger is nil"),
		},
		{
			name: "mode checked before timeout",
			cfg: func(c unavailable.Config) unavailable.Config {
				c.Mode, c.Timeout = 99, 0
				return c
			},
			assert: refused("unknown unavailable mode 99"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, unavailable.ValidateConfig(tc.cfg(unavailable.DefaultConfig())))
		})
	}
}
