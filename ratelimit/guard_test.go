// The guard cases are separate TestXxx functions where their setup differs in
// kind — a mock limiter, a real in-memory limiter, or a synthetic clock inside a
// synctest bubble — and tables wherever the rows share one call shape.
package ratelimit_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/ratelimit"
)

const (
	testFlow   = "api-key"
	testSource = "198.51.100.7"
)

// TestNewSourceGuardRefusesAGuardThatCannotCount pins the wiring mistakes that
// are caught before traffic. A guard with no limiter would let every attempt
// through while reading, at the call site, exactly like one that limits.
func TestNewSourceGuardRefusesAGuardThatCannotCount(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		flow    string
		limiter func(t *testing.T) ratelimit.Limiter
		opts    []ratelimit.GuardOption
		assert  func(t *testing.T, g *ratelimit.SourceGuard, err error)
	}

	workingLimiter := func(t *testing.T) ratelimit.Limiter {
		t.Helper()
		return NewMockLimiter(gomock.NewController(t))
	}
	// throttlingLimiter reports every source as over its limit, which is what
	// the "consumer clock" row below needs to make the guard write a sampled
	// refusal record.
	throttlingLimiter := func(t *testing.T) ratelimit.Limiter {
		t.Helper()
		l := NewMockLimiter(gomock.NewController(t))
		l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(true, nil).AnyTimes()
		return l
	}
	// consumerClockRecorder and consumerClockLogger capture what the
	// "consumer clock" row's guard writes, so the row can prove it read the
	// fixed clock rather than the wall clock.
	consumerClockRecorder, consumerClockLogger := newLogRecorder()

	// aggregateLimiter is never consulted by a constructor case; it only has
	// to be present, so the rows about the aggregate's bits are about the bits.
	aggregateLimiter := memoryLimiter(t)
	keyer56, err := ratelimit.NewSourceKeyer(ratelimit.WithIPv6SourcePrefix(56))
	require.NoError(t, err)

	refused := func(t *testing.T, g *ratelimit.SourceGuard, err error) {
		t.Helper()
		require.ErrorIs(t, err, ratelimit.ErrConfig)
		assert.Nil(t, g, "a refused configuration still handed back a guard")
	}

	cases := []testCase{
		{
			name:    "a nil limiter",
			flow:    testFlow,
			limiter: func(*testing.T) ratelimit.Limiter { return nil },
			assert:  refused,
		},
		{
			name: "an interface holding a nil limiter",
			flow: testFlow,
			limiter: func(*testing.T) ratelimit.Limiter {
				var l *ratelimit.MemoryLimiter // the nil result of an unchecked constructor
				return l
			},
			assert: refused,
		},
		{
			name:    "an empty flow name",
			flow:    "",
			limiter: workingLimiter,
			assert:  refused,
		},
		{
			name:    "a nil keyer",
			flow:    testFlow,
			limiter: workingLimiter,
			opts:    []ratelimit.GuardOption{ratelimit.WithSourceGuardKeyer(nil)},
			assert:  refused,
		},
		{
			name:    "a nil logger",
			flow:    testFlow,
			limiter: workingLimiter,
			opts:    []ratelimit.GuardOption{ratelimit.WithSourceGuardLogger(nil)},
			assert:  refused,
		},
		{
			name:    "a nil summary reporter",
			flow:    testFlow,
			limiter: workingLimiter,
			opts:    []ratelimit.GuardOption{ratelimit.WithSourceGuardLogReporter(nil)},
			assert:  refused,
		},
		{
			// *clockwork.FakeClock implements Now through a pointer receiver, so
			// a nil one is an interface holding a nil pointer: `== nil` misses
			// it, and only the reflect-based check the constructor now uses
			// catches it before the first refusal sample reads from a nil
			// receiver.
			name:    "a typed nil clock",
			flow:    testFlow,
			limiter: workingLimiter,
			opts:    []ratelimit.GuardOption{ratelimit.WithSourceGuardClock((*clockwork.FakeClock)(nil))},
			assert:  refused,
		},
		{
			name:    "an IPv6 aggregate with no limiter",
			flow:    testFlow,
			limiter: workingLimiter,
			opts:    []ratelimit.GuardOption{ratelimit.WithSourceGuardIPv6Aggregate(56, nil)},
			assert:  refused,
		},
		{
			name:    "an IPv6 aggregate with an interface holding a nil limiter",
			flow:    testFlow,
			limiter: workingLimiter,
			opts: []ratelimit.GuardOption{
				ratelimit.WithSourceGuardIPv6Aggregate(56, (*ratelimit.MemoryLimiter)(nil)),
			},
			assert: refused,
		},
		{
			name:    "an IPv6 aggregate of /0 pools every IPv6 source",
			flow:    testFlow,
			limiter: workingLimiter,
			opts:    []ratelimit.GuardOption{ratelimit.WithSourceGuardIPv6Aggregate(0, aggregateLimiter)},
			assert:  refused,
		},
		{
			name:    "an IPv6 aggregate of /128 is no prefix at all",
			flow:    testFlow,
			limiter: workingLimiter,
			opts:    []ratelimit.GuardOption{ratelimit.WithSourceGuardIPv6Aggregate(128, aggregateLimiter)},
			assert:  refused,
		},
		{
			name:    "an IPv6 aggregate as narrow as the default /64 source",
			flow:    testFlow,
			limiter: workingLimiter,
			opts:    []ratelimit.GuardOption{ratelimit.WithSourceGuardIPv6Aggregate(64, aggregateLimiter)},
			assert:  refused,
		},
		{
			// The scenario "Aggregate no wider than the source": the check is
			// made against the keyer the guard ends up with, not the default.
			name:    "an IPv6 aggregate as narrow as a consumer keyer's /56 source",
			flow:    testFlow,
			limiter: workingLimiter,
			opts: []ratelimit.GuardOption{
				ratelimit.WithSourceGuardKeyer(keyer56),
				ratelimit.WithSourceGuardIPv6Aggregate(56, aggregateLimiter),
			},
			assert: refused,
		},
		{
			name:    "an IPv6 aggregate of /56 over the default /64 source",
			flow:    testFlow,
			limiter: workingLimiter,
			opts:    []ratelimit.GuardOption{ratelimit.WithSourceGuardIPv6Aggregate(56, aggregateLimiter)},
			assert: func(t *testing.T, g *ratelimit.SourceGuard, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.NotNil(t, g)
			},
		},
		{
			name:    "a flow name and a limiter are all a guard needs",
			flow:    testFlow,
			limiter: workingLimiter,
			assert: func(t *testing.T, g *ratelimit.SourceGuard, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.NotNil(t, g)
			},
		},
		{
			// A Now-only consumer type: `time-source` "Read-only source for a
			// read-only component". Construction succeeds, and the guard
			// samples its refusal records by the consumer's clock: since
			// fixedClock never advances, a one-millisecond sampling window
			// never appears to elapse, so two refusals a real sleep apart
			// still produce one record — which is only possible if the guard
			// asks the clock rather than the wall clock for "now".
			name:    "a consumer's own read-only clock is accepted and used to sample refusal records",
			flow:    testFlow,
			limiter: throttlingLimiter,
			opts: []ratelimit.GuardOption{
				ratelimit.WithSourceGuardClock(fixedClock{at: epoch}),
				ratelimit.WithSourceGuardLogger(consumerClockLogger),
				ratelimit.WithSourceGuardLogInterval(time.Millisecond),
			},
			assert: func(t *testing.T, g *ratelimit.SourceGuard, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, g)

				_, _ = g.Check(t.Context(), testSource)
				time.Sleep(50 * time.Millisecond) // real time passes; the frozen clock does not
				_, _ = g.Check(t.Context(), testSource)

				assert.Len(t, logRecords(t, consumerClockRecorder), 1,
					"a clock that never advances must keep the sampling window from ever elapsing")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			g, err := ratelimit.NewSourceGuard(tc.flow, tc.limiter(t), tc.opts...)
			tc.assert(t, g, err)
		})
	}
}

// TestGuardFailsClosedWhenTheLimiterCannotDecide is the security property: a
// limiter that cannot answer must read as a source already over its limit. The
// alternative lifts every limit at exactly the moment something is wrong, which
// is how an attacker disables rate limiting.
func TestGuardFailsClosedWhenTheLimiterCannotDecide(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		expect  func(l *MockLimiter)
		ctx     func(ctx context.Context) context.Context
		assert  func(t *testing.T, recorder *logRecorder)
		wantErr error
	}

	errBackendDown := errors.New("dial tcp: connection refused")

	cases := []testCase{
		{
			name: "a limiter outage refuses the attempt",
			expect: func(l *MockLimiter) {
				l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, errBackendDown)
			},
			wantErr: ratelimit.ErrThrottled,
			assert: func(t *testing.T, recorder *logRecorder) {
				t.Helper()
				recs := logRecords(t, recorder)
				require.Len(t, recs, 1, "a limiter outage was refused without a word about it")
				assert.Equal(t, "WARN", recs[0]["level"],
					"an outage that refuses live traffic was written below warning level")
				assert.Equal(t, "limiter", recs[0]["reason"],
					"the record does not name what went wrong")
				assert.NotEmpty(t, recs[0]["error_type"],
					"the record does not name the error's type")
			},
		},
		{
			name: "a source over its limit is refused",
			expect: func(l *MockLimiter) {
				l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(true, nil)
			},
			wantErr: ratelimit.ErrThrottled,
			assert: func(t *testing.T, recorder *logRecorder) {
				t.Helper()
				recs := logRecords(t, recorder)
				require.Len(t, recs, 1)
				assert.Equal(t, testFlow, recs[0]["flow"])
				assert.Equal(t, testSource, recs[0]["source"])
			},
		},
		{
			name: "a check whose context has ended is refused, and logged without sampling",
			expect: func(l *MockLimiter) {
				l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, _ string) (bool, error) {
						return true, ctx.Err()
					})
			},
			ctx: func(ctx context.Context) context.Context {
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				return cancelled
			},
			wantErr: ratelimit.ErrThrottled,
			assert: func(t *testing.T, recorder *logRecorder) {
				t.Helper()
				recs := logRecords(t, recorder)
				require.Len(t, recs, 1)
				assert.Equal(t, "DEBUG", recs[0]["level"],
					"a caller that hung up was reported as an incident")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			l := NewMockLimiter(ctrl)
			tc.expect(l)

			recorder, logger := newLogRecorder()
			g, err := ratelimit.NewSourceGuard(testFlow, l,
				ratelimit.WithSourceGuardLogger(logger))
			require.NoError(t, err)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			src, err := g.Check(ctx, testSource)
			require.ErrorIs(t, err, tc.wantErr,
				"a limiter that could not answer let the attempt through")
			assert.Empty(t, src.Key(), "a refused check handed back a source to record against")
			tc.assert(t, recorder)
		})
	}
}

// TestGuardChecksAndRecordsOnTheSameKey pins the pairing the guard exists for:
// what a check read and what a recording writes are the same key, and a client
// that hangs up mid-attempt is still charged for it.
func TestGuardChecksAndRecordsOnTheSameKey(t *testing.T) {
	t.Parallel()

	t.Run("the key Check reads is the key RecordFailure writes", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		l := NewMockLimiter(ctrl)

		var checked, recorded string
		l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).
			DoAndReturn(func(_ context.Context, k string) (bool, error) { checked = k; return false, nil })
		l.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).
			DoAndReturn(func(_ context.Context, k string) error { recorded = k; return nil })

		g := guardOver(t, l)

		src, err := g.Check(t.Context(), testSource)
		require.NoError(t, err)
		g.RecordFailure(t.Context(), src)

		assert.Equal(t, checked, recorded, "the guard recorded against a different key than it checked")
		assert.Contains(t, checked, testFlow, "the key does not name the flow it belongs to")
	})

	t.Run("recording survives a cancelled caller context", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		l := NewMockLimiter(ctrl)
		l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil)
		l.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).
			DoAndReturn(func(ctx context.Context, _ string) error {
				assert.NoError(t, ctx.Err(), "the guard passed on the caller's cancellation")
				return nil
			})

		g := guardOver(t, l)

		src, err := g.Check(t.Context(), testSource)
		require.NoError(t, err)

		cancelled, cancel := context.WithCancel(t.Context())
		cancel()
		g.RecordFailure(cancelled, src)
	})

	t.Run("a recording error is logged, not returned", func(t *testing.T) {
		t.Parallel()

		errBackendDown := errors.New("dial tcp: connection refused")

		ctrl := gomock.NewController(t)
		l := NewMockLimiter(ctrl)
		l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil)
		l.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Return(errBackendDown)

		recorder, logger := newLogRecorder()
		g, err := ratelimit.NewSourceGuard(testFlow, l, ratelimit.WithSourceGuardLogger(logger))
		require.NoError(t, err)

		src, err := g.Check(t.Context(), testSource)
		require.NoError(t, err)
		g.RecordFailure(t.Context(), src)

		recs := logRecords(t, recorder)
		require.Len(t, recs, 1, "a failure that went uncounted was never reported")
		assert.Equal(t, "limiter", recs[0]["reason"],
			"the record does not name what went wrong")
		assert.NotEmpty(t, recs[0]["error_type"],
			"the record does not name the error's type")
	})

	t.Run("a source that never came from a check records nothing", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		l := NewMockLimiter(ctrl) // no call is expected: recording must not invent a key

		recorder, logger := newLogRecorder()
		g, err := ratelimit.NewSourceGuard(testFlow, l, ratelimit.WithSourceGuardLogger(logger))
		require.NoError(t, err)

		g.RecordFailure(t.Context(), ratelimit.Source{})

		assert.NotEmpty(t, logRecords(t, recorder), "a dropped recording was never reported")
	})
}

// TestGuardRefusesUnattributableSourcesUnderDistinctReasons pins that each shape
// of unattributable address is refused before the limiter is consulted and
// logged under its own reason. Pooling them would let one attacker spend an
// allowance every other unattributable caller then depends on, and pooling their
// log records would let it suppress the evidence too.
func TestGuardRefusesUnattributableSourcesUnderDistinctReasons(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name       string
		addr       string
		wantErr    error
		wantReason string
	}

	cases := []testCase{
		{
			name:       "an empty address",
			addr:       "",
			wantErr:    ratelimit.ErrSourceEmpty,
			wantReason: "empty",
		},
		{
			name:       "a host and port that is not a single IP",
			addr:       "example.com:443",
			wantErr:    ratelimit.ErrSourceNotAnIP,
			wantReason: "not-an-ip",
		},
		{
			name:       "a forwarding list passed through verbatim",
			addr:       "198.51.100.1, 203.0.113.9",
			wantErr:    ratelimit.ErrSourceNotAnIP,
			wantReason: "not-an-ip",
		},
		{
			name:       "the unspecified address",
			addr:       "0.0.0.0",
			wantErr:    ratelimit.ErrSourceUnspecified,
			wantReason: "unspecified",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			l := NewMockLimiter(ctrl) // no call is expected: the limiter must not be consulted

			recorder, logger := newLogRecorder()
			g, err := ratelimit.NewSourceGuard(testFlow, l, ratelimit.WithSourceGuardLogger(logger))
			require.NoError(t, err)

			src, err := g.Check(t.Context(), tc.addr)
			require.ErrorIs(t, err, tc.wantErr)
			require.ErrorIs(t, err, ratelimit.ErrSourceUnattributable)
			assert.Empty(t, src.Key(), "an unattributable address still produced a key")

			recs := logRecords(t, recorder)
			require.Len(t, recs, 1)
			assert.Equal(t, tc.wantReason, recs[0]["reason"],
				"the refusal was not logged under its own reason")
			assert.Equal(t, testFlow, recs[0]["flow"])
		})
	}
}

// TestGuardsKeepFlowsApartUnlessDeliberatelyShared pins that a source exhausting
// one flow's allowance still has its own in another, and that sharing is
// available to a consumer who asks for it by sharing a limiter and a flow name.
func TestGuardsKeepFlowsApartUnlessDeliberatelyShared(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		guards func(t *testing.T) (first, second *ratelimit.SourceGuard)
		assert func(t *testing.T, err error)
	}

	shared := func(t *testing.T, err error) {
		t.Helper()
		require.ErrorIs(t, err, ratelimit.ErrThrottled,
			"two guards sharing a limiter and a flow did not share the count")
	}
	apart := func(t *testing.T, err error) {
		t.Helper()
		require.NoError(t, err, "one flow's exhausted allowance throttled another")
	}

	cases := []testCase{
		{
			name: "separate limiters keep separate counts",
			guards: func(t *testing.T) (*ratelimit.SourceGuard, *ratelimit.SourceGuard) {
				t.Helper()
				return guardOverFlow(t, "api-key", memoryLimiter(t)),
					guardOverFlow(t, "magic-link", memoryLimiter(t))
			},
			assert: apart,
		},
		{
			name: "one limiter with two flow names keeps separate counts",
			guards: func(t *testing.T) (*ratelimit.SourceGuard, *ratelimit.SourceGuard) {
				t.Helper()
				l := memoryLimiter(t)
				return guardOverFlow(t, "api-key", l), guardOverFlow(t, "magic-link", l)
			},
			assert: apart,
		},
		{
			name: "one limiter and one flow name share the count, deliberately",
			guards: func(t *testing.T) (*ratelimit.SourceGuard, *ratelimit.SourceGuard) {
				t.Helper()
				l := memoryLimiter(t)
				return guardOverFlow(t, "api-key", l), guardOverFlow(t, "api-key", l)
			},
			assert: shared,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			first, second := tc.guards(t)

			for range testLimit {
				src, err := first.Check(t.Context(), testSource)
				require.NoError(t, err)
				first.RecordFailure(t.Context(), src)
			}
			_, err := first.Check(t.Context(), testSource)
			require.ErrorIs(t, err, ratelimit.ErrThrottled, "the first flow never reached its limit")

			_, err = second.Check(t.Context(), testSource)
			tc.assert(t, err)
		})
	}
}

// TestAGuardCountsFailuresPerSourceNotPerCredential pins what the count is
// against: a source that rotates its guesses spends the same allowance, and a
// source that succeeds spends nothing.
func TestAGuardCountsFailuresPerSourceNotPerCredential(t *testing.T) {
	t.Parallel()

	g := guardOver(t, memoryLimiter(t))

	for range 100 {
		_, err := g.Check(t.Context(), testSource) // a successful attempt records nothing
		require.NoError(t, err)
	}

	for range testLimit {
		src, err := g.Check(t.Context(), testSource)
		require.NoError(t, err, "successful attempts spent the source's allowance")
		g.RecordFailure(t.Context(), src) // a different presented credential each time
	}

	_, err := g.Check(t.Context(), testSource)
	require.ErrorIs(t, err, ratelimit.ErrThrottled,
		"rotating the guessed credential bought a fresh allowance")

	_, err = g.Check(t.Context(), "203.0.113.9")
	require.NoError(t, err, "one source's failures throttled another source")
}

// TestAConsumerLimiterReplacesTheDefaultEntirely pins the override: a consumer
// that supplies its own limiter gets every check and record sent to it, and none
// of the default's per-replica caveat, which does not apply to it.
func TestAConsumerLimiterReplacesTheDefaultEntirely(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	l := NewMockLimiter(ctrl)
	l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil).Times(1)
	l.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Return(nil).Times(1)

	recorder, logger := newLogRecorder()
	g, err := ratelimit.NewSourceGuard(testFlow, l, ratelimit.WithSourceGuardLogger(logger))
	require.NoError(t, err)

	src, err := g.Check(t.Context(), testSource)
	require.NoError(t, err)
	g.RecordFailure(t.Context(), src)

	assert.NotContains(t, recorder.String(), "counts only this replica",
		"a consumer's own limiter was warned about as if it were the in-memory one")
}

// TestThrottleRefusalsAreSampled pins that an attacker cannot drown the logs
// with its own refusals, that nothing is lost while it tries, and that the
// window governing this guard governs nothing else.
func TestThrottleRefusalsAreSampled(t *testing.T) {
	t.Run("sampling keys on both the flow and the source", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			recorder, logger := newLogRecorder()
			guardA := alwaysThrottling(t, "api-key", logger)
			guardB := alwaysThrottling(t, "magic-link", logger)

			for range 20 {
				_, _ = guardA.Check(t.Context(), "198.51.100.7")
				_, _ = guardA.Check(t.Context(), "198.51.100.8")
				_, _ = guardB.Check(t.Context(), "198.51.100.7")
			}

			assert.Equal(t, 3, len(logRecords(t, recorder)),
				"sampling did not key on both flow and source")
		})
	})

	t.Run("one suppressed burst is reported in full", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			recorder, logger := newLogRecorder()
			g := alwaysThrottling(t, testFlow, logger)

			const attempts = 500
			for range attempts {
				_, _ = g.Check(t.Context(), testSource)
			}
			require.Len(t, logRecords(t, recorder), 1,
				"an attacker at the limit wrote one record per attempt")

			g.Flush()

			recs := logRecords(t, recorder)
			require.Len(t, recs, 2, "the suppressed refusals were never accounted for")
			assert.Equal(t, float64(attempts-1), recs[1]["suppressed"],
				"the report does not say how many refusals it stands for")
		})
	})

	t.Run("the log interval governs this guard alone", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			recorder, logger := newLogRecorder()
			// The default window is one minute; the other guard is given an hour.
			byDefault := alwaysThrottling(t, "api-key", logger)
			hourly := alwaysThrottling(t, "magic-link", logger,
				ratelimit.WithSourceGuardLogInterval(time.Hour))

			_, _ = byDefault.Check(t.Context(), testSource)
			_, _ = hourly.Check(t.Context(), testSource)
			require.Len(t, logRecords(t, recorder), 2, "the first refusal of each guard is written")

			time.Sleep(90 * time.Second)

			_, _ = byDefault.Check(t.Context(), testSource)
			_, _ = hourly.Check(t.Context(), testSource)

			recs := logRecords(t, recorder)
			require.Len(t, recs, 3,
				"one guard's log interval moved the other guard's window")
			assert.Equal(t, "api-key", recs[2]["flow"],
				"the guard whose own window had passed is not the one that wrote")
		})
	})

	t.Run("unattributable refusals are sampled under their own reasons", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			recorder, logger := newLogRecorder()
			g := alwaysThrottling(t, testFlow, logger)

			for range 20 {
				_, _ = g.Check(t.Context(), "")                          // empty
				_, _ = g.Check(t.Context(), "198.51.100.1, 203.0.113.9") // not-an-ip
			}

			recs := logRecords(t, recorder)
			require.Len(t, recs, 2,
				"one unattributable reason suppressed the records of another")
			assert.ElementsMatch(t, []any{"empty", "not-an-ip"},
				[]any{recs[0]["reason"], recs[1]["reason"]})
		})
	})

	t.Run("a limiter outage writes one record per window, not one per attempt", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			l := NewMockLimiter(gomock.NewController(t))
			l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).
				Return(false, errors.New("dial tcp: connection refused")).AnyTimes()

			recorder, logger := newLogRecorder()
			g, err := ratelimit.NewSourceGuard(testFlow, l, ratelimit.WithSourceGuardLogger(logger))
			require.NoError(t, err)

			for range 20 {
				_, _ = g.Check(t.Context(), testSource)
				_, _ = g.Check(t.Context(), "203.0.113.9")
			}

			assert.Len(t, logRecords(t, recorder), 1,
				"an outage was reported per attempt, so the flood of refusals it causes pays for itself")
		})
	})

	t.Run("a consumer disables sampling with an interval of zero", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			recorder, logger := newLogRecorder()
			g := alwaysThrottling(t, testFlow, logger, ratelimit.WithSourceGuardLogInterval(0))

			for range 5 {
				_, _ = g.Check(t.Context(), testSource)
			}

			assert.Len(t, logRecords(t, recorder), 5,
				"a consumer who turned sampling off still had refusals suppressed")
		})
	})
}

// guardOver builds a guard over l for the default flow, with a discarding
// logger, which is what the cases that assert on behaviour rather than on
// records want.
func guardOver(t *testing.T, l ratelimit.Limiter) *ratelimit.SourceGuard {
	t.Helper()

	return guardOverFlow(t, testFlow, l)
}

// guardOverFlow builds a quiet guard for a named flow, so a case can build two
// guards that differ only in their flow.
func guardOverFlow(t *testing.T, flow string, l ratelimit.Limiter) *ratelimit.SourceGuard {
	t.Helper()

	g, err := ratelimit.NewSourceGuard(flow, l, ratelimit.WithSourceGuardLogger(discardLogger()))
	require.NoError(t, err)

	return g
}

// memoryLimiter returns the default limiter, kept quiet.
func memoryLimiter(t *testing.T) *ratelimit.MemoryLimiter {
	t.Helper()

	l, err := ratelimit.NewMemoryLimiter(testLimit, testWindow,
		ratelimit.WithMemoryLimiterLogger(discardLogger()))
	require.NoError(t, err)

	return l
}

// alwaysThrottling returns a guard whose limiter reports every source as over
// its limit, which is the state the sampling cases are about.
func alwaysThrottling(t *testing.T, flow string, logger *slog.Logger, opts ...ratelimit.GuardOption) *ratelimit.SourceGuard {
	t.Helper()

	l := NewMockLimiter(gomock.NewController(t))
	l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(true, nil).AnyTimes()

	g, err := ratelimit.NewSourceGuard(flow, l,
		append([]ratelimit.GuardOption{ratelimit.WithSourceGuardLogger(logger)}, opts...)...)
	require.NoError(t, err)

	return g
}

// logRecords decodes what was written, so a case can count records and read
// their fields rather than match message text.
func logRecords(t *testing.T, recorder *logRecorder) []map[string]any {
	t.Helper()

	var out []map[string]any
	for line := range strings.Lines(recorder.String()) {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &rec), "log line %q", line)
		out = append(out, rec)
	}

	return out
}

// TestSourceGuard_Full pins how a guard reports a limiter that is holding its
// maximum number of keys: the attempt is refused like any other, but the record
// says the limiter is full, not that it is down, and a flood at the cap cannot
// take the sampling slot the outage record needs.
func TestSourceGuard_Full(t *testing.T) {
	t.Parallel()

	const (
		fullMsg    = "ratelimit: refusing an attempt because the limiter is full"
		notCounted = "ratelimit: a failed attempt was not counted because the limiter is full"
		fullKey    = "full:" + testFlow + ":"
	)

	errFull := fmt.Errorf("memory limiter: %w", ratelimit.ErrLimiterFull)
	errDown := errors.New("dial tcp: connection refused")

	type testCase struct {
		name string
		ctx  func(ctx context.Context) context.Context // nil means identity
		// addr is the client address checked; an IPv6 one inside the aggregate
		// gives the guard an aggregate limiter.
		addr string
		// limiters returns the source limiter and the aggregate limiter; the
		// latter is nil for a guard without an aggregate.
		limiters func(t *testing.T) (source, aggregate ratelimit.Limiter)
		// run is the exercise; nil means one Check of addr.
		run    func(t *testing.T, g *ratelimit.SourceGuard, ctx context.Context, addr string) (ratelimit.Source, error)
		assert func(t *testing.T, src ratelimit.Source, err error, records []map[string]any, summaries []summaryCall)
	}

	refusedAsFull := func(t *testing.T, src ratelimit.Source, err error) {
		t.Helper()
		require.ErrorIs(t, err, ratelimit.ErrThrottled)
		require.ErrorIs(t, err, ratelimit.ErrLimiterFull, "the limiter's own error was lost behind the refusal")
		assert.NotContains(t, err.Error(), "could not be consulted", "a full limiter was described as unreachable")
		assert.Equal(t, ratelimit.Source{}, src, "a refused check still handed back a source to record against")
	}

	cases := []testCase{
		{
			name: "source limiter full",
			addr: testSource,
			limiters: func(t *testing.T) (ratelimit.Limiter, ratelimit.Limiter) {
				t.Helper()
				l := NewMockLimiter(gomock.NewController(t))
				l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(true, errFull)
				return l, nil
			},
			assert: func(t *testing.T, src ratelimit.Source, err error, records []map[string]any, _ []summaryCall) {
				t.Helper()
				refusedAsFull(t, src, err)
				require.Len(t, records, 1, "exactly one record, and not the outage one")
				assert.Equal(t, "WARN", records[0]["level"])
				assert.Equal(t, fullMsg, records[0]["msg"])
				assert.Equal(t, "limiter-full", records[0]["reason"])
				assert.Equal(t, testSource, records[0]["source"])
				assert.Equal(t, testFlow, records[0]["flow"])
				assert.NotContains(t, records[0], "aggregate")
			},
		},
		{
			name: "aggregate limiter full",
			addr: aggregatedSource,
			limiters: func(t *testing.T) (ratelimit.Limiter, ratelimit.Limiter) {
				t.Helper()
				source := NewMockLimiter(gomock.NewController(t))
				source.EXPECT().Exceeded(gomock.Any(), sourceKey).Return(false, nil)
				aggregate := NewMockLimiter(gomock.NewController(t))
				aggregate.EXPECT().Exceeded(gomock.Any(), aggregateKey).Return(true, errFull)
				return source, aggregate
			},
			assert: func(t *testing.T, src ratelimit.Source, err error, records []map[string]any, _ []summaryCall) {
				t.Helper()
				refusedAsFull(t, src, err)
				require.Len(t, records, 1, "exactly one record, and not the outage one")
				assert.Equal(t, "WARN", records[0]["level"])
				assert.Equal(t, fullMsg, records[0]["msg"])
				assert.Equal(t, "limiter-full", records[0]["reason"])
				assert.Equal(t, "2001:db8:1:2::/64", records[0]["source"])
				assert.Equal(t, aggregatedPrefix, records[0]["aggregate"])
			},
		},
		{
			name: "aggregate limiter full at record time",
			addr: aggregatedSource,
			limiters: func(t *testing.T) (ratelimit.Limiter, ratelimit.Limiter) {
				t.Helper()
				source := NewMockLimiter(gomock.NewController(t))
				source.EXPECT().Exceeded(gomock.Any(), sourceKey).Return(false, nil).Times(2)
				source.EXPECT().RecordFailure(gomock.Any(), sourceKey).Return(nil).Times(2)
				aggregate := NewMockLimiter(gomock.NewController(t))
				aggregate.EXPECT().Exceeded(gomock.Any(), aggregateKey).Return(false, nil).Times(2)
				aggregate.EXPECT().RecordFailure(gomock.Any(), aggregateKey).Return(errFull).Times(2)
				return source, aggregate
			},
			run: func(t *testing.T, g *ratelimit.SourceGuard, ctx context.Context, addr string) (ratelimit.Source, error) {
				t.Helper()
				var (
					src ratelimit.Source
					err error
				)
				for range 2 {
					src, err = g.Check(ctx, addr)
					require.NoError(t, err)
					g.RecordFailure(ctx, src)
				}
				g.Flush()
				return src, err
			},
			assert: func(t *testing.T, _ ratelimit.Source, err error, records []map[string]any, summaries []summaryCall) {
				t.Helper()
				require.NoError(t, err)
				require.Len(t, records, 1, "the second uncounted failure was not sampled away")
				assert.Equal(t, "WARN", records[0]["level"])
				assert.Equal(t, notCounted, records[0]["msg"])
				assert.Equal(t, "limiter-full", records[0]["reason"])
				assert.Equal(t, "2001:db8:1:2::/64", records[0]["source"])
				assert.Equal(t, aggregatedPrefix, records[0]["aggregate"],
					"the record does not say it was the aggregate that was full")
				assert.Equal(t, []summaryCall{{key: fullKey, suppressed: 1}}, summaries,
					"the uncounted failure was not sampled under the full family")
			},
		},
		{
			name: "sampling",
			addr: testSource,
			limiters: func(t *testing.T) (ratelimit.Limiter, ratelimit.Limiter) {
				t.Helper()
				l := NewMockLimiter(gomock.NewController(t))
				l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(true, errFull).Times(20)
				return l, nil
			},
			run: func(t *testing.T, g *ratelimit.SourceGuard, ctx context.Context, addr string) (ratelimit.Source, error) {
				t.Helper()
				var (
					src ratelimit.Source
					err error
				)
				for range 20 {
					src, err = g.Check(ctx, addr)
				}
				g.Flush()
				return src, err
			},
			assert: func(t *testing.T, src ratelimit.Source, err error, records []map[string]any, summaries []summaryCall) {
				t.Helper()
				refusedAsFull(t, src, err)
				require.Len(t, records, 1, "a flood at the cap wrote a record per attempt")
				assert.Equal(t, fullMsg, records[0]["msg"])
				assert.Equal(t, []summaryCall{{key: fullKey, suppressed: 19}}, summaries,
					"Flush did not report the suppressed refusals under the full family")
			},
		},
		{
			name: "ended context is not full",
			addr: testSource,
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()
				return cctx
			},
			limiters: func(t *testing.T) (ratelimit.Limiter, ratelimit.Limiter) {
				t.Helper()
				l := NewMockLimiter(gomock.NewController(t))
				l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(true, context.Canceled)
				return l, nil
			},
			assert: func(t *testing.T, src ratelimit.Source, err error, records []map[string]any, _ []summaryCall) {
				t.Helper()
				require.ErrorIs(t, err, ratelimit.ErrThrottled)
				assert.NotErrorIs(t, err, ratelimit.ErrLimiterFull)
				assert.Equal(t, ratelimit.Source{}, src)
				require.Len(t, records, 1)
				assert.Equal(t, "DEBUG", records[0]["level"])
				assert.Equal(t, "ratelimit: refusing an attempt whose context had already ended", records[0]["msg"])
			},
		},
		{
			name: "full on record",
			addr: testSource,
			limiters: func(t *testing.T) (ratelimit.Limiter, ratelimit.Limiter) {
				t.Helper()
				l := NewMockLimiter(gomock.NewController(t))
				gomock.InOrder(
					l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil),
					l.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Return(errFull),
					l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, errDown),
				)
				return l, nil
			},
			run: func(t *testing.T, g *ratelimit.SourceGuard, ctx context.Context, addr string) (ratelimit.Source, error) {
				t.Helper()
				src, err := g.Check(ctx, addr)
				require.NoError(t, err)
				g.RecordFailure(ctx, src)

				// An outage after the flood must still find its own sampling slot.
				return g.Check(ctx, addr)
			},
			assert: func(t *testing.T, _ ratelimit.Source, err error, records []map[string]any, _ []summaryCall) {
				t.Helper()
				require.ErrorIs(t, err, ratelimit.ErrThrottled)
				require.Len(t, records, 2, "the full record and the outage record are both written")

				assert.Equal(t, "WARN", records[0]["level"])
				assert.Equal(t, notCounted, records[0]["msg"])
				assert.Equal(t, "limiter-full", records[0]["reason"])
				assert.Equal(t, testSource, records[0]["source"])
				assert.NotContains(t, records[0], "aggregate")

				assert.Equal(t, "ratelimit: refusing an attempt because the limiter could not be consulted",
					records[1]["msg"], "a full limiter at record time took the outage record's sampling slot")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			source, aggregate := tc.limiters(t)
			recorder, logger := newLogRecorder()
			summaries := &summaryRecorder{}
			opts := []ratelimit.GuardOption{
				ratelimit.WithSourceGuardLogger(logger),
				ratelimit.WithSourceGuardClock(clockwork.NewFakeClock()),
				ratelimit.WithSourceGuardLogReporter(summaries.report),
			}
			if aggregate != nil {
				opts = append(opts, ratelimit.WithSourceGuardIPv6Aggregate(aggregateBits, aggregate))
			}
			g, err := ratelimit.NewSourceGuard(testFlow, source, opts...)
			require.NoError(t, err)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			var src ratelimit.Source
			if tc.run != nil {
				src, err = tc.run(t, g, ctx, tc.addr)
			} else {
				src, err = g.Check(ctx, tc.addr)
			}

			tc.assert(t, src, err, logRecords(t, recorder), summaries.received())
		})
	}
}
