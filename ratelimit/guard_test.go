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
	"sync"
	"sync/atomic"
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
			name:    "a flow name carrying a colon",
			flow:    "login:2001",
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

// TestCheckThenRecordOvershootsByAtMostTheConcurrency pins the bound the guard's
// godoc states, rather than an exact count. Checking and recording are separate
// calls, so a burst can have every attempt read the count before any of them has
// recorded; what must hold is that the overshoot is bounded by the burst itself
// and the limit still stops sustained guessing.
func TestCheckThenRecordOvershootsByAtMostTheConcurrency(t *testing.T) {
	t.Parallel()

	const (
		concurrency      = 8
		attemptsPerBurst = 25
	)

	g := guardOver(t, memoryLimiter(t))

	var passed atomic.Int64
	start := make(chan struct{})

	var wg sync.WaitGroup
	for range concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()

			<-start
			for range attemptsPerBurst {
				src, err := g.Check(t.Context(), testSource)
				if err != nil {
					continue
				}
				passed.Add(1)
				g.RecordFailure(t.Context(), src)
			}
		}()
	}
	close(start)
	wg.Wait()

	admitted := int(passed.Load())
	assert.LessOrEqual(t, admitted, testLimit+concurrency,
		"a concurrent burst overshot the limit by more than its own concurrency")
	assert.GreaterOrEqual(t, admitted, testLimit,
		"the limit's own allowance was never available")
	assert.Less(t, admitted, concurrency*attemptsPerBurst,
		"the guard admitted every attempt, so nothing was limited at all")
}

const (
	aggregateBits  = 56
	aggregateLimit = 4
	sourceLimit    = 5

	// aggregatedSource is an IPv6 source inside aggregatedPrefix, and these are
	// the keys a guard for testFlow counts it under.
	aggregatedSource = "2001:db8:1:2::1"
	sourceKey        = testFlow + ":2001:db8:1:2::/64"
	aggregateKey     = testFlow + ":2001:db8:1::/56"
	aggregatedPrefix = "2001:db8:1::/56"
)

// TestSourceGuard_Aggregate pins how a guard with an IPv6 aggregate checks and
// records: the source and its aggregate are both consulted, either one over its
// limit or unable to answer refuses the attempt, and a failure counts against
// both — one recording failing never skipping the other.
func TestSourceGuard_Aggregate(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// limiters returns the source limiter and the aggregate limiter.
		limiters func(t *testing.T) (source, aggregate ratelimit.Limiter)
		// failures are addresses that each pass a check and then record one
		// failure, before the check under test.
		failures []string
		addr     string
		assert   func(t *testing.T, src ratelimit.Source, err error, records []map[string]any)
	}

	inMemory := func(t *testing.T) (ratelimit.Limiter, ratelimit.Limiter) {
		t.Helper()
		return memoryLimiterOf(t, sourceLimit), memoryLimiterOf(t, aggregateLimit)
	}
	throttled := func(t *testing.T, src ratelimit.Source, err error, _ []map[string]any) {
		t.Helper()
		require.ErrorIs(t, err, ratelimit.ErrThrottled)
		assert.Equal(t, ratelimit.Source{}, src, "a refused check still handed back a source to record against")
	}
	admitted := func(t *testing.T, src ratelimit.Source, err error, _ []map[string]any) {
		t.Helper()
		require.NoError(t, err)
		assert.NotEmpty(t, src.Key())
	}
	// oneUncountedFailure is what a recording error leaves behind: the attempt
	// was still admitted, and the failure that went uncounted is on the record.
	oneUncountedFailure := func(t *testing.T, _ ratelimit.Source, err error, records []map[string]any) {
		t.Helper()
		require.NoError(t, err)
		require.Len(t, records, 1, "a failure that went uncounted was not reported")
		assert.Equal(t, "ratelimit: a failed attempt was not counted", records[0]["msg"])
	}

	cases := []testCase{
		{
			name:     "rotating /64s inside one aggregate are refused once the aggregate is over its limit",
			limiters: inMemory,
			failures: []string{"2001:db8:1:1::1", "2001:db8:1:2::1", "2001:db8:1:3::1", "2001:db8:1:4::1"},
			addr:     "2001:db8:1:5::1",
			assert:   throttled,
		},
		{
			name:     "another aggregate is unaffected",
			limiters: inMemory,
			failures: []string{"2001:db8:1:1::1", "2001:db8:1:2::1", "2001:db8:1:3::1", "2001:db8:1:4::1"},
			addr:     "2001:db8:1:100::1",
			assert:   admitted,
		},
		{
			// The aggregate mock has no expectations, so a call to it for an
			// IPv4 source, on the check or on the record, fails the case.
			name: "IPv4 consults only the source's own key",
			limiters: func(t *testing.T) (ratelimit.Limiter, ratelimit.Limiter) {
				t.Helper()
				return memoryLimiterOf(t, sourceLimit), NewMockLimiter(gomock.NewController(t))
			},
			failures: []string{"203.0.113.7"},
			addr:     "203.0.113.7",
			assert:   admitted,
		},
		{
			name: "a source over its limit is refused without asking the aggregate",
			limiters: func(t *testing.T) (ratelimit.Limiter, ratelimit.Limiter) {
				t.Helper()
				source := NewMockLimiter(gomock.NewController(t))
				source.EXPECT().Exceeded(gomock.Any(), sourceKey).Return(true, nil)
				return source, NewMockLimiter(gomock.NewController(t))
			},
			addr:   aggregatedSource,
			assert: throttled,
		},
		{
			name: "an aggregate over its limit is refused",
			limiters: func(t *testing.T) (ratelimit.Limiter, ratelimit.Limiter) {
				t.Helper()
				source := NewMockLimiter(gomock.NewController(t))
				source.EXPECT().Exceeded(gomock.Any(), sourceKey).Return(false, nil)
				aggregate := NewMockLimiter(gomock.NewController(t))
				aggregate.EXPECT().Exceeded(gomock.Any(), aggregateKey).Return(true, nil)
				return source, aggregate
			},
			addr:   aggregatedSource,
			assert: throttled,
		},
		{
			name: "an aggregate limiter error fails closed",
			limiters: func(t *testing.T) (ratelimit.Limiter, ratelimit.Limiter) {
				t.Helper()
				source := NewMockLimiter(gomock.NewController(t))
				source.EXPECT().Exceeded(gomock.Any(), sourceKey).Return(false, nil)
				aggregate := NewMockLimiter(gomock.NewController(t))
				aggregate.EXPECT().Exceeded(gomock.Any(), aggregateKey).
					Return(false, errors.New("dial tcp: connection refused"))
				return source, aggregate
			},
			addr: aggregatedSource,
			assert: func(t *testing.T, src ratelimit.Source, err error, records []map[string]any) {
				t.Helper()
				throttled(t, src, err, records)
				require.Len(t, records, 1, "an aggregate outage refused the attempt without a record")
				assert.Equal(t, "ratelimit: refusing an attempt because the limiter could not be consulted",
					records[0]["msg"])
			},
		},
		{
			name: "a source record that fails still records the aggregate",
			limiters: func(t *testing.T) (ratelimit.Limiter, ratelimit.Limiter) {
				t.Helper()
				source := NewMockLimiter(gomock.NewController(t))
				source.EXPECT().Exceeded(gomock.Any(), sourceKey).Return(false, nil).Times(2)
				source.EXPECT().RecordFailure(gomock.Any(), sourceKey).Return(errors.New("source store down"))
				aggregate := NewMockLimiter(gomock.NewController(t))
				aggregate.EXPECT().Exceeded(gomock.Any(), aggregateKey).Return(false, nil).Times(2)
				aggregate.EXPECT().RecordFailure(gomock.Any(), aggregateKey).Return(nil)
				return source, aggregate
			},
			failures: []string{aggregatedSource},
			addr:     aggregatedSource,
			assert:   oneUncountedFailure,
		},
		{
			name: "an aggregate record that fails does not undo the source's",
			limiters: func(t *testing.T) (ratelimit.Limiter, ratelimit.Limiter) {
				t.Helper()
				source := NewMockLimiter(gomock.NewController(t))
				source.EXPECT().Exceeded(gomock.Any(), sourceKey).Return(false, nil).Times(2)
				source.EXPECT().RecordFailure(gomock.Any(), sourceKey).Return(nil)
				aggregate := NewMockLimiter(gomock.NewController(t))
				aggregate.EXPECT().Exceeded(gomock.Any(), aggregateKey).Return(false, nil).Times(2)
				aggregate.EXPECT().RecordFailure(gomock.Any(), aggregateKey).Return(errors.New("aggregate store down"))
				return source, aggregate
			},
			failures: []string{aggregatedSource},
			addr:     aggregatedSource,
			assert: func(t *testing.T, src ratelimit.Source, err error, records []map[string]any) {
				t.Helper()
				oneUncountedFailure(t, src, err, records)
				assert.Equal(t, aggregatedPrefix, records[0]["aggregate"],
					"the record does not say it was the aggregate that went uncounted")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			source, aggregate := tc.limiters(t)
			recorder, logger := newLogRecorder()
			g, err := ratelimit.NewSourceGuard(testFlow, source,
				ratelimit.WithSourceGuardIPv6Aggregate(aggregateBits, aggregate),
				ratelimit.WithSourceGuardLogger(logger))
			require.NoError(t, err)

			for _, addr := range tc.failures {
				s, err := g.Check(t.Context(), addr)
				require.NoError(t, err, "the check before recording a failure from %s", addr)
				g.RecordFailure(t.Context(), s)
			}

			src, err := g.Check(t.Context(), tc.addr)
			tc.assert(t, src, err, logRecords(t, recorder))
		})
	}
}

// TestSourceGuard_AggregateLog pins that a client rotating through the /64s of
// one throttled aggregate writes one record per window, naming the aggregate,
// rather than one per /64 it moves to: sampling by source would let rotation
// buy a fresh record with every address, which is the logging cost sampling
// exists to deny.
func TestSourceGuard_AggregateLog(t *testing.T) {
	t.Parallel()

	recorder, logger := newLogRecorder()
	summaries := &summaryRecorder{}
	g, err := ratelimit.NewSourceGuard(testFlow, memoryLimiterOf(t, sourceLimit),
		ratelimit.WithSourceGuardIPv6Aggregate(aggregateBits, memoryLimiterOf(t, aggregateLimit)),
		ratelimit.WithSourceGuardLogger(logger),
		ratelimit.WithSourceGuardClock(clockwork.NewFakeClockAt(epoch)),
		ratelimit.WithSourceGuardLogReporter(summaries.report))
	require.NoError(t, err)

	for i := range aggregateLimit {
		s, err := g.Check(t.Context(), fmt.Sprintf("2001:db8:1:%x::1", i+1))
		require.NoError(t, err)
		g.RecordFailure(t.Context(), s)
	}

	const rotations = 50
	for i := range rotations {
		_, err := g.Check(t.Context(), fmt.Sprintf("2001:db8:1:%x::1", 0x10+i))
		require.ErrorIs(t, err, ratelimit.ErrThrottled, "rotation %d was admitted", i)
	}

	recs := logRecords(t, recorder)
	require.Len(t, recs, 1, "rotation inside one throttled aggregate must write exactly one record per window")
	assert.Equal(t, "WARN", recs[0]["level"])
	assert.Equal(t, "ratelimit: refusing an attempt from an IPv6 aggregate over its limit", recs[0]["msg"])
	assert.Equal(t, aggregatedPrefix, recs[0]["aggregate"])
	assert.Equal(t, "2001:db8:1:10::/64", recs[0]["source"])
	assert.Equal(t, testFlow, recs[0]["flow"])

	g.Flush()

	assert.Equal(t,
		[]summaryCall{{key: "throttled:" + testFlow + ":" + aggregatedPrefix, suppressed: rotations - 1}},
		summaries.received())
}

// TestSourceGuard_AggregateOutageRecordNamesAggregate pins what the refusal
// record says when a limiter cannot answer: it names the aggregate only when the
// aggregate limiter is the one that is down, so a reader can tell which of the
// two to go and fix. A context that had already ended is the caller's doing, not
// an outage, and is written at debug level instead.
func TestSourceGuard_AggregateOutageRecordNamesAggregate(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		ctx  func(ctx context.Context) context.Context // nil means identity
		// limiters returns the source limiter and the aggregate limiter.
		limiters func(t *testing.T) (source, aggregate ratelimit.Limiter)
		assert   func(t *testing.T, src ratelimit.Source, err error, records []map[string]any)
	}

	cancelled := func(ctx context.Context) context.Context {
		cctx, cancel := context.WithCancel(ctx)
		cancel()

		return cctx
	}

	cases := []testCase{
		{
			name: "an aggregate outage names the aggregate",
			limiters: func(t *testing.T) (ratelimit.Limiter, ratelimit.Limiter) {
				t.Helper()
				source := NewMockLimiter(gomock.NewController(t))
				source.EXPECT().Exceeded(gomock.Any(), sourceKey).Return(false, nil)
				aggregate := NewMockLimiter(gomock.NewController(t))
				aggregate.EXPECT().Exceeded(gomock.Any(), aggregateKey).Return(true, errors.New("down"))
				return source, aggregate
			},
			assert: func(t *testing.T, _ ratelimit.Source, err error, records []map[string]any) {
				t.Helper()
				require.ErrorIs(t, err, ratelimit.ErrThrottled)
				require.Len(t, records, 1)
				assert.Equal(t, "WARN", records[0]["level"])
				assert.Equal(t, aggregatedPrefix, records[0]["aggregate"])
			},
		},
		{
			name: "a source outage carries no aggregate",
			limiters: func(t *testing.T) (ratelimit.Limiter, ratelimit.Limiter) {
				t.Helper()
				source := NewMockLimiter(gomock.NewController(t))
				source.EXPECT().Exceeded(gomock.Any(), sourceKey).Return(true, errors.New("down"))
				return source, NewMockLimiter(gomock.NewController(t))
			},
			assert: func(t *testing.T, _ ratelimit.Source, err error, records []map[string]any) {
				t.Helper()
				require.ErrorIs(t, err, ratelimit.ErrThrottled)
				require.Len(t, records, 1)
				assert.Equal(t, "WARN", records[0]["level"])
				assert.NotContains(t, records[0], "aggregate")
			},
		},
		{
			name: "an aggregate check meeting an ended context is a debug record, not an outage",
			ctx:  cancelled,
			limiters: func(t *testing.T) (ratelimit.Limiter, ratelimit.Limiter) {
				t.Helper()
				source := NewMockLimiter(gomock.NewController(t))
				source.EXPECT().Exceeded(gomock.Any(), sourceKey).Return(false, nil)
				aggregate := NewMockLimiter(gomock.NewController(t))
				aggregate.EXPECT().Exceeded(gomock.Any(), aggregateKey).Return(true, context.Canceled)
				return source, aggregate
			},
			assert: func(t *testing.T, src ratelimit.Source, err error, records []map[string]any) {
				t.Helper()
				require.ErrorIs(t, err, ratelimit.ErrThrottled)
				assert.Equal(t, ratelimit.Source{}, src)
				require.Len(t, records, 1)
				assert.Equal(t, "DEBUG", records[0]["level"])
				assert.Equal(t, "ratelimit: refusing an attempt whose context had already ended", records[0]["msg"])
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			source, aggregate := tc.limiters(t)
			recorder, logger := newLogRecorder()
			g, err := ratelimit.NewSourceGuard(testFlow, source,
				ratelimit.WithSourceGuardIPv6Aggregate(aggregateBits, aggregate),
				ratelimit.WithSourceGuardLogger(logger))
			require.NoError(t, err)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			src, err := g.Check(ctx, aggregatedSource)
			tc.assert(t, src, err, logRecords(t, recorder))
		})
	}
}

// TestSourceGuard_RecordFailureFromAnotherGuardDoesNotPanic pins that a Source
// is a plain value any guard will accept: one handed to a guard without an
// aggregate counts against that guard's source key and nothing else.
func TestSourceGuard_RecordFailureFromAnotherGuardDoesNotPanic(t *testing.T) {
	t.Parallel()

	with, err := ratelimit.NewSourceGuard(testFlow, memoryLimiterOf(t, sourceLimit),
		ratelimit.WithSourceGuardIPv6Aggregate(aggregateBits, memoryLimiterOf(t, aggregateLimit)),
		ratelimit.WithSourceGuardLogger(discardLogger()))
	require.NoError(t, err)

	without, err := ratelimit.NewSourceGuard(testFlow, memoryLimiterOf(t, 1),
		ratelimit.WithSourceGuardLogger(discardLogger()))
	require.NoError(t, err)

	src, err := with.Check(t.Context(), aggregatedSource)
	require.NoError(t, err)

	require.NotPanics(t, func() { without.RecordFailure(t.Context(), src) })

	_, err = without.Check(t.Context(), aggregatedSource)
	require.ErrorIs(t, err, ratelimit.ErrThrottled, "the source key was not recorded by the guard without an aggregate")
}

// memoryLimiterOf returns a quiet in-memory limiter with its own limit, so the
// source and the aggregate can be given different ones.
func memoryLimiterOf(t *testing.T, limit int) *ratelimit.MemoryLimiter {
	t.Helper()

	l, err := ratelimit.NewMemoryLimiter(limit, time.Minute,
		ratelimit.WithMemoryLimiterLogger(discardLogger()))
	require.NoError(t, err)

	return l
}

// summaryCall is one report a consumer's summary reporter received.
type summaryCall struct {
	key        string
	suppressed int
}

// summaryRecorder is a consumer's reporter that keeps every call it receives.
type summaryRecorder struct {
	mu    sync.Mutex
	calls []summaryCall
}

func (r *summaryRecorder) report(key string, suppressed int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.calls = append(r.calls, summaryCall{key: key, suppressed: suppressed})
}

func (r *summaryRecorder) received() []summaryCall {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]summaryCall(nil), r.calls...)
}

// TestSourceGuardLogReporter pins where a guard's suppressed refusal counts go
// when its sampler lets them go: by default a summary record through the
// guard's logger, and to the consumer's reporter instead when one is given.
func TestSourceGuardLogReporter(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// opts returns the guard options under test; r is the consumer's
		// reporter, for the rows that install it.
		opts   func(r *summaryRecorder) []ratelimit.GuardOption
		assert func(t *testing.T, records []map[string]any, calls []summaryCall)
	}

	cases := []testCase{
		{
			name: "the default writes a summary record through the guard's logger",
			opts: func(*summaryRecorder) []ratelimit.GuardOption { return nil },
			assert: func(t *testing.T, records []map[string]any, calls []summaryCall) {
				t.Helper()

				assert.Empty(t, calls)
				require.Len(t, records, 2, "one throttled-source record, then one summary")
				assert.Equal(t, "ratelimit: refusal records suppressed", records[1]["msg"])
				assert.Equal(t, testFlow, records[1]["flow"])
				assert.Equal(t, float64(4), records[1]["suppressed"])
			},
		},
		{
			name: "a consumer reporter receives the summary in its place",
			opts: func(r *summaryRecorder) []ratelimit.GuardOption {
				return []ratelimit.GuardOption{ratelimit.WithSourceGuardLogReporter(r.report)}
			},
			assert: func(t *testing.T, records []map[string]any, calls []summaryCall) {
				t.Helper()

				require.Len(t, calls, 1, "the consumer's reporter was not given the suppressed count")
				assert.Equal(t, 4, calls[0].suppressed)
				assert.Contains(t, calls[0].key, testFlow, "the key names the flow it was sampled under")
				assert.Contains(t, calls[0].key, testSource, "the key names the source it was sampled under")
				assert.Len(t, records, 1,
					"the consumer's reporter replaces the summary record, it does not add to it")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				recorder, logger := newLogRecorder()
				r := &summaryRecorder{}
				g := alwaysThrottling(t, testFlow, logger, tc.opts(r)...)

				for range 5 {
					_, _ = g.Check(t.Context(), testSource)
				}

				g.Flush()

				tc.assert(t, logRecords(t, recorder), r.received())
			})
		})
	}
}

// limiterKeyText is the key a consumer's own limiter might quote in its own
// error — in a format the guard itself never produces, since a dependency's
// text is not something the library controls.
const limiterKeyText = "magic-link|203.0.113.7"

// errLimiterFixture is the dependency error every leak row proves against: a
// limiter's own text, quoting its key, an address and a user reference the
// record must never repeat.
var errLimiterFixture = fmt.Errorf(
	"limiter: key %s: store: Key (username)=(alice@example.com) for user u-123", limiterKeyText)

// TestGuardFailureRecords pins the diagnostic-redaction requirement: a
// limiter's own failure is recorded by a fixed reason and the error's Go
// type, never by the limiter's own text, while the deliberate fields — the
// flow and the throttled source's address — are kept.
//
// Each row's call sequence differs — a check that cannot consult the
// limiter, a check that is throttled, a recording the limiter fails — so each
// is a run closure rather than a shared call shape.
func TestGuardFailureRecords(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		run    func(t *testing.T) (*logRecorder, error)
		assert func(t *testing.T, recs []map[string]any, rendered string)
	}

	cases := []testCase{
		{
			name: "the limiter cannot say whether a source is over its limit",
			run: func(t *testing.T) (*logRecorder, error) {
				t.Helper()

				ctrl := gomock.NewController(t)
				l := NewMockLimiter(ctrl)
				l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, errLimiterFixture)

				recorder, logger := newLogRecorder()
				g, err := ratelimit.NewSourceGuard("magic-link", l, ratelimit.WithSourceGuardLogger(logger))
				require.NoError(t, err)

				_, checkErr := g.Check(t.Context(), "203.0.113.7")

				return recorder, checkErr
			},
			assert: func(t *testing.T, recs []map[string]any, rendered string) {
				t.Helper()

				require.Len(t, recs, 1)
				assert.Equal(t, "magic-link", recs[0]["flow"])
				assert.Equal(t, "limiter", recs[0]["reason"])
				assert.NotEmpty(t, recs[0]["error_type"])
				assert.NotContains(t, rendered, limiterKeyText, "the limiter's own key text leaked")
			},
		},
		{
			name: "a throttled source still writes its record with the deliberate source field",
			run: func(t *testing.T) (*logRecorder, error) {
				t.Helper()

				ctrl := gomock.NewController(t)
				l := NewMockLimiter(ctrl)
				l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(true, nil)

				recorder, logger := newLogRecorder()
				g, err := ratelimit.NewSourceGuard(testFlow, l, ratelimit.WithSourceGuardLogger(logger))
				require.NoError(t, err)

				_, checkErr := g.Check(t.Context(), testSource)

				return recorder, checkErr
			},
			assert: func(t *testing.T, recs []map[string]any, _ string) {
				t.Helper()

				require.Len(t, recs, 1)
				assert.Equal(t, testFlow, recs[0]["flow"])
				assert.Equal(t, testSource, recs[0]["source"], "the deliberate throttle field is kept")
			},
		},
		{
			// Found while reading guard.go alongside the named site above: the
			// same limiter dependency's error also reaches RecordFailure's own
			// failure record unredacted. It shares the fix, since it is the
			// same defect in the same file.
			name: "recording a failure the limiter cannot count",
			run: func(t *testing.T) (*logRecorder, error) {
				t.Helper()

				ctrl := gomock.NewController(t)
				l := NewMockLimiter(ctrl)
				l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil)
				l.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Return(errLimiterFixture)

				recorder, logger := newLogRecorder()
				g, err := ratelimit.NewSourceGuard(testFlow, l, ratelimit.WithSourceGuardLogger(logger))
				require.NoError(t, err)

				src, err := g.Check(t.Context(), testSource)
				require.NoError(t, err)

				g.RecordFailure(t.Context(), src)

				return recorder, nil
			},
			assert: func(t *testing.T, recs []map[string]any, rendered string) {
				t.Helper()

				require.Len(t, recs, 1)
				assert.Equal(t, "limiter", recs[0]["reason"])
				assert.NotEmpty(t, recs[0]["error_type"])
				assert.NotContains(t, rendered, limiterKeyText, "the limiter's own key text leaked")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			recorder, _ := tc.run(t)
			rendered := recorder.String()

			assert.NotContains(t, rendered, "alice@example.com", "a written record leaked the fixture address")
			assert.NotContains(t, rendered, "u-123", "a written record leaked the fixture user reference")

			tc.assert(t, logRecords(t, recorder), rendered)
		})
	}
}

// TestGuardReturnedErrors pins the diagnostic-redaction requirement for
// SourceGuard.Check's own returned error (design decision 8): a limiter
// failure comes back as fixed library text, with ErrThrottled and the
// limiter's own error both still reachable by identity, and the status this
// error maps to (httpsec.StatusForError, which keys on ErrThrottled) is
// therefore unchanged.
func TestGuardReturnedErrors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		run    func(t *testing.T) error
		assert func(t *testing.T, err error)
	}{
		{
			name: "the limiter cannot say whether a source is over its limit",
			run: func(t *testing.T) error {
				t.Helper()

				l := NewMockLimiter(gomock.NewController(t))
				l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, errLimiterFixture)

				g, err := ratelimit.NewSourceGuard(testFlow, l)
				require.NoError(t, err)

				_, checkErr := g.Check(t.Context(), testSource)

				return checkErr
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				assert.NotContains(t, err.Error(), "alice@example.com",
					"the returned error quoted the limiter's own text")
				assert.NotContains(t, err.Error(), "u-123",
					"the returned error quoted the limiter's own text")
				assert.NotContains(t, err.Error(), limiterKeyText,
					"the returned error quoted the limiter's own key")
				assert.ErrorIs(t, err, errLimiterFixture, "the limiter's own error is no longer reachable")
				assert.ErrorIs(t, err, ratelimit.ErrThrottled, "the throttle sentinel is no longer reachable")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.run(t))
		})
	}
}
