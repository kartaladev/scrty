package ratelimit_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/ratelimit"
)

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
