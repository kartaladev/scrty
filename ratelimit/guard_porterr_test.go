package ratelimit_test

// Every test in this file replaces slog.Default() for its duration, so none of
// them runs in parallel, and each restores the logger it found.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/ratelimit"
)

// guardPortErrRowEnv names the row a child process runs. It is empty in the
// parent.
const guardPortErrRowEnv = "SCRTY_RATELIMIT_GUARD_PORTERR_ROW"

// guardPortErrRan is what a child prints, as a line of its own followed by the
// row's name, once it has run its row to the end. A child whose row matched
// nothing prints nothing, and its parent fails rather than passing on an empty
// run.
const guardPortErrRan = "guard-porterr-row-ran:"

// guardHostileSecret is the text every hostile fixture's Error returns.
const guardHostileSecret = "guard-hostile-secret-text"

// guardPanicValue is what a panicking Unwrap panics with.
const guardPanicValue = "the limiter error's Unwrap panicked"

// guardWithin bounds one call into the guard, with the checks on its answer.
const guardWithin = 2 * time.Second

// guardPortAddr is an IPv6 client, so a guard with an aggregate counts it in
// both limiters.
const guardPortAddr = "2001:db8:1:2::1"

// msgLimiterFullReason is the reason a record about a full limiter carries.
const msgLimiterFullReason = "limiter-full"

// guardCycleOne is a chain that contains itself through Unwrap() error.
type guardCycleOne struct{}

func (*guardCycleOne) Error() string   { return guardHostileSecret }
func (c *guardCycleOne) Unwrap() error { return c }

// guardCycleMany is a chain that contains itself through Unwrap() []error.
type guardCycleMany struct{}

func (*guardCycleMany) Error() string     { return guardHostileSecret }
func (c *guardCycleMany) Unwrap() []error { return []error{c} }

// guardCycleWrapping wraps a sentinel and itself through Unwrap() []error:
// stdlib errors.Is finds the sentinel before it loops, and loops (to a fatal
// stack overflow) when asked for anything else.
type guardCycleWrapping struct{ sentinel error }

func (*guardCycleWrapping) Error() string { return guardHostileSecret }
func (c *guardCycleWrapping) Unwrap() []error {
	return []error{c.sentinel, c}
}

// guardUnwrapPanics is an error whose Unwrap panics.
type guardUnwrapPanics struct{}

func (guardUnwrapPanics) Error() string { return guardHostileSecret }
func (guardUnwrapPanics) Unwrap() error { panic(guardPanicValue) }

// guardUnwrapPanicsNil is an error whose Unwrap panics with nil.
type guardUnwrapPanicsNil struct{}

func (guardUnwrapPanicsNil) Error() string { return guardHostileSecret }
func (guardUnwrapPanicsNil) Unwrap() error { panic(nil) } //nolint:govet // the hostile case under test

// guardTypedNil is returned as a nil pointer inside a non-nil error.
type guardTypedNil struct{}

func (*guardTypedNil) Error() string { return guardHostileSecret }

// guardFanOut is errors.Join(n, n) nested depth times: no cycle, but 2^depth
// paths for an unbounded walk.
func guardFanOut(depth int) error {
	err := errors.New(guardHostileSecret)
	for range depth {
		err = errors.Join(err, err)
	}

	return err
}

// guardRecords is a slog.Handler that keeps every record it is handed.
type guardRecords struct {
	mu   sync.Mutex
	recs []slog.Record
}

func (*guardRecords) Enabled(context.Context, slog.Level) bool { return true }

func (h *guardRecords) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.recs = append(h.recs, r.Clone())

	return nil
}

func (h *guardRecords) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *guardRecords) WithGroup(string) slog.Handler      { return h }

func (h *guardRecords) all() []slog.Record {
	h.mu.Lock()
	defer h.mu.Unlock()

	return append([]slog.Record(nil), h.recs...)
}

// guardAborts returns the sanitizer's abort records among recs.
func guardAborts(recs []slog.Record) []slog.Record {
	var out []slog.Record

	for _, r := range recs {
		if r.Message == porterr.MsgClassificationAborted {
			out = append(out, r)
		}
	}

	return out
}

// guardSwapDefaultLogger points slog.Default() at a capturing handler until
// the test ends. The caller must not be parallel.
func guardSwapDefaultLogger(t *testing.T) *guardRecords {
	t.Helper()

	prev := slog.Default()
	logs := &guardRecords{}
	slog.SetDefault(slog.New(logs))
	t.Cleanup(func() { slog.SetDefault(prev) })

	return logs
}

// guardPortOutcome is what one call into the guard produced that a caller or
// an operator can observe.
type guardPortOutcome struct {
	// Check's refusal: whether it matches ErrThrottled and ErrLimiterFull,
	// and whether the Source it returned is the zero value.
	refused, throttled, full, zeroSource bool

	// answer is HasRecentFailures' or HasRecentAggregateFailures' answer.
	answer bool

	// records are the guard's records other than an abort, as "LEVEL msg",
	// and fullReason counts those naming a full limiter.
	records    []string
	fullReason int

	aborts []slog.Record
}

// guardPortSite is one guard call site whose limiter error the sanitizer
// stands in front of. run makes the call on ctx through a guard whose limiter
// fails at that site with portErr, logging to logger.
type guardPortSite struct {
	name string
	run  func(t *testing.T, ctx context.Context, portErr error, logger *slog.Logger) guardPortOutcome
}

// newPortErrGuard builds a guard over source, with aggregate as its IPv6
// aggregate when it is not nil.
func newPortErrGuard(t *testing.T, logger *slog.Logger, source, aggregate ratelimit.Limiter) *ratelimit.SourceGuard {
	t.Helper()

	opts := []ratelimit.GuardOption{ratelimit.WithSourceGuardLogger(logger)}
	if aggregate != nil {
		opts = append(opts, ratelimit.WithSourceGuardIPv6Aggregate(56, aggregate))
	}

	g, err := ratelimit.NewSourceGuard("login", source, opts...)
	require.NoError(t, err)

	return g
}

// checkOutcome reads Check's answer. It runs inside the bound, since an
// unsanitized refusal wraps the limiter's own chain.
func checkOutcome(src ratelimit.Source, err error) guardPortOutcome {
	return guardPortOutcome{
		refused:    err != nil,
		throttled:  errors.Is(err, ratelimit.ErrThrottled),
		full:       errors.Is(err, ratelimit.ErrLimiterFull),
		zeroSource: src == ratelimit.Source{},
	}
}

func guardPortSites() []guardPortSite {
	return []guardPortSite{
		{
			name: "check, the source limiter",
			run: func(t *testing.T, ctx context.Context, portErr error, logger *slog.Logger) guardPortOutcome {
				t.Helper()

				lim := NewMockLimiter(gomock.NewController(t))
				lim.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, portErr)

				g := newPortErrGuard(t, logger, lim, nil)

				return checkOutcome(g.Check(ctx, guardPortAddr))
			},
		},
		{
			name: "check, the aggregate limiter",
			run: func(t *testing.T, ctx context.Context, portErr error, logger *slog.Logger) guardPortOutcome {
				t.Helper()

				ctrl := gomock.NewController(t)
				lim := NewMockLimiter(ctrl)
				lim.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil)
				agg := NewMockLimiter(ctrl)
				agg.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, portErr)

				g := newPortErrGuard(t, logger, lim, agg)

				return checkOutcome(g.Check(ctx, guardPortAddr))
			},
		},
		{
			name: "recording a failure, the source limiter",
			run: func(t *testing.T, ctx context.Context, portErr error, logger *slog.Logger) guardPortOutcome {
				t.Helper()

				lim := NewMockLimiter(gomock.NewController(t))
				lim.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil)
				lim.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Return(portErr)

				g := newPortErrGuard(t, logger, lim, nil)

				src, err := g.Check(ctx, guardPortAddr)
				require.NoError(t, err)

				g.RecordFailure(ctx, src)

				return guardPortOutcome{}
			},
		},
		{
			name: "recording a failure, the aggregate limiter",
			run: func(t *testing.T, ctx context.Context, portErr error, logger *slog.Logger) guardPortOutcome {
				t.Helper()

				ctrl := gomock.NewController(t)
				lim := NewMockLimiter(ctrl)
				lim.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil)
				lim.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Return(nil)
				agg := NewMockLimiter(ctrl)
				agg.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil)
				agg.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Return(portErr)

				g := newPortErrGuard(t, logger, lim, agg)

				src, err := g.Check(ctx, guardPortAddr)
				require.NoError(t, err)

				g.RecordFailure(ctx, src)

				return guardPortOutcome{}
			},
		},
		{
			name: "recent failures, the source limiter",
			run: func(t *testing.T, ctx context.Context, portErr error, logger *slog.Logger) guardPortOutcome {
				t.Helper()

				ctrl := gomock.NewController(t)
				r := NewMockRecentFailureReporter(ctrl)
				r.EXPECT().HasRecentFailures(gomock.Any(), gomock.Any()).Return(false, portErr)

				g := newPortErrGuard(t, logger,
					reportingLimiter{MockLimiter: NewMockLimiter(ctrl), MockRecentFailureReporter: r}, nil)

				return guardPortOutcome{answer: g.HasRecentFailures(ctx, guardPortAddr)}
			},
		},
		{
			name: "recent failures, the aggregate limiter",
			run: func(t *testing.T, ctx context.Context, portErr error, logger *slog.Logger) guardPortOutcome {
				t.Helper()

				ctrl := gomock.NewController(t)
				r := NewMockRecentFailureReporter(ctrl)
				r.EXPECT().HasRecentFailures(gomock.Any(), gomock.Any()).Return(false, portErr)

				g := newPortErrGuard(t, logger, NewMockLimiter(ctrl),
					reportingLimiter{MockLimiter: NewMockLimiter(ctrl), MockRecentFailureReporter: r})

				return guardPortOutcome{answer: g.HasRecentAggregateFailures(ctx, guardPortAddr)}
			},
		},
	}
}

// guardPortErrKind is one error a limiter may return.
type guardPortErrKind struct {
	name string
	err  error

	// reason is the abort record's reason, and "" when the walk completes.
	reason string

	// child runs the row in a child process: unsanitized, it overflows the
	// stack fatally at some site.
	child bool

	// ctx, when set, restricts the row to the named context.
	ctx string
}

func guardPortErrKinds() []guardPortErrKind {
	return []guardPortErrKind{
		{name: "self-cycle through Unwrap() error", err: &guardCycleOne{}, reason: "budget"},
		{name: "self-cycle through Unwrap() []error", err: &guardCycleMany{}, reason: "budget", child: true},
		{name: "panicking Unwrap", err: guardUnwrapPanics{}, reason: "panic"},
		{name: "Unwrap panicking with nil", err: guardUnwrapPanicsNil{}, reason: "panic"},
		{name: "join fanning out", err: guardFanOut(25), reason: "budget"},
		{
			name: "cycle wrapping ErrLimiterFull", err: &guardCycleWrapping{sentinel: ratelimit.ErrLimiterFull},
			reason: "budget", child: true,
		},
		{
			name: "cycle wrapping ErrThrottled", err: &guardCycleWrapping{sentinel: ratelimit.ErrThrottled},
			reason: "budget", child: true,
		},
		{
			name: "cycle wrapping context.Canceled", err: &guardCycleWrapping{sentinel: context.Canceled},
			reason: "budget", child: true, ctx: "cancelled",
		},
		// Walked to the end, so it passes unchanged and is answered as any
		// plain limiter error.
		{name: "typed-nil root", err: (*guardTypedNil)(nil)},
	}
}

// guardRunWithin runs site on its own goroutine and fails the test when it
// does not return within guardWithin or lets a panic escape. A stack overflow
// still kills the process: only a child process can watch for one.
func guardRunWithin(t *testing.T, site guardPortSite, ctx context.Context, portErr error) guardPortOutcome {
	t.Helper()

	type result struct {
		out      guardPortOutcome
		panicked bool
		value    any
	}

	logs := &guardRecords{}
	done := make(chan result, 1)

	go func() {
		var r result

		returned := false

		defer func() {
			if !returned {
				r.panicked, r.value = true, recover()
			}

			done <- r
		}()

		r.out = site.run(t, ctx, portErr, slog.New(logs))
		returned = true
	}()

	var r result

	select {
	case r = <-done:
		require.False(t, r.panicked, "a hostile limiter error escaped as a panic: %v", r.value)
	case <-time.After(guardWithin):
		require.FailNow(t, "a hostile limiter error hung the guard")
	}

	for _, rec := range logs.all() {
		if rec.Message == porterr.MsgClassificationAborted {
			r.out.aborts = append(r.out.aborts, rec)

			continue
		}

		r.out.records = append(r.out.records, rec.Level.String()+" "+rec.Message)

		rec.Attrs(func(a slog.Attr) bool {
			if a.Key == "reason" && a.Value.String() == msgLimiterFullReason {
				r.out.fullReason++
			}

			return true
		})
	}

	return r.out
}

// TestPortErrors_SourceGuard pins that a hostile error from a consumer's
// limiter, at each place the guard asks one, is answered exactly as a plain
// limiter outage there: a check is refused as throttled behind the outage
// record, never as a full limiter; a failure that went uncounted is reported
// as not counted, never as full; and a recent-failures question is answered
// true. It is reported once, to the guard's own logger and not to
// slog.Default().
func TestPortErrors_SourceGuard(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	childRow := os.Getenv(guardPortErrRowEnv)
	if childRow != "" {
		debug.SetMaxStack(64 << 20)
	}

	contexts := []struct {
		name string
		ctx  func(ctx context.Context) context.Context
	}{
		{name: "live"},
		{name: "cancelled", ctx: func(ctx context.Context) context.Context {
			cctx, cancel := context.WithCancel(ctx)
			cancel()

			return cctx
		}},
	}

	plainOutage := errors.New("limiter: connection refused")

	for _, site := range guardPortSites() {
		for _, c := range contexts {
			for _, kind := range guardPortErrKinds() {
				row := site.name + "/" + c.name + "/" + kind.name
				if childRow != "" && childRow != row {
					continue
				}

				if kind.ctx != "" && kind.ctx != c.name {
					continue
				}

				t.Run(row, func(t *testing.T) {
					if kind.child && childRow == "" {
						guardPortErrInChild(t, row)

						return
					}

					defaults := guardSwapDefaultLogger(t)

					ctx := t.Context()
					if c.ctx != nil {
						ctx = c.ctx(ctx)
					}

					plain := guardRunWithin(t, site, ctx, plainOutage)
					require.Empty(t, plain.aborts, "the plain outage writes no abort record")
					require.NotEmpty(t, plain.records, "the plain outage is reported")
					require.Zero(t, plain.fullReason, "the plain outage is not a full limiter")

					got := guardRunWithin(t, site, ctx, kind.err)

					assert.Equal(t, plain.refused, got.refused, "refused")
					assert.Equal(t, plain.throttled, got.throttled, "matches ErrThrottled")
					assert.False(t, got.full, "a hostile error never matches ErrLimiterFull")
					assert.Equal(t, plain.zeroSource, got.zeroSource, "the zero Source")
					assert.Equal(t, plain.answer, got.answer, "recent failures answer")
					assert.Equal(t, plain.records, got.records, "the guard's records")
					assert.Zero(t, got.fullReason, "never reported as a full limiter")

					if kind.reason == "" {
						assert.Empty(t, got.aborts, "a walk that completes writes no abort record")
					} else {
						require.Len(t, got.aborts, 1, "one abort record, on the guard's logger")
						assertGuardAbortRecord(t, got.aborts[0], kind.reason)
					}

					assert.Empty(t, guardAborts(defaults.all()), "none on slog.Default()")

					if childRow != "" && !t.Failed() {
						fmt.Fprintln(os.Stdout, guardPortErrRan+row)
					}
				})
			}
		}
	}
}

// TestPortErrors_SourceGuardAbortRecordIsNotSampled pins that the abort record
// is written for every hostile error, while the guard's own not-counted record
// is sampled: two uncounted failures in one window write one not-counted
// record and two abort records. It replaces slog.Default().
func TestPortErrors_SourceGuardAbortRecordIsNotSampled(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	defaults := guardSwapDefaultLogger(t)

	site := guardPortSite{
		name: "recording two failures",
		run: func(t *testing.T, ctx context.Context, portErr error, logger *slog.Logger) guardPortOutcome {
			t.Helper()

			lim := NewMockLimiter(gomock.NewController(t))
			lim.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil)
			lim.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Return(portErr).Times(2)

			g := newPortErrGuard(t, logger, lim, nil)

			src, err := g.Check(ctx, guardPortAddr)
			require.NoError(t, err)

			g.RecordFailure(ctx, src)
			g.RecordFailure(ctx, src)

			return guardPortOutcome{}
		},
	}

	got := guardRunWithin(t, site, t.Context(), &guardCycleOne{})

	assert.Len(t, got.records, 1, "the not-counted record is sampled")
	require.Len(t, got.aborts, 2, "one abort record per hostile error, unsampled")
	assert.Empty(t, guardAborts(defaults.all()), "none on slog.Default()")
}

// assertGuardAbortRecord checks one abort record: Error level, the reason, and
// no text of the error or of a recovered panic anywhere in it.
func assertGuardAbortRecord(t *testing.T, r slog.Record, reason string) {
	t.Helper()

	assert.Equal(t, slog.LevelError, r.Level)

	var got string

	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "reason" {
			got = a.Value.String()
		}

		v := a.Value.String()
		assert.NotContains(t, v, guardHostileSecret, "attribute %q quotes the error's text", a.Key)
		assert.NotContains(t, v, guardPanicValue, "attribute %q quotes the panic's value", a.Key)

		return true
	})

	assert.Equal(t, reason, got, "the record names its reason")
}

// guardPortErrInChild re-runs the current top-level test in a child process
// limited to row, and fails unless it exits 0 within a minute having printed
// the row's marker line: a stack overflow is fatal and only a child can watch
// for one, and a row name that matched nothing would otherwise pass without
// running.
func guardPortErrInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), guardPortErrRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 8)], "\n"))

	ran := false

	sc := bufio.NewScanner(strings.NewReader(string(out)))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)

	for sc.Scan() {
		if sc.Text() == guardPortErrRan+row {
			ran = true
		}
	}

	require.NoError(t, sc.Err())
	assert.True(t, ran, "the child printed no line %q: it did not run its row", guardPortErrRan+row)
}
