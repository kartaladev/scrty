package lockout_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/internal/errwalk"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/policy/lockout"
)

// obsCycleOne contains itself through Unwrap() error.
type obsCycleOne struct{}

func (*obsCycleOne) Error() string   { return "cycle one" }
func (c *obsCycleOne) Unwrap() error { return c }

// obsCycleMany contains itself through Unwrap() []error.
type obsCycleMany struct{}

func (*obsCycleMany) Error() string     { return "cycle many" }
func (c *obsCycleMany) Unwrap() []error { return []error{c} }

// obsPanicUnwrap is a link whose Unwrap panics.
type obsPanicUnwrap struct{}

func (obsPanicUnwrap) Error() string { return "panic unwrap" }
func (obsPanicUnwrap) Unwrap() error { panic("test: Unwrap panicked") }

// obsPanicNil is a link whose Unwrap panics with nil.
type obsPanicNil struct{}

func (obsPanicNil) Error() string { return "panic nil" }
func (obsPanicNil) Unwrap() error { panic(nil) } //nolint:govet // the hostile case under test

// obsTypedNil is returned as a nil pointer inside a non-nil error.
type obsTypedNil struct{}

func (*obsTypedNil) Error() string { return "typed nil" }

// obsFanOut is errors.Join(n, n) nested depth times: no cycle, but 2^depth
// paths for an unbounded walk.
func obsFanOut(depth int) error {
	err := errors.New("fan out")
	for range depth {
		err = errors.Join(err, err)
	}

	return err
}

// obsChildMarker is what a child prints once it has run its row, so the parent
// can tell a row that ran from a name that matched no case.
func obsChildMarker(test, site, kind string) string {
	return "OBS-ROW-RAN " + test + "/" + site + "/" + kind
}

// obsChildEnv is set in the child process a fatal-on-failure row runs in.
const obsChildEnv = "SCRTY_LOCKOUT_OBS_CHILD"

// obsWithin runs call on its own goroutine and fails the test when it does
// not return within five seconds or lets a panic escape. A call that ends its
// goroutine through a failed expectation counts as returned: the failure is
// already recorded on t.
func obsWithin(t *testing.T, call func()) {
	t.Helper()

	type outcome struct {
		returned bool
		value    any
	}

	done := make(chan outcome, 1)

	go func() {
		returned := false

		defer func() {
			if returned {
				done <- outcome{returned: true}

				return
			}

			done <- outcome{value: recover()}
		}()

		call()

		returned = true
	}()

	select {
	case o := <-done:
		assert.True(t, o.returned || o.value == nil, "the call panicked: %v", o.value)
	case <-time.After(5 * time.Second):
		require.FailNow(t, "the call did not return within five seconds")
	}
}

// obsNoSink is a security event sink that drops everything, so a policy is
// watched and reads whether a failure locked its identifier.
func obsNoSink(context.Context, event.Event) {}

// obsSite is one log-only port read of the lockout policy: run provokes it
// with fail as the port's error, over a policy that logs to logger, and
// msg is the fixed text of the record the site writes for it.
type obsSite struct {
	name string
	msg  string
	run  func(t *testing.T, ctx context.Context, fail error, logger *slog.Logger)
}

const (
	obsMsgEventLost  = "lockout: a lock event was lost"
	obsMsgReportLost = "lockout: a lockout report was lost: the attempt store recorded the failure"
	obsMsgClearLost  = "lockout: a lockout report was lost: the attempt store could not count"
)

func obsSites() []obsSite {
	record := func(t *testing.T, ctx context.Context, p *lockout.Policy) {
		t.Helper()

		assert.NoError(t, p.Attempts().RecordFailure(ctx, "ada", lockoutNow))
	}
	reset := func(t *testing.T, ctx context.Context, p *lockout.Policy) {
		t.Helper()

		assert.NoError(t, p.Attempts().Reset(ctx, "ada"))
	}

	return []obsSite{
		{
			name: "LockedAtStreakRead",
			msg:  obsMsgEventLost,
			run: func(t *testing.T, ctx context.Context, fail error, logger *slog.Logger) {
				s := newStreakAttemptStore(t)
				s.MockFailureStreakStore.EXPECT().FailureStreak(gomock.Any(), "ada", gomock.Any()).
					Return(lockout.FailureStreak{}, fail)
				s.MockFailureStreakStore.EXPECT().AddStreakFailure(gomock.Any(), "ada", lockoutNow, gomock.Any(), 8).
					Return(lockout.FailureStreak{}, false, nil)
				s.MockAttemptStore.EXPECT().RecordFailure(gomock.Any(), "ada", lockoutNow).Return(nil)
				s.MockAttemptStore.EXPECT().FailureCount(gomock.Any(), "ada", gomock.Any()).Return(0, nil)

				p := lockoutWith(t, lockout.WithAttemptStore(s), lockout.WithFailureStreakLimit(8),
					lockout.WithSecurityEvents(obsNoSink), lockout.WithLogger(logger))
				record(t, ctx, p)
			},
		},
		{
			name: "LockedAtCountRead",
			msg:  obsMsgEventLost,
			run: func(t *testing.T, ctx context.Context, fail error, logger *slog.Logger) {
				s := NewMockAttemptStore(gomock.NewController(t))
				gomock.InOrder(
					s.EXPECT().FailureCount(gomock.Any(), "ada", gomock.Any()).Return(0, fail),
					s.EXPECT().RecordFailure(gomock.Any(), "ada", lockoutNow).Return(nil),
					s.EXPECT().FailureCount(gomock.Any(), "ada", gomock.Any()).Return(0, nil),
				)

				p := lockoutWith(t, lockout.WithAttemptStore(s),
					lockout.WithSecurityEvents(obsNoSink), lockout.WithLogger(logger))
				record(t, ctx, p)
			},
		},
		{
			name: "LockedAtRecencyRead",
			msg:  obsMsgEventLost,
			run: func(t *testing.T, ctx context.Context, fail error, logger *slog.Logger) {
				s := NewMockAttemptStore(gomock.NewController(t))
				gomock.InOrder(
					// A count between the threshold and the window failure
					// limit is what makes the policy read recency.
					s.EXPECT().FailureCount(gomock.Any(), "ada", gomock.Any()).Return(4, nil),
					s.EXPECT().FailureCount(gomock.Any(), "ada", gomock.Any()).Return(0, fail),
					s.EXPECT().RecordFailure(gomock.Any(), "ada", lockoutNow).Return(nil),
					s.EXPECT().FailureCount(gomock.Any(), "ada", gomock.Any()).Return(0, nil),
				)

				p := lockoutWith(t, lockout.WithAttemptStore(s),
					lockout.WithWaitThreshold(3), lockout.WithWindowFailureLimit(10),
					lockout.WithSecurityEvents(obsNoSink), lockout.WithLogger(logger))
				record(t, ctx, p)
			},
		},
		{
			name: "RecordedCountRead",
			msg:  obsMsgReportLost,
			run: func(t *testing.T, ctx context.Context, fail error, logger *slog.Logger) {
				s := NewMockAttemptStore(gomock.NewController(t))
				gomock.InOrder(
					s.EXPECT().RecordFailure(gomock.Any(), "ada", lockoutNow).Return(nil),
					s.EXPECT().FailureCount(gomock.Any(), "ada", gomock.Any()).Return(0, fail),
				)

				p := lockoutWith(t, lockout.WithAttemptStore(s),
					lockout.WithObserver(func(context.Context, lockout.Report) {}), lockout.WithLogger(logger))
				record(t, ctx, p)
			},
		},
		{
			name: "ResetCountRead",
			msg:  obsMsgClearLost,
			run: func(t *testing.T, ctx context.Context, fail error, logger *slog.Logger) {
				s := NewMockAttemptStore(gomock.NewController(t))
				gomock.InOrder(
					s.EXPECT().FailureCount(gomock.Any(), "ada", gomock.Any()).Return(0, fail),
					s.EXPECT().Reset(gomock.Any(), "ada").Return(nil),
				)

				p := lockoutWith(t, lockout.WithAttemptStore(s),
					lockout.WithObserver(func(context.Context, lockout.Report) {}), lockout.WithLogger(logger))
				reset(t, ctx, p)
			},
		},
		{
			name: "ResetStreakRead",
			msg:  obsMsgClearLost,
			run: func(t *testing.T, ctx context.Context, fail error, logger *slog.Logger) {
				s := newStreakAttemptStore(t)
				s.MockAttemptStore.EXPECT().FailureCount(gomock.Any(), "ada", gomock.Any()).Return(0, nil)
				s.MockFailureStreakStore.EXPECT().FailureStreak(gomock.Any(), "ada", gomock.Any()).
					Return(lockout.FailureStreak{}, fail)
				s.MockAttemptStore.EXPECT().Reset(gomock.Any(), "ada").Return(nil)

				p := lockoutWith(t, lockout.WithAttemptStore(s), lockout.WithFailureStreakLimit(8),
					lockout.WithObserver(func(context.Context, lockout.Report) {}), lockout.WithLogger(logger))
				reset(t, ctx, p)
			},
		},
	}
}

// obsRunSite provokes site with fail on a fresh logger, with slog.Default
// swapped for another buffer, and returns what each of the two received.
func obsRunSite(t *testing.T, ctx context.Context, site obsSite, fail error) (own, def string) {
	t.Helper()

	var ownBuf, defBuf bytes.Buffer

	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&defBuf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	obsWithin(t, func() {
		site.run(t, ctx, fail, slog.New(slog.NewTextHandler(&ownBuf, nil)))
	})

	return ownBuf.String(), defBuf.String()
}

// obsInChild re-runs one row in a child process and fails unless the child
// exits 0 within a minute. A stack overflow is fatal and cannot be recovered,
// so only a child can watch for one.
func obsInChild(t *testing.T, site, kind string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0],
		"-test.run=^TestObsPortErrors_LogOnlyReads$/^"+site+"$/^"+kind+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), obsChildEnv+"=1")

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 8)], "\n"))
	require.Contains(t, string(out), obsChildMarker("LogOnlyReads", site, kind),
		"the child exited 0 without running its row:\n%s", strings.Join(lines[:min(len(lines), 8)], "\n"))
}

// TestObsPortErrors_LogOnlyReads pins that a hostile error from an attempt
// store or streak store on a read whose only use is a log record is bounded
// and reported once, to the policy's logger, while the site's own record is
// written exactly as for a plain outage and the call returns as it does then.
func TestObsPortErrors_LogOnlyReads(t *testing.T) {
	// It swaps slog.Default, so it does not run in parallel.
	if os.Getenv(obsChildEnv) != "" {
		debug.SetMaxStack(64 << 20)
	}

	tests := []struct {
		name    string
		err     func() error
		hostile bool
		child   bool
		reason  string
	}{
		{name: "PlainOutage", err: func() error { return errAttemptStoreDown }},
		{name: "CycleOne", err: func() error { return &obsCycleOne{} }, hostile: true, reason: "reason=budget"},
		{name: "PanicUnwrap", err: func() error { return obsPanicUnwrap{} }, hostile: true, reason: "reason=panic"},
		{name: "CycleMany", err: func() error { return &obsCycleMany{} }, hostile: true, child: true, reason: "reason=budget"},
	}

	for _, site := range obsSites() {
		t.Run(site.name, func(t *testing.T) {
			for _, tc := range tests {
				t.Run(tc.name, func(t *testing.T) {
					if tc.child && os.Getenv(obsChildEnv) == "" {
						obsInChild(t, site.name, tc.name)

						return
					}

					own, def := obsRunSite(t, t.Context(), site, tc.err())

					assert.Equal(t, 1, strings.Count(own, site.msg),
						"the site's own record must be written once, as for a plain outage:\n%s", own)
					assert.Zero(t, strings.Count(def, porterr.MsgClassificationAborted),
						"the abort record went to slog.Default, not the policy's logger:\n%s", def)

					if !tc.hostile {
						assert.Zero(t, strings.Count(own, porterr.MsgClassificationAborted),
							"a plain outage must not write an abort record:\n%s", own)

						return
					}

					assert.Equal(t, 1, strings.Count(own, porterr.MsgClassificationAborted),
						"a hostile error must write exactly one abort record to the policy's logger:\n%s", own)
					assert.Contains(t, own, tc.reason)

					if tc.child {
						fmt.Println(obsChildMarker("LogOnlyReads", site.name, tc.name))
					}
				})
			}
		})
	}
}

// TestObsPortErrors_CancelledContext pins that a call whose context is
// already cancelled still writes the abort record, and still returns as it
// does for a plain outage.
func TestObsPortErrors_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	site := obsSites()[1]
	own, def := obsRunSite(t, ctx, site, &obsCycleOne{})

	assert.Equal(t, 1, strings.Count(own, site.msg), "the site's own record:\n%s", own)
	assert.Equal(t, 1, strings.Count(own, porterr.MsgClassificationAborted), "the abort record:\n%s", own)
	assert.Zero(t, strings.Count(def, porterr.MsgClassificationAborted), "slog.Default:\n%s", def)
}

// obsPassSite is one call of the lockout policy's attempt-store view whose
// store error is returned to the caller: run provokes it with fail as the
// hostile port's error over a policy that logs to logger, and returns what the
// call returned. joined sites also fail the other port with a plain error, and
// both sites fail both ports with fail.
type obsPassSite struct {
	name   string
	joined bool
	both   bool
	run    func(t *testing.T, ctx context.Context, fail error, logger *slog.Logger) error
}

func obsPassSites() []obsPassSite {
	return []obsPassSite{
		{
			name: "RecordLogWrite",
			run: func(t *testing.T, ctx context.Context, fail error, logger *slog.Logger) error {
				s := NewMockAttemptStore(gomock.NewController(t))
				s.EXPECT().RecordFailure(gomock.Any(), "ada", lockoutNow).Return(fail)

				p := lockoutWith(t, lockout.WithAttemptStore(s), lockout.WithLogger(logger))

				return p.Attempts().RecordFailure(ctx, "ada", lockoutNow)
			},
		},
		{
			name: "RecordStreakWrite",
			run: func(t *testing.T, ctx context.Context, fail error, logger *slog.Logger) error {
				s := newStreakAttemptStore(t)
				s.MockFailureStreakStore.EXPECT().AddStreakFailure(gomock.Any(), "ada", lockoutNow, gomock.Any(), 8).
					Return(lockout.FailureStreak{}, false, fail)
				s.MockAttemptStore.EXPECT().RecordFailure(gomock.Any(), "ada", lockoutNow).Return(nil)

				p := lockoutWith(t, lockout.WithAttemptStore(s), lockout.WithFailureStreakLimit(8),
					lockout.WithLogger(logger))

				return p.Attempts().RecordFailure(ctx, "ada", lockoutNow)
			},
		},
		{
			name:   "RecordJoinedStreakHostile",
			joined: true,
			run: func(t *testing.T, ctx context.Context, fail error, logger *slog.Logger) error {
				s := newStreakAttemptStore(t)
				s.MockFailureStreakStore.EXPECT().AddStreakFailure(gomock.Any(), "ada", lockoutNow, gomock.Any(), 8).
					Return(lockout.FailureStreak{}, false, fail)
				s.MockAttemptStore.EXPECT().RecordFailure(gomock.Any(), "ada", lockoutNow).Return(errAttemptStoreDown)

				p := lockoutWith(t, lockout.WithAttemptStore(s), lockout.WithFailureStreakLimit(8),
					lockout.WithLogger(logger))

				return p.Attempts().RecordFailure(ctx, "ada", lockoutNow)
			},
		},
		{
			name:   "RecordJoinedLogHostile",
			joined: true,
			run: func(t *testing.T, ctx context.Context, fail error, logger *slog.Logger) error {
				s := newStreakAttemptStore(t)
				s.MockFailureStreakStore.EXPECT().AddStreakFailure(gomock.Any(), "ada", lockoutNow, gomock.Any(), 8).
					Return(lockout.FailureStreak{}, false, errAttemptStoreDown)
				s.MockAttemptStore.EXPECT().RecordFailure(gomock.Any(), "ada", lockoutNow).Return(fail)

				p := lockoutWith(t, lockout.WithAttemptStore(s), lockout.WithFailureStreakLimit(8),
					lockout.WithLogger(logger))

				return p.Attempts().RecordFailure(ctx, "ada", lockoutNow)
			},
		},
		{
			name: "RecordBothHostile",
			both: true,
			run: func(t *testing.T, ctx context.Context, fail error, logger *slog.Logger) error {
				s := newStreakAttemptStore(t)
				s.MockFailureStreakStore.EXPECT().AddStreakFailure(gomock.Any(), "ada", lockoutNow, gomock.Any(), 8).
					Return(lockout.FailureStreak{}, false, fail)
				s.MockAttemptStore.EXPECT().RecordFailure(gomock.Any(), "ada", lockoutNow).Return(fail)

				p := lockoutWith(t, lockout.WithAttemptStore(s), lockout.WithFailureStreakLimit(8),
					lockout.WithLogger(logger))

				return p.Attempts().RecordFailure(ctx, "ada", lockoutNow)
			},
		},
		{
			name: "ResetWithoutObserver",
			run: func(t *testing.T, ctx context.Context, fail error, logger *slog.Logger) error {
				s := NewMockAttemptStore(gomock.NewController(t))
				s.EXPECT().Reset(gomock.Any(), "ada").Return(fail)

				p := lockoutWith(t, lockout.WithAttemptStore(s), lockout.WithLogger(logger))

				return p.Attempts().Reset(ctx, "ada")
			},
		},
		{
			name: "ResetWithObserver",
			run: func(t *testing.T, ctx context.Context, fail error, logger *slog.Logger) error {
				s := NewMockAttemptStore(gomock.NewController(t))
				gomock.InOrder(
					s.EXPECT().FailureCount(gomock.Any(), "ada", gomock.Any()).Return(0, nil),
					s.EXPECT().Reset(gomock.Any(), "ada").Return(fail),
				)

				p := lockoutWith(t, lockout.WithAttemptStore(s),
					lockout.WithObserver(func(context.Context, lockout.Report) {}), lockout.WithLogger(logger))

				return p.Attempts().Reset(ctx, "ada")
			},
		},
		{
			name: "FailureCountForwarder",
			run: func(t *testing.T, ctx context.Context, fail error, logger *slog.Logger) error {
				s := NewMockAttemptStore(gomock.NewController(t))
				s.EXPECT().FailureCount(gomock.Any(), "ada", gomock.Any()).Return(0, fail)

				p := lockoutWith(t, lockout.WithAttemptStore(s), lockout.WithLogger(logger))
				_, err := p.Attempts().FailureCount(ctx, "ada", lockoutNow)

				return err
			},
		},
	}
}

// obsPassInChild re-runs one TestObsPortErrors_PassUp row in a child process,
// for a row whose failure is a fatal stack overflow. The child must print the
// marker of the row it ran.
func obsPassInChild(t *testing.T, site, kind string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0],
		"-test.run=^TestObsPortErrors_PassUp$/^"+site+"$/^"+kind+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), obsChildEnv+"=1")

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	head := strings.Join(lines[:min(len(lines), 8)], "\n")
	require.NoError(t, err, "the child failed:\n%s", head)
	require.Contains(t, string(out), obsChildMarker("PassUp", site, kind),
		"the child exited 0 without running its row:\n%s", head)
}

// obsPassOutcome is everything a caller can observe of one pass-up call,
// read with every check bounded.
type obsPassOutcome struct {
	got         error
	walkAbort   error
	own, def    string
	matched     []error
	isUnwalk    bool
	isPlain     bool
	ctxCanceled bool
}

// obsPassRun runs site with fail over a policy logging to its own buffer, and
// reads the returned error as a caller would, all inside one bounded call so a
// returned error that loops forever fails the row instead of hanging it.
func obsPassRun(t *testing.T, ctx context.Context, site obsPassSite, fail error) obsPassOutcome {
	t.Helper()

	var ownBuf, defBuf bytes.Buffer

	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&defBuf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	sentinels := []error{
		lockout.ErrAccountLocked, lockout.ErrAccountHeld, lockout.ErrAttemptStoreFull,
		lockout.ErrReapUnsupported, lockout.ErrRetainSinceRequired, policy.ErrDenied, policy.ErrConfig,
	}

	var o obsPassOutcome

	obsWithin(t, func() {
		o.got = site.run(t, ctx, fail, slog.New(slog.NewTextHandler(&ownBuf, nil)))
		if o.got == nil {
			return
		}

		_, o.walkAbort = errwalk.Flatten(o.got)
		o.isUnwalk = errors.Is(o.got, porterr.ErrUnwalkable)
		o.isPlain = errors.Is(o.got, errAttemptStoreDown)
		o.ctxCanceled = errors.Is(o.got, context.Canceled)

		for _, s := range sentinels {
			if errors.Is(o.got, s) {
				o.matched = append(o.matched, s)
			}
		}
	})

	o.own, o.def = ownBuf.String(), defBuf.String()

	return o
}

// TestObsPortErrors_PassUp pins that a hostile error from the attempt store or
// streak store, on a call whose error goes back to the caller, comes back as a
// walkable error that matches porterr.ErrUnwalkable and no lockout or policy
// sentinel, is reported once per hostile error to the policy's logger, and that
// a plain error of the other port in the same call still comes back joined with
// it. Every check on the returned error is bounded, so an unsanitized cycle
// fails its row within seconds.
func TestObsPortErrors_PassUp(t *testing.T) {
	// It swaps slog.Default, so it does not run in parallel.
	if os.Getenv(obsChildEnv) != "" {
		debug.SetMaxStack(64 << 20)
	}

	tests := []struct {
		name    string
		err     func() error
		hostile bool
		child   bool
		reason  string
	}{
		{name: "PlainOutage", err: func() error { return errAttemptStoreDown }},
		{name: "CycleOne", err: func() error { return &obsCycleOne{} }, hostile: true, reason: "reason=budget"},
		{name: "PanicUnwrap", err: func() error { return obsPanicUnwrap{} }, hostile: true, reason: "reason=panic"},
		{name: "PanicNil", err: func() error { return obsPanicNil{} }, hostile: true, reason: "reason=panic"},
		{name: "FanOut", err: func() error { return obsFanOut(25) }, hostile: true, reason: "reason=budget"},
		{name: "CycleMany", err: func() error { return &obsCycleMany{} }, hostile: true, child: true, reason: "reason=budget"},
		// A typed-nil root is walked to the end, so it passes unchanged and is
		// answered as the plain outage is: no abort record.
		{name: "TypedNilRoot", err: func() error { return (*obsTypedNil)(nil) }},
	}

	for _, site := range obsPassSites() {
		t.Run(site.name, func(t *testing.T) {
			for _, tc := range tests {
				t.Run(tc.name, func(t *testing.T) {
					if tc.child && os.Getenv(obsChildEnv) == "" {
						obsPassInChild(t, site.name, tc.name)

						return
					}

					o := obsPassRun(t, t.Context(), site, tc.err())

					require.Error(t, o.got)
					assert.NoError(t, o.walkAbort, "the returned error must be walkable")
					assert.Empty(t, o.matched, "no lockout or policy sentinel may match")
					assert.Zero(t, strings.Count(o.def, porterr.MsgClassificationAborted),
						"the abort record went to slog.Default, not the policy's logger:\n%s", o.def)

					if !tc.hostile {
						if tc.name == "PlainOutage" {
							assert.True(t, o.isPlain, "a plain outage must come back as itself")
						}

						assert.False(t, o.isUnwalk, "a walkable error is not a fault")
						assert.Zero(t, strings.Count(o.own, porterr.MsgClassificationAborted),
							"a walkable error must not write an abort record:\n%s", o.own)

						return
					}

					want := 1
					if site.both {
						want = 2
					}

					assert.True(t, o.isUnwalk, "a hostile error must come back matching porterr.ErrUnwalkable")
					assert.Equal(t, want, strings.Count(o.own, porterr.MsgClassificationAborted),
						"a hostile error must write exactly one abort record each to the policy's logger:\n%s", o.own)
					assert.Contains(t, o.own, tc.reason)

					if site.joined {
						assert.True(t, o.isPlain, "the other port's plain error must still come back")
					}

					if tc.child {
						fmt.Println(obsChildMarker("PassUp", site.name, tc.name))
					}
				})
			}
		})
	}
}

// TestObsPortErrors_PassUpCancelledContext pins that a pass-up call whose
// context is already cancelled still writes the abort record once per hostile
// error, and still returns a fault as it does for a live context.
func TestObsPortErrors_PassUpCancelledContext(t *testing.T) {
	for _, site := range obsPassSites() {
		t.Run(site.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			cancel()

			o := obsPassRun(t, ctx, site, &obsCycleOne{})

			require.Error(t, o.got)
			assert.True(t, o.isUnwalk, "must come back matching porterr.ErrUnwalkable")
			assert.False(t, o.ctxCanceled, "the cancelled context must not leak into the answer")
			assert.Zero(t, strings.Count(o.def, porterr.MsgClassificationAborted), "slog.Default:\n%s", o.def)

			want := 1
			if site.both {
				want = 2
			}

			assert.Equal(t, want, strings.Count(o.own, porterr.MsgClassificationAborted),
				"the abort records:\n%s", o.own)
		})
	}
}
