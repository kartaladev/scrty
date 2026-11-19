package lockout_test

// Every test in this file replaces slog.Default() for its duration, so none of
// them runs in parallel, and each restores the logger it found.

import (
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

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/policy/lockout"
)

// lockoutPortRowEnv names the one row a child process runs. A cycle through
// Unwrap() []error overflows the stack, which is fatal and cannot be
// recovered, so only a child can watch for it.
const lockoutPortRowEnv = "SCRTY_LOCKOUT_PORTERR_ROW"

// lockoutPortSecret is the text every hostile fixture's Error returns, so a
// test can show that no reason or record quotes it.
const lockoutPortSecret = "lockout-port-secret"

// lockoutPortCycleOne contains itself through Unwrap() error.
type lockoutPortCycleOne struct{}

func (*lockoutPortCycleOne) Error() string   { return lockoutPortSecret }
func (c *lockoutPortCycleOne) Unwrap() error { return c }

// lockoutPortCycleMany contains itself through Unwrap() []error.
type lockoutPortCycleMany struct{}

func (*lockoutPortCycleMany) Error() string     { return lockoutPortSecret }
func (c *lockoutPortCycleMany) Unwrap() []error { return []error{c} }

// lockoutPortPanicUnwrap is a link whose Unwrap panics.
type lockoutPortPanicUnwrap struct{}

func (lockoutPortPanicUnwrap) Error() string { return lockoutPortSecret }
func (lockoutPortPanicUnwrap) Unwrap() error { panic("test: Unwrap panicked") }

// lockoutPortPanicNil is a link whose Unwrap panics with nil.
type lockoutPortPanicNil struct{}

func (lockoutPortPanicNil) Error() string { return lockoutPortSecret }
func (lockoutPortPanicNil) Unwrap() error { panic(nil) } //nolint:govet // the hostile case under test

// lockoutPortTypedNil is returned as a nil pointer inside a non-nil error.
type lockoutPortTypedNil struct{}

func (*lockoutPortTypedNil) Error() string { return lockoutPortSecret }

// lockoutPortFanOut is errors.Join(n, n) nested depth times: no cycle, but
// 2^depth paths for an unbounded walk.
func lockoutPortFanOut(depth int) error {
	err := errors.New(lockoutPortSecret)
	for range depth {
		err = errors.Join(err, err)
	}

	return err
}

// lockoutPortKind is one error a lockout store may return.
type lockoutPortKind struct {
	name string
	err  func() error

	// reason is the abort record's reason, and "" when the walk completes.
	reason string

	// child runs the row in a child process: unsanitized, it overflows the
	// stack fatally.
	child bool
}

func lockoutPortKinds() []lockoutPortKind {
	return []lockoutPortKind{
		{name: "self-cycle through Unwrap() error", err: func() error { return &lockoutPortCycleOne{} }, reason: "budget"},
		{
			name: "self-cycle through Unwrap() []error", err: func() error { return &lockoutPortCycleMany{} },
			reason: "budget", child: true,
		},
		{name: "panicking Unwrap", err: func() error { return lockoutPortPanicUnwrap{} }, reason: "panic"},
		{name: "Unwrap panicking with nil", err: func() error { return lockoutPortPanicNil{} }, reason: "panic"},
		{name: "join fanning out", err: func() error { return lockoutPortFanOut(25) }, reason: "budget"},
		// A typed-nil root is walked to the end, so it passes unchanged and is
		// answered as the plain outage is.
		{name: "typed-nil root", err: func() error { return (*lockoutPortTypedNil)(nil) }},
	}
}

// lockoutPortSentinels are every library sentinel a lockout refusal, or a
// purge's error, could be taken for. A row's verdict records errors.Is
// against each.
var lockoutPortSentinels = []error{
	lockout.ErrAccountLocked,
	lockout.ErrAccountHeld,
	lockout.ErrAttemptStoreFull,
	lockout.ErrReapUnsupported,
	lockout.ErrRetainSinceRequired,
	policy.ErrDenied,
	policy.ErrConfig,
	policy.ErrMFARequired,
	policy.ErrMFAEnrolmentRequired,
	policy.ErrFederatedAssuranceNotMet,
	policy.ErrMFARequirementLookupMissing,
	policy.ErrMFARequirementUnsatisfiable,
	policy.ErrSecondFactorSameChannel,
	policy.ErrSessionIdle,
	policy.ErrTooManySessions,
}

// lockoutPortVerdict is everything a caller can observe of one call: the
// decision without its reason, or a purge's count, then the error's text, the
// sentinels it matches, the lock it carries and whether it is a bare
// ErrRetainSinceRequired.
type lockoutPortVerdict struct {
	decision policy.Decision // Reason cleared
	removed  int
	isNil    bool
	text     string
	matches  map[string]bool
	locked   bool          // errors.As *lockout.Error
	wait     time.Duration // the lock's wait, the retry-after a caller reads
	bare     bool          // err == lockout.ErrRetainSinceRequired
}

// lockoutPortVerdictOf reads err as a caller would, every check bounded.
func lockoutPortVerdictOf(t *testing.T, err error) lockoutPortVerdict {
	t.Helper()

	v := lockoutPortVerdict{isNil: err == nil, matches: map[string]bool{}}
	if err == nil {
		return v
	}

	v.text = err.Error()
	v.bare = err == lockout.ErrRetainSinceRequired //nolint:errorlint // identity is what PurgeExpired promises

	for _, s := range lockoutPortSentinels {
		v.matches[s.Error()] = lockoutPortWithin(t, func() bool { return errors.Is(err, s) })
	}

	var lockErr *lockout.Error
	v.locked = lockoutPortWithin(t, func() bool { return errors.As(err, &lockErr) })
	if v.locked {
		v.wait = lockErr.Wait
	}

	return v
}

// lockoutPortWithin fails the test when call does not return in ten seconds
// or panics. The bound only catches hangs.
func lockoutPortWithin[T any](t *testing.T, call func() T) T {
	t.Helper()

	type result struct {
		v        T
		panicked bool
		value    any
	}

	done := make(chan result, 1)

	go func() {
		r := result{}
		returned := false

		defer func() {
			if !returned {
				r.panicked, r.value = true, recover()
			}

			done <- r
		}()

		r.v = call()
		returned = true
	}()

	select {
	case r := <-done:
		require.False(t, r.panicked, "a hostile store error escaped as a panic: %v", r.value)

		return r.v
	case <-time.After(10 * time.Second):
		require.FailNow(t, "a hostile store error hung the call")

		panic("unreachable")
	}
}

// lockoutPortRecord is one record a logger received: its message and its
// reason attribute.
type lockoutPortRecord struct {
	message, reason string
	text            string // every attribute, rendered, to show none quotes the error
}

// lockoutPortLogs keeps the records written through it.
type lockoutPortLogs struct {
	mu   sync.Mutex
	recs []lockoutPortRecord
}

func (h *lockoutPortLogs) Enabled(context.Context, slog.Level) bool { return true }

func (h *lockoutPortLogs) Handle(_ context.Context, r slog.Record) error {
	rec := lockoutPortRecord{message: r.Message}

	var b strings.Builder

	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "reason" {
			rec.reason = a.Value.String()
		}

		b.WriteString(a.String())
		b.WriteByte(' ')

		return true
	})

	rec.text = b.String()

	h.mu.Lock()
	defer h.mu.Unlock()

	h.recs = append(h.recs, rec)

	return nil
}

func (h *lockoutPortLogs) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h *lockoutPortLogs) WithGroup(string) slog.Handler { return h }

func (h *lockoutPortLogs) all() []lockoutPortRecord {
	h.mu.Lock()
	defer h.mu.Unlock()

	return append([]lockoutPortRecord(nil), h.recs...)
}

// aborts returns the sanitizer's records.
func (h *lockoutPortLogs) aborts() []lockoutPortRecord {
	var out []lockoutPortRecord

	for _, r := range h.all() {
		if r.message == porterr.MsgClassificationAborted {
			out = append(out, r)
		}
	}

	return out
}

// others returns the messages of every record that is not the sanitizer's.
func (h *lockoutPortLogs) others() []string {
	var out []string

	for _, r := range h.all() {
		if r.message != porterr.MsgClassificationAborted {
			out = append(out, r.message)
		}
	}

	return out
}

// lockoutPortSwapDefault routes slog.Default() to a recorder until the test
// ends. The test must not run in parallel.
func lockoutPortSwapDefault(t *testing.T) *lockoutPortLogs {
	t.Helper()

	h := &lockoutPortLogs{}
	previous := slog.Default()

	slog.SetDefault(slog.New(h))
	t.Cleanup(func() { slog.SetDefault(previous) })

	return h
}

// lockoutPortSite is one port read of the lockout policy. run builds a policy
// over strict mocks that fail the test on any call they were not told to
// expect, so a write of any record is caught, and returns what the call
// returned as a verdict.
type lockoutPortSite struct {
	name string
	run  func(t *testing.T, ctx context.Context, storeErr error, logger *slog.Logger) lockoutPortVerdict
}

// lockoutPortPolicy builds a policy over store at the tests' fixed instant,
// logging to logger.
func lockoutPortPolicy(t *testing.T, store policy.AttemptStore, logger *slog.Logger, opts ...lockout.Option) *lockout.Policy {
	t.Helper()

	all := append([]lockout.Option{
		lockout.WithClock(clockwork.NewFakeClockAt(lockoutNow)),
		lockout.WithAttemptStore(store),
		lockout.WithLogger(logger),
	}, opts...)

	p, err := lockout.New(all...)
	require.NoError(t, err)

	return p
}

// lockoutPortEvaluate evaluates p for "ada" on ctx, bounded.
func lockoutPortEvaluate(ctx context.Context, t *testing.T, p *lockout.Policy) lockoutPortVerdict {
	t.Helper()

	d := lockoutPortWithin(t, func() policy.Decision { return p.Evaluate(ctx, lockoutInput("ada")) })

	v := lockoutPortVerdictOf(t, d.Reason)
	d.Reason = nil
	v.decision = d

	return v
}

// lockoutPortPurge purges through p on ctx, bounded.
func lockoutPortPurge(ctx context.Context, t *testing.T, p *lockout.Policy) lockoutPortVerdict {
	t.Helper()

	type purged struct {
		removed int
		err     error
	}

	got := lockoutPortWithin(t, func() purged {
		n, err := p.PurgeExpired(ctx)

		return purged{n, err}
	})

	v := lockoutPortVerdictOf(t, got.err)
	v.removed = got.removed

	return v
}

func lockoutPortSites() []lockoutPortSite {
	streakLimit := lockout.WithFailureStreakLimit(lockout.NISTFailureStreakLimit)

	return []lockoutPortSite{
		{
			name: "Evaluate, FailureStreak",
			run: func(t *testing.T, ctx context.Context, storeErr error, logger *slog.Logger) lockoutPortVerdict {
				s := newStreakAttemptStore(t)
				s.MockFailureStreakStore.EXPECT().
					FailureStreak(gomock.Any(), "ada", lockoutNow.Add(-defaultCapRetention)).
					Return(lockout.FailureStreak{Failures: lockout.NISTFailureStreakLimit}, storeErr)

				return lockoutPortEvaluate(ctx, t, lockoutPortPolicy(t, s, logger, streakLimit))
			},
		},
		{
			name: "Evaluate, FailureCount in the window",
			run: func(t *testing.T, ctx context.Context, storeErr error, logger *slog.Logger) lockoutPortVerdict {
				s := NewMockAttemptStore(gomock.NewController(t))
				s.EXPECT().FailureCount(gomock.Any(), "ada", lockoutDefaultCutoff).Return(100, storeErr)

				return lockoutPortEvaluate(ctx, t, lockoutPortPolicy(t, s, logger))
			},
		},
		{
			name: "Evaluate, FailureCount inside the wait",
			run: func(t *testing.T, ctx context.Context, storeErr error, logger *slog.Logger) lockoutPortVerdict {
				s := NewMockAttemptStore(gomock.NewController(t))
				gomock.InOrder(
					s.EXPECT().FailureCount(gomock.Any(), "ada", lockoutDefaultCutoff).Return(5, nil),
					s.EXPECT().FailureCount(gomock.Any(), "ada", lockoutNow.Add(-30*time.Second)).Return(1, storeErr),
				)

				return lockoutPortEvaluate(ctx, t, lockoutPortPolicy(t, s, logger))
			},
		},
		{
			name: "PurgeExpired, DeleteAttemptsBefore",
			run: func(t *testing.T, ctx context.Context, storeErr error, logger *slog.Logger) lockoutPortVerdict {
				s := newStreakReaperStore(t)
				s.MockAttemptReaper.EXPECT().DeleteAttemptsBefore(gomock.Any(), lockoutDefaultCutoff).Return(7, storeErr)

				return lockoutPortPurge(ctx, t, lockoutPortPolicy(t, s, logger, streakLimit))
			},
		},
		{
			name: "PurgeExpired, DeleteStreaksBefore",
			run: func(t *testing.T, ctx context.Context, storeErr error, logger *slog.Logger) lockoutPortVerdict {
				s := newStreakReaperStore(t)
				gomock.InOrder(
					s.MockAttemptReaper.EXPECT().DeleteAttemptsBefore(gomock.Any(), lockoutDefaultCutoff).Return(3, nil),
					s.MockFailureStreakStore.EXPECT().
						DeleteStreaksBefore(gomock.Any(), lockoutNow.Add(-defaultCapRetention)).Return(2, storeErr),
				)

				return lockoutPortPurge(ctx, t, lockoutPortPolicy(t, s, logger, streakLimit))
			},
		},
	}
}

// TestLockoutPortErrors pins that a hostile error from any store read of the
// lockout policy is answered exactly as a plain store outage is: the same
// decision (a deny matching policy.ErrDenied, never a lock, a hold or an
// allow), the same text, the same sentinels, no wait, and nothing written. A
// purge returns the same count and an error that is never the bare
// ErrRetainSinceRequired. The abort is reported once, to the policy's own
// logger and not to slog.Default(), on a live or a cancelled context alike.
func TestLockoutPortErrors(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	childRow := os.Getenv(lockoutPortRowEnv)
	if childRow != "" {
		debug.SetMaxStack(64 << 20)
	}

	contexts := []struct {
		name string
		ctx  func(ctx context.Context) context.Context
	}{
		{name: "live", ctx: func(ctx context.Context) context.Context { return ctx }},
		{name: "cancelled", ctx: func(ctx context.Context) context.Context {
			cctx, cancel := context.WithCancel(ctx)
			cancel()

			return cctx
		}},
	}

	for _, site := range lockoutPortSites() {
		for _, c := range contexts {
			for _, kind := range lockoutPortKinds() {
				row := site.name + "/" + c.name + "/" + kind.name
				if childRow != "" && childRow != row {
					continue
				}

				t.Run(row, func(t *testing.T) {
					if kind.child && childRow == "" {
						lockoutPortInChild(t, row)

						return
					}

					defaults := lockoutPortSwapDefault(t)
					ctx := c.ctx(t.Context())

					plainLogs := &lockoutPortLogs{}
					plain := site.run(t, ctx, errAttemptStoreDown, slog.New(plainLogs))
					require.False(t, plain.isNil, "the reference outage must refuse")
					require.Empty(t, plainLogs.aborts(), "the reference writes no abort record")

					logs := &lockoutPortLogs{}
					got := site.run(t, ctx, kind.err(), slog.New(logs))

					assert.Equal(t, plain, got, "the outcome differs from a plain store outage")
					assert.NotContains(t, got.text, lockoutPortSecret, "the reason quotes the store's error")
					assert.False(t, got.matches[lockout.ErrAccountLocked.Error()], "a store failure claimed a lock")
					assert.False(t, got.matches[lockout.ErrAccountHeld.Error()], "a store failure claimed a hold")
					assert.False(t, got.bare, "a store failure came back as the bare ErrRetainSinceRequired")
					assert.Equal(t, plainLogs.others(), logs.others(), "the policy's other records")

					aborts := logs.aborts()
					if kind.reason == "" {
						assert.Empty(t, aborts, "a walk that completes writes no abort record")
					} else {
						require.Len(t, aborts, 1, "one abort record, on the policy's logger")
						assert.Equal(t, kind.reason, aborts[0].reason, "the abort's reason")
						assert.NotContains(t, aborts[0].text, lockoutPortSecret, "the record quotes the error")
					}

					assert.Empty(t, defaults.aborts(), "none on slog.Default()")

					if childRow != "" && !t.Failed() {
						fmt.Println(lockoutPortRanMarker(row))
					}
				})
			}
		}
	}
}

// TestLockoutPortErrorsMatchUnwalkable pins that a hostile store error reaches
// the caller as the sanitizer's fault, matching porterr.ErrUnwalkable, which a
// plain outage never does. It is how a caller tells the two apart, and
// nothing else differs.
func TestLockoutPortErrorsMatchUnwalkable(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	type testCase struct {
		name   string
		err    error
		assert func(t *testing.T, v lockoutPortVerdict, reason error)
	}

	cases := []testCase{
		{
			name: "a plain outage does not match ErrUnwalkable",
			err:  errAttemptStoreDown,
			assert: func(t *testing.T, _ lockoutPortVerdict, reason error) {
				assert.NotErrorIs(t, reason, porterr.ErrUnwalkable)
				assert.ErrorIs(t, reason, errAttemptStoreDown, "the cause was collapsed")
			},
		},
		{
			name: "a cycle matches ErrUnwalkable and reaches nothing of the store's",
			err:  &lockoutPortCycleOne{},
			assert: func(t *testing.T, _ lockoutPortVerdict, reason error) {
				assert.True(t, lockoutPortWithin(t, func() bool { return errors.Is(reason, porterr.ErrUnwalkable) }))

				var cyc *lockoutPortCycleOne
				assert.False(t, lockoutPortWithin(t, func() bool { return errors.As(reason, &cyc) }),
					"the store's error travelled on")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lockoutPortSwapDefault(t)

			s := NewMockAttemptStore(gomock.NewController(t))
			s.EXPECT().FailureCount(gomock.Any(), "ada", lockoutDefaultCutoff).Return(0, tc.err)

			p := lockoutPortPolicy(t, s, slog.New(&lockoutPortLogs{}))
			d := lockoutPortWithin(t, func() policy.Decision { return p.Evaluate(t.Context(), lockoutInput("ada")) })

			require.Equal(t, policy.Deny, d.Outcome)
			tc.assert(t, lockoutPortVerdictOf(t, d.Reason), d.Reason)
		})
	}
}

// TestLockoutPortErrors_DefaultLogger pins where the abort record goes when
// the consumer chose no logger: a policy built without WithLogger, or with
// WithLogger(nil), which is ignored, reports a hostile store error once to the
// slog.Default() it was built with, and still denies as a plain outage does.
func TestLockoutPortErrors_DefaultLogger(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	type testCase struct {
		name   string
		opts   []lockout.Option
		assert func(t *testing.T, d policy.Decision, defaults *lockoutPortLogs)
	}

	deniedOnce := func(t *testing.T, d policy.Decision, defaults *lockoutPortLogs) {
		require.Equal(t, policy.Deny, d.Outcome)
		assert.True(t, lockoutPortWithin(t, func() bool { return errors.Is(d.Reason, policy.ErrDenied) }))
		assert.False(t, lockoutPortWithin(t, func() bool { return errors.Is(d.Reason, lockout.ErrAccountLocked) }))

		aborts := defaults.aborts()
		require.Len(t, aborts, 1, "one abort record, on slog.Default()")
		assert.Equal(t, "budget", aborts[0].reason)
	}

	cases := []testCase{
		{name: "no WithLogger", assert: deniedOnce},
		{name: "WithLogger(nil) is ignored", opts: []lockout.Option{lockout.WithLogger(nil)}, assert: deniedOnce},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defaults := lockoutPortSwapDefault(t)

			s := NewMockAttemptStore(gomock.NewController(t))
			s.EXPECT().FailureCount(gomock.Any(), "ada", lockoutDefaultCutoff).Return(0, &lockoutPortCycleOne{})

			p, err := lockout.New(append([]lockout.Option{
				lockout.WithClock(clockwork.NewFakeClockAt(lockoutNow)),
				lockout.WithAttemptStore(s),
			}, tc.opts...)...)
			require.NoError(t, err)

			d := lockoutPortWithin(t, func() policy.Decision { return p.Evaluate(t.Context(), lockoutInput("ada")) })
			tc.assert(t, d, defaults)
		})
	}
}

// lockoutPortRanMarker is the line a child prints on stdout once its row has
// run and passed.
func lockoutPortRanMarker(row string) string { return "SCRTY-LOCKOUT-PORTERR-ROW-RAN:" + row }

// requireRanLine fails unless one line of the child's combined output equals
// marker exactly: not a substring, and not a line with a suffix.
func requireRanLine(t *testing.T, out []byte, marker string) {
	t.Helper()

	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.TrimSuffix(line, "\r") == marker {
			return
		}
	}

	t.Fatalf("the child exited 0 without running its row (no line equals %q); output:\n%s", marker, out)
}

// lockoutPortInChild re-runs the current top-level test in a child process
// limited to row, and fails unless it exits 0 within a minute: a stack
// overflow is fatal and only a child can watch for one.
func lockoutPortInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), lockoutPortRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 8)], "\n"))
	requireRanLine(t, out, lockoutPortRanMarker(row))
}
