package recovery_test

// TestPortErrors_Start replaces slog.Default() for its duration, so it does
// not run in parallel, and it restores the logger it found.

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/notify"
	"github.com/kartaladev/scrty/recovery"
)

// startPortErrRowEnv names the row a child process runs. It is empty in the
// parent.
const startPortErrRowEnv = "SCRTY_RECOVERY_START_PORTERR_ROW"

// startPortErrRanMarker prefixes the line a child prints, followed by the
// row's name, after the row ran and passed.
const startPortErrRanMarker = "SCRTY_RECOVERY_START_PORTERR_RAN: "

// startNotFoundCycle claims to be identity.ErrUserNotFound through its own Is
// and contains itself through Unwrap() error. A check that believed its Is
// would conceal an outage as an unknown username.
type startNotFoundCycle struct{}

func (*startNotFoundCycle) Error() string   { return limPortErrSecret }
func (c *startNotFoundCycle) Unwrap() error { return c }
func (*startNotFoundCycle) Is(target error) bool {
	return target == identity.ErrUserNotFound //nolint:errorlint // identity of a sentinel
}

// startNotFoundCycleMany wraps identity.ErrUserNotFound beside itself through
// Unwrap() []error: a depth-first match finds the sentinel before the cycle.
type startNotFoundCycleMany struct{}

func (*startNotFoundCycleMany) Error() string { return limPortErrSecret }
func (c *startNotFoundCycleMany) Unwrap() []error {
	return []error{identity.ErrUserNotFound, c}
}

// errStartPortDown is the plain outage every parity run fails with.
var errStartPortDown = errors.New("port: connection refused")

// startSite names the port call a row fails.
type startSite string

const (
	startResolver startSite = "the contact resolver"
	startSender   startSite = "the sender"
	startLoader   startSite = "the user loader"
)

// startRecord is one record the recoverer's logger wrote, other than an abort
// record, reduced to what a consumer routes on.
type startRecord struct {
	level, msg, reason string
}

// startOutcome is what one Start through a failing port produced.
type startOutcome struct {
	// events are the security events the recoverer reported.
	events []event.Event

	// sendCalls is how many times the sender was asked to send.
	sendCalls int32

	// records are the recoverer's records other than abort records, and raw
	// all of its output.
	records []startRecord
	raw     string

	// aborts are the sanitizer's records on the recoverer's logger.
	aborts []map[string]any
}

// runStartSite runs Start on ctx against a port that fails the site's call
// with portErr. It fails the test when Start hangs or lets a panic escape.
func runStartSite(t *testing.T, ctx context.Context, site startSite, portErr error) startOutcome {
	t.Helper()

	f := newFixture(t)
	logs := &syncBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	own := &recoveryEvents{}

	var sendCalls atomic.Int32

	resolver := func(_ context.Context, d *identity.Details) (string, error) {
		return d.Username, nil
	}

	switch site {
	case startResolver:
		f.users.EXPECT().LoadByUsername(gomock.Any(), anaUsername).Return(anaDetails(), nil).Times(1)
		resolver = func(context.Context, *identity.Details) (string, error) { return "", portErr }
	case startSender:
		f.users.EXPECT().LoadByUsername(gomock.Any(), anaUsername).Return(anaDetails(), nil).Times(1)
		f.sender.EXPECT().Send(gomock.Any(), gomock.Any()).DoAndReturn(func(context.Context, notify.Message) error {
			sendCalls.Add(1)

			return portErr
		}).Times(1)
	case startLoader:
		f.users.EXPECT().LoadByUsername(gomock.Any(), anaUsername).Return(nil, portErr).Times(1)
	}

	// Any send the site does not fail is counted and succeeds.
	f.sender.EXPECT().Send(gomock.Any(), gomock.Any()).DoAndReturn(func(context.Context, notify.Message) error {
		sendCalls.Add(1)

		return nil
	}).AnyTimes()

	r, err := recovery.NewRecoverer(f.deps(), f.opts(recovery.WithContactResolver(resolver),
		recovery.WithSecurityEvents(own.sink), recovery.WithLogger(logger))...)
	require.NoError(t, err)

	type result struct {
		panicked bool
		value    any
	}

	done := make(chan result, 1)

	go func() {
		returned := false

		defer func() {
			if !returned {
				done <- result{panicked: true, value: recover()}
			}
		}()

		r.Start(ctx, anaUsername)

		returned = true
		done <- result{}
	}()

	select {
	case res := <-done:
		require.False(t, res.panicked, "a hostile port error escaped Start as a panic: %v", res.value)
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a hostile port error hung Start")
	}

	out := startOutcome{events: own.all(), sendCalls: sendCalls.Load(), raw: logs.String()}

	for _, rec := range limJSONRecords(t, out.raw) {
		if rec["msg"] == porterr.MsgClassificationAborted {
			out.aborts = append(out.aborts, rec)

			continue
		}

		reason, _ := rec["reason"].(string)
		out.records = append(out.records, startRecord{level: rec["level"].(string), msg: rec["msg"].(string), reason: reason})
	}

	return out
}

// startSiteRecord is the record the site writes for a port that failed, at
// the level a plain outage gets.
func startSiteRecord(site startSite) startRecord {
	switch site {
	case startResolver:
		return startRecord{level: "ERROR", msg: "recovery: start failed: the contact address could not be resolved", reason: "contact-resolver"}
	case startSender:
		return startRecord{level: "ERROR", msg: "recovery: start failed: the code could not be sent", reason: "sender"}
	default:
		return startRecord{level: "ERROR", msg: "recovery: start failed: the username could not be resolved", reason: "user-loader"}
	}
}

// TestPortErrors_Start pins that each port Start calls — the contact
// resolver, the sender and the user loader — failing with an error whose chain
// cannot be walked is answered exactly as a plain outage of that port: Start
// returns, reports RecoveryStarted for the same user, sends what a plain
// outage sends, and writes the same records at the same levels. A chain that
// claims identity.ErrUserNotFound but cannot be walked is an outage, never an
// unknown username. The sanitizer writes one record, to the recoverer's
// logger, and none to slog.Default().
func TestPortErrors_Start(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(startPortErrRowEnv)
	if only != "" {
		debug.SetMaxStack(64 << 20)
	}

	cancelled := func(ctx context.Context) context.Context {
		cctx, cancel := context.WithCancel(ctx)
		cancel()

		return cctx
	}

	type testCase struct {
		name string
		site startSite
		err  error

		// ctx modifies the context both runs of the row use. nil means the
		// test's own.
		ctx func(ctx context.Context) context.Context

		// child runs the row in a child process: unsanitized, it may
		// overflow the stack fatally.
		child bool

		// assert receives the plain outage's outcome and the row's.
		assert func(t *testing.T, plain, got startOutcome)
	}

	sameAsPlain := func(t *testing.T, site startSite, plain, got startOutcome) {
		t.Helper()

		require.Len(t, plain.events, 1, "precondition: a plain outage reports one event")
		require.Len(t, got.events, 1, "Start reports one event")
		assert.Equal(t, event.RecoveryStarted, got.events[0].Name)
		assert.Equal(t, plain.events[0].Name, got.events[0].Name)
		assert.Equal(t, plain.events[0].Outcome, got.events[0].Outcome)
		assert.Equal(t, plain.events[0].User, got.events[0].User, "the same user on the event")
		assert.Equal(t, plain.sendCalls, got.sendCalls, "the same sends attempted")
		assert.Equal(t, plain.records, got.records, "the same records, levels and reasons")

		assert.Contains(t, got.records, startSiteRecord(site), "the site's outage record")
		assert.NotContains(t, got.raw, limPortErrSecret, "a record quotes the error")

		if site == startLoader {
			assert.NotContains(t, got.raw, "no account for the submitted username", "an outage logged as an unknown username")
			assert.Empty(t, got.events[0].User, "no user resolved")
		} else {
			assert.Equal(t, anaID, got.events[0].User)
		}
	}

	asOutage := func(site startSite, reason string) func(t *testing.T, plain, got startOutcome) {
		return func(t *testing.T, plain, got startOutcome) {
			t.Helper()

			sameAsPlain(t, site, plain, got)

			require.Len(t, got.aborts, 1, "one abort record, on the recoverer's logger")
			assert.Equal(t, "ERROR", got.aborts[0]["level"])
			assert.Equal(t, reason, got.aborts[0]["reason"])

			raw, err := json.Marshal(got.aborts[0])
			require.NoError(t, err)
			assert.NotContains(t, string(raw), limPortErrSecret, "the abort record quotes the error")
		}
	}

	var cases []testCase

	for _, site := range []startSite{startResolver, startSender, startLoader} {
		prefix := string(site) + ": "

		cases = append(cases,
			testCase{name: prefix + "a cycle through Unwrap() error", site: site, err: &limCycleOne{},
				assert: asOutage(site, "budget")},
			testCase{name: prefix + "a cycle through Unwrap() []error", site: site, err: &limCycleMany{}, child: true,
				assert: asOutage(site, "budget")},
			testCase{name: prefix + "a link whose Unwrap panics", site: site, err: limPanicUnwrap{},
				assert: asOutage(site, "panic")},
			testCase{name: prefix + "a link whose Unwrap panics with nil", site: site, err: limPanicNilUnwrap{},
				assert: asOutage(site, "panic")},
			testCase{name: prefix + "a join that fans out", site: site, err: limFanOut(25),
				assert: asOutage(site, "budget")},
			testCase{
				name: prefix + "a cycle on a context the caller cancelled is an outage",
				site: site, err: &limCycleOne{}, ctx: cancelled,
				assert: asOutage(site, "budget"),
			},
			testCase{
				name: prefix + "a typed-nil root walks to the end and is answered as an outage",
				site: site, err: (*limTypedNil)(nil),
				assert: func(t *testing.T, plain, got startOutcome) {
					t.Helper()

					sameAsPlain(t, site, plain, got)
					assert.Empty(t, got.aborts, "a walk that completes writes no abort record")
				},
			},
		)
	}

	cases = append(cases,
		testCase{
			name: string(startLoader) + ": a cycle whose Is claims an unknown user is an outage",
			site: startLoader, err: &startNotFoundCycle{},
			assert: asOutage(startLoader, "budget"),
		},
		testCase{
			name: string(startLoader) + ": a cycle wrapping an unknown user beside itself is an outage",
			site: startLoader, err: &startNotFoundCycleMany{}, child: true,
			assert: asOutage(startLoader, "budget"),
		},
	)

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				startPortErrInChild(t, tc.name)

				return
			}

			defaults := limDefaultRecords(t)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			plain := runStartSite(t, ctx, tc.site, errStartPortDown)
			require.Empty(t, plain.aborts, "a plain outage writes no abort record")

			got := runStartSite(t, ctx, tc.site, tc.err)
			tc.assert(t, plain, got)

			for _, rec := range limJSONRecords(t, defaults.String()) {
				assert.NotEqual(t, porterr.MsgClassificationAborted, rec["msg"], "an abort record went to slog.Default()")
			}

			if only != "" && !t.Failed() {
				// Stdout, so the parent's CombinedOutput carries it.
				_, _ = os.Stdout.WriteString(startPortErrRanMarker + tc.name + "\n")
			}
		})
	}
}

// startPortErrInChild re-runs the current top-level test in a child process
// limited to row, and fails unless it exits 0 within a minute and prints the
// marker that shows it ran the row: a stack overflow is fatal and only a
// child can watch for one.
func startPortErrInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), startPortErrRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 8)], "\n"))

	// A child whose row name matched no case skips every row and exits 0: it
	// proves it ran the row only by printing the marker after the row passed.
	// One whole line must equal the marker.
	want := startPortErrRanMarker + row
	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.TrimSuffix(line, "\r") == want {
			return
		}
	}

	t.Fatalf("the child never ran row %q: no line equals %q; output:\n%s", row, want, out)
}
