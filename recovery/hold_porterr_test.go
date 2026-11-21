package recovery_test

// TestPortErrors_Hold replaces slog.Default() for its duration, so it does not
// run in parallel, and it restores the logger it found.

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/recovery"
)

// holdPortErrRowEnv names the row a child process runs. It is empty in the
// parent.
const holdPortErrRowEnv = "SCRTY_RECOVERY_HOLD_PORTERR_ROW"

// holdPortErrRanMarker prefixes the line a child prints, followed by the
// row's name, after the row ran and passed.
const holdPortErrRanMarker = "SCRTY_RECOVERY_HOLD_PORTERR_RAN: "

// errHoldPortDown is the plain outage every parity run fails with.
var errHoldPortDown = errors.New("store: connection refused")

// holdSite names the port call a row fails.
type holdSite string

const (
	holdInsert       holdSite = "the hold's record insert"
	holdDeleteUser   holdSite = "the hold's saved-set delete"
	holdFinishLoader holdSite = "the finish's user loader"
	holdFinishFind   holdSite = "the finish's record find"
	holdCancelFind   holdSite = "the cancel's record find"
	holdCancelRecord holdSite = "the cancel's record write"
	holdCancelLoader holdSite = "the cancel's user loader"
)

// holdReturns reports whether the site's flow returns an error: Recover and
// Finish do, Cancel answers nothing.
func holdReturns(site holdSite) bool {
	switch site {
	case holdInsert, holdDeleteUser, holdFinishLoader, holdFinishFind:
		return true
	default:
		return false
	}
}

// holdRecord is one record the recoverer's logger wrote, other than an abort
// record, reduced to what a consumer routes on.
type holdRecord struct {
	level, msg, reason string
}

// holdEvent is one security event, reduced to what parity compares.
type holdEvent struct {
	name    string
	outcome string
	user    identity.UserID
}

// holdOutcome is what one call through a failing port produced. Every error
// classification is made inside the bound, so a hostile chain that reaches the
// caller raw fails the run as a hang rather than hanging the test.
type holdOutcome struct {
	text string

	refused    bool
	notYet     bool
	unwalkable bool
	resultNil  bool

	events []holdEvent

	// state is the record's state after the call: none, pending, completed
	// or cancelled.
	state       string
	issued      int
	consumed    []string
	savedUsable bool
	held        int
	cancelled   int
	recovered   int
	messages    int

	// records are the recoverer's records other than abort records, and raw
	// all of its output.
	records []holdRecord
	raw     string

	// aborts are the sanitizer's records on the recoverer's logger.
	aborts []map[string]any
}

// holdRecordState reads the state of record rid from the env's own store.
func holdRecordState(t *testing.T, e *completeEnv, rid id.ID) string {
	t.Helper()

	rec, err := e.records.Find(t.Context(), rid)
	if errors.Is(err, recovery.ErrRecordNotFound) {
		return "none"
	}

	require.NoError(t, err)

	switch {
	case !rec.CompletedAt.IsZero():
		return "completed"
	case !rec.CancelledAt.IsZero():
		return "cancelled"
	default:
		return "pending"
	}
}

// runHoldSite runs the flow that reaches the site's call, on ctx, against a
// port that fails that call with portErr. Recover reaches the insert and the
// delete; Finish and Cancel run over a recovery already held. It fails the
// test when the flow, or the classification of its error, hangs or lets a
// panic escape.
func runHoldSite(ctx context.Context, t *testing.T, site holdSite, portErr error) holdOutcome {
	t.Helper()

	e := newCompleteEnv(t) //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
	logs := &syncBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	own := &recoveryEvents{}

	r, tokens, rid := e.faultyHold(t, recovery.WithSecurityEvents(own.sink), recovery.WithLogger(logger))
	req := savedAndIssuedReq(e)

	recoverCall := func(ctx context.Context) (*recovery.Result, error) { return r.Recover(ctx, req) }

	var call func(ctx context.Context) (*recovery.Result, error)

	switch site {
	case holdInsert:
		e.faults.arm(faultRecordsInsert, portErr)
		call = recoverCall
	case holdDeleteUser:
		e.faults.arm(faultCodesDeleteUser, portErr)
		call = recoverCall
	case holdFinishLoader, holdFinishFind:
		h := heldRecovery(t.Context(), t, r, req) //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
		e.clock.Advance(73 * time.Hour)

		if site == holdFinishLoader {
			e.failLookup(portErr)
		} else {
			e.faults.arm(faultRecordsFind, portErr)
		}

		call = func(ctx context.Context) (*recovery.Result, error) { return r.Finish(ctx, h.CompletionToken) }
	case holdCancelFind, holdCancelRecord, holdCancelLoader:
		heldRecovery(t.Context(), t, r, req) //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
		token := e.cancelToken(t)

		switch site {
		case holdCancelFind:
			e.faults.arm(faultRecordsFind, portErr)
		case holdCancelRecord:
			e.faults.arm(faultRecordsCancel, portErr)
		default:
			e.failLookup(portErr)
		}

		call = func(ctx context.Context) (*recovery.Result, error) {
			r.Cancel(ctx, token)

			return nil, nil
		}
	}

	type result struct {
		out      holdOutcome
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

		res, err := call(ctx)

		o := holdOutcome{resultNil: res == nil}
		if err != nil {
			o.text = err.Error()
			o.refused = errors.Is(err, recovery.ErrRefused)
			o.notYet = errors.Is(err, recovery.ErrNotYetCompletable)
			o.unwalkable = errors.Is(err, porterr.ErrUnwalkable)
		}

		returned = true
		done <- result{out: o}
	}()

	var out holdOutcome

	select {
	case res := <-done:
		require.False(t, res.panicked, "a hostile port error escaped the flow as a panic: %v", res.value)
		out = res.out
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a hostile port error hung the flow, or the classification of its error")
	}

	e.faults.arm(faultRecordsInsert, nil)
	e.faults.arm(faultCodesDeleteUser, nil)
	e.faults.arm(faultRecordsFind, nil)
	e.faults.arm(faultRecordsCancel, nil)
	e.failLookup(nil)

	for _, ev := range own.all() {
		out.events = append(out.events, holdEvent{name: ev.Name, outcome: ev.Outcome, user: ev.User})
	}

	out.state = holdRecordState(t, e, rid) //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
	out.issued = len(tokens.purposes())
	out.consumed = tokens.consumedPurposes()
	out.savedUsable = e.savedUsable(t.Context(), t, e.saved[1]) //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
	out.held = len(e.out.heldNotices())
	out.cancelled = len(e.out.cancelledNotices())
	out.recovered = len(e.out.recoveredNotices())
	out.messages = len(e.out.messages())
	out.raw = logs.String()

	for _, rec := range limJSONRecords(t, out.raw) {
		if rec["msg"] == porterr.MsgClassificationAborted {
			out.aborts = append(out.aborts, rec)

			continue
		}

		reason, _ := rec["reason"].(string)
		out.records = append(out.records, holdRecord{level: rec["level"].(string), msg: rec["msg"].(string), reason: reason})
	}

	return out
}

// TestPortErrors_Hold pins that each port call a held recovery makes — the
// hold's record insert and saved-set delete, the finish's record find and
// user loader, and the cancel's record find, record write and user loader —
// failing with an error whose chain cannot be walked is answered exactly as a
// plain outage of that port: the same error class, the same events, the same
// record state, tokens, codes and notices, and the same records. A chain that
// claims or wraps the not-found sentinel the site branches on never takes the
// not-found branch: the finish answers a lookup or store failure, never a
// refusal, and the cancel logs a store outage. Cancel answers nothing either
// way. The sanitizer writes one record, to the recoverer's logger, and none
// to slog.Default().
func TestPortErrors_Hold(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(holdPortErrRowEnv)
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
		site holdSite
		err  error

		// ctx modifies the context both runs of the row use. nil means the
		// test's own.
		ctx func(ctx context.Context) context.Context

		// child runs the row in a child process: unsanitized, it may
		// overflow the stack fatally.
		child bool

		// assert receives the plain run's outcome and the row's.
		assert func(t *testing.T, plain, got holdOutcome)
	}

	// sameAsPlain compares everything but the error's own text.
	sameAsPlain := func(t *testing.T, plain, got holdOutcome) {
		t.Helper()

		assert.Equal(t, plain.resultNil, got.resultNil, "a result handed out alike")
		assert.Equal(t, plain.refused, got.refused, "ErrRefused")
		assert.Equal(t, plain.notYet, got.notYet, "ErrNotYetCompletable")
		assert.Equal(t, plain.events, got.events, "the same events")
		assert.Equal(t, plain.state, got.state, "the record left alike")
		assert.Equal(t, plain.issued, got.issued, "the same hold tokens issued")
		assert.Equal(t, plain.consumed, got.consumed, "the same hold tokens consumed")
		assert.Equal(t, plain.savedUsable, got.savedUsable, "the saved set voided alike")
		assert.Equal(t, plain.held, got.held, "the same held notices")
		assert.Equal(t, plain.cancelled, got.cancelled, "the same cancelled notices")
		assert.Equal(t, plain.recovered, got.recovered, "the same recovered notices")
		assert.Equal(t, plain.messages, got.messages, "the same messages sent")
		assert.Equal(t, plain.records, got.records, "the same records, levels and reasons")
	}

	asOutage := func(site holdSite, reason string) func(t *testing.T, plain, got holdOutcome) {
		return func(t *testing.T, plain, got holdOutcome) {
			t.Helper()

			sameAsPlain(t, plain, got)

			if holdReturns(site) {
				require.False(t, plain.refused, "precondition: a plain outage is not a refusal")
				require.NotEmpty(t, plain.text, "precondition: a plain outage is returned")
				assert.False(t, got.refused, "an outage answered as a refusal")
				assert.True(t, got.unwalkable, "the answer is a fault standing for the port's error")
				assert.Equal(t, plain.text, got.text, "the same fixed text")
			} else {
				assert.Empty(t, got.text, "Cancel answers nothing")
			}

			assert.NotContains(t, got.text, limPortErrSecret, "the returned error quotes the port's")
			assert.NotContains(t, got.raw, limPortErrSecret, "a record quotes the port's error")

			require.Len(t, got.aborts, 1, "one abort record, on the recoverer's logger")
			assert.Equal(t, "ERROR", got.aborts[0]["level"])
			assert.Equal(t, reason, got.aborts[0]["reason"])

			raw, err := json.Marshal(got.aborts[0])
			require.NoError(t, err)
			assert.NotContains(t, string(raw), limPortErrSecret, "the abort record quotes the error")
		}
	}

	// walked is a chain the sanitizer reads to its end: answered as a plain
	// error is, with no abort record.
	walked := func(t *testing.T, plain, got holdOutcome) {
		t.Helper()

		sameAsPlain(t, plain, got)
		assert.False(t, got.unwalkable, "a walkable error replaced by a fault")
		assert.Equal(t, plain.text, got.text, "the same fixed text")
		assert.Empty(t, got.aborts, "a walk that completes writes no abort record")
	}

	var cases []testCase

	sites := []holdSite{
		holdInsert, holdDeleteUser, holdFinishLoader, holdFinishFind, holdCancelFind, holdCancelRecord, holdCancelLoader,
	}

	for _, site := range sites {
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
				name: prefix + "a typed-nil root walks to the end and is answered as a plain error",
				site: site, err: (*limTypedNil)(nil),
				assert: walked,
			},
		)
	}

	// The not-found sentinels the finish and the cancel branch on, claimed
	// through Is by a cycle and wrapped beside a cycle through Unwrap() []error.
	claimed := []struct {
		site     holdSite
		sentinel error
		label    string
	}{
		{holdFinishLoader, identity.ErrUserNotFound, "an unknown user"},
		{holdFinishFind, recovery.ErrRecordNotFound, "an unknown record"},
		{holdCancelFind, recovery.ErrRecordNotFound, "an unknown record"},
	}

	for _, c := range claimed {
		prefix := string(c.site) + ": "

		cases = append(cases,
			testCase{
				name: prefix + "a cycle whose Is claims " + c.label + " is an outage",
				site: c.site, err: &recClaimCycle{claims: c.sentinel},
				assert: asOutage(c.site, "budget"),
			},
			testCase{
				name: prefix + "a cycle wrapping " + c.label + " beside itself is an outage",
				site: c.site, err: &recWrapCycleMany{wraps: c.sentinel}, child: true,
				assert: asOutage(c.site, "budget"),
			},
		)
	}

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				holdPortErrInChild(t, tc.name)

				return
			}

			defaults := limDefaultRecords(t)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			plain := runHoldSite(ctx, t, tc.site, errHoldPortDown)
			require.Empty(t, plain.aborts, "a plain outage writes no abort record")

			got := runHoldSite(ctx, t, tc.site, tc.err)
			tc.assert(t, plain, got)

			for _, rec := range limJSONRecords(t, defaults.String()) {
				assert.NotEqual(t, porterr.MsgClassificationAborted, rec["msg"], "an abort record went to slog.Default()")
			}

			if only != "" && !t.Failed() {
				// Stdout, so the parent's CombinedOutput carries it.
				_, _ = os.Stdout.WriteString(holdPortErrRanMarker + tc.name + "\n")
			}
		})
	}
}

// holdPortErrInChild re-runs the current top-level test in a child process
// limited to row, and fails unless it exits 0 within a minute and prints the
// marker that shows it ran the row: a stack overflow is fatal and only a
// child can watch for one.
func holdPortErrInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), holdPortErrRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 12)], "\n"))

	// A child whose row name matched no case skips every row and exits 0: it
	// proves it ran the row only by printing the marker after the row passed.
	// One whole line must equal the marker.
	want := holdPortErrRanMarker + row
	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.TrimSuffix(line, "\r") == want {
			return
		}
	}

	t.Fatalf("the child never ran row %q: no line equals %q; output:\n%s", row, want, out)
}
