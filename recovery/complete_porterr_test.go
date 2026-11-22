package recovery_test

// TestPortErrors_Complete replaces slog.Default() for its duration, so it does
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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/recovery"
)

// cmpPortErrRowEnv names the row a child process runs. It is empty in the
// parent.
const cmpPortErrRowEnv = "SCRTY_RECOVERY_COMPLETE_PORTERR_ROW"

// cmpPortErrRanMarker prefixes the line a child prints, followed by the row's
// name, after the row ran and passed.
const cmpPortErrRanMarker = "SCRTY_RECOVERY_COMPLETE_PORTERR_RAN: "

// errCmpPortDown is the plain outage every parity run fails with.
var errCmpPortDown = errors.New("port: connection refused")

// cmpSite names the port call a row fails.
type cmpSite string

const (
	cmpFinishComplete cmpSite = "the finish's record completion"
	cmpCancelPending  cmpSite = "the login's pending-record cancel"
	cmpNewID          cmpSite = "the record identifier generator"
	cmpInsert         cmpSite = "the completed record's insert"
	cmpIssue          cmpSite = "the credential issuer"
	cmpGrants         cmpSite = "the grant revoker after the sessions ended"
)

// cmpRecords is a record store whose CancelPending fails with err when it is
// set.
type cmpRecords struct {
	recovery.RecordStore

	err error
}

func (s cmpRecords) CancelPending(ctx context.Context, user identity.UserID, at time.Time) (int, error) {
	if s.err != nil {
		return 0, s.err
	}

	return s.RecordStore.CancelPending(ctx, user, at)
}

// cmpFailIDs is a consumer's identifier generator that fails with err. The
// project has no mock of the one-method id.Generator, so a stub stands in.
type cmpFailIDs struct{ err error }

func (g cmpFailIDs) NewID() (id.ID, error) {
	var zero id.ID

	return zero, g.err
}

// cmpRecord is one record the recoverer's logger wrote, other than an abort
// record, reduced to what a consumer routes on.
type cmpRecord struct {
	level, msg, reason string
}

// cmpEvent is one security event, reduced to what parity compares.
type cmpEvent struct {
	name    string
	outcome string
	user    identity.UserID
}

// cmpOutcome is what one call through a failing port produced. Every error
// classification is made inside the bound, so a hostile chain that reaches the
// caller raw fails the run as a hang rather than hanging the test.
type cmpOutcome struct {
	text string

	failed     bool
	refused    bool
	unwalkable bool
	resultNil  bool

	grantsNotRevoked bool
	hasSession       bool

	events []cmpEvent

	// state is the record's state after the call: none, pending, completed
	// or cancelled.
	state        string
	savedUsable  bool
	issuedUsable bool
	priorKept    bool
	recovered    int

	// records are the recoverer's records other than abort records, and raw
	// all of its output.
	records []cmpRecord
	raw     string

	// aborts are the sanitizer's records on the recoverer's logger.
	aborts []map[string]any
}

// runCmpSite runs the flow that reaches the site's call, on ctx, against a
// port that fails that call with portErr. It fails the test when the flow, or
// the classification of its error, hangs or lets a panic escape.
func runCmpSite(ctx context.Context, t *testing.T, site cmpSite, portErr error) cmpOutcome {
	t.Helper()

	e := newCompleteEnv(t) //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
	logs := &syncBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	own := &recoveryEvents{}
	rid := newRecordID(t)
	prior := e.priorSessions(t, 1) //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's

	extra := []recovery.Option{recovery.WithSecurityEvents(own.sink), recovery.WithLogger(logger)}
	deps := e.completeDeps()
	req := savedAndIssuedReq(e)

	var (
		call  func(ctx context.Context, r *recovery.Recoverer) (*recovery.Result, error)
		reset func()
	)

	recoverCall := func(ctx context.Context, r *recovery.Recoverer) (*recovery.Result, error) {
		return r.Recover(ctx, req)
	}

	switch site {
	case cmpFinishComplete:
		reset = func() { e.faults.arm(faultRecordsComplete, nil) }
	case cmpCancelPending:
		deps.Records = cmpRecords{RecordStore: e.records, err: portErr}
		require.NoError(t, e.records.Insert(t.Context(), recovery.Record{ //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
			ID: rid, User: anaID, StartedAt: e.clock.Now(), NotBefore: e.clock.Now().Add(72 * time.Hour),
		}))

		call = func(ctx context.Context, r *recovery.Recoverer) (*recovery.Result, error) {
			return nil, r.CancelPending(ctx, anaID)
		}
	case cmpNewID:
		extra = append(extra, recovery.WithIDGenerator(cmpFailIDs{err: portErr}))
		call = recoverCall
	case cmpInsert:
		deps.Records = faultyRecordStore{RecordStore: e.records, f: e.faults}
		extra = append(extra, recovery.WithIDGenerator(fixedIDs{rid}))
		e.faults.arm(faultRecordsInsert, portErr)
		reset = func() { e.faults.arm(faultRecordsInsert, nil) }
		call = recoverCall
	case cmpIssue:
		e.failIssue(portErr)
		reset = func() { e.failIssue(nil) }
		call = recoverCall
	case cmpGrants:
		g := NewMockGrantRevoker(e.ctrl)
		g.EXPECT().RevokeUserGrants(gomock.Any(), anaID, "recovery").DoAndReturn(
			func(context.Context, identity.UserID, string) error {
				// The first revocation, before the sessions end, succeeds: only
				// the one after them is the site.
				if e.loads(t, prior[0]) { //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
					return nil
				}

				return portErr
			}).AnyTimes()

		extra = append(extra, recovery.WithGrantRevoker(g), recovery.WithIDGenerator(fixedIDs{rid}))
		call = recoverCall
	}

	var r *recovery.Recoverer

	if site == cmpFinishComplete {
		held, _, heldID := e.faultyHold(t, extra...)
		rid, r = heldID, held
		h := heldRecovery(t.Context(), t, r, req) //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's

		e.clock.Advance(73 * time.Hour)
		e.faults.arm(faultRecordsComplete, portErr)

		call = func(ctx context.Context, r *recovery.Recoverer) (*recovery.Result, error) {
			return r.Finish(ctx, h.CompletionToken)
		}
	} else {
		var err error

		r, err = recovery.NewRecoverer(deps, e.recovererOpts(extra...)...)
		require.NoError(t, err)
	}

	type result struct {
		out      cmpOutcome
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

		res, err := call(ctx, r)

		o := cmpOutcome{resultNil: res == nil}
		if res != nil {
			o.grantsNotRevoked = res.GrantsNotRevoked
			o.hasSession = res.Session != nil
		}

		if err != nil {
			o.failed = true
			o.text = err.Error()
			o.refused = errors.Is(err, recovery.ErrRefused)
			o.unwalkable = errors.Is(err, porterr.ErrUnwalkable)
		}

		returned = true
		done <- result{out: o}
	}()

	var out cmpOutcome

	select {
	case res := <-done:
		require.False(t, res.panicked, "a hostile port error escaped the flow as a panic: %v", res.value)
		out = res.out
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a hostile port error hung the flow, or the classification of its error")
	}

	if reset != nil {
		reset()
	}

	for _, ev := range own.all() {
		out.events = append(out.events, cmpEvent{name: ev.Name, outcome: ev.Outcome, user: ev.User})
	}

	out.state = holdRecordState(t, e, rid)                                //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
	out.savedUsable = e.savedUsable(t.Context(), t, e.saved[0])           //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
	out.issuedUsable = e.issuedUsable(t.Context(), t, r, anaID, e.issued) //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
	out.priorKept = e.loads(t, prior[0])                                  //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
	out.recovered = len(e.out.recoveredNotices())
	out.raw = logs.String()

	for _, rec := range limJSONRecords(t, out.raw) {
		if rec["msg"] == porterr.MsgClassificationAborted {
			out.aborts = append(out.aborts, rec)

			continue
		}

		reason, _ := rec["reason"].(string)
		out.records = append(out.records, cmpRecord{level: rec["level"].(string), msg: rec["msg"].(string), reason: reason})
	}

	return out
}

// TestPortErrors_Complete pins that each port call a recovery's completion
// makes — the finish's record completion, the login's pending-record cancel,
// the record identifier generator, the completed record's insert, the
// consumer's credential issuer and the grant revoker run after the sessions
// ended — failing with an error whose chain cannot be walked is answered
// exactly as a plain outage of that port: the same error class, events,
// record state, spent codes, sessions and records. The login a failed cancel
// guards is still refused. A failed revocation still sets GrantsNotRevoked on
// a recovery that stands. A cycle claiming context.Canceled is never taken for
// a caller hang-up: the issuer's failure is still logged as an error. The
// sanitizer writes one record, to the recoverer's logger, and none to
// slog.Default().
func TestPortErrors_Complete(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(cmpPortErrRowEnv)
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
		site cmpSite
		err  error

		// ctx modifies the context both runs of the row use. nil means the
		// test's own.
		ctx func(ctx context.Context) context.Context

		// child runs the row in a child process: unsanitized, it may
		// overflow the stack fatally.
		child bool

		// assert receives the plain run's outcome and the row's.
		assert func(t *testing.T, plain, got cmpOutcome)
	}

	// sameAsPlain compares everything but the error's own text.
	sameAsPlain := func(t *testing.T, plain, got cmpOutcome) {
		t.Helper()

		assert.Equal(t, plain.failed, got.failed, "an error returned alike")
		assert.Equal(t, plain.resultNil, got.resultNil, "a result handed out alike")
		assert.Equal(t, plain.hasSession, got.hasSession, "a session handed out alike")
		assert.Equal(t, plain.refused, got.refused, "ErrRefused")
		assert.Equal(t, plain.grantsNotRevoked, got.grantsNotRevoked, "GrantsNotRevoked")
		assert.Equal(t, plain.events, got.events, "the same events")
		assert.Equal(t, plain.state, got.state, "the record left alike")
		assert.Equal(t, plain.savedUsable, got.savedUsable, "the saved code spent alike")
		assert.Equal(t, plain.issuedUsable, got.issuedUsable, "the issued code spent alike")
		assert.Equal(t, plain.priorKept, got.priorKept, "the prior sessions ended alike")
		assert.Equal(t, plain.recovered, got.recovered, "the same recovered notices")
		assert.Equal(t, plain.records, got.records, "the same records, levels and reasons")
	}

	asOutage := func(site cmpSite, reason string) func(t *testing.T, plain, got cmpOutcome) {
		return func(t *testing.T, plain, got cmpOutcome) {
			t.Helper()

			sameAsPlain(t, plain, got)

			if site == cmpGrants {
				require.False(t, plain.failed, "precondition: a failed revocation leaves a completed recovery")
				assert.True(t, got.grantsNotRevoked, "the recovery says its grants were not revoked")
				assert.False(t, got.failed, "a failed revocation fails the recovery")
			} else {
				require.True(t, plain.failed, "precondition: a plain outage is returned")
				require.False(t, plain.refused, "precondition: a plain outage is not a refusal")
				assert.True(t, got.failed, "an outage that was swallowed")
				assert.False(t, got.refused, "an outage answered as a refusal")
				assert.True(t, got.unwalkable, "the answer is a fault standing for the port's error")
				assert.Equal(t, plain.text, got.text, "the same fixed text")
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
	walked := func(t *testing.T, plain, got cmpOutcome) {
		t.Helper()

		sameAsPlain(t, plain, got)
		assert.False(t, got.unwalkable, "a walkable error replaced by a fault")
		assert.Equal(t, plain.text, got.text, "the same fixed text")
		assert.Empty(t, got.aborts, "a walk that completes writes no abort record")
	}

	var cases []testCase

	sites := []cmpSite{cmpFinishComplete, cmpCancelPending, cmpNewID, cmpInsert, cmpIssue, cmpGrants}

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
				name: prefix + "a typed-nil root walks to the end and is answered as a plain error",
				site: site, err: (*limTypedNil)(nil),
				assert: walked,
			},
		)
	}

	// A caller's cancellation reaches only the sites that run on its context: a
	// recovery refuses at the code spend on a cancelled context, so the
	// identifier, insert and revocation, which run after it on a detached
	// context, are never reached with one (accepted: nothing to observe).
	for _, site := range []cmpSite{cmpFinishComplete, cmpCancelPending, cmpIssue} {
		prefix := string(site) + ": "

		cases = append(cases,
			testCase{
				name: prefix + "a cycle on a context the caller cancelled is an outage",
				site: site, err: &limCycleOne{}, ctx: cancelled,
				assert: asOutage(site, "budget"),
			},
			testCase{
				name: prefix + "a cycle claiming context.Canceled on a cancelled context is an outage",
				site: site, err: &recClaimCycle{claims: context.Canceled}, ctx: cancelled,
				assert: asOutage(site, "budget"),
			},
			testCase{
				name: prefix + "a cycle wrapping context.Canceled beside itself is an outage",
				site: site, err: &recWrapCycleMany{wraps: context.Canceled}, ctx: cancelled, child: true,
				assert: asOutage(site, "budget"),
			},
		)
	}

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				cmpPortErrInChild(t, tc.name)

				return
			}

			defaults := limDefaultRecords(t)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			plain := runCmpSite(ctx, t, tc.site, errCmpPortDown)
			require.Empty(t, plain.aborts, "a plain outage writes no abort record")

			got := runCmpSite(ctx, t, tc.site, tc.err)
			tc.assert(t, plain, got)

			for _, rec := range limJSONRecords(t, defaults.String()) {
				assert.NotEqual(t, porterr.MsgClassificationAborted, rec["msg"], "an abort record went to slog.Default()")
			}

			if only != "" && !t.Failed() {
				// Stdout, so the parent's CombinedOutput carries it.
				_, _ = os.Stdout.WriteString(cmpPortErrRanMarker + tc.name + "\n")
			}
		})
	}
}

// cmpPortErrInChild re-runs the current top-level test in a child process
// limited to row, and fails unless it exits 0 within a minute and prints the
// marker that shows it ran the row: a stack overflow is fatal and only a
// child can watch for one.
func cmpPortErrInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), cmpPortErrRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 12)], "\n"))

	// A child whose row name matched no case skips every row and exits 0: it
	// proves it ran the row only by printing the marker after the row passed.
	// One whole line must equal the marker.
	want := cmpPortErrRanMarker + row
	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.TrimSuffix(line, "\r") == want {
			return
		}
	}

	t.Fatalf("the child never ran row %q: no line equals %q; output:\n%s", row, want, out)
}
