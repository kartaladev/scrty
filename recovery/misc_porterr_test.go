package recovery_test

// TestPortErrors_Misc replaces slog.Default() for its duration, so it does not
// run in parallel, and it restores the logger it found.

import (
	"context"
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
	"github.com/kartaladev/scrty/notify"
	"github.com/kartaladev/scrty/recovery"
)

// miscPortErrRowEnv names the row a child process runs. It is empty in the
// parent.
const miscPortErrRowEnv = "SCRTY_RECOVERY_MISC_PORTERR_ROW"

// miscPortErrRanMarker prefixes the line a child prints, followed by the row's
// name, after the row ran and passed.
const miscPortErrRanMarker = "SCRTY_RECOVERY_MISC_PORTERR_RAN: "

// errMiscPortDown is the plain outage every parity run fails with.
var errMiscPortDown = errors.New("port: connection refused")

// miscSite names the port call a row fails.
type miscSite string

const (
	miscResolver miscSite = "the notice's contact resolver"
	miscSender   miscSite = "the notice's sender"
	miscLoader   miscSite = "the notice's user loader"
	miscFactory  miscSite = "the user limiter factory at construction"
	miscGrants   miscSite = "the grant revoker before the codes are spent"
	miscRandom   miscSite = "the saved-code random source"
)

// miscFailSender is a consumer's sender that fails with err, honouring no
// context, so a row can fail it on a context the caller cancelled. It reports
// that it does not wait, as a recoverer requires.
type miscFailSender struct{ err error }

func (s miscFailSender) Send(context.Context, notify.Message) error { return s.err }
func (miscFailSender) NonBlocking() bool                            { return true }

// miscFailReader is a consumer's random source that fails with err.
type miscFailReader struct{ err error }

func (r miscFailReader) Read([]byte) (int, error) { return 0, r.err }

// miscOutcome is what one call through a failing port produced. Every error
// classification is made inside the bound, so a hostile chain that reaches the
// caller raw fails the run as a hang rather than hanging the test.
type miscOutcome struct {
	text string

	failed     bool
	config     bool
	dependency bool
	unwalkable bool

	codes int

	// kept is how many of the user's saved codes (or the previous set) are
	// still unspent, and issuedUsable whether the issued code still is.
	kept         int
	issuedUsable bool

	events []cmpEvent

	// records are the component's records other than abort records, and raw
	// all of its output.
	records []cmpRecord
	raw     string

	// aborts are the sanitizer's records on the component's logger.
	aborts []map[string]any
}

// miscClassify reduces a returned error to what parity compares.
func (o *miscOutcome) miscClassify(err error) {
	if err == nil {
		return
	}

	o.failed = true
	o.text = err.Error()
	o.config = errors.Is(err, recovery.ErrConfig)
	o.dependency = errors.Is(err, recovery.ErrDependency)
	o.unwalkable = errors.Is(err, porterr.ErrUnwalkable)
}

// miscSplitRecords fills the outcome's records from the component's output.
func (o *miscOutcome) miscSplitRecords(t *testing.T, raw string) {
	t.Helper()

	o.raw = raw

	for _, rec := range limJSONRecords(t, raw) {
		if rec["msg"] == porterr.MsgClassificationAborted {
			o.aborts = append(o.aborts, rec)

			continue
		}

		reason, _ := rec["reason"].(string)
		o.records = append(o.records, cmpRecord{level: rec["level"].(string), msg: rec["msg"].(string), reason: reason})
	}
}

// miscBounded runs call and fails the test when it hangs or lets a panic
// escape, so a hostile port error that reaches a check raw is a red row and
// not a stuck test.
func miscBounded(t *testing.T, call func() miscOutcome) miscOutcome {
	t.Helper()

	type result struct {
		out      miscOutcome
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

		out := call()
		returned = true
		done <- result{out: out}
	}()

	select {
	case res := <-done:
		require.False(t, res.panicked, "a hostile port error escaped the flow as a panic: %v", res.value)

		return res.out
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a hostile port error hung the flow, or the classification of its error")
	}

	return miscOutcome{}
}

// runMiscSite runs the flow that reaches the site's call, on ctx, against a
// port that fails that call with portErr.
func runMiscSite(ctx context.Context, t *testing.T, site miscSite, portErr error) miscOutcome {
	t.Helper()

	logs := &syncBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	if site == miscRandom {
		return runMiscRandom(ctx, t, portErr, logs, logger)
	}

	e := newCompleteEnv(t) //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
	own := &recoveryEvents{}
	extra := []recovery.Option{recovery.WithSecurityEvents(own.sink), recovery.WithLogger(logger)}
	deps := e.completeDeps()

	var call func() miscOutcome

	switch site {
	case miscResolver:
		extra = append(extra, recovery.WithContactResolver(func(context.Context, *identity.Details) (string, error) {
			return "", portErr
		}))
	case miscSender:
		deps.Sender = miscFailSender{err: portErr}
	case miscLoader:
		e.failLookup(portErr)
	case miscFactory:
		f := NewMockLimiterFactory(e.ctrl)
		f.EXPECT().NewLimiter(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, portErr).Times(1)

		extra = append(extra, recovery.WithUserLimiterFactory(f))
	case miscGrants:
		g := NewMockGrantRevoker(e.ctrl)
		g.EXPECT().RevokeUserGrants(gomock.Any(), anaID, "recovery").Return(portErr).Times(1)

		extra = append(extra, recovery.WithGrantRevoker(g))
	}

	switch site {
	case miscFactory:
		// The env's own user limiter would win over the factory, so the
		// options are the fixture's, without it.
		opts := e.fixture.opts(append([]recovery.Option{
			recovery.WithProofs(recovery.ProofSaved, recovery.ProofIssued),
			recovery.WithMessages(e.capturingMessages()),
			recovery.WithCredentialIssuer(e.issueCredential),
		}, extra...)...)

		call = func() miscOutcome {
			_, err := recovery.NewRecoverer(deps, opts...)

			o := miscOutcome{}
			o.miscClassify(err)

			return o
		}
	case miscGrants:
		r, err := recovery.NewRecoverer(deps, e.recovererOpts(extra...)...)
		require.NoError(t, err)

		req := savedAndIssuedReq(e)

		call = func() miscOutcome {
			_, err := r.Recover(ctx, req)

			o := miscOutcome{}
			o.miscClassify(err)
			o.issuedUsable = e.issuedUsable(t.Context(), t, r, anaID, e.issued) //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's

			if e.savedUsable(t.Context(), t, e.saved[0]) { //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
				o.kept = 1
			}

			return o
		}
	default:
		r, err := recovery.NewRecoverer(deps, e.recovererOpts(extra...)...)
		require.NoError(t, err)

		call = func() miscOutcome {
			codes, err := r.Regenerate(ctx, anaID)

			o := miscOutcome{codes: len(codes)}
			o.miscClassify(err)

			return o
		}
	}

	out := miscBounded(t, call)

	for _, ev := range own.all() {
		out.events = append(out.events, cmpEvent{name: ev.Name, outcome: ev.Outcome, user: ev.User})
	}

	out.miscSplitRecords(t, logs.String())

	return out
}

// runMiscRandom runs a saved-code set's generation against a random source
// that fails with portErr, over a store that already holds a set.
func runMiscRandom(ctx context.Context, t *testing.T, portErr error, logs *syncBuffer, logger *slog.Logger) miscOutcome {
	t.Helper()

	store := recovery.NewMemoryCodeStore()

	first, err := recovery.NewCodes(recovery.WithCodesStore(store))
	require.NoError(t, err)

	_, err = first.Generate(t.Context(), anaID) //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
	require.NoError(t, err)

	failing, err := recovery.NewCodes(recovery.WithCodesStore(store), recovery.WithCodesLogger(logger),
		recovery.WithCodesRandom(miscFailReader{err: portErr}))
	require.NoError(t, err)

	out := miscBounded(t, func() miscOutcome {
		codes, err := failing.Generate(ctx, anaID)

		o := miscOutcome{codes: len(codes)}
		o.miscClassify(err)

		return o
	})

	remaining, err := store.Remaining(t.Context(), anaID) //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
	require.NoError(t, err)

	out.kept = remaining
	out.miscSplitRecords(t, logs.String())

	return out
}

// TestPortErrors_Misc pins that each of these port calls failing with an error
// whose chain cannot be walked is answered exactly as a plain outage of that
// port is:
//
//   - the contact resolver, the sender and the user loader of a notice are
//     logged and the notice is dropped, and the regenerated codes are still
//     returned;
//   - the user limiter factory's error is a configuration error at
//     construction, never a panic or a hang;
//   - the grant revoker's failure is a dependency failure that spends,
//     records and sends nothing;
//   - the saved-code random source's failure is returned, the previous set
//     standing.
//
// The sanitizer writes one record, to the component's own logger, and none to
// slog.Default(). A context the caller cancelled, with a cycle claiming
// context.Canceled, is never taken for a hang-up. An Is that panics only for
// the site's own sentinel is accepted (design decision 11): it passes the
// sanitizer.
func TestPortErrors_Misc(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(miscPortErrRowEnv)
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
		site miscSite
		err  error

		// ctx modifies the context both runs of the row use. nil means the
		// test's own.
		ctx func(ctx context.Context) context.Context

		// child runs the row in a child process: unsanitized, it may
		// overflow the stack fatally.
		child bool

		assert func(t *testing.T, plain, got miscOutcome)
	}

	sameAsPlain := func(t *testing.T, plain, got miscOutcome) {
		t.Helper()

		assert.Equal(t, plain.failed, got.failed, "an error returned alike")
		assert.Equal(t, plain.config, got.config, "ErrConfig")
		assert.Equal(t, plain.dependency, got.dependency, "ErrDependency")
		assert.Equal(t, plain.codes, got.codes, "the codes returned alike")
		assert.Equal(t, plain.kept, got.kept, "the saved codes left alike")
		assert.Equal(t, plain.issuedUsable, got.issuedUsable, "the issued code spent alike")
		assert.Equal(t, plain.events, got.events, "the same events")
		assert.Equal(t, plain.records, got.records, "the same records, levels and reasons")
	}

	asOutage := func(site miscSite, reason string) func(t *testing.T, plain, got miscOutcome) {
		return func(t *testing.T, plain, got miscOutcome) {
			t.Helper()

			sameAsPlain(t, plain, got)

			switch site {
			case miscResolver, miscSender, miscLoader:
				require.False(t, plain.failed, "precondition: a dropped notice fails nothing")
				assert.Equal(t, 10, got.codes, "the codes are still returned")
			case miscFactory:
				require.True(t, plain.config, "precondition: a plain outage is a configuration error")
				assert.True(t, got.unwalkable, "the answer carries the fault standing for the error")
			case miscGrants:
				require.True(t, plain.dependency, "precondition: a plain outage is a dependency failure")
				assert.True(t, got.unwalkable, "the answer carries the fault standing for the error")
				assert.True(t, got.issuedUsable, "nothing is spent")
				assert.Equal(t, 1, got.kept, "nothing is spent")
				assert.Empty(t, got.events, "no event")
			case miscRandom:
				require.True(t, plain.failed, "precondition: a plain outage is returned")
				assert.True(t, got.unwalkable, "the answer carries the fault standing for the error")
				assert.Equal(t, 0, got.codes)
				assert.Equal(t, 10, got.kept, "the previous set stands")
			}

			assert.NotContains(t, got.text, limPortErrSecret, "the returned error quotes the port's")
			assert.NotContains(t, got.raw, limPortErrSecret, "a record quotes the port's error")

			require.Len(t, got.aborts, 1, "one abort record, on the component's logger")
			assert.Equal(t, "ERROR", got.aborts[0]["level"])
			assert.Equal(t, reason, got.aborts[0]["reason"])
		}
	}

	// walked is a chain the sanitizer reads to its end: answered as a plain
	// error is, with no abort record.
	walked := func(t *testing.T, plain, got miscOutcome) {
		t.Helper()

		sameAsPlain(t, plain, got)
		assert.False(t, got.unwalkable, "a walkable error replaced by a fault")
		assert.Empty(t, got.aborts, "a walk that completes writes no abort record")
	}

	sites := []miscSite{miscResolver, miscSender, miscLoader, miscFactory, miscGrants, miscRandom}

	var cases []testCase

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

	// A caller's cancellation reaches the sites that run on its context; the
	// factory runs at construction, with none (accepted: nothing to observe).
	for _, site := range []miscSite{miscResolver, miscSender, miscLoader, miscGrants, miscRandom} {
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
				miscPortErrInChild(t, tc.name)

				return
			}

			defaults := limDefaultRecords(t)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			plain := runMiscSite(ctx, t, tc.site, errMiscPortDown)
			require.Empty(t, plain.aborts, "a plain outage writes no abort record")

			got := runMiscSite(ctx, t, tc.site, tc.err)
			tc.assert(t, plain, got)

			for _, rec := range limJSONRecords(t, defaults.String()) {
				assert.NotEqual(t, porterr.MsgClassificationAborted, rec["msg"], "an abort record went to slog.Default()")
			}

			if only != "" && !t.Failed() {
				// Stdout, so the parent's CombinedOutput carries it.
				_, _ = os.Stdout.WriteString(miscPortErrRanMarker + tc.name + "\n")
			}
		})
	}
}

// miscPortErrInChild re-runs the current top-level test in a child process
// limited to row, and fails unless it exits 0 within a minute and prints the
// marker that shows it ran the row: a stack overflow is fatal and only a
// child can watch for one.
func miscPortErrInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), miscPortErrRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 12)], "\n"))

	// A child whose row name matched no case skips every row and exits 0: it
	// proves it ran the row only by printing the marker after the row passed.
	// One whole line must equal the marker.
	want := miscPortErrRanMarker + row
	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.TrimSuffix(line, "\r") == want {
			return
		}
	}

	t.Fatalf("the child never ran row %q: no line equals %q; output:\n%s", row, want, out)
}
