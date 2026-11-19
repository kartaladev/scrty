package recovery_test

// TestPortErrors_Limiter replaces slog.Default() for its duration, so it does
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

	"github.com/kartaladev/scrty/internal/depfault"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/recovery"
)

// limPortErrSecret is the text every hostile error here returns, so a test can
// assert no record and no returned error quotes it.
const limPortErrSecret = "limiter-secret-text"

// limPortErrRowEnv names the row a child process runs. It is empty in the
// parent.
const limPortErrRowEnv = "SCRTY_RECOVERY_LIMITER_PORTERR_ROW"

// limPortErrRanMarker prefixes the line a child prints, followed by the row's
// name, after the row ran and passed.
const limPortErrRanMarker = "SCRTY_RECOVERY_LIMITER_PORTERR_RAN: "

// limCycleOne contains itself through Unwrap() error.
type limCycleOne struct{}

func (*limCycleOne) Error() string   { return limPortErrSecret }
func (c *limCycleOne) Unwrap() error { return c }

// limCycleMany contains itself through Unwrap() []error. Unsanitized, the
// stdlib walk overflows the stack fatally, so its rows run in a child process.
type limCycleMany struct{}

func (*limCycleMany) Error() string     { return limPortErrSecret }
func (c *limCycleMany) Unwrap() []error { return []error{c} }

// limPanicUnwrap is an error whose Unwrap panics.
type limPanicUnwrap struct{}

func (limPanicUnwrap) Error() string { return limPortErrSecret }
func (limPanicUnwrap) Unwrap() error { panic("test: Unwrap panicked for " + limPortErrSecret) }

// limPanicNilUnwrap is an error whose Unwrap panics with nil.
type limPanicNilUnwrap struct{}

func (limPanicNilUnwrap) Error() string { return limPortErrSecret }
func (limPanicNilUnwrap) Unwrap() error { panic(nil) } //nolint:govet // the hostile case under test

// limTypedNil is returned as a nil pointer inside a non-nil error.
type limTypedNil struct{}

func (*limTypedNil) Error() string { return limPortErrSecret }

// limFanOut is errors.Join(n, n) nested depth times: no cycle, but 2^depth
// paths for an unbounded walk.
func limFanOut(depth int) error {
	err := errors.New(limPortErrSecret)
	for range depth {
		err = errors.Join(err, err)
	}

	return err
}

// errLimiterDown is the plain outage the parity runs fail with.
var errLimiterDown = errors.New("limiter: connection refused")

// limSite names the limiter call a row fails.
type limSite string

const (
	limUserExceeded      limSite = "Recover's user-limit check"
	limUserRecord        limSite = "Recover's failure record"
	limCodeChargeRecover limSite = "Recover's saved-code charge"
	limCodeChargeConfirm limSite = "Confirm's saved-code charge"
	limCodeRefund        limSite = "Confirm's saved-code refund"
)

// limSiteMessage is the record the site writes for a limiter that failed.
func limSiteMessage(site limSite) string {
	switch site {
	case limUserExceeded:
		return "recovery: user limiter could not be consulted"
	case limUserRecord:
		return "recovery: user failure could not be recorded"
	case limCodeRefund:
		return "recovery: saved-code charge could not be refunded"
	default:
		return "recovery: saved-code limiter could not be consulted"
	}
}

// limOnCodesLogger reports whether the site writes through the saved-code
// manager's logger rather than the recoverer's.
func limOnCodesLogger(site limSite) bool {
	return site == limCodeChargeRecover || site == limCodeChargeConfirm || site == limCodeRefund
}

// limOutcome is what one call through a failing limiter produced. Every error
// classification is made inside the bound, so a hostile chain that reaches the
// caller raw fails the run as a hang rather than hanging the test.
type limOutcome struct {
	err  error
	text string

	refused    bool
	throttled  bool
	failed     bool
	unwalkable bool
	afterCode  bool

	// events are the security events the recoverer's own sink received, and
	// messages the notices it sent.
	events   int
	messages int

	// recorded is how many failures the user limiter recorded.
	recorded int32

	// issuedUsable is the issued code still being unspent after a recovery;
	// remaining is how many saved codes are unspent after a confirmation.
	issuedUsable bool
	remaining    int

	// siteRecords are the levels of the site's failure record.
	siteRecords []string

	// siteFull are the site's failure records in full.
	siteFull []map[string]any

	// aborts are the sanitizer's records on the site's component logger, and
	// otherAborts those on the other component's logger.
	aborts      []map[string]any
	otherAborts int
}

// runLimSite runs the call site names on ctx against a limiter that fails that
// call with limErr. It fails the test when the call hangs or lets a panic
// escape.
func runLimSite(t *testing.T, ctx context.Context, site limSite, limErr error) limOutcome {
	t.Helper()

	recLogs, codeLogs := &syncBuffer{}, &syncBuffer{}
	recLogger := slog.New(slog.NewJSONHandler(recLogs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	codeLogger := slog.New(slog.NewJSONHandler(codeLogs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	var (
		out  limOutcome
		call func() limOutcome
		post func(out *limOutcome)
	)

	switch site {
	case limUserExceeded, limUserRecord, limCodeChargeRecover:
		e := newCompleteEnv(t)
		own := &recoveryEvents{}

		var recorded atomic.Int32

		userLim := NewMockLimiter(e.ctrl)
		key := recovery.UserThrottleKey(anaID)

		switch site {
		case limUserExceeded:
			// No RecordFailure is expected: an outage is not counted.
			userLim.EXPECT().Exceeded(gomock.Any(), key).Return(false, limErr).Times(1)
		case limUserRecord:
			userLim.EXPECT().Exceeded(gomock.Any(), key).Return(false, nil).Times(1)
			userLim.EXPECT().RecordFailure(gomock.Any(), key).Return(limErr).Times(1)
		case limCodeChargeRecover:
			userLim.EXPECT().Exceeded(gomock.Any(), key).Return(false, nil).Times(1)
			userLim.EXPECT().RecordFailure(gomock.Any(), key).DoAndReturn(func(context.Context, string) error {
				recorded.Add(1)

				return nil
			}).AnyTimes()

			codeLim := NewMockLimiter(e.ctrl)
			codeLim.EXPECT().Charge(gomock.Any(), recovery.CodeThrottleKey(anaID)).
				Return(ratelimit.Receipt{}, false, limErr).Times(1)

			codes, err := recovery.NewCodes(recovery.WithCodesClock(e.clock),
				recovery.WithCodesLimiter(codeLim), recovery.WithCodesLogger(codeLogger))
			require.NoError(t, err)
			e.codes = codes
		}

		r := e.recoverer(t, recovery.WithSecurityEvents(own.sink), recovery.WithUserLimiter(userLim),
			recovery.WithLogger(recLogger))

		req := savedAndIssuedReq(e)
		if site == limUserRecord {
			req.Saved = "AAAA-BBBB-CCCC"
		}

		call = func() limOutcome {
			_, err := r.Recover(ctx, req)

			return limOutcome{err: err}
		}
		post = func(out *limOutcome) {
			out.events = len(own.all())
			out.messages = len(e.out.messages())
			out.recorded = recorded.Load()
			out.issuedUsable = e.issuedUsable(t.Context(), t, r, anaID, e.issued)
		}
	case limCodeChargeConfirm, limCodeRefund:
		ctrl := gomock.NewController(t)
		codeLim := NewMockLimiter(ctrl)
		store := recovery.NewMemoryCodeStore()

		codes, err := recovery.NewCodes(recovery.WithCodesStore(store), recovery.WithCodesLimiter(codeLim),
			recovery.WithCodesLogger(codeLogger))
		require.NoError(t, err)

		set, err := codes.Generate(t.Context(), anaID)
		require.NoError(t, err)

		key := recovery.CodeThrottleKey(anaID)

		if site == limCodeChargeConfirm {
			codeLim.EXPECT().Charge(gomock.Any(), key).Return(ratelimit.Receipt{}, false, limErr).Times(1)
		} else {
			receipt := ratelimit.NewReceipt(key, time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC))
			gomock.InOrder(
				codeLim.EXPECT().Charge(gomock.Any(), key).Return(receipt, false, nil).Times(1),
				codeLim.EXPECT().Refund(gomock.Any(), receipt).Return(limErr).Times(1),
			)
		}

		call = func() limOutcome {
			return limOutcome{err: codes.Confirm(ctx, anaID, set[0])}
		}
		post = func(out *limOutcome) {
			n, err := store.Remaining(t.Context(), anaID)
			require.NoError(t, err)
			out.remaining = n
		}
	}

	type result struct {
		out      limOutcome
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

		o := call()
		if o.err != nil {
			o.text = o.err.Error()
			o.refused = errors.Is(o.err, recovery.ErrRefused)
			o.throttled = errors.Is(o.err, recovery.ErrCodeThrottled)
			o.failed = errors.Is(o.err, depfault.ErrFailed)
			o.unwalkable = errors.Is(o.err, porterr.ErrUnwalkable)
			o.afterCode = recovery.RefusedAfterValidCode(o.err)
		}

		returned = true
		done <- result{out: o}
	}()

	select {
	case r := <-done:
		require.False(t, r.panicked, "a hostile limiter error escaped as a panic: %v", r.value)
		out = r.out
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a hostile limiter error hung the call, or its classification")
	}

	post(&out)

	siteLogs, otherLogs := recLogs, codeLogs
	if limOnCodesLogger(site) {
		siteLogs, otherLogs = codeLogs, recLogs
	}

	for _, rec := range limJSONRecords(t, siteLogs.String()) {
		switch rec["msg"] {
		case limSiteMessage(site):
			out.siteRecords = append(out.siteRecords, rec["level"].(string))
			out.siteFull = append(out.siteFull, rec)
		case porterr.MsgClassificationAborted:
			out.aborts = append(out.aborts, rec)
		}
	}

	for _, rec := range limJSONRecords(t, otherLogs.String()) {
		if rec["msg"] == porterr.MsgClassificationAborted {
			out.otherAborts++
		}
	}

	return out
}

// limJSONRecords decodes every JSON record in out.
func limJSONRecords(t *testing.T, out string) []map[string]any {
	t.Helper()

	var records []map[string]any

	for line := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}

		rec := map[string]any{}
		require.NoError(t, json.Unmarshal([]byte(line), &rec))
		records = append(records, rec)
	}

	return records
}

// limDefaultRecords points slog.Default() at a JSON buffer until the test
// ends. The caller must not be parallel.
func limDefaultRecords(t *testing.T) *syncBuffer {
	t.Helper()

	buf := &syncBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	return buf
}

// TestPortErrors_Limiter pins that a rate limiter call failing with an error
// whose chain cannot be walked is answered exactly as a plain limiter outage
// is, at each of the recoverer's user-limit check and failure record and the
// saved-code manager's charge and refund:
//
//   - the user-limit check refuses with ErrRefused, its own text, counts
//     nothing, sends nothing and reports no refusal event;
//   - the failure record leaves the refusal and its event as they were;
//   - the saved-code charge answers Confirm as a throttled code and Recover as
//     an uncounted-by-the-limiter refusal with no event, spending nothing;
//   - the refund leaves the confirmation successful.
//
// The sanitizer writes one record, to the site's own component logger, and
// none to slog.Default() or the other component's logger.
func TestPortErrors_Limiter(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(limPortErrRowEnv)
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
		site limSite
		err  error

		// ctx modifies the context every run of the row uses. nil means the
		// test's own.
		ctx func(ctx context.Context) context.Context

		// child runs the row in a child process: unsanitized, it overflows
		// the stack fatally.
		child bool

		// assert receives the plain outage's outcome and the row's.
		assert func(t *testing.T, plain, got limOutcome)
	}

	sameAsPlain := func(t *testing.T, site limSite, plain, got limOutcome) {
		t.Helper()

		assert.Equal(t, plain.refused, got.refused, "the same refusal")
		assert.Equal(t, plain.throttled, got.throttled, "the same throttle answer")
		assert.Equal(t, plain.failed, got.failed, "the same dependency-failure mark")
		assert.Equal(t, plain.afterCode, got.afterCode, "the same after-code mark")
		assert.Equal(t, plain.text, got.text, "the same fixed text")
		assert.Equal(t, plain.events, got.events, "the same security events")
		assert.Equal(t, plain.messages, got.messages, "the same notices sent")
		assert.Equal(t, plain.recorded, got.recorded, "the same failures recorded")
		assert.Equal(t, plain.issuedUsable, got.issuedUsable, "the same issued code left unspent")
		assert.Equal(t, plain.remaining, got.remaining, "the same saved codes left unspent")
		assert.Equal(t, plain.siteRecords, got.siteRecords, "the same failure record")

		switch site {
		case limUserExceeded:
			require.True(t, plain.refused, "precondition: a plain outage refuses")
			assert.Equal(t, recovery.ErrRefused.Error(), got.text)
			assert.Zero(t, got.events, "an outage reports no refusal event")
			assert.Zero(t, got.messages)
			assert.True(t, got.issuedUsable, "nothing is spent")
		case limUserRecord:
			require.True(t, plain.refused, "precondition: a wrong code is refused")
			assert.Equal(t, 1, got.events, "the wrong code's refusal is still reported")
		case limCodeChargeRecover:
			require.True(t, plain.refused, "precondition: a plain outage refuses")
			assert.False(t, got.throttled, "the answer is the refusal, not the throttle")
			assert.Zero(t, got.events, "an outage reports no refusal event")
			assert.Zero(t, got.messages)
			assert.True(t, got.issuedUsable, "nothing is spent")
		case limCodeChargeConfirm:
			require.True(t, plain.throttled, "precondition: a plain outage answers as a throttled code")
			assert.Equal(t, 10, got.remaining, "no code is spent")
		case limCodeRefund:
			require.NoError(t, plain.err, "precondition: a failed refund leaves the confirmation successful")
			assert.NoError(t, got.err)
		}

		assert.NotContains(t, got.text, limPortErrSecret)
		assert.Equal(t, []string{"ERROR"}, got.siteRecords, "one error-level failure record")

		require.Len(t, got.siteFull, 1, "one failure record, in full")
		siteRaw, err := json.Marshal(got.siteFull[0])
		require.NoError(t, err)
		assert.NotContains(t, string(siteRaw), limPortErrSecret, "the site's failure record quotes the error")
	}

	asOutage := func(site limSite, reason string) func(t *testing.T, plain, got limOutcome) {
		return func(t *testing.T, plain, got limOutcome) {
			t.Helper()

			sameAsPlain(t, site, plain, got)

			if site == limUserExceeded || site == limCodeChargeRecover || site == limCodeChargeConfirm {
				assert.True(t, got.unwalkable, "the refusal carries the sanitizer's fault")
			}

			require.Len(t, got.aborts, 1, "one abort record, on the site's component logger")
			assert.Zero(t, got.otherAborts, "an abort record went to the other component's logger")
			assert.Equal(t, "ERROR", got.aborts[0]["level"])
			assert.Equal(t, reason, got.aborts[0]["reason"])

			raw, err := json.Marshal(got.aborts[0])
			require.NoError(t, err)
			assert.NotContains(t, string(raw), limPortErrSecret, "the record quotes the error")
		}
	}

	var cases []testCase

	for _, site := range []limSite{limUserExceeded, limUserRecord, limCodeChargeRecover, limCodeChargeConfirm, limCodeRefund} {
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
				assert: func(t *testing.T, plain, got limOutcome) {
					t.Helper()

					sameAsPlain(t, site, plain, got)
					assert.Empty(t, got.aborts, "a walk that completes writes no abort record")
				},
			},
		)
	}

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				limPortErrInChild(t, tc.name)

				return
			}

			defaults := limDefaultRecords(t)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			plain := runLimSite(t, ctx, tc.site, errLimiterDown)
			require.Empty(t, plain.aborts, "a plain outage writes no abort record")

			got := runLimSite(t, ctx, tc.site, tc.err)
			tc.assert(t, plain, got)

			for _, rec := range limJSONRecords(t, defaults.String()) {
				assert.NotEqual(t, porterr.MsgClassificationAborted, rec["msg"], "an abort record went to slog.Default()")
			}

			if only != "" && !t.Failed() {
				// Stdout, so the parent's CombinedOutput carries it.
				_, _ = os.Stdout.WriteString(limPortErrRanMarker + tc.name + "\n")
			}
		})
	}
}

// limPortErrInChild re-runs the current top-level test in a child process
// limited to row, and fails unless it exits 0 within a minute and prints the
// marker that shows it ran the row: a stack overflow is fatal and only a child
// can watch for one.
func limPortErrInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), limPortErrRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 8)], "\n"))

	// A child whose row name matched no case skips every row and exits 0: it
	// proves it ran the row only by printing the marker after the row passed.
	// One whole line must equal the marker: not a substring of the output, and
	// not a line with a suffix.
	want := limPortErrRanMarker + row
	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.TrimSuffix(line, "\r") == want {
			return
		}
	}

	t.Fatalf("the child never ran row %q: no line equals %q; output:\n%s", row, want, out)
}
