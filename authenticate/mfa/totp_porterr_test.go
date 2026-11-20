//go:debug panicnil=1

package mfa_test

// This file covers the TOTP method's port calls: TestPortErrors_TOTPStore the
// enrolment store's verification-side calls (Verify's and Enrolled's Get, the
// attempt charge, the step accept and the refund, and ConfirmEnrolment's Get),
// and TestPortErrors_TOTPEnrolment the enrolment-side ones (the random source,
// the generation generator, PutPending, Confirm and Delete). Each replaces
// slog.Default() for its duration, so neither runs in parallel, and each
// restores the logger it found.
//
// The go:debug line above makes panic(nil) panic with a nil value, as before
// Go 1.21, so the panic(nil) rows exercise the case a recover cannot tell from
// no panic. It applies to the whole test binary of this package, so every
// helper here that detects a panic does so by whether the call returned, never
// by recover's value.

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"runtime/debug"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/internal/porterr"
)

// ptotpSecret is the text every hostile error here returns.
const ptotpSecret = "totp-store-secret-text"

// ptotpRowEnv names the row a child process runs. It is empty in the parent.
const ptotpRowEnv = "SCRTY_MFA_TOTP_PORTERR_ROW"

// ptotpRanMarker prefixes the line a child prints, followed by the row's name,
// after the row ran and passed.
const ptotpRanMarker = "SCRTY_MFA_TOTP_PORTERR_RAN: "

var errPtotpDown = errors.New("enrolment store: connection refused")

type ptotpCycleOne struct{}

func (*ptotpCycleOne) Error() string   { return ptotpSecret }
func (c *ptotpCycleOne) Unwrap() error { return c }

type ptotpCycleMany struct{}

func (*ptotpCycleMany) Error() string     { return ptotpSecret }
func (c *ptotpCycleMany) Unwrap() []error { return []error{c} }

type ptotpPanicUnwrap struct{}

func (ptotpPanicUnwrap) Error() string { return ptotpSecret }
func (ptotpPanicUnwrap) Unwrap() error { panic("test: Unwrap panicked for " + ptotpSecret) }

type ptotpPanicNilUnwrap struct{}

func (ptotpPanicNilUnwrap) Error() string { return ptotpSecret }
func (ptotpPanicNilUnwrap) Unwrap() error { panic(nil) } //nolint:govet // the hostile case under test

type ptotpTypedNil struct{}

func (*ptotpTypedNil) Error() string { return ptotpSecret }

func ptotpFanOut(depth int) error {
	err := errors.New(ptotpSecret)
	for range depth {
		err = errors.Join(err, err)
	}

	return err
}

// ptotpSite names the enrolment store call a row fails, and the entry point
// that reaches it.
type ptotpSite string

const (
	ptotpVerifyGet  ptotpSite = "Verify's Get"
	ptotpEnrolled   ptotpSite = "Enrolled's Get"
	ptotpConfirmGet ptotpSite = "ConfirmEnrolment's Get"
	ptotpCharge     ptotpSite = "ChargeVerifyAttempt"
	ptotpAccept     ptotpSite = "AcceptStep"
	ptotpRefund     ptotpSite = "RefundVerifyAttempt"
)

var ptotpSites = []ptotpSite{ptotpVerifyGet, ptotpEnrolled, ptotpConfirmGet, ptotpCharge, ptotpAccept, ptotpRefund}

// ptotpOutcome is what one call through a failing store produced.
type ptotpOutcome struct {
	err      error
	text     string
	enrolled bool
	// provisioned is whether a begin handed back a secret.
	provisioned bool
	// msgs are the messages of the records the method's logger received,
	// abort records left out.
	msgs     []string
	aborts   []map[string]any
	panicked bool
	hung     bool
}

var (
	ptotpNow = time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	ptotpKey = []byte("0123456789abcdefghij")
)

// runPtotpSite calls the entry point that reaches site, with the store failing
// there with portErr and answering every earlier call as a healthy store does.
// A call the flow must not make has no expectation, so gomock fails the test
// if the flow makes it: a charge that failed never reaches AcceptStep, and a
// step that was not accepted is never refunded. It is bounded: a hang is
// reported, not waited for.
func runPtotpSite(t *testing.T, ctx context.Context, site ptotpSite, portErr error) ptotpOutcome {
	t.Helper()

	ctrl := gomock.NewController(t)
	mock := NewMockEnrolmentStore(ctrl)

	logs := &rstSyncBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	totpm, err := mfa.NewTOTP(mock, "scrty-test",
		mfa.WithClock(clockwork.NewFakeClockAt(ptotpNow)), mfa.WithLogger(logger))
	require.NoError(t, err)

	confirmed := mfa.Enrolment{
		User: "u-1", Secret: ptotpKey, Generation: fixtureGen, ConfirmedAt: ptotpNow.Add(-time.Hour),
	}
	until := ptotpNow.Add(time.Minute)
	code := codeAt(t, ptotpKey, ptotpNow, 6, 30*time.Second)

	switch site {
	case ptotpVerifyGet, ptotpEnrolled, ptotpConfirmGet:
		// A store that says "not found" and fails at once must still be read
		// as failing, never as "not enrolled".
		mock.EXPECT().Get(gomock.Any(), gomock.Any()).Return(mfa.Enrolment{}, false, portErr)
	case ptotpCharge:
		mock.EXPECT().Get(gomock.Any(), gomock.Any()).Return(confirmed, true, nil)
		// The failing charge claims it charged: a failure must still refuse,
		// so the code is never checked against an attempt nobody paid for.
		mock.EXPECT().ChargeVerifyAttempt(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(until, true, portErr)
	case ptotpAccept:
		mock.EXPECT().Get(gomock.Any(), gomock.Any()).Return(confirmed, true, nil)
		mock.EXPECT().ChargeVerifyAttempt(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(until, true, nil)
		// The failing accept claims it accepted: a failure must still refuse,
		// so a replayed step never passes.
		mock.EXPECT().AcceptStep(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(true, portErr)
	case ptotpRefund:
		mock.EXPECT().Get(gomock.Any(), gomock.Any()).Return(confirmed, true, nil)
		mock.EXPECT().ChargeVerifyAttempt(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(until, true, nil)
		mock.EXPECT().AcceptStep(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(true, nil)
		mock.EXPECT().RefundVerifyAttempt(gomock.Any(), gomock.Any(), gomock.Any()).Return(false, portErr)
	}

	return ptotpBounded(t, logs, func(out *ptotpOutcome) {
		switch site {
		case ptotpEnrolled:
			out.enrolled, out.err = totpm.Enrolled(ctx, "u-1")
		case ptotpConfirmGet:
			out.err = totpm.ConfirmEnrolment(ctx, "u-1", code)
		default:
			out.err = totpm.Verify(ctx, "u-1", []byte(code))
		}
	})
}

// ptotpBounded runs call on its own goroutine and returns what it produced,
// with the records logs received split into abort records and the messages of
// the others. It is bounded: a hang is reported, not waited for. A call that
// does not return normally is a panic, whatever recover reads: under
// panicnil=1 a panic(nil) recovers as nil.
func ptotpBounded(t *testing.T, logs *rstSyncBuffer, call func(out *ptotpOutcome)) ptotpOutcome {
	t.Helper()

	done := make(chan ptotpOutcome, 1)

	go func() {
		var (
			out      ptotpOutcome
			returned bool
		)

		defer func() {
			_ = recover()
			out.panicked = !returned
			done <- out
		}()

		call(&out)

		returned = true

		if out.err != nil {
			out.text = out.err.Error()
		}
	}()

	select {
	case out := <-done:
		for _, rec := range ptotpRecords(t, logs.Bytes()) {
			if rec["msg"] == porterr.MsgClassificationAborted {
				out.aborts = append(out.aborts, rec)

				continue
			}

			msg, _ := rec["msg"].(string)
			out.msgs = append(out.msgs, msg)
		}

		return out
	case <-time.After(10 * time.Second):
		return ptotpOutcome{hung: true}
	}
}

func ptotpRecords(t *testing.T, out []byte) []map[string]any {
	t.Helper()

	var records []map[string]any

	for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}

		rec := map[string]any{}
		require.NoError(t, json.Unmarshal([]byte(line), &rec))
		records = append(records, rec)
	}

	return records
}

// TestPortErrors_TOTPStore pins that an enrolment store call failing with an
// error whose chain cannot be walked ends exactly as a plain store outage
// does: the same returned text, never "not enrolled", never ErrInvalidCode,
// never a code checked on an attempt the charge did not record, never a step
// accepted that the store did not record, and a failed give-back changing
// nothing. The one abort record goes to the method's own logger, none to
// slog.Default().
func TestPortErrors_TOTPStore(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(ptotpRowEnv)
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
		site ptotpSite
		err  error
		ctx  func(ctx context.Context) context.Context

		// child runs the row in a child process: unsanitized, it overflows the
		// stack fatally.
		child bool

		// aborts is the number of abort records expected on the method's logger.
		aborts int
		// reason is the abort record's reason, when aborts is 1.
		reason string
	}

	var cases []testCase

	for _, site := range ptotpSites {
		p := string(site) + ": "

		cases = append(cases,
			testCase{name: p + "a cycle through Unwrap() error", site: site, err: &ptotpCycleOne{}, aborts: 1, reason: "budget"},
			testCase{name: p + "a cycle through Unwrap() []error", site: site, err: &ptotpCycleMany{}, child: true,
				aborts: 1, reason: "budget"},
			testCase{name: p + "a link whose Unwrap panics", site: site, err: ptotpPanicUnwrap{}, aborts: 1, reason: "panic"},
			testCase{name: p + "a link whose Unwrap panics with nil", site: site, err: ptotpPanicNilUnwrap{},
				aborts: 1, reason: "panic"},
			testCase{name: p + "a join that fans out", site: site, err: ptotpFanOut(25), aborts: 1, reason: "budget"},
			testCase{name: p + "a cycle on a context the caller cancelled", site: site, err: &ptotpCycleOne{},
				ctx: cancelled, aborts: 1, reason: "budget"},
			testCase{name: p + "a typed-nil root walks to the end", site: site, err: (*ptotpTypedNil)(nil)},
		)
	}

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				ptotpPortErrInChild(t, tc.name)

				return
			}

			defaults := rstDefaultRecords(t)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			plain := runPtotpSite(t, ctx, tc.site, errPtotpDown)
			require.False(t, plain.hung)
			require.False(t, plain.panicked)
			require.Empty(t, plain.aborts, "a plain outage writes no abort record")

			if tc.site == ptotpRefund {
				require.NoError(t, plain.err, "a failed give-back refuses nothing")
			} else {
				require.ErrorIs(t, plain.err, errPtotpDown, "the plain outage is returned")
				require.NotErrorIs(t, plain.err, mfa.ErrInvalidCode)
				require.False(t, plain.enrolled)
			}

			got := runPtotpSite(t, ctx, tc.site, tc.err)
			require.False(t, got.hung, "the TOTP method hung on a hostile error")
			require.False(t, got.panicked, "the TOTP method panicked on a hostile error")

			assert.Equal(t, plain.err == nil, got.err == nil, "refused exactly when the plain outage is")
			assert.Equal(t, plain.text, got.text, "the same fixed text as a plain outage")
			assert.NotContains(t, got.text, ptotpSecret)
			assert.False(t, got.enrolled, "a failing store is never read as enrolled")
			assert.Equal(t, plain.msgs, got.msgs, "the same records, abort aside")

			require.Len(t, got.aborts, tc.aborts, "abort records on the method's logger")
			assert.Empty(t, rstAborts(t, defaults.Bytes()), "no abort record on slog.Default()")

			if tc.aborts == 1 {
				assert.Equal(t, tc.reason, got.aborts[0]["reason"])

				raw, err := json.Marshal(got.aborts[0])
				require.NoError(t, err)
				assert.NotContains(t, string(raw), ptotpSecret)

				if got.err != nil {
					ptotpRequireFault(t, got.err)
					require.ErrorIs(t, got.err, porterr.ErrUnwalkable, "the fixed error, not the hostile one")
					assert.NotErrorIs(t, got.err, mfa.ErrInvalidCode)
					assert.NotErrorIs(t, got.err, mfa.ErrVerifyAttemptsExhausted)
				}
			}

			if only != "" && !t.Failed() {
				_, _ = os.Stdout.WriteString(ptotpRanMarker + tc.name + "\n")
			}
		})
	}
}

// ptotpPortErrInChild re-runs the current top-level test in a child process
// limited to row, and fails unless it exits 0 within a minute and prints a line
// equal to the marker proving it ran the row.
func ptotpPortErrInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), ptotpRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 8)], "\n"))

	marker := ptotpRanMarker + row
	ran := slices.ContainsFunc(strings.Split(string(out), "\n"), func(line string) bool {
		return strings.TrimSuffix(line, "\r") == marker
	})
	require.True(t, ran, "the child never ran row %q: no output line equals %q:\n%s", row, marker, string(out))
}

// ptotpIsFault reports whether err is, or wraps, a *porterr.Fault, reading its
// chain with a bounded walk of its own: stdlib errors.As and errors.Is follow a
// cycle forever, so a row that checks the returned error with them hangs the
// whole package, silently, when the error is the raw hostile one. It
// recovers an Unwrap that panics, which then reads as no fault.
func ptotpIsFault(err error) (found bool) {
	defer func() { _ = recover() }()

	const budget = 256

	queue := []error{err}

	for steps := 0; len(queue) > 0 && steps < budget; steps++ {
		e := queue[0]
		queue = queue[1:]

		switch u := e.(type) {
		case nil:
		case *porterr.Fault:
			return true
		case interface{ Unwrap() error }:
			queue = append(queue, u.Unwrap())
		case interface{ Unwrap() []error }:
			queue = append(queue, u.Unwrap()...)
		}
	}

	return false
}

// ptotpRequireFault fails fast, with a message, when err is not the fixed
// fault a sanitized hostile error becomes. It is called before any stdlib
// errors.Is or errors.As on the returned error.
func ptotpRequireFault(t *testing.T, err error) {
	t.Helper()

	require.True(t, ptotpIsFault(err),
		"the returned error is not a *porterr.Fault: the hostile error came back unsanitized")
}

// ptotpEnrolledCycle claims ErrAlreadyEnrolled through a chain that cycles back
// to itself: stdlib errors.Is finds the sentinel first and answers "already
// enrolled", while anything that walks past it never ends.
type ptotpEnrolledCycle struct{}

func (*ptotpEnrolledCycle) Error() string     { return ptotpSecret }
func (c *ptotpEnrolledCycle) Unwrap() []error { return []error{mfa.ErrAlreadyEnrolled, c} }

// ptotpEnrolledClaim claims ErrAlreadyEnrolled through its own Is, and its
// Unwrap panics.
type ptotpEnrolledClaim struct{}

func (ptotpEnrolledClaim) Error() string { return ptotpSecret }
func (ptotpEnrolledClaim) Is(target error) bool {
	return target == mfa.ErrAlreadyEnrolled //nolint:errorlint // identity of a sentinel
}
func (ptotpEnrolledClaim) Unwrap() error { panic("test: Unwrap panicked for " + ptotpSecret) }

// ptotpReader is a random source whose every read fails with err.
type ptotpReader struct{ err error }

func (r ptotpReader) Read([]byte) (int, error) { return 0, r.err }

// ptotpEnrolSite names the enrolment-side port call a row fails.
type ptotpEnrolSite string

const (
	ptotpRandom     ptotpEnrolSite = "the random source's Read"
	ptotpNewID      ptotpEnrolSite = "the generator's NewID"
	ptotpPutPending ptotpEnrolSite = "PutPending"
	ptotpConfirm    ptotpEnrolSite = "Confirm"
	ptotpDelete     ptotpEnrolSite = "Delete"
)

var ptotpEnrolSites = []ptotpEnrolSite{ptotpRandom, ptotpNewID, ptotpPutPending, ptotpConfirm, ptotpDelete}

// ptotpEager reports whether site's error is wrapped with fmt.Errorf, so a
// walkable error's own text ends the returned text.
func ptotpEager(site ptotpEnrolSite) bool { return site == ptotpRandom || site == ptotpNewID }

// runPtotpEnrolSite calls the entry point that reaches site, with that port
// failing with portErr and every earlier call answered as a healthy port
// does. A call the flow must not make has no expectation, so gomock fails the
// test if the flow makes it: a begin whose secret or generation failed stores
// nothing. Each failing port that returns a result claims success beside its
// error, so the error alone must decide. It is bounded: a hang is reported,
// not waited for.
func runPtotpEnrolSite(t *testing.T, ctx context.Context, site ptotpEnrolSite, portErr error) ptotpOutcome {
	t.Helper()

	ctrl := gomock.NewController(t)
	store := NewMockEnrolmentStore(ctrl)
	ids := NewMockGenerator(ctrl)

	logs := &rstSyncBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	opts := []mfa.Option{
		mfa.WithClock(clockwork.NewFakeClockAt(ptotpNow)), mfa.WithLogger(logger), mfa.WithIDGenerator(ids),
	}

	pending := mfa.Enrolment{User: "u-1", Secret: ptotpKey, Generation: fixtureGen, CreatedAt: ptotpNow}
	code := codeAt(t, ptotpKey, ptotpNow, 6, 30*time.Second)

	switch site {
	case ptotpRandom:
		opts = append(opts, mfa.WithRandom(ptotpReader{err: portErr}))
	case ptotpNewID:
		ids.EXPECT().NewID().Return(fixtureGen, portErr)
	case ptotpPutPending:
		ids.EXPECT().NewID().Return(fixtureGen, nil)
		store.EXPECT().PutPending(gomock.Any(), gomock.Any()).Return(portErr)
	case ptotpConfirm:
		store.EXPECT().Get(gomock.Any(), gomock.Any()).Return(pending, true, nil)
		store.EXPECT().Confirm(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(true, portErr)
	case ptotpDelete:
		store.EXPECT().Delete(gomock.Any(), gomock.Any()).Return(portErr)
	}

	totpm, err := mfa.NewTOTP(store, "scrty-test", opts...)
	require.NoError(t, err)

	return ptotpBounded(t, logs, func(out *ptotpOutcome) {
		switch site {
		case ptotpConfirm:
			out.err = totpm.ConfirmEnrolment(ctx, "u-1", code)
		case ptotpDelete:
			out.err = totpm.RemoveEnrolment(ctx, "u-1")
		default:
			var p mfa.Provisioning
			p, _, out.err = totpm.BeginEnrolmentGeneration(ctx, "u-1", "ada@example.com")
			out.provisioned = p != (mfa.Provisioning{})
		}
	})
}

// TestPortErrors_TOTPEnrolment pins that an enrolment-side port (the random
// source, the generation generator, and the store's PutPending, Confirm and
// Delete) failing with an error whose chain cannot be walked ends exactly as a
// plain outage does: refused, nothing provisioned, stored, confirmed or
// removed, the same records, and never ErrAlreadyEnrolled or ErrInvalidCode,
// whatever the hostile chain claims. Where the method wraps the port's error
// with fmt.Errorf, the hostile error is replaced before the wrap, so it is in
// neither the chain nor the text. The one abort record goes to the method's
// own logger, none to slog.Default().
func TestPortErrors_TOTPEnrolment(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(ptotpRowEnv)
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
		site ptotpEnrolSite
		err  error
		ctx  func(ctx context.Context) context.Context

		// child runs the row in a child process: unsanitized, it overflows the
		// stack fatally.
		child bool

		// aborts is the number of abort records expected on the method's logger.
		aborts int
		// reason is the abort record's reason, when aborts is 1.
		reason string
	}

	var cases []testCase

	for _, site := range ptotpEnrolSites {
		p := string(site) + ": "

		cases = append(cases,
			testCase{name: p + "a cycle through Unwrap() error", site: site, err: &ptotpCycleOne{}, aborts: 1, reason: "budget"},
			testCase{name: p + "a cycle through Unwrap() []error", site: site, err: &ptotpCycleMany{}, child: true,
				aborts: 1, reason: "budget"},
			testCase{name: p + "a link whose Unwrap panics", site: site, err: ptotpPanicUnwrap{}, aborts: 1, reason: "panic"},
			testCase{name: p + "a link whose Unwrap panics with nil", site: site, err: ptotpPanicNilUnwrap{},
				aborts: 1, reason: "panic"},
			testCase{name: p + "a join that fans out", site: site, err: ptotpFanOut(25), aborts: 1, reason: "budget"},
			testCase{name: p + "a cycle on a context the caller cancelled", site: site, err: &ptotpCycleOne{},
				ctx: cancelled, aborts: 1, reason: "budget"},
			testCase{name: p + "a typed-nil root walks to the end", site: site, err: (*ptotpTypedNil)(nil)},
		)
	}

	// The store may return ErrAlreadyEnrolled bare, and the method then returns
	// it as itself (pinned in mfa_test.go). A hostile chain that claims it is
	// an outage, never an enrolment the caller would report as existing.
	cases = append(cases,
		testCase{name: "PutPending: a cycle that leads with ErrAlreadyEnrolled", site: ptotpPutPending,
			err: &ptotpEnrolledCycle{}, child: true, aborts: 1, reason: "budget"},
		testCase{name: "PutPending: an Is claiming ErrAlreadyEnrolled on a link whose Unwrap panics",
			site: ptotpPutPending, err: ptotpEnrolledClaim{}, aborts: 1, reason: "panic"},
	)

	fault := new(porterr.Fault).Error()

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				ptotpPortErrInChild(t, tc.name)

				return
			}

			defaults := rstDefaultRecords(t)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			plain := runPtotpEnrolSite(t, ctx, tc.site, errPtotpDown)
			require.False(t, plain.hung)
			require.False(t, plain.panicked)
			require.Empty(t, plain.aborts, "a plain outage writes no abort record")
			require.ErrorIs(t, plain.err, errPtotpDown, "the plain outage is returned")
			require.NotErrorIs(t, plain.err, mfa.ErrAlreadyEnrolled)
			require.NotErrorIs(t, plain.err, mfa.ErrInvalidCode)
			require.False(t, plain.provisioned)
			require.Empty(t, plain.msgs, "a plain outage records no change")

			got := runPtotpEnrolSite(t, ctx, tc.site, tc.err)
			require.False(t, got.hung, "the TOTP method hung on a hostile error")
			require.False(t, got.panicked, "the TOTP method panicked on a hostile error")
			require.Error(t, got.err, "refused as the plain outage is")

			// Neither check walks the returned chain, so a row that is not
			// sanitized fails here rather than hanging in a later errors.Is.
			require.Len(t, got.aborts, tc.aborts, "abort records on the method's logger")
			require.Empty(t, rstAborts(t, defaults.Bytes()), "no abort record on slog.Default()")

			if ptotpEager(tc.site) {
				prefix, ok := strings.CutSuffix(plain.text, errPtotpDown.Error())
				require.True(t, ok, "the plain outage's text ends with the port's: %q", plain.text)

				if tc.aborts == 1 {
					assert.Equal(t, prefix+fault, got.text, "the method's text, then the fixed fault's")
				} else {
					assert.Equal(t, prefix+tc.err.Error(), got.text, "a walkable error is wrapped unchanged")
				}
			} else {
				assert.Equal(t, plain.text, got.text, "the same fixed text as a plain outage")
			}

			if tc.aborts == 1 || !ptotpEager(tc.site) {
				assert.NotContains(t, got.text, ptotpSecret)
			}

			assert.False(t, got.provisioned, "nothing is provisioned on a failing port")
			assert.Equal(t, plain.msgs, got.msgs, "the same records, abort aside")

			if tc.aborts == 1 {
				assert.Equal(t, tc.reason, got.aborts[0]["reason"])

				raw, err := json.Marshal(got.aborts[0])
				require.NoError(t, err)
				assert.NotContains(t, string(raw), ptotpSecret)

				ptotpRequireFault(t, got.err)
				require.NotErrorIs(t, got.err, mfa.ErrAlreadyEnrolled, "a hostile error is never \"already enrolled\"")
				require.ErrorIs(t, got.err, porterr.ErrUnwalkable, "the fixed error, not the hostile one")
				assert.NotErrorIs(t, got.err, mfa.ErrInvalidCode)
			} else {
				require.ErrorIs(t, got.err, tc.err, "a walkable error is kept")
				assert.NotErrorIs(t, got.err, mfa.ErrAlreadyEnrolled)
			}

			if only != "" && !t.Failed() {
				_, _ = os.Stdout.WriteString(ptotpRanMarker + tc.name + "\n")
			}
		})
	}
}
