package recovery_test

// TestPortErrors_Recover replaces slog.Default() for its duration, so it does
// not run in parallel, and it restores the logger it found.

import (
	"context"
	"encoding/json"
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

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/depfault"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/recovery"
)

// recPortErrRowEnv names the row a child process runs. It is empty in the
// parent.
const recPortErrRowEnv = "SCRTY_RECOVERY_RECOVER_PORTERR_ROW"

// recPortErrRanMarker prefixes the line a child prints, followed by the row's
// name, after the row ran and passed.
const recPortErrRanMarker = "SCRTY_RECOVERY_RECOVER_PORTERR_RAN: "

// recClaimCycle claims to be claims through its own Is and contains itself
// through Unwrap() error. A check that believed its Is would take the claimed
// sentinel's branch for an error nobody can inspect.
type recClaimCycle struct{ claims error }

func (*recClaimCycle) Error() string   { return limPortErrSecret }
func (c *recClaimCycle) Unwrap() error { return c }
func (c *recClaimCycle) Is(target error) bool {
	return target == c.claims //nolint:errorlint // identity of a sentinel
}

// recWrapCycleMany wraps a sentinel beside itself through Unwrap() []error: a
// depth-first match finds the sentinel before the cycle, and a miss recurses
// until the stack overflows.
type recWrapCycleMany struct{ wraps error }

func (*recWrapCycleMany) Error() string { return limPortErrSecret }
func (c *recWrapCycleMany) Unwrap() []error {
	return []error{c.wraps, c}
}

// errRecPortDown is the plain outage most parity runs fail with.
var errRecPortDown = errors.New("port: connection refused")

// errRecPasswordUnavailable is the plain outage of a password check: the user
// store could not answer.
var errRecPasswordUnavailable = fmt.Errorf("password store down: %w", authenticate.ErrUnavailable)

// recSite names the port call a row fails.
type recSite string

const (
	recPassword recSite = "the password check"
	recLoader   recSite = "the username loader"
	recEnrolled recSite = "the MFA enrolment lookup"
	recRisk     recSite = "the risk hook"
	recCheck    recSite = "the consumer check"
	recVerify   recSite = "the MFA verification"
)

// recPlain is the plain outage a site's parity run fails with.
func recPlain(site recSite) error {
	if site == recPassword {
		return errRecPasswordUnavailable
	}

	return errRecPortDown
}

// recRecord is one record the recoverer's logger wrote, other than an abort
// record, reduced to what a consumer routes on.
type recRecord struct {
	level, msg, reason string
}

// recEvent is one security event, reduced to what parity compares.
type recEvent struct {
	name    string
	outcome string
	user    identity.UserID
}

// recOutcome is what one Recover through a failing port produced. Every error
// classification is made inside the bound, so a hostile chain that reaches the
// caller raw fails the run as a hang rather than hanging the test.
type recOutcome struct {
	text string

	refused     bool
	unavailable bool
	authFailed  bool
	userMissing bool
	mfaRefusal  bool
	failed      bool
	unwalkable  bool
	afterCode   bool
	plainCause  bool
	resultNil   bool

	events   []recEvent
	failures int32
	notices  int

	savedUsable  bool
	issuedUsable bool

	// records are the recoverer's records other than abort records, and raw
	// all of its output.
	records []recRecord
	raw     string

	// aborts are the sanitizer's records on the recoverer's logger.
	aborts []map[string]any
}

// runRecSite runs Recover on ctx against a port that fails the site's call
// with portErr. It fails the test when Recover, or the classification of its
// error, hangs or lets a panic escape.
func runRecSite(t *testing.T, ctx context.Context, site recSite, portErr error) recOutcome {
	t.Helper()

	e := newCompleteEnv(t)
	logs := &syncBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	own := &recoveryEvents{}

	extra := []recovery.Option{recovery.WithSecurityEvents(own.sink), recovery.WithLogger(logger)}
	deps := e.completeDeps()
	req := savedAndIssuedReq(e)
	mfaReq := recovery.Request{Username: anaUsername, Saved: e.saved[0], MFAMethod: "totp", MFACode: "123456"}

	switch site {
	case recPassword:
		e.passwordErr = portErr
		req = recovery.Request{Username: anaUsername, Saved: e.saved[0], Password: []byte(anaPassword)}
	case recLoader:
		users := NewMockUserLoader(e.ctrl)
		users.EXPECT().LoadByUsername(gomock.Any(), anaUsername).Return(nil, portErr).Times(1)
		deps.Users = users
	case recEnrolled:
		e.totp.EXPECT().Enrolled(gomock.Any(), anaID).Return(false, portErr).Times(1)
		req = mfaReq
	case recRisk:
		// A risk hook may hold a recovery, and a hold needs a cancel link.
		extra = append(extra, withCancelLink, recovery.WithRisk(func(context.Context, recovery.RiskInput) (time.Duration, error) {
			return 0, portErr
		}))
	case recCheck:
		extra = append(extra, recovery.WithChecks(func(context.Context, identity.UserID, []recovery.ProofKind) error {
			return portErr
		}))
	case recVerify:
		e.totp.EXPECT().Enrolled(gomock.Any(), anaID).Return(true, nil).Times(1)
		e.totp.EXPECT().Verify(gomock.Any(), anaID, []byte("123456")).Return(portErr).Times(1)
		req = mfaReq
	}

	r, err := recovery.NewRecoverer(deps, e.recovererOpts(extra...)...)
	require.NoError(t, err)

	type result struct {
		out      recOutcome
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

		res, err := r.Recover(ctx, req)

		o := recOutcome{resultNil: res == nil}
		if err != nil {
			o.text = err.Error()
			o.refused = errors.Is(err, recovery.ErrRefused)
			o.unavailable = errors.Is(err, authenticate.ErrUnavailable)
			o.authFailed = errors.Is(err, authenticate.ErrAuthenticationFailed)
			o.userMissing = errors.Is(err, identity.ErrUserNotFound)
			o.failed = errors.Is(err, depfault.ErrFailed)
			o.unwalkable = errors.Is(err, porterr.ErrUnwalkable)
			o.afterCode = recovery.RefusedAfterValidCode(err)
			o.plainCause = errors.Is(err, recPlain(site))

			for _, kind := range []error{mfa.ErrInvalidCode, mfa.ErrVerifyThrottled, mfa.ErrAuthenticatorRefused, mfa.ErrSameChannel} {
				o.mfaRefusal = o.mfaRefusal || errors.Is(err, kind)
			}
		}

		returned = true
		done <- result{out: o}
	}()

	var out recOutcome

	select {
	case res := <-done:
		require.False(t, res.panicked, "a hostile port error escaped Recover as a panic: %v", res.value)
		out = res.out
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a hostile port error hung Recover, or the classification of its error")
	}

	for _, ev := range own.all() {
		out.events = append(out.events, recEvent{name: ev.Name, outcome: ev.Outcome, user: ev.User})
	}

	out.failures = e.failures.Load()
	out.notices = len(e.out.messages())
	out.issuedUsable = e.issuedUsable(t.Context(), t, r, anaID, e.issued)
	out.savedUsable = e.savedUsable(t.Context(), t, e.saved[0])
	out.raw = logs.String()

	for _, rec := range limJSONRecords(t, out.raw) {
		if rec["msg"] == porterr.MsgClassificationAborted {
			out.aborts = append(out.aborts, rec)

			continue
		}

		reason, _ := rec["reason"].(string)
		out.records = append(out.records, recRecord{level: rec["level"].(string), msg: rec["msg"].(string), reason: reason})
	}

	return out
}

// TestPortErrors_Recover pins that each consumer port Recover calls — the
// password check, the username loader, the MFA method's enrolment lookup and
// verification, the risk hook and a consumer check — failing with an error
// whose chain cannot be walked is answered exactly as a plain outage of that
// port: the same error class, the same events, the same failures counted, the
// same notices and the same codes left unspent. A chain that claims or wraps a
// sentinel the site branches on never takes that sentinel's branch: a password
// check's cycle is an outage, never a failed authentication; a loader's is an
// outage, never an unknown user; an MFA method's is a dependency failure,
// never a refused code. The sanitizer writes one record, to the recoverer's
// logger, and none to slog.Default().
func TestPortErrors_Recover(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(recPortErrRowEnv)
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
		site recSite
		err  error

		// plain is the parity run's error. nil means the site's plain
		// outage.
		plain error

		// ctx modifies the context both runs of the row use. nil means the
		// test's own.
		ctx func(ctx context.Context) context.Context

		// child runs the row in a child process: unsanitized, it may
		// overflow the stack fatally.
		child bool

		// assert receives the plain run's outcome and the row's.
		assert func(t *testing.T, plain, got recOutcome)
	}

	// sameAsPlain compares everything but the error's own text and its
	// match of the plain error.
	sameAsPlain := func(t *testing.T, plain, got recOutcome) {
		t.Helper()

		assert.True(t, got.resultNil, "a failed recovery has no result")
		assert.Equal(t, plain.refused, got.refused, "ErrRefused")
		assert.Equal(t, plain.unavailable, got.unavailable, "authenticate.ErrUnavailable")
		assert.Equal(t, plain.authFailed, got.authFailed, "authenticate.ErrAuthenticationFailed")
		assert.Equal(t, plain.userMissing, got.userMissing, "identity.ErrUserNotFound")
		assert.Equal(t, plain.mfaRefusal, got.mfaRefusal, "an MFA refusal sentinel")
		assert.Equal(t, plain.failed, got.failed, "depfault.ErrFailed")
		assert.Equal(t, plain.afterCode, got.afterCode, "RefusedAfterValidCode")
		assert.Equal(t, plain.events, got.events, "the same events")
		assert.Equal(t, plain.failures, got.failures, "the same failures counted against the user")
		assert.Equal(t, plain.notices, got.notices, "the same notices sent")
		assert.Equal(t, plain.savedUsable, got.savedUsable, "the saved code spent alike")
		assert.Equal(t, plain.issuedUsable, got.issuedUsable, "the issued code spent alike")
		assert.Equal(t, plain.records, got.records, "the same records, levels and reasons")
	}

	asOutage := func(site recSite, reason string) func(t *testing.T, plain, got recOutcome) {
		return func(t *testing.T, plain, got recOutcome) {
			t.Helper()

			sameAsPlain(t, plain, got)

			switch site {
			case recLoader:
				// Concealed: the answer is the bare outage sentinel, which
				// carries nothing of the loader's, and reads as a plain
				// outage does, never as an unknown user.
				require.True(t, plain.unavailable, "precondition: a plain loader outage is unavailable")
				assert.False(t, got.refused, "a loader outage answered as an unknown user")
				assert.False(t, got.unwalkable, "the concealed answer carries the fault")
				assert.Equal(t, plain.text, got.text, "the same fixed text")
			case recPassword:
				// The plain-outage branch: returned unmarked, never refused.
				require.True(t, plain.unavailable, "precondition: a plain check outage is unavailable")
				assert.False(t, got.authFailed, "an outage answered as a failed authentication")
				assert.True(t, got.unwalkable, "the answer is a fault standing for the check's error")
			case recCheck:
				assert.True(t, got.unwalkable, "the answer is a fault standing for the check's error")
				assert.Equal(t, porterr.ErrUnwalkable.Error(), got.text, "the fixed error's text")
			default:
				assert.True(t, got.unwalkable, "the answer is a fault standing for the port's error")
				assert.Equal(t, plain.text, got.text, "the same fixed text")
			}

			assert.False(t, got.userMissing, "an outage answered as an unknown user")
			assert.False(t, got.mfaRefusal, "an outage answered as a refused MFA code")
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

	// walked is a chain the sanitizer reads to its end: returned unchanged
	// and answered as a plain error is, with no abort record.
	walked := func(t *testing.T, plain, got recOutcome) {
		t.Helper()

		sameAsPlain(t, plain, got)
		assert.False(t, got.unwalkable, "a walkable error replaced by a fault")
		assert.Empty(t, got.aborts, "a walk that completes writes no abort record")
	}

	var cases []testCase

	for _, site := range []recSite{recPassword, recLoader, recEnrolled, recRisk, recCheck, recVerify} {
		prefix := string(site) + ": "

		typedNilPlain := error(nil)
		if site == recPassword {
			// A typed-nil root is no outage sentinel: the check failed for
			// another reason, as a plain unclassified error does.
			typedNilPlain = errRecPortDown
		}

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
				site: site, err: (*limTypedNil)(nil), plain: typedNilPlain,
				assert: walked,
			},
		)
	}

	// The sentinels each site branches on, claimed through Is by a cycle and
	// wrapped beside a cycle through Unwrap() []error.
	claimed := []struct {
		site     recSite
		sentinel error
		label    string
	}{
		{recPassword, authenticate.ErrAuthenticationFailed, "a failed authentication"},
		{recPassword, authenticate.ErrUnavailable, "an unavailable store"},
		{recLoader, identity.ErrUserNotFound, "an unknown user"},
		{recVerify, mfa.ErrInvalidCode, "an invalid MFA code"},
		{recVerify, mfa.ErrVerifyThrottled, "a throttled MFA verification"},
		{recVerify, mfa.ErrAuthenticatorRefused, "a refused MFA authenticator"},
		{recVerify, mfa.ErrSameChannel, "an MFA channel it cannot serve"},
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

	// A consumer's own refusal that its chain shows finite is returned as it
	// is: the sanitizer changes nothing for it.
	cases = append(cases, testCase{
		name: string(recCheck) + ": a walkable refusal is returned unchanged",
		site: recCheck, err: errRecPortDown,
		assert: func(t *testing.T, plain, got recOutcome) {
			t.Helper()

			walked(t, plain, got)
			assert.True(t, got.plainCause, "the consumer's refusal is still identifiable")
			assert.Equal(t, errRecPortDown.Error(), got.text, "the consumer's refusal keeps its text")
		},
	})

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				recPortErrInChild(t, tc.name)

				return
			}

			defaults := limDefaultRecords(t)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			plainErr := tc.plain
			if plainErr == nil {
				plainErr = recPlain(tc.site)
			}

			plain := runRecSite(t, ctx, tc.site, plainErr)
			require.Empty(t, plain.aborts, "a plain outage writes no abort record")

			got := runRecSite(t, ctx, tc.site, tc.err)
			tc.assert(t, plain, got)

			for _, rec := range limJSONRecords(t, defaults.String()) {
				assert.NotEqual(t, porterr.MsgClassificationAborted, rec["msg"], "an abort record went to slog.Default()")
			}

			if only != "" && !t.Failed() {
				// Stdout, so the parent's CombinedOutput carries it.
				_, _ = os.Stdout.WriteString(recPortErrRanMarker + tc.name + "\n")
			}
		})
	}
}

// recPortErrInChild re-runs the current top-level test in a child process
// limited to row, and fails unless it exits 0 within a minute and prints the
// marker that shows it ran the row: a stack overflow is fatal and only a
// child can watch for one.
func recPortErrInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), recPortErrRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 12)], "\n"))

	// A child whose row name matched no case skips every row and exits 0: it
	// proves it ran the row only by printing the marker after the row passed.
	// One whole line must equal the marker.
	want := recPortErrRanMarker + row
	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.TrimSuffix(line, "\r") == want {
			return
		}
	}

	t.Fatalf("the child never ran row %q: no line equals %q; output:\n%s", row, want, out)
}
