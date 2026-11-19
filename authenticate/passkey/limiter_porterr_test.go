package passkey_test

// TestPortErrors_ConfirmLimiter replaces slog.Default() for its duration, so it
// does not run in parallel, and it restores the logger it found.

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

	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/internal/porterr"
)

// limiterSecret is the text every hostile error here returns, so a test can
// assert no record and no returned error quotes it.
const limiterSecret = "confirm-limiter-secret-text"

// limiterRowEnv names the row a child process runs. It is empty in the parent.
const limiterRowEnv = "SCRTY_PASSKEY_LIMITER_PORTERR_ROW"

// limiterRanMarker prefixes the line a child prints, followed by the row's
// name, after the row ran and passed.
const limiterRanMarker = "SCRTY_PASSKEY_LIMITER_PORTERR_RAN: "

// errConfirmLimiterDown is the plain outage the parity runs fail with.
var errConfirmLimiterDown = errors.New("limiter: connection refused")

type limiterCycleOne struct{}

func (*limiterCycleOne) Error() string   { return limiterSecret }
func (c *limiterCycleOne) Unwrap() error { return c }

type limiterCycleMany struct{}

func (*limiterCycleMany) Error() string     { return limiterSecret }
func (c *limiterCycleMany) Unwrap() []error { return []error{c} }

type limiterPanicUnwrap struct{}

func (limiterPanicUnwrap) Error() string { return limiterSecret }
func (limiterPanicUnwrap) Unwrap() error { panic("test: Unwrap panicked for " + limiterSecret) }

type limiterPanicNilUnwrap struct{}

func (limiterPanicNilUnwrap) Error() string { return limiterSecret }
func (limiterPanicNilUnwrap) Unwrap() error { panic(nil) } //nolint:govet // the hostile case under test

type limiterTypedNil struct{}

func (*limiterTypedNil) Error() string { return limiterSecret }

// limiterFanOut is errors.Join(n, n) nested depth times.
func limiterFanOut(depth int) error {
	err := errors.New(limiterSecret)
	for range depth {
		err = errors.Join(err, err)
	}

	return err
}

// limiterSite names the limiter call a row fails.
type limiterSite string

const (
	limiterExceeded limiterSite = "ConfirmEmailCode's Exceeded"
	limiterRecord   limiterSite = "refuseEmailCode's RecordFailure"
)

// limiterOutcome is what one ConfirmEmailCode call through a failing limiter
// produced.
type limiterOutcome struct {
	err      error
	text     string
	panicked bool

	throttled   bool
	emailInvald bool

	// recordCtxErr is the Err of the context the limiter's RecordFailure was
	// given, when it was called at all.
	recordCalled bool
	recordCtxErr error

	// failures are the manager's "not counted" records, by level.
	failures []string

	// aborts are the sanitizer's records on the manager's logger.
	aborts []map[string]any
}

func limiterJSONRecords(t *testing.T, out string) []map[string]any {
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

// runLimiterSite runs ConfirmEmailCode on ctx against a consumer limiter that
// fails the call site names with limiterErr. It fails the test when the call
// hangs.
func runLimiterSite(t *testing.T, ctx context.Context, site limiterSite, limiterErr error) limiterOutcome {
	t.Helper()

	var out limiterOutcome

	l := NewMockLimiter(gomock.NewController(t))

	switch site {
	case limiterExceeded:
		l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, limiterErr)
	case limiterRecord:
		l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil)
		l.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).
			DoAndReturn(func(ctx context.Context, _ string) error {
				out.recordCalled, out.recordCtxErr = true, ctx.Err()

				return limiterErr
			})
	}

	f := newFixture(t)
	logs := &logBuffer{}
	m := f.manager(t, passkey.WithLogger(logs.logger()))
	s := enrolmentSession("sess-a", "u-1")
	rc := passkey.RegistrationContext{EmailConfirmation: true, ConfirmLimiter: l}

	code := "000000"

	if site == limiterRecord {
		challenge := f.begin(t, m, s)
		_, err := m.FinishRegistration(t.Context(), s, regBody(challenge, "cred-a", ""), rc)
		require.NoError(t, err)

		code = wrongCode(emailedCode(t, f))
	}

	type result struct {
		err         error
		text        string
		throttled   bool
		emailInvald bool
		panicked    bool
	}

	done := make(chan result, 1)

	go func() {
		returned := false

		defer func() {
			if !returned {
				_ = recover()
				done <- result{panicked: true}
			}
		}()

		_, err := m.ConfirmEmailCode(ctx, s, code, rc)

		// Classified inside the bound: a hostile chain that reaches the caller
		// raw hangs here, and fails the run as a hang.
		res := result{err: err}
		if err != nil {
			res.text = err.Error()
			res.throttled = errors.Is(err, mfa.ErrEnrolmentThrottled)
			res.emailInvald = errors.Is(err, mfa.ErrEmailCodeInvalid)
		}

		returned = true
		done <- res
	}()

	select {
	case r := <-done:
		require.False(t, r.panicked, "a hostile limiter error escaped as a panic")
		out.err, out.text, out.throttled, out.emailInvald = r.err, r.text, r.throttled, r.emailInvald
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a hostile limiter error hung the call, or its classification")
	}

	for _, rec := range limiterJSONRecords(t, logs.String()) {
		switch rec["msg"] {
		case "passkey: a failed confirmation was not counted":
			out.failures = append(out.failures, rec["level"].(string))
		case porterr.MsgClassificationAborted:
			out.aborts = append(out.aborts, rec)
		}
	}

	return out
}

// limiterDefaultRecords points slog.Default() at a buffer until the test ends.
// The caller must not be parallel.
func limiterDefaultRecords(t *testing.T) *logBuffer {
	t.Helper()

	buf := &logBuffer{}
	prev := slog.Default()
	slog.SetDefault(buf.logger())
	t.Cleanup(func() { slog.SetDefault(prev) })

	return buf
}

// TestPortErrors_ConfirmLimiter pins that a confirmation limiter's call failing
// with an error whose chain cannot be walked is answered exactly as a plain
// limiter outage is:
//
//   - Exceeded refuses the confirmation, matching mfa.ErrEnrolmentThrottled
//     with the outage's fixed text, never admitting the code;
//   - RecordFailure still answers mfa.ErrEmailCodeInvalid, with the
//     outage's error-level record.
//
// The sanitizer writes one record to the manager's own logger and none to
// slog.Default().
func TestPortErrors_ConfirmLimiter(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(limiterRowEnv)
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
		site limiterSite
		err  error

		// ctx modifies the context the row uses. nil means the test's own.
		ctx func(ctx context.Context) context.Context

		// child runs the row in a child process: unsanitized, it overflows the
		// stack fatally.
		child bool

		// assert receives the plain outage's outcome and the row's.
		assert func(t *testing.T, plain, got limiterOutcome)
	}

	sameAsPlain := func(t *testing.T, site limiterSite, plain, got limiterOutcome) {
		t.Helper()

		assert.Equal(t, plain.text, got.text, "the same fixed text")
		assert.Equal(t, plain.throttled, got.throttled)
		assert.Equal(t, plain.emailInvald, got.emailInvald)
		assert.Equal(t, plain.failures, got.failures, "the same limiter-failure record")
		assert.Equal(t, plain.recordCalled, got.recordCalled)
		assert.NotContains(t, got.text, limiterSecret)

		switch site {
		case limiterExceeded:
			require.ErrorIs(t, got.err, mfa.ErrEnrolmentThrottled, "an undecidable limiter refuses")
			assert.NotErrorIs(t, got.err, mfa.ErrEmailCodeInvalid, "never the not-throttled path")
			assert.False(t, got.recordCalled, "a refused confirmation is never counted")
		case limiterRecord:
			assert.Equal(t, mfa.ErrEmailCodeInvalid, got.err, "the refusal is unchanged") //nolint:testifylint,errorlint // identity is the claim
			assert.Equal(t, []string{"ERROR"}, got.failures)
			require.True(t, got.recordCalled, "the failure is still counted")
			assert.NoError(t, got.recordCtxErr, "under a context the caller cannot cancel")
		}
	}

	asOutage := func(site limiterSite, reason string) func(t *testing.T, plain, got limiterOutcome) {
		return func(t *testing.T, plain, got limiterOutcome) {
			t.Helper()

			sameAsPlain(t, site, plain, got)

			require.Len(t, got.aborts, 1, "one abort record, on the manager's logger")
			assert.Equal(t, "ERROR", got.aborts[0]["level"])
			assert.Equal(t, reason, got.aborts[0]["reason"])

			raw, err := json.Marshal(got.aborts[0])
			require.NoError(t, err)
			assert.NotContains(t, string(raw), limiterSecret, "the record quotes the error")
		}
	}

	var cases []testCase

	for _, site := range []limiterSite{limiterExceeded, limiterRecord} {
		prefix := string(site) + ": "

		cases = append(cases,
			testCase{name: prefix + "a cycle through Unwrap() error", site: site, err: &limiterCycleOne{},
				assert: asOutage(site, "budget")},
			testCase{name: prefix + "a cycle through Unwrap() []error", site: site, err: &limiterCycleMany{}, child: true,
				assert: asOutage(site, "budget")},
			testCase{name: prefix + "a link whose Unwrap panics", site: site, err: limiterPanicUnwrap{},
				assert: asOutage(site, "panic")},
			testCase{name: prefix + "a link whose Unwrap panics with nil", site: site, err: limiterPanicNilUnwrap{},
				assert: asOutage(site, "panic")},
			testCase{name: prefix + "a join that fans out", site: site, err: limiterFanOut(25),
				assert: asOutage(site, "budget")},
			testCase{name: prefix + "a cycle on a context the caller cancelled is an outage", site: site,
				err: &limiterCycleOne{}, ctx: cancelled, assert: asOutage(site, "budget")},
			testCase{name: prefix + "a typed-nil root walks to the end and is answered as an outage", site: site,
				err: (*limiterTypedNil)(nil),
				assert: func(t *testing.T, plain, got limiterOutcome) {
					t.Helper()

					sameAsPlain(t, site, plain, got)
					assert.Empty(t, got.aborts, "a walk that completes writes no abort record")
				}},
		)
	}

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				limiterPortErrInChild(t, tc.name)

				return
			}

			defaults := limiterDefaultRecords(t)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			plain := runLimiterSite(t, ctx, tc.site, errConfirmLimiterDown)
			require.Empty(t, plain.aborts, "a plain outage writes no abort record")

			got := runLimiterSite(t, ctx, tc.site, tc.err)
			tc.assert(t, plain, got)

			for _, rec := range limiterJSONRecords(t, defaults.String()) {
				assert.NotEqual(t, porterr.MsgClassificationAborted, rec["msg"], "an abort record went to slog.Default()")
			}

			if only != "" && !t.Failed() {
				// Stdout, so the parent's CombinedOutput carries it.
				_, _ = os.Stdout.WriteString(limiterRanMarker + tc.name + "\n")
			}
		})
	}
}

// limiterPortErrInChild re-runs the current top-level test in a child process
// limited to row, and fails unless it exits 0 within a minute and prints the
// marker proving it ran the row.
func limiterPortErrInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), limiterRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 8)], "\n"))
	require.Contains(t, string(out), limiterRanMarker+row,
		"the child never ran the row: its name matches no case")
}
