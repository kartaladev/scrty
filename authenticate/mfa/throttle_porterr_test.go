package mfa_test

// TestPortErrors_VerifyThrottleLimiter replaces slog.Default() for its
// duration, so it does not run in parallel, and it restores the logger it found.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/internal/porterr"
)

// throttleSecret is the text every hostile error here returns, so a test can
// assert no record and no returned error quotes it.
const throttleSecret = "limiter-secret-text"

// throttleRowEnv names the row a child process runs. It is empty in the parent.
const throttleRowEnv = "SCRTY_MFA_THROTTLE_PORTERR_ROW"

// throttleRanMarker prefixes the line a child prints, followed by the row's
// name, after the row ran and passed.
const throttleRanMarker = "SCRTY_MFA_THROTTLE_PORTERR_RAN: "

// errThrottleLimiterDown is the plain outage the parity runs fail with.
var errThrottleLimiterDown = errors.New("limiter: connection refused")

type throttleCycleOne struct{}

func (*throttleCycleOne) Error() string   { return throttleSecret }
func (c *throttleCycleOne) Unwrap() error { return c }

type throttleCycleMany struct{}

func (*throttleCycleMany) Error() string     { return throttleSecret }
func (c *throttleCycleMany) Unwrap() []error { return []error{c} }

type throttlePanicUnwrap struct{}

func (throttlePanicUnwrap) Error() string { return throttleSecret }
func (throttlePanicUnwrap) Unwrap() error { panic("test: Unwrap panicked for " + throttleSecret) }

type throttlePanicNilUnwrap struct{}

func (throttlePanicNilUnwrap) Error() string { return throttleSecret }
func (throttlePanicNilUnwrap) Unwrap() error { panic(nil) } //nolint:govet // the hostile case under test

type throttleTypedNil struct{}

func (*throttleTypedNil) Error() string { return throttleSecret }

// throttleFanOut is errors.Join(n, n) nested depth times.
func throttleFanOut(depth int) error {
	err := errors.New(throttleSecret)
	for range depth {
		err = errors.Join(err, err)
	}

	return err
}

// throttleSite names the limiter call a row fails.
type throttleSite string

const (
	throttleCheck  throttleSite = "Check's Exceeded"
	throttleRecord throttleSite = "RecordFailure's RecordFailure"
)

// throttleOutcome is what one call through a failing limiter produced.
type throttleOutcome struct {
	err       error
	text      string
	throttled bool
	panicked  bool

	// failures are the throttle's own limiter-failure records, by level.
	failures []string

	// aborts are the sanitizer's records on the throttle's logger.
	aborts []map[string]any
}

type throttleSyncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *throttleSyncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

func (b *throttleSyncBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()

	return append([]byte(nil), b.buf.Bytes()...)
}

func throttleJSONRecords(t *testing.T, out []byte) []map[string]any {
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

// runThrottleSite runs the call site names on ctx against a throttle whose
// limiter fails that call with limiterErr. It fails the test when the call
// hangs.
func runThrottleSite(t *testing.T, ctx context.Context, site throttleSite, limiterErr error) throttleOutcome {
	t.Helper()

	limiter := NewMockLimiter(gomock.NewController(t))

	switch site {
	case throttleCheck:
		limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, limiterErr)
	case throttleRecord:
		limiter.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Return(limiterErr)
	}

	buf := &throttleSyncBuffer{}

	th, err := mfa.NewVerifyThrottle(
		mfa.WithThrottleLimiter(limiter),
		mfa.WithThrottleLogger(slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))),
	)
	require.NoError(t, err)

	done := make(chan throttleOutcome, 1)

	go func() {
		returned := false

		defer func() {
			if !returned {
				_ = recover()
				done <- throttleOutcome{panicked: true}
			}
		}()

		var out throttleOutcome

		switch site {
		case throttleCheck:
			out.err = th.Check(ctx, "u-1")
		case throttleRecord:
			th.RecordFailure(ctx, "u-1")
		}

		if out.err != nil {
			out.text = out.err.Error()
			out.throttled = errors.Is(out.err, mfa.ErrVerifyThrottled)
		}

		returned = true
		done <- out
	}()

	var out throttleOutcome

	select {
	case out = <-done:
		require.False(t, out.panicked, "a hostile limiter error escaped as a panic")
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a hostile limiter error hung the call, or its classification")
	}

	for _, rec := range throttleJSONRecords(t, buf.Bytes()) {
		switch rec["msg"] {
		case "mfa: verification throttle could not be consulted", "mfa: verification failure could not be recorded":
			out.failures = append(out.failures, rec["level"].(string))
		case porterr.MsgClassificationAborted:
			out.aborts = append(out.aborts, rec)
		}
	}

	return out
}

// throttleDefaultRecords points slog.Default() at a JSON buffer until the test
// ends. The caller must not be parallel.
func throttleDefaultRecords(t *testing.T) *throttleSyncBuffer {
	t.Helper()

	buf := &throttleSyncBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	return buf
}

// TestPortErrors_VerifyThrottleLimiter pins that a limiter call failing with an
// error whose chain cannot be walked is answered exactly as a plain limiter
// outage is: Check refuses with ErrVerifyThrottled, and RecordFailure changes
// no outcome. The sanitizer writes one record to the throttle's own logger and
// none to slog.Default().
func TestPortErrors_VerifyThrottleLimiter(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(throttleRowEnv)
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
		site throttleSite
		err  error

		// ctx modifies the context the row uses. nil means the test's own.
		ctx func(ctx context.Context) context.Context

		// child runs the row in a child process: unsanitized, it overflows the
		// stack fatally.
		child bool

		// assert receives the plain outage's outcome and the row's.
		assert func(t *testing.T, plain, got throttleOutcome)
	}

	sameAsPlain := func(t *testing.T, site throttleSite, plain, got throttleOutcome) {
		t.Helper()

		assert.Equal(t, plain.err, got.err, "the same returned error")
		assert.Equal(t, plain.throttled, got.throttled)
		assert.Equal(t, plain.failures, got.failures, "the same limiter-failure record")
		assert.Equal(t, []string{"ERROR"}, got.failures)
		assert.NotContains(t, got.text, throttleSecret)

		if site == throttleCheck {
			require.ErrorIs(t, got.err, mfa.ErrVerifyThrottled, "an undecidable limiter refuses")
		} else {
			assert.NoError(t, got.err, "RecordFailure reports nothing back")
		}
	}

	asOutage := func(site throttleSite, reason string) func(t *testing.T, plain, got throttleOutcome) {
		return func(t *testing.T, plain, got throttleOutcome) {
			t.Helper()

			sameAsPlain(t, site, plain, got)

			require.Len(t, got.aborts, 1, "one abort record, on the throttle's logger")
			assert.Equal(t, "ERROR", got.aborts[0]["level"])
			assert.Equal(t, reason, got.aborts[0]["reason"])

			raw, err := json.Marshal(got.aborts[0])
			require.NoError(t, err)
			assert.NotContains(t, string(raw), throttleSecret, "the record quotes the error")
		}
	}

	var cases []testCase

	for _, site := range []throttleSite{throttleCheck, throttleRecord} {
		prefix := string(site) + ": "

		cases = append(cases,
			testCase{name: prefix + "a cycle through Unwrap() error", site: site, err: &throttleCycleOne{},
				assert: asOutage(site, "budget")},
			testCase{name: prefix + "a cycle through Unwrap() []error", site: site, err: &throttleCycleMany{}, child: true,
				assert: asOutage(site, "budget")},
			testCase{name: prefix + "a link whose Unwrap panics", site: site, err: throttlePanicUnwrap{},
				assert: asOutage(site, "panic")},
			testCase{name: prefix + "a link whose Unwrap panics with nil", site: site, err: throttlePanicNilUnwrap{},
				assert: asOutage(site, "panic")},
			testCase{name: prefix + "a join that fans out", site: site, err: throttleFanOut(25),
				assert: asOutage(site, "budget")},
			testCase{name: prefix + "a cycle on a context the caller cancelled is an outage", site: site,
				err: &throttleCycleOne{}, ctx: cancelled, assert: asOutage(site, "budget")},
			testCase{name: prefix + "a typed-nil root walks to the end and is answered as an outage", site: site,
				err: (*throttleTypedNil)(nil),
				assert: func(t *testing.T, plain, got throttleOutcome) {
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
				throttlePortErrInChild(t, tc.name)

				return
			}

			defaults := throttleDefaultRecords(t)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			plain := runThrottleSite(t, ctx, tc.site, errThrottleLimiterDown)
			require.Empty(t, plain.aborts, "a plain outage writes no abort record")

			got := runThrottleSite(t, ctx, tc.site, tc.err)
			tc.assert(t, plain, got)

			for _, rec := range throttleJSONRecords(t, defaults.Bytes()) {
				assert.NotEqual(t, porterr.MsgClassificationAborted, rec["msg"], "an abort record went to slog.Default()")
			}

			if only != "" && !t.Failed() {
				// Stdout, so the parent's CombinedOutput carries it.
				_, _ = os.Stdout.WriteString(throttleRanMarker + tc.name + "\n")
			}
		})
	}
}

// throttlePortErrInChild re-runs the current top-level test in a child process
// limited to row, and fails unless it exits 0 within a minute and prints the
// marker proving it ran the row.
func throttlePortErrInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), throttleRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 8)], "\n"))
	marker := throttleRanMarker + row
	ran := slices.ContainsFunc(strings.Split(string(out), "\n"), func(line string) bool {
		return strings.TrimSuffix(line, "\r") == marker
	})
	require.True(t, ran, "the child never ran row %q: no output line equals %q:\n%s", row, marker, string(out))
}
