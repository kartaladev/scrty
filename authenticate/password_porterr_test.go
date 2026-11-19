package authenticate_test

// TestPortErrors_PasswordUserLoader replaces slog.Default() for its duration,
// so it does not run in parallel, and it restores the logger it found.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/identity"
)

// passwordPortErrSecret is the text every hostile error here returns, so a
// test can assert no record and no returned error quotes it.
const passwordPortErrSecret = "user-store-secret-text"

// msgPortErrAborted is the record the boundary sanitizer writes for a port
// error whose chain it could not walk.
const msgPortErrAborted = "httpsec: error classification aborted"

// passwordPortErrRowEnv names the row a child process runs. It is empty in
// the parent.
const passwordPortErrRowEnv = "SCRTY_AUTHENTICATE_PORTERR_ROW"

// loaderCycleOne contains itself through Unwrap() error.
type loaderCycleOne struct{}

func (*loaderCycleOne) Error() string   { return passwordPortErrSecret }
func (c *loaderCycleOne) Unwrap() error { return c }

// loaderCycleMany contains itself through Unwrap() []error. Unsanitized, the
// stdlib walk overflows the stack fatally, so its row runs in a child process.
type loaderCycleMany struct{}

func (*loaderCycleMany) Error() string     { return passwordPortErrSecret }
func (c *loaderCycleMany) Unwrap() []error { return []error{c} }

// loaderNotFoundCycle wraps identity.ErrUserNotFound and itself through
// Unwrap() []error: the one hostile shape the stdlib reads as "not found",
// since errors.Is finds the sentinel before it loops. Its row runs in a child
// process, because the stdlib walk overflows on it.
type loaderNotFoundCycle struct{}

func (*loaderNotFoundCycle) Error() string { return passwordPortErrSecret }
func (c *loaderNotFoundCycle) Unwrap() []error {
	return []error{identity.ErrUserNotFound, c}
}

// loaderCanceledCycle wraps context.Canceled and itself, so the stdlib reads
// it as the caller's hang-up when the walk is not sanitized.
type loaderCanceledCycle struct{}

func (*loaderCanceledCycle) Error() string { return passwordPortErrSecret }
func (c *loaderCanceledCycle) Unwrap() []error {
	return []error{context.Canceled, c}
}

// loaderPanicUnwrap is an error whose Unwrap panics.
type loaderPanicUnwrap struct{}

func (loaderPanicUnwrap) Error() string { return passwordPortErrSecret }
func (loaderPanicUnwrap) Unwrap() error { panic("test: Unwrap panicked for " + passwordPortErrSecret) }

// loaderPanicNilUnwrap is an error whose Unwrap panics with nil.
type loaderPanicNilUnwrap struct{}

func (loaderPanicNilUnwrap) Error() string { return passwordPortErrSecret }
func (loaderPanicNilUnwrap) Unwrap() error { panic(nil) } //nolint:govet // the hostile case under test

// loaderTypedNil is returned as a nil pointer inside a non-nil error.
type loaderTypedNil struct{}

func (*loaderTypedNil) Error() string { return passwordPortErrSecret }

// loaderFanOut is errors.Join(n, n) nested depth times: no cycle, but 2^depth
// paths for an unbounded walk.
func loaderFanOut(depth int) error {
	err := errors.New(passwordPortErrSecret)
	for range depth {
		err = errors.Join(err, err)
	}

	return err
}

// errLoaderDown is the plain outage the parity row's loader fails with.
var errLoaderDown = errors.New("user store: connection refused")

// loaderOutcome is what one Authenticate call through a failing loader
// produced: what it returned, what it logged, and how much password work it
// spent.
type loaderOutcome struct {
	err     error
	matches int

	// refusals are the "authentication refused" records, reduced to their
	// level and reason.
	refusals []string

	// aborts are the sanitizer's records on the provider's logger.
	aborts []map[string]any
}

// authenticateThroughLoader runs one Authenticate on ctx against a provider
// whose loader fails with loadErr. It fails the test when the call hangs or
// lets a panic escape.
func authenticateThroughLoader(t *testing.T, ctx context.Context, loadErr error) loaderOutcome {
	t.Helper()

	ctrl := gomock.NewController(t)

	users := NewMockUserLoader(ctrl)
	users.EXPECT().LoadByUsername(gomock.Any(), "ada").Return(nil, loadErr)

	var (
		mu      sync.Mutex
		matches int
	)

	enc := NewMockEncoder(ctrl)
	enc.EXPECT().Encode(gomock.Any()).Return([]byte("$fake$reference"), nil)
	enc.EXPECT().Match(gomock.Any(), gomock.Any()).DoAndReturn(func(string, []byte) bool {
		mu.Lock()
		defer mu.Unlock()

		matches++

		return false
	}).AnyTimes()

	buf := &syncBuffer{}
	auth, err := authenticate.NewUsernamePasswordAuthenticator(users,
		authenticate.WithPasswordEncoder(enc),
		authenticate.WithPasswordLogger(slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))))
	require.NoError(t, err)

	type result struct {
		err      error
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

		_, err := auth.Authenticate(ctx, identity.NewUsernamePassword("ada", []byte("guess")))
		returned = true
		done <- result{err: err}
	}()

	var r result

	select {
	case r = <-done:
		require.False(t, r.panicked, "a hostile loader error escaped as a panic: %v", r.value)
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a hostile loader error hung Authenticate")
	}

	out := loaderOutcome{err: r.err}

	mu.Lock()
	out.matches = matches
	mu.Unlock()

	for _, rec := range jsonRecords(t, buf.Bytes()) {
		switch rec["msg"] {
		case "authentication refused":
			out.refusals = append(out.refusals, rec["level"].(string)+" "+rec["reason"].(string))
		case msgPortErrAborted:
			out.aborts = append(out.aborts, rec)
		}
	}

	return out
}

// syncBuffer is a bytes.Buffer safe for the handler and the test to share.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

func (b *syncBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()

	return append([]byte(nil), b.buf.Bytes()...)
}

// jsonRecords decodes every JSON record in out.
func jsonRecords(t *testing.T, out []byte) []map[string]any {
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

// defaultRecords points slog.Default() at a JSON buffer until the test ends.
// The caller must not be parallel.
func defaultRecords(t *testing.T) *syncBuffer {
	t.Helper()

	buf := &syncBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	return buf
}

// TestPortErrors_PasswordUserLoader pins that a user loader failing with an
// error whose chain cannot be walked is answered exactly as a plain loader
// outage is: the bare ErrUnavailable, never the unknown-user refusal and never
// a hang-up, after the same one reference verification and the same
// error-level refusal record. The sanitizer writes one record, to the
// provider's own logger and none to slog.Default().
func TestPortErrors_PasswordUserLoader(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(passwordPortErrRowEnv)
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
		err  error

		// ctx modifies the context both the parity call and this row's call
		// run on. nil means the test's own.
		ctx func(ctx context.Context) context.Context

		// child runs the row in a child process: unsanitized, it overflows
		// the stack fatally.
		child bool

		assert func(t *testing.T, plain, got loaderOutcome)
	}

	// asOutage is what every row whose walk aborts asserts: the outcome is the
	// plain outage's, and one abort record with reason went to the provider's
	// logger.
	asOutage := func(reason string) func(t *testing.T, plain, got loaderOutcome) {
		return func(t *testing.T, plain, got loaderOutcome) {
			t.Helper()

			require.ErrorIs(t, plain.err, authenticate.ErrUnavailable, "precondition: a plain outage is unavailable")

			assert.Equal(t, plain.err, got.err, "the hostile error is answered as the bare ErrUnavailable")
			assert.NotErrorIs(t, got.err, authenticate.ErrAuthenticationFailed, "never the unknown-user refusal")
			assert.NotContains(t, got.err.Error(), passwordPortErrSecret)
			assert.Equal(t, plain.matches, got.matches, "the same reference verification")
			assert.Equal(t, plain.refusals, got.refusals, "the same refusal record")

			require.Len(t, got.aborts, 1, "one abort record, on the provider's logger")
			assert.Equal(t, "ERROR", got.aborts[0]["level"])
			assert.Equal(t, reason, got.aborts[0]["reason"])

			raw, err := json.Marshal(got.aborts[0])
			require.NoError(t, err)
			assert.NotContains(t, string(raw), passwordPortErrSecret, "the record quotes the error")
		}
	}

	cases := []testCase{
		{name: "a cycle through Unwrap() error", err: &loaderCycleOne{}, assert: asOutage("budget")},
		{name: "a cycle through Unwrap() []error", err: &loaderCycleMany{}, child: true, assert: asOutage("budget")},
		{name: "a link whose Unwrap panics", err: loaderPanicUnwrap{}, assert: asOutage("panic")},
		{name: "a link whose Unwrap panics with nil", err: loaderPanicNilUnwrap{}, assert: asOutage("panic")},
		{name: "a join that fans out", err: loaderFanOut(25), assert: asOutage("budget")},
		{
			name:  "a cycle wrapping ErrUserNotFound is an outage, never the unknown-user refusal",
			err:   &loaderNotFoundCycle{},
			child: true,
			assert: func(t *testing.T, plain, got loaderOutcome) {
				t.Helper()

				assert.ErrorIs(t, got.err, authenticate.ErrUnavailable, "never the not-found branch")
				assert.Equal(t, []string{"ERROR user-loader"}, got.refusals, "the outage's record")
				asOutage("budget")(t, plain, got)
			},
		},
		{
			name:  "a cycle wrapping context.Canceled on a cancelled context is an outage, not a hang-up",
			err:   &loaderCanceledCycle{},
			ctx:   cancelled,
			child: true,
			assert: func(t *testing.T, plain, got loaderOutcome) {
				t.Helper()

				assert.NotErrorIs(t, got.err, context.Canceled, "read as the caller's hang-up")
				assert.Equal(t, []string{"ERROR user-loader"}, got.refusals, "an outage is error level, a hang-up debug")
				asOutage("budget")(t, plain, got)
			},
		},
		{
			name: "a cycle on a context the caller cancelled is an outage, not a hang-up",
			err:  &loaderCycleOne{},
			ctx:  cancelled,
			assert: func(t *testing.T, plain, got loaderOutcome) {
				t.Helper()

				assert.NotErrorIs(t, got.err, context.Canceled, "the hostile error was read as the caller's hang-up")
				asOutage("budget")(t, plain, got)
			},
		},
		{
			name: "a typed-nil root walks to the end, so it passes unchanged and is answered as an outage",
			err:  (*loaderTypedNil)(nil),
			assert: func(t *testing.T, plain, got loaderOutcome) {
				t.Helper()

				assert.Equal(t, plain.err, got.err)
				assert.Equal(t, plain.refusals, got.refusals)
				assert.Empty(t, got.aborts, "a walk that completes writes no abort record")
			},
		},
	}

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				passwordPortErrInChild(t, tc.name)

				return
			}

			defaults := defaultRecords(t)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			plain := authenticateThroughLoader(t, ctx, errLoaderDown)
			require.Empty(t, plain.aborts, "a plain outage writes no abort record")

			got := authenticateThroughLoader(t, ctx, tc.err)
			tc.assert(t, plain, got)

			for _, rec := range jsonRecords(t, defaults.Bytes()) {
				assert.NotEqual(t, msgPortErrAborted, rec["msg"], "an abort record went to slog.Default()")
			}
		})
	}
}

// passwordPortErrInChild re-runs the current top-level test in a child
// process limited to row, and fails unless it exits 0 within a minute: a
// stack overflow is fatal and only a child can watch for one.
func passwordPortErrInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), passwordPortErrRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 8)], "\n"))
}
