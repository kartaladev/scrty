package authenticate_test

// TestPortErrors_PasswordIDGenerator replaces slog.Default() for its duration,
// so it does not run in parallel, and it restores the logger it found.

import (
	"context"
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
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/pkg/id"
)

// passwordIDPortErrRowEnv names the row a child process runs. It is empty in
// the parent.
const passwordIDPortErrRowEnv = "SCRTY_AUTHENTICATE_PASSWORD_IDGEN_PORTERR_ROW"

// passwordIDOutcome is what one correct-password Authenticate returned when the
// identifier generator failed, and what each logger recorded.
type passwordIDOutcome struct {
	err error

	// aborts counts the sanitizer's records on the authenticator's own logger.
	aborts int

	// defaultAborts counts them on slog.Default().
	defaultAborts int
}

// authenticateThroughIDGenerator runs one Authenticate with the right
// password against a provider whose identifier generator fails with genErr.
// It fails the test when the call hangs or lets a panic escape.
func authenticateThroughIDGenerator(ctx context.Context, t *testing.T, genErr error) passwordIDOutcome {
	t.Helper()

	defaults := defaultRecords(t)
	own := &syncBuffer{}
	ctrl := gomock.NewController(t)

	ids := NewMockGenerator(ctrl)
	ids.EXPECT().NewID().Return(id.Nil, genErr)

	auth, _ := authenticatorFor(t, cheapEncoder(t), //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
		authenticate.WithPasswordIDGenerator(ids),
		authenticate.WithPasswordLogger(slog.New(slog.NewJSONHandler(own, &slog.HandlerOptions{Level: slog.LevelDebug}))))

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

		_, err := auth.Authenticate(ctx, identity.NewUsernamePassword("ada", []byte(storedPassword)))
		returned = true
		done <- result{err: err}
	}()

	var r result

	select {
	case r = <-done:
		require.False(t, r.panicked, "a hostile generator error escaped as a panic: %v", r.value)
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a hostile generator error hung Authenticate")
	}

	out := passwordIDOutcome{err: r.err}

	for _, rec := range jsonRecords(t, own.Bytes()) {
		if rec["msg"] == msgPortErrAborted {
			out.aborts++
		}
	}

	for _, rec := range jsonRecords(t, defaults.Bytes()) {
		if rec["msg"] == msgPortErrAborted {
			out.defaultAborts++
		}
	}

	return out
}

// TestPortErrors_PasswordIDGenerator pins that an identifier generator failing
// with an error whose chain cannot be walked is answered as a plain generator
// failure is: the error that names no event, never a refusal. The sanitizer
// writes one record to the authenticator's own logger and none to
// slog.Default().
func TestPortErrors_PasswordIDGenerator(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(passwordIDPortErrRowEnv)
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

		// passes is true for a walk that completes, which writes no record.
		passes bool

		assert func(t *testing.T, plain, got error)
	}

	asGeneratorFailure := func(t *testing.T, plain, got error) {
		t.Helper()

		require.Error(t, plain)
		require.ErrorIs(t, plain, errNoIdentifier, "precondition")
		require.Contains(t, plain.Error(), "naming the authentication", "precondition")

		require.Error(t, got)
		assert.Contains(t, got.Error(), "naming the authentication", "the same error as a plain generator failure")
		assert.NotErrorIs(t, got, authenticate.ErrAuthenticationFailed, "a failure to name the event is no refusal")
		assert.NotContains(t, got.Error(), passwordPortErrSecret)
		assert.ErrorIs(t, got, porterr.ErrUnwalkable)
	}

	cases := []testCase{
		{name: "a cycle through Unwrap() error", err: &loaderCycleOne{}, assert: asGeneratorFailure},
		{name: "a cycle through Unwrap() []error", err: &loaderCycleMany{}, child: true, assert: asGeneratorFailure},
		{name: "a link whose Unwrap panics", err: loaderPanicUnwrap{}, assert: asGeneratorFailure},
		{name: "a link whose Unwrap panics with nil", err: loaderPanicNilUnwrap{}, assert: asGeneratorFailure},
		{name: "a join that fans out", err: loaderFanOut(25), assert: asGeneratorFailure},
		{name: "a cycle on a context the caller cancelled", err: &loaderCycleOne{}, ctx: cancelled, assert: asGeneratorFailure},
		{
			name: "a typed-nil root walks to the end and passes unchanged", err: (*loaderTypedNil)(nil), passes: true,
			assert: func(t *testing.T, _, got error) {
				t.Helper()

				require.Error(t, got)
				assert.Contains(t, got.Error(), "naming the authentication")
				assert.NotErrorIs(t, got, authenticate.ErrAuthenticationFailed)
			},
		},
	}

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				passwordIDPortErrInChild(t, tc.name)

				return
			}

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			plain := authenticateThroughIDGenerator(ctx, t, errNoIdentifier)
			require.Zero(t, plain.aborts, "a plain failure writes no abort record")

			got := authenticateThroughIDGenerator(ctx, t, tc.err)
			tc.assert(t, plain.err, got.err)

			if tc.passes {
				assert.Zero(t, got.aborts, "a walk that completes writes no abort record")
			} else {
				assert.Equal(t, 1, got.aborts, "one abort record, on the authenticator's logger")
			}

			assert.Zero(t, got.defaultAborts, "an abort record went to slog.Default()")

			announcePortErrRan(t, only, tc.name)
		})
	}
}

// passwordIDPortErrInChild re-runs the current top-level test in a child
// process limited to row, and fails unless it exits 0 within a minute and
// prints the row's marker line.
func passwordIDPortErrInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), passwordIDPortErrRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 8)], "\n"))
	requireChildRan(t, out, row)
}
