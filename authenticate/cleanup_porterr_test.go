package authenticate_test

// TestPortErrors_JWTCredentialsCleanup replaces slog.Default() for its
// duration, so it does not run in parallel, and it restores the logger it
// found.
//
// The password authenticator's own cleanup is not a row: it only ever calls
// identity.UsernamePassword.Cleanup, a concrete method that always returns
// nil, so no hostile error can reach it.

import (
	"context"
	"errors"
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
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/token"
)

// cleanupPortErrRowEnv names the row a child process runs. It is empty in the
// parent.
const cleanupPortErrRowEnv = "SCRTY_AUTHENTICATE_CLEANUP_PORTERR_ROW"

// errCleanupDown is the plain failure the parity row's cleanup returns.
var errCleanupDown = errors.New("credential: wipe failed")

// errCleanupProbe is a sentinel nothing in the chain matches: asking for it
// makes the stdlib walk the whole returned error.
var errCleanupProbe = errors.New("test: probe")

// cleanupOutcome is what one successful verification with a failing cleanup
// produced.
type cleanupOutcome struct {
	err    error
	aborts int
}

// authenticateThroughCleanup runs one Authenticate on ctx over a credential
// whose Cleanup fails with cleanupErr. It walks the returned error the way a
// caller's errors.Is does, and fails the test when any of it hangs or panics.
func authenticateThroughCleanup(t *testing.T, ctx context.Context, cleanupErr error) cleanupOutcome {
	t.Helper()

	defaults := defaultRecords(t)
	ctrl := gomock.NewController(t)

	verifier := NewMockVerifier(ctrl)
	verifier.EXPECT().Verify(gomock.Any(), gomock.Any()).
		Return(token.NewClaims("ada", "opaque-issuer-reference"), nil)

	auth, err := authenticate.NewJWTAuthenticator(authenticate.WithJWTVerifier(verifier))
	require.NoError(t, err)

	creds := NewMockBearerCredentials(ctrl)
	creds.EXPECT().Token().Return("a.b.c")
	creds.EXPECT().Cleanup().Return(cleanupErr)

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

		_, err := auth.Authenticate(ctx, creds)
		if err != nil {
			// What a caller does next: classify the error, then print it.
			_ = errors.Is(err, errCleanupProbe)
			_ = err.Error()
		}

		returned = true
		done <- result{err: err}
	}()

	var r result

	select {
	case r = <-done:
		require.False(t, r.panicked, "a hostile cleanup error escaped as a panic: %v", r.value)
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a hostile cleanup error hung Authenticate or the walk of what it returned")
	}

	aborts := 0

	for _, rec := range jsonRecords(t, defaults.Bytes()) {
		if rec["msg"] == msgPortErrAborted {
			aborts++
		}
	}

	return cleanupOutcome{err: r.err, aborts: aborts}
}

// TestPortErrors_JWTCredentialsCleanup pins that a credential whose Cleanup
// fails with an error whose chain cannot be walked is answered as a plain
// cleanup failure is: the same fixed text, never a success and never a
// refusal. The returned error can be walked and printed without a hang, and
// the sanitizer writes one record to slog.Default(), the provider holding no
// logger of its own.
func TestPortErrors_JWTCredentialsCleanup(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(cleanupPortErrRowEnv)
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

		// child runs the row in a child process: unsanitized, the walk of
		// the returned error overflows the stack fatally.
		child bool

		// passes is true for a walk that completes, which writes no record.
		passes bool

		assert func(t *testing.T, plain, got cleanupOutcome)
	}

	asCleanupFailure := func(t *testing.T, plain, got cleanupOutcome) {
		t.Helper()

		require.Error(t, plain.err)
		require.ErrorIs(t, plain.err, errCleanupDown, "precondition")
		require.Contains(t, plain.err.Error(), "clearing the presented token", "precondition")

		require.Error(t, got.err, "a cleanup failure is never swallowed")
		assert.Equal(t, plain.err.Error(), got.err.Error(), "the same fixed text as a plain cleanup failure")
		assert.NotErrorIs(t, got.err, authenticate.ErrAuthenticationFailed, "no refusal")
		assert.NotErrorIs(t, got.err, context.Canceled)
		assert.NotContains(t, got.err.Error(), jwtPortErrSecret)
		assert.ErrorIs(t, got.err, porterr.ErrUnwalkable)
	}

	cases := []testCase{
		{name: "a cycle through Unwrap() error", err: &jwtCycleOne{}, assert: asCleanupFailure},
		{name: "a cycle through Unwrap() []error", err: &jwtCycleMany{}, child: true, assert: asCleanupFailure},
		{name: "a link whose Unwrap panics", err: jwtPanicUnwrap{}, assert: asCleanupFailure},
		{name: "a link whose Unwrap panics with nil", err: jwtPanicNilUnwrap{}, assert: asCleanupFailure},
		// Depth 10 holds 2,047 entries, past the walk's budget of 1,000, yet an
		// unsanitized stdlib walk of it ends in microseconds: the row fails on
		// its assertions, never by leaving a walk spinning past the bound.
		{name: "a join that fans out", err: jwtFanOut(10), assert: asCleanupFailure},
		{name: "a cycle on a context the caller cancelled", err: &jwtCycleOne{}, ctx: cancelled, assert: asCleanupFailure},
		{
			name: "a typed-nil root walks to the end and passes unchanged", err: (*jwtTypedNil)(nil), passes: true,
			assert: func(t *testing.T, plain, got cleanupOutcome) {
				t.Helper()

				require.Error(t, got.err)
				assert.Equal(t, plain.err.Error(), got.err.Error())
				assert.NotErrorIs(t, got.err, porterr.ErrUnwalkable)
			},
		},
	}

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				cleanupPortErrInChild(t, tc.name)

				return
			}

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			plain := authenticateThroughCleanup(t, ctx, errCleanupDown)
			require.Zero(t, plain.aborts, "a plain failure writes no abort record")

			got := authenticateThroughCleanup(t, ctx, tc.err)
			tc.assert(t, plain, got)

			if tc.passes {
				assert.Zero(t, got.aborts, "a walk that completes writes no abort record")
			} else {
				assert.Equal(t, 1, got.aborts, "one abort record, on slog.Default()")
			}

			announcePortErrRan(t, only, tc.name)
		})
	}
}

// cleanupPortErrInChild re-runs the current top-level test in a child process
// limited to row, and fails unless it exits 0 within a minute and prints the
// row's marker line: a stack overflow is fatal and only a child can watch for
// one.
func cleanupPortErrInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), cleanupPortErrRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 8)], "\n"))
	requireChildRan(t, out, row)
}
