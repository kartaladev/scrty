package authenticate_test

// TestPortErrors_JWT replaces slog.Default() for its duration, so it does not
// run in parallel, and it restores the logger it found.

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
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/token"
)

// jwtPortErrSecret is the text every hostile error here returns.
const jwtPortErrSecret = "jwt-port-secret-text" //nolint:gosec // G101: a fixture, not a credential

// jwtPortErrRowEnv names the row a child process runs. It is empty in the
// parent.
const jwtPortErrRowEnv = "SCRTY_AUTHENTICATE_JWT_PORTERR_ROW"

// jwtCycleOne contains itself through Unwrap() error.
type jwtCycleOne struct{}

func (*jwtCycleOne) Error() string   { return jwtPortErrSecret }
func (c *jwtCycleOne) Unwrap() error { return c }

// jwtCycleMany contains itself through Unwrap() []error. Unsanitized, the
// stdlib walk overflows the stack fatally, so its row runs in a child process.
type jwtCycleMany struct{}

func (*jwtCycleMany) Error() string     { return jwtPortErrSecret }
func (c *jwtCycleMany) Unwrap() []error { return []error{c} }

// jwtInvalidCycle wraps token.ErrInvalid and itself: the shape the stdlib
// reads as a refusal of the token when its walk is not sanitized.
type jwtInvalidCycle struct{}

func (*jwtInvalidCycle) Error() string { return jwtPortErrSecret }
func (c *jwtInvalidCycle) Unwrap() []error {
	return []error{token.ErrInvalid, c}
}

// jwtCanceledCycle wraps context.Canceled and itself, so the stdlib reads it
// as the caller's hang-up when the walk is not sanitized.
type jwtCanceledCycle struct{}

func (*jwtCanceledCycle) Error() string { return jwtPortErrSecret }
func (c *jwtCanceledCycle) Unwrap() []error {
	return []error{context.Canceled, c}
}

// jwtPanicUnwrap is an error whose Unwrap panics.
type jwtPanicUnwrap struct{}

func (jwtPanicUnwrap) Error() string { return jwtPortErrSecret }
func (jwtPanicUnwrap) Unwrap() error { panic("test: Unwrap panicked for " + jwtPortErrSecret) }

// jwtPanicNilUnwrap is an error whose Unwrap panics with nil.
type jwtPanicNilUnwrap struct{}

func (jwtPanicNilUnwrap) Error() string { return jwtPortErrSecret }
func (jwtPanicNilUnwrap) Unwrap() error { panic(nil) } //nolint:govet // the hostile case under test

// jwtTypedNil is returned as a nil pointer inside a non-nil error.
type jwtTypedNil struct{}

func (*jwtTypedNil) Error() string { return jwtPortErrSecret }

// jwtFanOut is errors.Join(n, n) nested depth times.
func jwtFanOut(depth int) error {
	err := errors.New(jwtPortErrSecret)
	for range depth {
		err = errors.Join(err, err)
	}

	return err
}

// errJWTPortDown is the plain outage the parity row's port fails with.
var errJWTPortDown = errors.New("port: connection refused")

// jwtSite names the port a row makes fail.
type jwtSite int

const (
	jwtSiteVerifier jwtSite = iota
	jwtSiteGenerator
)

// authenticateThroughJWT runs one Authenticate on ctx with the chosen port
// failing with portErr. It returns what the call returned and how many abort
// records reached slog.Default(), and fails the test when the call hangs or a
// panic escapes.
func authenticateThroughJWT(ctx context.Context, t *testing.T, site jwtSite, portErr error) (int, error) {
	t.Helper()

	defaults := defaultRecords(t)
	ctrl := gomock.NewController(t)

	verifier := NewMockVerifier(ctrl)
	opts := []authenticate.JWTOption{authenticate.WithJWTVerifier(verifier)}

	switch site {
	case jwtSiteVerifier:
		verifier.EXPECT().Verify(gomock.Any(), gomock.Any()).Return(nil, portErr)
	case jwtSiteGenerator:
		verifier.EXPECT().Verify(gomock.Any(), gomock.Any()).
			Return(token.NewClaims("ada", "opaque-issuer-reference"), nil)

		ids := NewMockGenerator(ctrl)
		ids.EXPECT().NewID().Return(id.Nil, portErr)

		opts = append(opts, authenticate.WithJWTIDGenerator(ids))
	}

	auth, err := authenticate.NewJWTAuthenticator(opts...)
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

		_, err := auth.Authenticate(ctx, authenticate.NewBearerToken("a.b.c"))
		returned = true
		done <- result{err: err}
	}()

	var r result

	select {
	case r = <-done:
		require.False(t, r.panicked, "a hostile port error escaped as a panic: %v", r.value)
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a hostile port error hung Authenticate")
	}

	aborts := 0

	for _, rec := range jsonRecords(t, defaults.Bytes()) {
		if rec["msg"] == msgPortErrAborted {
			aborts++
		}
	}

	return aborts, r.err
}

// TestPortErrors_JWT pins that a verifier or an identifier generator failing
// with an error whose chain cannot be walked is answered as a plain failure of
// that port is: the verifier's as the key outage, never the refusal of the
// token and never a hang-up on a live context; the generator's as the error
// that names no event, never a refusal. The sanitizer writes one record to
// slog.Default(), the provider holding no logger of its own.
func TestPortErrors_JWT(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(jwtPortErrRowEnv)
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
		site jwtSite
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

	asVerifierOutage := func(t *testing.T, plain, got error) {
		t.Helper()

		require.Error(t, plain)
		require.NotErrorIs(t, plain, authenticate.ErrAuthenticationFailed, "precondition: a plain outage is no refusal")
		assert.Contains(t, plain.Error(), "verification keys unavailable", "precondition")

		require.Error(t, got)
		assert.Contains(t, got.Error(), "verification keys unavailable", "the same key-outage text")
		assert.NotErrorIs(t, got, authenticate.ErrAuthenticationFailed, "never the refusal of the token")
		assert.NotErrorIs(t, got, token.ErrInvalid)
		assert.NotErrorIs(t, got, context.Canceled, "never the caller's hang-up")
		assert.NotContains(t, got.Error(), "the caller left")
		assert.NotContains(t, got.Error(), jwtPortErrSecret)
		assert.ErrorIs(t, got, porterr.ErrUnwalkable)
	}

	asGeneratorFailure := func(t *testing.T, plain, got error) {
		t.Helper()

		require.Error(t, plain)
		require.ErrorIs(t, plain, errJWTPortDown, "precondition")
		require.Contains(t, plain.Error(), "naming the authentication", "precondition")

		require.Error(t, got)
		assert.Contains(t, got.Error(), "naming the authentication", "the same error as a plain generator failure")
		assert.NotErrorIs(t, got, authenticate.ErrAuthenticationFailed, "a failure to name the event is no refusal")
		assert.NotContains(t, got.Error(), jwtPortErrSecret)
		assert.ErrorIs(t, got, porterr.ErrUnwalkable)
	}

	cases := []testCase{
		{name: "verifier: a cycle through Unwrap() error", site: jwtSiteVerifier, err: &jwtCycleOne{}, assert: asVerifierOutage},
		{name: "verifier: a cycle through Unwrap() []error", site: jwtSiteVerifier, err: &jwtCycleMany{}, child: true, assert: asVerifierOutage},
		{name: "verifier: a link whose Unwrap panics", site: jwtSiteVerifier, err: jwtPanicUnwrap{}, assert: asVerifierOutage},
		{name: "verifier: a link whose Unwrap panics with nil", site: jwtSiteVerifier, err: jwtPanicNilUnwrap{}, assert: asVerifierOutage},
		{name: "verifier: a join that fans out", site: jwtSiteVerifier, err: jwtFanOut(25), assert: asVerifierOutage},
		{
			name: "verifier: a cycle wrapping token.ErrInvalid is an outage, never a refusal",
			site: jwtSiteVerifier, err: &jwtInvalidCycle{}, child: true, assert: asVerifierOutage,
		},
		{
			name: "verifier: a cycle wrapping context.Canceled on a live context is an outage, not a hang-up",
			site: jwtSiteVerifier, err: &jwtCanceledCycle{}, child: true, assert: asVerifierOutage,
		},
		{
			name: "verifier: a cycle on a context the caller cancelled is an outage, not a hang-up",
			site: jwtSiteVerifier, err: &jwtCycleOne{}, ctx: cancelled, assert: asVerifierOutage,
		},
		{
			name: "verifier: a typed-nil root walks to the end and passes unchanged", site: jwtSiteVerifier,
			err: (*jwtTypedNil)(nil), passes: true,
			assert: func(t *testing.T, plain, got error) {
				t.Helper()

				assert.Equal(t, plain.Error(), got.Error())
				assert.NotErrorIs(t, got, authenticate.ErrAuthenticationFailed)
			},
		},
		{name: "generator: a cycle through Unwrap() error", site: jwtSiteGenerator, err: &jwtCycleOne{}, assert: asGeneratorFailure},
		{name: "generator: a cycle through Unwrap() []error", site: jwtSiteGenerator, err: &jwtCycleMany{}, child: true, assert: asGeneratorFailure},
		{name: "generator: a link whose Unwrap panics", site: jwtSiteGenerator, err: jwtPanicUnwrap{}, assert: asGeneratorFailure},
		{name: "generator: a link whose Unwrap panics with nil", site: jwtSiteGenerator, err: jwtPanicNilUnwrap{}, assert: asGeneratorFailure},
		{name: "generator: a join that fans out", site: jwtSiteGenerator, err: jwtFanOut(25), assert: asGeneratorFailure},
	}

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				jwtPortErrInChild(t, tc.name)

				return
			}

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			plainAborts, plain := authenticateThroughJWT(ctx, t, tc.site, errJWTPortDown)
			require.Zero(t, plainAborts, "a plain outage writes no abort record")

			aborts, got := authenticateThroughJWT(ctx, t, tc.site, tc.err)
			tc.assert(t, plain, got)

			if tc.passes {
				assert.Zero(t, aborts, "a walk that completes writes no abort record")
			} else {
				assert.Equal(t, 1, aborts, "one abort record, on slog.Default()")
			}

			announcePortErrRan(t, only, tc.name)
		})
	}
}

// jwtPortErrInChild re-runs the current top-level test in a child process
// limited to row, and fails unless it exits 0 within a minute: a stack
// overflow is fatal and only a child can watch for one.
func jwtPortErrInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), jwtPortErrRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 8)], "\n"))
	requireChildRan(t, out, row)
}
