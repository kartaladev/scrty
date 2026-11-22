package authenticate_test

// TestPortErrors_PasswordEncoderProbe replaces slog.Default() for its
// duration, so it does not run in parallel, and it restores the logger it
// found.
//
// The hostile errors are the ones firstof_porterr_test.go declares.

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

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/internal/porterr"
)

// probePortErrRowEnv names the row a child process runs. It is empty in the
// parent.
const probePortErrRowEnv = "SCRTY_AUTHENTICATE_PROBE_PORTERR_ROW"

// errProbeEncodeDown is the plain failure the parity run's encoder returns.
var errProbeEncodeDown = errors.New("encoder: entropy exhausted")

// errProbeAsked is a sentinel nothing in the chain matches: asking for it
// makes the stdlib walk the whole returned error, as a caller's own check
// would.
var errProbeAsked = errors.New("test: probe")

// probeOutcome is what one construction with a failing reference-hash probe
// produced, every check of the error taken inside the bound.
type probeOutcome struct {
	built, config, unwalkable, asked, quotes bool

	text string

	aborts        []map[string]any
	defaultAborts int
}

// constructWithProbe builds a password authenticator whose encoder fails the
// construction-time reference-hash probe with probeErr. It fails the test when
// the construction or the checks of its error hang or let a panic escape.
func constructWithProbe(t *testing.T, probeErr error) probeOutcome {
	t.Helper()

	defaults := defaultRecords(t)
	ctrl := gomock.NewController(t)

	users := NewMockUserLoader(ctrl)
	enc := NewMockEncoder(ctrl)
	enc.EXPECT().Encode(gomock.Any()).Return(nil, probeErr)

	buf := &syncBuffer{}
	logger := slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	type result struct {
		out      probeOutcome
		returned bool
		value    any
	}

	done := make(chan result, 1)

	go func() {
		var r result

		defer func() {
			if !r.returned {
				r.value = recover()
			}

			done <- r
		}()

		a, err := authenticate.NewUsernamePasswordAuthenticator(users,
			authenticate.WithPasswordEncoder(enc), authenticate.WithPasswordLogger(logger))

		r.out = probeOutcome{
			built:      a != nil,
			config:     errors.Is(err, authenticate.ErrConfig),
			unwalkable: errors.Is(err, porterr.ErrUnwalkable),
			asked:      errors.Is(err, errProbeAsked),
		}
		if err != nil {
			r.out.text = err.Error()
			r.out.quotes = strings.Contains(r.out.text, firstOfPortErrSecret)
		}

		r.returned = true
	}()

	var r result

	select {
	case r = <-done:
		require.True(t, r.returned, "a hostile probe error escaped as a panic: %v", r.value)
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a hostile probe error hung the constructor or the checks of its error")
	}

	out := r.out

	for _, rec := range jsonRecords(t, buf.Bytes()) {
		if rec["msg"] == msgPortErrAborted {
			out.aborts = append(out.aborts, rec)
		}
	}

	for _, rec := range jsonRecords(t, defaults.Bytes()) {
		if rec["msg"] == msgPortErrAborted {
			out.defaultAborts++
		}
	}

	return out
}

// TestPortErrors_PasswordEncoderProbe pins that an encoder failing the
// construction-time reference-hash probe with an error whose chain cannot be
// walked is answered as a plain probe failure is: no authenticator, an
// ErrConfig with the same fixed text, and an error a caller can check and
// print without a hang or a panic. It also matches porterr.ErrUnwalkable,
// and the sanitizer writes one abort record to the provider's logger and none
// to slog.Default().
//
// Construction has no context, so there is no cancelled-context row: the
// record is written with context.Background().
func TestPortErrors_PasswordEncoderProbe(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(probePortErrRowEnv)
	if only != "" {
		debug.SetMaxStack(64 << 20)
	}

	type testCase struct {
		name string
		err  error

		// child runs the row in a child process: unsanitized, the caller's
		// check of the returned error overflows the stack fatally.
		child bool

		assert func(t *testing.T, plain, got probeOutcome)
	}

	// sameAsPlain asserts what a plain probe failure gives: no authenticator,
	// an ErrConfig with the same fixed text, nothing quoted, and nothing on
	// slog.Default().
	sameAsPlain := func(t *testing.T, plain, got probeOutcome) {
		t.Helper()

		assert.False(t, got.built, "never an authenticator")
		assert.True(t, got.config, "still a configuration error")
		assert.False(t, got.asked)
		assert.False(t, got.quotes, "the error's text quotes the encoder's")
		assert.Equal(t, plain.text, got.text, "the same fixed text as a plain probe failure")
		assert.Zero(t, got.defaultAborts, "nothing on slog.Default(): the provider has its own logger")
	}

	// aborted asserts the plain outcome, an error matching ErrUnwalkable, and
	// one abort record with reason on the provider's logger, quoting nothing
	// of the encoder's error.
	aborted := func(reason string) func(t *testing.T, plain, got probeOutcome) {
		return func(t *testing.T, plain, got probeOutcome) {
			t.Helper()

			sameAsPlain(t, plain, got)
			assert.True(t, got.unwalkable, "the probe's error is answered as uninspectable")

			require.Len(t, got.aborts, 1, "one abort record, on the provider's logger")
			assert.Equal(t, "ERROR", got.aborts[0]["level"])
			assert.Equal(t, reason, got.aborts[0]["reason"])

			for k, v := range got.aborts[0] {
				s, _ := v.(string)
				assert.NotContains(t, s, firstOfPortErrSecret, "attribute %q quotes the encoder's error", k)
			}
		}
	}

	cases := []testCase{
		{name: "a cycle through Unwrap() error", err: &foCycleOne{}, assert: aborted("budget")},
		{name: "a cycle through Unwrap() []error", err: &foCycleMany{}, child: true, assert: aborted("budget")},
		{
			name:   "a join that fans out",
			err:    foFanOut(errors.New(firstOfPortErrSecret), firstOfFanOutDepth),
			assert: aborted("budget"),
		},
		{name: "a link whose Unwrap panics", err: foUnwrapPanics{value: "boom " + firstOfPortErrSecret}, assert: aborted("panic")},
		{name: "a link whose Unwrap panics with nil", err: foUnwrapPanics{value: nil}, assert: aborted("panic")},
		{
			name: "a typed-nil root walks to the end and is answered as a plain failure",
			err:  (*foTypedNil)(nil),
			assert: func(t *testing.T, plain, got probeOutcome) {
				t.Helper()

				sameAsPlain(t, plain, got)
				assert.False(t, got.unwalkable)
				assert.Empty(t, got.aborts, "a walk that completes writes nothing")
			},
		},
	}

	for _, tc := range cases {
		if only != "" && (!tc.child || only != tc.name) {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				probePortErrInChild(t, tc.name)

				return
			}

			plain := constructWithProbe(t, errProbeEncodeDown)
			require.False(t, plain.built, "precondition: no authenticator is built")
			require.True(t, plain.config, "precondition: a failed probe is a configuration error")
			require.False(t, plain.unwalkable, "precondition")
			require.Empty(t, plain.aborts, "a plain failure writes no abort record")
			require.Zero(t, plain.defaultAborts)

			tc.assert(t, plain, constructWithProbe(t, tc.err))

			announcePortErrRan(t, only, tc.name)
		})
	}
}

// probePortErrInChild re-runs TestPortErrors_PasswordEncoderProbe in a child
// process limited to row, and fails unless it exits 0 within a minute and
// prints the row's marker as a whole line.
func probePortErrInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPortErrors_PasswordEncoderProbe$", "-test.count=1")
	cmd.Env = append(os.Environ(), probePortErrRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 12)], "\n"))
	requireChildRan(t, out, row)
}
