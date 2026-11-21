package authenticate_test

// TestPortErrors_FirstOf replaces slog.Default() for its duration, so it does
// not run in parallel, and it restores the logger it found.

import (
	"context"
	"errors"
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

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/porterr"
)

// firstOfPortErrSecret is the text every hostile delegate error returns.
const firstOfPortErrSecret = "firstof-delegate-secret-text"

// firstOfPortErrRowEnv names the row a child process runs. It is empty in the
// parent.
const firstOfPortErrRowEnv = "SCRTY_AUTHENTICATE_FIRSTOF_PORTERR_ROW"

// firstOfFanOutDepth nests errors.Join(n, n) deep enough that the chain holds
// more entries than the sanitizer's walk budget, yet shallow enough that an
// unsanitized stdlib walk of it ends in microseconds rather than spinning on
// past the row's bound.
const firstOfFanOutDepth = 10

// errFirstOfDelegateDown is the plain outage every parity run fails with.
var errFirstOfDelegateDown = errors.New("delegate: user store unreachable")

// foCycleOne is an error whose Unwrap returns itself. claims, when set, is a
// sentinel its own Is method reports a match for, as a hostile error claiming
// to be a skip would.
type foCycleOne struct{ claims error }

func (*foCycleOne) Error() string   { return firstOfPortErrSecret }
func (c *foCycleOne) Unwrap() error { return c }

func (c *foCycleOne) Is(target error) bool {
	return c.claims != nil && target == c.claims //nolint:errorlint // identity of a sentinel
}

// foCycleMany is an error whose Unwrap() []error lists claims, when set, and
// then itself. Without a claim it overflows a stdlib walk's stack; with one,
// stdlib errors.Is finds the claim first and never sees the cycle.
type foCycleMany struct{ claims error }

func (*foCycleMany) Error() string { return firstOfPortErrSecret }

func (c *foCycleMany) Unwrap() []error {
	if c.claims != nil {
		return []error{c.claims, c}
	}

	return []error{c}
}

// foUnwrapPanics is an error whose Unwrap panics with value.
type foUnwrapPanics struct{ value any }

func (foUnwrapPanics) Error() string   { return firstOfPortErrSecret }
func (p foUnwrapPanics) Unwrap() error { panic(p.value) }

// foTypedNil is returned as a nil pointer inside a non-nil error.
type foTypedNil struct{}

func (*foTypedNil) Error() string { return firstOfPortErrSecret }

// foFanOut joins leaf with itself depth times: no cycle, but 2^depth leaves.
func foFanOut(leaf error, depth int) error {
	node := leaf
	for range depth {
		node = errors.Join(node, node)
	}

	return node
}

// foOutcome is what one FirstOf.Authenticate produced, every classification
// taken inside the bound.
type foOutcome struct {
	authenticated bool
	same          bool // the error returned is the delegate's own value
	next          int  // how often the delegate after the failing one ran
	unsupported   bool
	noEligible    bool
	failed        bool
	unwalkable    bool
	quotes        bool // the returned error's text quotes the hostile error
}

// foRun offers a credential to a FirstOf whose first delegate fails with
// delegateErr and whose second would authenticate. It returns the outcome and
// the abort records slog.Default() received, and fails the test when the call
// or the checks of its error hang or let a panic escape.
func foRun(t *testing.T, ctx context.Context, delegateErr error) (foOutcome, []map[string]any) {
	t.Helper()

	return foRunShaped(t, ctx, delegateErr, false)
}

// foRunShaped is foRun, and with nested set the failing delegate sits inside a
// FirstOf of its own, which is the first delegate of the one being called.
func foRunShaped(t *testing.T, ctx context.Context, delegateErr error, nested bool) (foOutcome, []map[string]any) {
	t.Helper()

	defaults := defaultRecords(t)
	ctrl := gomock.NewController(t)
	who := principal(t)

	var next atomic.Int32

	failing := NewMockAuthenticator(ctrl)
	failing.EXPECT().Authenticate(gomock.Any(), gomock.Any()).Return(nil, delegateErr)

	granting := NewMockAuthenticator(ctrl)
	granting.EXPECT().Authenticate(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(context.Context, identity.Credentials) (*authenticate.Authentication, error) {
			next.Add(1)

			return &authenticate.Authentication{Principal: who}, nil
		})

	var first authenticate.Authenticator = failing

	if nested {
		inner, ierr := authenticate.NewFirstOf(failing)
		require.NoError(t, ierr)

		first = inner
	}

	m, err := authenticate.NewFirstOf(first, granting)
	require.NoError(t, err)

	type result struct {
		out      foOutcome
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

		a, aerr := m.Authenticate(ctx, identity.NewUsernamePassword("ada", []byte("guess")))
		r.out = foOutcome{
			authenticated: aerr == nil && a != nil,
			same:          aerr != nil && aerr == delegateErr, //nolint:errorlint // identity: returned unchanged
			next:          int(next.Load()),
			unsupported:   errors.Is(aerr, authenticate.ErrUnsupportedCredentials),
			noEligible:    errors.Is(aerr, authenticate.ErrNoEligibleAuthenticator),
			failed:        errors.Is(aerr, authenticate.ErrAuthenticationFailed),
			unwalkable:    errors.Is(aerr, porterr.ErrUnwalkable),
		}
		if aerr != nil {
			r.out.quotes = strings.Contains(aerr.Error(), firstOfPortErrSecret)
		}

		r.returned = true
	}()

	var r result

	select {
	case r = <-done:
		require.True(t, r.returned, "a hostile delegate error escaped as a panic: %v", r.value)
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a hostile delegate error hung FirstOf.Authenticate or the checks of its error")
	}

	var aborts []map[string]any

	for _, rec := range jsonRecords(t, defaults.Bytes()) {
		if rec["msg"] == msgPortErrAborted {
			aborts = append(aborts, rec)
		}
	}

	return r.out, aborts
}

// TestPortErrors_FirstOf pins that a delegate failing with an error whose
// chain cannot be walked stops the manager exactly as a plain outage of that
// delegate does: never a skip to the next delegate (which would let it
// authenticate), never ErrNoEligibleAuthenticator or a refusal the error
// merely claims, never a hang or a panic. It answers porterr.ErrUnwalkable in
// place of the delegate's error, and the sanitizer writes one abort record to
// slog.Default(), FirstOf holding no logger of its own.
func TestPortErrors_FirstOf(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(firstOfPortErrRowEnv)
	if only != "" {
		debug.SetMaxStack(64 << 20)
	}

	cancelled := func(ctx context.Context) context.Context {
		cctx, cancel := context.WithCancel(ctx)
		cancel()

		return cctx
	}

	// Each flow is the same chain, with the hostile error claiming one of the
	// two sentinels FirstOf reads as a skip.
	type flowCase struct {
		name   string
		claims error
	}

	flows := []flowCase{
		{name: "claiming unsupported credentials", claims: authenticate.ErrUnsupportedCredentials},
		{name: "claiming no eligible authenticator", claims: authenticate.ErrNoEligibleAuthenticator},
	}

	type testCase struct {
		name string
		err  func(claims error) error
		ctx  func(context.Context) context.Context
		// child runs the row in a child process: unsanitized, the stdlib walk
		// overflows the stack fatally.
		child  bool
		assert func(t *testing.T, plain, got foOutcome, aborts []map[string]any)
	}

	asOutage := func(reason string) func(t *testing.T, plain, got foOutcome, aborts []map[string]any) {
		return func(t *testing.T, plain, got foOutcome, aborts []map[string]any) {
			t.Helper()

			require.False(t, plain.authenticated, "precondition")
			require.True(t, plain.same, "precondition: a plain delegate error comes back as itself")
			require.Zero(t, plain.next, "precondition: an outage stops the manager")

			want := plain
			want.same = false
			want.unwalkable = true
			assert.Equal(t, want, got, "the hostile error takes the plain outage's branch")

			require.Len(t, aborts, 1, "one abort record, on slog.Default()")
			assert.Equal(t, "ERROR", aborts[0]["level"])
			assert.Equal(t, reason, aborts[0]["reason"])

			for k, v := range aborts[0] {
				s, _ := v.(string)
				assert.NotContains(t, s, firstOfPortErrSecret, "attribute %q quotes the delegate's error", k)
			}
		}
	}

	cases := []testCase{
		{
			name:   "self-cycle through Unwrap() error",
			err:    func(error) error { return &foCycleOne{} },
			assert: asOutage("budget"),
		},
		{
			name:   "self-cycle claiming the skip sentinel through Is",
			err:    func(c error) error { return &foCycleOne{claims: c} },
			assert: asOutage("budget"),
		},
		{
			name:  "Unwrap() []error cycle listing the skip sentinel first",
			err:   func(c error) error { return &foCycleMany{claims: c} },
			child: true, assert: asOutage("budget"),
		},
		{
			name:  "self-cycle through Unwrap() []error",
			err:   func(error) error { return &foCycleMany{} },
			child: true, assert: asOutage("budget"),
		},
		{
			name:   "fan-out with no cycle",
			err:    func(error) error { return foFanOut(errors.New(firstOfPortErrSecret), firstOfFanOutDepth) },
			assert: asOutage("budget"),
		},
		{
			name:   "fan-out whose leaves are the skip sentinel",
			err:    func(c error) error { return foFanOut(c, firstOfFanOutDepth) },
			assert: asOutage("budget"),
		},
		{
			name:   "panicking Unwrap",
			err:    func(error) error { return foUnwrapPanics{value: "boom " + firstOfPortErrSecret} },
			assert: asOutage("panic"),
		},
		{
			name:   "Unwrap panicking with nil",
			err:    func(error) error { return foUnwrapPanics{value: nil} },
			assert: asOutage("panic"),
		},
		{
			name:   "self-cycle claiming the skip sentinel on a cancelled context",
			err:    func(c error) error { return &foCycleOne{claims: c} },
			ctx:    cancelled,
			assert: asOutage("budget"),
		},
		{
			name: "a typed-nil root walks to the end and is answered as a plain error",
			err:  func(error) error { return (*foTypedNil)(nil) },
			assert: func(t *testing.T, plain, got foOutcome, aborts []map[string]any) {
				t.Helper()

				want := plain
				want.quotes = true // its own text, returned unchanged as a plain error is
				assert.Equal(t, want, got)
				assert.Empty(t, aborts, "a walk that completes writes nothing")
			},
		},
	}

	for _, fc := range flows {
		for _, tc := range cases {
			row := fc.name + "/" + tc.name
			if only != "" && (!tc.child || row != only) {
				continue
			}

			t.Run(row, func(t *testing.T) {
				if tc.child && only == "" {
					firstOfPortErrInChild(t, row)

					return
				}

				ctx := t.Context()
				if tc.ctx != nil {
					ctx = tc.ctx(ctx)
				}

				plain, plainAborts := foRun(t, ctx, errFirstOfDelegateDown)
				require.Empty(t, plainAborts, "a plain outage writes no abort record")

				got, aborts := foRun(t, ctx, tc.err(fc.claims))
				tc.assert(t, plain, got, aborts)

				announcePortErrRan(t, only, row)
			})
		}
	}
}

// TestPortErrors_FirstOf_Nested pins that a hostile delegate error inside a
// nested FirstOf stops the outer manager as well: the inner one sanitizes it
// into a fault matching porterr.ErrUnwalkable and no skip, the outer passes
// that fault through, the delegate after the nested one never runs, and the
// abort is recorded once, by the inner manager, not again by the outer.
//
// No row runs in a child process: the inner manager replaces the hostile
// chain before any stdlib walk meets it, and the sanitizer's own walk is
// bounded.
func TestPortErrors_FirstOf_Nested(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	type testCase struct {
		name   string
		err    error
		assert func(t *testing.T, got foOutcome, aborts []map[string]any)
	}

	stopped := func(reason string) func(t *testing.T, got foOutcome, aborts []map[string]any) {
		return func(t *testing.T, got foOutcome, aborts []map[string]any) {
			t.Helper()

			assert.Equal(t, foOutcome{unwalkable: true}, got,
				"the outer manager stops with the inner one's fault: no skip, no later delegate, no quote")

			require.Len(t, aborts, 1, "one abort record: the inner manager's, not a second by the outer")
			assert.Equal(t, "ERROR", aborts[0]["level"])
			assert.Equal(t, reason, aborts[0]["reason"])

			for k, v := range aborts[0] {
				s, _ := v.(string)
				assert.NotContains(t, s, firstOfPortErrSecret, "attribute %q quotes the delegate's error", k)
			}
		}
	}

	cases := []testCase{
		{
			name:   "self-cycle claiming unsupported credentials through Is",
			err:    &foCycleOne{claims: authenticate.ErrUnsupportedCredentials},
			assert: stopped("budget"),
		},
		{
			name:   "self-cycle claiming no eligible authenticator through Is",
			err:    &foCycleOne{claims: authenticate.ErrNoEligibleAuthenticator},
			assert: stopped("budget"),
		},
		{
			name:   "panicking Unwrap",
			err:    foUnwrapPanics{value: "boom " + firstOfPortErrSecret},
			assert: stopped("panic"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, aborts := foRunShaped(t, t.Context(), tc.err, true)
			tc.assert(t, got, aborts)
		})
	}
}

// firstOfPortErrInChild re-runs TestPortErrors_FirstOf in a child process
// limited to row, and fails unless it exits 0 within a minute and prints the
// row's marker as a whole line: a stack overflow is fatal and only a child can
// watch for one.
func firstOfPortErrInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPortErrors_FirstOf$", "-test.count=1")
	cmd.Env = append(os.Environ(), firstOfPortErrRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 12)], "\n"))
	requireChildRan(t, out, row)
}
