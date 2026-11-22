package hangup_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/errwalk"
	"github.com/kartaladev/scrty/internal/hangup"
)

// cycleOne contains itself through Unwrap() error.
type cycleOne struct{}

func (*cycleOne) Error() string   { return "cycle one" }
func (c *cycleOne) Unwrap() error { return c }

// cycleMany contains itself through Unwrap() []error.
type cycleMany struct{}

func (*cycleMany) Error() string     { return "cycle many" }
func (c *cycleMany) Unwrap() []error { return []error{c} }

// isPanics is a link whose own Is method panics.
type isPanics struct{}

func (isPanics) Error() string { return "is panics" }
func (isPanics) Is(error) bool { panic("the link's Is panicked") }

// selectiveIs panics when its own Is method is asked about panicsOn, and
// matches nothing else.
type selectiveIs struct{ panicsOn error }

func (selectiveIs) Error() string { return "selective" }

func (e selectiveIs) Is(target error) bool {
	if target == e.panicsOn { //nolint:errorlint // the identity of the target asked about
		panic("the link's Is panicked")
	}

	return false
}

// walked is what one call of ByCallerWalk returned, and what ByCaller said of
// the same error.
type walked struct {
	hungUp   bool
	abort    error
	byCaller bool
}

// byCallerWithin runs ByCallerWalk and ByCaller on their own goroutine and
// fails the test when they do not return within two seconds or let a panic
// escape. A stack overflow still kills the process, which nothing can recover.
func byCallerWithin(ctx context.Context, t *testing.T, err error) walked {
	t.Helper()

	type result struct {
		got      walked
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

		var got walked
		got.hungUp, got.abort = hangup.ByCallerWalk(ctx, err)
		got.byCaller = hangup.ByCaller(ctx, err)
		returned = true
		done <- result{got: got}
	}()

	select {
	case r := <-done:
		require.False(t, r.panicked, "a panic escaped ByCaller: %v", r.value)

		return r.got
	case <-time.After(2 * time.Second):
		t.Fatal("ByCaller did not return within 2s")

		return walked{}
	}
}

// TestByCaller_HostileErrors pins that ByCaller's walk of err is bounded and
// recovering: on an ended context, an error it cannot walk is not a hang-up,
// so the caller treats it as the failure it may be, and the context's own
// error is still told as one. ByCallerWalk gives the same answer and also
// returns the abort, with its reason, so a caller that can report it does;
// a live context walks nothing and returns no abort.
func TestByCaller_HostileErrors(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		err    func(ctx context.Context) error
		live   bool
		assert func(t *testing.T, got walked)
	}

	aborted := func(reason string) func(t *testing.T, got walked) {
		return func(t *testing.T, got walked) {
			t.Helper()
			assert.False(t, got.hungUp, "an error that could not be walked was told as a hang-up")
			assert.False(t, got.byCaller, "ByCaller told an error that could not be walked as a hang-up")
			require.Error(t, got.abort, "the walk's abort was not returned")
			assert.Equal(t, reason, errwalk.Reason(got.abort))
		}
	}

	cases := []testCase{
		{name: "a cycle through Unwrap() error", err: func(context.Context) error { return &cycleOne{} }, assert: aborted("budget")},
		{name: "a cycle through Unwrap() []error", err: func(context.Context) error { return &cycleMany{} }, assert: aborted("budget")},
		{name: "a link whose Is panics", err: func(context.Context) error { return isPanics{} }, assert: aborted("panic")},
		{
			name:   "a link whose Is panics only for the context's error",
			err:    func(context.Context) error { return selectiveIs{panicsOn: context.Canceled} },
			assert: aborted("panic"),
		},
		{
			name: "the context's own error joined with a cycle",
			err: func(ctx context.Context) error {
				return fmt.Errorf("db: %w: %w", ctx.Err(), &cycleOne{})
			},
			assert: aborted("budget"),
		},
		{
			name: "a cycle on a live context, which walks nothing",
			err:  func(context.Context) error { return &cycleOne{} },
			live: true,
			assert: func(t *testing.T, got walked) {
				t.Helper()
				assert.False(t, got.hungUp)
				assert.False(t, got.byCaller)
				assert.NoError(t, got.abort)
			},
		},
		{
			name: "the context's own error, as before",
			err:  func(ctx context.Context) error { return fmt.Errorf("db: %w", ctx.Err()) },
			assert: func(t *testing.T, got walked) {
				t.Helper()
				assert.True(t, got.hungUp)
				assert.True(t, got.byCaller)
				assert.NoError(t, got.abort)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if !tc.live {
				cctx, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cctx
			}

			tc.assert(t, byCallerWithin(ctx, t, tc.err(ctx)))
		})
	}
}
