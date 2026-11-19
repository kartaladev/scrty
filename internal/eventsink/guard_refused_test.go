package eventsink_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/internal/errwalk"
	"github.com/kartaladev/scrty/internal/eventsink"
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

// selectiveIs matches matches through its own Is method, and panics when
// asked about panicsOn and nothing else.
type selectiveIs struct{ matches, panicsOn error }

func (selectiveIs) Error() string { return "selective" }

func (e selectiveIs) Is(target error) bool {
	if target == e.panicsOn { //nolint:errorlint // the identity of the target asked about
		panic("the link's Is panicked")
	}

	return target == e.matches //nolint:errorlint // the identity of the target asked about
}

// guardOutcome is what one GuardRefused call produced: the events it sent and
// the abort it returned.
type guardOutcome struct {
	events []event.Event
	abort  error
}

// TestGuardRefused_HostileErrors pins that GuardRefused's walk of the refusal
// is bounded and recovering: an error it cannot walk reports no event, with
// no hang and no escaped panic, and its abort is returned to the guard,
// unwrapped, so the guard's reporting rule can be applied. GuardRefused writes
// no record of its own. A denial is reported as before, and a request no sink
// watches walks nothing, reports nothing and returns no abort.
func TestGuardRefused_HostileErrors(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		err    error
		noSink bool
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, got guardOutcome)
	}

	quiet := func(t *testing.T, got guardOutcome) {
		t.Helper()
		assert.Empty(t, got.events)
		assert.NoError(t, got.abort)
	}

	aborted := func(reason string) func(t *testing.T, got guardOutcome) {
		return func(t *testing.T, got guardOutcome) {
			t.Helper()
			assert.Empty(t, got.events, "an aborted walk reports no event")
			require.Error(t, got.abort, "the abort is returned to the guard")
			assert.Equal(t, reason, errwalk.Reason(got.abort))
		}
	}

	ended := func(ctx context.Context) context.Context {
		cctx, cancel := context.WithCancel(ctx)
		cancel()

		return cctx
	}

	denialWithCycle := fmt.Errorf("%w: %w", authorize.ErrAccessDenied, &cycleOne{})
	panicsOnDenial := selectiveIs{matches: authorize.ErrAuthenticationRequired, panicsOn: authorize.ErrAccessDenied}
	panicsOnHangUp := selectiveIs{matches: authorize.ErrAccessDenied, panicsOn: context.Canceled}

	cases := []testCase{
		{name: "a cycle through Unwrap() error", err: &cycleOne{}, assert: aborted("budget")},
		{name: "a cycle through Unwrap() []error", err: &cycleMany{}, assert: aborted("budget")},
		{name: "a link whose Is panics", err: isPanics{}, assert: aborted("panic")},
		{name: "a link whose Is panics only for the denial", err: panicsOnDenial, assert: aborted("panic")},
		{name: "a denial joined with a cycle", err: denialWithCycle, assert: aborted("budget")},
		{
			name: "a denial joined with a cycle, the context ended", err: denialWithCycle, ctx: ended,
			assert: aborted("budget"),
		},
		{
			name: "a denial whose Is panics only for the hang-up check, the context ended", err: panicsOnHangUp, ctx: ended,
			assert: aborted("panic"),
		},
		{name: "a cycle on a request no sink watches", err: &cycleOne{}, noSink: true, assert: quiet},
		{
			name: "a denial, as before",
			err:  fmt.Errorf("%w: rule", authorize.ErrAccessDenied),
			assert: func(t *testing.T, got guardOutcome) {
				t.Helper()
				require.Len(t, got.events, 1)
				assert.Equal(t, event.AuthzFail, got.events[0].Name)
				assert.NoError(t, got.abort)
			},
		},
		{name: "a denial on an ended context, as before", err: authorize.ErrAccessDenied, ctx: ended, assert: func(t *testing.T, got guardOutcome) {
			t.Helper()
			require.Len(t, got.events, 1, "a denial unrelated to the context's end is still reported")
			assert.NoError(t, got.abort)
		}},
		{name: "another refusal, as before", err: authorize.ErrAuthenticationRequired, assert: quiet},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var (
				mu  sync.Mutex
				got guardOutcome
			)

			ctx := t.Context()
			if !tc.noSink {
				ctx = eventsink.With(ctx, func(_ context.Context, e event.Event) {
					mu.Lock()
					defer mu.Unlock()

					got.events = append(got.events, e)
				})
			}

			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			done := make(chan any, 1)

			go func() {
				returned := false

				defer func() {
					if !returned {
						done <- recover()
					}
				}()

				abort := eventsink.GuardRefused(ctx, tc.err)

				mu.Lock()
				got.abort = abort
				mu.Unlock()

				returned = true
				done <- nil
			}()

			select {
			case v := <-done:
				require.Nil(t, v, "a panic escaped GuardRefused")
			case <-time.After(2 * time.Second):
				t.Fatal("GuardRefused did not return within 2s")
			}

			mu.Lock()
			defer mu.Unlock()

			tc.assert(t, got)
		})
	}
}
