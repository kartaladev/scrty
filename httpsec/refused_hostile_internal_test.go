package httpsec

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authorize"
)

// refusedCycle contains itself through Unwrap() error.
type refusedCycle struct{}

func (*refusedCycle) Error() string   { return "cycle" }
func (c *refusedCycle) Unwrap() error { return c }

// refusedCycleMany contains itself through Unwrap() []error.
type refusedCycleMany struct{}

func (*refusedCycleMany) Error() string     { return "cycle many" }
func (c *refusedCycleMany) Unwrap() []error { return []error{c} }

// refusedIsPanics is a link whose own Is method panics.
type refusedIsPanics struct{}

func (refusedIsPanics) Error() string { return "is panics" }
func (refusedIsPanics) Is(error) bool { panic("the link's Is panicked") }

// TestRefused_HostileErrors pins that refused, which an event site asks
// about a consumer's error before any lookup answers it (a password change
// function's, a per-request policy's, a second factor's), reads it through
// the bounded walk: an error the walk gives up on is no refusal, with no hang
// and no escaped panic, and every other error is judged as before.
func TestRefused_HostileErrors(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		err    error
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, got bool)
	}

	notRefused := func(t *testing.T, got bool) {
		t.Helper()
		assert.False(t, got)
	}

	ended := func(ctx context.Context) context.Context {
		cctx, cancel := context.WithCancel(ctx)
		cancel()

		return cctx
	}

	cases := []testCase{
		{name: "a cycle through Unwrap() error", err: &refusedCycle{}, assert: notRefused},
		{name: "a cycle through Unwrap() []error", err: &refusedCycleMany{}, assert: notRefused},
		{name: "a link whose Is panics", err: refusedIsPanics{}, assert: notRefused},
		{name: "a cycle, the context ended", err: &refusedCycle{}, ctx: ended, assert: notRefused},
		{
			name: "a denial, as before",
			err:  fmt.Errorf("%w: rule", authorize.ErrAccessDenied),
			assert: func(t *testing.T, got bool) {
				t.Helper()
				assert.True(t, got)
			},
		},
		{name: "the user store's outage, as before", err: authenticate.ErrUnavailable, assert: notRefused},
		{name: "an unrecognised error, as before", err: errors.New("db down"), assert: notRefused},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			type result struct {
				got      bool
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

				got := refused(ctx, nil, tc.err)
				returned = true
				done <- result{got: got}
			}()

			select {
			case r := <-done:
				require.False(t, r.panicked, "a panic escaped refused: %v", r.value)
				tc.assert(t, r.got)
			case <-time.After(2 * time.Second):
				t.Fatal("refused did not return within 2s")
			}
		})
	}
}
