package lifecycle_test

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/lifecycle"
)

func TestAwait(t *testing.T) {
	t.Parallel()

	// closed returns a channel that is already closed.
	closed := func() <-chan struct{} {
		ch := make(chan struct{})
		close(ch)

		return ch
	}

	type testCase struct {
		name string
		// done builds the channel Await waits on; a case that closes it later
		// does so from a goroutine of its own.
		done   func() <-chan struct{}
		ctx    func(ctx context.Context) context.Context // nil means identity
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name: "done already closed with ctx already done gives nil",
			done: closed,
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			assert: func(t *testing.T, err error) {
				require.NoError(t, err, "completion wins a tie")
			},
		},
		{
			name: "ctx ends first gives its error",
			done: func() <-chan struct{} { return make(chan struct{}) },
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
				context.AfterFunc(cctx, cancel)

				return cctx
			},
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, context.DeadlineExceeded)
			},
		},
		{
			name: "done closes first gives nil",
			done: func() <-chan struct{} {
				ch := make(chan struct{})
				time.AfterFunc(100*time.Millisecond, func() { close(ch) })

				return ch
			},
			assert: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// A bubble makes the timed cases exact, and lets the tie case
			// repeat until a select left to pick at random would have lost it.
			synctest.Test(t, func(t *testing.T) {
				for range 100 {
					ctx := t.Context()
					if tc.ctx != nil {
						ctx = tc.ctx(ctx)
					}

					start := time.Now()
					err := lifecycle.Await(ctx, tc.done())
					tc.assert(t, err)
					assert.LessOrEqual(t, time.Since(start), 100*time.Millisecond,
						"Await returns as soon as one side is ready")
				}
			})
		})
	}
}
