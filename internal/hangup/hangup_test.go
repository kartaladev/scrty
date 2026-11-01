package hangup_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/internal/hangup"
)

// errClientGone is the cause a caller cancels its context with.
var errClientGone = errors.New("test: the client closed its connection")

// TestByCaller pins that a hang-up is the caller's own context having ended
// with err matching that context's error or the cause it was cancelled with,
// and nothing else: not a live context's error, and not an error unrelated to
// the context's end.
func TestByCaller(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// ctx modifies the caller's context; nil leaves it live.
		ctx func(t *testing.T, ctx context.Context) context.Context

		// err is the error the dependency returned, given the caller's context.
		err func(ctx context.Context) error

		assert func(t *testing.T, got bool)
	}

	cancelled := func(cause error) func(*testing.T, context.Context) context.Context {
		return func(_ *testing.T, ctx context.Context) context.Context {
			cctx, cancel := context.WithCancelCause(ctx)
			cancel(cause)

			return cctx
		}
	}

	isHangUp := func(t *testing.T, got bool) {
		t.Helper()
		assert.True(t, got, "a caller that left was not told as a hang-up")
	}
	isNotHangUp := func(t *testing.T, got bool) {
		t.Helper()
		assert.False(t, got, "a failure was told as a hang-up")
	}

	cases := []testCase{
		{
			name: "a live context, with a dependency that met a deadline of its own",
			err: func(context.Context) error {
				return fmt.Errorf("db: %w", context.DeadlineExceeded)
			},
			assert: isNotHangUp,
		},
		{
			name: "a cancelled context, with err its Canceled",
			ctx:  cancelled(nil),
			err: func(ctx context.Context) error {
				return fmt.Errorf("db: %w", ctx.Err())
			},
			assert: isHangUp,
		},
		{
			name: "a context cancelled with a cause, with err that cause",
			ctx:  cancelled(errClientGone),
			err: func(ctx context.Context) error {
				return fmt.Errorf("db: %w", context.Cause(ctx))
			},
			assert: isHangUp,
		},
		{
			name: "a cancelled context, with an unrelated err",
			ctx:  cancelled(errClientGone),
			err: func(context.Context) error {
				return errors.New("db: connection refused")
			},
			assert: isNotHangUp,
		},
		{
			name: "an expired deadline, with err its DeadlineExceeded",
			ctx: func(t *testing.T, ctx context.Context) context.Context {
				t.Helper()

				cctx, cancel := context.WithDeadline(ctx, time.Now().Add(-time.Second))
				t.Cleanup(cancel)

				return cctx
			},
			err: func(ctx context.Context) error {
				return fmt.Errorf("db: %w", ctx.Err())
			},
			assert: isHangUp,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(t, ctx)
			}

			tc.assert(t, hangup.ByCaller(ctx, tc.err(ctx)))
		})
	}
}
