package ctxlog_test

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/internal/ctxlog"
)

// keyAnswerer is a context that answers ctxlog.Key from its own Value method,
// as a chain's run context does, without storing it under the key.
type keyAnswerer struct {
	context.Context //nolint:containedctx // the test context wraps its parent

	logger any
}

func (k keyAnswerer) Value(key any) any {
	if _, ok := key.(ctxlog.Key); ok {
		return k.logger
	}

	return k.Context.Value(key)
}

func TestFrom(t *testing.T) {
	t.Parallel()

	outer := slog.New(slog.NewTextHandler(io.Discard, nil))
	inner := slog.New(slog.NewTextHandler(io.Discard, nil))

	type testCase struct {
		name   string
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, got *slog.Logger)
	}

	cases := []testCase{
		{
			name: "a context carrying nothing answers nil",
			assert: func(t *testing.T, got *slog.Logger) {
				assert.Nil(t, got)
			},
		},
		{
			name: "a context carrying a logger answers it",
			ctx: func(ctx context.Context) context.Context {
				return ctxlog.With(ctx, outer)
			},
			assert: func(t *testing.T, got *slog.Logger) {
				assert.Same(t, outer, got)
			},
		},
		{
			name: "the nearest logger wins",
			ctx: func(ctx context.Context) context.Context {
				return ctxlog.With(ctxlog.With(ctx, outer), inner)
			},
			assert: func(t *testing.T, got *slog.Logger) {
				assert.Same(t, inner, got)
			},
		},
		{
			name: "a nil logger is ignored, keeping the one already carried",
			ctx: func(ctx context.Context) context.Context {
				return ctxlog.With(ctxlog.With(ctx, outer), nil)
			},
			assert: func(t *testing.T, got *slog.Logger) {
				assert.Same(t, outer, got)
			},
		},
		{
			name: "a nil context answers nil",
			ctx: func(context.Context) context.Context {
				return nil
			},
			assert: func(t *testing.T, got *slog.Logger) {
				assert.Nil(t, got)
			},
		},
		{
			name: "a context answering the key from its own Value is read",
			ctx: func(ctx context.Context) context.Context {
				return keyAnswerer{Context: ctx, logger: inner}
			},
			assert: func(t *testing.T, got *slog.Logger) {
				assert.Same(t, inner, got)
			},
		},
		{
			name: "a value of another type under the key answers nil",
			ctx: func(ctx context.Context) context.Context {
				return keyAnswerer{Context: ctx, logger: "not a logger"}
			},
			assert: func(t *testing.T, got *slog.Logger) {
				assert.Nil(t, got)
			},
		},
		{
			name: "a typed-nil logger under the key answers nil",
			ctx: func(ctx context.Context) context.Context {
				return keyAnswerer{Context: ctx, logger: (*slog.Logger)(nil)}
			},
			assert: func(t *testing.T, got *slog.Logger) {
				assert.Nil(t, got)
			},
		},
		{
			name: "a cancelled context still answers its logger",
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctxlog.With(ctx, outer))
				cancel()

				return cctx
			},
			assert: func(t *testing.T, got *slog.Logger) {
				assert.Same(t, outer, got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			tc.assert(t, ctxlog.From(ctx))
		})
	}
}
