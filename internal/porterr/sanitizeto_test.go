package porterr_test

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/porterr"
)

type ctxKey struct{}

// ctxRecorder is a handler that reads a value from the context it is handed,
// as a consumer's request-aware handler does, and keeps every record with it.
type ctxRecorder struct{ recorder }

func (r *ctxRecorder) Handle(ctx context.Context, rec slog.Record) error {
	if v, ok := ctx.Value(ctxKey{}).(string); ok {
		rec.AddAttrs(slog.String("request_id", v))
	}

	return r.recorder.Handle(ctx, rec)
}

// panickingHandler panics on every record, as a consumer's broken handler may.
type panickingHandler struct{ recorder }

func (*panickingHandler) Handle(context.Context, slog.Record) error {
	panic("test: the handler panicked")
}

// TestSanitizeTo pins that SanitizeTo is Sanitize with the abort record's
// destination chosen by the caller: the one record goes to the given logger,
// with the given context, and none goes to slog.Default(). A nil logger is the
// default logger, a nil context is context.Background(), and a walk that
// completes writes nothing anywhere.
//
// It is not parallel: it swaps slog.Default(), which is process-wide, and
// testing.AllocsPerRun counts every allocation in the process.
//
//nolint:paralleltest // see above
func TestSanitizeTo(t *testing.T) {
	type outcome struct {
		got      error
		panicked bool
		value    any
		given    *ctxRecorder // what the given logger saw
		def      *ctxRecorder // what slog.Default() saw
	}

	type testCase struct {
		name      string
		err       func() error
		ctx       func(ctx context.Context) context.Context // nil means a context carrying the request id
		nilCtx    bool
		nilLogger bool
		handler   slog.Handler // nil means the given recorder
		assert    func(t *testing.T, out outcome)
	}

	cancelled := func(ctx context.Context) context.Context {
		cctx, cancel := context.WithCancel(ctx)
		cancel()

		return cctx
	}

	oneOnGiven := func(t *testing.T, out outcome) {
		t.Helper()
		require.False(t, out.panicked, "SanitizeTo panicked: %v", out.value)

		_, ok := out.got.(*porterr.Fault) //nolint:errorlint // the exact value returned
		require.True(t, ok, "got %T, want *porterr.Fault", out.got)
		require.Len(t, out.given.all(), 1)
		assert.Empty(t, out.def.all(), "the record went to slog.Default()")
		assert.Equal(t, porterr.MsgClassificationAborted, out.given.all()[0].Message)
	}

	cases := []testCase{
		{
			name: "an aborting error writes one record to the given logger and none to the default",
			err:  func() error { return &cycleOne{} },
			assert: func(t *testing.T, out outcome) {
				oneOnGiven(t, out)
				assert.Equal(t, "req-1", attrsOf(out.given.all()[0])["request_id"], "the record did not carry the context's attribute")
			},
		},
		{
			name:      "a nil logger writes the one record to slog.Default()",
			err:       func() error { return &cycleOne{} },
			nilLogger: true,
			assert: func(t *testing.T, out outcome) {
				require.False(t, out.panicked, "SanitizeTo panicked: %v", out.value)
				assert.Empty(t, out.given.all())
				require.Len(t, out.def.all(), 1)
				assert.Equal(t, "req-1", attrsOf(out.def.all()[0])["request_id"], "the default logger's handler was not handed the context")
			},
		},
		{
			name: "a walkable error writes nothing anywhere",
			err:  func() error { return fmt.Errorf("store: %w", errUnavailable) },
			assert: func(t *testing.T, out outcome) {
				require.False(t, out.panicked)
				assert.Empty(t, out.given.all())
				assert.Empty(t, out.def.all())
			},
		},
		{
			name:   "a nil context does not panic and still writes one record",
			err:    func() error { return &cycleOne{} },
			nilCtx: true,
			assert: func(t *testing.T, out outcome) {
				oneOnGiven(t, out)
				assert.NotContains(t, attrsOf(out.given.all()[0]), "request_id")
			},
		},
		{
			name: "a cancelled context still writes the record, with the context's attribute",
			err:  func() error { return &cycleOne{} },
			ctx:  cancelled,
			assert: func(t *testing.T, out outcome) {
				oneOnGiven(t, out)
				assert.Equal(t, "req-1", attrsOf(out.given.all()[0])["request_id"])
			},
		},
		{
			name:    "a handler that panics is the consumer's: the panic escapes (accepted)",
			err:     func() error { return &cycleOne{} },
			handler: new(panickingHandler),
			assert: func(t *testing.T, out outcome) {
				assert.True(t, out.panicked, "the handler's panic was swallowed")
				assert.Empty(t, out.def.all())
			},
		},
		{
			name: "a walkable short chain allocates nothing",
			err:  func() error { return fmt.Errorf("a: %w", fmt.Errorf("b: %w", &plainError{})) },
			assert: func(t *testing.T, _ outcome) {
				in := fmt.Errorf("a: %w", fmt.Errorf("b: %w", &plainError{}))
				logger := slog.New(new(ctxRecorder))
				ctx := t.Context()

				allocs := testing.AllocsPerRun(1000, func() {
					_ = porterr.SanitizeTo(ctx, logger, in, errUnavailable)
				})
				assert.Zero(t, allocs, "SanitizeTo allocated for a chain that fits its buffer")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := outcome{given: new(ctxRecorder), def: new(ctxRecorder)}

			prev := slog.Default()
			slog.SetDefault(slog.New(out.def))
			t.Cleanup(func() { slog.SetDefault(prev) })

			ctx := context.WithValue(t.Context(), ctxKey{}, "req-1")
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			if tc.nilCtx {
				ctx = nil //nolint:staticcheck // the row hands SanitizeTo a nil context on purpose
			}

			var logger *slog.Logger

			switch {
			case tc.nilLogger:
			case tc.handler != nil:
				logger = slog.New(tc.handler)
			default:
				logger = slog.New(out.given)
			}

			in := tc.err()

			func() {
				defer func() {
					if out.panicked {
						out.value = recover()
					}
				}()

				out.panicked = true
				out.got = porterr.SanitizeTo(ctx, logger, in, errUnavailable)
				out.panicked = false
			}()

			tc.assert(t, out)
		})
	}
}

// TestSanitizeTo_NilUnavailable pins that a nil unavailable sentinel panics on
// every call of SanitizeTo, as it does for Sanitize, a nil error included.
func TestSanitizeTo_NilUnavailable(t *testing.T) {
	t.Parallel()

	assert.Panics(t, func() { _ = porterr.SanitizeTo(t.Context(), slog.New(slog.DiscardHandler), nil, nil) })
}

// TestSanitizeTo_Concurrent pins that SanitizeTo keeps no state: concurrent
// calls on one logger each write their own record. Run it with -race.
func TestSanitizeTo_Concurrent(t *testing.T) {
	t.Parallel()

	const workers, calls = 8, 50

	rec := new(ctxRecorder)
	logger := slog.New(rec)

	var wg sync.WaitGroup

	for range workers {
		wg.Go(func() {
			for range calls {
				_ = porterr.SanitizeTo(t.Context(), logger, &cycleOne{}, errUnavailable)
			}
		})
	}

	wg.Wait()

	assert.Len(t, rec.all(), workers*calls)
}
