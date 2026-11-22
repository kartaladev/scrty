package porterr_test

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/ctxlog"
	"github.com/kartaladev/scrty/internal/errwalk"
	"github.com/kartaladev/scrty/internal/porterr"
)

// abortOf returns the abort errwalk's walk of err stops with.
func abortOf(t *testing.T, err error) error {
	t.Helper()

	_, abort := errwalk.Flatten(err)
	require.Error(t, abort, "the walk of %T did not abort", err)

	return abort
}

// TestReportAbort pins the one record of an aborted walk, written by every
// abort reporter in the library: Error level, the constant message, the
// reason, and for a panic its redacted attributes, never the error's text or
// the panic's value. A nil logger resolves as a routing logger does.
//
// It is not parallel: it swaps slog.Default(), which is process-wide.
//
//nolint:paralleltest // see above
func TestReportAbort(t *testing.T) {
	type sinks struct{ given, def *recorder }

	type testCase struct {
		name   string
		abort  func(t *testing.T) error
		ctx    func(ctx context.Context, s sinks) context.Context
		logger func(s sinks) *slog.Logger // nil means the given recorder
		extra  []slog.Attr
		assert func(t *testing.T, s sinks)
	}

	oneRecord := func(t *testing.T, recs []slog.Record, reason string) slog.Record {
		t.Helper()

		require.Len(t, recs, 1)

		rec := recs[0]
		assert.Equal(t, slog.LevelError, rec.Level)
		assert.Equal(t, porterr.MsgClassificationAborted, rec.Message)
		assert.Equal(t, reason, attrsOf(rec)["reason"])
		assert.NotContains(t, rendered(t, rec), secret)

		return rec
	}

	cases := []testCase{
		{
			name:  "budget",
			abort: func(t *testing.T) error { return abortOf(t, &cycleOne{}) },
			assert: func(t *testing.T, s sinks) {
				rec := oneRecord(t, s.given.all(), "budget")
				assert.NotContains(t, attrsOf(rec), "panic_type")
				assert.Empty(t, s.def.all())
			},
		},
		{
			name:  "panic",
			abort: func(t *testing.T) error { return abortOf(t, panicUnwrap{}) },
			assert: func(t *testing.T, s sinks) {
				rec := oneRecord(t, s.given.all(), "panic")
				assert.Greater(t, rec.NumAttrs(), 1, "the panic's redacted attributes are missing")
				assert.Empty(t, s.def.all())
			},
		},
		{
			name:  "panic(nil)",
			abort: func(t *testing.T) error { return abortOf(t, panicNilUnwrap{}) },
			assert: func(t *testing.T, s sinks) {
				oneRecord(t, s.given.all(), "panic")
				assert.Empty(t, s.def.all())
			},
		},
		{
			name:  "extra attributes follow the abort's",
			abort: func(t *testing.T) error { return abortOf(t, panicUnwrap{}) },
			extra: []slog.Attr{slog.Int("suppressed", 3)},
			assert: func(t *testing.T, s sinks) {
				rec := oneRecord(t, s.given.all(), "panic")

				var last slog.Attr

				rec.Attrs(func(a slog.Attr) bool {
					last = a

					return true
				})
				assert.Equal(t, "suppressed", last.Key, "the extra attribute is not the record's last")
				assert.Equal(t, int64(3), last.Value.Int64())
			},
		},
		{
			name:  "a nil logger writes to the chain logger the context carries",
			abort: func(t *testing.T) error { return abortOf(t, &cycleOne{}) },
			ctx: func(ctx context.Context, s sinks) context.Context {
				return ctxlog.With(ctx, slog.New(s.given))
			},
			logger: func(sinks) *slog.Logger { return nil },
			assert: func(t *testing.T, s sinks) {
				oneRecord(t, s.given.all(), "budget")
				assert.Empty(t, s.def.all())
			},
		},
		{
			name:   "a nil logger with no chain writes to slog.Default() at record time",
			abort:  func(t *testing.T) error { return abortOf(t, &cycleOne{}) },
			logger: func(sinks) *slog.Logger { return nil },
			assert: func(t *testing.T, s sinks) {
				oneRecord(t, s.def.all(), "budget")
				assert.Empty(t, s.given.all())
			},
		},
		{
			name:  "a nil context does not panic",
			abort: func(t *testing.T) error { return abortOf(t, &cycleOne{}) },
			ctx:   func(context.Context, sinks) context.Context { return nil },
			assert: func(t *testing.T, s sinks) {
				oneRecord(t, s.given.all(), "budget")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := sinks{given: new(recorder), def: recording(t)}

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx, s)
			}

			logger := slog.New(s.given)
			if tc.logger != nil {
				logger = tc.logger(s)
			}

			abort := tc.abort(t)

			require.NotPanics(t, func() { porterr.ReportAbort(ctx, logger, abort, tc.extra...) })
			tc.assert(t, s)
		})
	}
}
