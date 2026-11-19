package guardauth_test

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/errwalk"
	"github.com/kartaladev/scrty/internal/guardauth"
)

// headers is a HeaderWriter over an http.Header.
type headers http.Header

func (h headers) SetHeader(name, value string) { http.Header(h).Set(name, value) }
func (h headers) AddHeader(name, value string) { http.Header(h).Add(name, value) }

func TestChallenge(t *testing.T) {
	t.Parallel()

	errRefused := errors.New("refused")
	errReplaced := errors.New("the challenge could not be set")
	_, budget := errwalk.Flatten(&cycle{})

	type testCase struct {
		name   string
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, h http.Header, err, abort error)
	}

	cases := []testCase{
		{
			name: "nothing published: the refusal unchanged, no header, no abort",
			assert: func(t *testing.T, h http.Header, err, abort error) {
				require.ErrorIs(t, err, errRefused)
				assert.Empty(t, h)
				assert.NoError(t, abort)
			},
		},
		{
			name: "the challenger's abort is returned to the guard",
			ctx: func(ctx context.Context) context.Context {
				return guardauth.WithChallenger(ctx,
					func(_ context.Context, _ guardauth.HeaderWriter, err error) (out, abort error) {
						return err, budget
					})
			},
			assert: func(t *testing.T, h http.Header, err, abort error) {
				require.ErrorIs(t, err, errRefused)
				assert.Empty(t, h)
				assert.Equal(t, budget, abort, "the abort value itself, unwrapped")
			},
		},
		{
			name: "the published challenger sets its challenge",
			ctx: func(ctx context.Context) context.Context {
				return guardauth.WithChallenger(ctx,
					func(_ context.Context, w guardauth.HeaderWriter, err error) (out, abort error) {
						w.AddHeader("WWW-Authenticate", "DPoP")

						return err, nil
					})
			},
			assert: func(t *testing.T, h http.Header, err, abort error) {
				require.ErrorIs(t, err, errRefused)
				assert.Equal(t, []string{"DPoP"}, h.Values("WWW-Authenticate"))
				assert.NoError(t, abort)
			},
		},
		{
			name: "the challenger's error replaces the refusal",
			ctx: func(ctx context.Context) context.Context {
				return guardauth.WithChallenger(ctx,
					func(context.Context, guardauth.HeaderWriter, error) (out, abort error) { return errReplaced, nil })
			},
			assert: func(t *testing.T, _ http.Header, err, _ error) {
				require.ErrorIs(t, err, errReplaced)
			},
		},
		{
			name: "a nil challenger is nothing published",
			ctx: func(ctx context.Context) context.Context {
				return guardauth.WithChallenger(ctx, nil)
			},
			assert: func(t *testing.T, h http.Header, err, abort error) {
				require.ErrorIs(t, err, errRefused)
				assert.Empty(t, h)
				assert.NoError(t, abort)
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

			h := http.Header{}
			err, abort := guardauth.Challenge(ctx, headers(h), errRefused)
			tc.assert(t, h, err, abort)
		})
	}
}

// cycle contains itself through Unwrap() error.
type cycle struct{}

func (*cycle) Error() string   { return "cycle" }
func (c *cycle) Unwrap() error { return c }

// panicsUnwrap is a link whose Unwrap method panics.
type panicsUnwrap struct{}

func (panicsUnwrap) Error() string { return "panics" }
func (panicsUnwrap) Unwrap() error { panic("the link's Unwrap panicked") }

func TestLookupAborts(t *testing.T) {
	t.Parallel()

	errRefused := errors.New("refused")
	_, budget := errwalk.Flatten(&cycle{})

	type testCase struct {
		name   string
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, aborts bool, asked []error)
	}

	publishing := func(abort error, asked *[]error) func(ctx context.Context) context.Context {
		return func(ctx context.Context) context.Context {
			var lookup guardauth.Lookup = func(err error) error {
				*asked = append(*asked, err)

				return abort
			}

			return context.WithValue(ctx, guardauth.LookupKey{}, lookup)
		}
	}

	var askedAborting, askedPassing []error

	cases := []testCase{
		{
			name: "no chain lookup: false, so the guard reports what it met",
			assert: func(t *testing.T, aborts bool, _ []error) {
				assert.False(t, aborts)
			},
		},
		{
			name: "a chain lookup that aborts: true",
			ctx:  publishing(budget, &askedAborting),
			assert: func(t *testing.T, aborts bool, _ []error) {
				assert.True(t, aborts)
				assert.Equal(t, []error{errRefused}, askedAborting, "the lookup is asked about the refusal")
			},
		},
		{
			name: "a chain lookup that completes: false",
			ctx:  publishing(nil, &askedPassing),
			assert: func(t *testing.T, aborts bool, _ []error) {
				assert.False(t, aborts)
				assert.Equal(t, []error{errRefused}, askedPassing)
			},
		},
		{
			name: "a nil lookup is no lookup",
			ctx: func(ctx context.Context) context.Context {
				return context.WithValue(ctx, guardauth.LookupKey{}, guardauth.Lookup(nil))
			},
			assert: func(t *testing.T, aborts bool, _ []error) {
				assert.False(t, aborts)
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

			tc.assert(t, guardauth.LookupAborts(ctx, errRefused), nil)
		})
	}
}

// records keeps the records written to it.
type records struct {
	mu   sync.Mutex
	recs []slog.Record
}

func (h *records) Enabled(context.Context, slog.Level) bool { return true }
func (h *records) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h *records) WithGroup(string) slog.Handler            { return h }

func (h *records) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.recs = append(h.recs, r)

	return nil
}

// TestReportAbort pins the record a guard writes for an abort it reports: one
// Error record on slog.Default(), with the constant message, the reason and,
// for a panic, the panic's type and frames, never the error's text.
//
// It replaces slog.Default(), so it does not run in parallel.
func TestReportAbort(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	_, budget := errwalk.Flatten(&cycle{})
	_, panicked := errwalk.Flatten(panicsUnwrap{})

	type testCase struct {
		name   string
		abort  error
		assert func(t *testing.T, attrs map[string]string)
	}

	cases := []testCase{
		{
			name:  "a budget abort names its reason",
			abort: budget,
			assert: func(t *testing.T, attrs map[string]string) {
				assert.Equal(t, map[string]string{"reason": "budget"}, attrs)
			},
		},
		{
			name:  "a panic abort names its reason and the panic's type and frames",
			abort: panicked,
			assert: func(t *testing.T, attrs map[string]string) {
				assert.Equal(t, "panic", attrs["reason"])
				assert.Contains(t, attrs, "panic_type")
				assert.Contains(t, attrs, "frames")
				assert.NotContains(t, attrs["panic_type"], "the link's Unwrap panicked", "never the panic's value")
			},
		},
	}

	for _, tc := range cases { //nolint:paralleltest // it replaces slog.Default()
		t.Run(tc.name, func(t *testing.T) {
			logs := &records{}
			prev := slog.Default()
			slog.SetDefault(slog.New(logs))
			t.Cleanup(func() { slog.SetDefault(prev) })

			guardauth.ReportAbort(t.Context(), tc.abort)

			logs.mu.Lock()
			defer logs.mu.Unlock()

			require.Len(t, logs.recs, 1)
			assert.Equal(t, slog.LevelError, logs.recs[0].Level)
			assert.Equal(t, guardauth.MsgClassificationAborted, logs.recs[0].Message)

			attrs := map[string]string{}
			logs.recs[0].Attrs(func(a slog.Attr) bool {
				attrs[a.Key] = a.Value.String()

				return true
			})

			tc.assert(t, attrs)
		})
	}
}
