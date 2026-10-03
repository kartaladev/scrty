package unavailable_test

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/internal/unavailable"
	"github.com/kartaladev/scrty/ratelimit"
)

// TestMain fails the package if any test leaves a goroutine behind. The
// decorator starts none of its own; this is what shows it.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

const (
	testNamespace = "mfa-verify"
	testLimit     = 3
	testWindow    = time.Minute
	testKey       = "k"
	otherKey      = "other"

	defaultTimeout  = 250 * time.Millisecond
	defaultInterval = time.Second
)

// epoch is where every fake clock starts, so the times a failing case prints
// are readable.
var epoch = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

// errDown stands for any backend failure: a refused connection, a timeout, an
// exhausted pool.
var errDown = errors.New("dial tcp 10.0.0.1:6379: connection refused")

// harness is one wrapped limiter over a mock backend, with the fake clock its
// breaker and hold set read, and the records it logged.
type harness struct {
	backend *MockLimiter
	clock   *clockwork.FakeClock
	logs    *recorder
	limiter ratelimit.Limiter
}

func newHarness(t *testing.T, mode ratelimit.UnavailableMode) *harness {
	t.Helper()

	return newHarnessWith(t, mode, nil)
}

// newHarnessWith is newHarness with edit applied to the configuration last, so
// a case can override a default the harness would otherwise set.
func newHarnessWith(t *testing.T, mode ratelimit.UnavailableMode, edit func(cfg *unavailable.Config)) *harness {
	t.Helper()

	h := &harness{
		backend: NewMockLimiter(gomock.NewController(t)),
		clock:   clockwork.NewFakeClockAt(epoch),
		logs:    &recorder{},
	}

	cfg := unavailable.DefaultConfig()
	cfg.Mode = mode
	cfg.Clock = h.clock
	cfg.Logger = slog.New(h.logs)
	if edit != nil {
		edit(&cfg)
	}

	l, err := unavailable.Wrap(h.backend, testNamespace, testLimit, testWindow, cfg)
	require.NoError(t, err)
	h.limiter = l

	return h
}

// down makes every backend call fail, as many times as it is called.
func (h *harness) down() {
	h.backend.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(true, errDown).AnyTimes()
	h.backend.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Return(errDown).AnyTimes()
}

// openBreaker fails one check, which opens the breaker.
func (h *harness) openBreaker(t *testing.T) {
	t.Helper()

	h.backend.EXPECT().Exceeded(gomock.Any(), otherKey).Return(true, errDown)
	_, _ = h.limiter.Exceeded(t.Context(), otherKey)
}

// record is one log record, flattened.
type record struct {
	level   slog.Level
	message string
	attrs   map[string]slog.Value
}

// recorder is a slog.Handler that keeps every record it is given.
type recorder struct {
	mu      sync.Mutex
	records []record
}

func (r *recorder) Enabled(context.Context, slog.Level) bool { return true }

func (r *recorder) Handle(_ context.Context, rec slog.Record) error {
	attrs := map[string]slog.Value{}
	rec.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value
		return true
	})

	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = append(r.records, record{level: rec.Level, message: rec.Message, attrs: attrs})

	return nil
}

func (r *recorder) WithAttrs([]slog.Attr) slog.Handler { return r }
func (r *recorder) WithGroup(string) slog.Handler      { return r }

// all returns a copy of what has been recorded so far.
func (r *recorder) all() []record {
	r.mu.Lock()
	defer r.mu.Unlock()

	return slices.Clone(r.records)
}

// at returns the records written at level.
func (r *recorder) at(level slog.Level) []record {
	var out []record
	for _, rec := range r.all() {
		if rec.level == level {
			out = append(out, rec)
		}
	}

	return out
}

func cancelled(ctx context.Context) context.Context {
	cctx, cancel := context.WithCancel(ctx)
	cancel()

	return cctx
}

// TestUnavailable_Construction covers task 4.1's wiring rules: every
// meaningless configuration is refused with ErrConfig before any traffic, and
// the defaults are accepted as they are.
func TestUnavailable_Construction(t *testing.T) {
	t.Parallel()

	type input struct {
		backend   func(ctrl *gomock.Controller) ratelimit.Limiter
		namespace string
		limit     int
		window    time.Duration
		cfg       func(cfg *unavailable.Config)
	}

	type testCase struct {
		name   string
		input  input
		assert func(t *testing.T, l ratelimit.Limiter, err error)
	}

	valid := func() input {
		return input{
			backend:   func(ctrl *gomock.Controller) ratelimit.Limiter { return NewMockLimiter(ctrl) },
			namespace: testNamespace,
			limit:     testLimit,
			window:    testWindow,
		}
	}
	with := func(edit func(in *input)) input {
		in := valid()
		edit(&in)

		return in
	}
	refused := func(t *testing.T, l ratelimit.Limiter, err error) {
		require.ErrorIs(t, err, ratelimit.ErrConfig)
		assert.Nil(t, l)
	}

	cases := []testCase{
		{
			name:  "the defaults are accepted",
			input: valid(),
			assert: func(t *testing.T, l ratelimit.Limiter, err error) {
				require.NoError(t, err)
				assert.NotNil(t, l)
			},
		},
		{
			name:  "every mode is accepted",
			input: valid(),
			assert: func(t *testing.T, _ ratelimit.Limiter, _ error) {
				for _, mode := range []ratelimit.UnavailableMode{
					ratelimit.UnavailableRefuse, ratelimit.UnavailableFallBackToLocal, ratelimit.UnavailableAllow,
				} {
					cfg := unavailable.DefaultConfig()
					cfg.Mode = mode
					l, err := unavailable.Wrap(NewMockLimiter(gomock.NewController(t)),
						testNamespace, testLimit, testWindow, cfg)
					require.NoError(t, err, "mode %d", mode)
					assert.NotNil(t, l, "mode %d", mode)
				}
			},
		},
		{
			name: "an unknown mode is refused",
			input: with(func(in *input) {
				in.cfg = func(cfg *unavailable.Config) { cfg.Mode = ratelimit.UnavailableMode(9) }
			}),
			assert: refused,
		},
		{
			name: "a negative mode is refused",
			input: with(func(in *input) {
				in.cfg = func(cfg *unavailable.Config) { cfg.Mode = ratelimit.UnavailableMode(-1) }
			}),
			assert: refused,
		},
		{
			name:   "a zero timeout is refused",
			input:  with(func(in *input) { in.cfg = func(cfg *unavailable.Config) { cfg.Timeout = 0 } }),
			assert: refused,
		},
		{
			name:   "a negative timeout is refused",
			input:  with(func(in *input) { in.cfg = func(cfg *unavailable.Config) { cfg.Timeout = -time.Second } }),
			assert: refused,
		},
		{
			name:   "a zero probe interval is refused",
			input:  with(func(in *input) { in.cfg = func(cfg *unavailable.Config) { cfg.ProbeInterval = 0 } }),
			assert: refused,
		},
		{
			name: "a negative probe interval is refused",
			input: with(func(in *input) {
				in.cfg = func(cfg *unavailable.Config) { cfg.ProbeInterval = -time.Second }
			}),
			assert: refused,
		},
		{
			name: "a nil backend is refused",
			input: with(func(in *input) {
				in.backend = func(*gomock.Controller) ratelimit.Limiter { return nil }
			}),
			assert: refused,
		},
		{
			name: "a typed nil backend is refused",
			input: with(func(in *input) {
				in.backend = func(*gomock.Controller) ratelimit.Limiter { return (*MockLimiter)(nil) }
			}),
			assert: refused,
		},
		{
			name:   "an empty namespace is refused",
			input:  with(func(in *input) { in.namespace = "" }),
			assert: refused,
		},
		{
			name:   "a zero limit is refused",
			input:  with(func(in *input) { in.limit = 0 }),
			assert: refused,
		},
		{
			name:   "a zero window is refused",
			input:  with(func(in *input) { in.window = 0 }),
			assert: refused,
		},
		{
			name:   "a nil clock is refused",
			input:  with(func(in *input) { in.cfg = func(cfg *unavailable.Config) { cfg.Clock = nil } }),
			assert: refused,
		},
		{
			name: "a typed nil clock is refused",
			input: with(func(in *input) {
				in.cfg = func(cfg *unavailable.Config) { cfg.Clock = (*clockwork.FakeClock)(nil) }
			}),
			assert: refused,
		},
		{
			name:   "a nil logger is refused",
			input:  with(func(in *input) { in.cfg = func(cfg *unavailable.Config) { cfg.Logger = nil } }),
			assert: refused,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := unavailable.DefaultConfig()
			if tc.input.cfg != nil {
				tc.input.cfg(&cfg)
			}

			l, err := unavailable.Wrap(tc.input.backend(gomock.NewController(t)),
				tc.input.namespace, tc.input.limit, tc.input.window, cfg)
			tc.assert(t, l, err)
		})
	}
}

// TestUnavailable_DefaultConfig pins the documented defaults, which the backend
// modules' own option godoc names.
func TestUnavailable_DefaultConfig(t *testing.T) {
	t.Parallel()

	cfg := unavailable.DefaultConfig()

	assert.Equal(t, ratelimit.UnavailableRefuse, cfg.Mode)
	assert.Equal(t, defaultTimeout, cfg.Timeout)
	assert.Equal(t, defaultInterval, cfg.ProbeInterval)
	assert.NotNil(t, cfg.Clock)
	assert.Same(t, slog.Default(), cfg.Logger)
	assert.Equal(t, ratelimit.DefaultLogInterval, cfg.LogInterval)
}

// TestUnavailable_PassThrough covers task 4.1's healthy path and the
// ended-context rule: a live backend's answers pass through unchanged, every
// call is bounded by the operation timeout, and a check on an ended caller
// context fails closed without touching the backend, whatever the mode.
func TestUnavailable_PassThrough(t *testing.T) {
	t.Parallel()

	type call func(ctx context.Context, l ratelimit.Limiter) (bool, error)

	check := func(ctx context.Context, l ratelimit.Limiter) (bool, error) {
		return l.Exceeded(ctx, testKey)
	}
	recordFailure := func(ctx context.Context, l ratelimit.Limiter) (bool, error) {
		return false, l.RecordFailure(ctx, testKey)
	}

	// boundedByTimeout asserts the context the backend was handed is live and
	// ends within the operation timeout.
	boundedByTimeout := func(t *testing.T, ctx context.Context) {
		t.Helper()

		require.NoError(t, ctx.Err(), "the backend was handed an ended context")
		deadline, ok := ctx.Deadline()
		require.True(t, ok, "the backend call carries no deadline")
		assert.LessOrEqual(t, time.Until(deadline), defaultTimeout)
	}

	type testCase struct {
		name    string
		mode    ratelimit.UnavailableMode
		ctx     func(ctx context.Context) context.Context
		arrange func(t *testing.T, h *harness)
		call    call
		assert  func(t *testing.T, exceeded bool, err error)
	}

	endedCheck := func(label string, mode ratelimit.UnavailableMode) testCase {
		return testCase{
			name:    "an ended caller context fails closed without the backend, " + label,
			mode:    mode,
			ctx:     cancelled,
			arrange: func(*testing.T, *harness) {}, // any backend call fails the mock
			call:    check,
			assert: func(t *testing.T, exceeded bool, err error) {
				require.ErrorIs(t, err, context.Canceled)
				assert.NotErrorIs(t, err, ratelimit.ErrBackendUnavailable)
				assert.True(t, exceeded)
			},
		}
	}

	cases := []testCase{
		{
			name: "an exceeded answer passes through",
			arrange: func(_ *testing.T, h *harness) {
				h.backend.EXPECT().Exceeded(gomock.Any(), testKey).Return(true, nil)
			},
			call: check,
			assert: func(t *testing.T, exceeded bool, err error) {
				require.NoError(t, err)
				assert.True(t, exceeded)
			},
		},
		{
			name: "a not-exceeded answer passes through",
			arrange: func(_ *testing.T, h *harness) {
				h.backend.EXPECT().Exceeded(gomock.Any(), testKey).Return(false, nil)
			},
			call: check,
			assert: func(t *testing.T, exceeded bool, err error) {
				require.NoError(t, err)
				assert.False(t, exceeded)
			},
		},
		{
			name: "a record passes through",
			arrange: func(_ *testing.T, h *harness) {
				h.backend.EXPECT().RecordFailure(gomock.Any(), testKey).Return(nil)
			},
			call: recordFailure,
			assert: func(t *testing.T, _ bool, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "a check is bounded by the operation timeout",
			arrange: func(t *testing.T, h *harness) {
				h.backend.EXPECT().Exceeded(gomock.Any(), testKey).DoAndReturn(
					func(ctx context.Context, _ string) (bool, error) {
						boundedByTimeout(t, ctx)
						return false, nil
					})
			},
			call: check,
			assert: func(t *testing.T, _ bool, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "a record on an ended caller context still reaches the backend, bounded by the timeout",
			ctx:  cancelled,
			arrange: func(t *testing.T, h *harness) {
				h.backend.EXPECT().RecordFailure(gomock.Any(), testKey).DoAndReturn(
					func(ctx context.Context, _ string) error {
						boundedByTimeout(t, ctx)
						return nil
					})
			},
			call: recordFailure,
			assert: func(t *testing.T, _ bool, err error) {
				require.NoError(t, err)
			},
		},
		endedCheck("refuse mode", ratelimit.UnavailableRefuse),
		endedCheck("fall-back mode", ratelimit.UnavailableFallBackToLocal),
		endedCheck("allow mode", ratelimit.UnavailableAllow),
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, tc.mode)
			tc.arrange(t, h)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			exceeded, err := tc.call(ctx, h.limiter)
			tc.assert(t, exceeded, err)
		})
	}
}

// TestUnavailable_ErrorTextOmitsKey covers the rule that a key, which a
// consumer composes and may build from a user's identifier, never reaches the
// text of an error the decorator returns. In fall-back mode the local
// in-memory limiter's errors quote the key, so they are wrapped in fixed text;
// the caller's own error stays reachable through errors.Is.
func TestUnavailable_ErrorTextOmitsKey(t *testing.T) {
	t.Parallel()

	const key = "alice@example.com"

	type testCase struct {
		name    string
		arrange func(t *testing.T, h *harness, cancel context.CancelFunc)
	}

	cases := []testCase{
		{
			name: "the caller ends while the backend answers a fall-back check",
			arrange: func(_ *testing.T, h *harness, cancel context.CancelFunc) {
				h.backend.EXPECT().Exceeded(gomock.Any(), key).DoAndReturn(
					func(context.Context, string) (bool, error) {
						cancel()
						return false, nil
					})
			},
		},
		{
			name: "the caller has ended before a fall-back check",
			arrange: func(_ *testing.T, _ *harness, cancel context.CancelFunc) {
				cancel()
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, ratelimit.UnavailableFallBackToLocal)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			tc.arrange(t, h, cancel)

			exceeded, err := h.limiter.Exceeded(ctx, key)
			assert.True(t, exceeded)
			require.ErrorIs(t, err, context.Canceled)
			assert.NotContains(t, err.Error(), key)
		})
	}
}
