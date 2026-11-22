package mfa_test

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/ctxlog"
	"github.com/kartaladev/scrty/internal/eventsink"
)

// lrBuffers are the three destinations a record can reach: the component's own
// logger, the logger of the chain handling the request, and slog.Default().
type lrBuffers struct {
	own, chain, def bytes.Buffer
}

// lrSetup swaps slog.Default() for a buffer until the test ends. Tests using
// it replace the default logger, so they do not run in parallel.
func lrSetup(t *testing.T) *lrBuffers {
	t.Helper()

	b := &lrBuffers{}
	previous := slog.Default()
	slog.SetDefault(lrLogger(&b.def))
	t.Cleanup(func() { slog.SetDefault(previous) })

	return b
}

func lrLogger(w *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func (b *lrBuffers) ctx(t *testing.T, chain bool) context.Context {
	t.Helper()

	if !chain {
		return t.Context()
	}

	return ctxlog.With(t.Context(), lrLogger(&b.chain))
}

// lrPanicUnwrap is an error whose Unwrap panics, so the sanitizer writes an
// abort record.
type lrPanicUnwrap struct{}

func (lrPanicUnwrap) Error() string { return "lr: hostile" }
func (lrPanicUnwrap) Unwrap() error { panic("lr: Unwrap panicked") }

type lrCase struct {
	name  string
	chain bool
	// option builds the logger option, nil for none.
	option func(own *slog.Logger) any
	assert func(t *testing.T, err error, b *lrBuffers)
}

func lrRows(optionName, msg string) []lrCase {
	return []lrCase{
		{
			name:  "no option, inside a configured chain",
			chain: true,
			assert: func(t *testing.T, err error, b *lrBuffers) {
				require.NoError(t, err)
				assert.Contains(t, b.chain.String(), msg)
				assert.Empty(t, b.def.String(), "the default logger must see nothing")
			},
		},
		{
			name:   "own option wins",
			chain:  true,
			option: func(own *slog.Logger) any { return own },
			assert: func(t *testing.T, err error, b *lrBuffers) {
				require.NoError(t, err)
				assert.Contains(t, b.own.String(), msg)
				assert.Empty(t, b.chain.String())
				assert.Empty(t, b.def.String())
			},
		},
		{
			name: "no chain",
			assert: func(t *testing.T, err error, b *lrBuffers) {
				require.NoError(t, err)
				assert.Contains(t, b.def.String(), msg, "the default as swapped at record time")
			},
		},
		{
			name:   "nil option",
			option: func(*slog.Logger) any { return (*slog.Logger)(nil) },
			assert: func(t *testing.T, err error, _ *lrBuffers) {
				require.ErrorIs(t, err, mfa.ErrConfig)
				assert.ErrorContains(t, err, optionName)
			},
		},
	}
}

// TestLogRoute_VerifyThrottle pins where the throttle's records go: its own
// logger when given, else the logger of the chain handling the request, else
// slog.Default() as it is when the record is written.
func TestLogRoute_VerifyThrottle(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	for _, tc := range lrRows("WithThrottleLogger", "mfa: verification throttled") {
		t.Run(tc.name, func(t *testing.T) {
			b := lrSetup(t)

			ctrl := gomock.NewController(t)
			limiter := NewMockLimiter(ctrl)
			limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(true, nil).AnyTimes()

			opts := []mfa.ThrottleOption{mfa.WithThrottleLimiter(limiter)}
			if tc.option != nil {
				opts = append(opts, mfa.WithThrottleLogger(tc.option(lrLogger(&b.own)).(*slog.Logger)))
			}

			throttle, err := mfa.NewVerifyThrottle(opts...)
			if err != nil {
				tc.assert(t, err, b)

				return
			}

			require.ErrorIs(t, throttle.Check(b.ctx(t, tc.chain), "u-1"), mfa.ErrVerifyThrottled)

			tc.assert(t, nil, b)
		})
	}
}

// TestLogRoute_VerifyThrottleSummary pins that the suppressed-count summary,
// written with no request in scope, goes to the chain logger the throttle last
// wrote through, else to the default.
func TestLogRoute_VerifyThrottleSummary(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	const msg = "mfa: verification refusals suppressed"

	type testCase struct {
		name   string
		chain  bool
		assert func(t *testing.T, b *lrBuffers)
	}

	cases := []testCase{
		{
			name:  "inside a configured chain",
			chain: true,
			assert: func(t *testing.T, b *lrBuffers) {
				assert.Contains(t, b.chain.String(), msg)
				assert.Empty(t, b.def.String(), "the default logger must see nothing")
			},
		},
		{
			name: "no chain",
			assert: func(t *testing.T, b *lrBuffers) {
				assert.Contains(t, b.def.String(), msg)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := lrSetup(t)

			ctrl := gomock.NewController(t)
			limiter := NewMockLimiter(ctrl)
			limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(true, nil).AnyTimes()

			throttle, err := mfa.NewVerifyThrottle(mfa.WithThrottleLimiter(limiter))
			require.NoError(t, err)

			ctx := b.ctx(t, tc.chain)
			for range 3 { // the first writes; the rest are held back and counted
				require.ErrorIs(t, throttle.Check(ctx, "u-1"), mfa.ErrVerifyThrottled)
			}

			require.NoError(t, throttle.FlushRefusalLogs())

			tc.assert(t, b)
		})
	}
}

// TestLogRoute_TOTP pins where the method's records go: its own logger when
// given, else the logger of the chain handling the request, else
// slog.Default() as it is when the record is written.
func TestLogRoute_TOTP(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	for _, tc := range lrRows("WithLogger", "mfa: totp code refused") {
		t.Run(tc.name, func(t *testing.T) {
			b := lrSetup(t)

			var opts []mfa.Option
			if tc.option != nil {
				opts = append(opts, mfa.WithLogger(tc.option(lrLogger(&b.own)).(*slog.Logger)))
			}

			method, err := mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "scrty-test", opts...)
			if err != nil {
				tc.assert(t, err, b)

				return
			}

			// No enrolment: a refusal, recorded at debug level.
			require.ErrorIs(t, method.Verify(b.ctx(t, tc.chain), "u-1", []byte("123456")), mfa.ErrInvalidCode)

			tc.assert(t, nil, b)
		})
	}
}

// TestLogRoute_Reset pins that the reset, which has no logger of its own,
// writes the abort record of a hostile port error and the record of a
// panicking security-event sink to the logger of the chain handling the
// request, else to slog.Default() as it is when the record is written.
func TestLogRoute_Reset(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	type testCase struct {
		name   string
		chain  bool
		remove error
		opts   []mfa.ResetOption
		assert func(t *testing.T, b *lrBuffers)
	}

	panickingSink := mfa.WithResetSecurityEvents(func(context.Context, event.Event) { panic("sink down") })

	cases := []testCase{
		{
			name: "hostile remover, inside a configured chain", chain: true, remove: lrPanicUnwrap{},
			assert: func(t *testing.T, b *lrBuffers) {
				assert.Contains(t, b.chain.String(), "error classification aborted")
				assert.Empty(t, b.def.String(), "the default logger must see nothing")
			},
		},
		{
			name: "hostile remover, no chain", remove: lrPanicUnwrap{},
			assert: func(t *testing.T, b *lrBuffers) {
				assert.Contains(t, b.def.String(), "error classification aborted")
			},
		},
		{
			name: "panicking sink, inside a configured chain", chain: true, opts: []mfa.ResetOption{panickingSink},
			assert: func(t *testing.T, b *lrBuffers) {
				assert.Contains(t, b.chain.String(), eventsink.MsgSinkPanicked)
				assert.Empty(t, b.def.String(), "the default logger must see nothing")
			},
		},
		{
			name: "panicking sink, no chain", opts: []mfa.ResetOption{panickingSink},
			assert: func(t *testing.T, b *lrBuffers) {
				assert.Contains(t, b.def.String(), eventsink.MsgSinkPanicked)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := lrSetup(t)

			ctrl := gomock.NewController(t)
			remover := NewMockEnrolmentRemover(ctrl)
			remover.EXPECT().RemoveEnrolment(gomock.Any(), identity.UserID("u-1")).Return(tc.remove)
			sessions := NewMockSessionRevoker(ctrl)
			sessions.EXPECT().DeleteByUser(gomock.Any(), identity.UserID("u-1")).Return(nil).AnyTimes()

			opts := append([]mfa.ResetOption{mfa.WithoutResetNotification()}, tc.opts...)
			err := mfa.ResetEnrolment(b.ctx(t, tc.chain), "u-1", mfa.ResetDeps{
				Enrolments: []mfa.EnrolmentRemover{remover},
				Sessions:   sessions,
			}, opts...)

			if tc.remove != nil {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			tc.assert(t, b)
		})
	}
}
