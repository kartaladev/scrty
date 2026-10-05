package mfa_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/ratelimit"
)

// memoryLimiter builds the limiter the throttle defaults to, so a case that is
// about the throttle does not restate the limit it is testing against.
func memoryLimiter(t *testing.T) ratelimit.Limiter {
	t.Helper()

	l, err := ratelimit.NewMemoryLimiter(5, 15*time.Minute)
	require.NoError(t, err)

	return l
}

func TestVerifyThrottle(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		limiter func(t *testing.T) ratelimit.Limiter
		assert  func(t *testing.T, th *mfa.VerifyThrottle)
	}

	cases := []testCase{
		{
			name:    "five failures in the window then a refusal",
			limiter: memoryLimiter,
			assert: func(t *testing.T, th *mfa.VerifyThrottle) {
				ctx := t.Context()

				for range 5 {
					require.NoError(t, th.Check(ctx, "u-1"))
					th.RecordFailure(ctx, "u-1")
				}

				assert.ErrorIs(t, th.Check(ctx, "u-1"), mfa.ErrVerifyThrottled)
			},
		},
		{
			name:    "another user is unaffected",
			limiter: memoryLimiter,
			assert: func(t *testing.T, th *mfa.VerifyThrottle) {
				ctx := t.Context()

				for range 5 {
					th.RecordFailure(ctx, "u-1")
				}

				assert.ErrorIs(t, th.Check(ctx, "u-1"), mfa.ErrVerifyThrottled)
				assert.NoError(t, th.Check(ctx, "u-2"))
			},
		},
		{
			name:    "a success spends nothing",
			limiter: memoryLimiter,
			assert: func(t *testing.T, th *mfa.VerifyThrottle) {
				ctx := t.Context()

				for range 100 {
					require.NoError(t, th.Check(ctx, "u-1"))
				}
			},
		},
		{
			name: "a limiter that cannot decide refuses",
			limiter: func(t *testing.T) ratelimit.Limiter {
				l := NewMockLimiter(gomock.NewController(t))
				l.EXPECT().
					Exceeded(gomock.Any(), gomock.Any()).
					Return(false, errors.New("redis: connection refused")).
					AnyTimes()

				return l
			},
			assert: func(t *testing.T, th *mfa.VerifyThrottle) {
				assert.ErrorIs(t, th.Check(t.Context(), "u-1"), mfa.ErrVerifyThrottled,
					"an undecidable limiter fails closed")
			},
		},
		{
			name: "a limiter that cannot record does not refuse the caller",
			limiter: func(t *testing.T) ratelimit.Limiter {
				l := NewMockLimiter(gomock.NewController(t))
				l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()
				l.EXPECT().
					RecordFailure(gomock.Any(), gomock.Any()).
					Return(errors.New("redis: connection refused")).
					AnyTimes()

				return l
			},
			assert: func(t *testing.T, th *mfa.VerifyThrottle) {
				ctx := t.Context()

				th.RecordFailure(ctx, "u-1")
				assert.NoError(t, th.Check(ctx, "u-1"),
					"an outage while recording is not a judgement about the caller")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			th, err := mfa.NewVerifyThrottle(mfa.WithVerifyLimiter(tc.limiter(t)))
			require.NoError(t, err)

			tc.assert(t, th)
		})
	}
}

// TestVerifyThrottleDefaults pins what a consumer who wires nothing gets: the
// documented 5 failures per 15 minutes, with no limiter of their own.
func TestVerifyThrottleDefaults(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	th, err := mfa.NewVerifyThrottle()
	require.NoError(t, err)

	for range 5 {
		require.NoError(t, th.Check(ctx, "u-1"))
		th.RecordFailure(ctx, "u-1")
	}

	assert.ErrorIs(t, th.Check(ctx, "u-1"), mfa.ErrVerifyThrottled)
	assert.NoError(t, th.Check(ctx, "u-2"))
}

func TestNewVerifyThrottleConfig(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []mfa.ThrottleOption
		assert func(t *testing.T, th *mfa.VerifyThrottle, err error)
	}

	configError := func(t *testing.T, th *mfa.VerifyThrottle, err error) {
		require.Error(t, err)
		assert.Nil(t, th)
	}

	cases := []testCase{
		{
			name: "no options",
			assert: func(t *testing.T, th *mfa.VerifyThrottle, err error) {
				require.NoError(t, err)
				assert.NotNil(t, th)
			},
		},
		{
			name:   "a nil limiter",
			opts:   []mfa.ThrottleOption{mfa.WithVerifyLimiter(nil)},
			assert: configError,
		},
		{
			name:   "a typed-nil limiter",
			opts:   []mfa.ThrottleOption{mfa.WithVerifyLimiter((*ratelimit.MemoryLimiter)(nil))},
			assert: configError,
		},
		{
			name:   "a nil logger",
			opts:   []mfa.ThrottleOption{mfa.WithVerifyLogger(nil)},
			assert: configError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			th, err := mfa.NewVerifyThrottle(tc.opts...)
			tc.assert(t, th, err)
		})
	}
}

func TestVerifyThrottleConsumerLimiter(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	shared := NewMockLimiter(ctrl)

	shared.EXPECT().Exceeded(gomock.Any(), gomock.Eq("mfa-verify|u-1")).Return(false, nil).Times(1)
	shared.EXPECT().RecordFailure(gomock.Any(), gomock.Eq("mfa-verify|u-1")).Return(nil).Times(1)

	th, err := mfa.NewVerifyThrottle(mfa.WithVerifyLimiter(shared))
	require.NoError(t, err)

	require.NoError(t, th.Check(t.Context(), "u-1"))
	th.RecordFailure(t.Context(), "u-1")

	// The two expectations above pin the bucket by its literal, deliberately:
	// computing it with VerifyThrottleKey would pass whatever shape the key
	// took. This pins the other half — that the exported name a consumer reads
	// or clears the bucket by is the very string the failures land under.
	assert.Equal(t, "mfa-verify|u-1", mfa.VerifyThrottleKey("u-1"),
		"the documented key and the bucket the throttle uses are one string")
}

func TestVerifyThrottleLogSampling(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	l, err := ratelimit.NewMemoryLimiter(1, 15*time.Minute)
	require.NoError(t, err)

	th, err := mfa.NewVerifyThrottle(
		mfa.WithVerifyLimiter(l),
		mfa.WithVerifyLogger(logger),
		mfa.WithVerifyLogInterval(time.Minute),
	)
	require.NoError(t, err)

	ctx := t.Context()
	th.RecordFailure(ctx, "u-1")

	for range 200 {
		require.ErrorIs(t, th.Check(ctx, "u-1"), mfa.ErrVerifyThrottled)
	}

	assert.Equal(t, 1, strings.Count(buf.String(), "mfa: verification throttled"),
		"200 refusals in one window write one record")
	assert.NotContains(t, buf.String(), "u-1",
		"the record names the reason, which is what the sampler keys on")
}

func TestMFALogsCarryNoSecrets(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	store := mfa.NewMemoryEnrolmentStore()

	m, err := mfa.NewTOTP(store, "Example",
		mfa.WithClock(clockwork.NewFakeClockAt(base)),
		mfa.WithTOTPLogger(logger),
	)
	require.NoError(t, err)

	p, err := m.BeginEnrolment(t.Context(), "u-1", "ada@example.com")
	require.NoError(t, err)
	require.NoError(t, m.ConfirmEnrolment(t.Context(), "u-1", codeForSecret(t, p.Secret, base)))

	assert.ErrorIs(t, m.Verify(t.Context(), "u-1", []byte("123456")), mfa.ErrInvalidCode)

	// A replay, too: the code that confirmed the enrolment must not reappear.
	spent := codeForSecret(t, p.Secret, base)
	_ = m.Verify(t.Context(), "u-1", []byte(spent))

	require.NoError(t, m.RemoveEnrolment(t.Context(), "u-1"))

	logged := buf.String()
	require.NotEmpty(t, logged, "the assertions below would be vacuous with nothing written")

	assert.NotContains(t, logged, "123456", "a presented code must not be logged")
	assert.NotContains(t, logged, spent, "nor an accepted one")
	assert.NotContains(t, logged, p.Secret, "an enrolment secret must not be logged")
	assert.NotContains(t, logged, p.URI, "a provisioning URI must not be logged")
	assert.NotContains(t, logged, "otpauth://")
}

// TestVerifyThrottleFailureRecords pins the diagnostic-redaction requirement
// for the limiter's own failures (spec diagnostic-redaction, "Log records
// carry no dependency error text"): the record names the reason and the
// limiter error's Go type, never its text, and the reason is named exactly
// once — diag.Failure's own reason attribute, not a second one alongside it.
func TestVerifyThrottleFailureRecords(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name       string
		wantReason string
		wantMsg    string
		limiter    func(t *testing.T, ctrl *gomock.Controller) ratelimit.Limiter
		trigger    func(t *testing.T, th *mfa.VerifyThrottle)
	}

	cases := []testCase{
		{
			name:       "the limiter cannot decide whether the user is throttled",
			wantReason: "limiter-error",
			wantMsg:    "mfa: verification throttle could not be consulted",
			limiter: func(t *testing.T, ctrl *gomock.Controller) ratelimit.Limiter {
				t.Helper()

				l := NewMockLimiter(ctrl)
				l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, errMFAFixture).AnyTimes()
				return l
			},
			trigger: func(t *testing.T, th *mfa.VerifyThrottle) {
				t.Helper()

				_ = th.Check(t.Context(), "some-user")
			},
		},
		{
			name:       "the limiter cannot record a failure",
			wantReason: "record-error",
			wantMsg:    "mfa: verification failure could not be recorded",
			limiter: func(t *testing.T, ctrl *gomock.Controller) ratelimit.Limiter {
				t.Helper()

				l := NewMockLimiter(ctrl)
				l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()
				l.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Return(errMFAFixture).AnyTimes()
				return l
			},
			trigger: func(t *testing.T, th *mfa.VerifyThrottle) {
				t.Helper()

				th.RecordFailure(t.Context(), "some-user")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

			ctrl := gomock.NewController(t)
			th, err := mfa.NewVerifyThrottle(
				mfa.WithVerifyLimiter(tc.limiter(t, ctrl)),
				mfa.WithVerifyLogger(logger),
			)
			require.NoError(t, err)

			tc.trigger(t, th)

			logged := buf.String()
			require.NotEmpty(t, logged, "the failure reaches the logger")

			line := strings.TrimSpace(strings.SplitN(logged, "\n", 2)[0])
			var rec map[string]any
			require.NoError(t, json.Unmarshal([]byte(line), &rec))

			assert.Equal(t, tc.wantMsg, rec["msg"])
			assert.Equal(t, tc.wantReason, rec["reason"])
			assert.Equal(t, 1, strings.Count(line, `"reason":`),
				"the reason is named exactly once, not once by this site and again by diag.Failure")
			assert.NotEmpty(t, rec["error_type"], "the record carries the limiter error's Go type")
			assert.NotContains(t, logged, "alice@example.com",
				"the record must not carry the limiter's own error text")
			assert.NotContains(t, logged, "u-123",
				"the record must not carry the limiter's own error text")
		})
	}
}

// TestVerifyThrottleChargesAHangUp pins the asymmetry between the two calls the
// throttle makes on its limiter: a Check whose caller has gone may be refused,
// but a failure already made must still be counted. The limiter port documents
// that its RecordFailure may be handed a cancellation-stripped context for
// exactly this reason, and a networked limiter would decline a write on a
// context that is already done — handing the guesser a free retry.
func TestVerifyThrottleChargesAHangUp(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	limiter := NewMockLimiter(ctrl)

	var recordedWithLiveCancel bool

	limiter.EXPECT().
		RecordFailure(gomock.Any(), mfa.VerifyThrottleKey("u-1")).
		DoAndReturn(func(ctx context.Context, _ string) error {
			recordedWithLiveCancel = ctx.Err() != nil

			return nil
		})

	throttle, err := mfa.NewVerifyThrottle(mfa.WithVerifyLimiter(limiter))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	cancel() // the client hung up before the answer was written

	throttle.RecordFailure(ctx, "u-1")

	assert.False(t, recordedWithLiveCancel,
		"a guess that was made is charged even when the caller has gone; the limiter "+
			"must not be handed a context that is already cancelled")
}

func TestVerifyThrottle_DefaultLimiterWarnsThroughConfiguredLogger(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	th, err := mfa.NewVerifyThrottle(mfa.WithVerifyLogger(logger))
	require.NoError(t, err)

	require.NoError(t, th.Check(t.Context(), "user-1")) // first use writes the per-replica warning

	assert.Contains(t, buf.String(), "counts only this replica",
		"the default limiter's per-replica warning must reach the configured logger")
}

// TestNewVerifyThrottle_LimiterFactory pins where the verification limiter comes
// from: the explicit limiter, then the factory, then the in-memory default.
func TestNewVerifyThrottle_LimiterFactory(t *testing.T) {
	t.Parallel()

	errFactory := errors.New("factory: backend refused the namespace")

	type testCase struct {
		name   string
		opts   func(t *testing.T) []mfa.ThrottleOption
		assert func(t *testing.T, th *mfa.VerifyThrottle, err error)
	}

	cases := []testCase{
		{
			name: "default builds in-memory",
			opts: func(*testing.T) []mfa.ThrottleOption { return nil },
			assert: func(t *testing.T, th *mfa.VerifyThrottle, err error) {
				require.NoError(t, err)

				for range 5 {
					th.RecordFailure(t.Context(), "u-1")
				}

				assert.ErrorIs(t, th.Check(t.Context(), "u-1"), mfa.ErrVerifyThrottled,
					"the default counts 5 failures per 15 minutes")
			},
		},
		{
			name: "factory asked with namespace, limit, window",
			opts: func(t *testing.T) []mfa.ThrottleOption {
				ctrl := gomock.NewController(t)
				built := NewMockLimiter(ctrl)
				built.EXPECT().Exceeded(gomock.Any(), "mfa-verify|u-1").Return(true, nil)

				f := NewMockLimiterFactory(ctrl)
				f.EXPECT().NewLimiter("mfa-verify", 5, 15*time.Minute).Return(built, nil).Times(1)

				return []mfa.ThrottleOption{mfa.WithVerifyLimiterFactory(f)}
			},
			assert: func(t *testing.T, th *mfa.VerifyThrottle, err error) {
				require.NoError(t, err)
				assert.ErrorIs(t, th.Check(t.Context(), "u-1"), mfa.ErrVerifyThrottled,
					"the throttle counts through the limiter the factory built")
			},
		},
		{
			name: "explicit limiter wins and factory not asked",
			opts: func(t *testing.T) []mfa.ThrottleOption {
				ctrl := gomock.NewController(t)
				explicit := NewMockLimiter(ctrl)
				explicit.EXPECT().Exceeded(gomock.Any(), "mfa-verify|u-1").Return(true, nil)

				// No expectation: gomock fails the case if the factory is asked.
				f := NewMockLimiterFactory(ctrl)

				return []mfa.ThrottleOption{mfa.WithVerifyLimiter(explicit), mfa.WithVerifyLimiterFactory(f)}
			},
			assert: func(t *testing.T, th *mfa.VerifyThrottle, err error) {
				require.NoError(t, err)
				assert.ErrorIs(t, th.Check(t.Context(), "u-1"), mfa.ErrVerifyThrottled)
			},
		},
		{
			name: "nil factory refused",
			opts: func(*testing.T) []mfa.ThrottleOption {
				return []mfa.ThrottleOption{mfa.WithVerifyLimiterFactory(nil)}
			},
			assert: func(t *testing.T, th *mfa.VerifyThrottle, err error) {
				require.ErrorIs(t, err, mfa.ErrConfig)
				assert.Nil(t, th)
			},
		},
		{
			name: "typed-nil factory refused",
			opts: func(*testing.T) []mfa.ThrottleOption {
				return []mfa.ThrottleOption{mfa.WithVerifyLimiterFactory((*MockLimiterFactory)(nil))}
			},
			assert: func(t *testing.T, th *mfa.VerifyThrottle, err error) {
				require.ErrorIs(t, err, mfa.ErrConfig)
				assert.Nil(t, th)
			},
		},
		{
			// The explicit limiter wins, but a factory replaced with nothing is
			// a wiring mistake whatever else was given.
			name: "typed-nil factory refused beside an explicit limiter",
			opts: func(t *testing.T) []mfa.ThrottleOption {
				return []mfa.ThrottleOption{
					mfa.WithVerifyLimiter(NewMockLimiter(gomock.NewController(t))),
					mfa.WithVerifyLimiterFactory((*MockLimiterFactory)(nil)),
				}
			},
			assert: func(t *testing.T, th *mfa.VerifyThrottle, err error) {
				require.ErrorIs(t, err, mfa.ErrConfig)
				assert.Nil(t, th)
			},
		},
		{
			name: "factory error fails construction",
			opts: func(t *testing.T) []mfa.ThrottleOption {
				f := NewMockLimiterFactory(gomock.NewController(t))
				f.EXPECT().NewLimiter("mfa-verify", 5, 15*time.Minute).Return(nil, errFactory)

				return []mfa.ThrottleOption{mfa.WithVerifyLimiterFactory(f)}
			},
			assert: func(t *testing.T, th *mfa.VerifyThrottle, err error) {
				require.ErrorIs(t, err, mfa.ErrConfig)
				require.ErrorIs(t, err, errFactory)
				assert.Contains(t, err.Error(), `"mfa-verify"`, "the error names the namespace")
				assert.Nil(t, th)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			th, err := mfa.NewVerifyThrottle(tc.opts(t)...)
			tc.assert(t, th, err)
		})
	}
}

func TestWithVerifyClock(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   func(fc *clockwork.FakeClock) []mfa.ThrottleOption
		assert func(t *testing.T, fc *clockwork.FakeClock, th *mfa.VerifyThrottle, err error)
	}

	refused := func(t *testing.T, _ *clockwork.FakeClock, th *mfa.VerifyThrottle, err error) {
		require.ErrorIs(t, err, mfa.ErrConfig)
		assert.Nil(t, th)
	}

	cases := []testCase{
		{
			name: "nil clock",
			opts: func(*clockwork.FakeClock) []mfa.ThrottleOption {
				return []mfa.ThrottleOption{mfa.WithVerifyClock(nil)}
			},
			assert: refused,
		},
		{
			name: "typed nil clock",
			opts: func(*clockwork.FakeClock) []mfa.ThrottleOption {
				return []mfa.ThrottleOption{mfa.WithVerifyClock((*clockwork.FakeClock)(nil))}
			},
			assert: refused,
		},
		{
			// With a consumer's limiter no default limiter is built, so only the
			// throttle's own check stands between a nil clock and a panic at
			// the first sampled record.
			name: "nil clock beside a consumer's limiter",
			opts: func(*clockwork.FakeClock) []mfa.ThrottleOption {
				l, err := ratelimit.NewMemoryLimiter(5, 15*time.Minute)
				if err != nil {
					panic(err)
				}

				return []mfa.ThrottleOption{mfa.WithVerifyLimiter(l), mfa.WithVerifyClock(nil)}
			},
			assert: refused,
		},
		{
			name: "a throttle window follows the given clock",
			opts: func(fc *clockwork.FakeClock) []mfa.ThrottleOption {
				return []mfa.ThrottleOption{mfa.WithVerifyClock(fc)}
			},
			assert: func(t *testing.T, fc *clockwork.FakeClock, th *mfa.VerifyThrottle, err error) {
				require.NoError(t, err)

				ctx := t.Context()

				for range 5 {
					require.NoError(t, th.Check(ctx, "ada"))
					th.RecordFailure(ctx, "ada")
				}

				require.ErrorIs(t, th.Check(ctx, "ada"), mfa.ErrVerifyThrottled, "the allowance is spent")

				fc.Advance(15*time.Minute + time.Second)

				assert.NoError(t, th.Check(ctx, "ada"), "the window passed on the given clock")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			fc := clockwork.NewFakeClock()
			opts := append(tc.opts(fc), mfa.WithVerifyLogger(slog.New(slog.DiscardHandler)))
			th, err := mfa.NewVerifyThrottle(opts...)
			tc.assert(t, fc, th, err)
		})
	}
}
