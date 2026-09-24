package mfa_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

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
		mfa.WithClock(func() time.Time { return base }),
		mfa.WithTOTPLogger(logger),
	)
	require.NoError(t, err)

	p, err := m.BeginEnrolment(t.Context(), "u-1", "ada@example.com")
	require.NoError(t, err)
	require.NoError(t, m.ConfirmEnrolment(t.Context(), "u-1", codeForSecret(t, p.Secret, base)))

	assert.ErrorIs(t, m.Verify(t.Context(), "u-1", "123456"), mfa.ErrInvalidCode)

	// A replay, too: the code that confirmed the enrolment must not reappear.
	spent := codeForSecret(t, p.Secret, base)
	_ = m.Verify(t.Context(), "u-1", spent)

	require.NoError(t, m.RemoveEnrolment(t.Context(), "u-1"))

	logged := buf.String()
	require.NotEmpty(t, logged, "the assertions below would be vacuous with nothing written")

	assert.NotContains(t, logged, "123456", "a presented code must not be logged")
	assert.NotContains(t, logged, spent, "nor an accepted one")
	assert.NotContains(t, logged, p.Secret, "an enrolment secret must not be logged")
	assert.NotContains(t, logged, p.URI, "a provisioning URI must not be logged")
	assert.NotContains(t, logged, "otpauth://")
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
