package mfa_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/detach"
	"github.com/kartaladev/scrty/ratelimit"
)

// ctxProbe records what a double saw of the context it was called with. The
// calls under test are synchronous, so it needs no lock.
type ctxProbe struct {
	called   bool
	deadline time.Time
	has      bool
	err      error
}

func (p *ctxProbe) see(ctx context.Context) {
	p.called = true
	p.deadline, p.has = ctx.Deadline()
	p.err = ctx.Err()
}

// cancelled returns ctx already cancelled, with no deadline of its own.
func cancelled(ctx context.Context) context.Context {
	cctx, cancel := context.WithCancel(ctx)
	cancel()

	return cctx
}

// TestTOTP_DetachedCallsCarryDeadline pins the bound on the calls this package
// makes under a context the caller cannot cancel: the give-back of a charged
// attempt is a write and carries detach.WriteTimeout, while the throttle's
// RecordFailure is class 5 and carries no deadline of the library's making.
// The caller's context in every case has no deadline, so one seen by a double
// can only be the library's.
func TestTOTP_DetachedCallsCarryDeadline(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// run makes the call under test with ctx and returns what the double saw.
		run    func(t *testing.T, ctx context.Context, p *ctxProbe) (f *attemptsFixture, err error)
		ctx    func(ctx context.Context) context.Context // nil means identity
		assert func(t *testing.T, p *ctxProbe, f *attemptsFixture, err error)
	}

	until := attemptsEpoch.Add(mfa.DefaultVerifyAttemptWindow)

	// verifyWithRefund verifies a valid code against a mock store whose
	// give-back runs refund.
	verifyWithRefund := func(refund func(ctx context.Context) (bool, error)) func(*testing.T, context.Context, *ctxProbe) (*attemptsFixture, error) {
		return func(t *testing.T, ctx context.Context, p *ctxProbe) (*attemptsFixture, error) {
			s := NewMockEnrolmentStore(gomock.NewController(t))
			s.EXPECT().Get(gomock.Any(), identity.UserID("u-1")).Return(confirmedEnrolment("u-1"), true, nil)
			s.EXPECT().
				ChargeVerifyAttempt(gomock.Any(), identity.UserID("u-1"), gomock.Any(), gomock.Any(), gomock.Any()).
				Return(until, true, nil)
			s.EXPECT().AcceptStep(gomock.Any(), identity.UserID("u-1"), gomock.Any(), gomock.Any()).Return(true, nil)
			s.EXPECT().
				RefundVerifyAttempt(gomock.Any(), identity.UserID("u-1"), until).
				DoAndReturn(func(ctx context.Context, _ identity.UserID, _ time.Time) (bool, error) {
					p.see(ctx)

					return refund(ctx)
				})

			f := newAttemptsFixture(t, s) //nolint:contextcheck // the case's ctx is the caller's; fixtures are built on t.Context()

			return f, f.totp.Verify(ctx, f.user, f.valid(t))
		}
	}

	// recordFailure calls the throttle's RecordFailure over a mock limiter.
	recordFailure := func(t *testing.T, ctx context.Context, p *ctxProbe) (*attemptsFixture, error) {
		l := NewMockLimiter(gomock.NewController(t))
		l.EXPECT().
			RecordFailure(gomock.Any(), gomock.Any()).
			DoAndReturn(func(ctx context.Context, _ string) error {
				p.see(ctx)

				return nil
			})

		th, err := mfa.NewVerifyThrottle(mfa.WithThrottleLimiter(ratelimit.Limiter(l)))
		require.NoError(t, err)

		th.RecordFailure(ctx, "u-1")

		return nil, nil
	}

	assertBounded := func(bound time.Duration) func(*testing.T, *ctxProbe, *attemptsFixture, error) {
		return func(t *testing.T, p *ctxProbe, _ *attemptsFixture, err error) {
			require.NoError(t, err)
			require.True(t, p.called)
			require.True(t, p.has, "the detached call has no deadline")
			remaining := time.Until(p.deadline)
			assert.Positive(t, remaining)
			assert.LessOrEqual(t, remaining, bound)
		}
	}

	cases := []testCase{
		{
			name:   "give-back carries the write deadline",
			run:    verifyWithRefund(func(context.Context) (bool, error) { return true, nil }),
			assert: assertBounded(detach.WriteTimeout),
		},
		{
			name: "give-back stays live when the caller is cancelled",
			run:  verifyWithRefund(func(context.Context) (bool, error) { return true, nil }),
			ctx:  cancelled,
			assert: func(t *testing.T, p *ctxProbe, f *attemptsFixture, err error) {
				assertBounded(detach.WriteTimeout)(t, p, f, err)
				assert.NoError(t, p.err)
			},
		},
		{
			name: "give-back deadline exceeded keeps the warn-and-carry-on outcome",
			run: verifyWithRefund(func(context.Context) (bool, error) {
				return false, context.DeadlineExceeded
			}),
			assert: func(t *testing.T, p *ctxProbe, f *attemptsFixture, err error) {
				require.NoError(t, err, "a failed give-back refuses nothing")
				require.True(t, p.called)
				assert.Equal(t, 1, f.warnRecords())
			},
		},
		{
			name: "throttle RecordFailure carries no library deadline",
			run:  recordFailure,
			assert: func(t *testing.T, p *ctxProbe, _ *attemptsFixture, _ error) {
				require.True(t, p.called)
				assert.False(t, p.has, "RecordFailure is class 5: the limiter owns its bound")
			},
		},
		{
			name: "throttle RecordFailure stays live when the caller is cancelled",
			run:  recordFailure,
			ctx:  cancelled,
			assert: func(t *testing.T, p *ctxProbe, _ *attemptsFixture, _ error) {
				require.True(t, p.called)
				assert.False(t, p.has)
				assert.NoError(t, p.err)
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

			p := &ctxProbe{}
			f, err := tc.run(t, ctx, p)
			tc.assert(t, p, f, err)
		})
	}
}
