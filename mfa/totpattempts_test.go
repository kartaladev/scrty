package mfa_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
)

// attemptsEpoch is the instant the attempt tests start at.
var attemptsEpoch = time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)

// barrierLimiter holds every Exceeded call until n callers have checked, so
// all of them pass the throttle's check before any failure is recorded: the
// interleaving a limiter that checks and records in two steps admits.
type barrierLimiter struct {
	wg sync.WaitGroup
}

func newBarrierLimiter(n int) *barrierLimiter {
	l := &barrierLimiter{}
	l.wg.Add(n)

	return l
}

func (l *barrierLimiter) Exceeded(context.Context, string) (bool, error) {
	l.wg.Done()
	l.wg.Wait()

	return false, nil
}

func (l *barrierLimiter) RecordFailure(context.Context, string) error { return nil }

// wrongCodeAt returns a well-formed code that matches none of the steps a
// verification at at accepts.
func wrongCodeAt(t *testing.T, secret []byte, at time.Time) string {
	t.Helper()

	accepted := map[string]bool{}
	for _, d := range []time.Duration{-30 * time.Second, 0, 30 * time.Second} {
		accepted[codeAt(t, secret, at.Add(d), 6, 30*time.Second)] = true
	}

	for _, c := range []string{"000000", "111111", "222222", "333333"} {
		if !accepted[c] {
			return c
		}
	}

	t.Fatal("no wrong code found")

	return ""
}

// raceWrongCodes sends racers wrong codes for one confirmed enrolment at once,
// every one of them past a throttle whose limiter admits them all, and reports
// how many were compared (refused as ErrInvalidCode rather than refused before
// the compare). It also returns a func that verifies a valid code of the same
// window afterwards, so a caller can see what the race left behind.
func raceWrongCodes(t *testing.T, racers int, opts ...mfa.TOTPOption) (int, func() error) {
	t.Helper()

	ctx := t.Context()
	clk := clockwork.NewFakeClockAt(attemptsEpoch)
	store := mfa.NewMemoryEnrolmentStore()
	totp, err := mfa.NewTOTP(store, "scrty-test", append([]mfa.TOTPOption{mfa.WithClock(clk)}, opts...)...)
	require.NoError(t, err)

	user := identity.UserID("u-1")
	secret := []byte(rfc6238SHA1Secret)
	enrolConfirmed(t, store, user, secret)
	wrong := wrongCodeAt(t, secret, clk.Now())

	throttle, err := mfa.NewVerifyThrottle(mfa.WithVerifyLimiter(newBarrierLimiter(racers)))
	require.NoError(t, err)

	var compared atomic.Int32

	var wg sync.WaitGroup
	for range racers {
		wg.Go(func() {
			if throttle.Check(ctx, user) != nil {
				return
			}

			if errors.Is(totp.Verify(ctx, user, []byte(wrong)), mfa.ErrInvalidCode) {
				compared.Add(1)
			}
		})
	}

	wg.Wait()

	validNow := func() error {
		return totp.Verify(ctx, user, []byte(codeAt(t, secret, clk.Now(), 6, 30*time.Second)))
	}

	return int(compared.Load()), validNow
}

func TestTOTP_VerifyAttemptLimit(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		racers int
		opts   []mfa.TOTPOption
		assert func(t *testing.T, compared int)
	}

	cases := []testCase{
		{
			name:   "the default limit is 5",
			racers: mfa.DefaultVerifyAttemptLimit + 1,
			assert: func(t *testing.T, compared int) {
				assert.Equal(t, mfa.DefaultVerifyAttemptLimit, compared)
			},
		},
		{
			name:   "consumer limit",
			racers: 4,
			opts:   []mfa.TOTPOption{mfa.WithVerifyAttempts(3, 10*time.Minute)},
			assert: func(t *testing.T, compared int) {
				assert.Equal(t, 3, compared)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			compared, _ := raceWrongCodes(t, tc.racers, tc.opts...)
			tc.assert(t, compared)
		})
	}
}

func TestTOTP_ConcurrentWrongCodesAreComparedAtMostTheLimit(t *testing.T) {
	t.Parallel()

	compared, validNow := raceWrongCodes(t, 20)

	assert.LessOrEqual(t, compared, mfa.DefaultVerifyAttemptLimit,
		"wrong codes compared against one enrolment")
	assert.ErrorIs(t, validNow(), mfa.ErrVerifyAttemptsExhausted,
		"a valid code in the same window after the limit is spent")
}

// errChargeBoom is a store that cannot charge or give back an attempt.
var errChargeBoom = errors.New("totpattempts_test: store unreachable")

// attemptsFixture is one TOTP method over one store, with its fake clock and a
// capture of what it logged.
type attemptsFixture struct {
	store  mfa.EnrolmentStore
	totp   *mfa.TOTP
	clk    *clockwork.FakeClock
	logs   *lockedWriter
	buf    *bytes.Buffer
	user   identity.UserID
	secret []byte
}

// newAttemptsFixture builds the method over store, or over a memory store
// holding a confirmed enrolment for the fixture's user when store is nil.
func newAttemptsFixture(t *testing.T, store mfa.EnrolmentStore, opts ...mfa.TOTPOption) *attemptsFixture {
	t.Helper()

	f := &attemptsFixture{
		clk:    clockwork.NewFakeClockAt(attemptsEpoch),
		buf:    &bytes.Buffer{},
		user:   "u-1",
		secret: []byte(rfc6238SHA1Secret),
	}
	f.logs = &lockedWriter{w: f.buf}

	if store == nil {
		mem := mfa.NewMemoryEnrolmentStore()
		enrolConfirmed(t, mem, f.user, f.secret)
		store = mem
	}

	f.store = store

	logger := slog.New(slog.NewJSONHandler(f.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	m, err := mfa.NewTOTP(store, "scrty-test",
		append([]mfa.TOTPOption{mfa.WithClock(f.clk), mfa.WithTOTPLogger(logger)}, opts...)...)
	require.NoError(t, err)

	f.totp = m

	return f
}

// valid is the code an authenticator shows now.
func (f *attemptsFixture) valid(t *testing.T) []byte {
	t.Helper()

	return []byte(codeAt(t, f.secret, f.clk.Now(), 6, 30*time.Second))
}

// wrong is a well-formed code no step accepted now matches.
func (f *attemptsFixture) wrong(t *testing.T) []byte {
	t.Helper()

	return []byte(wrongCodeAt(t, f.secret, f.clk.Now()))
}

// attempts reads how many attempts the enrolment has charged.
func (f *attemptsFixture) attempts(t *testing.T) int {
	t.Helper()

	e, ok, err := f.store.Get(t.Context(), f.user)
	require.NoError(t, err)
	require.True(t, ok)

	return e.VerifyAttempts
}

// confirmedEnrolment is the record a mock store hands back for a user who
// has proved the factor.
func confirmedEnrolment(user identity.UserID) mfa.Enrolment {
	return mfa.Enrolment{
		User:        user,
		Secret:      []byte(rfc6238SHA1Secret),
		CreatedAt:   attemptsEpoch.Add(-time.Hour),
		ConfirmedAt: attemptsEpoch.Add(-time.Hour),
	}
}

func TestTOTP_VerifyCharges(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		store   func(t *testing.T, ctrl *gomock.Controller) mfa.EnrolmentStore // nil: memory, confirmed
		opts    []mfa.TOTPOption
		prepare func(t *testing.T, f *attemptsFixture)
		code    func(t *testing.T, f *attemptsFixture) []byte
		assert  func(t *testing.T, f *attemptsFixture, err error)
	}

	wrong := func(t *testing.T, f *attemptsFixture) []byte { return f.wrong(t) }
	valid := func(t *testing.T, f *attemptsFixture) []byte { return f.valid(t) }

	cases := []testCase{
		{
			name: "malformed code is charged",
			code: func(*testing.T, *attemptsFixture) []byte { return []byte("12") },
			assert: func(t *testing.T, f *attemptsFixture, err error) {
				require.ErrorIs(t, err, mfa.ErrInvalidCode)
				assert.Equal(t, 1, f.attempts(t))
			},
		},
		{
			name: "wrong code is charged",
			code: wrong,
			assert: func(t *testing.T, f *attemptsFixture, err error) {
				require.ErrorIs(t, err, mfa.ErrInvalidCode)
				assert.Equal(t, 1, f.attempts(t))
			},
		},
		{
			name: "pending enrolment is not charged",
			store: func(t *testing.T, _ *gomock.Controller) mfa.EnrolmentStore {
				mem := mfa.NewMemoryEnrolmentStore()
				require.NoError(t, mem.PutPending(t.Context(), mfa.Enrolment{
					User: "u-1", Secret: []byte(rfc6238SHA1Secret),
				}))

				return mem
			},
			code: valid,
			assert: func(t *testing.T, f *attemptsFixture, err error) {
				require.ErrorIs(t, err, mfa.ErrInvalidCode)
				require.NotErrorIs(t, err, mfa.ErrVerifyThrottled)
				assert.Equal(t, 0, f.attempts(t))
			},
		},
		{
			name: "absent enrolment is not charged",
			store: func(_ *testing.T, ctrl *gomock.Controller) mfa.EnrolmentStore {
				s := NewMockEnrolmentStore(ctrl)
				s.EXPECT().Get(gomock.Any(), identity.UserID("u-1")).Return(mfa.Enrolment{}, false, nil)

				return s
			},
			code: wrong,
			assert: func(t *testing.T, _ *attemptsFixture, err error) {
				require.ErrorIs(t, err, mfa.ErrInvalidCode)
				require.NotErrorIs(t, err, mfa.ErrVerifyThrottled)
			},
		},
		{
			name: "refused charge is not compared",
			store: func(_ *testing.T, ctrl *gomock.Controller) mfa.EnrolmentStore {
				s := NewMockEnrolmentStore(ctrl)
				s.EXPECT().Get(gomock.Any(), identity.UserID("u-1")).Return(confirmedEnrolment("u-1"), true, nil)
				s.EXPECT().
					ChargeVerifyAttempt(gomock.Any(), identity.UserID("u-1"), attemptsEpoch,
						mfa.DefaultVerifyAttemptLimit, mfa.DefaultVerifyAttemptWindow).
					Return(time.Time{}, false, nil)

				return s
			},
			code: valid,
			assert: func(t *testing.T, _ *attemptsFixture, err error) {
				require.ErrorIs(t, err, mfa.ErrVerifyAttemptsExhausted)
				require.ErrorIs(t, err, mfa.ErrVerifyThrottled)
				require.NotErrorIs(t, err, mfa.ErrInvalidCode)
			},
		},
		{
			name: "store failure while charging",
			store: func(_ *testing.T, ctrl *gomock.Controller) mfa.EnrolmentStore {
				s := NewMockEnrolmentStore(ctrl)
				s.EXPECT().Get(gomock.Any(), identity.UserID("u-1")).Return(confirmedEnrolment("u-1"), true, nil)
				s.EXPECT().
					ChargeVerifyAttempt(gomock.Any(), identity.UserID("u-1"), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(time.Time{}, false, errChargeBoom)

				return s
			},
			code: wrong,
			assert: func(t *testing.T, _ *attemptsFixture, err error) {
				require.ErrorIs(t, err, errChargeBoom)
				require.NotErrorIs(t, err, mfa.ErrInvalidCode)
				require.NotErrorIs(t, err, mfa.ErrVerifyThrottled)
				assert.True(t, strings.HasPrefix(err.Error(), "mfa:"), "text %q is not the package's own", err)
				assert.NotContains(t, err.Error(), errChargeBoom.Error())
			},
		},
		{
			name: "a spent window refuses even a valid code",
			prepare: func(t *testing.T, f *attemptsFixture) {
				for range mfa.DefaultVerifyAttemptLimit {
					require.ErrorIs(t, f.totp.Verify(t.Context(), f.user, f.wrong(t)), mfa.ErrInvalidCode)
				}
			},
			code: valid,
			assert: func(t *testing.T, f *attemptsFixture, err error) {
				require.ErrorIs(t, err, mfa.ErrVerifyAttemptsExhausted)
				assert.Equal(t, mfa.DefaultVerifyAttemptLimit, f.attempts(t))
			},
		},
		{
			name: "a consumer window opens anew at its own end",
			opts: []mfa.TOTPOption{mfa.WithVerifyAttempts(1, 10*time.Minute)},
			prepare: func(t *testing.T, f *attemptsFixture) {
				require.ErrorIs(t, f.totp.Verify(t.Context(), f.user, f.wrong(t)), mfa.ErrInvalidCode)
				f.clk.Advance(10 * time.Minute)
			},
			code: wrong,
			assert: func(t *testing.T, f *attemptsFixture, err error) {
				require.ErrorIs(t, err, mfa.ErrInvalidCode)
				assert.Equal(t, 1, f.attempts(t))
			},
		},
		{
			name: "a new window admits a valid code",
			prepare: func(t *testing.T, f *attemptsFixture) {
				for range mfa.DefaultVerifyAttemptLimit {
					require.ErrorIs(t, f.totp.Verify(t.Context(), f.user, f.wrong(t)), mfa.ErrInvalidCode)
				}

				require.ErrorIs(t, f.totp.Verify(t.Context(), f.user, f.wrong(t)), mfa.ErrVerifyAttemptsExhausted)

				f.clk.Advance(16 * time.Minute)
			},
			code: valid,
			assert: func(t *testing.T, _ *attemptsFixture, err error) {
				require.NoError(t, err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)

			var store mfa.EnrolmentStore
			if tc.store != nil {
				store = tc.store(t, ctrl)
			}

			f := newAttemptsFixture(t, store, tc.opts...)
			if tc.prepare != nil {
				tc.prepare(t, f)
			}

			err := f.totp.Verify(t.Context(), f.user, tc.code(t, f))
			tc.assert(t, f, err)
		})
	}
}

// cancelOnChargeKey carries, in a request context, the function that cancels
// it, so a store can end the request between the charge and the give-back.
type cancelOnChargeKey struct{}

// cancellingStore cancels the request after charging, and refuses a give-back
// on an ended context, as a store reaching a database through it would.
type cancellingStore struct {
	mfa.EnrolmentStore
}

func (s cancellingStore) ChargeVerifyAttempt(
	ctx context.Context, user identity.UserID, at time.Time, limit int, window time.Duration,
) (time.Time, bool, error) {
	until, ok, err := s.EnrolmentStore.ChargeVerifyAttempt(ctx, user, at, limit, window)
	if cancel, has := ctx.Value(cancelOnChargeKey{}).(context.CancelFunc); has {
		cancel()
	}

	return until, ok, err
}

func (s cancellingStore) RefundVerifyAttempt(ctx context.Context, user identity.UserID, until time.Time) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}

	return s.EnrolmentStore.RefundVerifyAttempt(ctx, user, until)
}

// warnRecords counts the WARN records the fixture's method wrote.
func (f *attemptsFixture) warnRecords() int {
	f.logs.mu.Lock()
	defer f.logs.mu.Unlock()

	return strings.Count(f.buf.String(), `"level":"WARN"`)
}

func TestTOTP_VerifyGivesBack(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		store   func(t *testing.T, ctrl *gomock.Controller) mfa.EnrolmentStore // nil: memory, confirmed
		ctx     func(ctx context.Context) context.Context
		prepare func(t *testing.T, f *attemptsFixture)
		code    func(t *testing.T, f *attemptsFixture) []byte
		assert  func(t *testing.T, f *attemptsFixture, err error)
	}

	valid := func(t *testing.T, f *attemptsFixture) []byte { return f.valid(t) }

	cases := []testCase{
		{
			name: "successes spend nothing",
			prepare: func(t *testing.T, f *attemptsFixture) {
				for range mfa.DefaultVerifyAttemptLimit + 1 {
					require.NoError(t, f.totp.Verify(t.Context(), f.user, f.valid(t)))
					f.clk.Advance(30 * time.Second)
				}
			},
			code: valid,
			assert: func(t *testing.T, f *attemptsFixture, err error) {
				require.NoError(t, err)
				assert.Equal(t, 0, f.attempts(t))
			},
		},
		{
			name: "replayed step keeps its charge",
			prepare: func(t *testing.T, f *attemptsFixture) {
				require.NoError(t, f.totp.Verify(t.Context(), f.user, f.valid(t)))
			},
			code: valid,
			assert: func(t *testing.T, f *attemptsFixture, err error) {
				require.ErrorIs(t, err, mfa.ErrInvalidCode)
				assert.Equal(t, 1, f.attempts(t))
			},
		},
		{
			name: "give-back failure is logged and does not refuse",
			store: func(_ *testing.T, ctrl *gomock.Controller) mfa.EnrolmentStore {
				until := attemptsEpoch.Add(mfa.DefaultVerifyAttemptWindow)
				s := NewMockEnrolmentStore(ctrl)
				s.EXPECT().Get(gomock.Any(), identity.UserID("u-1")).Return(confirmedEnrolment("u-1"), true, nil)
				s.EXPECT().
					ChargeVerifyAttempt(gomock.Any(), identity.UserID("u-1"), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(until, true, nil)
				s.EXPECT().AcceptStep(gomock.Any(), identity.UserID("u-1"), gomock.Any()).Return(true, nil)
				s.EXPECT().RefundVerifyAttempt(gomock.Any(), identity.UserID("u-1"), until).Return(false, errChargeBoom)

				return s
			},
			code: valid,
			assert: func(t *testing.T, f *attemptsFixture, err error) {
				require.NoError(t, err)
				assert.Equal(t, 1, f.warnRecords())

				f.logs.mu.Lock()
				defer f.logs.mu.Unlock()
				assert.Contains(t, f.buf.String(), `"reason":"enrolment-store"`)
				assert.Contains(t, f.buf.String(), `"error_type":"*errors.errorString"`)
				assert.NotContains(t, f.buf.String(), errChargeBoom.Error(), "a store's error text is never logged")
			},
		},
		{
			name: "cancelled context still gives back",
			store: func(t *testing.T, _ *gomock.Controller) mfa.EnrolmentStore {
				mem := mfa.NewMemoryEnrolmentStore()
				enrolConfirmed(t, mem, "u-1", []byte(rfc6238SHA1Secret))

				return cancellingStore{EnrolmentStore: mem}
			},
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)

				return context.WithValue(cctx, cancelOnChargeKey{}, cancel)
			},
			code: valid,
			assert: func(t *testing.T, f *attemptsFixture, err error) {
				require.NoError(t, err)
				assert.Equal(t, 0, f.attempts(t))
				assert.Zero(t, f.warnRecords())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)

			var store mfa.EnrolmentStore
			if tc.store != nil {
				store = tc.store(t, ctrl)
			}

			f := newAttemptsFixture(t, store)
			if tc.prepare != nil {
				tc.prepare(t, f)
			}

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			err := f.totp.Verify(ctx, f.user, tc.code(t, f))
			tc.assert(t, f, err)
		})
	}
}
