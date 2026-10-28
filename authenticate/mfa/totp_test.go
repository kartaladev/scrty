package mfa_test

import (
	"bytes"
	"context"
	"encoding/base32"
	"errors"
	"io"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
)

// rfc6238SHA1Secret is the ASCII seed RFC 6238 Appendix B uses for HMAC-SHA-1,
// "12345678901234567890", which an enrolment carries as raw bytes and a
// provisioning URI as base32.
const rfc6238SHA1Secret = "12345678901234567890"

// countingEnrolmentStore counts the calls that decide acceptance, so a test can
// assert that a code refused on its form never reached the store at all.
type countingEnrolmentStore struct {
	mfa.EnrolmentStore

	acceptStep atomic.Int64
}

func (s *countingEnrolmentStore) AcceptStep(
	ctx context.Context, user identity.UserID, gen id.ID, step int64,
) (bool, error) {
	s.acceptStep.Add(1)

	return s.EnrolmentStore.AcceptStep(ctx, user, gen, step)
}

func (s *countingEnrolmentStore) AcceptStepCalls() int64 { return s.acceptStep.Load() }

func TestTOTPRFC6238Vectors(t *testing.T) {
	t.Parallel()

	type testCase struct {
		unix int64
		code string
	}

	// Appendix B, the SHA-1 rows, at 8 digits.
	cases := []testCase{
		{unix: 59, code: "94287082"},
		{unix: 1111111109, code: "07081804"},
		{unix: 1111111111, code: "14050471"},
		{unix: 1234567890, code: "89005924"},
		{unix: 2000000000, code: "69279037"},
		{unix: 20000000000, code: "65353130"},
	}

	for _, tc := range cases {
		t.Run(strconv.FormatInt(tc.unix, 10), func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			at := time.Unix(tc.unix, 0).UTC()
			store := mfa.NewMemoryEnrolmentStore()

			m, err := mfa.NewTOTP(store, "Example",
				mfa.WithDigits(8),
				mfa.WithClock(clockwork.NewFakeClockAt(at)),
			)
			require.NoError(t, err)

			enrolConfirmed(t, store, "u-1", []byte(rfc6238SHA1Secret))

			assert.NoError(t, m.Verify(ctx, "u-1", []byte(tc.code)))
		})
	}
}

func TestTOTPStepWindow(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)

	type testCase struct {
		name   string
		offset time.Duration
		mutate func(code string) string
		assert func(t *testing.T, err error)
	}

	ok := func(t *testing.T, err error) { assert.NoError(t, err) }
	invalid := func(t *testing.T, err error) { assert.ErrorIs(t, err, mfa.ErrInvalidCode) }

	cases := []testCase{
		{name: "the current step", offset: 0, assert: ok},
		{name: "one step back", offset: -30 * time.Second, assert: ok},
		{name: "one step forward", offset: 30 * time.Second, assert: ok},
		{name: "two steps back", offset: -60 * time.Second, assert: invalid},
		{name: "two steps forward", offset: 60 * time.Second, assert: invalid},
		{
			name:   "a wrong code",
			mutate: func(string) string { return "000000" },
			assert: invalid,
		},
		{name: "too few digits", mutate: func(c string) string { return c[:5] }, assert: invalid},
		{name: "too many digits", mutate: func(c string) string { return c + "0" }, assert: invalid},
		{name: "not digits", mutate: func(string) string { return "12345a" }, assert: invalid},
		{name: "a signed number", mutate: func(string) string { return "+12345" }, assert: invalid},
		{name: "unicode digits", mutate: func(string) string { return "١٢٣٤٥٦" }, assert: invalid},
		{name: "empty", mutate: func(string) string { return "" }, assert: invalid},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			store := &countingEnrolmentStore{EnrolmentStore: mfa.NewMemoryEnrolmentStore()}
			m, err := mfa.NewTOTP(store, "Example",
				mfa.WithClock(clockwork.NewFakeClockAt(base)),
			)
			require.NoError(t, err)

			secret := []byte(rfc6238SHA1Secret)
			enrolConfirmed(t, store, "u-1", secret)

			code := codeAt(t, secret, base.Add(tc.offset), 6, 30*time.Second)
			if tc.mutate != nil {
				code = tc.mutate(code)
			}

			before := store.AcceptStepCalls()
			tc.assert(t, m.Verify(ctx, "u-1", []byte(code)))

			if tc.mutate != nil {
				assert.Equal(t, before, store.AcceptStepCalls(),
					"a malformed or wrong code must not reach the store")
			}
		})
	}
}

func TestTOTPDeclarations(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		assert func(t *testing.T, m *mfa.TOTP)
	}

	cases := []testCase{
		{
			name: "named totp",
			assert: func(t *testing.T, m *mfa.TOTP) {
				assert.Equal(t, "totp", m.Name())
			},
		},
		{
			name: "responds with the code form field of up to 4 KiB",
			assert: func(t *testing.T, m *mfa.TOTP) {
				assert.Equal(t, mfa.FormField("code", 4<<10), m.Response())
				assert.Equal(t, mfa.ResponseFormField, m.Response().Kind())
				assert.Equal(t, "code", m.Response().Field())
				assert.Equal(t, int64(4<<10), m.Response().Limit())
			},
		},
		{
			name: "verifies a valid code handed over as bytes",
			assert: func(t *testing.T, m *mfa.TOTP) {
				// u-1 is enrolled on the RFC 6238 secret by the subtest body.
				at := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
				code := codeAt(t, []byte(rfc6238SHA1Secret), at, 6, 30*time.Second)
				assert.NoError(t, m.Verify(t.Context(), "u-1", []byte(code)))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := mfa.NewMemoryEnrolmentStore()
			m, err := mfa.NewTOTP(store, "Example",
				mfa.WithClock(clockwork.NewFakeClockAt(time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC))),
			)
			require.NoError(t, err)
			enrolConfirmed(t, store, "u-1", []byte(rfc6238SHA1Secret))

			tc.assert(t, m)
		})
	}
}

// TestNewTOTP_RefusesSubSecondPeriod pins that a period which is not a whole
// number of seconds, at least one, is refused at construction: a shorter one
// truncates to a zero-second step and divides by it at the first code, and a
// fractional one is silently truncated, so codes would follow a step the
// consumer never configured.
func TestNewTOTP_RefusesSubSecondPeriod(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 24, 10, 0, 15, 0, time.UTC)

	type testCase struct {
		name   string
		period time.Duration
		assert func(t *testing.T, err error)
	}

	refused := func(t *testing.T, err error) {
		t.Helper()
		require.ErrorIs(t, err, mfa.ErrConfig)
	}

	cases := []testCase{
		{name: "half a second", period: 500 * time.Millisecond, assert: refused},
		{name: "a fraction above a whole second", period: 45*time.Second + 500*time.Millisecond, assert: refused},
		{
			name:   "one second is the shortest accepted",
			period: time.Second,
			assert: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			var err error
			assert.NotPanics(t, func() {
				var m *mfa.TOTP
				m, err = mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example",
					mfa.WithPeriod(tc.period), mfa.WithClock(clockwork.NewFakeClockAt(now)))
				if err != nil {
					return
				}

				// A method that was built must also survive its first code.
				p, beginErr := m.BeginEnrolment(ctx, "u-1", "alice")
				require.NoError(t, beginErr)
				_ = m.ConfirmEnrolment(ctx, "u-1", codeForSecret(t, p.Secret, now))
			})

			tc.assert(t, err)
		})
	}
}

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
func raceWrongCodes(t *testing.T, racers int, opts ...mfa.Option) (int, func() error) {
	t.Helper()

	ctx := t.Context()
	clk := clockwork.NewFakeClockAt(attemptsEpoch)
	store := mfa.NewMemoryEnrolmentStore()
	totp, err := mfa.NewTOTP(store, "scrty-test", append([]mfa.Option{mfa.WithClock(clk)}, opts...)...)
	require.NoError(t, err)

	user := identity.UserID("u-1")
	secret := []byte(rfc6238SHA1Secret)
	enrolConfirmed(t, store, user, secret)
	wrong := wrongCodeAt(t, secret, clk.Now())

	throttle, err := mfa.NewVerifyThrottle(mfa.WithThrottleLimiter(newBarrierLimiter(racers)))
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
		opts   []mfa.Option
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
			opts:   []mfa.Option{mfa.WithVerifyAttempts(3, 10*time.Minute)},
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

// Standalone: it races wrong codes against one enrolment from many goroutines.
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
func newAttemptsFixture(t *testing.T, store mfa.EnrolmentStore, opts ...mfa.Option) *attemptsFixture {
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
		append([]mfa.Option{mfa.WithClock(f.clk), mfa.WithLogger(logger)}, opts...)...)
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
		opts    []mfa.Option
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
			opts: []mfa.Option{mfa.WithVerifyAttempts(1, 10*time.Minute)},
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
				s.EXPECT().AcceptStep(gomock.Any(), identity.UserID("u-1"), gomock.Any(), gomock.Any()).Return(true, nil)
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

// failingReader is a random source that cannot produce bytes.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("entropy pool exhausted") }

func TestTOTPBeginEnrolment(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		label  string
		random io.Reader
		assert func(t *testing.T, p mfa.Provisioning, err error, stored bool)
	}

	refused := func(t *testing.T, p mfa.Provisioning, err error, stored bool) {
		require.Error(t, err)
		assert.False(t, stored)
		assert.Empty(t, p.Secret)
	}

	cases := []testCase{
		{
			name:  "the URI names the issuer, the label and the parameters",
			label: "ada@example.com",
			assert: func(t *testing.T, p mfa.Provisioning, err error, stored bool) {
				require.NoError(t, err)
				assert.True(t, stored)

				u, parseErr := url.Parse(p.URI)
				require.NoError(t, parseErr)

				assert.Equal(t, "otpauth", u.Scheme)
				assert.Equal(t, "totp", u.Host)
				assert.Equal(t, "/Example Payroll:ada@example.com", u.Path)
				assert.Equal(t, "Example Payroll", u.Query().Get("issuer"))
				assert.Equal(t, "SHA1", u.Query().Get("algorithm"))
				assert.Equal(t, "6", u.Query().Get("digits"))
				assert.Equal(t, "30", u.Query().Get("period"))
				assert.Equal(t, p.Secret, u.Query().Get("secret"))

				raw, decErr := base32.StdEncoding.WithPadding(base32.NoPadding).
					DecodeString(p.Secret)
				require.NoError(t, decErr)
				assert.Len(t, raw, 20, "20 bytes from the OS random source")

				assert.NotContains(t, p.URI, "u-1",
					"the label is the consumer's, never the user reference")
			},
		},
		{
			name:  "a label needing escaping survives",
			label: "ada+payroll@example.com",
			assert: func(t *testing.T, p mfa.Provisioning, err error, stored bool) {
				require.NoError(t, err)
				assert.True(t, stored)

				u, parseErr := url.Parse(p.URI)
				require.NoError(t, parseErr)
				assert.Equal(t, "/Example Payroll:ada+payroll@example.com", u.Path)
			},
		},
		{name: "an empty label is refused", label: "", assert: refused},
		{name: "a label with a colon is refused", label: "ada:example", assert: refused},
		{
			name:   "a random source failure stores nothing",
			label:  "ada@example.com",
			random: failingReader{},
			assert: func(t *testing.T, p mfa.Provisioning, err error, stored bool) {
				require.Error(t, err)
				assert.False(t, stored, "no pending enrolment may be written")
				assert.Empty(t, p.Secret)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			store := mfa.NewMemoryEnrolmentStore()

			opts := []mfa.Option{}
			if tc.random != nil {
				opts = append(opts, mfa.WithRandom(tc.random))
			}

			m, err := mfa.NewTOTP(store, "Example Payroll", opts...)
			require.NoError(t, err)

			p, beginErr := m.BeginEnrolment(ctx, "u-1", tc.label)

			_, stored, getErr := store.Get(ctx, "u-1")
			require.NoError(t, getErr)

			tc.assert(t, p, beginErr, stored)
		})
	}
}

func TestTOTPConfirmEnrolment(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)

	type testCase struct {
		name   string
		code   func(t *testing.T, secret string) string
		assert func(t *testing.T, m *mfa.TOTP, err error)
	}

	cases := []testCase{
		{
			name: "a valid code confirms",
			code: func(t *testing.T, secret string) string { return codeForSecret(t, secret, base) },
			assert: func(t *testing.T, m *mfa.TOTP, err error) {
				require.NoError(t, err)

				enrolled, lookupErr := m.Enrolled(t.Context(), "u-1")
				require.NoError(t, lookupErr)
				assert.True(t, enrolled)
			},
		},
		{
			name: "a wrong code does not",
			code: func(*testing.T, string) string { return "000000" },
			assert: func(t *testing.T, m *mfa.TOTP, err error) {
				assert.ErrorIs(t, err, mfa.ErrInvalidCode)

				enrolled, lookupErr := m.Enrolled(t.Context(), "u-1")
				require.NoError(t, lookupErr)
				assert.False(t, enrolled)
			},
		},
		{
			name: "a malformed code does not",
			code: func(*testing.T, string) string { return "12345a" },
			assert: func(t *testing.T, m *mfa.TOTP, err error) {
				assert.ErrorIs(t, err, mfa.ErrInvalidCode)

				enrolled, lookupErr := m.Enrolled(t.Context(), "u-1")
				require.NoError(t, lookupErr)
				assert.False(t, enrolled)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			m, err := mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example",
				mfa.WithClock(clockwork.NewFakeClockAt(base)))
			require.NoError(t, err)

			p, err := m.BeginEnrolment(ctx, "u-1", "ada@example.com")
			require.NoError(t, err)

			pending, err := m.Enrolled(ctx, "u-1")
			require.NoError(t, err)
			require.False(t, pending, "a pending enrolment is not an enrolment")

			tc.assert(t, m, m.ConfirmEnrolment(ctx, "u-1", tc.code(t, p.Secret)))
		})
	}
}

// TestTOTPConfirmEnrolmentUnknown pins the two shapes that have no pending
// enrolment to confirm at all, which the table above always has.
// Standalone: it confirms with no pending enrolment, unlike every case of TestTOTPConfirmEnrolment.
func TestTOTPConfirmEnrolmentUnknown(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)

	m, err := mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example",
		mfa.WithClock(clockwork.NewFakeClockAt(base)))
	require.NoError(t, err)

	assert.ErrorIs(t, m.ConfirmEnrolment(ctx, "nobody", "123456"), mfa.ErrInvalidCode)

	p, err := m.BeginEnrolment(ctx, "u-1", "ada@example.com")
	require.NoError(t, err)

	code := codeForSecret(t, p.Secret, base)
	require.NoError(t, m.ConfirmEnrolment(ctx, "u-1", code))
	assert.ErrorIs(t, m.ConfirmEnrolment(ctx, "u-1", code), mfa.ErrInvalidCode,
		"there is nothing pending to confirm a second time")
}

// Standalone: it begins, begins again and confirms in sequence over one store.
func TestTOTPBeginEnrolmentTwice(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	store := mfa.NewMemoryEnrolmentStore()

	m, err := mfa.NewTOTP(store, "Example", mfa.WithClock(clockwork.NewFakeClockAt(base)))
	require.NoError(t, err)

	first, err := m.BeginEnrolment(ctx, "u-1", "ada@example.com")
	require.NoError(t, err)

	second, err := m.BeginEnrolment(ctx, "u-1", "ada@example.com")
	require.NoError(t, err, "a pending enrolment is replaced")
	assert.NotEqual(t, first.Secret, second.Secret)

	require.NoError(t, m.ConfirmEnrolment(ctx, "u-1", codeForSecret(t, second.Secret, base)))

	_, err = m.BeginEnrolment(ctx, "u-1", "ada@example.com")
	assert.ErrorIs(t, err, mfa.ErrAlreadyEnrolled)

	// The existing authenticator still works: nothing was replaced.
	later := base.Add(time.Minute)

	m2, err := mfa.NewTOTP(store, "Example", mfa.WithClock(clockwork.NewFakeClockAt(later)))
	require.NoError(t, err)
	assert.NoError(t, m2.Verify(ctx, "u-1", []byte(codeForSecret(t, second.Secret, later))))
}

func TestTOTPRemoveEnrolment(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	store := mfa.NewMemoryEnrolmentStore()

	m, err := mfa.NewTOTP(store, "Example", mfa.WithClock(clockwork.NewFakeClockAt(base)))
	require.NoError(t, err)

	p, err := m.BeginEnrolment(ctx, "u-1", "ada@example.com")
	require.NoError(t, err)
	require.NoError(t, m.ConfirmEnrolment(ctx, "u-1", codeForSecret(t, p.Secret, base)))

	required := &stubRequirement{required: map[identity.UserID]bool{"u-1": true}}

	require.NoError(t, m.RemoveEnrolment(ctx, "u-1"))

	enrolled, err := m.Enrolled(ctx, "u-1")
	require.NoError(t, err)
	assert.False(t, enrolled)

	stillRequired, err := required.Required(ctx, "u-1")
	require.NoError(t, err)
	assert.True(t, stillRequired, "removing an enrolment cannot clear the requirement")

	require.NoError(t, m.RemoveEnrolment(ctx, "u-1"), "removing nothing is not an error")

	// And the user may enrol again, because nothing confirmed is left.
	_, err = m.BeginEnrolment(ctx, "u-1", "ada@example.com")
	assert.NoError(t, err)
}

// interleavingStore runs a hook once, just before the first Confirm or
// AcceptStep reaches the store, so a test can land another session's writes
// between the method's read and its write.
type interleavingStore struct {
	mfa.EnrolmentStore

	beforeConfirm func()
	beforeAccept  func()

	confirmOnce, acceptOnce sync.Once
}

func (s *interleavingStore) Confirm(
	ctx context.Context, user identity.UserID, gen id.ID, step int64, at time.Time,
) (bool, error) {
	if s.beforeConfirm != nil {
		s.confirmOnce.Do(s.beforeConfirm)
	}

	return s.EnrolmentStore.Confirm(ctx, user, gen, step, at)
}

func (s *interleavingStore) AcceptStep(
	ctx context.Context, user identity.UserID, gen id.ID, step int64,
) (bool, error) {
	if s.beforeAccept != nil {
		s.acceptOnce.Do(s.beforeAccept)
	}

	return s.EnrolmentStore.AcceptStep(ctx, user, gen, step)
}

// rawSecret decodes the base32 secret a provisioning hands back.
func rawSecret(t *testing.T, secret string) []byte {
	t.Helper()

	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	require.NoError(t, err)

	return raw
}

// TestConfirmEnrolment_NeverConfirmsASecretTheCodeWasNotFor lands a new begin
// between ConfirmEnrolment's read of secret A and its write: the code was
// checked against A, so it must confirm nothing, and above all not B.
// Standalone: it lands a begin inside ConfirmEnrolment through a hooked store.
func TestConfirmEnrolment_NeverConfirmsASecretTheCodeWasNotFor(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	now := time.Date(2026, 9, 24, 10, 0, 15, 0, time.UTC)
	inner := mfa.NewMemoryEnrolmentStore()
	store := &interleavingStore{EnrolmentStore: inner}
	m, err := mfa.NewTOTP(store, "Example", mfa.WithClock(clockwork.NewFakeClockAt(now)))
	require.NoError(t, err)

	first, err := m.BeginEnrolment(ctx, "u-1", "alice")
	require.NoError(t, err)

	var second mfa.Provisioning
	store.beforeConfirm = func() {
		var beginErr error
		second, beginErr = m.BeginEnrolment(ctx, "u-1", "alice")
		require.NoError(t, beginErr)
	}

	err = m.ConfirmEnrolment(ctx, "u-1", codeForSecret(t, first.Secret, now))
	require.ErrorIs(t, err, mfa.ErrInvalidCode, "a code checked against A must not confirm B")

	got, ok, err := inner.Get(ctx, "u-1")
	require.NoError(t, err)
	require.True(t, ok)
	assert.True(t, got.ConfirmedAt.IsZero(), "the enrolment must read as unconfirmed")
	assert.Equal(t, rawSecret(t, second.Secret), got.Secret, "the enrolment must hold secret B")
}

// TestVerify_RefusesCodeOfARemovedSecretAfterReEnrolment lands a removal and a
// confirmed re-enrolment between Verify's check of the old secret's code and
// its AcceptStep: the code belonged to a secret that no longer exists.
// Standalone: it lands a removal and re-enrolment inside Verify through a hooked store.
func TestVerify_RefusesCodeOfARemovedSecretAfterReEnrolment(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	now := time.Date(2026, 9, 24, 10, 0, 15, 0, time.UTC)
	before := now.Add(-30 * time.Second)
	inner := mfa.NewMemoryEnrolmentStore()
	store := &interleavingStore{EnrolmentStore: inner}
	m, err := mfa.NewTOTP(store, "Example", mfa.WithClock(clockwork.NewFakeClockAt(now)))
	require.NoError(t, err)

	old, err := m.BeginEnrolment(ctx, "u-1", "alice")
	require.NoError(t, err)
	require.NoError(t, m.ConfirmEnrolment(ctx, "u-1", codeForSecret(t, old.Secret, before)))

	store.beforeAccept = func() {
		require.NoError(t, m.RemoveEnrolment(ctx, "u-1"))
		renewed, beginErr := m.BeginEnrolment(ctx, "u-1", "alice")
		require.NoError(t, beginErr)
		require.NoError(t, m.ConfirmEnrolment(ctx, "u-1", codeForSecret(t, renewed.Secret, before)))
	}

	err = m.Verify(ctx, "u-1", []byte(codeForSecret(t, old.Secret, now)))
	require.ErrorIs(t, err, mfa.ErrInvalidCode, "a code of the removed secret must not be accepted")
}

func TestNewTOTP(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		store  mfa.EnrolmentStore
		issuer string
		opts   []mfa.Option
		assert func(t *testing.T, m *mfa.TOTP, err error)
	}

	configError := func(t *testing.T, m *mfa.TOTP, err error) {
		require.Error(t, err)
		assert.Nil(t, m)
	}

	// An absent time or random source is the package's configuration error,
	// so a consumer can tell a wiring mistake apart with errors.Is.
	sourceConfigError := func(t *testing.T, m *mfa.TOTP, err error) {
		require.ErrorIs(t, err, mfa.ErrConfig)
		assert.Nil(t, m)
	}

	namesIssuer := func(t *testing.T, m *mfa.TOTP, err error) {
		require.Error(t, err)
		assert.Nil(t, m)
		assert.Contains(t, strings.ToLower(err.Error()), "issuer")
	}

	cases := []testCase{
		{
			name:   "defaults",
			issuer: "Example Payroll",
			assert: func(t *testing.T, m *mfa.TOTP, err error) {
				require.NoError(t, err)
				assert.Equal(t, 6, m.Digits())
				assert.Equal(t, 30*time.Second, m.Period())
			},
		},
		{name: "no issuer", issuer: "", assert: namesIssuer},
		{name: "issuer with a colon", issuer: "Example: Payroll", assert: namesIssuer},
		{
			name:   "no store",
			store:  noStore{},
			issuer: "Example",
			assert: configError,
		},
		{
			name:   "a typed-nil store",
			store:  typedNilStore(),
			issuer: "Example",
			assert: configError,
		},
		{
			name:   "seven digits",
			issuer: "Example",
			opts:   []mfa.Option{mfa.WithDigits(7)},
			assert: configError,
		},
		{
			name:   "zero digits",
			issuer: "Example",
			opts:   []mfa.Option{mfa.WithDigits(0)},
			assert: configError,
		},
		{
			name:   "nil identifier generator",
			issuer: "Example",
			opts:   []mfa.Option{mfa.WithIDGenerator(nil)},
			assert: configError,
		},
		{
			name:   "zero period",
			issuer: "Example",
			opts:   []mfa.Option{mfa.WithPeriod(0)},
			assert: configError,
		},
		{
			name:   "negative period",
			issuer: "Example",
			opts:   []mfa.Option{mfa.WithPeriod(-time.Second)},
			assert: configError,
		},
		{
			name:   "zero verification attempts",
			issuer: "Example",
			opts:   []mfa.Option{mfa.WithVerifyAttempts(0, time.Minute)},
			assert: sourceConfigError,
		},
		{
			name:   "negative verification attempts",
			issuer: "Example",
			opts:   []mfa.Option{mfa.WithVerifyAttempts(-1, time.Minute)},
			assert: sourceConfigError,
		},
		{
			name:   "zero verification attempt window",
			issuer: "Example",
			opts:   []mfa.Option{mfa.WithVerifyAttempts(5, 0)},
			assert: sourceConfigError,
		},
		{
			name:   "negative verification attempt window",
			issuer: "Example",
			opts:   []mfa.Option{mfa.WithVerifyAttempts(5, -time.Minute)},
			assert: sourceConfigError,
		},
		{
			name:   "a consumer verification attempt limit",
			issuer: "Example",
			opts:   []mfa.Option{mfa.WithVerifyAttempts(3, 10*time.Minute)},
			assert: func(t *testing.T, m *mfa.TOTP, err error) {
				require.NoError(t, err)
				require.NotNil(t, m)
			},
		},
		{
			name:   "a nil clock",
			issuer: "Example",
			opts:   []mfa.Option{mfa.WithClock(nil)},
			assert: sourceConfigError,
		},
		{
			// A nil pointer inside the interface is refused like an untyped
			// nil, rather than read at the first verification.
			name:   "a typed-nil clock",
			issuer: "Example",
			opts:   []mfa.Option{mfa.WithClock((*nilClock)(nil))},
			assert: sourceConfigError,
		},
		{
			name:   "a consumer clock with only Now",
			issuer: "Example",
			opts:   []mfa.Option{mfa.WithClock(fixedClock{at: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)})},
			assert: func(t *testing.T, m *mfa.TOTP, err error) {
				require.NoError(t, err)
				require.NotNil(t, m)
			},
		},
		{
			name:   "a nil random source",
			issuer: "Example",
			opts:   []mfa.Option{mfa.WithRandom(nil)},
			assert: sourceConfigError,
		},
		{
			// *failAfterReader implements io.Reader through a pointer receiver,
			// so a nil one passed to WithRandom is an interface holding a nil
			// pointer: `t.random == nil` misses it, and only the reflect-based
			// check the constructor now uses catches it before the first draw
			// reads from a nil receiver.
			name:   "a typed-nil random source",
			issuer: "Example",
			opts:   []mfa.Option{mfa.WithRandom((*failAfterReader)(nil))},
			assert: sourceConfigError,
		},
		{
			name:   "a nil logger",
			issuer: "Example",
			opts:   []mfa.Option{mfa.WithLogger(nil)},
			assert: configError,
		},
		{
			name:   "eight digits and a consumer period",
			issuer: "Example",
			opts:   []mfa.Option{mfa.WithDigits(8), mfa.WithPeriod(60 * time.Second)},
			assert: func(t *testing.T, m *mfa.TOTP, err error) {
				require.NoError(t, err)
				assert.Equal(t, 8, m.Digits())
				assert.Equal(t, 60*time.Second, m.Period())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := tc.store
			if store == nil {
				store = mfa.NewMemoryEnrolmentStore()
			}

			if _, isNone := store.(noStore); isNone {
				store = nil
			}

			m, err := mfa.NewTOTP(store, tc.issuer, tc.opts...)
			tc.assert(t, m, err)
		})
	}
}

// noStore stands for "pass nil as the store" in a table whose zero value
// already means "use the default", so the two cases stay distinguishable.
type noStore struct{ mfa.EnrolmentStore }

// typedNilStore is a non-nil interface holding a nil pointer, the nil a plain
// comparison misses.
func typedNilStore() mfa.EnrolmentStore { return (*mfa.MemoryEnrolmentStore)(nil) }

func TestTOTPChannel(t *testing.T) {
	t.Parallel()

	m, err := mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example")
	require.NoError(t, err)

	assert.Equal(t, factor.AuthenticatorApp, m.Channel())

	for _, kind := range []factor.Kind{
		factor.Password, factor.Basic, factor.MagicLink, factor.OIDC, factor.APIKey,
	} {
		assert.NotEqual(t, m.Channel(), kind.Channel(),
			"an authenticator code must not arrive on any first factor's channel: %s", kind)
	}
}

// fixedClock is a consumer's own clock with only Now.
type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time { return c.at }

// Standalone: it presents the same code twice in sequence.
func TestTOTPReplay(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	store := mfa.NewMemoryEnrolmentStore()

	m, err := mfa.NewTOTP(store, "Example", mfa.WithClock(clockwork.NewFakeClockAt(base)))
	require.NoError(t, err)

	secret := []byte(rfc6238SHA1Secret)
	enrolConfirmed(t, store, "u-1", secret)

	code := codeAt(t, secret, base, 6, 30*time.Second)

	require.NoError(t, m.Verify(ctx, "u-1", []byte(code)), "the first presentation is accepted")
	assert.ErrorIs(t, m.Verify(ctx, "u-1", []byte(code)), mfa.ErrInvalidCode,
		"the same code within its step is refused")
}

// TestTOTPVerifyStoreFailure pins the other half of the refusal rule: an outage
// is returned as itself, so a caller can tell a refusal from a failure and
// never reports the user as simply not enrolled.
// Standalone: it builds TOTP over a store whose every call fails.
func TestTOTPVerifyStoreFailure(t *testing.T) {
	t.Parallel()

	outage := errors.New("dial tcp: connection refused")

	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)

	m, err := mfa.NewTOTP(failingEnrolmentStore{err: outage}, "Example",
		mfa.WithClock(clockwork.NewFakeClockAt(base)))
	require.NoError(t, err)

	err = m.Verify(t.Context(), "u-1", []byte("123456"))
	assert.ErrorIs(t, err, outage)
	assert.NotErrorIs(t, err, mfa.ErrInvalidCode)

	enrolled, err := m.Enrolled(t.Context(), "u-1")
	assert.ErrorIs(t, err, outage)
	assert.False(t, enrolled, "and the bool must not be read as an answer")
}

// Standalone: it races one valid code from many goroutines.
func TestTOTPVerifyRace(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	store := mfa.NewMemoryEnrolmentStore()

	m, err := mfa.NewTOTP(store, "Example", mfa.WithClock(clockwork.NewFakeClockAt(base)))
	require.NoError(t, err)

	secret := []byte(rfc6238SHA1Secret)
	enrolConfirmed(t, store, "u-1", secret)
	code := codeAt(t, secret, base, 6, 30*time.Second)

	const goroutines = 16

	var (
		wg       sync.WaitGroup
		accepted atomic.Int64
		start    = make(chan struct{})
	)

	wg.Add(goroutines)

	for range goroutines {
		go func() {
			defer wg.Done()
			<-start

			if m.Verify(ctx, "u-1", []byte(code)) == nil {
				accepted.Add(1)
			}
		}()
	}

	close(start)
	wg.Wait()

	assert.Equal(t, int64(1), accepted.Load(), "exactly one of sixteen may succeed")
}

// The code that proved a device on the enrolment path must never be accepted
// again. The single-call confirm refuses a path-proven enrolment, but the
// store's Confirm can still reach it (the stated limit of that call: a proof
// landing between its read and its write) with the step before, which the
// window admits; that must not move the recorded step backwards below the
// proving one.
// Standalone: it drives the store's own ProveDevice and Confirm between TOTP calls.
func TestTOTPProvingCodeNotReplayableAfterConfirm(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 24, 10, 0, 15, 0, time.UTC)
	store := mfa.NewMemoryEnrolmentStore()
	m, err := mfa.NewTOTP(store, "Example", mfa.WithClock(clockwork.NewFakeClockAt(now)))
	require.NoError(t, err)

	_, gen, err := m.BeginEnrolmentGeneration(t.Context(), "u-1", "alice")
	require.NoError(t, err)
	e, _, err := store.Get(t.Context(), "u-1")
	require.NoError(t, err)

	proved, err := store.ProveDevice(t.Context(), "u-1", gen, now.Unix()/30, nil, time.Time{}, now)
	require.NoError(t, err)
	require.True(t, proved)

	previous := codeAt(t, e.Secret, now.Add(-30*time.Second), 6, 30*time.Second)
	require.ErrorIs(t, m.ConfirmEnrolment(t.Context(), "u-1", previous), mfa.ErrInvalidCode,
		"a path-proven enrolment completes only through the path")

	confirmed, err := store.Confirm(t.Context(), "u-1", gen, now.Unix()/30-1, now)
	require.NoError(t, err)
	require.True(t, confirmed)

	proving := codeAt(t, e.Secret, now, 6, 30*time.Second)
	assert.Error(t, m.Verify(t.Context(), "u-1", []byte(proving)),
		"the code that proved the device was accepted again")
}

func TestMFALogsCarryNoSecrets(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	store := mfa.NewMemoryEnrolmentStore()

	m, err := mfa.NewTOTP(store, "Example",
		mfa.WithClock(clockwork.NewFakeClockAt(base)),
		mfa.WithLogger(logger),
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
