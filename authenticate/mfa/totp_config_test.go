package mfa_test

import (
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/pkg/id"
)

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

// TestMFAConstructors_ErrorsAreConfigErrors pins that every construction
// failure of the TOTP method and the verification throttle matches ErrConfig,
// whatever parameter caused it.
func TestMFAConstructors_ErrorsAreConfigErrors(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		build  func() error
		assert func(t *testing.T, err error)
	}

	configError := func(t *testing.T, err error) {
		t.Helper()
		require.ErrorIs(t, err, mfa.ErrConfig)
	}

	totp := func(store mfa.EnrolmentStore, issuer string, opts ...mfa.TOTPOption) func() error {
		return func() error {
			_, err := mfa.NewTOTP(store, issuer, opts...)
			return err
		}
	}
	store := mfa.NewMemoryEnrolmentStore()

	cases := []testCase{
		{name: "totp: nil store", build: totp(nil, "Example"), assert: configError},
		{name: "totp: typed nil store", build: totp((*mfa.MemoryEnrolmentStore)(nil), "Example"), assert: configError},
		{name: "totp: empty issuer", build: totp(store, ""), assert: configError},
		{name: "totp: issuer containing ':'", build: totp(store, "Ex:ample"), assert: configError},
		{name: "totp: 7 digits", build: totp(store, "Example", mfa.WithDigits(7)), assert: configError},
		{name: "totp: zero period", build: totp(store, "Example", mfa.WithPeriod(0)), assert: configError},
		{name: "totp: negative period", build: totp(store, "Example", mfa.WithPeriod(-time.Second)), assert: configError},
		{name: "totp: nil logger", build: totp(store, "Example", mfa.WithTOTPLogger(nil)), assert: configError},
		{
			name:   "totp: nil identifier generator",
			build:  totp(store, "Example", mfa.WithTOTPIDGenerator((id.Generator)(nil))),
			assert: configError,
		},
		{
			name: "throttle: nil logger",
			build: func() error {
				_, err := mfa.NewVerifyThrottle(mfa.WithVerifyLogger(nil))
				return err
			},
			assert: configError,
		},
		{
			name: "throttle: nil clock",
			build: func() error {
				_, err := mfa.NewVerifyThrottle(mfa.WithVerifyClock(nil))
				return err
			},
			assert: configError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.build())
		})
	}
}
