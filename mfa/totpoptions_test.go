package mfa_test

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/mfa"
)

func TestNewTOTP(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		store  mfa.EnrolmentStore
		issuer string
		opts   []mfa.TOTPOption
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
			opts:   []mfa.TOTPOption{mfa.WithDigits(7)},
			assert: configError,
		},
		{
			name:   "zero digits",
			issuer: "Example",
			opts:   []mfa.TOTPOption{mfa.WithDigits(0)},
			assert: configError,
		},
		{
			name:   "nil identifier generator",
			issuer: "Example",
			opts:   []mfa.TOTPOption{mfa.WithTOTPIDGenerator(nil)},
			assert: configError,
		},
		{
			name:   "zero period",
			issuer: "Example",
			opts:   []mfa.TOTPOption{mfa.WithPeriod(0)},
			assert: configError,
		},
		{
			name:   "negative period",
			issuer: "Example",
			opts:   []mfa.TOTPOption{mfa.WithPeriod(-time.Second)},
			assert: configError,
		},
		{
			name:   "a nil clock",
			issuer: "Example",
			opts:   []mfa.TOTPOption{mfa.WithClock(nil)},
			assert: sourceConfigError,
		},
		{
			// A nil pointer inside the interface is refused like an untyped
			// nil, rather than read at the first verification.
			name:   "a typed-nil clock",
			issuer: "Example",
			opts:   []mfa.TOTPOption{mfa.WithClock((*nilClock)(nil))},
			assert: sourceConfigError,
		},
		{
			name:   "a consumer clock with only Now",
			issuer: "Example",
			opts:   []mfa.TOTPOption{mfa.WithClock(fixedClock{at: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)})},
			assert: func(t *testing.T, m *mfa.TOTP, err error) {
				require.NoError(t, err)
				require.NotNil(t, m)
			},
		},
		{
			name:   "a nil random source",
			issuer: "Example",
			opts:   []mfa.TOTPOption{mfa.WithRandom(nil)},
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
			opts:   []mfa.TOTPOption{mfa.WithRandom((*failAfterReader)(nil))},
			assert: sourceConfigError,
		},
		{
			name:   "a nil logger",
			issuer: "Example",
			opts:   []mfa.TOTPOption{mfa.WithTOTPLogger(nil)},
			assert: configError,
		},
		{
			name:   "eight digits and a consumer period",
			issuer: "Example",
			opts:   []mfa.TOTPOption{mfa.WithDigits(8), mfa.WithPeriod(60 * time.Second)},
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

// nilClock is a consumer's clock type; (*nilClock)(nil) is the typed nil an
// unchecked constructor error hands over.
type nilClock struct{}

func (*nilClock) Now() time.Time { return time.Time{} }

// fixedClock is a consumer's own clock with only Now.
type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time { return c.at }
