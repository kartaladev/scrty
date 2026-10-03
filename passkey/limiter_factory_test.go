package passkey_test

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/passkey"
	"github.com/kartaladev/scrty/session"
)

// TestNew_ConfirmLimiterFactory pins where the emailed-code confirm limiter
// comes from: the factory when one is given, then the in-memory default. The
// explicit limiter of this flow is per call (RegistrationContext.ConfirmLimiter)
// and is pinned where ConfirmEmailCode is.
func TestNew_ConfirmLimiterFactory(t *testing.T) {
	t.Parallel()

	errFactory := errors.New("factory: backend refused the namespace")

	const user = "u-1"

	type testCase struct {
		name   string
		opts   func(t *testing.T) []passkey.Option
		assert func(t *testing.T, m *passkey.Manager, err error)
	}

	// confirm presents a code for user with no per-call limiter, so the
	// Manager's own limiter answers.
	confirm := func(t *testing.T, m *passkey.Manager) error {
		t.Helper()

		_, err := m.ConfirmEmailCode(t.Context(), &session.Session{UserID: user}, "000000",
			passkey.RegistrationContext{})

		return err
	}

	cases := []testCase{
		{
			name: "default builds in-memory",
			opts: func(*testing.T) []passkey.Option { return nil },
			assert: func(t *testing.T, m *passkey.Manager, err error) {
				require.NoError(t, err)
				assert.NotErrorIs(t, confirm(t, m), mfa.ErrEnrolmentThrottled,
					"a fresh in-memory limiter has nothing counted yet")
			},
		},
		{
			name: "factory asked with namespace, limit, window",
			opts: func(t *testing.T) []passkey.Option {
				ctrl := gomock.NewController(t)
				built := NewMockLimiter(ctrl)
				built.EXPECT().Exceeded(gomock.Any(), passkey.EmailConfirmThrottleKey(user)).Return(true, nil)

				f := NewMockLimiterFactory(ctrl)
				f.EXPECT().NewLimiter("passkey-email-confirm", 5, 15*time.Minute).Return(built, nil).Times(1)

				return []passkey.Option{passkey.WithConfirmLimiterFactory(f)}
			},
			assert: func(t *testing.T, m *passkey.Manager, err error) {
				require.NoError(t, err)
				assert.ErrorIs(t, confirm(t, m), mfa.ErrEnrolmentThrottled,
					"the confirmation is counted through the limiter the factory built")
			},
		},
		{
			name: "nil factory refused",
			opts: func(*testing.T) []passkey.Option {
				return []passkey.Option{passkey.WithConfirmLimiterFactory(nil)}
			},
			assert: func(t *testing.T, m *passkey.Manager, err error) {
				require.ErrorIs(t, err, passkey.ErrConfig)
				assert.Nil(t, m)
			},
		},
		{
			name: "typed-nil factory refused",
			opts: func(*testing.T) []passkey.Option {
				return []passkey.Option{passkey.WithConfirmLimiterFactory((*MockLimiterFactory)(nil))}
			},
			assert: func(t *testing.T, m *passkey.Manager, err error) {
				require.ErrorIs(t, err, passkey.ErrConfig)
				assert.Nil(t, m)
			},
		},
		{
			name: "factory error fails construction",
			opts: func(t *testing.T) []passkey.Option {
				f := NewMockLimiterFactory(gomock.NewController(t))
				f.EXPECT().NewLimiter("passkey-email-confirm", 5, 15*time.Minute).Return(nil, errFactory)

				return []passkey.Option{passkey.WithConfirmLimiterFactory(f)}
			},
			assert: func(t *testing.T, m *passkey.Manager, err error) {
				require.ErrorIs(t, err, passkey.ErrConfig)
				require.ErrorIs(t, err, errFactory)
				assert.Contains(t, err.Error(), `"passkey-email-confirm"`, "the error names the namespace")
				assert.Nil(t, m)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t)
			base := []passkey.Option{passkey.WithClock(f.clock), passkey.WithRepudiationContact("help@example.com")}

			m, err := passkey.New(f.deps, append(base, tc.opts(t)...)...)
			tc.assert(t, m, err)
		})
	}
}
