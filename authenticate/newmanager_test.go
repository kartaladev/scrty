package authenticate_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
)

func TestNewManager(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		delegates func(t *testing.T, ctrl *gomock.Controller) []authenticate.Authenticator
		assert    func(t *testing.T, m *authenticate.Manager, err error)
	}

	configError := func(t *testing.T, m *authenticate.Manager, err error) {
		t.Helper()

		require.ErrorIs(t, err, authenticate.ErrConfig)
		assert.Nil(t, m, "a refused configuration still produced a manager")
	}

	cases := []testCase{
		{
			name: "one live delegate constructs",
			delegates: func(t *testing.T, ctrl *gomock.Controller) []authenticate.Authenticator {
				t.Helper()

				return []authenticate.Authenticator{NewMockAuthenticator(ctrl)}
			},
			assert: func(t *testing.T, m *authenticate.Manager, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.NotNil(t, m)
			},
		},
		{
			name: "no delegates is refused, because such a manager authenticates nobody",
			delegates: func(t *testing.T, _ *gomock.Controller) []authenticate.Authenticator {
				t.Helper()

				return nil
			},
			assert: configError,
		},
		{
			name: "an absent delegate is refused rather than skipped",
			delegates: func(t *testing.T, ctrl *gomock.Controller) []authenticate.Authenticator {
				t.Helper()

				return []authenticate.Authenticator{NewMockAuthenticator(ctrl), nil}
			},
			assert: configError,
		},
		{
			name: "a non-nil interface holding a nil pointer is refused too",
			delegates: func(t *testing.T, _ *gomock.Controller) []authenticate.Authenticator {
				t.Helper()

				// What an unchecked constructor error hands over: `d == nil` is
				// false, so an unchecked manager panics on the first request.
				var unchecked *authenticate.Manager

				return []authenticate.Authenticator{unchecked}
			},
			assert: configError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)

			m, err := authenticate.NewManager(tc.delegates(t, ctrl)...)
			tc.assert(t, m, err)
		})
	}
}
