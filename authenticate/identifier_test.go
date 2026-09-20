package authenticate_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
)

func TestAuthenticationIdentifier(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   func(t *testing.T, ctrl *gomock.Controller) []authenticate.PasswordOption
		assert func(t *testing.T, first, second *authenticate.Authentication, err error)
	}

	cases := []testCase{
		{
			name: "the default generator yields a fresh, sortable identifier per authentication",
			assert: func(t *testing.T, first, second *authenticate.Authentication, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.False(t, first.ID.IsZero(), "the result carries no identifier at all")
				assert.NotEqual(t, first.ID, second.ID, "two authentications share one identifier")
				assert.Negative(t, bytes.Compare(first.ID[:], second.ID[:]),
					"identifiers do not increase, so they cannot order the events they name")
			},
		},
		{
			name: "a consumer generator replaces the default",
			opts: func(t *testing.T, ctrl *gomock.Controller) []authenticate.PasswordOption {
				t.Helper()

				ids := NewMockGenerator(ctrl)
				ids.EXPECT().NewID().Return(consumerID, nil).AnyTimes()

				return []authenticate.PasswordOption{authenticate.WithPasswordIDGenerator(ids)}
			},
			assert: func(t *testing.T, first, second *authenticate.Authentication, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, consumerID, first.ID)
				assert.Equal(t, consumerID, second.ID)
			},
		},
		{
			name: "a generator failure is an error, never a result with no identifier",
			opts: func(t *testing.T, ctrl *gomock.Controller) []authenticate.PasswordOption {
				t.Helper()

				ids := NewMockGenerator(ctrl)
				ids.EXPECT().NewID().Return(id.Nil, errNoIdentifier).AnyTimes()

				return []authenticate.PasswordOption{authenticate.WithPasswordIDGenerator(ids)}
			},
			assert: func(t *testing.T, first, _ *authenticate.Authentication, err error) {
				t.Helper()

				require.ErrorIs(t, err, errNoIdentifier)
				assert.NotErrorIs(t, err, authenticate.ErrAuthenticationFailed,
					"a failure to name the event was reported as a decision about the caller")
				assert.Nil(t, first)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)

			var opts []authenticate.PasswordOption
			if tc.opts != nil {
				opts = tc.opts(t, ctrl)
			}
			auth, _ := authenticatorFor(t, cheapEncoder(t), opts...)

			first, err := auth.Authenticate(t.Context(),
				identity.NewUsernamePassword("ada", []byte(storedPassword)))
			if err != nil {
				tc.assert(t, first, nil, err)

				return
			}

			second, err := auth.Authenticate(t.Context(),
				identity.NewUsernamePassword("ada", []byte(storedPassword)))
			tc.assert(t, first, second, err)
		})
	}
}

// consumerID is the identifier a consumer's own generator hands back, so a test
// can tell it apart from anything the library would have minted.
var consumerID = id.MustParse("0192f3a4-5b6c-7d8e-9f01-234567890abc")

// errNoIdentifier stands for a generator that cannot mint an identifier, such
// as one backed by a counter service that is unreachable.
var errNoIdentifier = errors.New("the identifier generator is unavailable")
