package authenticate_test

import (
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/password"
)

func TestNewUsernamePasswordAuthenticator(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		users  func(t *testing.T, ctrl *gomock.Controller) identity.UserLoader
		opts   func(t *testing.T, ctrl *gomock.Controller) []authenticate.PasswordOption
		assert func(t *testing.T, a authenticate.Authenticator, err error)
	}

	configError := func(t *testing.T, a authenticate.Authenticator, err error) {
		t.Helper()

		require.ErrorIs(t, err, authenticate.ErrConfig)
		assert.Nil(t, a, "a refused configuration still produced a provider")
	}

	liveLoader := func(t *testing.T, ctrl *gomock.Controller) identity.UserLoader {
		t.Helper()

		return NewMockUserLoader(ctrl)
	}

	cases := []testCase{
		{
			name:  "a user loader alone constructs, with no further configuration",
			users: liveLoader,
			assert: func(t *testing.T, a authenticate.Authenticator, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.NotNil(t, a)
			},
		},
		{
			name: "a nil user loader is refused, naming the port",
			users: func(t *testing.T, _ *gomock.Controller) identity.UserLoader {
				t.Helper()

				return nil
			},
			assert: func(t *testing.T, a authenticate.Authenticator, err error) {
				t.Helper()

				configError(t, a, err)
				assert.ErrorIs(t, err, identity.ErrMissingPort,
					"the consumer is told something is missing but not which port")
				assert.Contains(t, err.Error(), "user loader")
			},
		},
		{
			name: "a non-nil interface holding a nil pointer is refused too",
			users: func(t *testing.T, _ *gomock.Controller) identity.UserLoader {
				t.Helper()

				// What an unchecked constructor error hands over.
				var unchecked *MockUserLoader

				return unchecked
			},
			assert: configError,
		},
		{
			name:  "an encoder that cannot produce the reference hash is refused",
			users: liveLoader,
			opts: func(t *testing.T, ctrl *gomock.Controller) []authenticate.PasswordOption {
				t.Helper()

				enc := NewMockEncoder(ctrl)
				enc.EXPECT().Encode(gomock.Any()).Return(nil, errEncoderBroken)

				return []authenticate.PasswordOption{authenticate.WithPasswordEncoder(enc)}
			},
			assert: func(t *testing.T, a authenticate.Authenticator, err error) {
				t.Helper()

				configError(t, a, err)
				assert.ErrorIs(t, err, errEncoderBroken,
					"the cause was collapsed, so the consumer cannot see why the encoder refused")
			},
		},
		{
			name:  "a nil encoder is refused rather than quietly restoring the default",
			users: liveLoader,
			opts: func(t *testing.T, _ *gomock.Controller) []authenticate.PasswordOption {
				t.Helper()

				return []authenticate.PasswordOption{authenticate.WithPasswordEncoder(nil)}
			},
			assert: configError,
		},
		{
			name:  "a nil identifier generator is refused rather than quietly restoring the default",
			users: liveLoader,
			opts: func(t *testing.T, _ *gomock.Controller) []authenticate.PasswordOption {
				t.Helper()

				return []authenticate.PasswordOption{authenticate.WithPasswordIDGenerator(nil)}
			},
			assert: configError,
		},
		{
			name:  "a nil option is skipped, so a conditionally built slice need not be filtered",
			users: liveLoader,
			opts: func(t *testing.T, _ *gomock.Controller) []authenticate.PasswordOption {
				t.Helper()

				return []authenticate.PasswordOption{nil}
			},
			assert: func(t *testing.T, a authenticate.Authenticator, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.NotNil(t, a)
			},
		},
		{
			name:  "the reference hash is encoded at construction, by the configured encoder",
			users: liveLoader,
			opts: func(t *testing.T, ctrl *gomock.Controller) []authenticate.PasswordOption {
				t.Helper()

				enc := NewMockEncoder(ctrl)
				// Exactly once, before any traffic: a provider that encoded it
				// per request would pay for it on every refusal.
				enc.EXPECT().Encode(gomock.Any()).Return([]byte("$fake$reference"), nil).Times(1)

				return []authenticate.PasswordOption{authenticate.WithPasswordEncoder(enc)}
			},
			assert: func(t *testing.T, a authenticate.Authenticator, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.NotNil(t, a)
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

			a, err := authenticate.NewUsernamePasswordAuthenticator(tc.users(t, ctrl), opts...)
			tc.assert(t, a, err)
		})
	}
}

// errEncoderBroken stands for an encoder that cannot hash at all — misconfigured
// parameters, or a salt source that will not read.
var errEncoderBroken = errors.New("the encoder cannot hash")

// recordingEncoder is a generated Encoder mock in front of a real encoder. The
// hashing stays real, so a test asserts against the format the configured
// algorithm actually produces, while the calls the provider made stay visible.
type recordingEncoder struct {
	*MockEncoder

	mu        sync.Mutex
	encoded   [][]byte
	matchedTo [][]byte
	matches   int
}

func newRecordingEncoder(t *testing.T, ctrl *gomock.Controller, inner password.Encoder) *recordingEncoder {
	t.Helper()

	r := &recordingEncoder{MockEncoder: NewMockEncoder(ctrl)}

	r.EXPECT().Encode(gomock.Any()).DoAndReturn(func(in string) ([]byte, error) {
		encoded, err := inner.Encode(in)

		r.mu.Lock()
		defer r.mu.Unlock()
		r.encoded = append(r.encoded, encoded)

		return encoded, err
	}).AnyTimes()

	r.EXPECT().Match(gomock.Any(), gomock.Any()).DoAndReturn(func(in string, encoded []byte) bool {
		r.mu.Lock()
		r.matches++
		r.matchedTo = append(r.matchedTo, encoded)
		r.mu.Unlock()

		return inner.Match(in, encoded)
	}).AnyTimes()

	return r
}

// calls reports how many verifications ran and what they were checked against.
func (r *recordingEncoder) calls() (matches int, matchedTo [][]byte) {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.matches, append([][]byte(nil), r.matchedTo...)
}

// reference returns the hash the provider had this encoder produce at
// construction.
func (r *recordingEncoder) reference(t *testing.T) []byte {
	t.Helper()

	r.mu.Lock()
	defer r.mu.Unlock()
	require.Len(t, r.encoded, 1, "the reference hash was not encoded exactly once at construction")

	return r.encoded[0]
}
