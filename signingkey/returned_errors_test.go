package signingkey_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/signingkey"
)

// TestSigningkeyReturnedErrors pins task 5.7: construction's own load and
// store of a key carry fixed library text when the configured KeyStore
// fails, with the store's own error still reachable by identity.
func TestSigningkeyReturnedErrors(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		store  func(t *testing.T, ctrl *gomock.Controller) *MockKeyStore
		assert func(t *testing.T, err error)
	}

	// redacted is the shape every site here shares: the fixture's text is
	// gone, and the store's own error is still reachable by identity.
	redacted := func(t *testing.T, err error) {
		t.Helper()

		require.Error(t, err)
		assert.NotContains(t, err.Error(), "alice@example.com")
		assert.NotContains(t, err.Error(), "u-123")
		assert.ErrorIs(t, err, errRedactionFixture, "the store's own error is still reachable")
	}

	cases := []testCase{
		{
			name: "construction's load fails",
			store: func(t *testing.T, ctrl *gomock.Controller) *MockKeyStore {
				t.Helper()
				s := NewMockKeyStore(ctrl)
				s.EXPECT().LoadAll(gomock.Any()).Return(nil, errRedactionFixture)
				return s
			},
			assert: func(t *testing.T, err error) {
				redacted(t, err)
				assert.EqualError(t, err, "signingkey: load keys")
			},
		},
		{
			name: "construction's store of a freshly minted key fails",
			store: func(t *testing.T, ctrl *gomock.Controller) *MockKeyStore {
				t.Helper()
				s := NewMockKeyStore(ctrl)
				s.EXPECT().LoadAll(gomock.Any()).Return(nil, nil)
				s.EXPECT().Store(gomock.Any(), gomock.Any()).Return(errRedactionFixture)
				return s
			},
			assert: func(t *testing.T, err error) {
				redacted(t, err)
				assert.Regexp(t, `^signingkey: store \S+ key$`, err.Error())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			_, err := signingkey.NewKeyManager(t.Context(), signingkey.WithKeyStore(tc.store(t, ctrl)))
			tc.assert(t, err)
		})
	}
}
