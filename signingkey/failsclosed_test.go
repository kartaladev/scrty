package signingkey_test

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/signingkey"
)

func TestNewKeyManagerFailsClosed(t *testing.T) {
	t.Parallel()

	errStore := errors.New("store unreachable")
	storedAt := time.Date(2030, 3, 4, 5, 6, 7, 0, time.UTC)

	// corrupt returns a real record whose private bytes have been damaged in
	// place. Everything else about it — its kid, its algorithm, its public JWK,
	// its creation time — is genuine, so the manager has no other ground to
	// reject it on, and an implementation that never looked at the private
	// bytes would succeed.
	corrupt := func(t *testing.T, damage func(der []byte) []byte) signingkey.Record {
		t.Helper()

		rec := realRecord(t, storedAt)
		rec.Private = damage(slices.Clone(rec.Private))
		return rec
	}

	type testCase struct {
		name string
		// store returns the store to construct over, and the kid the failure
		// must name, if any.
		store  func(t *testing.T, ctrl *gomock.Controller) (signingkey.KeyStore, string)
		assert func(t *testing.T, km *signingkey.KeyManager, kid string, err error)
	}

	cases := []testCase{
		{
			name: "the store cannot be read",
			store: func(_ *testing.T, ctrl *gomock.Controller) (signingkey.KeyStore, string) {
				store := NewMockKeyStore(ctrl)
				store.EXPECT().LoadAll(gomock.Any()).Return(nil, errStore)
				// No Store call is expected: an unreadable store must never be
				// treated as an empty one.
				return store, ""
			},
			assert: func(t *testing.T, km *signingkey.KeyManager, _ string, err error) {
				require.ErrorIs(t, err, errStore)
				assert.Nil(t, km)
			},
		},
		{
			name: "a stored key whose private bytes are truncated is never skipped",
			store: func(t *testing.T, ctrl *gomock.Controller) (signingkey.KeyStore, string) {
				rec := corrupt(t, func(der []byte) []byte { return der[:len(der)-8] })
				store := NewMockKeyStore(ctrl)
				store.EXPECT().LoadAll(gomock.Any()).Return([]signingkey.Record{rec}, nil)
				return store, rec.Kid
			},
			assert: func(t *testing.T, km *signingkey.KeyManager, kid string, err error) {
				require.Error(t, err)
				assert.Nil(t, km)
				assert.Contains(t, err.Error(), kid, "the error names the key it could not decode")
			},
		},
		{
			name: "a stored key whose private bytes were flipped is never skipped",
			store: func(t *testing.T, ctrl *gomock.Controller) (signingkey.KeyStore, string) {
				rec := corrupt(t, func(der []byte) []byte {
					der[len(der)/2] ^= 0xff
					return der
				})
				store := NewMockKeyStore(ctrl)
				store.EXPECT().LoadAll(gomock.Any()).Return([]signingkey.Record{rec}, nil)
				return store, rec.Kid
			},
			assert: func(t *testing.T, km *signingkey.KeyManager, kid string, err error) {
				require.Error(t, err)
				assert.Nil(t, km)
				assert.Contains(t, err.Error(), kid, "the error names the key it could not decode")
			},
		},
		{
			name: "the initial write fails",
			store: func(_ *testing.T, ctrl *gomock.Controller) (signingkey.KeyStore, string) {
				store := NewMockKeyStore(ctrl)
				store.EXPECT().LoadAll(gomock.Any()).Return(nil, nil)
				store.EXPECT().Store(gomock.Any(), gomock.Any()).Return(errStore)
				return store, ""
			},
			assert: func(t *testing.T, km *signingkey.KeyManager, _ string, err error) {
				require.ErrorIs(t, err, errStore)
				assert.Nil(t, km)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			store, kid := tc.store(t, ctrl)

			km, err := signingkey.NewKeyManager(signingkey.WithKeyStore(store))
			tc.assert(t, km, kid, err)
		})
	}
}
