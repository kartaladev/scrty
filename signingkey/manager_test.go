// The tests here are split by setup shape, not by case: one table per store
// shape (the in-memory store, a gomock store, a store that lists records in its
// own order), because the setup — not the assertion — is what differs.
package signingkey_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/signingkey"
)

func TestNewKeyManager(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []signingkey.Option
		assert func(t *testing.T, km *signingkey.KeyManager, store signingkey.KeyStore, err error)
	}

	cases := []testCase{
		{
			name: "empty store gets a current RS256 key that is stored first",
			assert: func(t *testing.T, km *signingkey.KeyManager, store signingkey.KeyStore, err error) {
				require.NoError(t, err)

				kid, signer, ok := km.GetSigner(signingkey.RS256)
				require.True(t, ok)
				require.NotEmpty(t, kid)
				pub, isRSA := signer.Public().(*rsa.PublicKey)
				require.True(t, isRSA, "RS256 signs with an RSA key, got %T", signer.Public())
				assert.Equal(t, 2048, pub.N.BitLen(), "RSA keys are 2048 bits")

				recs, loadErr := store.LoadAll(t.Context())
				require.NoError(t, loadErr)
				require.Len(t, recs, 1, "the key is written to the store before it is used")
				assert.Equal(t, kid, recs[0].Kid)
				assert.Equal(t, signingkey.RS256, recs[0].Alg)
			},
		},
		{
			name: "consumer algorithms",
			opts: []signingkey.Option{signingkey.WithAlgs(signingkey.ES256, signingkey.EdDSA)},
			assert: func(t *testing.T, km *signingkey.KeyManager, _ signingkey.KeyStore, err error) {
				require.NoError(t, err)

				_, es, ok := km.GetSigner(signingkey.ES256)
				require.True(t, ok)
				_, isEC := es.Public().(*ecdsa.PublicKey)
				assert.True(t, isEC, "ES256 signs with an ECDSA key, got %T", es.Public())

				_, ed, ok := km.GetSigner(signingkey.EdDSA)
				require.True(t, ok)
				_, isEd := ed.Public().(ed25519.PublicKey)
				assert.True(t, isEd, "EdDSA signs with an Ed25519 key, got %T", ed.Public())

				assert.ElementsMatch(t,
					[]signingkey.Alg{signingkey.ES256, signingkey.EdDSA}, km.SupportedAlgs())

				_, _, rsOK := km.GetSigner(signingkey.RS256)
				assert.False(t, rsOK, "an algorithm the consumer did not configure has no key")
			},
		},
		{
			name: "unsupported algorithm is refused",
			opts: []signingkey.Option{signingkey.WithAlgs("HS256")},
			assert: func(t *testing.T, km *signingkey.KeyManager, store signingkey.KeyStore, err error) {
				require.Error(t, err)
				assert.Nil(t, km)
				assert.Contains(t, err.Error(), "HS256")

				recs, loadErr := store.LoadAll(t.Context())
				require.NoError(t, loadErr)
				assert.Empty(t, recs, "a refused configuration writes nothing")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := signingkey.NewInMemoryKeyStore()
			opts := append([]signingkey.Option{signingkey.WithKeyStore(store)}, tc.opts...)

			km, err := signingkey.NewKeyManager(opts...)
			tc.assert(t, km, store, err)
		})
	}
}

func TestNewKeyManagerStoresBeforeUse(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	store := NewMockKeyStore(ctrl)

	minted := time.Date(2030, 6, 1, 9, 30, 0, 0, time.UTC)

	var written signingkey.Record
	load := store.EXPECT().LoadAll(gomock.Any()).Return(nil, nil)
	store.EXPECT().
		Store(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, rec signingkey.Record) error {
			written = rec
			return nil
		}).
		After(load.Call)

	km, err := signingkey.NewKeyManager(
		signingkey.WithKeyStore(store),
		signingkey.WithClock(newFakeClock(minted)),
	)
	require.NoError(t, err)

	kid, signer, ok := km.GetSigner(signingkey.RS256)
	require.True(t, ok)

	assert.Equal(t, kid, written.Kid,
		"the key the manager signs with is the one the store was given")
	assert.Equal(t, signingkey.RS256, written.Alg)
	assert.Equal(t, minted, written.CreatedAt, "the creation time comes from the clock")
	assert.NotEmpty(t, written.Private, "the private key is persisted, not left to be regenerated")

	set, err := km.JWKS()
	require.NoError(t, err)
	published, ok := set.LookupKeyID(kid)
	require.True(t, ok, "the stored key is the published key")

	publicOfSigner, err := jwk.Import[jwk.Key](signer.Public())
	require.NoError(t, err)
	ownThumb, err := publicOfSigner.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	publishedThumb, err := published.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	assert.Equal(t, ownThumb, publishedThumb, "the published key is the public part of the signer")
}
