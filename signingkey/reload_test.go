package signingkey_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/signingkey"
)

// listingStore returns records in the order it was given them, whatever their
// creation times. A conforming store may do this — for instance a decorating
// store that re-reads its backing rows — and the key manager must not depend on
// the order.
type listingStore struct {
	recs   []signingkey.Record
	stored int
}

func (s *listingStore) Store(_ context.Context, rec signingkey.Record) error {
	s.stored++
	s.recs = append(s.recs, rec)
	return nil
}

func (s *listingStore) LoadAll(context.Context) ([]signingkey.Record, error) {
	return s.recs, nil
}

// realRecord returns a genuine RS256 record, created at the given time. It is
// minted by a throwaway manager so the private bytes and the thumbprint are
// real: only CreatedAt is rewritten.
func realRecord(t *testing.T, createdAt time.Time) signingkey.Record {
	t.Helper()

	store := signingkey.NewInMemoryKeyStore()
	_, err := signingkey.NewKeyManager(signingkey.WithKeyStore(store))
	require.NoError(t, err)

	recs, err := store.LoadAll(t.Context())
	require.NoError(t, err)
	require.Len(t, recs, 1)

	rec := recs[0]
	rec.CreatedAt = createdAt
	return rec
}

func TestKeyManagerAdoptsStoredKeys(t *testing.T) {
	t.Parallel()

	at := func(h int) time.Time { return time.Date(2030, 1, 1, h, 0, 0, 0, time.UTC) }

	type testCase struct {
		name   string
		setup  func(t *testing.T) (store signingkey.KeyStore, wantKid string)
		assert func(t *testing.T, km *signingkey.KeyManager, store signingkey.KeyStore, wantKid string)
	}

	cases := []testCase{
		{
			name: "a restart adopts the stored key and mints no replacement",
			setup: func(t *testing.T) (signingkey.KeyStore, string) {
				store := signingkey.NewInMemoryKeyStore()
				first, err := signingkey.NewKeyManager(signingkey.WithKeyStore(store))
				require.NoError(t, err)
				kid, _, ok := first.GetSigner(signingkey.RS256)
				require.True(t, ok)
				return store, kid
			},
			assert: func(t *testing.T, km *signingkey.KeyManager, store signingkey.KeyStore, wantKid string) {
				kid, _, ok := km.GetSigner(signingkey.RS256)
				require.True(t, ok)
				assert.Equal(t, wantKid, kid, "the second manager signs with the stored key")

				recs, err := store.LoadAll(t.Context())
				require.NoError(t, err)
				assert.Len(t, recs, 1,
					"an algorithm that already has a stored key gets no replacement")

				set, err := km.JWKS()
				require.NoError(t, err)
				_, published := set.LookupKeyID(wantKid)
				assert.True(t, published, "the stored key is published, so its tokens still verify")
			},
		},
		{
			name: "the key created most recently is current, not the one listed last",
			setup: func(t *testing.T) (signingkey.KeyStore, string) {
				newer := realRecord(t, at(11))
				older := realRecord(t, at(10))
				// 11:00 is listed before 10:00.
				return &listingStore{recs: []signingkey.Record{newer, older}}, newer.Kid
			},
			assert: func(t *testing.T, km *signingkey.KeyManager, store signingkey.KeyStore, wantKid string) {
				kid, _, ok := km.GetSigner(signingkey.RS256)
				require.True(t, ok)
				assert.Equal(t, wantKid, kid, "the current key is the latest CreatedAt")

				assert.Zero(t, store.(*listingStore).stored, "nothing is minted or rewritten")

				set, err := km.JWKS()
				require.NoError(t, err)
				assert.Equal(t, 2, set.Len(), "the key it replaced stays published")
			},
		},
		{
			name: "an exact tie in CreatedAt goes to the record listed later",
			setup: func(t *testing.T) (signingkey.KeyStore, string) {
				first := realRecord(t, at(10))
				second := realRecord(t, at(10))
				require.NotEqual(t, first.Kid, second.Kid)
				return &listingStore{recs: []signingkey.Record{first, second}}, second.Kid
			},
			assert: func(t *testing.T, km *signingkey.KeyManager, _ signingkey.KeyStore, wantKid string) {
				kid, _, ok := km.GetSigner(signingkey.RS256)
				require.True(t, ok)
				assert.Equal(t, wantKid, kid, "the tie goes to the record the store listed later")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store, wantKid := tc.setup(t)

			km, err := signingkey.NewKeyManager(signingkey.WithKeyStore(store))
			require.NoError(t, err)

			tc.assert(t, km, store, wantKid)
		})
	}
}
