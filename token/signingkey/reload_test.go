package signingkey_test

import (
	"context"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/token/signingkey"
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

// realRecord returns a genuine RS256 record, created at the given time, which
// is the algorithm every default-configured test runs on.
func realRecord(t *testing.T, createdAt time.Time) signingkey.Record {
	t.Helper()

	return realRecordFor(t, signingkey.RS256, createdAt)
}

func TestKeyManagerAdoptsStoredKeys(t *testing.T) {
	t.Parallel()

	at := func(h int) time.Time { return time.Date(2030, 1, 1, h, 0, 0, 0, time.UTC) }
	// Every manager here reads the time as noon on the day the records are
	// dated, so none of them is dated ahead of the present by accident. A
	// clockwork clock only read, never advanced, is safe to share.
	noon := signingkey.WithClock(clockwork.NewFakeClockAt(at(12)))

	type testCase struct {
		name   string
		setup  func(t *testing.T) (store signingkey.KeyStore, wantKid string)
		assert func(t *testing.T, km *signingkey.Keys, store signingkey.KeyStore, wantKid string)
	}

	cases := []testCase{
		{
			name: "a restart adopts the stored key and mints no replacement",
			setup: func(t *testing.T) (signingkey.KeyStore, string) {
				store := signingkey.NewMemoryKeyStore()
				first, err := signingkey.New(t.Context(), signingkey.WithKeyStore(store), noon)
				require.NoError(t, err)
				kid, _, ok := first.Signer(signingkey.RS256)
				require.True(t, ok)
				return store, kid
			},
			assert: func(t *testing.T, km *signingkey.Keys, store signingkey.KeyStore, wantKid string) {
				kid, _, ok := km.Signer(signingkey.RS256)
				require.True(t, ok)
				assert.Equal(t, wantKid, kid, "the second manager signs with the stored key")

				recs, err := store.LoadAll(t.Context())
				require.NoError(t, err)
				assert.Len(t, recs, 1,
					"an algorithm that already has a stored key gets no replacement")

				assert.True(t, publishes(km, wantKid),
					"the stored key is published, so its tokens still verify")
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
			assert: func(t *testing.T, km *signingkey.Keys, store signingkey.KeyStore, wantKid string) {
				kid, _, ok := km.Signer(signingkey.RS256)
				require.True(t, ok)
				assert.Equal(t, wantKid, kid, "the current key is the latest CreatedAt")

				assert.Zero(t, store.(*listingStore).stored, "nothing is minted or rewritten")

				published, err := km.VerificationKeys()
				require.NoError(t, err)
				assert.Len(t, published, 2, "the key it replaced stays published")
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
			assert: func(t *testing.T, km *signingkey.Keys, _ signingkey.KeyStore, wantKid string) {
				kid, _, ok := km.Signer(signingkey.RS256)
				require.True(t, ok)
				assert.Equal(t, wantKid, kid, "the tie goes to the record the store listed later")
			},
		},
		{
			name: "a key dated a year ahead is neither current nor published",
			setup: func(t *testing.T) (signingkey.KeyStore, string) {
				present := realRecord(t, at(12))
				future := realRecord(t, at(12).Add(365*24*time.Hour))
				return &listingStore{recs: []signingkey.Record{present, future}}, present.Kid
			},
			assert: func(t *testing.T, km *signingkey.Keys, store signingkey.KeyStore, wantKid string) {
				assert.Equal(t, wantKid, currentKid(t, km, signingkey.RS256),
					"the current key is the one created now")
				published, err := km.VerificationKeys()
				require.NoError(t, err)
				assert.Equal(t, []string{wantKid}, kidsOf(published),
					"a key dated more than one lifetime ahead is not published")
				assert.Zero(t, store.(*listingStore).stored, "nothing is minted")
			},
		},
		{
			name: "a key ahead by less than the reload interval is current",
			setup: func(t *testing.T) (signingkey.KeyStore, string) {
				present := realRecord(t, at(12))
				skewed := realRecord(t, at(12).Add(30*time.Second))
				return &listingStore{recs: []signingkey.Record{present, skewed}}, skewed.Kid
			},
			assert: func(t *testing.T, km *signingkey.Keys, _ signingkey.KeyStore, wantKid string) {
				assert.Equal(t, wantKid, currentKid(t, km, signingkey.RS256),
					"a key a slightly fast replica just minted is adopted")
			},
		},
		{
			name: "a key ahead by more than the reload interval is published but not current",
			setup: func(t *testing.T) (signingkey.KeyStore, string) {
				present := realRecord(t, at(12))
				ahead := realRecord(t, at(14))
				return &listingStore{recs: []signingkey.Record{present, ahead}}, ahead.Kid
			},
			assert: func(t *testing.T, km *signingkey.Keys, _ signingkey.KeyStore, ahead string) {
				assert.NotEqual(t, ahead, currentKid(t, km, signingkey.RS256),
					"a key dated beyond the reload interval does not sign yet")
				assert.True(t, publishes(km, ahead),
					"but it is within one lifetime, so the tokens it signed still verify")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store, wantKid := tc.setup(t)

			km, err := signingkey.New(t.Context(), signingkey.WithKeyStore(store), noon)
			require.NoError(t, err)

			tc.assert(t, km, store, wantKid)
		})
	}
}
