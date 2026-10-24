package signingkey_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/signingkey"
)

func TestInMemoryKeyStore(t *testing.T) {
	t.Parallel()

	at := func(h int) time.Time { return time.Date(2030, 1, 1, h, 0, 0, 0, time.UTC) }

	// sealed is an arbitrary sealed envelope: it is not DER, so a store that
	// parsed what it was given would have to fail on it.
	sealed := []byte{0x00, 0xff, 0x10, 'n', 'o', 't', ' ', 'D', 'E', 'R'}

	type testCase struct {
		name   string
		seed   []signingkey.Record
		assert func(t *testing.T, got []signingkey.Record, err error)
	}

	cases := []testCase{
		{
			name: "loads oldest first whatever order they were stored in",
			seed: []signingkey.Record{
				{Kid: "b", Alg: signingkey.RS256, CreatedAt: at(11)},
				{Kid: "a", Alg: signingkey.RS256, CreatedAt: at(10)},
			},
			assert: func(t *testing.T, got []signingkey.Record, err error) {
				require.NoError(t, err)
				require.Len(t, got, 2)
				assert.Equal(t, "a", got[0].Kid)
				assert.Equal(t, "b", got[1].Kid)
			},
		},
		{
			// Many records, so that an order the store did not keep — such as
			// a map's — cannot match the stored order by chance.
			name: "records created at the same instant load in the order they were stored",
			seed: tiedRecords(at(10), 16),
			assert: func(t *testing.T, got []signingkey.Record, err error) {
				require.NoError(t, err)
				assert.Equal(t, recordKids(tiedRecords(at(10), 16)), recordKids(got),
					"a tie in creation time keeps the store order")
			},
		},
		{
			name: "storing an existing kid again keeps its place among tied records",
			seed: append(tiedRecords(at(10), 3),
				signingkey.Record{Kid: "tied-00", Alg: signingkey.RS256, CreatedAt: at(10), Private: []byte("again")}),
			assert: func(t *testing.T, got []signingkey.Record, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"tied-00", "tied-01", "tied-02"}, recordKids(got))
				assert.Equal(t, []byte("again"), got[0].Private)
			},
		},
		{
			name: "storing an existing kid replaces that record",
			seed: []signingkey.Record{
				{Kid: "a", Alg: signingkey.RS256, CreatedAt: at(10), Private: []byte("first")},
				{Kid: "a", Alg: signingkey.RS256, CreatedAt: at(10), Private: []byte("second")},
			},
			assert: func(t *testing.T, got []signingkey.Record, err error) {
				require.NoError(t, err)
				require.Len(t, got, 1)
				assert.Equal(t, []byte("second"), got[0].Private)
			},
		},
		{
			name: "private bytes are opaque and returned unchanged",
			seed: []signingkey.Record{{
				Kid:       "sealed",
				Alg:       signingkey.RS256,
				CreatedAt: at(10),
				Private:   sealed,
			}},
			assert: func(t *testing.T, got []signingkey.Record, err error) {
				require.NoError(t, err)
				require.Len(t, got, 1)
				assert.Equal(t, sealed, got[0].Private,
					"the store never interprets the private bytes")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			store := signingkey.NewInMemoryKeyStore()
			for _, rec := range tc.seed {
				require.NoError(t, store.Store(ctx, rec))
			}

			got, err := store.LoadAll(ctx)
			tc.assert(t, got, err)
		})
	}
}

// tiedRecords returns n RS256 records all created at the same instant, with
// kids that sort in the order they are returned.
func tiedRecords(at time.Time, n int) []signingkey.Record {
	recs := make([]signingkey.Record, 0, n)
	for i := range n {
		recs = append(recs, signingkey.Record{Kid: fmt.Sprintf("tied-%02d", i), Alg: signingkey.RS256, CreatedAt: at})
	}
	return recs
}

// recordKids returns the kids of recs, in order.
func recordKids(recs []signingkey.Record) []string {
	kids := make([]string, 0, len(recs))
	for _, rec := range recs {
		kids = append(kids, rec.Kid)
	}
	return kids
}
