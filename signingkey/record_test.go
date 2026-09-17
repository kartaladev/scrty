package signingkey_test

import (
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
