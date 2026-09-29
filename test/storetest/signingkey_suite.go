package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/signingkey"
)

// signingKeyRecord returns a record for kid created at created. Its key
// material is opaque bytes: the store never reads it.
func signingKeyRecord(kid string, created time.Time) signingkey.Record {
	return signingkey.Record{
		Kid:       kid,
		Alg:       signingkey.RS256,
		Private:   []byte("private-der-of-" + kid + "\x00\xff"),
		PublicJWK: []byte(`{"kty":"RSA","kid":"` + kid + `","alg":"RS256","use":"sig"}`),
		CreatedAt: created,
	}
}

// assertSigningKeys requires LoadAll to return exactly want, in order.
func assertSigningKeys(ctx context.Context, t *testing.T, s signingkey.KeyStore, want ...signingkey.Record) {
	t.Helper()

	got, err := s.LoadAll(ctx)
	require.NoError(t, err)

	kids := func(recs []signingkey.Record) []string {
		out := make([]string, 0, len(recs))
		for _, rec := range recs {
			out = append(out, rec.Kid)
		}
		return out
	}
	require.Equal(t, kids(want), kids(got), "LoadAll must return exactly these keys, oldest first")
	for i := range want {
		assert.Equal(t, want[i].Alg, got[i].Alg, "key %s", want[i].Kid)
		assert.Equal(t, want[i].Private, got[i].Private, "key %s", want[i].Kid)
		assert.Equal(t, want[i].PublicJWK, got[i].PublicJWK, "key %s", want[i].Kid)
		assertTimeEqual(t, want[i].CreatedAt, got[i].CreatedAt, "CreatedAt of "+want[i].Kid)
	}
}

// RunSigningKeyStoreSuite checks a signingkey.KeyStore against the contract
// the key manager relies on: a record round-trips unchanged; storing a record
// with a key identifier already present replaces it, leaving one; LoadAll
// returns every record oldest first by CreatedAt; and an empty store loads
// nothing without an error.
//
// newStore is called once per case and must return an empty store.
func RunSigningKeyStoreSuite(t *testing.T, newStore func(t *testing.T) signingkey.KeyStore) {
	t.Helper()

	cases := []suiteCase[signingkey.KeyStore]{
		{
			name: "an empty store loads no keys and no error",
			assert: func(t *testing.T, ctx context.Context, s signingkey.KeyStore, _ *clockwork.FakeClock) {
				got, err := s.LoadAll(ctx)
				require.NoError(t, err)
				assert.Empty(t, got)
			},
		},
		{
			name: "a stored key loads unchanged",
			assert: func(t *testing.T, ctx context.Context, s signingkey.KeyStore, _ *clockwork.FakeClock) {
				rec := signingKeyRecord("kid-a", suiteStart)
				require.NoError(t, s.Store(ctx, rec))

				assertSigningKeys(ctx, t, s, rec)
			},
		},
		{
			name: "creation times keep at least microsecond precision",
			assert: func(t *testing.T, ctx context.Context, s signingkey.KeyStore, _ *clockwork.FakeClock) {
				require.NoError(t, s.Store(ctx, signingKeyRecord("kid-a", preciseStart)))

				got, err := s.LoadAll(ctx)
				require.NoError(t, err)
				require.Len(t, got, 1)
				assertTimeMicro(t, preciseStart, got[0].CreatedAt, "CreatedAt")
			},
		},
		{
			name: "storing a key id again replaces the record, leaving one",
			assert: func(t *testing.T, ctx context.Context, s signingkey.KeyStore, _ *clockwork.FakeClock) {
				first := signingKeyRecord("kid-a", suiteStart)
				other := signingKeyRecord("kid-b", suiteStart.Add(time.Minute))
				require.NoError(t, s.Store(ctx, first))
				require.NoError(t, s.Store(ctx, other))

				second := signingKeyRecord("kid-a", suiteStart.Add(2*time.Minute))
				second.Alg = signingkey.ES256
				second.Private = []byte("resealed private material")
				second.PublicJWK = []byte(`{"kty":"EC","kid":"kid-a"}`)
				require.NoError(t, s.Store(ctx, second))

				assertSigningKeys(ctx, t, s, other, second)
			},
		},
		{
			name: "keys load oldest first by creation time, whatever order they were stored in",
			assert: func(t *testing.T, ctx context.Context, s signingkey.KeyStore, _ *clockwork.FakeClock) {
				oldest := signingKeyRecord("kid-z", suiteStart)
				middle := signingKeyRecord("kid-a", suiteStart.Add(time.Hour))
				newest := signingKeyRecord("kid-m", suiteStart.Add(2*time.Hour))
				for _, rec := range []signingkey.Record{newest, oldest, middle} {
					require.NoError(t, s.Store(ctx, rec))
				}

				assertSigningKeys(ctx, t, s, oldest, middle, newest)
			},
		},
	}

	runSuite(t, cases, withoutClock(newStore))
}
