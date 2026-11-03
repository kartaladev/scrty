package storetest

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/token/signingkey"
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

// manyKeyIDs is more key identifiers than PostgreSQL accepts as bound parameters
// in one statement, which is 65535.
const manyKeyIDs = 70_000

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
// returns every record oldest first by CreatedAt; an empty store loads nothing
// without an error; and Delete removes the named records, is idempotent, and
// with no key identifiers changes nothing, however many it names.
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
		{
			name: "deleting removes only the named keys, and they are not loaded",
			assert: func(t *testing.T, ctx context.Context, s signingkey.KeyStore, _ *clockwork.FakeClock) {
				first := signingKeyRecord("kid-a", suiteStart)
				second := signingKeyRecord("kid-b", suiteStart.Add(time.Minute))
				kept := signingKeyRecord("kid-c", suiteStart.Add(2*time.Minute))
				for _, rec := range []signingkey.Record{first, second, kept} {
					require.NoError(t, s.Store(ctx, rec))
				}

				require.NoError(t, s.Delete(ctx, first.Kid, second.Kid))

				assertSigningKeys(ctx, t, s, kept)
			},
		},
		{
			name: "deleting a missing key is not an error",
			assert: func(t *testing.T, ctx context.Context, s signingkey.KeyStore, _ *clockwork.FakeClock) {
				kept := signingKeyRecord("kid-a", suiteStart)
				gone := signingKeyRecord("kid-b", suiteStart.Add(time.Minute))
				require.NoError(t, s.Store(ctx, kept))
				require.NoError(t, s.Store(ctx, gone))

				require.NoError(t, s.Delete(ctx, "kid-never-stored"))
				require.NoError(t, s.Delete(ctx, gone.Kid))
				require.NoError(t, s.Delete(ctx, gone.Kid), "another replica deleted it first")

				assertSigningKeys(ctx, t, s, kept)
			},
		},
		{
			name: "a missing key beside a stored one does not stop the stored one going",
			assert: func(t *testing.T, ctx context.Context, s signingkey.KeyStore, _ *clockwork.FakeClock) {
				gone := signingKeyRecord("kid-a", suiteStart)
				require.NoError(t, s.Store(ctx, gone))

				require.NoError(t, s.Delete(ctx, "kid-never-stored", gone.Kid, gone.Kid))

				assertSigningKeys(ctx, t, s)
			},
		},
		{
			name: "delete with no keys is a no-op",
			assert: func(t *testing.T, ctx context.Context, s signingkey.KeyStore, _ *clockwork.FakeClock) {
				kept := signingKeyRecord("kid-a", suiteStart)
				require.NoError(t, s.Store(ctx, kept))

				require.NoError(t, s.Delete(ctx))

				assertSigningKeys(ctx, t, s, kept)
			},
		},
		{
			name: "a key id is matched whole, whatever it holds",
			assert: func(t *testing.T, ctx context.Context, s signingkey.KeyStore, _ *clockwork.FakeClock) {
				awkward := signingKeyRecord(`kid"',{}\%_<é`, suiteStart)
				kept := signingKeyRecord("kid-a", suiteStart.Add(time.Minute))
				require.NoError(t, s.Store(ctx, awkward))
				require.NoError(t, s.Store(ctx, kept))

				require.NoError(t, s.Delete(ctx, "kid", "%", "kid-_"))
				assertSigningKeys(ctx, t, s, awkward, kept)

				require.NoError(t, s.Delete(ctx, awkward.Kid))
				assertSigningKeys(ctx, t, s, kept)
			},
		},
		{
			name: "a key id no store could hold is missing, and does not stop the others going",
			assert: func(t *testing.T, ctx context.Context, s signingkey.KeyStore, _ *clockwork.FakeClock) {
				gone := signingKeyRecord("kid-a", suiteStart)
				require.NoError(t, s.Store(ctx, gone))

				require.NoError(t, s.Delete(ctx, "kid\x00nul", "kid\xffutf8"))
				assertSigningKeys(ctx, t, s, gone)

				require.NoError(t, s.Delete(ctx, "kid\x00nul", gone.Kid))
				assertSigningKeys(ctx, t, s)
			},
		},
		{
			// Only the keys that show a call was split or cut short are stored,
			// so the case costs one call however many identifiers it names: the
			// first, the last of a first batch and the first past it, and the last.
			name: "a delete naming more keys than a statement can bind removes every named key",
			assert: func(t *testing.T, ctx context.Context, s signingkey.KeyStore, _ *clockwork.FakeClock) {
				kids := make([]string, manyKeyIDs)
				for i := range kids {
					kids[i] = fmt.Sprintf("kid-missing-%d", i)
				}
				for i, at := range []int{0, 65534, 65535, manyKeyIDs - 1} {
					kids[at] = fmt.Sprintf("kid-named-%d", i)
					require.NoError(t, s.Store(ctx, signingKeyRecord(kids[at], suiteStart.Add(time.Duration(i)*time.Minute))))
				}
				kept := signingKeyRecord("kid-kept", suiteStart.Add(time.Hour))
				require.NoError(t, s.Store(ctx, kept))

				require.NoError(t, s.Delete(ctx, kids...))

				assertSigningKeys(ctx, t, s, kept)
			},
		},
		{
			name: "a deleted key id can be stored again",
			assert: func(t *testing.T, ctx context.Context, s signingkey.KeyStore, _ *clockwork.FakeClock) {
				rec := signingKeyRecord("kid-a", suiteStart)
				require.NoError(t, s.Store(ctx, rec))
				require.NoError(t, s.Delete(ctx, rec.Kid))

				require.NoError(t, s.Store(ctx, rec))

				assertSigningKeys(ctx, t, s, rec)
			},
		},
	}

	runSuite(t, cases, withoutClock(newStore))
}
