package signingkey_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/token/signingkey"
)

// BenchmarkReload_RetiredKeysKept measures one reload of a manager that keeps
// retired keys, when it already holds every key the store lists: the case the
// reload's early return serves. No key here is retired, so the option has no
// effect on the work; the name is kept for the design and tasks that cite it.
// Nothing is fresh to decode, so the cost is the listing, the bookkeeping over it,
// and whatever the reload does to decide that no held key needs dropping.
//
// The clock moves one reload interval per iteration and the lifetime dwarfs the
// run, so every key stays within its retire time throughout.
func BenchmarkReload_RetiredKeysKept(b *testing.B) {
	const reloadEvery = time.Millisecond

	sizes := []int{50, 1000, 10000}
	recs := make([]signingkey.Record, 0, sizes[len(sizes)-1])
	for i := range cap(recs) {
		recs = append(recs, benchRecord(b, epoch.Add(-time.Duration(i+1)*time.Second)))
	}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("keys=%d", size), func(b *testing.B) {
			mem := signingkey.NewMemoryKeyStore()
			for _, rec := range recs[:size] {
				require.NoError(b, mem.Store(b.Context(), rec))
			}

			clk := newClock()
			km, err := signingkey.New(b.Context(),
				signingkey.WithKeyStore(mem),
				signingkey.WithClock(clk),
				signingkey.WithAlgs(signingkey.EdDSA),
				signingkey.WithKeyLifetime(1_000_000*time.Hour),
				signingkey.WithRotateInterval(100_000*time.Hour),
				signingkey.WithHousekeepingInterval(1_000*time.Hour),
				signingkey.WithReloadInterval(reloadEvery),
				signingkey.WithRetiredKeysKept(),
			)
			require.NoError(b, err)
			require.NoError(b, km.Start(b.Context()))
			b.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), parkTimeout)
				defer cancel()
				_ = km.Shutdown(ctx)
			})

			parked := func() {
				ctx, cancel := context.WithTimeout(b.Context(), parkTimeout)
				defer cancel()
				require.NoError(b, clk.BlockUntilContext(ctx, loopCount))
			}
			parked()

			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				clk.Advance(reloadEvery)
				parked()
			}
		})
	}
}

// benchRecord returns a genuine EdDSA record created at createdAt.
func benchRecord(b *testing.B, createdAt time.Time) signingkey.Record {
	b.Helper()

	store := signingkey.NewMemoryKeyStore()
	_, err := signingkey.New(b.Context(),
		signingkey.WithKeyStore(store),
		signingkey.WithAlgs(signingkey.EdDSA),
	)
	require.NoError(b, err)

	recs, err := store.LoadAll(b.Context())
	require.NoError(b, err)
	require.Len(b, recs, 1)

	rec := recs[0]
	rec.CreatedAt = createdAt
	return rec
}
