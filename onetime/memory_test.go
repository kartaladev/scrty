package onetime_test

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/onetime"
	"github.com/kartaladev/scrty/pkg/id"
)

// storedToken is one record as Insert would receive it.
func storedToken(t *testing.T, tokenID id.ID) onetime.Token {
	t.Helper()

	return onetime.Token{
		ID:          tokenID,
		Purpose:     "magic-link",
		Subject:     "ada@example.com",
		SecretHash:  sha256Of(checkSecret),
		BindingHash: sha256Of(checkBinding),
		IssuedAt:    issuedAt,
		ExpiresAt:   issuedAt.Add(15 * time.Minute),
	}
}

func TestMemoryStoreIsolatesRecords(t *testing.T) {
	t.Parallel()

	t.Run("a caller writing to what it inserted cannot change what was stored", func(t *testing.T) {
		t.Parallel()

		clk := clockwork.NewFakeClockAt(issuedAt)
		store := onetime.NewMemoryStore(onetime.WithMemoryStoreClock(clk))

		tok := storedToken(t, checkTokenID)
		want := bytes.Clone(tok.SecretHash)
		require.NoError(t, store.Insert(t.Context(), tok))

		// Ordinary hygiene on the caller's side: wipe the buffer once it has
		// been handed over. Without a copy this destroys the stored hash, and
		// the token stops matching for reasons nothing points at.
		clear(tok.SecretHash)
		clear(tok.BindingHash)

		stored, err := store.FindByID(t.Context(), checkTokenID)
		require.NoError(t, err)
		assert.Equal(t, want, stored.SecretHash, "the store aliased the caller's buffer on write")
		assert.Equal(t, sha256Of(checkBinding), stored.BindingHash)
	})

	t.Run("a caller writing to what it read back cannot change what was stored", func(t *testing.T) {
		t.Parallel()

		clk := clockwork.NewFakeClockAt(issuedAt)
		store := onetime.NewMemoryStore(onetime.WithMemoryStoreClock(clk))
		require.NoError(t, store.Insert(t.Context(), storedToken(t, checkTokenID)))

		first, err := store.FindByID(t.Context(), checkTokenID)
		require.NoError(t, err)
		clear(first.SecretHash)
		clear(first.BindingHash)
		first.Subject = "mallory@example.com"

		again, err := store.FindByID(t.Context(), checkTokenID)
		require.NoError(t, err)
		assert.Equal(t, sha256Of(checkSecret), again.SecretHash, "the store aliased its own record on read")
		assert.Equal(t, sha256Of(checkBinding), again.BindingHash)
		assert.Equal(t, "ada@example.com", again.Subject)
	})

	t.Run("an absent binding stays absent", func(t *testing.T) {
		t.Parallel()

		clk := clockwork.NewFakeClockAt(issuedAt)
		store := onetime.NewMemoryStore(onetime.WithMemoryStoreClock(clk))

		tok := storedToken(t, checkTokenID)
		tok.BindingHash = nil
		require.NoError(t, store.Insert(t.Context(), tok))

		stored, err := store.FindByID(t.Context(), checkTokenID)
		require.NoError(t, err)
		assert.Nil(t, stored.BindingHash,
			"an absent binding came back as an empty one, which compares equal to a presented nothing")
	})
}

func TestMemoryStore(t *testing.T) {
	t.Parallel()

	t.Run("a record that was never inserted is not found", func(t *testing.T) {
		t.Parallel()

		store := onetime.NewMemoryStore()

		got, err := store.FindByID(t.Context(), checkTokenID)
		require.ErrorIs(t, err, onetime.ErrTokenNotFound)
		assert.Nil(t, got)
	})

	t.Run("a record identifier that is already stored is refused, never replaced", func(t *testing.T) {
		t.Parallel()

		store := onetime.NewMemoryStore()
		require.NoError(t, store.Insert(t.Context(), storedToken(t, checkTokenID)))

		require.Error(t, store.Insert(t.Context(), storedToken(t, checkTokenID)),
			"a second insert replaced a record, invalidating a token already in a holder's hands")
		assert.Equal(t, 1, store.Len())
	})

	t.Run("consuming what is not there and what is already spent look alike", func(t *testing.T) {
		t.Parallel()

		clk := clockwork.NewFakeClockAt(issuedAt)
		store := onetime.NewMemoryStore(onetime.WithMemoryStoreClock(clk))
		require.NoError(t, store.Insert(t.Context(), storedToken(t, checkTokenID)))

		require.NoError(t, store.Consume(t.Context(), checkTokenID, issuedAt.Add(time.Minute)))

		spent := store.Consume(t.Context(), checkTokenID, issuedAt.Add(2*time.Minute))
		missing := store.Consume(t.Context(), id.MustParse("01999f00-0000-7000-8000-0000000000ff"), issuedAt)
		require.ErrorIs(t, spent, onetime.ErrTokenNotFound)
		require.ErrorIs(t, missing, onetime.ErrTokenNotFound)

		stored, err := store.FindByID(t.Context(), checkTokenID)
		require.NoError(t, err)
		assert.Equal(t, issuedAt.Add(time.Minute), stored.ConsumedAt,
			"a second consumption moved the time the first one recorded")
	})

	t.Run("a purge with no cutoff is refused and deletes nothing", func(t *testing.T) {
		t.Parallel()

		clk := clockwork.NewFakeClockAt(issuedAt.Add(time.Hour))
		store := onetime.NewMemoryStore(onetime.WithMemoryStoreClock(clk))
		require.NoError(t, store.Insert(t.Context(), storedToken(t, checkTokenID)))

		removed, err := store.DeleteExpiredBefore(t.Context(), "magic-link", time.Time{})
		require.ErrorIs(t, err, onetime.ErrRetainSinceRequired)
		assert.Zero(t, removed)
		assert.Equal(t, 1, store.Len(), "a refused purge still deleted a record")
	})
}

func TestMemoryStoreIsSafeForConcurrentUse(t *testing.T) {
	t.Parallel()

	const writers = 32

	clk := clockwork.NewFakeClockAt(issuedAt)
	store := onetime.NewMemoryStore(onetime.WithMemoryStoreClock(clk))
	gen := id.NewV7Generator()

	ids := make([]id.ID, writers)
	for i := range ids {
		tokenID, err := gen.NewID()
		require.NoError(t, err)
		ids[i] = tokenID
		require.NoError(t, store.Insert(t.Context(), storedToken(t, tokenID)))
	}

	var wg sync.WaitGroup
	for _, tokenID := range ids {
		wg.Add(1)
		go func() {
			defer wg.Done()

			_, _ = store.FindByID(t.Context(), tokenID)
			_ = store.Consume(t.Context(), tokenID, issuedAt.Add(time.Minute))
			_, _ = store.CountRecentBySubject(t.Context(), "magic-link", "ada@example.com", issuedAt)
			_, _ = store.DeleteExpiredBefore(t.Context(), "magic-link", issuedAt)
			_ = store.Len()
		}()
	}
	wg.Wait()
}

// TestMemoryStoreClock covers the store's own time source, which judges expiry
// when the store purges. A constructor that cannot fail cannot refuse an absent
// clock, so nil and typed nil keep the system clock instead.
func TestMemoryStoreClock(t *testing.T) {
	t.Parallel()

	// sweepsBySystemTime asserts that the store judged expiry by the system
	// clock: of a record expired an hour ago and one that expires in an hour,
	// only the first is purged.
	sweepsBySystemTime := func(t *testing.T, store *onetime.MemoryStore) {
		t.Helper()

		now := time.Now()
		expired := storedToken(t, id.MustParse("01999f00-0000-7000-8000-000000000001"))
		expired.IssuedAt, expired.ExpiresAt = now.Add(-2*time.Hour), now.Add(-time.Hour)
		live := storedToken(t, id.MustParse("01999f00-0000-7000-8000-000000000002"))
		live.IssuedAt, live.ExpiresAt = now.Add(-2*time.Hour), now.Add(time.Hour)
		require.NoError(t, store.Insert(t.Context(), expired))
		require.NoError(t, store.Insert(t.Context(), live))

		removed, err := store.DeleteExpiredBefore(t.Context(), "magic-link", now)
		require.NoError(t, err)
		assert.Equal(t, 1, removed, "the store did not judge expiry by the system clock")
		_, err = store.FindByID(t.Context(), live.ID)
		assert.NoError(t, err, "the store purged a record the system clock says is live")
	}

	type testCase struct {
		name   string
		opts   []onetime.MemoryStoreOption
		assert func(t *testing.T, store *onetime.MemoryStore)
	}

	cases := []testCase{
		{
			name:   "no clock option reads the system clock",
			assert: sweepsBySystemTime,
		},
		{
			name:   "an untyped nil clock keeps the system clock",
			opts:   []onetime.MemoryStoreOption{onetime.WithMemoryStoreClock(nil)},
			assert: sweepsBySystemTime,
		},
		{
			// time-source: "Absent source on a constructor that cannot fail".
			name:   "a typed nil clock keeps the system clock, rather than being read",
			opts:   []onetime.MemoryStoreOption{onetime.WithMemoryStoreClock((*nilClock)(nil))},
			assert: sweepsBySystemTime,
		},
		{
			name: "a consumer clock judges expiry in place of the system clock",
			opts: []onetime.MemoryStoreOption{onetime.WithMemoryStoreClock(fixedClock{at: issuedAt.Add(time.Minute)})},
			assert: func(t *testing.T, store *onetime.MemoryStore) {
				// Live by the consumer's clock, long expired by the system
				// clock: a store reading the latter would purge it.
				require.NoError(t, store.Insert(t.Context(), storedToken(t, checkTokenID)))

				removed, err := store.DeleteExpiredBefore(t.Context(), "magic-link", issuedAt.Add(time.Second))
				require.NoError(t, err)
				assert.Zero(t, removed, "the store judged expiry by the system clock")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := onetime.NewMemoryStore(tc.opts...)
			tc.assert(t, store)
		})
	}
}

// TestManagerAndStoreShareAConsumerClock is the time-source scenario "Consumer
// time source": a manager and its store read one controlled clock, so a token
// is dated, expired and purged by it with no real waiting. It stands alone
// because it builds a manager over the store, which no other store case does.
func TestManagerAndStoreShareAConsumerClock(t *testing.T) {
	t.Parallel()

	start := time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)
	clk := clockwork.NewFakeClockAt(start)
	store := onetime.NewMemoryStore(onetime.WithMemoryStoreClock(clk))
	m, err := onetime.NewManager("magic-link",
		onetime.WithStore(store), onetime.WithClock(clk), onetime.WithTTL(5*time.Minute))
	require.NoError(t, err)

	presented, tok, err := m.Issue(t.Context(), "ada@example.com")
	require.NoError(t, err)
	assert.Equal(t, time.Date(2030, 1, 1, 12, 5, 0, 0, time.UTC), tok.ExpiresAt)

	removed, err := store.DeleteExpiredBefore(t.Context(), "magic-link", clk.Now().Add(time.Second))
	require.NoError(t, err)
	require.Zero(t, removed, "the store purged a token its clock says is live")

	clk.Advance(6 * time.Minute)

	_, err = m.Redeem(t.Context(), presented, "")
	require.ErrorIs(t, err, onetime.ErrInvalidToken, "a token past its expiry by the shared clock was redeemed")

	removed, err = store.DeleteExpiredBefore(t.Context(), "magic-link", clk.Now().Add(time.Second))
	require.NoError(t, err)
	assert.Equal(t, 1, removed, "the store did not judge expiry by the shared clock")
}
