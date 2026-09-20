package onetime_test

import (
	"bytes"
	"sync"
	"testing"
	"time"

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

		clk := newTestClock(issuedAt)
		store := onetime.NewMemoryStore(onetime.WithMemoryStoreClock(clk.Now))

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

		clk := newTestClock(issuedAt)
		store := onetime.NewMemoryStore(onetime.WithMemoryStoreClock(clk.Now))
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

		clk := newTestClock(issuedAt)
		store := onetime.NewMemoryStore(onetime.WithMemoryStoreClock(clk.Now))

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

		clk := newTestClock(issuedAt)
		store := onetime.NewMemoryStore(onetime.WithMemoryStoreClock(clk.Now))
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

		clk := newTestClock(issuedAt.Add(time.Hour))
		store := onetime.NewMemoryStore(onetime.WithMemoryStoreClock(clk.Now))
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

	clk := newTestClock(issuedAt)
	store := onetime.NewMemoryStore(onetime.WithMemoryStoreClock(clk.Now))
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
