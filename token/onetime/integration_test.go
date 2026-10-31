package onetime_test

import (
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/token/onetime"
)

// TestManagerAndStoreShareAConsumerClock is the time-source scenario "Consumer
// time source": a manager and its store read one controlled clock, so a token
// is dated, expired and purged by it with no real waiting. It stands alone
// because it builds a manager over the store, which no other store case does.
func TestManagerAndStoreShareAConsumerClock(t *testing.T) {
	t.Parallel()

	start := time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)
	clk := clockwork.NewFakeClockAt(start)
	store := must.Must(onetime.NewMemoryStore(onetime.WithMemoryStoreClock(clk)))
	m, err := onetime.New("magic-link",
		onetime.WithStore(store), onetime.WithClock(clk), onetime.WithTokenTTL(5*time.Minute))
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
