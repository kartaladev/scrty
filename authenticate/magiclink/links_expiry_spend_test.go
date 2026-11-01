package magiclink_test

import (
	"context"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/magiclink"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/token/onetime"
)

// A link whose expiry passes while a caller's check runs (the step that issues
// the credential is such a check) is refused and not spent.
func TestRedeem_RefusesLinkExpiredDuringChecks(t *testing.T) {
	clk := clockwork.NewFakeClockAt(time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC))
	store := must.Must(onetime.NewMemoryStore(onetime.WithMemoryStoreClock(clk)))
	tokens := must.Must(onetime.New("magic-link", onetime.WithClock(clk), onetime.WithStore(store),
		onetime.WithTokenTTL(time.Minute)))
	m, err := magiclink.New(tokens, activeByID(), &recordingSender{}, "https://app.example.com",
		magiclink.WithSameDeviceBinding(false))
	require.NoError(t, err)

	link, tok, err := tokens.Issue(t.Context(), "u-1")
	require.NoError(t, err)
	clk.Advance(59 * time.Second)

	r, err := m.Redeem(t.Context(), link, "", func(context.Context, identity.Principal, time.Time) error {
		clk.Advance(2 * time.Second)
		return nil
	})

	assert.ErrorIs(t, err, magiclink.ErrInvalidLink)
	assert.Empty(t, r.Principal.ID)
	rec, findErr := store.FindByID(t.Context(), tok.ID)
	require.NoError(t, findErr)
	assert.True(t, rec.ConsumedAt.IsZero(), "an expired link must not be spent")
}
