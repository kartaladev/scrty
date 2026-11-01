package onetime_test

import (
	"context"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/token/onetime"
)

// A token's expiry is judged at the spend, not only at the check: a caller's
// own step between the two (issuing a credential, say) may outlast it.
func TestTokens_ConsumeRefusesExpiredToken(t *testing.T) {
	tests := map[string]struct {
		spendAfter time.Duration
		assert     func(t *testing.T, err error, spent bool)
	}{
		"clock past the expiry at consume": {
			spendAfter: 61 * time.Second,
			assert: func(t *testing.T, err error, spent bool) {
				assert.ErrorIs(t, err, onetime.ErrInvalidToken)
				assert.False(t, spent, "an expired token must not be spent")
			},
		},
		"clock exactly at the expiry instant": {
			spendAfter: 60 * time.Second,
			assert: func(t *testing.T, err error, spent bool) {
				assert.ErrorIs(t, err, onetime.ErrInvalidToken)
				assert.False(t, spent, "a token is refused at its expiry instant")
			},
		},
		"clock just before the expiry": {
			spendAfter: 59 * time.Second,
			assert: func(t *testing.T, err error, spent bool) {
				assert.NoError(t, err)
				assert.True(t, spent)
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			clk := clockwork.NewFakeClockAt(issuedAt)
			m, store := newManager(t, clk, onetime.WithTokenTTL(time.Minute))

			presented, tok, err := m.Issue(t.Context(), "ada@example.com")
			require.NoError(t, err)
			clk.Advance(59 * time.Second)

			checked, err := m.Check(t.Context(), presented, "")
			require.NoError(t, err)

			clk.Advance(tc.spendAfter - 59*time.Second)
			err = m.Consume(t.Context(), checked)

			rec, findErr := store.FindByID(t.Context(), tok.ID)
			require.NoError(t, findErr)
			tc.assert(t, err, !rec.ConsumedAt.IsZero())
		})
	}
}

// A refused spend leaves the token unspent, also through Redeem with a check
// that outlasts the expiry.
func TestTokens_RedeemRefusesTokenExpiredDuringChecks(t *testing.T) {
	clk := clockwork.NewFakeClockAt(issuedAt)
	m, store := newManager(t, clk, onetime.WithTokenTTL(time.Minute))

	presented, tok, err := m.Issue(t.Context(), "ada@example.com")
	require.NoError(t, err)
	clk.Advance(59 * time.Second)

	_, err = m.Redeem(t.Context(), presented, "", func(context.Context, onetime.Token) error {
		clk.Advance(2 * time.Second)
		return nil
	})
	assert.ErrorIs(t, err, onetime.ErrInvalidToken)

	rec, err := store.FindByID(t.Context(), tok.ID)
	require.NoError(t, err)
	assert.True(t, rec.ConsumedAt.IsZero(), "the token must still be unspent")
}
