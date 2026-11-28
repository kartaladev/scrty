package oidcprovider_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

// errUndecodableRow is what a store answers for a read that reaches a row it
// cannot decode.
var errUndecodableRow = errors.New("test: a stored row cannot be decoded")

// oneUnreadableFamily is a session store holding one row it cannot decode, in
// the family unreadable. A listing of the user reaches that row and fails; a
// read of another family does not reach it.
type oneUnreadableFamily struct {
	*session.MemoryStore

	unreadable id.ID
}

// ListByUser implements session.Store: the listing reaches the unreadable row.
func (oneUnreadableFamily) ListByUser(context.Context, identity.UserID, time.Time) ([]*session.Session, error) {
	return nil, errUndecodableRow
}

// ListByFamily implements session.Store: only the unreadable family fails.
func (s oneUnreadableFamily) ListByFamily(ctx context.Context, user identity.UserID, family id.ID, now time.Time) ([]*session.Session, error) {
	if family == s.unreadable {
		return nil, errUndecodableRow
	}

	return s.MemoryStore.ListByFamily(ctx, user, family, now)
}

// Each session-store wrapper the provider puts around its lineage store
// answers a read of one family through the inner store's family read, never
// through the user's listing, so a row of another family that the inner store
// cannot decode does not fail it.
func TestLineageWrappersReadOneFamily(t *testing.T) {
	t.Parallel()

	const user identity.UserID = "u-1"
	clk := clockwork.NewFakeClockAt(time.Date(2026, 11, 28, 9, 0, 0, 0, time.UTC))
	memory, err := session.NewMemoryStore(session.WithMemoryStoreClock(clk))
	require.NoError(t, err)
	seed, err := session.New(session.WithStore(memory), session.WithClock(clk))
	require.NoError(t, err)

	readable, err := seed.Create(t.Context(), user)
	require.NoError(t, err)
	unreadable, err := seed.Create(t.Context(), user)
	require.NoError(t, err)
	inner := oneUnreadableFamily{MemoryStore: memory, unreadable: unreadable.FamilyID}

	for name, wrapper := range oidcprovider.LineageWrappersForTest(inner, clk) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			m, err := session.New(session.WithStore(wrapper), session.WithClock(clk))
			require.NoError(t, err)

			state, err := m.SignInState(t.Context(), user, readable.FamilyID)
			require.NoError(t, err, "a row of another family must not fail the read")
			assert.True(t, state.IdleDeadline.Equal(readable.IdleExpiresAt))
			assert.True(t, state.AbsoluteDeadline.Equal(readable.AbsoluteExpiresAt))
			assert.True(t, state.AuthenticatedAt.Equal(readable.AuthenticatedAt))

			_, err = m.SignInState(t.Context(), user, unreadable.FamilyID)
			require.ErrorIs(t, err, session.ErrListUnavailable, "the unreadable family's own read still fails")
			require.ErrorIs(t, err, errUndecodableRow)
		})
	}
}
