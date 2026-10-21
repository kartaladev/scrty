package session_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/session"
)

// outageAfterRecoveryStore lets a recovery of the original commit when the
// presented successor's mark arrives, then fails that mark as an outage would.
type outageAfterRecoveryStore struct {
	*session.MemoryStore
	s1      string
	recover func()
}

func (s *outageAfterRecoveryStore) MarkPresented(ctx context.Context, id string, at time.Time) error {
	if id == s.s1 && s.recover != nil {
		r := s.recover
		s.recover = nil
		r()
		return errors.New("connection reset")
	}
	return s.MemoryStore.MarkPresented(ctx, id, at)
}

func TestFailingMarkAfterRecoveryIsNotServed(t *testing.T) {
	clk := clockwork.NewFakeClockAt(createdAt)
	inner := session.NewMemoryStore(session.WithMemoryStoreClock(clk))
	store := &outageAfterRecoveryStore{MemoryStore: inner}
	presenter := recoveryManager(t, store, clk)
	renewer := recoveryManager(t, store, clk)

	o, err := presenter.Create(t.Context(), testUser)
	require.NoError(t, err)
	s1, _, err := presenter.RotateWithGrace(t.Context(), o, 30*time.Second)
	require.NoError(t, err)
	clk.Advance(nextDay)

	var s2 *session.Session
	var renewErr error
	store.s1 = s1.ID
	store.recover = func() { s2, _, renewErr = renewer.RotateWithGrace(t.Context(), o, 30*time.Second) }

	got, loadErr := presenter.Load(t.Context(), s1.ID)

	require.NoError(t, renewErr)
	require.NotNil(t, s2)
	require.False(t, loadErr == nil && got != nil,
		"S1 was served after the recovery knocked it out, while S2 is live: %v", got != nil)
}
