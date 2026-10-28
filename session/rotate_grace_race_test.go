package session_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/session"
)

// loadBarrierStore holds its first two Loads until both have read, so two
// renewals of one identifier observe the same stored state before either
// supersedes it: the interleaving in which only the store's condition can
// keep the family to one successor. Later Loads pass straight through.
type loadBarrierStore struct {
	*session.MemoryStore

	loads   atomic.Int32
	arrived sync.WaitGroup
}

func newLoadBarrierStore(inner *session.MemoryStore) *loadBarrierStore {
	s := &loadBarrierStore{MemoryStore: inner}
	s.arrived.Add(2)

	return s
}

func (s *loadBarrierStore) Load(ctx context.Context, id string) (*session.Session, error) {
	got, err := s.MemoryStore.Load(ctx, id)
	if s.loads.Add(1) <= 2 {
		s.arrived.Done()
		s.arrived.Wait()
	}

	return got, err
}

func TestRotateWithGrace_ConcurrentRenewalsProduceOneSuccessor(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// managers is how many managers share the store; the two renewals
		// alternate between them.
		managers int
	}

	cases := []testCase{
		{name: "through one manager", managers: 1},
		{name: "through two managers sharing one store", managers: 2},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(createdAt)
			inner := session.NewMemoryStore(session.WithMemoryStoreClock(clk))
			store := newLoadBarrierStore(inner)
			managers := make([]*session.Sessions, tc.managers)
			for i := range managers {
				managers[i] = managerFor(t, session.WithStore(store), session.WithClock(clk))
			}
			o, err := managers[0].Create(t.Context(), testUser)
			require.NoError(t, err)

			var (
				wg         sync.WaitGroup
				successors [2]*session.Session
				errs       [2]error
			)
			for i := range 2 {
				wg.Go(func() {
					successors[i], _, errs[i] = managers[i%tc.managers].RotateWithGrace(t.Context(), o, 30*time.Second)
				})
			}
			wg.Wait()

			won := 0
			for i := range 2 {
				if errs[i] == nil {
					won = i
				}
			}
			loser := 1 - won
			require.NoError(t, errs[won])
			require.ErrorIs(t, errs[loser], session.ErrRenewalConflict, "both renewals produced a successor")
			assert.Nil(t, successors[loser])

			assert.Equal(t, 2, inner.Len(), "the family holds the old session and exactly one successor")
			live, err := inner.Load(t.Context(), successors[won].ID)
			require.NoError(t, err)
			assert.True(t, live.SupersededAt.IsZero(), "the winning successor was superseded")
		})
	}
}
