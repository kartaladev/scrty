package session_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/session"
)

// raceOrder is the interleaving a presentationRaceStore forces between the
// first presentation of S1 and the recovery renewal of O.
type raceOrder int

const (
	// raceFree holds S1's read and O's read until both have happened, then
	// lets the two run as they will.
	raceFree raceOrder = iota
	// raceRenewalFirst reads S1 first, then lets the recovery commit before
	// S1's presentation is recorded: the interleaving in which only the
	// store's refusal of the mark of a superseded session (and the load's
	// re-read after it) can refuse S1.
	raceRenewalFirst
	// racePresentationFirst lets S1's load finish before the recovery
	// supersedes.
	racePresentationFirst
	// raceRenewalFirstLater is raceRenewalFirst with the clock moving on
	// between S1's judgement and the recovery: S1's load reads its time, the
	// clock advances a second, and only then does the renewal read its own.
	// The recovery's knock-out of S1 is then later than the time S1's load
	// holds.
	raceRenewalFirstLater
)

// presentationRaceStore forces an order between a Load of s1 and a
// RotateWithGrace of o over one memory store.
type presentationRaceStore struct {
	*session.MemoryStore

	order  raceOrder
	clk    *clockwork.FakeClock
	s1, o  string
	s1Seen atomic.Int32
	oSeen  atomic.Int32

	arrived    sync.WaitGroup // raceFree: S1's and O's first reads
	s1Read     chan struct{}  // closed after S1's first read
	superseded chan struct{}  // closed after the first Supersede returns
	renewed    chan struct{}  // closed by the test once the renewal has returned
	advanced   chan struct{}  // raceRenewalFirstLater: closed once the clock moved on
	loaded     chan struct{}  // closed by the test once Load(S1) has returned
	once       sync.Once
	readOnce   sync.Once
}

func newPresentationRaceStore(inner *session.MemoryStore, order raceOrder) *presentationRaceStore {
	s := &presentationRaceStore{
		MemoryStore: inner,
		order:       order,
		s1Read:      make(chan struct{}),
		superseded:  make(chan struct{}),
		renewed:     make(chan struct{}),
		loaded:      make(chan struct{}),
		advanced:    make(chan struct{}),
	}
	s.arrived.Add(2)

	return s
}

func (s *presentationRaceStore) Load(ctx context.Context, id string) (*session.Session, error) {
	got, err := s.MemoryStore.Load(ctx, id)
	first := id == s.s1 && s.s1Seen.Add(1) == 1 || id == s.o && s.oSeen.Add(1) == 1
	if !first {
		return got, err
	}
	if id == s.s1 {
		s.readOnce.Do(func() { close(s.s1Read) })
	}
	if id == s.o && s.order == raceRenewalFirstLater {
		// The renewal reads its time after this returns, so after the
		// advance S1's load made once it had judged S1.
		<-s.advanced
	}
	if s.order == raceFree {
		s.arrived.Done()
		s.arrived.Wait()
	}

	return got, err
}

func (s *presentationRaceStore) MarkPresented(ctx context.Context, id string, at time.Time) error {
	if s.order == raceRenewalFirstLater && id == s.s1 {
		s.clk.Advance(time.Second)
		close(s.advanced)
	}
	if (s.order == raceRenewalFirst || s.order == raceRenewalFirstLater) && id == s.s1 {
		// A renewal refused before it supersedes never closes superseded.
		select {
		case <-s.superseded:
		case <-s.renewed:
		}
	}

	return s.MemoryStore.MarkPresented(ctx, id, at)
}

func (s *presentationRaceStore) Supersede(ctx context.Context, op session.Supersession) error {
	if op.Old != s.o || s.o == "" {
		// The fixture's own first rotation, before the race is armed.
		return s.MemoryStore.Supersede(ctx, op)
	}
	switch s.order {
	case raceRenewalFirst, raceRenewalFirstLater:
		<-s.s1Read
	case racePresentationFirst:
		<-s.loaded
	case raceFree:
	}
	err := s.MemoryStore.Supersede(ctx, op)
	s.once.Do(func() { close(s.superseded) })

	return err
}

// TestUnusedSuccessorRecovery_FirstPresentationRacingRecovery pins that S1
// presented while O is recovered never leaves both a live S1 and a live S2:
// either S1's load succeeds and the renewal is reuse, or the renewal
// recovers and S1 is reuse. Run it with -race -count=50.
func TestUnusedSuccessorRecovery_FirstPresentationRacingRecovery(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		order  raceOrder
		assert func(t *testing.T, s1Err, renewErr error)
	}

	presentationWon := func(s1Err, renewErr error) bool {
		return s1Err == nil && errors.Is(renewErr, session.ErrReused)
	}
	renewalWon := func(s1Err, renewErr error) bool {
		return renewErr == nil && errors.Is(s1Err, session.ErrReused)
	}

	cases := []testCase{
		{
			name:  "the recovery commits between S1's read and its mark",
			order: raceRenewalFirst,
			assert: func(t *testing.T, s1Err, renewErr error) {
				assert.True(t, renewalWon(s1Err, renewErr), "S1: %v, renewal: %v", s1Err, renewErr)
			},
		},
		{
			name:  "the recovery commits between S1's read and its mark, a second after S1's load read the clock",
			order: raceRenewalFirstLater,
			assert: func(t *testing.T, s1Err, renewErr error) {
				assert.True(t, renewalWon(s1Err, renewErr), "S1: %v, renewal: %v", s1Err, renewErr)
			},
		},
		{
			name:  "S1's load completes before the recovery",
			order: racePresentationFirst,
			assert: func(t *testing.T, s1Err, renewErr error) {
				assert.True(t, presentationWon(s1Err, renewErr), "S1: %v, renewal: %v", s1Err, renewErr)
			},
		},
		{
			// Unforced, either side may win, and nothing else can happen: a
			// renewal is refused only once S1 is marked, and S1's load
			// re-reads only when its mark is refused as superseded, which
			// means the renewal won. S1's load therefore never finds its
			// family revoked, and ErrSessionNotFound is not an outcome.
			name:  "both read, then run freely",
			order: raceFree,
			assert: func(t *testing.T, s1Err, renewErr error) {
				assert.True(t, presentationWon(s1Err, renewErr) || renewalWon(s1Err, renewErr),
					"S1: %v, renewal: %v", s1Err, renewErr)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(createdAt)
			inner := session.NewMemoryStore(session.WithMemoryStoreClock(clk))
			store := newPresentationRaceStore(inner, tc.order)
			store.clk = clk
			presenter := recoveryManager(t, store, clk)
			renewer := recoveryManager(t, store, clk)

			o, err := presenter.Create(t.Context(), testUser)
			require.NoError(t, err)
			s1, _, err := presenter.RotateWithGrace(t.Context(), o, 30*time.Second)
			require.NoError(t, err)
			clk.Advance(nextDay)
			store.s1, store.o = s1.ID, o.ID

			var (
				wg                sync.WaitGroup
				s1Err, renewErr   error
				s1Live, renewedTo *session.Session
			)
			wg.Go(func() {
				s1Live, s1Err = presenter.Load(t.Context(), s1.ID)
				close(store.loaded)
			})
			wg.Go(func() {
				renewedTo, _, renewErr = renewer.RotateWithGrace(t.Context(), o, 30*time.Second)
				close(store.renewed)
			})
			wg.Wait()

			require.False(t, s1Err == nil && renewErr == nil,
				"both a live S1 and a live S2: S1 loaded and the renewal issued %v", renewedTo != nil)
			tc.assert(t, s1Err, renewErr)
			if s1Err == nil {
				assert.NotNil(t, s1Live)
			}
			assert.Zero(t, inner.Len(), "the family still holds a session after the verdict")
		})
	}
}
