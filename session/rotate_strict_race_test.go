package session_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/session"
)

// gate holds one store call until the test opens it, after telling the test
// the call has arrived.
type gate struct {
	arrived chan struct{}
	open    chan struct{}
}

func newGate() *gate { return &gate{arrived: make(chan struct{}), open: make(chan struct{})} }

// pass signals arrival and waits until the test opens the gate.
func (g *gate) pass() {
	close(g.arrived)
	<-g.open
}

// gatedStore holds chosen calls once armed: the n-th armed Load (counted
// from 1) after it has read, and the first armed Delete before it deletes.
// Every other call passes straight through.
type gatedStore struct {
	*session.MemoryStore

	armed   atomic.Bool
	loads   atomic.Int32
	deletes atomic.Int32

	loadGates map[int32]*gate
	delete    *gate
}

func (s *gatedStore) Load(ctx context.Context, id string) (*session.Session, error) {
	got, err := s.MemoryStore.Load(ctx, id)
	if s.armed.Load() {
		if g, ok := s.loadGates[s.loads.Add(1)]; ok {
			g.pass()
		}
	}

	return got, err
}

func (s *gatedStore) Delete(ctx context.Context, id string) error {
	if s.armed.Load() && s.delete != nil && s.deletes.Add(1) == 1 {
		s.delete.pass()
	}

	return s.MemoryStore.Delete(ctx, id)
}

// rotations are the two racing calls' results.
type rotations struct {
	strict, grace       *session.Session
	strictErr, graceErr error
}

// TestRotate_RacingAGraceRotationLeavesOneLiveHead pins that a strict
// rotation (second-factor verification) and a grace rotation (renewal) of
// one session cannot both produce a successor, through one manager or two
// sharing a store. Whichever supersedes second is refused by the store's
// condition with ErrSessionRenewalConflict and stores nothing; a grace
// rotation that reads the session only after the strict one superseded it
// finds a window that has already ended, which is reuse.
func TestRotate_RacingAGraceRotationLeavesOneLiveHead(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// managers is how many managers share the store; the strict
		// rotation runs on the first and the grace rotation on the last.
		managers int
		// drive runs the two rotations in one interleaving. strict and
		// grace start them; each returns a channel closed when it is done.
		drive  func(store *gatedStore, strict, grace func() <-chan struct{})
		gates  func(store *gatedStore)
		live   int
		assert func(t *testing.T, r rotations)
	}

	interleavings := []testCase{
		{
			name: "strict read first, grace superseded in between",
			gates: func(s *gatedStore) {
				s.loadGates = map[int32]*gate{1: newGate()}
			},
			drive: func(s *gatedStore, strict, grace func() <-chan struct{}) {
				strictDone := strict()
				<-s.loadGates[1].arrived
				<-grace()
				close(s.loadGates[1].open)
				<-strictDone
			},
			live: 1,
			assert: func(t *testing.T, r rotations) {
				require.NoError(t, r.graceErr)
				require.ErrorIs(t, r.strictErr, session.ErrSessionRenewalConflict)
				assert.Nil(t, r.strict)
			},
		},
		{
			name: "grace read first, strict superseded in between",
			gates: func(s *gatedStore) {
				s.loadGates = map[int32]*gate{1: newGate()}
				s.delete = newGate()
			},
			drive: func(s *gatedStore, strict, grace func() <-chan struct{}) {
				graceDone := grace()
				<-s.loadGates[1].arrived
				strictDone := strict()
				<-s.delete.arrived
				close(s.loadGates[1].open)
				<-graceDone
				close(s.delete.open)
				<-strictDone
			},
			live: 1,
			assert: func(t *testing.T, r rotations) {
				require.NoError(t, r.strictErr)
				require.ErrorIs(t, r.graceErr, session.ErrSessionRenewalConflict)
				assert.Nil(t, r.grace)
			},
		},
		{
			name: "grace read after strict superseded, before its delete",
			gates: func(s *gatedStore) {
				s.delete = newGate()
			},
			drive: func(s *gatedStore, strict, grace func() <-chan struct{}) {
				strictDone := strict()
				<-s.delete.arrived
				<-grace()
				close(s.delete.open)
				<-strictDone
			},
			live: 0,
			assert: func(t *testing.T, r rotations) {
				require.NoError(t, r.strictErr)
				require.ErrorIs(t, r.graceErr, session.ErrSessionReused)
				assert.Nil(t, r.grace)
			},
		},
	}

	var cases []testCase
	for _, managers := range []int{1, 2} {
		for _, tc := range interleavings {
			tc.managers = managers
			tc.name += map[int]string{1: ", one manager", 2: ", two managers sharing one store"}[managers]
			cases = append(cases, tc)
		}
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(createdAt)
			inner := session.NewMemoryStore(session.WithMemoryStoreClock(clk))
			store := &gatedStore{MemoryStore: inner}
			tc.gates(store)
			ms := make([]*session.Manager, tc.managers)
			for i := range ms {
				ms[i] = managerFor(t, session.WithStore(store), session.WithClock(clk))
			}
			s, err := ms[0].Create(t.Context(), testUser)
			require.NoError(t, err)
			store.armed.Store(true)

			var r rotations
			strict := func() <-chan struct{} {
				done := make(chan struct{})
				go func() {
					defer close(done)
					r.strict, r.strictErr = ms[0].Rotate(t.Context(), s)
				}()

				return done
			}
			grace := func() <-chan struct{} {
				done := make(chan struct{})
				go func() {
					defer close(done)
					r.grace, _, r.graceErr = ms[tc.managers-1].RotateWithGrace(t.Context(), s, 30*time.Second)
				}()

				return done
			}
			tc.drive(store, strict, grace)

			live := 0
			for _, got := range []*session.Session{r.strict, r.grace} {
				if got == nil {
					continue
				}
				stored, loadErr := inner.Load(t.Context(), got.ID)
				if loadErr == nil && stored.SupersededAt.IsZero() {
					live++
				}
			}
			assert.Equal(t, tc.live, live, "live heads left in the family")
			tc.assert(t, r)
		})
	}
}

// failingDeleteStore refuses every Delete, which is the last write a strict
// rotation makes.
type failingDeleteStore struct {
	*session.MemoryStore
}

func (failingDeleteStore) Delete(context.Context, string) error { return errStoreWrite }

// TestRotate_FailedDeleteLeavesTheOldHandleReused pins that a strict rotation
// whose final delete fails still fails safe: the old record is left
// superseded with a window that has already ended, so presenting the
// pre-rotation handle is reuse and revokes the family, rather than a second
// live head beside the successor.
func TestRotate_FailedDeleteLeavesTheOldHandleReused(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		options []session.ManagerOption
		// present presents the old handle after the failed rotation.
		present func(t *testing.T, m *session.Manager, old *session.Session) error
	}

	cases := []testCase{
		{
			name: "loading it",
			present: func(t *testing.T, m *session.Manager, old *session.Session) error {
				_, err := m.Load(t.Context(), old.ID)

				return err
			},
		},
		{
			name: "renewing it",
			present: func(t *testing.T, m *session.Manager, old *session.Session) error {
				_, _, err := m.RotateWithGrace(t.Context(), old, 30*time.Second)

				return err
			},
		},
		{
			name:    "renewing it with unused-successor recovery on",
			options: []session.ManagerOption{session.WithUnusedSuccessorRecovery()},
			present: func(t *testing.T, m *session.Manager, old *session.Session) error {
				loaded, err := m.LoadForRenewal(t.Context(), old.ID)
				if err != nil {
					return err
				}
				_, _, err = m.RotateWithGrace(t.Context(), loaded, 30*time.Second)

				return err
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(createdAt)
			inner := session.NewMemoryStore(session.WithMemoryStoreClock(clk))
			opts := append([]session.ManagerOption{
				session.WithStore(failingDeleteStore{MemoryStore: inner}),
				session.WithClock(clk),
			}, tc.options...)
			m := managerFor(t, opts...)
			old, err := m.Create(t.Context(), testUser)
			require.NoError(t, err)

			rotated, err := m.Rotate(t.Context(), old)
			require.ErrorIs(t, err, errStoreWrite)
			assert.Nil(t, rotated)

			stored, err := inner.Load(t.Context(), old.ID)
			require.NoError(t, err)
			assert.False(t, stored.SupersededAt.IsZero(), "the old record must be superseded")
			assert.True(t, stored.AcceptUntil.Equal(clk.Now()), "the old record's window must already have ended")

			clk.Advance(time.Second)
			require.ErrorIs(t, tc.present(t, m, old), session.ErrSessionReused)
			assert.Zero(t, inner.Len(), "reuse must revoke the whole family, the successor included")
		})
	}
}
