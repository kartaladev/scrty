package session_test

import (
	"bytes"
	"context"
	"log/slog"
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
// finds it inside the in-flight window and re-rotates it, which knocks the
// strict successor out.
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
			// The strict rotation's in-flight window is open, so the grace
			// rotation is a re-rotation: it knocks the strict successor out,
			// and the family keeps one live head.
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
			live: 1,
			assert: func(t *testing.T, r rotations) {
				require.NoError(t, r.strictErr)
				require.NoError(t, r.graceErr)
				require.NotNil(t, r.grace)
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

// inFlightStore stands between a strict rotation's two writes: once armed,
// the first Supersede signals and waits on afterSupersede after it has
// written, and failDelete refuses every Delete, the rotation's last write.
type inFlightStore struct {
	*session.MemoryStore

	afterSupersede *gate
	failDelete     bool
}

func (s *inFlightStore) Supersede(ctx context.Context, op session.Supersession) error {
	err := s.MemoryStore.Supersede(ctx, op)
	if s.afterSupersede != nil {
		s.afterSupersede.pass()
	}

	return err
}

func (s *inFlightStore) Delete(ctx context.Context, id string) error {
	if s.failDelete {
		return errStoreWrite
	}

	return s.MemoryStore.Delete(ctx, id)
}

// inFlightFixture is a session still owing its second factor, the copy the
// verification endpoint rotates once the factor is satisfied, and what they
// run on.
type inFlightFixture struct {
	clk   *clockwork.FakeClock
	inner *session.MemoryStore
	store *inFlightStore
	m     *session.Manager
	logs  *bytes.Buffer

	// pending is the stored session; satisfied is the caller's copy with the
	// second factor met, which is what Rotate is given.
	pending, satisfied *session.Session
}

// TestRotate_OldIdentifierInFlight pins that rotation at second-factor
// verification serves the old identifier only in flight: a request that
// loads it between the supersession and the delete gets the old session as it
// was, not a reuse verdict, and a delete that fails does not fail the
// rotation. In both, the old identifier stops answering once the in-flight
// window, session.DefaultRenewalGrace, ends.
func TestRotate_OldIdentifierInFlight(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name  string
		store func(inner *session.MemoryStore) *inFlightStore
		run   func(t *testing.T, f *inFlightFixture)
	}

	cases := []testCase{
		{
			name: "a load between the writes returns the old session",
			store: func(inner *session.MemoryStore) *inFlightStore {
				return &inFlightStore{MemoryStore: inner, afterSupersede: newGate()}
			},
			run: func(t *testing.T, f *inFlightFixture) {
				type result struct {
					s   *session.Session
					err error
				}
				done := make(chan result, 1)
				go func() {
					rotated, err := f.m.Rotate(t.Context(), f.satisfied)
					done <- result{rotated, err}
				}()
				<-f.store.afterSupersede.arrived

				got, err := f.m.Load(t.Context(), f.pending.ID)
				require.NoError(t, err, "a request in flight between the writes is not reuse")
				assert.Equal(t, testUser, got.UserID)
				assert.Equal(t, session.MFAPending, got.MFA, "the old session still owes its second factor")
				assert.Equal(t, 2, f.inner.Len(), "the family was not revoked")

				close(f.store.afterSupersede.open)
				r := <-done
				require.NoError(t, r.err)
				require.NotNil(t, r.s)

				next, err := f.m.Load(t.Context(), r.s.ID)
				require.NoError(t, err, "the successor loads after the rotation")
				assert.Equal(t, session.MFASatisfied, next.MFA)

				_, err = f.m.Load(t.Context(), f.pending.ID)
				require.ErrorIs(t, err, session.ErrSessionNotFound, "once deleted the old identifier is not found")
			},
		},
		{
			name: "a failed delete does not fail the rotation",
			store: func(inner *session.MemoryStore) *inFlightStore {
				return &inFlightStore{MemoryStore: inner, failDelete: true}
			},
			run: func(t *testing.T, f *inFlightFixture) {
				rotated, err := f.m.Rotate(t.Context(), f.satisfied)
				require.NoError(t, err, "the successor is stored, so the rotation succeeded")
				require.NotNil(t, rotated)
				assert.Equal(t, session.MFASatisfied, rotated.MFA)

				logged := f.logs.String()
				assert.Contains(t, logged, "level=ERROR")
				assert.Contains(t, logged, "the session rotated from could not be deleted")
				assert.Contains(t, logged, f.pending.FamilyID.String(), "the log names the family")
				assert.NotContains(t, logged, f.pending.ID, "the log never carries the old identifier")
				assert.NotContains(t, logged, rotated.ID, "the log never carries the successor's identifier")

				next, err := f.m.Load(t.Context(), rotated.ID)
				require.NoError(t, err)
				assert.Equal(t, session.MFASatisfied, next.MFA)

				f.clk.Advance(10 * time.Second)
				old, err := f.m.Load(t.Context(), f.pending.ID)
				require.NoError(t, err, "inside the in-flight window the old identifier still loads")
				assert.Equal(t, session.MFAPending, old.MFA)

				f.clk.Advance(session.DefaultRenewalGrace + time.Second - 10*time.Second)
				_, err = f.m.Load(t.Context(), f.pending.ID)
				require.ErrorIs(t, err, session.ErrSessionReused, "after the window the old identifier is reuse")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := &inFlightFixture{clk: clockwork.NewFakeClockAt(createdAt), logs: &bytes.Buffer{}}
			f.inner = session.NewMemoryStore(session.WithMemoryStoreClock(f.clk))
			f.store = tc.store(f.inner)
			f.m = managerFor(t, session.WithStore(f.store), session.WithClock(f.clk),
				session.WithSessionLogger(slog.New(slog.NewTextHandler(f.logs, nil))))

			var err error
			f.pending, err = f.m.Create(t.Context(), testUser)
			require.NoError(t, err)
			f.pending.MFA = session.MFAPending
			require.NoError(t, f.m.Save(t.Context(), f.pending))

			satisfied := *f.pending
			satisfied.MFA = session.MFASatisfied
			satisfied.MFASatisfiedAt = f.clk.Now()
			f.satisfied = &satisfied

			tc.run(t, f)
		})
	}
}
