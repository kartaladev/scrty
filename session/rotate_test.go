package session_test

import (
	"context"
	"errors"
	"maps"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/session"
)

// errStoreWrite stands in for a store that cannot take the new entry.
var errStoreWrite = errors.New("store refused the write")

// failingWriteStore is a real store that takes the first insert — the case's
// own fixture — and refuses every later one, which is the write a rotation
// makes before it deletes anything.
type failingWriteStore struct {
	session.Store

	inserts atomic.Int64
}

func (s *failingWriteStore) Create(ctx context.Context, sess *session.Session) error {
	if s.inserts.Add(1) == 1 {
		return s.Store.Create(ctx, sess)
	}

	return errStoreWrite
}

// snapshot copies the caller-visible state of s, so a case can compare what
// rotation returned against what the session held before it ran.
func snapshot(s *session.Session) *session.Session {
	out := *s
	out.Data = maps.Clone(s.Data)

	return &out
}

// TestManagerRotate pins what rotation is for: a handle obtained before a
// privilege change stops working, the new one carries everything else, and a
// store that refuses the write leaves the caller exactly where they were.
func TestManagerRotate(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		store  func(t *testing.T) session.Store
		assert func(t *testing.T, m *session.Manager, old, got *session.Session, err error)
	}

	cases := []testCase{
		{
			name:  "the old handle stops loading and the new one carries everything",
			store: func(*testing.T) session.Store { return session.NewMemoryStore() },
			assert: func(t *testing.T, m *session.Manager, old, got *session.Session, err error) {
				require.NoError(t, err)
				assert.NotEqual(t, old.ID, got.ID)
				assert.Equal(t, old.UserID, got.UserID)
				assert.Equal(t, old.FirstFactor, got.FirstFactor)
				assert.Equal(t, old.Data, got.Data)
				assert.True(t, got.CreatedAt.Equal(old.CreatedAt))
				assert.True(t, got.AbsoluteExpiresAt.Equal(old.AbsoluteExpiresAt))

				_, loadErr := m.Load(t.Context(), old.ID)
				assert.ErrorIs(t, loadErr, session.ErrSessionNotFound)

				reloaded, loadErr := m.Load(t.Context(), got.ID)
				require.NoError(t, loadErr)
				assert.Equal(t, old.UserID, reloaded.UserID)
				assert.Equal(t, old.Data, reloaded.Data)
			},
		},
		{
			name: "a failed write leaves the old handle loadable",
			store: func(*testing.T) session.Store {
				return &failingWriteStore{Store: session.NewMemoryStore()}
			},
			assert: func(t *testing.T, m *session.Manager, old, got *session.Session, err error) {
				require.ErrorIs(t, err, errStoreWrite)
				assert.Nil(t, got)

				reloaded, loadErr := m.Load(t.Context(), old.ID)
				require.NoError(t, loadErr)
				assert.Equal(t, old.ID, reloaded.ID)
			},
		},
		{
			name:  "a handle already rotated away cannot be rotated again",
			store: func(*testing.T) session.Store { return session.NewMemoryStore() },
			assert: func(t *testing.T, m *session.Manager, old, got *session.Session, err error) {
				require.NoError(t, err)
				require.NotNil(t, got)

				again, againErr := m.Rotate(t.Context(), old)
				require.ErrorIs(t, againErr, session.ErrSessionNotFound)
				assert.Nil(t, again)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()

			m := managerFor(t, session.WithStore(tc.store(t)))
			old, err := m.Create(ctx, testUser, session.WithFirstFactor(factor.MagicLink))
			require.NoError(t, err)

			old.Data = map[string]string{"tenant": "acme"}
			require.NoError(t, m.Save(ctx, old))

			before := snapshot(old)

			got, err := m.Rotate(ctx, old)
			tc.assert(t, m, before, got, err)
		})
	}
}

// TestManagerRotateConcurrent pins that rotation cannot be made to hand out
// two live handles for one session by racing it: exactly one caller wins, and
// the handle they all started from is gone either way.
func TestManagerRotateConcurrent(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	m := managerFor(t)
	s, err := m.Create(ctx, testUser, session.WithFirstFactor(factor.Password))
	require.NoError(t, err)

	const goroutines = 16

	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		ids   []string
		start = make(chan struct{})
	)

	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			<-start

			rotated, rotErr := m.Rotate(ctx, s)
			if rotErr == nil {
				mu.Lock()
				ids = append(ids, rotated.ID)
				mu.Unlock()
			}
		}()
	}

	close(start)
	wg.Wait()

	live := 0
	for _, id := range ids {
		if _, loadErr := m.Load(ctx, id); loadErr == nil {
			live++
		}
	}

	assert.Equal(t, 1, live, "exactly one rotated handle may remain loadable")

	_, err = m.Load(ctx, s.ID)
	assert.ErrorIs(t, err, session.ErrSessionNotFound, "the original handle must not survive")
}

// barrierWait is how long a barrier insert waits for its fellows before it
// gives up. It is long enough that a machine under load still clears the
// barrier, and short enough that a rotation lock which serialises unrelated
// sessions reports a failure rather than hanging the package.
const barrierWait = 2 * time.Second

// errBarrierTimeout is what a barrier insert reports when the rotations it was
// waiting for never arrived, which is what a lock held across every session
// looks like from inside the store.
var errBarrierTimeout = errors.New("insert waited alone: rotations of distinct sessions were serialised")

// barrierStore holds every insert until want of them are in flight at once, so
// a test can tell rotations that genuinely overlap from rotations that merely
// take turns.
//
// It passes inserts straight through until arm is called, so a case can build
// its fixtures through the same manager.
type barrierStore struct {
	session.Store

	want int

	armed   atomic.Bool
	mu      sync.Mutex
	arrived int
	open    chan struct{}
}

func newBarrierStore(inner session.Store, want int) *barrierStore {
	return &barrierStore{Store: inner, want: want, open: make(chan struct{})}
}

func (s *barrierStore) arm() { s.armed.Store(true) }

func (s *barrierStore) Create(ctx context.Context, sess *session.Session) error {
	if !s.armed.Load() {
		return s.Store.Create(ctx, sess)
	}

	s.mu.Lock()
	s.arrived++
	if s.arrived == s.want {
		close(s.open)
	}
	s.mu.Unlock()

	select {
	case <-s.open:
		return s.Store.Create(ctx, sess)
	case <-time.After(barrierWait):
		return errBarrierTimeout
	}
}

// TestManagerRotateConcurrentDistinctSessions pins that the lock rotation
// takes follows the session and not the manager: two users completing a second
// factor at the same moment must not take turns, least of all across the three
// store round-trips a rotation makes.
func TestManagerRotateConcurrentDistinctSessions(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	const sessions = 8

	store := newBarrierStore(session.NewMemoryStore(), sessions)
	m := managerFor(t, session.WithStore(store))

	originals := make([]*session.Session, 0, sessions)
	for range sessions {
		s, err := m.Create(ctx, testUser, session.WithFirstFactor(factor.Password))
		require.NoError(t, err)
		originals = append(originals, s)
	}

	store.arm()

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []error
	)

	wg.Add(sessions)
	for _, s := range originals {
		go func() {
			defer wg.Done()

			_, rotErr := m.Rotate(ctx, s)

			mu.Lock()
			errs = append(errs, rotErr)
			mu.Unlock()
		}()
	}

	wg.Wait()

	for _, err := range errs {
		require.NoError(t, err, "rotations of distinct sessions must overlap")
	}
}
