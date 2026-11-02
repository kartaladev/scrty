package session_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/session"
)

// endFixture is what one end-by-handle case runs against: the manager, the
// store behind it, and the sessions it created, by name.
type endFixture struct {
	m     *session.Sessions
	store *session.MemoryStore
	s     map[string]*session.Session
}

// newEndFixture creates, on one clock, the caller's current sign-in, another
// of the caller's sign-ins renewed once, and a sign-in of another user.
func newEndFixture(t *testing.T) endFixture {
	t.Helper()

	clk := clockwork.NewFakeClockAt(createdAt)
	m, store := managerOnClock(t, clk)

	current, err := m.Create(t.Context(), testUser)
	require.NoError(t, err)
	laptop, err := m.Create(t.Context(), testUser)
	require.NoError(t, err)
	laptopNext := renewed(t, m, clk, laptop, time.Minute)
	foreign, err := m.Create(t.Context(), otherUser)
	require.NoError(t, err)

	return endFixture{m: m, store: store, s: map[string]*session.Session{
		"current": current, "laptop": laptop, "laptopNext": laptopNext, "foreign": foreign,
	}}
}

// stored reports whether the store still holds the session.
func (f endFixture) stored(t *testing.T, name string) bool {
	t.Helper()

	_, err := f.store.Load(t.Context(), f.s[name].ID)
	if err == nil {
		return true
	}
	require.ErrorIs(t, err, session.ErrNotFound)

	return false
}

// assertStored asserts exactly which named sessions the store still holds.
func (f endFixture) assertStored(t *testing.T, want ...string) {
	t.Helper()

	kept := map[string]bool{}
	for _, name := range want {
		kept[name] = true
	}
	for name := range f.s {
		assert.Equal(t, kept[name], f.stored(t, name), "whether %s is still stored", name)
	}
}

func TestSessions_EndSignIn(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		handle func(f endFixture) string
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, f endFixture, err error)
	}

	cases := []testCase{
		{
			name:   "the user's own handle revokes the whole family",
			handle: func(f endFixture) string { return f.s["laptop"].FamilyID.String() },
			assert: func(t *testing.T, f endFixture, err error) {
				require.NoError(t, err)
				f.assertStored(t, "current", "foreign")
			},
		},
		{
			name:   "the current sign-in's own handle revokes it, as a logout",
			handle: func(f endFixture) string { return f.s["current"].FamilyID.String() },
			assert: func(t *testing.T, f endFixture, err error) {
				require.NoError(t, err)
				f.assertStored(t, "laptop", "laptopNext", "foreign")
				_, err = f.m.Load(t.Context(), f.s["current"].ID)
				require.ErrorIs(t, err, session.ErrNotFound, "the current session no longer loads")
			},
		},
		{
			name:   "a malformed handle is not found and revokes nothing",
			handle: func(endFixture) string { return "not-a-family" },
			assert: func(t *testing.T, f endFixture, err error) {
				require.ErrorIs(t, err, session.ErrNotFound)
				f.assertStored(t, "current", "laptop", "laptopNext", "foreign")
			},
		},
		{
			name:   "an empty handle is not found and revokes nothing",
			handle: func(endFixture) string { return "" },
			assert: func(t *testing.T, f endFixture, err error) {
				require.ErrorIs(t, err, session.ErrNotFound)
				f.assertStored(t, "current", "laptop", "laptopNext", "foreign")
			},
		},
		{
			name:   "the nil family is not found and revokes nothing",
			handle: func(endFixture) string { return "00000000-0000-0000-0000-000000000000" },
			assert: func(t *testing.T, f endFixture, err error) {
				require.ErrorIs(t, err, session.ErrNotFound)
				f.assertStored(t, "current", "laptop", "laptopNext", "foreign")
			},
		},
		{
			name:   "an unknown handle is not found and revokes nothing",
			handle: func(endFixture) string { return "0190b5a8-7c4e-7d3a-9b1e-2f3a4b5c6d7e" },
			assert: func(t *testing.T, f endFixture, err error) {
				require.ErrorIs(t, err, session.ErrNotFound)
				f.assertStored(t, "current", "laptop", "laptopNext", "foreign")
			},
		},
		{
			name:   "another user's handle is not found and revokes nothing",
			handle: func(f endFixture) string { return f.s["foreign"].FamilyID.String() },
			assert: func(t *testing.T, f endFixture, err error) {
				require.ErrorIs(t, err, session.ErrNotFound)
				f.assertStored(t, "current", "laptop", "laptopNext", "foreign")
			},
		},
		{
			name:   "a cancelled context revokes nothing",
			handle: func(f endFixture) string { return f.s["laptop"].FamilyID.String() },
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			assert: func(t *testing.T, f endFixture, err error) {
				require.ErrorIs(t, err, context.Canceled)
				f.assertStored(t, "current", "laptop", "laptopNext", "foreign")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newEndFixture(t)
			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			err := f.m.EndSignIn(ctx, testUser, tc.handle(f))
			tc.assert(t, f, err)
		})
	}
}

// heldExceptStore holds DeleteByUserExcept after it is called and before it
// reaches the store, until released, so a renewal can commit in between.
type heldExceptStore struct {
	*session.MemoryStore

	entered, release chan struct{}
}

func (s *heldExceptStore) DeleteByUserExcept(ctx context.Context, user identity.UserID, keep string) (int, error) {
	close(s.entered)
	<-s.release

	return s.MemoryStore.DeleteByUserExcept(ctx, user, keep)
}

func TestSessions_EndSignIn_Others(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		current func(f endFixture) *session.Session
		assert  func(t *testing.T, f endFixture, n int, err error)
	}

	cases := []testCase{
		{
			name:    "every other family of the user goes, the current one and other users' stay",
			current: func(f endFixture) *session.Session { return f.s["current"] },
			assert: func(t *testing.T, f endFixture, n int, err error) {
				require.NoError(t, err)
				assert.Equal(t, 2, n)
				f.assertStored(t, "current", "foreign")
			},
		},
		{
			name:    "a current sign-in inside its grace window keeps its live successor",
			current: func(f endFixture) *session.Session { return f.s["laptop"] },
			assert: func(t *testing.T, f endFixture, n int, err error) {
				require.NoError(t, err)
				assert.Equal(t, 1, n)
				f.assertStored(t, "laptop", "laptopNext", "foreign")
			},
		},
		{
			name:    "no current session is refused and ends nothing",
			current: func(endFixture) *session.Session { return nil },
			assert: func(t *testing.T, f endFixture, _ int, err error) {
				require.Error(t, err)
				f.assertStored(t, "current", "laptop", "laptopNext", "foreign")
			},
		},
		{
			name:    "another user's session as current is refused and ends nothing",
			current: func(f endFixture) *session.Session { return f.s["foreign"] },
			assert: func(t *testing.T, f endFixture, _ int, err error) {
				require.Error(t, err)
				f.assertStored(t, "current", "laptop", "laptopNext", "foreign")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newEndFixture(t)
			n, err := f.m.EndOtherSignIns(t.Context(), testUser, tc.current(f))
			tc.assert(t, f, n, err)
		})
	}
}

// TestSessions_EndSignIn_OthersDuringRenewal pins that ending the user's other
// sign-ins keeps the successor a renewal of the current sign-in commits while
// the end is in flight.
func TestSessions_EndSignIn_OthersDuringRenewal(t *testing.T) {
	t.Parallel()

	t.Run("a renewal committed between the call and the store's delete survives", func(t *testing.T) {
		t.Parallel()

		clk := clockwork.NewFakeClockAt(createdAt)
		mem, err := session.NewMemoryStore(session.WithMemoryStoreClock(clk))
		require.NoError(t, err)
		store := &heldExceptStore{MemoryStore: mem, entered: make(chan struct{}), release: make(chan struct{})}
		m := managerFor(t, session.WithStore(store), session.WithClock(clk))

		current, err := m.Create(t.Context(), testUser)
		require.NoError(t, err)
		other, err := m.Create(t.Context(), testUser)
		require.NoError(t, err)

		done := make(chan error, 1)
		go func() {
			_, err := m.EndOtherSignIns(t.Context(), testUser, current)
			done <- err
		}()

		select {
		case <-store.entered:
		case err := <-done:
			require.FailNow(t, "ending the other sign-ins never reached the store's atomic keep-and-delete", "returned %v", err)
		}
		successor, _, err := m.RotateWithGrace(t.Context(), current, time.Minute)
		require.NoError(t, err)
		close(store.release)
		require.NoError(t, <-done)

		_, err = mem.Load(t.Context(), successor.ID)
		require.NoError(t, err, "the renewal's successor survives")
		_, err = mem.Load(t.Context(), other.ID)
		require.ErrorIs(t, err, session.ErrNotFound, "the other sign-in is ended")
	})

	t.Run("racing at a barrier, the successor always survives", func(t *testing.T) {
		t.Parallel()

		for range 50 {
			clk := clockwork.NewFakeClockAt(createdAt)
			m, store := managerOnClock(t, clk)
			current, err := m.Create(t.Context(), testUser)
			require.NoError(t, err)
			other, err := m.Create(t.Context(), testUser)
			require.NoError(t, err)

			var (
				wg        sync.WaitGroup
				barrier   = make(chan struct{})
				successor *session.Session
				renewErr  error
				endErr    error
			)
			wg.Add(2)
			go func() {
				defer wg.Done()
				<-barrier
				successor, _, renewErr = m.RotateWithGrace(t.Context(), current, time.Minute)
			}()
			go func() {
				defer wg.Done()
				<-barrier
				_, endErr = m.EndOtherSignIns(t.Context(), testUser, current)
			}()
			close(barrier)
			wg.Wait()

			require.NoError(t, renewErr)
			require.NoError(t, endErr)
			_, err = store.Load(t.Context(), successor.ID)
			require.NoError(t, err, "the renewal's successor survives")
			_, err = store.Load(t.Context(), other.ID)
			require.ErrorIs(t, err, session.ErrNotFound, "the other sign-in is ended")
		}
	})
}

// hangUpExceptStore stands in for a store whose caller hangs up while
// DeleteByUserExcept runs: it cancels the caller's context with a cause and
// answers as a driver does, with an error wrapping that cause and not
// context.Canceled itself.
type hangUpExceptStore struct {
	*session.MemoryStore

	cancel context.CancelCauseFunc
	cause  error
}

func (s *hangUpExceptStore) DeleteByUserExcept(context.Context, identity.UserID, string) (int, error) {
	s.cancel(s.cause)

	return 0, fmt.Errorf("driver: statement interrupted: %w", s.cause)
}

// TestSessions_EndOtherSignIns_HangUp pins that a caller who hangs up while
// the other sign-ins are being ended gets its context's error, as the listing
// and ending one sign-in answer, and not the outage's text.
func TestSessions_EndOtherSignIns_HangUp(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(createdAt)
	cause := errors.New("client went away")
	store := &hangUpExceptStore{
		MemoryStore: must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(clk))),
		cause:       cause,
	}
	m := managerFor(t, session.WithStore(store), session.WithClock(clk))

	current, err := m.Create(t.Context(), testUser)
	require.NoError(t, err)

	ctx, cancel := context.WithCancelCause(t.Context())
	store.cancel = cancel

	_, err = m.EndOtherSignIns(ctx, testUser, current)
	require.ErrorIs(t, err, context.Canceled)
	require.ErrorIs(t, err, cause, "the store's error stays reachable")
	assert.NotContains(t, err.Error(), "could not be ended", "a hang-up is not an outage")
	assert.NotContains(t, err.Error(), "driver", "the text is fixed library text")
}
