package session_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

// graceFixture is a manager and its memory store on one fake clock, with the
// session O created at 09:00.
type graceFixture struct {
	clk   *clockwork.FakeClock
	m     *session.Sessions
	store *session.MemoryStore
	o     *session.Session
}

func newGraceFixture(t *testing.T, opts ...session.Option) *graceFixture {
	t.Helper()

	clk := clockwork.NewFakeClockAt(createdAt)
	m, store := managerOnClock(t, clk, opts...)
	o, err := m.Create(t.Context(), testUser)
	require.NoError(t, err)

	return &graceFixture{clk: clk, m: m, store: store, o: o}
}

// renew rotates s with grace and requires it to succeed.
func (f *graceFixture) renew(ctx context.Context, t *testing.T, s *session.Session, grace time.Duration) *session.Session {
	t.Helper()

	next, _, err := f.m.RotateWithGrace(ctx, s, grace)
	require.NoError(t, err)

	return next
}

func TestRotateWithGrace(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		opts []session.Option
		// act runs the case's steps against the fixture, O created at 09:00,
		// and returns what its last step returned.
		act    func(ctx context.Context, t *testing.T, f *graceFixture) (*session.Session, error)
		assert func(t *testing.T, f *graceFixture, got *session.Session, err error)
	}

	cases := []testCase{
		{
			name: "a first rotation is fresh, keeps the family and leaves the old identifier superseded",
			act: func(ctx context.Context, t *testing.T, f *graceFixture) (*session.Session, error) {
				f.clk.Advance(10 * time.Minute)
				next, kind, err := f.m.RotateWithGrace(ctx, f.o, 30*time.Second)
				assert.Equal(t, session.RenewalFresh, kind)
				return next, err
			},
			assert: func(t *testing.T, f *graceFixture, got *session.Session, err error) {
				require.NoError(t, err)
				assert.NotEqual(t, f.o.ID, got.ID)
				assert.Equal(t, f.o.FamilyID, got.FamilyID)
				assert.Equal(t, f.o.FamilyCreatedAt, got.FamilyCreatedAt)
				assert.Equal(t, f.o.AbsoluteExpiresAt, got.AbsoluteExpiresAt, "the deadline is carried over")
				assert.True(t, got.SupersededAt.IsZero())
				assert.True(t, got.AcceptUntil.IsZero())
				assert.Empty(t, got.SuccessorDigest)
				assert.True(t, got.FirstPresentedAt.IsZero(), "a successor has not been presented yet")
				assert.Equal(t, 2, f.store.Len())
			},
		},
		{
			name: "the old identifier loads inside its window",
			act: func(ctx context.Context, t *testing.T, f *graceFixture) (*session.Session, error) {
				f.renew(ctx, t, f.o, 30*time.Second)
				f.clk.Advance(20 * time.Second)
				return f.m.Load(ctx, f.o.ID)
			},
			assert: func(t *testing.T, _ *graceFixture, got *session.Session, err error) {
				require.NoError(t, err)
				assert.Equal(t, createdAt, got.SupersededAt)
				assert.Equal(t, createdAt.Add(30*time.Second), got.AcceptUntil)
			},
		},
		{
			// O ends at 21:00; rotated at 20:59:50 with 30 s, its window ends
			// at 21:00 rather than 21:00:20.
			name: "the window is capped at the absolute deadline",
			opts: []session.Option{session.WithIdleTimeout(12 * time.Hour)},
			act: func(ctx context.Context, t *testing.T, f *graceFixture) (*session.Session, error) {
				f.clk.Advance(12*time.Hour - 10*time.Second)
				f.renew(ctx, t, f.o, 30*time.Second)
				return f.m.Load(ctx, f.o.ID)
			},
			assert: func(t *testing.T, f *graceFixture, got *session.Session, err error) {
				require.NoError(t, err)
				assert.Equal(t, f.o.AbsoluteExpiresAt, got.AcceptUntil)
			},
		},
		{
			name: "a negative grace is a configuration error and stores nothing",
			act: func(ctx context.Context, _ *testing.T, f *graceFixture) (*session.Session, error) {
				next, _, err := f.m.RotateWithGrace(ctx, f.o, -time.Second)
				return next, err
			},
			assert: assertGraceRefused,
		},
		{
			name: "a grace above the ceiling is a configuration error and stores nothing",
			act: func(ctx context.Context, _ *testing.T, f *graceFixture) (*session.Session, error) {
				next, _, err := f.m.RotateWithGrace(ctx, f.o, session.MaxRenewalGrace+time.Second)
				return next, err
			},
			assert: assertGraceRefused,
		},
		{
			name: "a grace of exactly the ceiling is accepted",
			act: func(ctx context.Context, t *testing.T, f *graceFixture) (*session.Session, error) {
				f.renew(ctx, t, f.o, session.MaxRenewalGrace)
				return f.m.Load(ctx, f.o.ID)
			},
			assert: func(t *testing.T, _ *graceFixture, got *session.Session, err error) {
				require.NoError(t, err)
				assert.Equal(t, createdAt.Add(5*time.Minute), got.AcceptUntil)
			},
		},
		{
			name: "re-rotation inside the window issues a fresh successor and makes the previous one reuse",
			act: func(ctx context.Context, t *testing.T, f *graceFixture) (*session.Session, error) {
				s1 := f.renew(ctx, t, f.o, 30*time.Second)
				f.clk.Advance(10 * time.Second)
				s2, kind, err := f.m.RotateWithGrace(ctx, f.o, 30*time.Second)
				require.NoError(t, err)
				assert.Equal(t, session.RenewalReRotation, kind)
				assert.NotEqual(t, s1.ID, s2.ID)
				assert.Equal(t, f.o.FamilyID, s2.FamilyID)

				_, err = f.m.Load(ctx, s1.ID)
				return s2, err
			},
			assert: func(t *testing.T, _ *graceFixture, _ *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrReused)
			},
		},
		{
			name: "re-rotation never extends the old identifier's window",
			act: func(ctx context.Context, t *testing.T, f *graceFixture) (*session.Session, error) {
				f.renew(ctx, t, f.o, 30*time.Second)
				f.clk.Advance(20 * time.Second)
				f.renew(ctx, t, f.o, 30*time.Second)
				f.clk.Advance(10 * time.Second)
				return f.m.Load(ctx, f.o.ID)
			},
			assert: func(t *testing.T, _ *graceFixture, _ *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrReused, "the window ended at 09:00:30")
			},
		},
		{
			name: "presentation after the window is reuse, matches expiry, and revokes the family",
			act: func(ctx context.Context, t *testing.T, f *graceFixture) (*session.Session, error) {
				s1 := f.renew(ctx, t, f.o, 30*time.Second)
				f.clk.Advance(5 * time.Minute)
				_, err := f.m.Load(ctx, f.o.ID)
				require.ErrorIs(t, err, session.ErrReused)
				require.ErrorIs(t, err, session.ErrExpired)

				return f.m.Load(ctx, s1.ID)
			},
			assert: func(t *testing.T, f *graceFixture, _ *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrNotFound)
				assert.Zero(t, f.store.Len())
			},
		},
		{
			name: "reuse is still detected hours after the window",
			act: func(ctx context.Context, t *testing.T, f *graceFixture) (*session.Session, error) {
				f.renew(ctx, t, f.o, 30*time.Second)
				f.clk.Advance(9 * time.Hour)
				return f.m.Load(ctx, f.o.ID)
			},
			assert: func(t *testing.T, f *graceFixture, _ *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrReused)
				assert.Zero(t, f.store.Len())
			},
		},
		{
			// Logout and the other endpoints reach a session through Load, so
			// the verdict is the same there as at the bearer.
			name: "after reuse the logout path's delete finds the family gone",
			act: func(ctx context.Context, t *testing.T, f *graceFixture) (*session.Session, error) {
				f.renew(ctx, t, f.o, 30*time.Second)
				f.clk.Advance(5 * time.Minute)
				_, err := f.m.Load(ctx, f.o.ID)
				require.ErrorIs(t, err, session.ErrReused)

				err = f.m.Delete(ctx, f.o.ID)
				if errors.Is(err, session.ErrNotFound) {
					err = nil
				}
				return nil, err
			},
			assert: func(t *testing.T, f *graceFixture, _ *session.Session, err error) {
				require.NoError(t, err)
				n, err := f.m.RevokeFamily(t.Context(), f.o.FamilyID)
				require.NoError(t, err)
				assert.Zero(t, n, "the family was already gone")
			},
		},
		{
			name: "the first load records first presentation once",
			act: func(ctx context.Context, t *testing.T, f *graceFixture) (*session.Session, error) {
				first, err := f.m.Load(ctx, f.o.ID)
				require.NoError(t, err)
				assert.Equal(t, createdAt, first.FirstPresentedAt)

				f.clk.Advance(time.Minute)
				return f.m.Load(ctx, f.o.ID)
			},
			assert: func(t *testing.T, _ *graceFixture, got *session.Session, err error) {
				require.NoError(t, err)
				assert.Equal(t, createdAt, got.FirstPresentedAt, "a later load moved the first presentation")
			},
		},
		{
			name: "strict rotation of a superseded identifier past its window is reuse",
			act: func(ctx context.Context, t *testing.T, f *graceFixture) (*session.Session, error) {
				f.renew(ctx, t, f.o, 30*time.Second)
				f.clk.Advance(time.Minute)
				return f.m.Rotate(ctx, f.o)
			},
			assert: func(t *testing.T, f *graceFixture, _ *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrReused)
				assert.Zero(t, f.store.Len())
			},
		},
		{
			name: "strict rotation of a superseded identifier inside its window is a conflict and writes nothing",
			act: func(ctx context.Context, t *testing.T, f *graceFixture) (*session.Session, error) {
				s1 := f.renew(ctx, t, f.o, 30*time.Second)
				f.clk.Advance(10 * time.Second)
				old, err := f.m.Load(ctx, f.o.ID)
				require.NoError(t, err)

				got, err := f.m.Rotate(ctx, old)
				require.ErrorIs(t, err, session.ErrRenewalConflict)

				_, loadErr := f.m.Load(ctx, s1.ID)
				require.NoError(t, loadErr, "the current successor must still load")
				return got, err
			},
			assert: func(t *testing.T, f *graceFixture, got *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrRenewalConflict)
				assert.Nil(t, got)
				assert.Equal(t, 2, f.store.Len(), "a refused strict rotation stored a session or deleted one")
				old, loadErr := f.store.Load(t.Context(), f.o.ID)
				require.NoError(t, loadErr)
				assert.Equal(t, createdAt.Add(30*time.Second), old.AcceptUntil, "the old window was changed")
			},
		},
		{
			// Two live heads otherwise: T, and the S2 a re-rotation of O would
			// issue, with no later presentation exposing either.
			name: "re-rotation after the successor was renewed is reuse and revokes the family",
			act: func(ctx context.Context, t *testing.T, f *graceFixture) (*session.Session, error) {
				s1 := f.renew(ctx, t, f.o, 30*time.Second)
				f.clk.Advance(5 * time.Second)
				f.renew(ctx, t, s1, 30*time.Second)
				f.clk.Advance(5 * time.Second)
				next, kind, err := f.m.RotateWithGrace(ctx, f.o, 30*time.Second)
				assert.Zero(t, kind)
				return next, err
			},
			assert: func(t *testing.T, f *graceFixture, got *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrReused)
				assert.Nil(t, got)
				assert.Zero(t, f.store.Len(), "the family was not revoked")
			},
		},
		{
			name: "re-rotation after the successor was deleted is reuse and revokes the family",
			act: func(ctx context.Context, t *testing.T, f *graceFixture) (*session.Session, error) {
				s1 := f.renew(ctx, t, f.o, 30*time.Second)
				require.NoError(t, f.m.Delete(ctx, s1.ID))
				f.clk.Advance(10 * time.Second)
				next, _, err := f.m.RotateWithGrace(ctx, f.o, 30*time.Second)
				return next, err
			},
			assert: func(t *testing.T, f *graceFixture, got *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrReused)
				assert.Nil(t, got)
				assert.Zero(t, f.store.Len(), "the family was not revoked")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newGraceFixture(t, tc.opts...)
			got, err := tc.act(t.Context(), t, f)
			tc.assert(t, f, got, err)
		})
	}
}

// assertGraceRefused asserts a rotation was refused as a wiring mistake and
// left O alone.
func assertGraceRefused(t *testing.T, f *graceFixture, got *session.Session, err error) {
	t.Helper()

	require.ErrorIs(t, err, session.ErrConfig)
	assert.Nil(t, got)
	assert.Equal(t, 1, f.store.Len(), "a refused rotation stored a successor")
	old, err := f.m.Load(t.Context(), f.o.ID)
	require.NoError(t, err)
	assert.True(t, old.SupersededAt.IsZero(), "a refused rotation superseded the old session")
}

// TestLoad_JudgesTheWindowByItsOwnClock pins that a manager judges
// AcceptUntil by its own reading: one whose clock is ahead refuses earlier,
// never later than AcceptUntil by its own clock.
func TestLoad_JudgesTheWindowByItsOwnClock(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// at is the reading manager's clock; the window ends at 09:00:30.
		at     time.Time
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name: "a clock at 09:00:29 is inside the window",
			at:   createdAt.Add(29 * time.Second),
			assert: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "a clock at exactly 09:00:30 is reuse",
			at:   createdAt.Add(30 * time.Second),
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, session.ErrReused)
			},
		},
		{
			name: "a clock at 09:00:31 is reuse",
			at:   createdAt.Add(31 * time.Second),
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, session.ErrReused)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newGraceFixture(t)
			f.renew(t.Context(), t, f.o, 30*time.Second)

			reader := managerFor(t, session.WithStore(f.store), session.WithClock(clockwork.NewFakeClockAt(tc.at)))
			_, err := reader.Load(t.Context(), f.o.ID)
			tc.assert(t, err)
		})
	}
}

func TestLoad_FirstPresentation(t *testing.T) {
	t.Parallel()

	const sid = "first-presentation"

	type testCase struct {
		name   string
		stored func() *session.Session
		expect func(store *MockStore)
		assert func(t *testing.T, got *session.Session, err error)
	}

	cases := []testCase{
		{
			name:   "a never-presented session is marked once, at the manager's time",
			stored: func() *session.Session { return liveUnpresented(sid) },
			expect: func(store *MockStore) {
				store.EXPECT().MarkPresented(gomock.Any(), sid, createdAt).Return(nil).Times(1)
			},
			assert: func(t *testing.T, got *session.Session, err error) {
				require.NoError(t, err)
				assert.Equal(t, createdAt, got.FirstPresentedAt)
			},
		},
		{
			name: "an already-presented session is not marked again",
			stored: func() *session.Session {
				s := liveUnpresented(sid)
				s.FirstPresentedAt = createdAt.Add(-time.Minute)
				return s
			},
			expect: func(*MockStore) {},
			assert: func(t *testing.T, got *session.Session, err error) {
				require.NoError(t, err)
				assert.Equal(t, createdAt.Add(-time.Minute), got.FirstPresentedAt)
			},
		},
		{
			name:   "a failing mark re-loads the session, and one still live is returned, unmarked",
			stored: func() *session.Session { return liveUnpresented(sid) },
			expect: func(store *MockStore) {
				store.EXPECT().MarkPresented(gomock.Any(), sid, createdAt).Return(errStoreQuotes).Times(1)
				store.EXPECT().Load(gomock.Any(), sid).Return(liveUnpresented(sid), nil).Times(1)
			},
			assert: func(t *testing.T, got *session.Session, err error) {
				require.NoError(t, err)
				require.NotNil(t, got)
				assert.True(t, got.FirstPresentedAt.IsZero(), "the session claims a mark the store refused")
			},
		},
		{
			name:   "a failing mark whose re-load fails too fails the load closed",
			stored: func() *session.Session { return liveUnpresented(sid) },
			expect: func(store *MockStore) {
				store.EXPECT().MarkPresented(gomock.Any(), sid, createdAt).Return(errStoreQuotes).Times(1)
				store.EXPECT().Load(gomock.Any(), sid).Return(nil, errStoreQuotes).Times(1)
			},
			assert: func(t *testing.T, got *session.Session, err error) {
				require.ErrorIs(t, err, errStoreQuotes)
				assert.NotContains(t, err.Error(), "alice@example.com")
				assert.Nil(t, got)
			},
		},
		{
			name:   "a mark refused as superseded re-loads the session, and a knocked-out one is reuse",
			stored: func() *session.Session { return liveUnpresented(sid) },
			expect: func(store *MockStore) {
				store.EXPECT().MarkPresented(gomock.Any(), sid, createdAt).Return(session.ErrSuperseded).Times(1)
				knockedOut := liveUnpresented(sid)
				knockedOut.SupersededAt = createdAt
				knockedOut.AcceptUntil = createdAt
				store.EXPECT().Load(gomock.Any(), sid).Return(knockedOut, nil).Times(1)
				store.EXPECT().DeleteFamily(gomock.Any(), graceFamily).Return(1, nil).Times(1)
			},
			assert: func(t *testing.T, got *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrReused)
				assert.Nil(t, got)
			},
		},
		{
			name:   "a mark refused as superseded inside the window returns the re-loaded session, unmarked",
			stored: func() *session.Session { return liveUnpresented(sid) },
			expect: func(store *MockStore) {
				store.EXPECT().MarkPresented(gomock.Any(), sid, createdAt).Return(session.ErrSuperseded).Times(1)
				renewed := liveUnpresented(sid)
				renewed.SupersededAt = createdAt
				renewed.AcceptUntil = createdAt.Add(30 * time.Second)
				renewed.SuccessorDigest = []byte("digest")
				store.EXPECT().Load(gomock.Any(), sid).Return(renewed, nil).Times(1)
			},
			assert: func(t *testing.T, got *session.Session, err error) {
				require.NoError(t, err)
				require.NotNil(t, got)
				assert.Equal(t, createdAt, got.SupersededAt, "the load returned the copy read before the supersession")
				assert.True(t, got.FirstPresentedAt.IsZero())
			},
		},
		{
			name:   "a mark refused as superseded whose re-load fails is a store failure",
			stored: func() *session.Session { return liveUnpresented(sid) },
			expect: func(store *MockStore) {
				store.EXPECT().MarkPresented(gomock.Any(), sid, createdAt).Return(session.ErrSuperseded).Times(1)
				store.EXPECT().Load(gomock.Any(), sid).Return(nil, errStoreQuotes).Times(1)
			},
			assert: func(t *testing.T, got *session.Session, err error) {
				require.ErrorIs(t, err, errStoreQuotes)
				assert.NotContains(t, err.Error(), "alice@example.com")
				assert.Nil(t, got)
			},
		},
		{
			name:   "a mark refused as not found is not found",
			stored: func() *session.Session { return liveUnpresented(sid) },
			expect: func(store *MockStore) {
				store.EXPECT().MarkPresented(gomock.Any(), sid, createdAt).Return(session.ErrNotFound).Times(1)
			},
			assert: func(t *testing.T, got *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrNotFound)
				assert.Nil(t, got)
			},
		},
		{
			name: "a superseded session inside its window is not marked",
			stored: func() *session.Session {
				s := liveUnpresented(sid)
				s.SupersededAt = createdAt.Add(-10 * time.Second)
				s.AcceptUntil = createdAt.Add(20 * time.Second)
				s.SuccessorDigest = []byte("digest")
				return s
			},
			expect: func(*MockStore) {},
			assert: func(t *testing.T, got *session.Session, err error) {
				require.NoError(t, err)
				assert.True(t, got.FirstPresentedAt.IsZero())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := NewMockStore(gomock.NewController(t))
			store.EXPECT().Load(gomock.Any(), sid).Return(tc.stored(), nil).Times(1)
			tc.expect(store)

			m := managerFor(t, session.WithStore(store), session.WithClock(clockwork.NewFakeClockAt(createdAt)))
			got, err := m.Load(t.Context(), sid)
			tc.assert(t, got, err)
		})
	}
}

// renewalSession is a live session of a family that started at familyStart,
// stored as a renewal at now would find it: created at now, idle until an
// hour later, absolute deadline abs.
func renewalSession(sid string, familyStart, now, abs time.Time) *session.Session {
	return &session.Session{
		ID:                sid,
		UserID:            testUser,
		CreatedAt:         now,
		LastAccessedAt:    now,
		IdleExpiresAt:     now.Add(time.Hour),
		AbsoluteExpiresAt: abs,
		FamilyID:          graceFamily,
		FamilyCreatedAt:   familyStart,
	}
}

func TestRenewalLifetime(t *testing.T) {
	t.Parallel()

	// long is a manager allowing 30-day sessions in 90-day families.
	long := []session.Option{
		session.WithMaxAbsoluteLifetime(30 * day),
		session.WithMaxFamilyLifetime(90 * day),
	}

	type testCase struct {
		name string
		opts []session.Option
		// familyStart, now and abs place the stored session; now is also the
		// manager's clock.
		familyStart, now, abs time.Time
		rotate                func(ctx context.Context, m *session.Sessions, s *session.Session) (*session.Session, error)
		assert                func(t *testing.T, store *session.MemoryStore, s, got *session.Session, err error)
	}

	withLifetime := func(d time.Duration) func(context.Context, *session.Sessions, *session.Session) (*session.Session, error) {
		return func(ctx context.Context, m *session.Sessions, s *session.Session) (*session.Session, error) {
			next, _, err := m.RotateWithGrace(ctx, s, 30*time.Second, session.WithSuccessorLifetime(d))
			return next, err
		}
	}
	refused := func(t *testing.T, store *session.MemoryStore, s, got *session.Session, err error) {
		t.Helper()
		require.ErrorIs(t, err, session.ErrConfig)
		assert.Nil(t, got)
		assert.Equal(t, 1, store.Len(), "a refused renewal stored a successor")
		old, err := store.Load(t.Context(), s.ID)
		require.NoError(t, err)
		assert.True(t, old.SupersededAt.IsZero(), "a refused renewal superseded the old session")
	}

	cases := []testCase{
		{
			name:        "the default carries the deadline over",
			familyStart: createdAt, now: createdAt.Add(6 * time.Hour), abs: createdAt.Add(12 * time.Hour),
			rotate: func(ctx context.Context, m *session.Sessions, s *session.Session) (*session.Session, error) {
				next, _, err := m.RotateWithGrace(ctx, s, 30*time.Second)
				return next, err
			},
			assert: func(t *testing.T, _ *session.MemoryStore, _, got *session.Session, err error) {
				require.NoError(t, err)
				assert.Equal(t, createdAt.Add(12*time.Hour), got.AbsoluteExpiresAt)
				assert.Equal(t, createdAt.Add(6*time.Hour+30*time.Minute), got.IdleExpiresAt, "the idle deadline starts afresh")
			},
		},
		{
			name:        "the default family maximum allows no extension",
			familyStart: createdAt, now: createdAt.Add(6 * time.Hour), abs: createdAt.Add(12 * time.Hour),
			rotate: withLifetime(12 * time.Hour),
			assert: func(t *testing.T, _ *session.MemoryStore, _, got *session.Session, err error) {
				require.NoError(t, err)
				assert.Equal(t, createdAt.Add(12*time.Hour), got.AbsoluteExpiresAt)
			},
		},
		{
			name:        "a chosen 30 days on day 20 of a 90-day family extends",
			opts:        long,
			familyStart: createdAt, now: createdAt.Add(20 * day), abs: createdAt.Add(30 * day),
			rotate: withLifetime(30 * day),
			assert: func(t *testing.T, _ *session.MemoryStore, _, got *session.Session, err error) {
				require.NoError(t, err)
				assert.Equal(t, createdAt.Add(50*day), got.AbsoluteExpiresAt)
				assert.Equal(t, createdAt, got.FamilyCreatedAt, "renewal reset the family's start")
			},
		},
		{
			name:        "on day 80 of a 90-day family the deadline is cut to the family maximum",
			opts:        long,
			familyStart: createdAt, now: createdAt.Add(80 * day), abs: createdAt.Add(85 * day),
			rotate: withLifetime(30 * day),
			assert: func(t *testing.T, _ *session.MemoryStore, _, got *session.Session, err error) {
				require.NoError(t, err)
				assert.Equal(t, createdAt.Add(90*day), got.AbsoluteExpiresAt)
				assert.Equal(t, createdAt.Add(80*day+30*time.Minute), got.IdleExpiresAt)
			},
		},
		{
			name:        "a lifetime above the lifetime maximum is refused and stores nothing",
			opts:        long,
			familyStart: createdAt, now: createdAt.Add(day), abs: createdAt.Add(30 * day),
			rotate: withLifetime(45 * day),
			assert: refused,
		},
		{
			name:        "a lifetime of zero is refused and stores nothing",
			familyStart: createdAt, now: createdAt.Add(time.Hour), abs: createdAt.Add(12 * time.Hour),
			rotate: withLifetime(0),
			assert: refused,
		},
		{
			name:        "rotation at second-factor verification never extends",
			opts:        long,
			familyStart: createdAt, now: createdAt.Add(6 * time.Hour), abs: createdAt.Add(12 * time.Hour),
			rotate: func(ctx context.Context, m *session.Sessions, s *session.Session) (*session.Session, error) {
				return m.Rotate(ctx, s)
			},
			assert: func(t *testing.T, _ *session.MemoryStore, _, got *session.Session, err error) {
				require.NoError(t, err)
				assert.Equal(t, createdAt.Add(12*time.Hour), got.AbsoluteExpiresAt)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(tc.now)
			m, store := managerOnClock(t, clk, tc.opts...)
			s := renewalSession("renewed", tc.familyStart, tc.now, tc.abs)
			require.NoError(t, store.Create(t.Context(), s))

			got, err := tc.rotate(t.Context(), m, s)
			tc.assert(t, store, s, got, err)
		})
	}
}

// TestRenewalLifetime_ExtendedFamilyStillDetectsReuse pins that a renewal
// extending the family keeps its superseded identifiers judged as reuse until
// the family's new deadline: one presented after its own original deadline,
// while the family is live, is reuse and revokes the family, rather than
// reading as an ordinary expiry that leaves the family alive.
func TestRenewalLifetime_ExtendedFamilyStillDetectsReuse(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// act renews O, created at 09:00 with a 12-hour lifetime, as the
		// case chooses, and returns the stolen identifier to present and
		// when to present it.
		act    func(ctx context.Context, t *testing.T, m *session.Sessions, o *session.Session, clk *clockwork.FakeClock) (stolen string, at time.Time)
		assert func(t *testing.T, store *session.MemoryStore, err error)
	}

	extend := func(ctx context.Context, t *testing.T, m *session.Sessions, s *session.Session) *session.Session {
		t.Helper()

		next, _, err := m.RotateWithGrace(ctx, s, 30*time.Second, session.WithSuccessorLifetime(12*time.Hour))
		require.NoError(t, err)
		require.True(t, next.AbsoluteExpiresAt.After(s.AbsoluteExpiresAt), "the renewal did not extend the family")

		return next
	}
	revoked := func(t *testing.T, store *session.MemoryStore, err error) {
		t.Helper()

		require.ErrorIs(t, err, session.ErrReused, "a stolen identifier presented while its family is live")
		assert.Zero(t, store.Len(), "the family was not revoked")
	}

	cases := []testCase{
		{
			name: "O renewed at 15:00 for 12 hours, presented at 22:00, past its own 21:00",
			act: func(ctx context.Context, t *testing.T, m *session.Sessions, o *session.Session, clk *clockwork.FakeClock) (string, time.Time) {
				clk.Advance(6 * time.Hour)
				extend(ctx, t, m, o)
				return o.ID, createdAt.Add(13 * time.Hour)
			},
			assert: revoked,
		},
		{
			name: "S1 renewed again at 16:00, presented at 03:30 the next day, past its own 03:00",
			act: func(ctx context.Context, t *testing.T, m *session.Sessions, o *session.Session, clk *clockwork.FakeClock) (string, time.Time) {
				clk.Advance(6 * time.Hour)
				s1 := extend(ctx, t, m, o)
				clk.Advance(time.Hour)
				extend(ctx, t, m, s1)
				return s1.ID, createdAt.Add(18*time.Hour + 30*time.Minute)
			},
			assert: revoked,
		},
		{
			name: "O, renewed twice down the chain, presented at 03:30 the next day",
			act: func(ctx context.Context, t *testing.T, m *session.Sessions, o *session.Session, clk *clockwork.FakeClock) (string, time.Time) {
				clk.Advance(6 * time.Hour)
				s1 := extend(ctx, t, m, o)
				clk.Advance(time.Hour)
				extend(ctx, t, m, s1)
				return o.ID, createdAt.Add(18*time.Hour + 30*time.Minute)
			},
			assert: revoked,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(createdAt)
			m, store := managerOnClock(t, clk,
				session.WithAbsoluteTimeout(12*time.Hour), session.WithIdleTimeout(12*time.Hour),
				session.WithMaxAbsoluteLifetime(12*time.Hour), session.WithMaxFamilyLifetime(30*day))
			o, err := m.Create(t.Context(), testUser)
			require.NoError(t, err)

			stolen, at := tc.act(t.Context(), t, m, o, clk)
			clk.Advance(at.Sub(clk.Now()))
			_, err = m.Load(t.Context(), stolen)

			tc.assert(t, store, err)
		})
	}
}

// reuseRun is what one detected reuse left behind.
type reuseRun struct {
	o, s1   *session.Session
	store   *session.MemoryStore
	reports []session.ReuseReport
	logs    string
}

func TestReuseObserver(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		observe bool
		assert  func(t *testing.T, r reuseRun, err error)
	}

	cases := []testCase{
		{
			name: "without an observer reuse is still refused and revoked",
			assert: func(t *testing.T, r reuseRun, err error) {
				require.ErrorIs(t, err, session.ErrReused)
				assert.Zero(t, r.store.Len())
				assert.Empty(t, r.reports)
			},
		},
		{
			name:    "an observer is called once with the user, the family and the times",
			observe: true,
			assert: func(t *testing.T, r reuseRun, err error) {
				require.ErrorIs(t, err, session.ErrReused)
				require.Len(t, r.reports, 1)
				assert.Equal(t, session.ReuseReport{
					User:         testUser,
					Family:       r.o.FamilyID,
					SupersededAt: createdAt,
					DetectedAt:   createdAt.Add(5 * time.Minute),
				}, r.reports[0])
			},
		},
		{
			name:    "the formatted report carries no session identifier",
			observe: true,
			assert: func(t *testing.T, r reuseRun, _ error) {
				require.Len(t, r.reports, 1)
				assertNoIdentifier(t, fmt.Sprintf("%+v", r.reports[0]), r.o.ID, r.s1.ID)
			},
		},
		{
			name: "the warning names the family and carries no session identifier",
			assert: func(t *testing.T, r reuseRun, err error) {
				require.ErrorIs(t, err, session.ErrReused)
				assert.Contains(t, r.logs, "level=WARN")
				assert.Contains(t, r.logs, "family="+r.o.FamilyID.String())
				assertNoIdentifier(t, r.logs, r.o.ID, r.s1.ID)
				assertNoIdentifier(t, err.Error(), r.o.ID, r.s1.ID)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var (
				r  reuseRun
				mu sync.Mutex
			)
			logs := &bytes.Buffer{}
			opts := []session.Option{session.WithLogger(
				slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))}
			if tc.observe {
				opts = append(opts, session.WithReuseObserver(func(_ context.Context, rep session.ReuseReport) {
					mu.Lock()
					defer mu.Unlock()
					r.reports = append(r.reports, rep)
				}))
			}

			f := newGraceFixture(t, opts...)
			r.o, r.store = f.o, f.store
			r.s1 = f.renew(t.Context(), t, f.o, 30*time.Second)
			f.clk.Advance(5 * time.Minute)

			_, err := f.m.Load(t.Context(), f.o.ID)
			r.logs = logs.String()
			tc.assert(t, r, err)
		})
	}
}

// assertNoIdentifier asserts text quotes none of the session identifiers,
// raw or as a digest in any of the encodings a formatter might choose.
func assertNoIdentifier(t *testing.T, text string, ids ...string) {
	t.Helper()

	for _, sid := range ids {
		sum := sha256.Sum256([]byte(sid))
		for _, form := range []string{
			sid,
			hex.EncodeToString(sum[:]),
			base64.StdEncoding.EncodeToString(sum[:]),
			base64.RawURLEncoding.EncodeToString(sum[:]),
			string(sum[:]),
		} {
			assert.NotContains(t, text, form)
		}
	}
}

// supersededStored is the stored O after a renewal at 09:00 with a 30 s
// window, as a mocked store returns it at 09:05.
func supersededStored(sid string) *session.Session {
	s := renewalSession(sid, createdAt, createdAt, createdAt.Add(12*time.Hour))
	s.IdleExpiresAt = s.AbsoluteExpiresAt
	s.SupersededAt = createdAt
	s.AcceptUntil = createdAt.Add(30 * time.Second)
	s.SuccessorDigest = []byte("successor digest")

	return s
}

func TestReuseObserver_RevocationOrder(t *testing.T) {
	t.Parallel()

	const sid = "reused"

	type testCase struct {
		name string
		// deleteErr is what the store's family revocation returns.
		deleteErr error
		assert    func(t *testing.T, observed int, err error)
	}

	cases := []testCase{
		{
			name: "the observer runs after the family is revoked",
			assert: func(t *testing.T, observed int, err error) {
				require.ErrorIs(t, err, session.ErrReused)
				assert.Equal(t, 1, observed)
			},
		},
		{
			name:      "a failed revocation is refused as reuse, reported, and not observed",
			deleteErr: errStoreQuotes,
			assert: func(t *testing.T, observed int, err error) {
				require.ErrorIs(t, err, session.ErrReused)
				require.ErrorIs(t, err, errStoreQuotes, "the revocation's failure was hidden")
				assert.NotContains(t, err.Error(), "alice@example.com")
				assert.Zero(t, observed, "the observer was told of a family that was not revoked")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := NewMockStore(gomock.NewController(t))
			revoked := false
			gomock.InOrder(
				store.EXPECT().Load(gomock.Any(), sid).Return(supersededStored(sid), nil),
				store.EXPECT().DeleteFamily(gomock.Any(), graceFamily).DoAndReturn(
					func(context.Context, id.ID) (int, error) {
						revoked = tc.deleteErr == nil
						return 2, tc.deleteErr
					}),
			)

			observed := 0
			m := managerFor(t,
				session.WithStore(store),
				session.WithClock(clockwork.NewFakeClockAt(createdAt.Add(5*time.Minute))),
				session.WithReuseObserver(func(ctx context.Context, _ session.ReuseReport) {
					assert.True(t, revoked, "the observer ran before the family was revoked")
					assert.NoError(t, ctx.Err())
					observed++
				}),
			)

			_, err := m.Load(t.Context(), sid)
			tc.assert(t, observed, err)
		})
	}
}

// TestRenewal_AuthenticationTime pins that no renewal refreshes when the user
// authenticated: a successor is a record written at the renewal, so its
// CreatedAt is the renewal time, while its AuthenticatedAt is the sign-in's.
func TestRenewal_AuthenticationTime(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		rotate func(ctx context.Context, m *session.Sessions, s *session.Session) (*session.Session, error)
		// createdAt is the successor's expected CreatedAt.
		createdAt time.Time
	}

	renewedAt := createdAt.Add(6 * time.Hour) // 15:00

	cases := []testCase{
		{
			name: "a renewal carries the authentication time over",
			rotate: func(ctx context.Context, m *session.Sessions, s *session.Session) (*session.Session, error) {
				next, _, err := m.RotateWithGrace(ctx, s, 30*time.Second)

				return next, err
			},
			createdAt: renewedAt,
		},
		{
			name: "a rotation at second-factor verification carries the authentication time over",
			rotate: func(ctx context.Context, m *session.Sessions, s *session.Session) (*session.Session, error) {
				return m.Rotate(ctx, s)
			},
			createdAt: renewedAt,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(createdAt)
			// An idle timeout long enough that the session is still live at
			// the renewal, six hours later.
			m, store := managerOnClock(t, clk, session.WithIdleTimeout(7*time.Hour))
			s, err := m.Create(t.Context(), testUser)
			require.NoError(t, err)

			clk.Advance(renewedAt.Sub(createdAt))

			next, err := tc.rotate(t.Context(), m, s)
			require.NoError(t, err)
			assert.Equal(t, createdAt, next.AuthenticatedAt, "the successor keeps the sign-in's authentication time")
			assert.Equal(t, tc.createdAt, next.CreatedAt)

			stored, err := store.Load(t.Context(), next.ID)
			require.NoError(t, err)
			assert.True(t, stored.AuthenticatedAt.Equal(createdAt), "the stored successor keeps it too")
			assert.True(t, stored.CreatedAt.Equal(tc.createdAt), "the stored successor's CreatedAt is when it was written: got %s", stored.CreatedAt)
		})
	}
}

// TestSupersededRecord_RetentionIsNotADeadline pins that the retention a
// supersession gives the record it supersedes is only how long the record is
// kept: it is never read back as the session's own deadline, by a
// re-rotation, a recovery or a load of the old identifier.
func TestSupersededRecord_RetentionIsNotADeadline(t *testing.T) {
	t.Parallel()

	const (
		month = 30 * 24 * time.Hour
		idle  = 30 * time.Minute
	)

	type fixture struct {
		clk   *clockwork.FakeClock
		m     *session.Sessions
		store *inFlightStore
	}

	type testCase struct {
		name string
		opts []session.Option
		// failDelete makes the store's Delete fail, as after a strict
		// rotation whose delete did not land.
		failDelete bool
		// act runs the case's steps from 09:00 and returns what its last
		// step returned.
		act    func(ctx context.Context, t *testing.T, f *fixture) (*session.Session, error)
		assert func(t *testing.T, got *session.Session, err error)
	}

	cases := []testCase{
		{
			// Spec: "By default a successor SHALL keep its predecessor's
			// absolute deadline."
			name: "a re-rotation carries the one-hour deadline over, not the retention",
			opts: []session.Option{session.WithMaxAbsoluteLifetime(month)},
			act: func(ctx context.Context, t *testing.T, f *fixture) (*session.Session, error) {
				o, err := f.m.Create(ctx, testUser, session.WithAbsoluteLifetime(time.Hour))
				require.NoError(t, err)
				_, _, err = f.m.RotateWithGrace(ctx, o, 30*time.Second)
				require.NoError(t, err)

				f.clk.Advance(10 * time.Second)
				next, kind, err := f.m.RotateWithGrace(ctx, o, 30*time.Second)
				require.Equal(t, session.RenewalReRotation, kind)

				return next, err
			},
			assert: func(t *testing.T, got *session.Session, err error) {
				require.NoError(t, err)
				assert.Equal(t, createdAt.Add(time.Hour), got.AbsoluteExpiresAt)
			},
		},
		{
			// Retention is supersession state, which belongs to the record
			// superseded alone: a successor is a live session and has none.
			name: "a re-rotation's successor carries no retention deadline over",
			opts: []session.Option{session.WithMaxAbsoluteLifetime(month)},
			act: func(ctx context.Context, t *testing.T, f *fixture) (*session.Session, error) {
				o, err := f.m.Create(ctx, testUser, session.WithAbsoluteLifetime(time.Hour))
				require.NoError(t, err)
				_, _, err = f.m.RotateWithGrace(ctx, o, 30*time.Second)
				require.NoError(t, err)

				f.clk.Advance(10 * time.Second)
				next, _, err := f.m.RotateWithGrace(ctx, o, 30*time.Second)
				require.NoError(t, err)

				return f.store.Load(ctx, next.ID)
			},
			assert: func(t *testing.T, got *session.Session, err error) {
				require.NoError(t, err)
				assert.Zero(t, got.RetainUntil)
			},
		},
		{
			// Spec: "By default a successor SHALL keep its predecessor's
			// absolute deadline", and the enrolment-only state lowers it.
			name: "a re-rotation of an enrolment-only session keeps its lowered deadline",
			act: func(ctx context.Context, t *testing.T, f *fixture) (*session.Session, error) {
				o, err := f.m.Create(ctx, testUser)
				require.NoError(t, err)
				f.m.MarkEnrolmentPending(o, 15*time.Minute)
				require.NoError(t, f.m.Save(ctx, o))
				_, _, err = f.m.RotateWithGrace(ctx, o, 30*time.Second)
				require.NoError(t, err)

				f.clk.Advance(10 * time.Second)
				next, _, err := f.m.RotateWithGrace(ctx, o, 30*time.Second)

				return next, err
			},
			assert: func(t *testing.T, got *session.Session, err error) {
				require.NoError(t, err)
				assert.Equal(t, createdAt.Add(15*time.Minute), got.AbsoluteExpiresAt)
			},
		},
		{
			// Spec: "By default a successor SHALL keep its predecessor's
			// absolute deadline."
			name:       "a re-rotation after a strict rotation whose delete failed carries the deadline over",
			opts:       []session.Option{session.WithMaxAbsoluteLifetime(month)},
			failDelete: true,
			act: func(ctx context.Context, t *testing.T, f *fixture) (*session.Session, error) {
				o, err := f.m.Create(ctx, testUser, session.WithAbsoluteLifetime(time.Hour))
				require.NoError(t, err)
				_, err = f.m.Rotate(ctx, o)
				require.NoError(t, err)

				f.clk.Advance(10 * time.Second)
				next, _, err := f.m.RotateWithGrace(ctx, o, 30*time.Second)

				return next, err
			},
			assert: func(t *testing.T, got *session.Session, err error) {
				require.NoError(t, err)
				assert.Equal(t, createdAt.Add(time.Hour), got.AbsoluteExpiresAt)
			},
		},
		{
			// Spec: "A load of the old identifier between the two writes
			// SHALL return the old session as it was."
			name:       "the old identifier in flight after a strict rotation loads with its own deadlines",
			opts:       []session.Option{session.WithMaxAbsoluteLifetime(month), session.WithIdleTimeout(idle)},
			failDelete: true,
			act: func(ctx context.Context, t *testing.T, f *fixture) (*session.Session, error) {
				o, err := f.m.Create(ctx, testUser, session.WithAbsoluteLifetime(time.Hour))
				require.NoError(t, err)
				_, err = f.m.Rotate(ctx, o)
				require.NoError(t, err)

				f.clk.Advance(10 * time.Second)

				return f.m.Load(ctx, o.ID)
			},
			assert: func(t *testing.T, got *session.Session, err error) {
				require.NoError(t, err)
				assert.Equal(t, createdAt.Add(time.Hour), got.AbsoluteExpiresAt)
				assert.Equal(t, createdAt.Add(idle), got.IdleExpiresAt)
			},
		},
		{
			// Spec: "Loading a session past either deadline SHALL fail with
			// an expired error", and a successor keeps its predecessor's
			// absolute deadline, which has passed.
			name: "recovery after the session's absolute deadline is expired",
			opts: []session.Option{
				session.WithAbsoluteTimeout(72 * time.Hour),
				session.WithIdleTimeout(48 * time.Hour),
				session.WithUnusedSuccessorRecovery(),
			},
			act: func(ctx context.Context, t *testing.T, f *fixture) (*session.Session, error) {
				o, err := f.m.Create(ctx, testUser, session.WithAbsoluteLifetime(2*time.Hour))
				require.NoError(t, err)
				_, _, err = f.m.RotateWithGrace(ctx, o, 30*time.Second)
				require.NoError(t, err)

				f.clk.Advance(3 * time.Hour)
				next, _, err := f.m.RotateWithGrace(ctx, o, 30*time.Second)

				assert.Equal(t, 2, f.store.Len(), "a successor was stored or the family was revoked")

				return next, err
			},
			assert: func(t *testing.T, got *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrExpired)
				assert.NotErrorIs(t, err, session.ErrReused)
				assert.Nil(t, got, "a family past its deadline was revived")
			},
		},
		{
			// Spec: "Loading a session past either deadline SHALL fail with
			// an expired error."
			name: "recovery after the session's idle deadline is expired",
			opts: []session.Option{
				session.WithAbsoluteTimeout(72 * time.Hour),
				session.WithIdleTimeout(idle),
				session.WithUnusedSuccessorRecovery(),
			},
			act: func(ctx context.Context, t *testing.T, f *fixture) (*session.Session, error) {
				o, err := f.m.Create(ctx, testUser)
				require.NoError(t, err)
				_, _, err = f.m.RotateWithGrace(ctx, o, 30*time.Second)
				require.NoError(t, err)

				f.clk.Advance(2 * idle)
				got, err := f.m.LoadForRenewal(ctx, o.ID)

				assert.Equal(t, 2, f.store.Len(), "a successor was stored or the family was revoked")

				return got, err
			},
			assert: func(t *testing.T, got *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrExpired)
				assert.NotErrorIs(t, err, session.ErrReused)
				assert.Nil(t, got, "a session past its idle deadline was returned for renewal")
			},
		},
		{
			// Spec: "Inside its window, loading a superseded identifier
			// SHALL succeed only while its own idle and absolute deadlines
			// are unexpired", and the family is not revoked.
			name: "inside the window, past its own idle deadline, is expired and revokes nothing",
			opts: []session.Option{session.WithIdleTimeout(10 * time.Second)},
			act: func(ctx context.Context, t *testing.T, f *fixture) (*session.Session, error) {
				o, err := f.m.Create(ctx, testUser)
				require.NoError(t, err)
				s1, _, err := f.m.RotateWithGrace(ctx, o, 30*time.Second)
				require.NoError(t, err)

				f.clk.Advance(20 * time.Second)
				got, err := f.m.Load(ctx, o.ID)

				_, err1 := f.store.Load(ctx, s1.ID)
				assert.NotErrorIs(t, err1, session.ErrNotFound, "the family was revoked")

				return got, err
			},
			assert: func(t *testing.T, got *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrExpired)
				assert.NotErrorIs(t, err, session.ErrReused)
				assert.Nil(t, got)
			},
		},
		{
			// A deadline is the first instant the session is no longer valid.
			name: "inside the window, exactly at its own idle deadline, is expired",
			opts: []session.Option{session.WithIdleTimeout(10 * time.Second)},
			act: func(ctx context.Context, t *testing.T, f *fixture) (*session.Session, error) {
				o, err := f.m.Create(ctx, testUser)
				require.NoError(t, err)
				_, _, err = f.m.RotateWithGrace(ctx, o, 30*time.Second)
				require.NoError(t, err)

				f.clk.Advance(10 * time.Second)

				return f.m.Load(ctx, o.ID)
			},
			assert: func(t *testing.T, got *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrExpired)
				assert.NotErrorIs(t, err, session.ErrReused)
				assert.Nil(t, got)
			},
		},
		{
			// Spec: "Detected after the session's own deadline." This is a
			// guard: it passes with the deadline raise too, and fails if the
			// fix drops retention.
			name: "after the window, past its own absolute deadline, is reuse",
			opts: []session.Option{session.WithMaxAbsoluteLifetime(month)},
			act: func(ctx context.Context, t *testing.T, f *fixture) (*session.Session, error) {
				o, err := f.m.Create(ctx, testUser, session.WithAbsoluteLifetime(time.Hour))
				require.NoError(t, err)
				s1, _, err := f.m.RotateWithGrace(ctx, o, 30*time.Second)
				require.NoError(t, err)

				f.clk.Advance(3 * time.Hour)
				got, err := f.m.Load(ctx, o.ID)

				_, err1 := f.store.Load(ctx, s1.ID)
				assert.ErrorIs(t, err1, session.ErrNotFound, "the family was not revoked")

				return got, err
			},
			assert: func(t *testing.T, got *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrReused)
				assert.Nil(t, got)
			},
		},
		{
			// Spec: "Recovery never revives a session that has ended", at
			// the deadline itself.
			name: "recovery exactly at its own idle deadline is expired, with no successor",
			opts: []session.Option{
				session.WithAbsoluteTimeout(72 * time.Hour),
				session.WithIdleTimeout(idle),
				session.WithUnusedSuccessorRecovery(),
			},
			act: func(ctx context.Context, t *testing.T, f *fixture) (*session.Session, error) {
				o, err := f.m.Create(ctx, testUser)
				require.NoError(t, err)
				_, _, err = f.m.RotateWithGrace(ctx, o, 30*time.Second)
				require.NoError(t, err)

				f.clk.Advance(idle)
				next, _, err := f.m.RotateWithGrace(ctx, o, 30*time.Second)

				assert.Equal(t, 2, f.store.Len(), "a successor was stored or the family was revoked")

				return next, err
			},
			assert: func(t *testing.T, got *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrExpired)
				assert.NotErrorIs(t, err, session.ErrReused)
				assert.Nil(t, got, "a session at its idle deadline was renewed")
			},
		},
		{
			// Spec: "An ended session whose successor was used is reuse."
			name: "an ended session whose successor was used is reuse",
			opts: []session.Option{session.WithIdleTimeout(idle), session.WithUnusedSuccessorRecovery()},
			act: func(ctx context.Context, t *testing.T, f *fixture) (*session.Session, error) {
				o, err := f.m.Create(ctx, testUser)
				require.NoError(t, err)
				// Rotated at 09:10, so S1's own idle deadline, 09:40, is
				// still ahead when O, idle since 09:00, is renewed at 09:31:
				// S1 is stored, as a store judges it.
				f.clk.Advance(10 * time.Minute)
				s1, _, err := f.m.RotateWithGrace(ctx, o, 30*time.Second)
				require.NoError(t, err)

				f.clk.Advance(10 * time.Minute)
				_, err = f.m.Load(ctx, s1.ID)
				require.NoError(t, err)

				f.clk.Advance(11 * time.Minute)
				next, err := renew(ctx, f.m, o.ID)

				_, err1 := f.store.Load(ctx, s1.ID)
				assert.ErrorIs(t, err1, session.ErrNotFound, "the used successor still loads")
				assert.Zero(t, f.store.Len(), "the family was not revoked")

				return next, err
			},
			assert: func(t *testing.T, got *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrReused)
				assert.Nil(t, got, "a successor was issued for an ended session")
			},
		},
		{
			// Spec: "An ended session whose unused successor is gone is
			// expired."
			name: "an ended session whose unused successor is gone is expired",
			opts: []session.Option{session.WithIdleTimeout(idle), session.WithUnusedSuccessorRecovery()},
			act: func(ctx context.Context, t *testing.T, f *fixture) (*session.Session, error) {
				o, err := f.m.Create(ctx, testUser)
				require.NoError(t, err)
				s1, _, err := f.m.RotateWithGrace(ctx, o, 30*time.Second)
				require.NoError(t, err)
				require.NoError(t, f.store.Delete(ctx, s1.ID))

				f.clk.Advance(31 * time.Minute)
				next, err := renew(ctx, f.m, o.ID)

				_, err1 := f.store.Load(ctx, o.ID)
				assert.NoError(t, err1, "the family was revoked")
				assert.Equal(t, 1, f.store.Len(), "a successor was stored or the family was revoked")

				return next, err
			},
			assert: func(t *testing.T, got *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrExpired)
				assert.NotErrorIs(t, err, session.ErrReused)
				assert.Nil(t, got, "a successor was issued for an ended session")
			},
		},
		{
			// Spec: "Recovery never revives a session that has ended", with
			// the successor unused and still live. O is rotated at 09:10, so
			// S1's own idle deadline, 09:40, is still ahead when O, idle
			// since 09:00, is renewed at 09:31.
			name: "an ended session whose successor is unused is expired",
			opts: []session.Option{session.WithIdleTimeout(idle), session.WithUnusedSuccessorRecovery()},
			act: func(ctx context.Context, t *testing.T, f *fixture) (*session.Session, error) {
				o, err := f.m.Create(ctx, testUser)
				require.NoError(t, err)
				f.clk.Advance(10 * time.Minute)
				s1, _, err := f.m.RotateWithGrace(ctx, o, 30*time.Second)
				require.NoError(t, err)

				f.clk.Advance(21 * time.Minute)
				next, err := renew(ctx, f.m, o.ID)

				assert.Equal(t, 2, f.store.Len(), "a successor was stored or the family was revoked")
				_, err1 := f.m.Load(ctx, s1.ID)
				assert.NoError(t, err1, "the unused successor no longer loads")

				return next, err
			},
			assert: func(t *testing.T, got *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrExpired)
				assert.NotErrorIs(t, err, session.ErrReused)
				assert.Nil(t, got, "a successor was issued for an ended session")
			},
		},
		{
			// Spec: "A knocked-out identifier is reuse whatever its own
			// deadlines". S1 is knocked out unused at 09:00:10, and is
			// renewed at 09:31, past its own idle deadline (09:30).
			name: "a knocked-out identifier renewed past its own idle deadline is reuse",
			opts: []session.Option{session.WithIdleTimeout(idle), session.WithUnusedSuccessorRecovery()},
			act: func(ctx context.Context, t *testing.T, f *fixture) (*session.Session, error) {
				o, err := f.m.Create(ctx, testUser)
				require.NoError(t, err)
				s1, _, err := f.m.RotateWithGrace(ctx, o, 30*time.Second)
				require.NoError(t, err)

				f.clk.Advance(10 * time.Second)
				_, kind, err := f.m.RotateWithGrace(ctx, o, 30*time.Second)
				require.NoError(t, err)
				require.Equal(t, session.RenewalReRotation, kind)

				f.clk.Advance(31 * time.Minute)
				next, err := renew(ctx, f.m, s1.ID)

				assert.Zero(t, f.store.Len(), "the family was not revoked")

				return next, err
			},
			assert: func(t *testing.T, got *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrReused)
				assert.Nil(t, got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(createdAt)
			inner := must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(clk)))
			f := &fixture{clk: clk, store: &inFlightStore{MemoryStore: inner, failDelete: tc.failDelete}}
			f.m = managerFor(t, append([]session.Option{
				session.WithStore(f.store),
				session.WithClock(clk),
			}, tc.opts...)...)

			got, err := tc.act(t.Context(), t, f)
			tc.assert(t, got, err)
		})
	}
}

// renew is what a renewal endpoint does: LoadForRenewal, then RotateWithGrace
// with the default grace when the load passed.
func renew(ctx context.Context, m *session.Sessions, sid string) (*session.Session, error) {
	s, err := m.LoadForRenewal(ctx, sid)
	if err != nil {
		return nil, err
	}
	next, _, err := m.RotateWithGrace(ctx, s, session.DefaultRenewalGrace)

	return next, err
}

// TestRecovery_AnEndedSessionAsksTheStoreWhetherItsSuccessorWasUsed pins,
// over the store mock, what a renewal under recovery of a superseded session
// past its window and its own idle deadline asks the store and writes. The
// mock is strict, so a call no case expects (a Supersede, a DeleteFamily, a
// MarkPresented) fails it. It is apart from the table above because its store
// is the mock, not a memory store.
func TestRecovery_AnEndedSessionAsksTheStoreWhetherItsSuccessorWasUsed(t *testing.T) {
	t.Parallel()

	const sid = "ended-under-recovery"

	// ended is a session rotated ten minutes before createdAt, past its
	// window, whose own idle deadline passed a minute before createdAt.
	ended := func() *session.Session {
		s := supersededPastWindow(sid)
		s.IdleExpiresAt = createdAt.Add(-time.Minute)

		return s
	}

	type testCase struct {
		name   string
		expect func(store *MockStore)
		assert func(t *testing.T, got *session.Session, err error)
	}

	cases := []testCase{
		{
			// Review Focus 11: the successor's first presentation lands just
			// after the read, which answered false. The decision is the
			// read's: expired, nothing revoked, no supersession.
			name: "an unused successor read just before its presentation is expired, and nothing is written",
			expect: func(store *MockStore) {
				store.EXPECT().SuccessorPresented(gomock.Any(), sid).Return(false, nil).Times(1)
			},
			assert: func(t *testing.T, got *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrExpired)
				assert.NotErrorIs(t, err, session.ErrReused)
				assert.Nil(t, got)
			},
		},
		{
			name: "a used successor is reuse, and the family is revoked",
			expect: func(store *MockStore) {
				store.EXPECT().SuccessorPresented(gomock.Any(), sid).Return(true, nil).Times(1)
				store.EXPECT().DeleteFamily(gomock.Any(), graceFamily).Return(2, nil).Times(1)
			},
			assert: func(t *testing.T, got *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrReused)
				assert.Nil(t, got)
			},
		},
		{
			name: "a failed read refuses the renewal, and nothing is written",
			expect: func(store *MockStore) {
				store.EXPECT().SuccessorPresented(gomock.Any(), sid).Return(false, errStoreWrite).Times(1)
			},
			assert: func(t *testing.T, got *session.Session, err error) {
				require.ErrorIs(t, err, errStoreWrite)
				assert.NotErrorIs(t, err, session.ErrReused)
				assert.Nil(t, got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := NewMockStore(gomock.NewController(t))
			store.EXPECT().Load(gomock.Any(), sid).Return(ended(), nil).Times(1)
			tc.expect(store)
			m := managerFor(t,
				session.WithStore(store),
				session.WithClock(clockwork.NewFakeClockAt(createdAt)),
				session.WithUnusedSuccessorRecovery(),
			)

			got, err := renew(t.Context(), m, sid)
			tc.assert(t, got, err)
		})
	}
}

// supersessionLog is a memory store that records every supersession it is
// handed.
type supersessionLog struct {
	*session.MemoryStore

	mu  sync.Mutex
	ops []session.Supersession
}

func (s *supersessionLog) Supersede(ctx context.Context, op session.Supersession) error {
	s.mu.Lock()
	s.ops = append(s.ops, op)
	s.mu.Unlock()

	return s.MemoryStore.Supersede(ctx, op)
}

func (s *supersessionLog) last(t *testing.T) session.Supersession {
	t.Helper()

	s.mu.Lock()
	defer s.mu.Unlock()
	require.NotEmpty(t, s.ops, "no supersession reached the store")

	return s.ops[len(s.ops)-1]
}

// TestSupersession_RetainUntilIsTheFamilyDeadline pins that every
// supersession the manager makes carries the family's start plus the family
// maximum as its retention deadline, whichever renewal made it: a session
// created at 09:00 with a 12-hour lifetime and a 48-hour family maximum
// retains to 09:00 two days later.
func TestSupersession_RetainUntilIsTheFamilyDeadline(t *testing.T) {
	t.Parallel()

	const familyMax = 48 * time.Hour

	type testCase struct {
		name   string
		renew  func(ctx context.Context, t *testing.T, m *session.Sessions, s *session.Session)
		assert func(t *testing.T, s *session.Session, op session.Supersession)
	}

	retainsFamilyDeadline := func(t *testing.T, s *session.Session, op session.Supersession) {
		t.Helper()

		assert.Equal(t, s.FamilyCreatedAt.Add(familyMax), op.RetainUntil,
			"the retention deadline is the family's start plus the family maximum")
	}

	cases := []testCase{
		{
			name: "a strict rotation",
			renew: func(ctx context.Context, t *testing.T, m *session.Sessions, s *session.Session) {
				_, err := m.Rotate(ctx, s)
				require.NoError(t, err)
			},
			assert: retainsFamilyDeadline,
		},
		{
			name: "a fresh renewal",
			renew: func(ctx context.Context, t *testing.T, m *session.Sessions, s *session.Session) {
				_, _, err := m.RotateWithGrace(ctx, s, 30*time.Second)
				require.NoError(t, err)
			},
			assert: retainsFamilyDeadline,
		},
		{
			name: "a renewal with a successor lifetime",
			renew: func(ctx context.Context, t *testing.T, m *session.Sessions, s *session.Session) {
				_, _, err := m.RotateWithGrace(ctx, s, 30*time.Second, session.WithSuccessorLifetime(12*time.Hour))
				require.NoError(t, err)
			},
			assert: retainsFamilyDeadline,
		},
		{
			name: "a re-rotation inside the window",
			renew: func(ctx context.Context, t *testing.T, m *session.Sessions, s *session.Session) {
				_, _, err := m.RotateWithGrace(ctx, s, 30*time.Second)
				require.NoError(t, err)
				_, kind, err := m.RotateWithGrace(ctx, s, 30*time.Second)
				require.NoError(t, err)
				require.Equal(t, session.RenewalReRotation, kind)
			},
			assert: retainsFamilyDeadline,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(createdAt)
			store := &supersessionLog{MemoryStore: must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(clk)))}
			m := managerFor(t,
				session.WithStore(store),
				session.WithClock(clk),
				session.WithAbsoluteTimeout(12*time.Hour),
				session.WithMaxAbsoluteLifetime(12*time.Hour),
				session.WithMaxFamilyLifetime(familyMax),
			)
			s, err := m.Create(t.Context(), testUser)
			require.NoError(t, err)
			clk.Advance(10 * time.Minute)

			tc.renew(t.Context(), t, m, s)

			tc.assert(t, s, store.last(t))
		})
	}
}

// twoDeploys returns two managers over one memory store and clock, as a
// rolling deploy that changes the family maximum leaves them: the first
// manager's lifetimes and family maximum are first, the second's are second.
func twoDeploys(t *testing.T, clk *clockwork.FakeClock, first, second time.Duration) (before, after *session.Sessions, store *session.MemoryStore) {
	t.Helper()

	store = must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(clk)))
	build := func(lifetime time.Duration, family time.Duration) *session.Sessions {
		return managerFor(t,
			session.WithStore(store),
			session.WithClock(clk),
			session.WithIdleTimeout(lifetime),
			session.WithAbsoluteTimeout(lifetime),
			session.WithMaxAbsoluteLifetime(lifetime),
			session.WithMaxFamilyLifetime(family),
		)
	}

	return build(first, first), build(second, second), store
}

// TestRotateWithGrace_LoweredFamilyMaximum pins that a deploy which lowers
// the family maximum never shortens a record already issued: a record
// renewed just before the new family end keeps its original deadline, so it
// is still judged inside its window, and a renewal past the new family end
// is refused.
func TestRotateWithGrace_LoweredFamilyMaximum(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		renew  time.Duration
		assert func(t *testing.T, m *session.Sessions, clk *clockwork.FakeClock, old, next *session.Session, err error)
	}

	cases := []testCase{
		{
			name:  "the grace window of a record renewed before the new family end is kept",
			renew: 5*time.Hour + 59*time.Minute + 50*time.Second,
			assert: func(t *testing.T, m *session.Sessions, clk *clockwork.FakeClock, old, next *session.Session, err error) {
				require.NoError(t, err)
				assert.Equal(t, old.FamilyCreatedAt.Add(6*time.Hour), next.AbsoluteExpiresAt,
					"the successor is cut at the family's end under the lowered maximum")

				clk.Advance(10 * time.Second) // 15:00:00, inside the 30 s window
				loaded, err := m.Load(t.Context(), old.ID)
				require.NoError(t, err, "the old record is still inside its window")
				assert.Equal(t, old.ID, loaded.ID)
			},
		},
		{
			name:  "a renewal past the new family end is refused as expired",
			renew: 6*time.Hour + 30*time.Minute,
			assert: func(t *testing.T, m *session.Sessions, _ *clockwork.FakeClock, old, next *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrExpired)
				assert.NotErrorIs(t, err, session.ErrReused)
				assert.Nil(t, next)

				loaded, err := m.Load(t.Context(), old.ID)
				require.NoError(t, err, "nothing was written: the old record is not superseded")
				assert.True(t, loaded.SupersededAt.IsZero())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(createdAt)
			before, after, _ := twoDeploys(t, clk, 12*time.Hour, 6*time.Hour)
			s, err := before.Create(t.Context(), testUser)
			require.NoError(t, err)
			clk.Advance(tc.renew)

			next, _, err := after.RotateWithGrace(t.Context(), s, 30*time.Second)

			tc.assert(t, before, clk, s, next, err)
		})
	}
}

// TestRotateWithGrace_RaisedFamilyMaximumReadsAsExpired pins the documented
// limit of raising the family maximum: a record superseded under the old
// maximum keeps the retention it was given, so presented after that while
// the family lives on under the new maximum, it is refused as expired and
// the family is not revoked.
// Standalone: it renews under two deploys in sequence and loads past the old retention.
func TestRotateWithGrace_RaisedFamilyMaximumReadsAsExpired(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(createdAt)
	before, after, _ := twoDeploys(t, clk, 12*time.Hour, 48*time.Hour)
	s, err := before.Create(t.Context(), testUser)
	require.NoError(t, err)
	clk.Advance(time.Hour)

	// Superseded by a deploy still on the old maximum: retained to 21:00.
	next, _, err := before.RotateWithGrace(t.Context(), s, 30*time.Second)
	require.NoError(t, err)

	// The family is extended under the new maximum before the old record's
	// retention (21:00) ends.
	clk.Advance(10 * time.Hour) // 20:00
	head, _, err := after.RotateWithGrace(t.Context(), next, 30*time.Second, session.WithSuccessorLifetime(12*time.Hour))
	require.NoError(t, err)

	clk.Advance(3 * time.Hour) // 23:00, past the old record's retention
	_, err = after.Load(t.Context(), s.ID)
	require.ErrorIs(t, err, session.ErrExpired)
	assert.NotErrorIs(t, err, session.ErrReused, "the limit: reuse is not detected past the old retention")

	_, err = after.Load(t.Context(), head.ID)
	require.NoError(t, err, "the family was not revoked: its head still loads")
}

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
			inner := must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(clk)))
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

// supersededPastWindow is a session rotated ten minutes before createdAt with
// a thirty-second window, which still names its successor: presenting it at
// createdAt is reuse.
func supersededPastWindow(sid string) *session.Session {
	s := liveUnpresented(sid)
	s.SupersededAt = createdAt.Add(-10 * time.Minute)
	s.AcceptUntil = s.SupersededAt.Add(30 * time.Second)
	s.SuccessorDigest = []byte("successor-digest")

	return s
}

// honouringDeleteFamily is what a context-honouring store does with
// DeleteFamily, as database/sql and pgx do: a cancelled context aborts the
// statement and nothing is deleted. It records the context's state on seen.
func honouringDeleteFamily(seen *error) func(ctx context.Context, _ id.ID) (int, error) {
	return func(ctx context.Context, _ id.ID) (int, error) {
		*seen = ctx.Err()
		if err := ctx.Err(); err != nil {
			return 0, err
		}

		return 1, nil
	}
}

// TestReuse_RevokesTheFamilyWhenThePresentingRequestIsCancelled pins that the
// family revocation on detected reuse does not depend on the presenting
// request staying connected: a client (or a thief) that hangs up once the
// superseded record has been read must not leave the family alive.
func TestReuse_RevokesTheFamilyWhenThePresentingRequestIsCancelled(t *testing.T) {
	t.Parallel()

	const sid = "reused-then-cancelled"

	type testCase struct {
		name string
		// opts are manager options the case adds to the store and the clock.
		opts []session.Option
		// expect wires the store; cancel is the presenting request hanging up,
		// which each case calls once the store has answered the read.
		expect func(store *MockStore, cancel context.CancelFunc, seen *error)
		call   func(ctx context.Context, m *session.Sessions) error
		assert func(t *testing.T, err error, seen error)
	}

	revoked := func(t *testing.T, err error, seen error) {
		t.Helper()
		require.ErrorIs(t, err, session.ErrReused)
		require.NoError(t, seen, "the family was revoked on the presenting request's cancelled context, so a context-honouring store aborted it and the family stays alive")
		assert.NotErrorIs(t, err, context.Canceled, "the revocation failed with the request's cancellation")
	}

	cases := []testCase{
		{
			name: "load of a superseded identifier past its window",
			expect: func(store *MockStore, cancel context.CancelFunc, seen *error) {
				store.EXPECT().Load(gomock.Any(), sid).DoAndReturn(func(context.Context, string) (*session.Session, error) {
					cancel()
					return supersededPastWindow(sid), nil
				}).Times(1)
				store.EXPECT().DeleteFamily(gomock.Any(), graceFamily).DoAndReturn(honouringDeleteFamily(seen)).Times(1)
			},
			call: func(ctx context.Context, m *session.Sessions) error {
				_, err := m.Load(ctx, sid)
				return err
			},
			assert: revoked,
		},
		{
			name: "grace renewal of a superseded identifier past its window",
			expect: func(store *MockStore, cancel context.CancelFunc, seen *error) {
				store.EXPECT().Load(gomock.Any(), sid).DoAndReturn(func(context.Context, string) (*session.Session, error) {
					cancel()
					return supersededPastWindow(sid), nil
				}).Times(1)
				store.EXPECT().DeleteFamily(gomock.Any(), graceFamily).DoAndReturn(honouringDeleteFamily(seen)).Times(1)
			},
			call: func(ctx context.Context, m *session.Sessions) error {
				_, _, err := m.RotateWithGrace(ctx, liveUnpresented(sid), session.DefaultRenewalGrace)
				return err
			},
			assert: revoked,
		},
		{
			name: "strict rotation of a superseded identifier past its window",
			expect: func(store *MockStore, cancel context.CancelFunc, seen *error) {
				store.EXPECT().Load(gomock.Any(), sid).DoAndReturn(func(context.Context, string) (*session.Session, error) {
					cancel()
					return supersededPastWindow(sid), nil
				}).Times(1)
				store.EXPECT().DeleteFamily(gomock.Any(), graceFamily).DoAndReturn(honouringDeleteFamily(seen)).Times(1)
			},
			call: func(ctx context.Context, m *session.Sessions) error {
				_, err := m.Rotate(ctx, liveUnpresented(sid))
				return err
			},
			assert: revoked,
		},
		{
			name: "grace renewal whose supersession finds the successor advanced",
			expect: func(store *MockStore, cancel context.CancelFunc, seen *error) {
				store.EXPECT().Load(gomock.Any(), sid).Return(liveUnpresented(sid), nil).Times(1)
				store.EXPECT().Supersede(gomock.Any(), gomock.Any()).DoAndReturn(func(context.Context, session.Supersession) error {
					cancel()
					return session.ErrSuccessorAdvanced
				}).Times(1)
				store.EXPECT().DeleteFamily(gomock.Any(), graceFamily).DoAndReturn(honouringDeleteFamily(seen)).Times(1)
			},
			call: func(ctx context.Context, m *session.Sessions) error {
				_, _, err := m.RotateWithGrace(ctx, liveUnpresented(sid), session.DefaultRenewalGrace)
				return err
			},
			assert: revoked,
		},
		{
			name: "renewal of an ended session whose successor was used",
			opts: []session.Option{session.WithUnusedSuccessorRecovery()},
			expect: func(store *MockStore, cancel context.CancelFunc, seen *error) {
				store.EXPECT().Load(gomock.Any(), sid).DoAndReturn(func(context.Context, string) (*session.Session, error) {
					cancel()
					s := supersededPastWindow(sid)
					s.IdleExpiresAt = createdAt.Add(-time.Minute)

					return s, nil
				}).Times(1)
				store.EXPECT().SuccessorPresented(gomock.Any(), sid).DoAndReturn(func(ctx context.Context, _ string) (bool, error) {
					if err := ctx.Err(); err != nil {
						return false, err
					}

					return true, nil
				}).Times(1)
				store.EXPECT().DeleteFamily(gomock.Any(), graceFamily).DoAndReturn(honouringDeleteFamily(seen)).Times(1)
			},
			call: func(ctx context.Context, m *session.Sessions) error {
				_, err := m.LoadForRenewal(ctx, sid)
				return err
			},
			assert: revoked,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			var seen error
			store := NewMockStore(gomock.NewController(t))
			tc.expect(store, cancel, &seen)
			m := managerFor(t, append([]session.Option{session.WithStore(store), session.WithClock(clockwork.NewFakeClockAt(createdAt))}, tc.opts...)...)

			err := tc.call(ctx, m)
			tc.assert(t, err, seen)
		})
	}
}

// nextDay is how long after O's rotation the late retries below arrive.
const nextDay = 24 * time.Hour

// recoveryFixture is a graceFixture whose sessions outlive a day, so a
// next-day retry is judged by its window and not by an ended deadline, with
// an observer counting the reuses it is told about.
type recoveryFixture struct {
	*graceFixture

	observed int
}

func newRecoveryFixture(t *testing.T, opts ...session.Option) *recoveryFixture {
	t.Helper()

	f := &recoveryFixture{}
	all := append([]session.Option{
		session.WithAbsoluteTimeout(72 * time.Hour),
		session.WithIdleTimeout(48 * time.Hour),
		session.WithReuseObserver(func(context.Context, session.ReuseReport) { f.observed++ }),
	}, opts...)
	f.graceFixture = newGraceFixture(t, all...)

	return f
}

func TestUnusedSuccessorRecovery(t *testing.T) {
	t.Parallel()

	recovery := []session.Option{session.WithUnusedSuccessorRecovery()}

	type testCase struct {
		name string
		opts []session.Option
		// act rotates O into S1 at 09:00 with a 30-second grace, runs the
		// case's steps, and returns what its last step returned.
		act    func(ctx context.Context, t *testing.T, f *recoveryFixture, s1 *session.Session) (*session.Session, session.RenewalKind, error)
		assert func(t *testing.T, f *recoveryFixture, got *session.Session, kind session.RenewalKind, err error)
	}

	renewO := func(ctx context.Context, f *recoveryFixture) (*session.Session, session.RenewalKind, error) {
		return f.m.RotateWithGrace(ctx, f.o, 30*time.Second)
	}
	assertFamilyRevoked := func(t *testing.T, f *recoveryFixture, got *session.Session, err error) {
		t.Helper()

		require.ErrorIs(t, err, session.ErrReused)
		assert.Nil(t, got)
		assert.Zero(t, f.store.Len(), "the family was not revoked")
		assert.Equal(t, 1, f.observed, "the observer was not told once")
	}

	cases := []testCase{
		{
			name: "by default a next-day renewal with an unused successor is reuse",
			act: func(ctx context.Context, _ *testing.T, f *recoveryFixture, _ *session.Session) (*session.Session, session.RenewalKind, error) {
				f.clk.Advance(nextDay)
				return renewO(ctx, f)
			},
			assert: func(t *testing.T, f *recoveryFixture, got *session.Session, _ session.RenewalKind, err error) {
				assertFamilyRevoked(t, f, got, err)
			},
		},
		{
			name: "by default a next-day renewal load is reuse, as Load is",
			act: func(ctx context.Context, _ *testing.T, f *recoveryFixture, _ *session.Session) (*session.Session, session.RenewalKind, error) {
				f.clk.Advance(nextDay)
				got, err := f.m.LoadForRenewal(ctx, f.o.ID)
				return got, 0, err
			},
			assert: func(t *testing.T, f *recoveryFixture, got *session.Session, _ session.RenewalKind, err error) {
				assertFamilyRevoked(t, f, got, err)
			},
		},
		{
			name: "with recovery an unused successor is recovered, and the old successor is then reuse",
			opts: recovery,
			act: func(ctx context.Context, t *testing.T, f *recoveryFixture, s1 *session.Session) (*session.Session, session.RenewalKind, error) {
				f.clk.Advance(nextDay)
				s2, kind, err := renewO(ctx, f)
				require.NoError(t, err)
				assert.Equal(t, session.RenewalRecovery, kind)
				assert.Equal(t, f.o.FamilyID, s2.FamilyID)
				assert.Equal(t, 0, f.observed, "a recovery is not reuse")

				_, err = f.m.Load(ctx, s1.ID)
				return s2, kind, err
			},
			assert: func(t *testing.T, f *recoveryFixture, _ *session.Session, _ session.RenewalKind, err error) {
				require.ErrorIs(t, err, session.ErrReused, "the knocked-out successor has nothing to recover into")
				assert.Zero(t, f.store.Len(), "the family was not revoked")
				assert.Equal(t, 1, f.observed)
			},
		},
		{
			name: "with recovery a renewal through LoadForRenewal recovers",
			opts: recovery,
			act: func(ctx context.Context, t *testing.T, f *recoveryFixture, _ *session.Session) (*session.Session, session.RenewalKind, error) {
				f.clk.Advance(nextDay)
				old, err := f.m.LoadForRenewal(ctx, f.o.ID)
				require.NoError(t, err)
				assert.False(t, old.SupersededAt.IsZero(), "the renewal load hands back the superseded session")

				return f.m.RotateWithGrace(ctx, old, 30*time.Second)
			},
			assert: func(t *testing.T, f *recoveryFixture, got *session.Session, kind session.RenewalKind, err error) {
				require.NoError(t, err)
				assert.Equal(t, session.RenewalRecovery, kind)
				assert.Equal(t, 3, f.store.Len())
				live, err := f.m.Load(t.Context(), got.ID)
				require.NoError(t, err)
				assert.True(t, live.SupersededAt.IsZero())

				old, err := f.store.Load(t.Context(), f.o.ID)
				require.NoError(t, err)
				assert.Equal(t, createdAt.Add(30*time.Second), old.AcceptUntil, "a recovery reopened the old window")
			},
		},
		{
			name: "with recovery a successor that was loaded once makes the renewal reuse",
			opts: recovery,
			act: func(ctx context.Context, t *testing.T, f *recoveryFixture, s1 *session.Session) (*session.Session, session.RenewalKind, error) {
				_, err := f.m.Load(ctx, s1.ID)
				require.NoError(t, err)
				f.clk.Advance(nextDay)
				return renewO(ctx, f)
			},
			assert: func(t *testing.T, f *recoveryFixture, got *session.Session, _ session.RenewalKind, err error) {
				assertFamilyRevoked(t, f, got, err)
			},
		},
		{
			name: "with recovery a successor that was itself renewed makes the renewal reuse",
			opts: recovery,
			act: func(ctx context.Context, t *testing.T, f *recoveryFixture, s1 *session.Session) (*session.Session, session.RenewalKind, error) {
				// Rotated straight from the stored record, never loaded.
				f.clk.Advance(time.Minute)
				f.renew(ctx, t, s1, 30*time.Second)
				f.clk.Advance(nextDay)
				return renewO(ctx, f)
			},
			assert: func(t *testing.T, f *recoveryFixture, got *session.Session, _ session.RenewalKind, err error) {
				assertFamilyRevoked(t, f, got, err)
			},
		},
		{
			name: "with recovery an ordinary late request is refused without revoking",
			opts: recovery,
			act: func(ctx context.Context, _ *testing.T, f *recoveryFixture, _ *session.Session) (*session.Session, session.RenewalKind, error) {
				f.clk.Advance(nextDay)
				got, err := f.m.Load(ctx, f.o.ID)
				return got, 0, err
			},
			assert: func(t *testing.T, f *recoveryFixture, got *session.Session, _ session.RenewalKind, err error) {
				require.ErrorIs(t, err, session.ErrRenewalRequired)
				require.ErrorIs(t, err, session.ErrExpired)
				require.NotErrorIs(t, err, session.ErrReused)
				assert.Nil(t, got)
				assert.Equal(t, 2, f.store.Len(), "an ordinary request revoked the family")
				assert.Zero(t, f.observed, "an ordinary request was reported as reuse")
			},
		},
		{
			name: "with recovery the successor still loads after an ordinary late request",
			opts: recovery,
			act: func(ctx context.Context, t *testing.T, f *recoveryFixture, s1 *session.Session) (*session.Session, session.RenewalKind, error) {
				f.clk.Advance(nextDay)
				_, err := f.m.Load(ctx, f.o.ID)
				require.ErrorIs(t, err, session.ErrRenewalRequired)
				got, err := f.m.Load(ctx, s1.ID)
				return got, 0, err
			},
			assert: func(t *testing.T, _ *recoveryFixture, got *session.Session, _ session.RenewalKind, err error) {
				require.NoError(t, err)
				assert.True(t, got.SupersededAt.IsZero())
			},
		},
		{
			name: "with recovery a strict rotation past the window is refused as an ordinary request",
			opts: recovery,
			act: func(ctx context.Context, _ *testing.T, f *recoveryFixture, _ *session.Session) (*session.Session, session.RenewalKind, error) {
				f.clk.Advance(nextDay)
				got, err := f.m.Rotate(ctx, f.o)
				return got, 0, err
			},
			assert: func(t *testing.T, f *recoveryFixture, got *session.Session, _ session.RenewalKind, err error) {
				require.ErrorIs(t, err, session.ErrRenewalRequired)
				assert.Nil(t, got)
				assert.Equal(t, 2, f.store.Len(), "a refused strict rotation wrote")
			},
		},
		{
			name: "with recovery the renewal load inside the window is an ordinary load",
			opts: recovery,
			act: func(ctx context.Context, _ *testing.T, f *recoveryFixture, _ *session.Session) (*session.Session, session.RenewalKind, error) {
				f.clk.Advance(10 * time.Second)
				got, err := f.m.LoadForRenewal(ctx, f.o.ID)
				return got, 0, err
			},
			assert: func(t *testing.T, f *recoveryFixture, got *session.Session, _ session.RenewalKind, err error) {
				require.NoError(t, err)
				assert.Equal(t, f.o.ID, got.ID)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newRecoveryFixture(t, tc.opts...)
			s1 := f.renew(t.Context(), t, f.o, 30*time.Second)
			got, kind, err := tc.act(t.Context(), t, f, s1)
			tc.assert(t, f, got, kind, err)
		})
	}
}

func TestRenewalKind_String(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		kind   session.RenewalKind
		assert func(t *testing.T, got string)
	}

	cases := []testCase{
		{name: "fresh", kind: session.RenewalFresh, assert: func(t *testing.T, got string) { assert.Equal(t, "fresh", got) }},
		{
			name: "re-rotation", kind: session.RenewalReRotation,
			assert: func(t *testing.T, got string) { assert.Equal(t, "re-rotation", got) },
		},
		{
			name: "recovery", kind: session.RenewalRecovery,
			assert: func(t *testing.T, got string) { assert.Equal(t, "recovery", got) },
		},
		{
			name: "an unnamed kind prints its number", kind: session.RenewalKind(99),
			assert: func(t *testing.T, got string) { assert.Equal(t, "RenewalKind(99)", got) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.kind.String())
		})
	}
}

// recoveryManager is a manager with recovery on over store, on clk, whose
// sessions outlive a day.
func recoveryManager(t *testing.T, store session.Store, clk *clockwork.FakeClock) *session.Sessions {
	t.Helper()

	return managerFor(t, session.WithStore(store), session.WithClock(clk),
		session.WithAbsoluteTimeout(72*time.Hour), session.WithIdleTimeout(48*time.Hour),
		session.WithUnusedSuccessorRecovery())
}

// TestKnockedOutSuccessor_IsReuseWhateverTheReaderClock pins that a successor
// superseded by a re-rotation or a recovery is reuse when presented, even
// through a manager whose clock is behind the one that knocked it out: the
// knock-out ended its window by definition, so no reading clock can reopen
// it. The two managers share one store, as two replicas would.
func TestKnockedOutSuccessor_IsReuseWhateverTheReaderClock(t *testing.T) {
	t.Parallel()

	type fixture struct {
		reader, writer       *session.Sessions
		readerClk, writerClk *clockwork.FakeClock
		store                *session.MemoryStore
		o, s1                *session.Session
	}

	type testCase struct {
		name     string
		recovery bool
		// act knocks S1 out through the writer, its clock ahead of the
		// reader's, then presents S1 through the reader.
		act    func(ctx context.Context, t *testing.T, f *fixture) error
		assert func(t *testing.T, f *fixture, err error)
	}

	assertReuse := func(t *testing.T, f *fixture, err error) {
		t.Helper()

		require.ErrorIs(t, err, session.ErrReused)
		assert.Zero(t, f.store.Len(), "the family was not revoked")
	}
	reRotate := func(ctx context.Context, t *testing.T, f *fixture) {
		t.Helper()

		f.writerClk.Advance(10 * time.Second)
		f.readerClk.Advance(5 * time.Second)
		_, kind, err := f.writer.RotateWithGrace(ctx, f.o, 30*time.Second)
		require.NoError(t, err)
		require.Equal(t, session.RenewalReRotation, kind)
	}

	cases := []testCase{
		{
			name: "a successor knocked out by a re-rotation, loaded inside the window by the reader's clock",
			act: func(ctx context.Context, t *testing.T, f *fixture) error {
				reRotate(ctx, t, f)
				_, err := f.reader.Load(ctx, f.s1.ID)
				return err
			},
			assert: assertReuse,
		},
		{
			name: "a successor knocked out by a re-rotation, rotated at second-factor verification by the reader",
			act: func(ctx context.Context, t *testing.T, f *fixture) error {
				reRotate(ctx, t, f)
				_, err := f.reader.Rotate(ctx, f.s1)
				return err
			},
			assert: assertReuse,
		},
		{
			name:     "with recovery, a successor knocked out by a recovery, loaded before the recovery by the reader's clock",
			recovery: true,
			act: func(ctx context.Context, t *testing.T, f *fixture) error {
				f.writerClk.Advance(nextDay + time.Hour)
				f.readerClk.Advance(nextDay)
				_, kind, err := f.writer.RotateWithGrace(ctx, f.o, 30*time.Second)
				require.NoError(t, err)
				require.Equal(t, session.RenewalRecovery, kind)

				_, err = f.reader.Load(ctx, f.s1.ID)
				return err
			},
			assert: assertReuse,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := &fixture{
				readerClk: clockwork.NewFakeClockAt(createdAt),
				writerClk: clockwork.NewFakeClockAt(createdAt),
			}
			f.store = must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(f.readerClk)))
			managerOn := func(clk *clockwork.FakeClock) *session.Sessions {
				opts := []session.Option{
					session.WithStore(f.store), session.WithClock(clk),
					session.WithAbsoluteTimeout(72 * time.Hour), session.WithIdleTimeout(48 * time.Hour),
				}
				if tc.recovery {
					opts = append(opts, session.WithUnusedSuccessorRecovery())
				}
				return managerFor(t, opts...)
			}
			f.reader, f.writer = managerOn(f.readerClk), managerOn(f.writerClk)

			var err error
			f.o, err = f.writer.Create(t.Context(), testUser)
			require.NoError(t, err)
			f.s1, _, err = f.writer.RotateWithGrace(t.Context(), f.o, 30*time.Second)
			require.NoError(t, err)

			tc.assert(t, f, tc.act(t.Context(), t, f))
		})
	}
}

// countingStore counts the Load and MarkPresented calls that reach a memory
// store.
type countingStore struct {
	*session.MemoryStore

	loads, marks atomic.Int32
}

func (s *countingStore) Load(ctx context.Context, id string) (*session.Session, error) {
	s.loads.Add(1)

	return s.MemoryStore.Load(ctx, id)
}

func (s *countingStore) MarkPresented(ctx context.Context, id string, at time.Time) error {
	s.marks.Add(1)

	return s.MemoryStore.MarkPresented(ctx, id, at)
}

// TestUnusedSuccessorRecovery_FirstPresentationCost pins that with recovery
// on, the first presentation of a live session costs one read and one write:
// the store, not a second read, tells the manager whether a recovery
// superseded it in between.
// Standalone: it counts the store calls of one first presentation through a counting store.
func TestUnusedSuccessorRecovery_FirstPresentationCost(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(createdAt)
	store := &countingStore{MemoryStore: must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(clk)))}
	m := recoveryManager(t, store, clk)
	s, err := m.Create(t.Context(), testUser)
	require.NoError(t, err)

	got, err := m.Load(t.Context(), s.ID)

	require.NoError(t, err)
	assert.Equal(t, createdAt, got.FirstPresentedAt)
	assert.Equal(t, int32(1), store.loads.Load(), "a first presentation under recovery makes exactly one load")
	assert.Equal(t, int32(1), store.marks.Load(), "a first presentation under recovery makes exactly one mark")
}

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
			// family revoked, and ErrNotFound is not an outcome.
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
			inner := must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(clk)))
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

// Standalone: it lands a renewal inside Load through a store that fails after recovery.
func TestFailingMarkAfterRecoveryIsNotServed(t *testing.T) {
	clk := clockwork.NewFakeClockAt(createdAt)
	inner := must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(clk)))
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

// TestLoad_FailedFirstUseWrite pins what a failed first-use write does to a
// load: with unused-successor recovery on it fails the load, because serving
// a session whose first use was not recorded would let a used successor be
// judged unused later; with recovery off the session is still served. It also
// pins the other half of that: the successor whose write failed was never
// served, so a late renewal of its predecessor recovers it rather than
// judging it reuse.
func TestLoad_FailedFirstUseWrite(t *testing.T) {
	t.Parallel()

	const sid = "failed-first-use"

	type testCase struct {
		name string
		opts []session.Option
		// act runs the case's steps and returns what its last step returned.
		act    func(ctx context.Context, t *testing.T, opts []session.Option) (*session.Session, error)
		assert func(t *testing.T, got *session.Session, err error)
	}

	loadOnMock := func(ctx context.Context, t *testing.T, opts []session.Option) (*session.Session, error) {
		t.Helper()

		store := NewMockStore(gomock.NewController(t))
		store.EXPECT().Load(gomock.Any(), sid).Return(liveUnpresented(sid), nil).AnyTimes()
		store.EXPECT().MarkPresented(gomock.Any(), sid, createdAt).Return(errStoreQuotes).Times(1)

		all := append([]session.Option{
			session.WithStore(store), session.WithClock(clockwork.NewFakeClockAt(createdAt)),
		}, opts...)

		return managerFor(t, all...).Load(ctx, sid)
	}

	cases := []testCase{
		{
			name: "with recovery on the load fails",
			opts: []session.Option{session.WithUnusedSuccessorRecovery()},
			act:  loadOnMock,
			assert: func(t *testing.T, got *session.Session, err error) {
				require.ErrorIs(t, err, errStoreQuotes)
				assert.NotContains(t, err.Error(), "alice@example.com")
				assert.Nil(t, got)
			},
		},
		{
			name: "with recovery off the session is served",
			act:  loadOnMock,
			assert: func(t *testing.T, got *session.Session, err error) {
				require.NoError(t, err)
				require.NotNil(t, got)
			},
		},
		{
			name: "with recovery on a later renewal of the predecessor recovers the successor whose write failed",
			act: func(ctx context.Context, t *testing.T, _ []session.Option) (*session.Session, error) {
				t.Helper()

				clk := clockwork.NewFakeClockAt(createdAt)
				store := &failFirstMarkStore{MemoryStore: must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(clk)))}
				m := recoveryManager(t, store, clk)

				o, err := m.Create(ctx, testUser)
				require.NoError(t, err)
				s1, _, err := m.RotateWithGrace(ctx, o, 30*time.Second)
				require.NoError(t, err)

				store.id = s1.ID
				_, err = m.Load(ctx, s1.ID)
				require.ErrorIs(t, err, errStoreQuotes, "the first use of the successor was not recorded")

				clk.Advance(nextDay)
				got, kind, err := m.RotateWithGrace(ctx, o, 30*time.Second)
				if err == nil {
					assert.Equal(t, session.RenewalRecovery, kind)
				}

				return got, err
			},
			assert: func(t *testing.T, got *session.Session, err error) {
				require.NoError(t, err, "a successor that was never served is recovered, not judged reuse")
				require.NotNil(t, got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := tc.act(t.Context(), t, tc.opts)
			tc.assert(t, got, err)
		})
	}
}
