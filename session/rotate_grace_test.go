package session_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

// graceFixture is a manager and its memory store on one fake clock, with the
// session O created at 09:00.
type graceFixture struct {
	clk   *clockwork.FakeClock
	m     *session.Manager
	store *session.MemoryStore
	o     *session.Session
}

func newGraceFixture(t *testing.T, opts ...session.ManagerOption) *graceFixture {
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
		opts []session.ManagerOption
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
			opts: []session.ManagerOption{session.WithIdleTimeout(12 * time.Hour)},
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
				require.ErrorIs(t, err, session.ErrSessionReused)
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
				require.ErrorIs(t, err, session.ErrSessionReused, "the window ended at 09:00:30")
			},
		},
		{
			name: "presentation after the window is reuse, matches expiry, and revokes the family",
			act: func(ctx context.Context, t *testing.T, f *graceFixture) (*session.Session, error) {
				s1 := f.renew(ctx, t, f.o, 30*time.Second)
				f.clk.Advance(5 * time.Minute)
				_, err := f.m.Load(ctx, f.o.ID)
				require.ErrorIs(t, err, session.ErrSessionReused)
				require.ErrorIs(t, err, session.ErrSessionExpired)

				return f.m.Load(ctx, s1.ID)
			},
			assert: func(t *testing.T, f *graceFixture, _ *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrSessionNotFound)
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
				require.ErrorIs(t, err, session.ErrSessionReused)
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
				require.ErrorIs(t, err, session.ErrSessionReused)

				err = f.m.Delete(ctx, f.o.ID)
				if errors.Is(err, session.ErrSessionNotFound) {
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
				require.ErrorIs(t, err, session.ErrSessionReused)
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
				require.ErrorIs(t, err, session.ErrSessionRenewalConflict)

				_, loadErr := f.m.Load(ctx, s1.ID)
				require.NoError(t, loadErr, "the current successor must still load")
				return got, err
			},
			assert: func(t *testing.T, f *graceFixture, got *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrSessionRenewalConflict)
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
				require.ErrorIs(t, err, session.ErrSessionReused)
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
				require.ErrorIs(t, err, session.ErrSessionReused)
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
				require.ErrorIs(t, err, session.ErrSessionReused)
			},
		},
		{
			name: "a clock at 09:00:31 is reuse",
			at:   createdAt.Add(31 * time.Second),
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, session.ErrSessionReused)
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

// graceFamily is the family of the mocked fixtures.
var graceFamily = id.MustParse("0192d2a0-0000-7000-8000-000000000001")

// liveUnpresented is a live session that has never been loaded.
func liveUnpresented(id string) *session.Session { return familyOf(id, graceFamily) }

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
			name:   "a failing mark does not fail the load",
			stored: func() *session.Session { return liveUnpresented(sid) },
			expect: func(store *MockStore) {
				store.EXPECT().MarkPresented(gomock.Any(), sid, createdAt).Return(errStoreQuotes).Times(1)
			},
			assert: func(t *testing.T, got *session.Session, err error) {
				require.NoError(t, err)
				require.NotNil(t, got)
				assert.True(t, got.FirstPresentedAt.IsZero(), "the session claims a mark the store refused")
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

// TestTouch_WritesNothingForASupersededSession pins that grace never extends:
// a superseded session's activity reaches no store.
func TestTouch_WritesNothingForASupersededSession(t *testing.T) {
	t.Parallel()

	store := NewMockStore(gomock.NewController(t)) // any call fails the test
	m := managerFor(t, session.WithStore(store), session.WithClock(clockwork.NewFakeClockAt(createdAt)))

	s := liveUnpresented("superseded")
	s.LastAccessedAt = createdAt.Add(-5 * time.Minute)
	s.SupersededAt = createdAt.Add(-10 * time.Second)
	s.AcceptUntil = createdAt.Add(20 * time.Second)

	require.NoError(t, m.Touch(t.Context(), s))
	assert.Equal(t, createdAt.Add(-5*time.Minute), s.LastAccessedAt)
}
