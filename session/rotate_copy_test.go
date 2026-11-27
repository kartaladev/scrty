package session_test

import (
	"context"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/session"
)

// TestRotate_CallerCopy pins what a strict rotation, Rotate and RotateIssuing
// alike, takes from the caller's copy of the session and what it takes from
// the stored record. The user and the first factor are the stored record's: a
// copy naming another user is refused with ErrConfig before the step runs,
// and another first factor is ignored. The deadlines are never extended: each
// is the earlier of the stored record's and the copy's, unless the copy lifted
// a stored enrolment confinement, when they are the copy's, never past the
// stored origin. Given WithSuccessorFromCaller, a stored record whose security
// state changed since the copy was loaded is refused with ErrRenewalConflict,
// and nothing is written.
func TestRotate_CallerCopy(t *testing.T) {
	t.Parallel()

	const idle = 30 * time.Minute
	rotatedAt := createdAt.Add(5 * time.Minute)

	type fixture struct {
		clk   *clockwork.FakeClock
		m     *session.Sessions
		store *callerSuccessorStore
		// stored is the record as the store holds it; loaded is the session
		// as the caller loaded it; copy is the caller's copy, verified.
		stored, loaded, copy *session.Session
		stepped              bool
	}

	type testCase struct {
		name    string
		prepare func(t *testing.T, f *fixture)
		opts    func(f *fixture) []session.RotateOption
		assert  func(t *testing.T, f *fixture, got *session.Session, err error)
	}

	load := func(t *testing.T, f *fixture, id string) *session.Session {
		t.Helper()
		s, err := f.store.Load(t.Context(), id)
		require.NoError(t, err)

		return s
	}
	// verified makes c a copy whose second factor was just satisfied, as MFA
	// verification makes it.
	verified := func(f *fixture, c *session.Session) *session.Session {
		c = copyOf(c)
		c.MFA = session.MFASatisfied
		c.MFASatisfiedAt = f.clk.Now()
		c.AuthenticatedAt = c.MFASatisfiedAt

		return c
	}
	// confineStored stores the session confined to enrolment for 15 minutes,
	// its deadlines lowered and the deadline it held recorded as the origin.
	confineStored := func(t *testing.T, f *fixture) {
		t.Helper()
		s := load(t, f, f.stored.ID)
		f.m.MarkEnrolmentPending(s, 15*time.Minute)
		require.NoError(t, f.store.Save(t.Context(), s))
	}
	// liftedCopy confines the stored record, reloads it, and makes the copy a
	// verified copy of it with the confinement lifted, as MFA verification
	// lifts it.
	liftedCopy := func(t *testing.T, f *fixture) {
		t.Helper()
		confineStored(t, f)
		f.stored = load(t, f, f.stored.ID)
		f.loaded = load(t, f, f.stored.ID)
		require.True(t, f.stored.AbsoluteExpiresAt.Before(f.stored.EnrolmentOriginDeadline), "the deadline is lowered")

		f.copy = verified(f, f.stored)
		require.NoError(t, f.m.RestoreEnrolmentDeadlines(f.copy))
		require.True(t, f.copy.AbsoluteExpiresAt.Equal(f.stored.EnrolmentOriginDeadline))
		require.True(t, f.copy.IdleExpiresAt.After(f.stored.IdleExpiresAt), "the restored idle deadline is later")
	}
	// rotatedWith asserts the rotation succeeded and returns the successor as
	// the store holds it.
	rotatedWith := func(t *testing.T, f *fixture, got *session.Session, err error) *session.Session {
		t.Helper()
		require.NoError(t, err)
		require.NotNil(t, got)

		return load(t, f, got.ID)
	}
	// nothingWritten asserts the old record was neither superseded nor
	// revoked, no successor was stored, and the issuing step never ran.
	nothingWritten := func(t *testing.T, f *fixture, got *session.Session) {
		t.Helper()
		assert.Nil(t, got)
		assert.False(t, f.stepped, "the issuing step never runs")
		assert.Equal(t, int32(0), f.store.supersedes.Load(), "nothing superseded")
		old := load(t, f, f.stored.ID)
		assert.True(t, old.SupersededAt.IsZero(), "the old session is not superseded")
		assert.False(t, old.RotatedStrictly, "the old session is not rotated")
		assert.Equal(t, 1, f.store.Len(), "no successor stored")
	}
	fromCaller := func(f *fixture) []session.RotateOption {
		return []session.RotateOption{session.WithSuccessorFromCaller(f.loaded)}
	}

	cases := []testCase{
		{
			name: "a copy with later deadlines keeps the stored ones",
			prepare: func(_ *testing.T, f *fixture) {
				f.copy.AbsoluteExpiresAt = f.stored.AbsoluteExpiresAt.Add(24 * time.Hour)
				f.copy.IdleExpiresAt = f.stored.IdleExpiresAt.Add(24 * time.Hour)
			},
			assert: func(t *testing.T, f *fixture, got *session.Session, err error) {
				s := rotatedWith(t, f, got, err)
				assert.True(t, s.AbsoluteExpiresAt.Equal(f.stored.AbsoluteExpiresAt), "absolute deadline %s, stored %s",
					s.AbsoluteExpiresAt, f.stored.AbsoluteExpiresAt)
				assert.True(t, s.IdleExpiresAt.Equal(f.stored.IdleExpiresAt), "idle deadline %s, stored %s",
					s.IdleExpiresAt, f.stored.IdleExpiresAt)
				assert.True(t, got.AbsoluteExpiresAt.Equal(f.stored.AbsoluteExpiresAt), "the returned successor agrees")
			},
		},
		{
			name: "a copy with a lowered deadline lowers the successor's",
			prepare: func(_ *testing.T, f *fixture) {
				f.m.MarkEnrolmentPending(f.copy, 15*time.Minute)
			},
			assert: func(t *testing.T, f *fixture, got *session.Session, err error) {
				s := rotatedWith(t, f, got, err)
				assert.True(t, s.AbsoluteExpiresAt.Equal(f.copy.AbsoluteExpiresAt), "absolute deadline %s, copy %s",
					s.AbsoluteExpiresAt, f.copy.AbsoluteExpiresAt)
				assert.True(t, s.AbsoluteExpiresAt.Before(f.stored.AbsoluteExpiresAt))
				assert.True(t, s.IdleExpiresAt.Equal(f.copy.IdleExpiresAt), "idle deadline %s, copy %s",
					s.IdleExpiresAt, f.copy.IdleExpiresAt)
			},
		},
		{
			name: "a copy naming another user is refused before anything is written",
			prepare: func(_ *testing.T, f *fixture) {
				f.copy.UserID = identity.UserID("someone-else")
			},
			assert: func(t *testing.T, f *fixture, got *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrConfig)
				nothingWritten(t, f, got)
			},
		},
		{
			name: "a copy with another first factor keeps the stored one",
			prepare: func(_ *testing.T, f *fixture) {
				f.copy.FirstFactor = factor.Kind("passkey")
			},
			assert: func(t *testing.T, f *fixture, got *session.Session, err error) {
				s := rotatedWith(t, f, got, err)
				assert.Equal(t, factor.Password, s.FirstFactor)
				assert.Equal(t, factor.Password, got.FirstFactor)
			},
		},
		{
			name:    "a copy that lifted the stored confinement takes the restored deadlines",
			prepare: liftedCopy,
			assert: func(t *testing.T, f *fixture, got *session.Session, err error) {
				s := rotatedWith(t, f, got, err)
				assert.True(t, s.AbsoluteExpiresAt.Equal(f.stored.EnrolmentOriginDeadline), "absolute deadline %s, origin %s",
					s.AbsoluteExpiresAt, f.stored.EnrolmentOriginDeadline)
				assert.True(t, s.IdleExpiresAt.Equal(f.copy.IdleExpiresAt), "idle deadline %s, copy %s",
					s.IdleExpiresAt, f.copy.IdleExpiresAt)
				assert.True(t, s.EnrolmentOriginDeadline.IsZero(), "the confinement is lifted")
			},
		},
		{
			name: "a lifted copy claiming a deadline past the origin keeps the stored, lowered ones",
			prepare: func(t *testing.T, f *fixture) {
				liftedCopy(t, f)
				f.copy.AbsoluteExpiresAt = f.stored.EnrolmentOriginDeadline.Add(time.Hour)
				f.copy.IdleExpiresAt = f.copy.AbsoluteExpiresAt
			},
			assert: func(t *testing.T, f *fixture, got *session.Session, err error) {
				s := rotatedWith(t, f, got, err)
				assert.True(t, s.AbsoluteExpiresAt.Equal(f.stored.AbsoluteExpiresAt), "absolute deadline %s, stored %s",
					s.AbsoluteExpiresAt, f.stored.AbsoluteExpiresAt)
				assert.True(t, s.IdleExpiresAt.Equal(f.stored.IdleExpiresAt), "idle deadline %s, stored %s",
					s.IdleExpiresAt, f.stored.IdleExpiresAt)
			},
		},
		{
			name: "with the loaded copy, an unchanged record rotates from the copy",
			opts: fromCaller,
			assert: func(t *testing.T, f *fixture, got *session.Session, err error) {
				s := rotatedWith(t, f, got, err)
				assert.Equal(t, session.MFASatisfied, s.MFA)
				assert.True(t, s.AuthenticatedAt.Equal(f.copy.AuthenticatedAt))
			},
		},
		{
			name: "with the loaded copy, a confinement saved after the load is a renewal conflict",
			prepare: func(t *testing.T, f *fixture) {
				confineStored(t, f)
			},
			opts: fromCaller,
			assert: func(t *testing.T, f *fixture, got *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrRenewalConflict)
				nothingWritten(t, f, got)
				stored := load(t, f, f.stored.ID)
				assert.Equal(t, session.MFAEnrolmentPending, stored.MFA, "the confinement stands")
				assert.False(t, stored.EnrolmentOriginDeadline.IsZero(), "the confinement stands")
			},
		},
		{
			name: "with the loaded copy, a pending password change saved after the load is a renewal conflict",
			prepare: func(t *testing.T, f *fixture) {
				s := load(t, f, f.stored.ID)
				s.PasswordChangePending = true
				require.NoError(t, f.store.Save(t.Context(), s))
			},
			opts: fromCaller,
			assert: func(t *testing.T, f *fixture, got *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrRenewalConflict)
				nothingWritten(t, f, got)
			},
		},
		{
			name: "a nil loaded copy is a configuration error",
			opts: func(*fixture) []session.RotateOption {
				return []session.RotateOption{session.WithSuccessorFromCaller(nil)}
			},
			assert: func(t *testing.T, f *fixture, got *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrConfig)
				nothingWritten(t, f, got)
			},
		},
		{
			name: "a loaded copy of another session is a configuration error",
			opts: func(f *fixture) []session.RotateOption {
				other := copyOf(f.loaded)
				other.ID = "another-session"

				return []session.RotateOption{session.WithSuccessorFromCaller(other)}
			},
			assert: func(t *testing.T, f *fixture, got *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrConfig)
				nothingWritten(t, f, got)
			},
		},
		{
			name: "with the loaded copy, a copy naming another user is a configuration error",
			prepare: func(_ *testing.T, f *fixture) {
				f.copy.UserID = identity.UserID("someone-else")
			},
			opts: fromCaller,
			assert: func(t *testing.T, f *fixture, got *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrConfig)
				nothingWritten(t, f, got)
			},
		},
	}

	rotators := []struct {
		name   string
		rotate func(ctx context.Context, f *fixture, opts ...session.RotateOption) (*session.Session, error)
	}{
		{
			name: "Rotate",
			rotate: func(ctx context.Context, f *fixture, opts ...session.RotateOption) (*session.Session, error) {
				return f.m.Rotate(ctx, f.copy, opts...)
			},
		},
		{
			name: "RotateIssuing",
			rotate: func(ctx context.Context, f *fixture, opts ...session.RotateOption) (*session.Session, error) {
				got, _, err := f.m.RotateIssuing(ctx, f.copy, func(*session.Session) (string, error) {
					f.stepped = true

					return "credential", nil
				}, opts...)

				return got, err
			},
		},
	}

	for _, r := range rotators {
		for _, tc := range cases {
			t.Run(r.name+"/"+tc.name, func(t *testing.T) {
				t.Parallel()

				clk := clockwork.NewFakeClockAt(createdAt)
				store := &callerSuccessorStore{
					MemoryStore: must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(clk))),
				}
				m := managerFor(t,
					session.WithStore(store),
					session.WithClock(clk),
					session.WithIdleTimeout(idle),
					session.WithAbsoluteTimeout(8*time.Hour))
				s, err := m.Create(t.Context(), testUser, session.WithFirstFactor(factor.Password))
				require.NoError(t, err)
				s.MFA = session.MFAPending
				require.NoError(t, m.Save(t.Context(), s))

				clk.Advance(rotatedAt.Sub(createdAt))
				f := &fixture{clk: clk, m: m, store: store}
				f.stored = load(t, f, s.ID)
				f.loaded = load(t, f, s.ID)
				f.copy = verified(f, f.loaded)
				if tc.prepare != nil {
					tc.prepare(t, f)
				}

				var opts []session.RotateOption
				if tc.opts != nil {
					opts = tc.opts(f)
				}

				got, err := r.rotate(t.Context(), f, opts...)
				tc.assert(t, f, got, err)
			})
		}
	}
}
