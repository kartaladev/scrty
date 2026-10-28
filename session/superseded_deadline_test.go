package session_test

import (
	"context"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/session"
)

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
			inner := session.NewMemoryStore(session.WithMemoryStoreClock(clk))
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
