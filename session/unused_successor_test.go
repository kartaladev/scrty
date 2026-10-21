package session_test

import (
	"context"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/session"
)

// nextDay is how long after O's rotation the late retries below arrive.
const nextDay = 24 * time.Hour

// recoveryFixture is a graceFixture whose sessions outlive a day, so a
// next-day retry is judged by its window and not by an ended deadline, with
// an observer counting the reuses it is told about.
type recoveryFixture struct {
	*graceFixture

	observed int
}

func newRecoveryFixture(t *testing.T, opts ...session.ManagerOption) *recoveryFixture {
	t.Helper()

	f := &recoveryFixture{}
	all := append([]session.ManagerOption{
		session.WithAbsoluteTimeout(72 * time.Hour),
		session.WithIdleTimeout(48 * time.Hour),
		session.WithReuseObserver(func(context.Context, session.ReuseReport) { f.observed++ }),
	}, opts...)
	f.graceFixture = newGraceFixture(t, all...)

	return f
}

func TestUnusedSuccessorRecovery(t *testing.T) {
	t.Parallel()

	recovery := []session.ManagerOption{session.WithUnusedSuccessorRecovery()}

	type testCase struct {
		name string
		opts []session.ManagerOption
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

		require.ErrorIs(t, err, session.ErrSessionReused)
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
				require.ErrorIs(t, err, session.ErrSessionReused, "the knocked-out successor has nothing to recover into")
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
				require.ErrorIs(t, err, session.ErrSessionRenewalRequired)
				require.ErrorIs(t, err, session.ErrSessionExpired)
				require.NotErrorIs(t, err, session.ErrSessionReused)
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
				require.ErrorIs(t, err, session.ErrSessionRenewalRequired)
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
				require.ErrorIs(t, err, session.ErrSessionRenewalRequired)
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
func recoveryManager(t *testing.T, store session.Store, clk *clockwork.FakeClock) *session.Manager {
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
		reader, writer       *session.Manager
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

		require.ErrorIs(t, err, session.ErrSessionReused)
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
			f.store = session.NewMemoryStore(session.WithMemoryStoreClock(f.readerClk))
			managerOn := func(clk *clockwork.FakeClock) *session.Manager {
				opts := []session.ManagerOption{
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
