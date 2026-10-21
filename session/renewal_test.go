package session_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

const day = 24 * time.Hour

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
	long := []session.ManagerOption{
		session.WithMaxAbsoluteLifetime(30 * day),
		session.WithMaxFamilyLifetime(90 * day),
	}

	type testCase struct {
		name string
		opts []session.ManagerOption
		// familyStart, now and abs place the stored session; now is also the
		// manager's clock.
		familyStart, now, abs time.Time
		rotate                func(ctx context.Context, m *session.Manager, s *session.Session) (*session.Session, error)
		assert                func(t *testing.T, store *session.MemoryStore, s, got *session.Session, err error)
	}

	withLifetime := func(d time.Duration) func(context.Context, *session.Manager, *session.Session) (*session.Session, error) {
		return func(ctx context.Context, m *session.Manager, s *session.Session) (*session.Session, error) {
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
			rotate: func(ctx context.Context, m *session.Manager, s *session.Session) (*session.Session, error) {
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
			rotate: func(ctx context.Context, m *session.Manager, s *session.Session) (*session.Session, error) {
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
		act    func(ctx context.Context, t *testing.T, m *session.Manager, o *session.Session, clk *clockwork.FakeClock) (stolen string, at time.Time)
		assert func(t *testing.T, store *session.MemoryStore, err error)
	}

	extend := func(ctx context.Context, t *testing.T, m *session.Manager, s *session.Session) *session.Session {
		t.Helper()

		next, _, err := m.RotateWithGrace(ctx, s, 30*time.Second, session.WithSuccessorLifetime(12*time.Hour))
		require.NoError(t, err)
		require.True(t, next.AbsoluteExpiresAt.After(s.AbsoluteExpiresAt), "the renewal did not extend the family")

		return next
	}
	revoked := func(t *testing.T, store *session.MemoryStore, err error) {
		t.Helper()

		require.ErrorIs(t, err, session.ErrSessionReused, "a stolen identifier presented while its family is live")
		assert.Zero(t, store.Len(), "the family was not revoked")
	}

	cases := []testCase{
		{
			name: "O renewed at 15:00 for 12 hours, presented at 22:00, past its own 21:00",
			act: func(ctx context.Context, t *testing.T, m *session.Manager, o *session.Session, clk *clockwork.FakeClock) (string, time.Time) {
				clk.Advance(6 * time.Hour)
				extend(ctx, t, m, o)
				return o.ID, createdAt.Add(13 * time.Hour)
			},
			assert: revoked,
		},
		{
			name: "S1 renewed again at 16:00, presented at 03:30 the next day, past its own 03:00",
			act: func(ctx context.Context, t *testing.T, m *session.Manager, o *session.Session, clk *clockwork.FakeClock) (string, time.Time) {
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
			act: func(ctx context.Context, t *testing.T, m *session.Manager, o *session.Session, clk *clockwork.FakeClock) (string, time.Time) {
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

func TestNewManager_RenewalOptions(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []session.ManagerOption
		assert func(t *testing.T, m *session.Manager, err error)
	}

	cases := []testCase{
		{
			name: "a family maximum below the lifetime maximum is refused",
			opts: []session.ManagerOption{
				session.WithMaxAbsoluteLifetime(30 * day),
				session.WithMaxFamilyLifetime(7 * day),
			},
			assert: func(t *testing.T, m *session.Manager, err error) {
				require.ErrorIs(t, err, session.ErrConfig)
				assert.Nil(t, m)
			},
		},
		{
			name: "a family maximum below the default lifetime maximum is refused",
			opts: []session.ManagerOption{session.WithMaxFamilyLifetime(time.Hour)},
			assert: func(t *testing.T, m *session.Manager, err error) {
				require.ErrorIs(t, err, session.ErrConfig)
				assert.Nil(t, m)
			},
		},
		{
			name: "a family maximum equal to the lifetime maximum is accepted",
			opts: []session.ManagerOption{
				session.WithMaxAbsoluteLifetime(30 * day),
				session.WithMaxFamilyLifetime(30 * day),
			},
			assert: func(t *testing.T, m *session.Manager, err error) {
				require.NoError(t, err)
				assert.NotNil(t, m)
			},
		},
		{
			name: "a nil reuse observer is refused",
			opts: []session.ManagerOption{session.WithReuseObserver(nil)},
			assert: func(t *testing.T, m *session.Manager, err error) {
				require.ErrorIs(t, err, session.ErrConfig)
				assert.Nil(t, m)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m, err := session.NewManager(tc.opts...)
			tc.assert(t, m, err)
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
				require.ErrorIs(t, err, session.ErrSessionReused)
				assert.Zero(t, r.store.Len())
				assert.Empty(t, r.reports)
			},
		},
		{
			name:    "an observer is called once with the user, the family and the times",
			observe: true,
			assert: func(t *testing.T, r reuseRun, err error) {
				require.ErrorIs(t, err, session.ErrSessionReused)
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
				require.ErrorIs(t, err, session.ErrSessionReused)
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
			opts := []session.ManagerOption{session.WithSessionLogger(
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
				require.ErrorIs(t, err, session.ErrSessionReused)
				assert.Equal(t, 1, observed)
			},
		},
		{
			name:      "a failed revocation is refused as reuse, reported, and not observed",
			deleteErr: errStoreQuotes,
			assert: func(t *testing.T, observed int, err error) {
				require.ErrorIs(t, err, session.ErrSessionReused)
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
