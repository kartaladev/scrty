package sqlstore_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/internal/idgen"
	"github.com/kartaladev/scrty/test/internal/idgenmock"

	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/store/sqlstore"
	"github.com/kartaladev/scrty/test/internal/storefix"
	"github.com/kartaladev/scrty/test/storetest"
)

// The durable login-attempt store carries the reaper as well as the store.
var _ interface {
	policy.AttemptStore
	lockout.AttemptReaper
} = (*sqlstore.AttemptStore)(nil)

// newAttemptStore builds the login-attempt store over db, failing t on a
// refusal.
func newAttemptStore(t *testing.T, db *sql.DB, opts ...sqlstore.Option) *sqlstore.AttemptStore {
	t.Helper()

	s, err := sqlstore.NewAttemptStore(db, opts...)
	require.NoError(t, err)

	return s
}

func TestAttemptStore(t *testing.T) {
	t.Parallel()

	db := migratedDB(t).DB

	t.Run("sqlstore", func(t *testing.T) {
		storetest.RunAttemptStoreSuite(t, func(t *testing.T) policy.AttemptStore {
			return newAttemptStore(t, emptied(t, db, "login_attempts"))
		}, storetest.RequireReaper())
	})
}

// The durable login-attempt store keeps consecutive-failure streaks too.
var _ lockout.FailureStreakStore = (*sqlstore.AttemptStore)(nil)

// TestFailureStreakStore runs the streak conformance suite and its race
// against the store, each case on emptied attempt and streak tables.
func TestFailureStreakStore(t *testing.T) {
	t.Parallel()

	db := migratedDB(t).DB
	newStore := func(t *testing.T) storetest.StreakStore {
		return newAttemptStore(t, emptied(t, emptied(t, db, "login_attempts"), "login_failure_streaks"))
	}

	t.Run("sqlstore", func(t *testing.T) {
		storetest.RunFailureStreakSuite(t, newStore)
		storetest.RunFailureStreakRace(t, newStore)
	})
}

func TestAttemptStore_IDs(t *testing.T) {
	t.Parallel()

	db := migratedDB(t).DB
	at := time.Date(2030, 1, 1, 10, 0, 0, 0, time.UTC)
	errGenerator := errors.New("generator exhausted")

	type testCase struct {
		name     string
		username string
		opts     []sqlstore.Option
		// ids, when set, is the generator the store mints from.
		ids    func(t *testing.T) id.Generator
		assert func(t *testing.T, err error, username string)
	}

	answering := func(got id.ID, err error) func(t *testing.T) id.Generator {
		return func(t *testing.T) id.Generator {
			g := idgenmock.NewMockGenerator(gomock.NewController(t))
			g.EXPECT().NewID().Return(got, err).AnyTimes()

			return g
		}
	}

	cases := []testCase{
		{
			name:     "with no generator configured the id is a version 7 uuid",
			username: "default-generator",
			assert: func(t *testing.T, err error, username string) {
				require.NoError(t, err)
				ids := storefix.AttemptIDs(t.Context(), t, db, username)
				require.Len(t, ids, 1)
				assert.Equal(t, byte('7'), ids[0][14], "id %s is not version 7", ids[0])
			},
		},
		{
			name:     "a consumer generator's id is the one stored",
			username: "consumer-generator",
			opts: []sqlstore.Option{sqlstore.WithIDGenerator(storefix.GeneratorFunc(func() (id.ID, error) {
				return id.MustParse("00000000-0000-4000-8000-000000000001"), nil
			}))},
			assert: func(t *testing.T, err error, username string) {
				require.NoError(t, err)
				assert.Equal(t, []string{"00000000-0000-4000-8000-000000000001"}, storefix.AttemptIDs(t.Context(), t, db, username))
			},
		},
		{
			name:     "a generator failure is returned wrapped, and nothing is written",
			username: "failing-generator",
			ids:      answering(id.Nil, errGenerator),
			assert: func(t *testing.T, err error, username string) {
				require.ErrorIs(t, err, errGenerator)
				assert.Empty(t, storefix.AttemptIDs(t.Context(), t, db, username))
			},
		},
		{
			name:     "a generator answering the nil id fails like a generator failure, and nothing is written",
			username: "nil-id-generator",
			ids:      answering(id.Nil, nil),
			assert: func(t *testing.T, err error, username string) {
				require.ErrorIs(t, err, idgen.ErrNil)
				assert.Contains(t, err.Error(), "record login failure")
				assert.Empty(t, storefix.AttemptIDs(t.Context(), t, db, username))
			},
		},
		{
			name:     "a username holding a NUL byte is refused without echoing it, never truncated",
			username: "a\x00b-canary-41",
			assert: func(t *testing.T, err error, _ string) {
				require.Error(t, err)
				assert.NotContains(t, err.Error(), "canary-41")
				assert.Empty(t, storefix.AttemptIDs(t.Context(), t, db, "a"), "the username was truncated at the NUL byte")
			},
		},
		{
			name:     "a username holding invalid UTF-8 is refused without echoing it, never altered",
			username: "caf\xe9-canary-42",
			assert: func(t *testing.T, err error, _ string) {
				require.Error(t, err)
				assert.NotContains(t, err.Error(), "canary-42")
				assert.Empty(t, storefix.AttemptIDs(t.Context(), t, db, "caf�-canary-42"), "the username was altered")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opts := tc.opts
			if tc.ids != nil {
				opts = append(opts[:len(opts):len(opts)], sqlstore.WithIDGenerator(tc.ids(t)))
			}
			err := newAttemptStore(t, db, opts...).RecordFailure(t.Context(), tc.username, at)
			tc.assert(t, err, tc.username)
		})
	}
}

// TestAttemptStore_StreakIDs pins that a streak's identifier comes from a
// generator that never answers the nil id: one that does fails the add and
// writes no streak.
func TestAttemptStore_StreakIDs(t *testing.T) {
	t.Parallel()

	db := migratedDB(t).DB
	at := time.Date(2030, 1, 1, 10, 0, 0, 0, time.UTC)
	errGenerator := errors.New("generator exhausted")

	type testCase struct {
		name     string
		username string
		got      id.ID
		genErr   error
		assert   func(t *testing.T, streak lockout.FailureStreak, err error, username string)
	}

	streakRows := func(t *testing.T, username string) int {
		t.Helper()

		var n int
		require.NoError(t, db.QueryRowContext(t.Context(),
			`SELECT count(*) FROM login_failure_streaks WHERE username = $1`, username).Scan(&n))

		return n
	}

	cases := []testCase{
		{
			name:     "a good id adds the streak",
			username: "streak-good-id",
			got:      storefix.NewID(t),
			assert: func(t *testing.T, streak lockout.FailureStreak, err error, username string) {
				require.NoError(t, err)
				assert.Equal(t, 1, streak.Failures)
				assert.Equal(t, 1, streakRows(t, username))
			},
		},
		{
			name:     "a generator failure fails the add and writes nothing",
			username: "streak-failing-generator",
			genErr:   errGenerator,
			assert: func(t *testing.T, _ lockout.FailureStreak, err error, username string) {
				require.ErrorIs(t, err, errGenerator)
				assert.Zero(t, streakRows(t, username))
			},
		},
		{
			name:     "a generator answering the nil id fails the add like a generator failure and writes nothing",
			username: "streak-nil-id",
			assert: func(t *testing.T, _ lockout.FailureStreak, err error, username string) {
				require.ErrorIs(t, err, idgen.ErrNil)
				assert.Contains(t, err.Error(), "add to login failure streak")
				assert.Zero(t, streakRows(t, username))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			g := idgenmock.NewMockGenerator(gomock.NewController(t))
			g.EXPECT().NewID().Return(tc.got, tc.genErr).AnyTimes()
			s := newAttemptStore(t, db, sqlstore.WithIDGenerator(g))

			streak, _, err := s.AddStreakFailure(t.Context(), tc.username, at, at.Add(-time.Hour), 5)
			tc.assert(t, streak, err, tc.username)
		})
	}
}

// TestAttemptStore_Refusals pins what the reaper refuses and how a failure is
// reported, on a store over one database.
func TestAttemptStore_Refusals(t *testing.T) {
	t.Parallel()

	db := migratedDB(t).DB
	s := newAttemptStore(t, db)

	type testCase struct {
		name   string
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, ctx context.Context)
	}

	cases := []testCase{
		{
			name: "a zero cutoff is refused",
			assert: func(t *testing.T, ctx context.Context) {
				n, err := s.DeleteAttemptsBefore(ctx, time.Time{})
				require.ErrorIs(t, err, lockout.ErrRetainSinceRequired)
				assert.Zero(t, n)
			},
		},
		{
			name: "a username PostgreSQL cannot hold is refused without aborting the caller's transaction",
			assert: func(t *testing.T, ctx context.Context) {
				tx, err := db.BeginTx(ctx, nil)
				require.NoError(t, err)
				t.Cleanup(func() { _ = tx.Rollback() })
				txCtx := sqlstore.WithTx(ctx, tx)
				at := time.Date(2030, 1, 1, 10, 0, 0, 0, time.UTC)

				require.Error(t, s.RecordFailure(txCtx, "nul\x00canary", at))
				require.Error(t, s.RecordFailure(txCtx, "caf\xe9canary", at))
				require.NoError(t, s.RecordFailure(txCtx, "after-refusal", at),
					"the refusal aborted the caller's transaction")
				require.NoError(t, tx.Commit())
				assert.Len(t, storefix.AttemptIDs(ctx, t, db, "after-refusal"), 1)
			},
		},
		{
			name: "a count under a cancelled context fails with the cancellation, never as zero",
			ctx:  storefix.Cancelled,
			assert: func(t *testing.T, ctx context.Context) {
				_, err := s.FailureCount(ctx, "alice", time.Time{})
				require.ErrorIs(t, err, context.Canceled)
				assert.ErrorContains(t, err, "sqlstore: count login failures")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}
			tc.assert(t, ctx)
		})
	}
}

func TestNewAttemptStore(t *testing.T) {
	t.Parallel()

	db := unreachableDB(t)

	type testCase struct {
		name   string
		db     *sql.DB
		opts   []sqlstore.Option
		assert func(t *testing.T, s *sqlstore.AttemptStore, err error)
	}

	refused := refusedConfig[*sqlstore.AttemptStore]
	accepted := storefix.AcceptedConfig[*sqlstore.AttemptStore]

	cases := []testCase{
		{name: "a handle is all it needs", db: db, assert: accepted},
		{
			name:   "it honours an id generator",
			db:     db,
			opts:   []sqlstore.Option{sqlstore.WithIDGenerator(id.NewV7Generator())},
			assert: accepted,
		},
		{name: "a missing handle is refused", assert: refused("the database handle is nil")},
		{
			name:   "a clock does not apply to attempts, whose instants come from the caller",
			db:     db,
			opts:   []sqlstore.Option{sqlstore.WithClock(clock.System())},
			assert: refused("WithClock does not apply to this store"),
		},
		{
			name:   "re-sealing does not apply to attempts",
			db:     db,
			opts:   []sqlstore.Option{sqlstore.WithResealOnRead(false)},
			assert: refused("WithResealOnRead does not apply to this store"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s, err := sqlstore.NewAttemptStore(tc.db, tc.opts...)
			tc.assert(t, s, err)
		})
	}
}
