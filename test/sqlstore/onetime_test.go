package sqlstore_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/onetime"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/sqlstore"
	"github.com/kartaladev/scrty/test"
	"github.com/kartaladev/scrty/test/internal/storefix"
	"github.com/kartaladev/scrty/test/storetest"
)

// The durable one-time token store carries the reaper as well as the store.
var _ interface {
	onetime.Store
	onetime.Reaper
} = (*sqlstore.OneTimeStore)(nil)

// newOneTimeStore builds the one-time token store over db, failing t on a
// refusal.
func newOneTimeStore(t *testing.T, db *sql.DB, opts ...sqlstore.Option) *sqlstore.OneTimeStore {
	t.Helper()

	s, err := sqlstore.NewOneTimeStore(db, opts...)
	require.NoError(t, err)

	return s
}

func TestOneTimeStore(t *testing.T) {
	t.Parallel()

	db := migratedDB(t).DB

	t.Run("sqlstore", func(t *testing.T) {
		storetest.RunOneTimeStoreSuite(t, func(t *testing.T, now func() time.Time) onetime.Store {
			return newOneTimeStore(t, emptied(t, db, "one_time_tokens"), sqlstore.WithClock(now))
		}, storetest.RequireReaper())
	})
}

func TestOneTimeStore_ConsumeRace(t *testing.T) {
	t.Parallel()

	h := durableHarness(migratedDB(t), func(t *testing.T, db *sql.DB, opts ...sqlstore.Option) *sqlstore.OneTimeStore {
		return newOneTimeStore(t, db, opts...)
	})

	t.Run("sqlstore", func(t *testing.T) {
		storetest.RunConsumeRace(t, h, storefix.ConsumeRace[*sqlstore.OneTimeStore]())
	})
}

func TestOneTimeStore_Failures(t *testing.T) {
	t.Parallel()

	conn := migratedDB(t)

	type testCase struct {
		name string
		// db returns the handle the store is built on.
		db     func(t *testing.T, conn test.PostgresConn) *sql.DB
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, ctx context.Context, s *sqlstore.OneTimeStore)
	}

	shared := func(_ *testing.T, conn test.PostgresConn) *sql.DB { return conn.DB }

	cases := []testCase{
		{
			name: "consumption fails, and is not the refusal, when the database is unavailable",
			db: func(t *testing.T, conn test.PostgresConn) *sql.DB {
				db := openReplica(t, conn.DSN)
				require.NoError(t, db.Close())
				return db
			},
			assert: func(t *testing.T, ctx context.Context, s *sqlstore.OneTimeStore) {
				err := s.Consume(ctx, storefix.RaceToken(1).ID, time.Now())
				require.Error(t, err)
				assert.NotErrorIs(t, err, onetime.ErrTokenNotFound)
				// A closed *sql.DB reports database/sql's own unexported error,
				// not sql.ErrConnDone, which is a closed connection or
				// transaction.
				assert.ErrorContains(t, err, "sql: database is closed")
				assert.ErrorContains(t, err, "sqlstore: consume one-time token")
			},
		},
		{
			name: "consumption fails, and is not the refusal, when the server cannot be reached",
			db: func(t *testing.T, _ test.PostgresConn) *sql.DB {
				return unreachableDB(t)
			},
			assert: func(t *testing.T, ctx context.Context, s *sqlstore.OneTimeStore) {
				err := s.Consume(ctx, storefix.RaceToken(1).ID, time.Now())
				require.Error(t, err)
				assert.NotErrorIs(t, err, onetime.ErrTokenNotFound)
				assert.ErrorContains(t, err, "sqlstore: consume one-time token")
			},
		},
		{
			name: "a consume under a cancelled context fails with the cancellation, never as not found",
			db:   shared,
			ctx:  storefix.Cancelled,
			assert: func(t *testing.T, ctx context.Context, s *sqlstore.OneTimeStore) {
				err := s.Consume(ctx, storefix.RaceToken(2).ID, time.Now())
				require.ErrorIs(t, err, context.Canceled)
				assert.NotErrorIs(t, err, onetime.ErrTokenNotFound)
			},
		},
		{
			name: "stored times are truncated to the microsecond",
			db:   shared,
			assert: func(t *testing.T, ctx context.Context, s *sqlstore.OneTimeStore) {
				tok := storefix.RaceToken(3)
				tok.IssuedAt = time.Date(2026, 9, 15, 10, 0, 0, 123456789, time.UTC)
				tok.ExpiresAt = tok.IssuedAt.Add(time.Hour)
				require.NoError(t, s.Insert(ctx, tok))

				got, err := s.FindByID(ctx, tok.ID)
				require.NoError(t, err)
				want := time.Date(2026, 9, 15, 10, 0, 0, 123456000, time.UTC)
				assert.True(t, want.Equal(got.IssuedAt), "issued at %v, want %v", got.IssuedAt, want)
				assert.True(t, want.Add(time.Hour).Equal(got.ExpiresAt), "expires at %v", got.ExpiresAt)
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

			tc.assert(t, ctx, newOneTimeStore(t, tc.db(t, conn)))
		})
	}
}

func TestNewOneTimeStore(t *testing.T) {
	t.Parallel()

	db := unreachableDB(t)

	type testCase struct {
		name   string
		db     *sql.DB
		opts   []sqlstore.Option
		assert func(t *testing.T, s *sqlstore.OneTimeStore, err error)
	}

	refused := refusedConfig[*sqlstore.OneTimeStore]
	accepted := storefix.AcceptedConfig[*sqlstore.OneTimeStore]

	cases := []testCase{
		{name: "a handle is all it needs", db: db, assert: accepted},
		{name: "it honours a clock, for its reaper", db: db, opts: []sqlstore.Option{sqlstore.WithClock(time.Now)}, assert: accepted},
		{name: "a missing handle is refused", assert: refused("the database handle is nil")},
		{
			name:   "an id generator does not apply to tokens, which carry their own",
			db:     db,
			opts:   []sqlstore.Option{sqlstore.WithIDGenerator(id.NewV7Generator())},
			assert: refused("WithIDGenerator does not apply to this store"),
		},
		{
			name:   "re-sealing does not apply to tokens",
			db:     db,
			opts:   []sqlstore.Option{sqlstore.WithResealOnRead(false)},
			assert: refused("WithResealOnRead does not apply to this store"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s, err := sqlstore.NewOneTimeStore(tc.db, tc.opts...)
			tc.assert(t, s, err)
		})
	}
}
