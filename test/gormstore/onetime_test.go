package gormstore_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gormdb "gorm.io/gorm"

	gormstore "github.com/kartaladev/scrty/gorm"
	"github.com/kartaladev/scrty/onetime"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/test/storetest"
)

// The durable one-time token store carries the reaper as well as the store.
var _ interface {
	onetime.Store
	onetime.Reaper
} = (*gormstore.OneTimeStore)(nil)

// newOneTimeStore builds the one-time token store over db, failing t on a
// refusal.
func newOneTimeStore(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) *gormstore.OneTimeStore {
	t.Helper()

	s, err := gormstore.NewOneTimeStore(db, opts...)
	require.NoError(t, err)

	return s
}

// raceToken is the i-th token a race seeds, unspent and valid for an hour.
func raceToken(i int) onetime.Token {
	secret := sha256.Sum256(fmt.Appendf(nil, "secret-%d", i))
	issued := time.Date(2030, 1, 1, 10, 0, 0, 0, time.UTC)

	return onetime.Token{
		ID:         id.MustParse(fmt.Sprintf("01926a4e-0000-7000-8000-%012x", 0x100000+i)),
		Purpose:    "race",
		Subject:    fmt.Sprintf("subject-%d", i),
		SecretHash: secret[:],
		IssuedAt:   issued,
		ExpiresAt:  issued.Add(time.Hour),
	}
}

// consumeRace is the race over consume, of any store that consumes like the
// one-time token store: Seed inserts token i through s, and Attempt consumes
// it, the refusal mapped to (false, nil).
func consumeRace[S onetime.Store]() storetest.Race[S] {
	return storetest.Race[S]{
		Seed: func(ctx context.Context, t *testing.T, s S, i int) string {
			tok := raceToken(i)
			require.NoError(t, s.Insert(ctx, tok))
			return tok.ID.String()
		},
		Attempt: func(ctx context.Context, s S, key string, _ int) (bool, error) {
			err := s.Consume(ctx, id.MustParse(key), time.Now())
			if errors.Is(err, onetime.ErrTokenNotFound) {
				return false, nil
			}
			return err == nil, err
		},
	}
}

func TestOneTimeStore(t *testing.T) {
	t.Parallel()

	d := migratedDB(t)

	t.Run("gorm", func(t *testing.T) {
		storetest.RunOneTimeStoreSuite(t, func(t *testing.T, now func() time.Time) onetime.Store {
			return newOneTimeStore(t, emptied(t, d, "one_time_tokens"), gormstore.WithClock(now))
		}, storetest.RequireReaper())
	})
}

func TestOneTimeStore_ConsumeRace(t *testing.T) {
	t.Parallel()

	h := durableHarness(migratedDB(t), func(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) *gormstore.OneTimeStore {
		return newOneTimeStore(t, db, opts...)
	})

	t.Run("gorm", func(t *testing.T) {
		storetest.RunConsumeRace(t, h, consumeRace[*gormstore.OneTimeStore]())
	})
}

func TestOneTimeStore_Failures(t *testing.T) {
	t.Parallel()

	d := migratedDB(t)

	type testCase struct {
		name string
		// db returns the handle the store is built on.
		db     func(t *testing.T, d database) *gormdb.DB
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, ctx context.Context, s *gormstore.OneTimeStore)
	}

	shared := func(_ *testing.T, d database) *gormdb.DB { return d.db }

	cases := []testCase{
		{
			name: "consumption fails, and is not the refusal, when the database is unavailable",
			db: func(t *testing.T, d database) *gormdb.DB {
				db := openGorm(t, d.conn.DSN)
				sqlDB, err := db.DB()
				require.NoError(t, err)
				require.NoError(t, sqlDB.Close())
				return db
			},
			assert: func(t *testing.T, ctx context.Context, s *gormstore.OneTimeStore) {
				err := s.Consume(ctx, raceToken(1).ID, time.Now())
				require.Error(t, err)
				assert.NotErrorIs(t, err, onetime.ErrTokenNotFound)
				// A closed *sql.DB under gorm reports database/sql's own
				// unexported error.
				assert.ErrorContains(t, err, "sql: database is closed")
				assert.ErrorContains(t, err, "gorm: consume one-time token")
			},
		},
		{
			name: "consumption fails, and is not the refusal, when the server cannot be reached",
			db: func(t *testing.T, _ database) *gormdb.DB {
				return unreachableDB(t)
			},
			assert: func(t *testing.T, ctx context.Context, s *gormstore.OneTimeStore) {
				err := s.Consume(ctx, raceToken(1).ID, time.Now())
				require.Error(t, err)
				assert.NotErrorIs(t, err, onetime.ErrTokenNotFound)
				assert.ErrorContains(t, err, "gorm: consume one-time token")
			},
		},
		{
			name: "a consume under a cancelled context fails with the cancellation, never as not found",
			db:   shared,
			ctx:  cancelled,
			assert: func(t *testing.T, ctx context.Context, s *gormstore.OneTimeStore) {
				err := s.Consume(ctx, raceToken(2).ID, time.Now())
				require.ErrorIs(t, err, context.Canceled)
				assert.NotErrorIs(t, err, onetime.ErrTokenNotFound)
			},
		},
		{
			name: "an unbound token's binding is stored NULL, and an empty one empty",
			db:   shared,
			assert: func(t *testing.T, ctx context.Context, s *gormstore.OneTimeStore) {
				unbound, empty := raceToken(4), raceToken(5)
				unbound.BindingHash, empty.BindingHash = nil, []byte{}
				require.NoError(t, s.Insert(ctx, unbound))
				require.NoError(t, s.Insert(ctx, empty))

				isNull := func(tok onetime.Token) bool {
					var null bool
					require.NoError(t, d.conn.DB.QueryRowContext(ctx,
						`SELECT binding_hash IS NULL FROM one_time_tokens WHERE id = $1`, tok.ID).Scan(&null))
					return null
				}
				assert.True(t, isNull(unbound), "an unbound token's binding is not NULL")
				assert.False(t, isNull(empty), "an empty binding is stored as NULL")
			},
		},
		{
			name: "stored times are truncated to the microsecond",
			db:   shared,
			assert: func(t *testing.T, ctx context.Context, s *gormstore.OneTimeStore) {
				tok := raceToken(3)
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

			tc.assert(t, ctx, newOneTimeStore(t, tc.db(t, d)))
		})
	}
}

func TestNewOneTimeStore(t *testing.T) {
	t.Parallel()

	db := unreachableDB(t)

	type testCase struct {
		name   string
		db     *gormdb.DB
		opts   []gormstore.Option
		assert func(t *testing.T, s *gormstore.OneTimeStore, err error)
	}

	refused := refusedConfig[*gormstore.OneTimeStore]
	accepted := acceptedConfig[*gormstore.OneTimeStore]

	cases := []testCase{
		{name: "a handle is all it needs", db: db, assert: accepted},
		{name: "it honours a clock, for its reaper", db: db, opts: []gormstore.Option{gormstore.WithClock(time.Now)}, assert: accepted},
		{name: "a missing handle is refused", assert: refused("the database handle is nil")},
		{
			name:   "an id generator does not apply to tokens, which carry their own",
			db:     db,
			opts:   []gormstore.Option{gormstore.WithIDGenerator(id.NewV7Generator())},
			assert: refused("WithIDGenerator does not apply to this store"),
		},
		{
			name:   "re-sealing does not apply to tokens",
			db:     db,
			opts:   []gormstore.Option{gormstore.WithResealOnRead(false)},
			assert: refused("WithResealOnRead does not apply to this store"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s, err := gormstore.NewOneTimeStore(tc.db, tc.opts...)
			tc.assert(t, s, err)
		})
	}
}
