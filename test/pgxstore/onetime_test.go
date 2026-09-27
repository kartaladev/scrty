package pgxstore_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/onetime"
	pgxstore "github.com/kartaladev/scrty/pgx"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/test/storetest"
)

// The durable one-time token store carries the reaper as well as the store.
var _ interface {
	onetime.Store
	onetime.Reaper
} = (*pgxstore.OneTimeStore)(nil)

// newOneTimeStore builds the one-time token store over pool, failing t on a
// refusal.
func newOneTimeStore(t *testing.T, pool *pgxpool.Pool, opts ...pgxstore.Option) *pgxstore.OneTimeStore {
	t.Helper()

	s, err := pgxstore.NewOneTimeStore(pool, opts...)
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

	db := migrated(t)

	t.Run("pgx", func(t *testing.T) {
		storetest.RunOneTimeStoreSuite(t, func(t *testing.T, now func() time.Time) onetime.Store {
			return newOneTimeStore(t, emptied(t, db, "one_time_tokens"), pgxstore.WithClock(now))
		}, storetest.RequireReaper())
	})
}

func TestOneTimeStore_ConsumeRace(t *testing.T) {
	t.Parallel()

	h := durableHarness(migrated(t), func(t *testing.T, pool *pgxpool.Pool, opts ...pgxstore.Option) *pgxstore.OneTimeStore {
		return newOneTimeStore(t, pool, opts...)
	})

	t.Run("pgx", func(t *testing.T) {
		storetest.RunConsumeRace(t, h, consumeRace[*pgxstore.OneTimeStore]())
	})
}

func TestOneTimeStore_Failures(t *testing.T) {
	t.Parallel()

	db := migrated(t)

	type testCase struct {
		name string
		// pool returns the pool the store is built on.
		pool   func(t *testing.T, db database) *pgxpool.Pool
		opts   []pgxstore.Option
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, ctx context.Context, s *pgxstore.OneTimeStore)
	}

	shared := func(_ *testing.T, db database) *pgxpool.Pool { return db.Pool }

	cases := []testCase{
		{
			name: "consumption fails, and is not the refusal, when the database is unavailable",
			pool: func(t *testing.T, db database) *pgxpool.Pool {
				pool := openPool(t, db.DSN)
				pool.Close()
				return pool
			},
			assert: func(t *testing.T, ctx context.Context, s *pgxstore.OneTimeStore) {
				err := s.Consume(ctx, raceToken(1).ID, time.Now())
				require.Error(t, err)
				assert.NotErrorIs(t, err, onetime.ErrTokenNotFound)
				assert.ErrorContains(t, err, "closed pool")
				assert.ErrorContains(t, err, "pgx: consume one-time token")
			},
		},
		{
			name: "consumption fails, and is not the refusal, when the server cannot be reached",
			pool: func(t *testing.T, _ database) *pgxpool.Pool {
				return unreachablePool(t)
			},
			assert: func(t *testing.T, ctx context.Context, s *pgxstore.OneTimeStore) {
				err := s.Consume(ctx, raceToken(1).ID, time.Now())
				require.Error(t, err)
				assert.NotErrorIs(t, err, onetime.ErrTokenNotFound)
				assert.ErrorContains(t, err, "pgx: consume one-time token")
			},
		},
		{
			name: "a consume under a cancelled context fails with the cancellation, never as not found",
			pool: shared,
			ctx:  cancelled,
			assert: func(t *testing.T, ctx context.Context, s *pgxstore.OneTimeStore) {
				err := s.Consume(ctx, raceToken(2).ID, time.Now())
				require.ErrorIs(t, err, context.Canceled)
				assert.NotErrorIs(t, err, onetime.ErrTokenNotFound)
			},
		},
		{
			name: "a find under a cancelled context fails with the cancellation, never as not found",
			pool: shared,
			ctx:  cancelled,
			assert: func(t *testing.T, ctx context.Context, s *pgxstore.OneTimeStore) {
				_, err := s.FindByID(ctx, raceToken(2).ID)
				require.ErrorIs(t, err, context.Canceled)
				assert.NotErrorIs(t, err, onetime.ErrTokenNotFound)
			},
		},
		{
			name: "a resolver reporting a nil transaction fails the consume, and is not the refusal",
			pool: shared,
			opts: []pgxstore.Option{pgxstore.WithTxResolver(func(context.Context) (pgx.Tx, bool) { return nil, true })},
			assert: func(t *testing.T, ctx context.Context, s *pgxstore.OneTimeStore) {
				err := s.Consume(ctx, raceToken(4).ID, time.Now())
				require.ErrorIs(t, err, pgxstore.ErrNilTransaction)
				assert.NotErrorIs(t, err, onetime.ErrTokenNotFound)
				assert.ErrorContains(t, err, "pgx: consume one-time token")
			},
		},
		{
			name: "a token whose consumption time is infinite is an error, never unspent",
			pool: shared,
			assert: func(t *testing.T, ctx context.Context, s *pgxstore.OneTimeStore) {
				tok := raceToken(5)
				require.NoError(t, s.Insert(ctx, tok))
				_, err := db.DB.ExecContext(ctx,
					`UPDATE one_time_tokens SET consumed_at = 'infinity' WHERE id = $1`, tok.ID.String())
				require.NoError(t, err)

				got, err := s.FindByID(ctx, tok.ID)
				require.Error(t, err, "an infinite consumption time read as %v", got)
				assert.NotErrorIs(t, err, onetime.ErrTokenNotFound)
				assert.Nil(t, got)
			},
		},
		{
			name: "stored times are truncated to the microsecond",
			pool: shared,
			assert: func(t *testing.T, ctx context.Context, s *pgxstore.OneTimeStore) {
				tok := raceToken(3)
				tok.IssuedAt = time.Date(2026, 9, 15, 10, 0, 0, 123456789, time.UTC)
				tok.ExpiresAt = tok.IssuedAt.Add(time.Hour)
				require.NoError(t, s.Insert(ctx, tok))

				got, err := s.FindByID(ctx, tok.ID)
				require.NoError(t, err)
				want := time.Date(2026, 9, 15, 10, 0, 0, 123456000, time.UTC)
				assert.True(t, want.Equal(got.IssuedAt), "issued at %v, want %v", got.IssuedAt, want)
				assert.True(t, want.Add(time.Hour).Equal(got.ExpiresAt), "expires at %v", got.ExpiresAt)
				assert.Equal(t, time.UTC, got.IssuedAt.Location(), "stored times come back in UTC")
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

			tc.assert(t, ctx, newOneTimeStore(t, tc.pool(t, db), tc.opts...))
		})
	}
}

func TestNewOneTimeStore(t *testing.T) {
	t.Parallel()

	pool := unreachablePool(t)

	type testCase struct {
		name   string
		pool   *pgxpool.Pool
		opts   []pgxstore.Option
		assert func(t *testing.T, s *pgxstore.OneTimeStore, err error)
	}

	refused := refusedConfig[*pgxstore.OneTimeStore]
	accepted := acceptedConfig[*pgxstore.OneTimeStore]

	cases := []testCase{
		{name: "a pool is all it needs", pool: pool, assert: accepted},
		{
			name:   "it honours a clock, for its reaper",
			pool:   pool,
			opts:   []pgxstore.Option{pgxstore.WithClock(time.Now)},
			assert: accepted,
		},
		{name: "a missing pool is refused", assert: refused("the pool is nil")},
		{name: "a nil option is refused", pool: pool, opts: []pgxstore.Option{nil}, assert: refused("an option is nil")},
		{
			name:   "a nil clock is refused",
			pool:   pool,
			opts:   []pgxstore.Option{pgxstore.WithClock(nil)},
			assert: refused("the clock is nil"),
		},
		{
			name:   "an id generator does not apply to tokens, which carry their own",
			pool:   pool,
			opts:   []pgxstore.Option{pgxstore.WithIDGenerator(id.NewV7Generator())},
			assert: refused("WithIDGenerator does not apply to this store"),
		},
		{
			name:   "re-sealing does not apply to tokens",
			pool:   pool,
			opts:   []pgxstore.Option{pgxstore.WithResealOnRead(false)},
			assert: refused("WithResealOnRead does not apply to this store"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s, err := pgxstore.NewOneTimeStore(tc.pool, tc.opts...)
			tc.assert(t, s, err)
		})
	}
}
