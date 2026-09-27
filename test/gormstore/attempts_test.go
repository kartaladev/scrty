package gormstore_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gormdb "gorm.io/gorm"

	gormstore "github.com/kartaladev/scrty/gorm"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/test/internal/storefix"
	"github.com/kartaladev/scrty/test/storetest"
)

// The durable login-attempt store carries the reaper as well as the store.
var _ interface {
	policy.AttemptStore
	policy.AttemptReaper
} = (*gormstore.AttemptStore)(nil)

// newAttemptStore builds the login-attempt store over db, failing t on a
// refusal.
func newAttemptStore(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) *gormstore.AttemptStore {
	t.Helper()

	s, err := gormstore.NewAttemptStore(db, opts...)
	require.NoError(t, err)

	return s
}

func TestAttemptStore(t *testing.T) {
	t.Parallel()

	d := migratedDB(t)

	t.Run("gorm", func(t *testing.T) {
		storetest.RunAttemptStoreSuite(t, func(t *testing.T) policy.AttemptStore {
			return newAttemptStore(t, emptied(t, d, "login_attempts"))
		}, storetest.RequireReaper())
	})
}

func TestAttemptStore_IDs(t *testing.T) {
	t.Parallel()

	d := migratedDB(t)
	raw := d.conn.DB
	at := time.Date(2030, 1, 1, 10, 0, 0, 0, time.UTC)
	errGenerator := errors.New("generator exhausted")

	type testCase struct {
		name     string
		username string
		opts     []gormstore.Option
		assert   func(t *testing.T, err error, username string)
	}

	cases := []testCase{
		{
			name:     "with no generator configured the id is a version 7 uuid",
			username: "default-generator",
			assert: func(t *testing.T, err error, username string) {
				require.NoError(t, err)
				ids := storefix.AttemptIDs(t.Context(), t, raw, username)
				require.Len(t, ids, 1)
				assert.Equal(t, byte('7'), ids[0][14], "id %s is not version 7", ids[0])
			},
		},
		{
			name:     "a consumer generator's id is the one stored",
			username: "consumer-generator",
			opts: []gormstore.Option{gormstore.WithIDGenerator(storefix.GeneratorFunc(func() (id.ID, error) {
				return id.MustParse("00000000-0000-4000-8000-000000000001"), nil
			}))},
			assert: func(t *testing.T, err error, username string) {
				require.NoError(t, err)
				assert.Equal(t, []string{"00000000-0000-4000-8000-000000000001"}, storefix.AttemptIDs(t.Context(), t, raw, username))
			},
		},
		{
			name:     "a generator failure is returned wrapped, and nothing is written",
			username: "failing-generator",
			opts: []gormstore.Option{gormstore.WithIDGenerator(storefix.GeneratorFunc(func() (id.ID, error) {
				return id.Nil, errGenerator
			}))},
			assert: func(t *testing.T, err error, username string) {
				require.ErrorIs(t, err, errGenerator)
				assert.Empty(t, storefix.AttemptIDs(t.Context(), t, raw, username))
			},
		},
		{
			name:     "a username holding a NUL byte is refused without echoing it, never truncated",
			username: "a\x00b-canary-41",
			assert: func(t *testing.T, err error, _ string) {
				require.Error(t, err)
				assert.NotContains(t, err.Error(), "canary-41")
				assert.Empty(t, storefix.AttemptIDs(t.Context(), t, raw, "a"), "the username was truncated at the NUL byte")
			},
		},
		{
			name:     "a username holding invalid UTF-8 is refused without echoing it, never altered",
			username: "caf\xe9-canary-42",
			assert: func(t *testing.T, err error, _ string) {
				require.Error(t, err)
				assert.NotContains(t, err.Error(), "canary-42")
				assert.Empty(t, storefix.AttemptIDs(t.Context(), t, raw, "caf�-canary-42"), "the username was altered")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := newAttemptStore(t, d.db, tc.opts...).RecordFailure(t.Context(), tc.username, at)
			tc.assert(t, err, tc.username)
		})
	}
}

// TestAttemptStore_Refusals pins what the reaper refuses and how a failure is
// reported, on a store over one database.
func TestAttemptStore_Refusals(t *testing.T) {
	t.Parallel()

	d := migratedDB(t)
	s := newAttemptStore(t, d.db)

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
				require.ErrorIs(t, err, policy.ErrRetainSinceRequired)
				assert.Zero(t, n)
			},
		},
		{
			name: "a username PostgreSQL cannot hold is refused without aborting the caller's transaction",
			assert: func(t *testing.T, ctx context.Context) {
				tx := d.db.WithContext(ctx).Begin()
				require.NoError(t, tx.Error)
				t.Cleanup(func() { _ = tx.Rollback() })
				txCtx := gormstore.WithTx(ctx, tx)
				at := time.Date(2030, 1, 1, 10, 0, 0, 0, time.UTC)

				require.Error(t, s.RecordFailure(txCtx, "nul\x00canary", at))
				require.Error(t, s.RecordFailure(txCtx, "caf\xe9canary", at))
				require.NoError(t, s.RecordFailure(txCtx, "after-refusal", at),
					"the refusal aborted the caller's transaction")
				require.NoError(t, tx.Commit().Error)
				assert.Len(t, storefix.AttemptIDs(ctx, t, d.conn.DB, "after-refusal"), 1)
			},
		},
		{
			name: "a count under a cancelled context fails with the cancellation, never as zero",
			ctx:  storefix.Cancelled,
			assert: func(t *testing.T, ctx context.Context) {
				_, err := s.FailureCount(ctx, "alice", time.Time{})
				require.ErrorIs(t, err, context.Canceled)
				assert.ErrorContains(t, err, "gorm: count login failures")
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
		db     *gormdb.DB
		opts   []gormstore.Option
		assert func(t *testing.T, s *gormstore.AttemptStore, err error)
	}

	refused := refusedConfig[*gormstore.AttemptStore]
	accepted := storefix.AcceptedConfig[*gormstore.AttemptStore]

	cases := []testCase{
		{name: "a handle is all it needs", db: db, assert: accepted},
		{
			name:   "it honours an id generator",
			db:     db,
			opts:   []gormstore.Option{gormstore.WithIDGenerator(id.NewV7Generator())},
			assert: accepted,
		},
		{name: "a missing handle is refused", assert: refused("the database handle is nil")},
		{
			name:   "a clock does not apply to attempts, whose instants come from the caller",
			db:     db,
			opts:   []gormstore.Option{gormstore.WithClock(time.Now)},
			assert: refused("WithClock does not apply to this store"),
		},
		{
			name:   "re-sealing does not apply to attempts",
			db:     db,
			opts:   []gormstore.Option{gormstore.WithResealOnRead(false)},
			assert: refused("WithResealOnRead does not apply to this store"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s, err := gormstore.NewAttemptStore(tc.db, tc.opts...)
			tc.assert(t, s, err)
		})
	}
}
