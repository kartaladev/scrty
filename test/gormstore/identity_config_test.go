package gormstore_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	gormdb "gorm.io/gorm"

	gormstore "github.com/kartaladev/scrty/gorm"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/test/internal/storefix"
)

// TestIdentityStore_ConsumerGormConfig pins that the identity store keeps its
// guarantees on a consumer's *gorm.DB opened with settings gorm leaves off
// by default: prepared statements, whose connection must not prepare the
// savepoint statements, and error translation, which replaces the driver's
// error before the store sees it.
func TestIdentityStore_ConsumerGormConfig(t *testing.T) {
	t.Parallel()

	d := migratedIdentityDB(t)

	// reissuing is a store on db whose generator mints one identifier for
	// every call, so a second provision collides on users.id: a real
	// primary-key violation, not the username decision.
	reissuing := func(t *testing.T, db *gormdb.DB) *gormstore.IdentityStore {
		t.Helper()
		reissued := storefix.NewID(t)

		return newIdentityStore(t, db,
			gormstore.WithIDGenerator(storefix.GeneratorFunc(func() (id.ID, error) { return reissued, nil })))
	}

	// cutFromDriver asserts err carries no driver error value and names none
	// of values.
	cutFromDriver := func(t *testing.T, err error, values ...string) {
		t.Helper()
		var pgErr *pgconn.PgError
		assert.False(t, errors.As(err, &pgErr), "the driver's error is reachable: %v", err)
		for _, text := range storefix.ErrorTexts(err) {
			for _, v := range values {
				assert.NotContains(t, text, v)
			}
		}
	}

	type testCase struct {
		name   string
		config gormdb.Config
		// run makes the store's calls on db, a handle opened with config
		// that logs to rec.
		run func(t *testing.T, ctx context.Context, db *gormdb.DB, rec *recordingLogger)
	}

	cases := []testCase{
		{
			name:   "prepared statements: a failed provision is undone and no savepoint statement is prepared",
			config: gormdb.Config{PrepareStmt: true},
			run: func(t *testing.T, ctx context.Context, db *gormdb.DB, rec *recordingLogger) {
				tx := beginGorm(ctx, t, db)
				_, prepared := tx.Statement.ConnPool.(*gormdb.PreparedStmtTX)
				require.True(t, prepared, "the caller's transaction does not run on gorm's prepared-statement connection")
				txCtx := gormstore.WithTx(ctx, tx)

				s := reissuing(t, db)
				_, err := s.Provision(txCtx, "prepared-kept-"+logCanary, identity.WithUserPassword([]byte(logCanary)))
				require.NoError(t, err)

				_, err = s.Provision(txCtx, "prepared-undone-"+logCanary, identity.WithUserPassword([]byte(logCanary)))
				require.Error(t, err)
				cutFromDriver(t, err, logCanary)

				_, err = s.Update(txCtx, "prepared-kept-"+logCanary, identity.WithUserName("Renamed"))
				require.NoError(t, err, "the failed provision left the caller's transaction unusable")

				assert.Empty(t, rec.recorded(), "an identity store operation reached the consumer's logger")

				var statements []string
				require.NoError(t, tx.Raw(`SELECT statement FROM pg_prepared_statements`).Scan(&statements).Error)
				for _, stmt := range statements {
					assert.NotContains(t, strings.ToUpper(stmt), "SAVEPOINT", "a savepoint statement was prepared")
				}

				require.NoError(t, tx.Commit().Error)
				assert.Equal(t, 1, userRowCount(ctx, t, d.conn.DB, "prepared-kept-"+logCanary))
				assert.Zero(t, userRowCount(ctx, t, d.conn.DB, "prepared-undone-"+logCanary),
					"the failed provision's row was committed with the caller's work")
			},
		},
		{
			name:   "translated errors: a taken username is still the username decision",
			config: gormdb.Config{TranslateError: true},
			run: func(t *testing.T, ctx context.Context, db *gormdb.DB, _ *recordingLogger) {
				s := newIdentityStore(t, db)
				_, err := s.Provision(ctx, "translated-taken")
				require.NoError(t, err)

				_, err = s.Provision(ctx, "translated-taken")
				require.ErrorIs(t, err, identity.ErrUserExists)
				cutFromDriver(t, err, "translated-taken")
				assert.Equal(t, "gorm: provision user: "+identity.ErrUserExists.Error(), err.Error(),
					"the collision's text is fixed library text")
			},
		},
		{
			name:   "translated errors: a colliding identifier is a database failure, cut from the driver",
			config: gormdb.Config{TranslateError: true},
			run: func(t *testing.T, ctx context.Context, db *gormdb.DB, _ *recordingLogger) {
				s := reissuing(t, db)
				_, err := s.Provision(ctx, "translated-first")
				require.NoError(t, err)

				_, err = s.Provision(ctx, "translated-collides")
				require.Error(t, err)
				assert.NotErrorIs(t, err, identity.ErrUserExists,
					"a colliding identifier is a database failure, not the username decision")
				cutFromDriver(t, err, "translated-collides")
				assert.Equal(t, "gorm: provision user: database failure (SQLSTATE 23505)", err.Error(),
					"neither gorm's translated text nor the driver's message is kept")
				assert.Zero(t, userRowCount(ctx, t, d.conn.DB, "translated-collides"))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rec := &recordingLogger{}
			cfg := tc.config
			cfg.Logger = rec
			cfg.DisableAutomaticPing = true
			db, err := gormdb.Open(postgres.Open(d.conn.DSN), &cfg)
			require.NoError(t, err)
			sqlDB, err := db.DB()
			require.NoError(t, err)
			t.Cleanup(func() { _ = sqlDB.Close() })

			tc.run(t, t.Context(), db, rec)
		})
	}
}
