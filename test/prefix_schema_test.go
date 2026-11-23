package test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	gormdb "gorm.io/gorm"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/store/gormstore"
	"github.com/kartaladev/scrty/store/migrate"
	"github.com/kartaladev/scrty/store/pgxstore"
	"github.com/kartaladev/scrty/store/seal"
	"github.com/kartaladev/scrty/store/sqlstore"
	"github.com/kartaladev/scrty/test/internal/storefix"
)

// consumerSchemaHandles are handles on one database, each opened with the
// search_path a consumer's connection string would carry.
type consumerSchemaHandles struct {
	admin *sql.DB // the helper's handle, on the default schema
	sql   *sql.DB
	pool  *pgxpool.Pool
	gorm  *gormdb.DB
}

// openOnSearchPath opens a database/sql, pgx and gorm handle on dsn, each
// resolving unqualified names through searchPath.
func openOnSearchPath(t *testing.T, dsn, searchPath string) (*sql.DB, *pgxpool.Pool, *gormdb.DB) {
	t.Helper()

	open := func() *sql.DB {
		cfg, err := pgx.ParseConfig(dsn)
		require.NoError(t, err)
		cfg.RuntimeParams["search_path"] = searchPath
		db := stdlib.OpenDB(*cfg)
		t.Cleanup(func() { _ = db.Close() })
		return db
	}

	pcfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	pcfg.ConnConfig.RuntimeParams["search_path"] = searchPath
	pool, err := pgxpool.NewWithConfig(t.Context(), pcfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	g, err := gormdb.Open(postgres.New(postgres.Config{Conn: open()}), &gormdb.Config{DisableAutomaticPing: true})
	require.NoError(t, err)

	return open(), pool, g
}

// roundTrip writes one session through each of the three session stores and
// loads the identity seeded as userID through each of the three identity
// stores, and calls Verify on both limiter factories. It returns the first
// failure of each step, named.
func (h consumerSchemaHandles) roundTrip(t *testing.T, sid string) map[string]error {
	t.Helper()

	ctx := t.Context()
	now := time.Now()
	cipher := storefix.CipherOf(t, seal.WithKeyringEncryptionKey("k1", storefix.SealKey(t)))
	out := map[string]error{}

	sqlSessions, err := sqlstore.NewSessionStore(h.sql, cipher)
	require.NoError(t, err)
	pgxSessions, err := pgxstore.NewSessionStore(h.pool, cipher)
	require.NoError(t, err)
	gormSessions, err := gormstore.NewSessionStore(h.gorm, cipher)
	require.NoError(t, err)
	for name, s := range map[string]session.Store{"sql session": sqlSessions, "pgx session": pgxSessions, "gorm session": gormSessions} {
		id := sid + "-" + name[:3]
		if err := s.Create(ctx, storefix.DurableSession(id, now)); err != nil {
			out[name] = err
			continue
		}
		_, out[name] = s.Load(ctx, id)
	}

	sqlIdentity, err := sqlstore.NewIdentityStore(h.sql)
	require.NoError(t, err)
	pgxIdentity, err := pgxstore.NewIdentityStore(h.pool)
	require.NoError(t, err)
	gormIdentity, err := gormstore.NewIdentityStore(h.gorm)
	require.NoError(t, err)
	for name, s := range map[string]interface {
		LoadByUsername(context.Context, string) (*identity.Details, error)
	}{"sql identity": sqlIdentity, "pgx identity": pgxIdentity, "gorm identity": gormIdentity} {
		d, err := s.LoadByUsername(ctx, "alice")
		if err == nil && d == nil {
			err = assert.AnError
		}
		out[name] = err
	}

	sqlLimiter, err := sqlstore.NewLimiterFactory(h.sql)
	require.NoError(t, err)
	out["sql limiter"] = sqlLimiter.Verify(ctx)
	pgxLimiter, err := pgxstore.NewLimiterFactory(h.pool)
	require.NoError(t, err)
	out["pgx limiter"] = pgxLimiter.Verify(ctx)

	return out
}

// TestPrefix_ConsumerSchema pins that a consumer who isolates scrty in a
// PostgreSQL schema, through search_path, gets working stores and limiters,
// and that its own tables named sessions or users, created beside scrty's,
// neither collide with them nor receive a row.
func TestPrefix_ConsumerSchema(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name       string
		searchPath string
		assert     func(t *testing.T, h consumerSchemaHandles)
	}

	cases := []testCase{
		{
			name:       "a schema holding the migrated tables serves every store and limiter",
			searchPath: "auth",
			assert: func(t *testing.T, h consumerSchemaHandles) {
				for name, err := range h.roundTrip(t, "s1") {
					assert.NoError(t, err, name)
				}

				// The consumer's own tables take the unprefixed names.
				for _, ddl := range []string{`CREATE TABLE auth.sessions (id int PRIMARY KEY)`, `CREATE TABLE auth.users (id int PRIMARY KEY)`} {
					_, err := h.admin.ExecContext(t.Context(), ddl)
					require.NoError(t, err, ddl)
				}

				for name, err := range h.roundTrip(t, "s2") {
					assert.NoError(t, err, name)
				}
				for _, table := range []string{"auth.sessions", "auth.users"} {
					assert.Zero(t, queryCount(t, h.admin, `SELECT count(*) FROM `+table), "%s stays empty", table)
				}
				assert.Equal(t, 6, queryCount(t, h.admin, `SELECT count(*) FROM auth.scrty_sessions`),
					"the stores wrote to the prefixed table")
			},
		},
		{
			name:       "a connection that does not reach the schema is refused by both limiter factories",
			searchPath: "public",
			assert: func(t *testing.T, h consumerSchemaHandles) {
				got := h.roundTrip(t, "s3")
				for _, name := range []string{"sql limiter", "pgx limiter"} {
					require.ErrorIs(t, got[name], ratelimit.ErrConfig, name)
					assert.ErrorContains(t, got[name], "scrty_rate_limit_buckets", name)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			conn := RunTestPostgres(t)
			ctx := t.Context()
			_, err := conn.DB.ExecContext(ctx, `CREATE SCHEMA auth`)
			require.NoError(t, err)
			t.Cleanup(func() {
				_, _ = conn.DB.ExecContext(context.WithoutCancel(ctx), `DROP SCHEMA auth CASCADE`)
			})

			authDB, _, _ := openOnSearchPath(t, conn.DSN, "auth")
			for _, set := range []migrate.Set{migrate.SecurityState(), migrate.Identity()} {
				p := provider(t, authDB, set.FS(), set.Dir, set.VersionTable)
				_, err := p.Up(ctx)
				require.NoError(t, err)
			}
			_, err = authDB.ExecContext(ctx, `INSERT INTO scrty_users (id, username, password, created_at, updated_at)
				VALUES ('11111111-1111-4111-8111-111111111111', 'alice', 'hash', now(), now())`)
			require.NoError(t, err)

			db, pool, g := openOnSearchPath(t, conn.DSN, tc.searchPath)
			tc.assert(t, consumerSchemaHandles{admin: conn.DB, sql: db, pool: pool, gorm: g})
		})
	}
}

// TestLimiterVerify_RefusesUnrenamedSchema pins that a binary built for the
// prefixed schema refuses, when its limiter factory is built, a database whose
// security-state set stops short of the rename. The error is a configuration
// error naming the table it could not find, so the operator sees which
// migration is missing.
func TestLimiterVerify_RefusesUnrenamedSchema(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		verify func(t *testing.T, conn PostgresConn) error
	}

	cases := []testCase{
		{
			name: "sqlstore",
			verify: func(t *testing.T, conn PostgresConn) error {
				f, err := sqlstore.NewLimiterFactory(conn.DB)
				require.NoError(t, err)
				return f.Verify(t.Context())
			},
		},
		{
			name: "pgxstore",
			verify: func(t *testing.T, conn PostgresConn) error {
				pool, err := pgxpool.New(t.Context(), conn.DSN)
				require.NoError(t, err)
				t.Cleanup(pool.Close)
				f, err := pgxstore.NewLimiterFactory(pool)
				require.NoError(t, err)
				return f.Verify(t.Context())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			set := migrate.SecurityState()
			conn := RunTestPostgres(t)
			p := provider(t, conn.DB, set.FS(), set.Dir, set.VersionTable)
			rollBackAtCleanup(t, conn.DB, p, set.VersionTable)
			_, err := p.UpTo(t.Context(), versionSecurityStateLast)
			require.NoError(t, err)

			err = tc.verify(t, conn)
			require.ErrorIs(t, err, ratelimit.ErrConfig)
			assert.ErrorContains(t, err, "scrty_rate_limit_buckets")
		})
	}
}
