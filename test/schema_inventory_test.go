package test

import (
	"context"
	"database/sql"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/store/migrate"
)

// Versions of the migrations that rename every table to its scrty_ name, and
// of the last migration each set holds before that rename.
const (
	versionScrtyPrefix        int64 = 20261124000000
	versionSecurityStateLast  int64 = 20261122000000
	versionIdentityBeforeName int64 = 20260928000000
)

// securityStateCountAtPrefix is how many security-state migrations are applied
// once the rename is: the count the rename's own tests expect, whatever
// migrations follow it.
const securityStateCountAtPrefix = 7

// scrtyPrefix is the fixed prefix of every relation scrty's migrations
// create.
const scrtyPrefix = "scrty_"

// postgresNameLimit is PostgreSQL's identifier limit in bytes; a longer name
// is silently truncated by the server.
const postgresNameLimit = 63

// Postgres images the catalog is checked on, the two the project's CI runs.
const (
	postgres15Image = "postgres:15.19-alpine"
	postgres18Image = "postgres:18.6-alpine"
)

// relationInventory lists the relations a migration set owns in the current
// schema, each sorted: ordinary tables, every index (including the ones that
// back a primary key or a unique constraint, whose constraint is renamed with
// them), and sequences. A nil slice means none.
type relationInventory struct {
	Tables    []string
	Indexes   []string
	Sequences []string
}

// securityStateInventory is what the security-state set creates, before the
// scrty_ rename. It excludes the version table and the version table's own
// index and sequence.
var securityStateInventory = relationInventory{
	Tables: []string{
		"account_recoveries",
		"api_keys",
		"login_attempts",
		"login_failure_streaks",
		"mfa_enrolments",
		"oidc_flows",
		"oidc_handoffs",
		"oidc_links",
		"one_time_tokens",
		"op_access_tokens",
		"op_authorization_codes",
		"op_browser_sessions",
		"op_client_assertions",
		"op_clients",
		"op_consents",
		"op_device_authorizations",
		"op_grants",
		"op_pending_requests",
		"op_refresh_tokens",
		"passkey_credentials",
		"passkey_user_handles",
		"rate_limit_buckets",
		"recovery_codes",
		"sessions",
		"signing_keys",
	},
	Indexes: []string{
		"account_recoveries_pkey",
		"account_recoveries_user",
		"api_keys_pkey",
		"api_keys_user",
		"login_attempts_pkey",
		"login_attempts_time",
		"login_attempts_username",
		"login_failure_streaks_inactive",
		"login_failure_streaks_pkey",
		"login_failure_streaks_username_key",
		"mfa_enrolments_pkey",
		"mfa_enrolments_user_id_key",
		"oidc_flows_expiry",
		"oidc_flows_handle_key",
		"oidc_flows_pkey",
		"oidc_handoffs_expiry",
		"oidc_handoffs_pkey",
		"oidc_handoffs_token_id_key",
		"oidc_links_pkey",
		"oidc_links_provider_issuer_subject_key",
		"oidc_links_user",
		"one_time_tokens_expiry",
		"one_time_tokens_pkey",
		"one_time_tokens_subject",
		"op_access_tokens_expiry",
		"op_access_tokens_pkey",
		"op_authorization_codes_expiry",
		"op_authorization_codes_external_session",
		"op_authorization_codes_pkey",
		"op_authorization_codes_sign_in",
		"op_authorization_codes_user_client",
		"op_authorization_codes_user_issuer",
		"op_browser_sessions_absolute_expiry",
		"op_browser_sessions_digest_key",
		"op_browser_sessions_external_session",
		"op_browser_sessions_idle_expiry",
		"op_browser_sessions_pkey",
		"op_browser_sessions_sign_in",
		"op_browser_sessions_user_issuer",
		"op_client_assertions_client_id_jti_key",
		"op_client_assertions_expiry",
		"op_client_assertions_pkey",
		"op_clients_client_id_key",
		"op_clients_pkey",
		"op_consents_pkey",
		"op_consents_user_ref_client_id_key",
		"op_device_authorizations_device_code_digest_key",
		"op_device_authorizations_expiry",
		"op_device_authorizations_external_session",
		"op_device_authorizations_pkey",
		"op_device_authorizations_sign_in",
		"op_device_authorizations_user_client",
		"op_device_authorizations_user_code_digest_key",
		"op_device_authorizations_user_issuer",
		"op_grants_expiry",
		"op_grants_external_session",
		"op_grants_pkey",
		"op_grants_revoked",
		"op_grants_sign_in",
		"op_grants_user",
		"op_grants_user_client",
		"op_grants_user_issuer",
		"op_pending_requests_expiry",
		"op_pending_requests_handle_digest_key",
		"op_pending_requests_pkey",
		"op_refresh_tokens_absolute_expiry",
		"op_refresh_tokens_external_session",
		"op_refresh_tokens_family",
		"op_refresh_tokens_id_digest_key",
		"op_refresh_tokens_idle_expiry",
		"op_refresh_tokens_pkey",
		"op_refresh_tokens_user",
		"op_refresh_tokens_user_issuer",
		"passkey_credentials_credential_id_key",
		"passkey_credentials_pkey",
		"passkey_credentials_user_id_idx",
		"passkey_user_handles_handle_key",
		"passkey_user_handles_pkey",
		"passkey_user_handles_user_id_key",
		"rate_limit_buckets_pkey",
		"recovery_codes_pkey",
		"recovery_codes_user_id_code_hash_key",
		"sessions_absolute_expiry",
		"sessions_external_session",
		"sessions_family",
		"sessions_id_digest_key",
		"sessions_idle_expiry",
		"sessions_pkey",
		"sessions_user",
		"sessions_user_issuer",
		"signing_keys_kid_key",
		"signing_keys_pkey",
	},
}

// identityInventory is what the identity set creates, before the scrty_
// rename, with the sequence behind password_history's serial column.
var identityInventory = relationInventory{
	Tables: []string{
		"assigned_roles",
		"groups",
		"organizations",
		"password_history",
		"resource_privileges",
		"roles",
		"users",
	},
	Indexes: []string{
		"assigned_roles_pkey",
		"assigned_roles_user_id",
		"groups_pkey",
		"organizations_pkey",
		"password_history_pkey",
		"password_history_user_seq",
		"resource_privileges_pkey",
		"resource_privileges_role_name",
		"roles_name_key",
		"roles_pkey",
		"users_pkey",
		"users_username_key",
	},
	Sequences: []string{"password_history_seq_seq"},
}

// prefixed maps every name in inv to its scrty_ name.
func prefixed(inv relationInventory) relationInventory {
	add := func(names []string) []string {
		if names == nil {
			return nil
		}
		out := make([]string, len(names))
		for i, n := range names {
			out[i] = scrtyPrefix + n
		}
		return out
	}
	return relationInventory{Tables: add(inv.Tables), Indexes: add(inv.Indexes), Sequences: add(inv.Sequences)}
}

// catalogRelations lists the current schema's tables, indexes and sequences,
// each sorted, leaving out goose's version tables and what they own: those
// are named by the consumer and never renamed.
func catalogRelations(t *testing.T, db *sql.DB) relationInventory {
	t.Helper()

	list := func(kind string) []string {
		rows := queryStrings(t, db, `SELECT c.relname FROM pg_class c
			WHERE c.relnamespace = current_schema()::regnamespace
			  AND c.relkind = $1
			  AND c.relname NOT LIKE 'goose\_%'
			ORDER BY c.relname COLLATE "C"`, kind)
		if len(rows) == 0 {
			return nil
		}
		return rows
	}
	return relationInventory{Tables: list("r"), Indexes: list("i"), Sequences: list("S")}
}

// catalogSnapshot renders the current schema's tables, columns, indexes,
// constraints and sequences as sorted lines, version tables excluded. Two
// snapshots are equal exactly when the catalogs are the same under every name.
func catalogSnapshot(t *testing.T, db *sql.DB) []string {
	t.Helper()

	var out []string
	for _, q := range []struct{ label, query string }{
		{"table", `SELECT relname FROM pg_class
			WHERE relnamespace = current_schema()::regnamespace AND relkind = 'r' AND relname NOT LIKE 'goose\_%'`},
		{"column", `SELECT table_name || '.' || column_name || ' ' || data_type || ' ' || is_nullable || ' '
				|| coalesce(column_default, '')
			FROM information_schema.columns
			WHERE table_schema = current_schema() AND table_name NOT LIKE 'goose\_%'`},
		{"index", `SELECT indexname || ' ' || indexdef FROM pg_indexes
			WHERE schemaname = current_schema() AND tablename NOT LIKE 'goose\_%'`},
		{"constraint", `SELECT conrelid::regclass::text || ' ' || conname || ' ' || pg_get_constraintdef(oid)
			FROM pg_constraint
			WHERE connamespace = current_schema()::regnamespace AND conrelid::regclass::text NOT LIKE 'goose\_%'`},
		{"sequence", `SELECT relname FROM pg_class
			WHERE relnamespace = current_schema()::regnamespace AND relkind = 'S' AND relname NOT LIKE 'goose\_%'`},
	} {
		for _, line := range queryStrings(t, db, q.query) {
			out = append(out, q.label+" "+line)
		}
	}
	slices.Sort(out)
	return out
}

// TestRelationInventory pins the relations each set creates before the scrty_
// rename, under both PostgreSQL images CI runs, so a name that differs by
// server version is caught here.
func TestRelationInventory(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name         string
		set          migrate.Set
		upTo         int64
		image        string
		versionTable string
		assert       func(t *testing.T, got relationInventory)
	}

	security := migrate.SecurityState()
	identity := migrate.Identity()

	cases := []testCase{}
	for _, image := range []string{postgres15Image, postgres18Image} {
		cases = append(cases,
			testCase{
				name: "security-state on " + image, set: security, upTo: versionSecurityStateLast, image: image,
				versionTable: migrate.SecurityStateVersionTable,
				assert: func(t *testing.T, got relationInventory) {
					assert.Equal(t, securityStateInventory, got)
					assert.Len(t, got.Tables, 25)
				},
			},
			testCase{
				name: "identity on " + image, set: identity, upTo: versionIdentityBeforeName, image: image,
				versionTable: migrate.IdentityVersionTable,
				assert: func(t *testing.T, got relationInventory) {
					assert.Equal(t, identityInventory, got)
					assert.Len(t, got.Tables, 7)
				},
			},
		)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			db := RunTestPostgres(t, WithTestPostgresImage(tc.image)).DB
			p := provider(t, db, tc.set.FS(), tc.set.Dir, tc.versionTable)
			_, err := p.UpTo(t.Context(), tc.upTo)
			require.NoError(t, err)

			tc.assert(t, catalogRelations(t, db))
		})
	}

	t.Run("inventories together hold 104 indexes", func(t *testing.T) {
		t.Parallel()

		// The counts below are a deliberate tripwire: they are hard-coded so that a
		// migration adding a table, index or sequence fails here until the inventory
		// and these numbers are updated together.
		assert.Len(t, securityStateInventory.Indexes, 92)
		assert.Len(t, identityInventory.Indexes, 12)
		assert.Len(t, securityStateInventory.Tables, 25)
		assert.Len(t, identityInventory.Tables, 7)
		for _, inv := range []relationInventory{securityStateInventory, identityInventory} {
			for _, n := range append(append(append([]string{}, inv.Tables...), inv.Indexes...), inv.Sequences...) {
				assert.LessOrEqual(t, len(scrtyPrefix+n), postgresNameLimit, n)
				assert.False(t, strings.HasPrefix(n, scrtyPrefix), "%s is already prefixed", n)
			}
		}
	})
}

// TestSecurityStatePrefix_Catalog pins the catalog the rename migration
// leaves: exactly the scrty_ names, none above the identifier limit, and the
// rename recorded in the version table. It stops at the rename's own version,
// so a later migration cannot change what it pins; a last step applies the rest
// of the set and pins the final inventory. It runs on both PostgreSQL images,
// because index and constraint names must not depend on the server version.
func TestSecurityStatePrefix_Catalog(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name  string
		image string
	}

	cases := []testCase{
		{name: "postgres 15", image: postgres15Image},
		{name: "postgres 18", image: postgres18Image},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			set := migrate.SecurityState()
			db := RunTestPostgres(t, WithTestPostgresImage(tc.image)).DB
			p := provider(t, db, set.FS(), set.Dir, set.VersionTable)
			rollBackAtCleanup(t, db, p, set.VersionTable)

			_, err := p.UpTo(t.Context(), versionScrtyPrefix)
			require.NoError(t, err)

			got := catalogRelations(t, db)
			assert.Equal(t, prefixed(securityStateInventory), got, "the catalog is exactly the prefixed inventory")

			for _, n := range append(append(append([]string{}, got.Tables...), got.Indexes...), got.Sequences...) {
				assert.LessOrEqual(t, len(n), postgresNameLimit, "%s must fit PostgreSQL's identifier limit", n)
			}

			assert.Equal(t, 1, queryCount(t, db, `SELECT count(*) FROM `+set.VersionTable+
				` WHERE is_applied AND version_id = 20261124000000`), "the rename is recorded as applied")
			assert.Equal(t, securityStateCountAtPrefix, appliedVersionCount(t, db, set.VersionTable))

			_, err = p.Up(t.Context())
			require.NoError(t, err)
			assert.Equal(t, prefixed(securityStateInventory), catalogRelations(t, db),
				"the migrations after the rename add no relation")
			assert.Equal(t, securityStateMigrationCount, appliedVersionCount(t, db, set.VersionTable))
		})
	}
}

// queryCount runs a single-integer query.
func queryCount(t *testing.T, db *sql.DB, query string, args ...any) int {
	t.Helper()

	var n int
	require.NoError(t, db.QueryRowContext(t.Context(), query, args...).Scan(&n))
	return n
}

// prefixNames returns names with the scrty_ prefix on each.
func prefixNames(names []string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = scrtyPrefix + n
	}
	return out
}

// TestSecurityStatePrefix_Failures pins what the rename does when it cannot
// run: a lock held on a table, and a name that is already taken. In every case
// the upgrade fails with an error naming the cause, nothing is renamed, no
// version is recorded, and the database still accepts the upgrade once the
// cause is gone.
//
// Each case sets up its obstacle differently, so each is a self-contained run
// over a database at the last version before the rename.
func TestSecurityStatePrefix_Failures(t *testing.T) {
	t.Parallel()

	set := migrate.SecurityState()

	// oldNames reports whether every inventory table still has its original
	// name and none has its prefixed one.
	oldNames := func(t *testing.T, db *sql.DB) {
		t.Helper()

		for _, table := range securityStateInventory.Tables {
			assert.True(t, regclassExists(t, db, table), "table %s keeps its name", table)
		}
	}
	noVersion := func(t *testing.T, db *sql.DB) {
		t.Helper()

		assert.Equal(t, 0, queryCount(t, db, `SELECT count(*) FROM `+set.VersionTable+
			` WHERE is_applied AND version_id = $1`, versionScrtyPrefix), "no version is recorded")
		assert.Equal(t, securityStateCountAtPrefix-1, appliedVersionCount(t, db, set.VersionTable))
	}

	type testCase struct {
		name string
		run  func(t *testing.T, db *sql.DB, p *goose.Provider)
	}

	cases := []testCase{
		{
			name: "a lock held on a table fails the upgrade within the bound, and a retry succeeds",
			run: func(t *testing.T, db *sql.DB, p *goose.Provider) {
				ctx := t.Context()

				// A reader mid-transaction holds ACCESS SHARE, which the rename's
				// ACCESS EXCLUSIVE lock waits behind.
				holder, err := db.BeginTx(ctx, nil)
				require.NoError(t, err)
				released := false
				release := func() {
					if !released {
						released = true
						_ = holder.Rollback()
					}
				}
				t.Cleanup(release)
				_, err = holder.ExecContext(ctx, `LOCK TABLE sessions IN ACCESS SHARE MODE`)
				require.NoError(t, err)

				const deadline = 10 * time.Second
				upCtx, cancel := context.WithTimeout(ctx, deadline)
				defer cancel()
				started := time.Now()
				_, err = p.UpTo(upCtx, versionScrtyPrefix)
				elapsed := time.Since(started)

				var pgErr *pgconn.PgError
				require.ErrorAs(t, err, &pgErr, "the upgrade fails with the server's error, not a client timeout: %v", err)
				assert.Equal(t, "55P03", pgErr.Code, "lock_not_available")
				assert.Less(t, elapsed, deadline, "the bound, not the caller's deadline, ended the wait")

				oldNames(t, db)
				noVersion(t, db)

				release()
				_, err = p.UpTo(ctx, versionScrtyPrefix)
				require.NoError(t, err, "the same upgrade succeeds once the lock is gone")
				assert.True(t, regclassExists(t, db, "scrty_sessions"))
			},
		},
		{
			name: "a table name already taken fails the upgrade and leaves that table untouched",
			run: func(t *testing.T, db *sql.DB, p *goose.Provider) {
				ctx := t.Context()

				_, err := db.ExecContext(ctx, `CREATE TABLE scrty_sessions (x int)`)
				require.NoError(t, err)
				t.Cleanup(func() {
					// Runs before the rollback registered by freshSecurityState.
					dctx := context.WithoutCancel(ctx)
					_, _ = db.ExecContext(dctx, `DROP TABLE IF EXISTS scrty_sessions`)
				})

				_, err = p.UpTo(ctx, versionScrtyPrefix)
				require.Error(t, err)
				var pgErr *pgconn.PgError
				require.ErrorAs(t, err, &pgErr)
				assert.Equal(t, "42P07", pgErr.Code, "duplicate_table")

				assert.True(t, regclassExists(t, db, "sessions"), "the table that would have been renamed keeps its name")
				assert.Equal(t, []string{"x"}, queryStrings(t, db, `SELECT column_name FROM information_schema.columns
					WHERE table_schema = current_schema() AND table_name = 'scrty_sessions'`),
					"the pre-existing table is left as it was")
				oldNames(t, db)
				noVersion(t, db)
			},
		},
		{
			name: "an index name taken after every table is renamed rolls every rename back",
			run: func(t *testing.T, db *sql.DB, p *goose.Provider) {
				ctx := t.Context()

				// A table shares the namespace of the indexes, so it blocks an index rename.
				_, err := db.ExecContext(ctx, `CREATE TABLE scrty_sessions_user (x int)`)
				require.NoError(t, err)
				t.Cleanup(func() {
					dctx := context.WithoutCancel(ctx)
					_, _ = db.ExecContext(dctx, `DROP TABLE IF EXISTS scrty_sessions_user`)
				})

				_, err = p.UpTo(ctx, versionScrtyPrefix)
				var pgErr *pgconn.PgError
				require.ErrorAs(t, err, &pgErr)
				assert.Equal(t, "42P07", pgErr.Code)

				oldNames(t, db)
				for _, table := range securityStateInventory.Tables {
					assert.False(t, regclassExists(t, db, scrtyPrefix+table), "table %s was renamed", table)
				}
				assert.True(t, regclassExists(t, db, "sessions_user"), "the index keeps its name")
				noVersion(t, db)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			db, p := freshSecurityState(t, set)
			_, err := p.UpTo(t.Context(), versionSecurityStateLast)
			require.NoError(t, err)

			tc.run(t, db, p)
		})
	}
}

// TestSecurityStatePrefix_Rollback pins the rename's Down section: it restores
// the catalog exactly as it was before the rename, it still completes when a
// relation has since been dropped, and the rename can be applied again after
// it.
func TestSecurityStatePrefix_Rollback(t *testing.T) {
	t.Parallel()

	set := migrate.SecurityState()

	type testCase struct {
		name string
		run  func(t *testing.T, db *sql.DB, p *goose.Provider)
	}

	cases := []testCase{
		{
			name: "rolling the rename back restores every table, column, index, constraint and sequence",
			run: func(t *testing.T, db *sql.DB, p *goose.Provider) {
				ctx := t.Context()

				before := catalogSnapshot(t, db)
				require.NotEmpty(t, before)

				_, err := p.UpTo(ctx, versionScrtyPrefix)
				require.NoError(t, err)
				require.NotEqual(t, before, catalogSnapshot(t, db), "the rename changed the catalog")

				_, err = p.Down(ctx)
				require.NoError(t, err)

				assert.Equal(t, securityStateInventory, catalogRelations(t, db), "no relation keeps its prefixed name")
				assert.Equal(t, before, catalogSnapshot(t, db), "everything else is as it was")
				assert.Equal(t, securityStateCountAtPrefix-1, appliedVersionCount(t, db, set.VersionTable))
			},
		},
		{
			name: "rolling back to zero succeeds after a table was dropped",
			run: func(t *testing.T, db *sql.DB, p *goose.Provider) {
				ctx := t.Context()

				_, err := p.UpTo(ctx, versionScrtyPrefix)
				require.NoError(t, err)
				_, err = db.ExecContext(ctx, `DROP TABLE scrty_sessions`)
				require.NoError(t, err)

				_, err = p.DownTo(ctx, 0)
				require.NoError(t, err, "rollback succeeds even though a table was already dropped")

				assert.Equal(t, relationInventory{}, catalogRelations(t, db), "nothing but the version table is left")
				assert.Equal(t, 0, appliedVersionCount(t, db, set.VersionTable))
			},
		},
		{
			name: "applying again after a rollback gives the prefixed catalog",
			run: func(t *testing.T, db *sql.DB, p *goose.Provider) {
				ctx := t.Context()

				_, err := p.UpTo(ctx, versionScrtyPrefix)
				require.NoError(t, err)
				_, err = p.Down(ctx)
				require.NoError(t, err)
				_, err = p.UpTo(ctx, versionScrtyPrefix)
				require.NoError(t, err)

				assert.Equal(t, prefixed(securityStateInventory), catalogRelations(t, db))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			db, p := freshSecurityState(t, set)
			_, err := p.UpTo(t.Context(), versionSecurityStateLast)
			require.NoError(t, err)

			tc.run(t, db, p)
		})
	}
}
