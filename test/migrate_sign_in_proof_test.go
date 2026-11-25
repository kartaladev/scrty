package test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	gormdb "gorm.io/gorm"

	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/store/gormstore"
	"github.com/kartaladev/scrty/store/migrate"
	"github.com/kartaladev/scrty/store/pgxstore"
	"github.com/kartaladev/scrty/store/sqlstore"
)

// The records a database at the baseline holds before the sign-in proof migration,
// written in the baseline's own shape.
var (
	proofGrant       = id.MustParse("0192f000-0000-7000-8000-0000000003a1")
	proofTombstone   = id.MustParse("0192f000-0000-7000-8000-0000000003a2")
	proofCode        = id.MustParse("0192f000-0000-7000-8000-0000000003a3")
	proofSignIn      = id.MustParse("0192f000-0000-7000-8000-0000000003a4")
	proofDevice      = id.MustParse("0192f000-0000-7000-8000-0000000003a5")
	proofAt          = time.Date(2030, 3, 1, 9, 0, 0, 0, time.UTC)
	proofBrowser     = []byte{0xb1}
	proofHandle      = []byte{0xb2}
	proofDeviceCode  = []byte{0xb3}
	proofOldDocument = `{"user":"u-1","family":"0192f000-0000-7000-8000-0000000003a4",
		"authenticated_at":"2030-03-01T08:00:00Z","amr":["pwd"],"acr":"loa1",
		"absolute_expires_at":"2030-03-01T21:00:00Z","external_issuer":"https://idp.example.com",
		"external_session_id":"x-9"}`
)

// proofTables are the tables the migration adds columns to.
var proofTables = []string{"scrty_op_grants", "scrty_op_authorization_codes", "scrty_op_browser_sessions"}

// proofColumns are the columns it adds to each of them.
var proofColumns = []string{"second_factor_verified", "external_provider", "external_amr", "external_acr"}

// seedBeforeSignInProof writes, at the baseline, one record of every kind that keeps a
// sign-in: a grant, a revocation recorded before its grant, a code, a browser session, a
// pending request and an approved device authorization, the last two with a sign-in
// document of the baseline's keys alone.
func seedBeforeSignInProof(t *testing.T, db *sql.DB) {
	t.Helper()

	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO scrty_op_grants (family, user_ref, client_id, scopes, auth_time, amr, acr, sign_in_family,
			external_issuer, external_session_id, holds_lineage, created_at, expires_at)
			VALUES ($1, 'u-1', 'billing-web', '["openid"]', $2, '["pwd"]', 'loa1', $3,
			'https://idp.example.com', 'x-9', true, $2, $4)`,
			[]any{proofGrant.String(), proofAt, proofSignIn.String(), proofAt.Add(24 * time.Hour)}},
		{`INSERT INTO scrty_op_grants (family, revoked, revoked_at, revoke_cause) VALUES ($1, true, $2, 'revoked')`,
			[]any{proofTombstone.String(), proofAt}},
		{`INSERT INTO scrty_op_authorization_codes (token_id, client_id, user_ref, sign_in_family, authenticated_at,
			amr, acr, sign_in_absolute_expires_at, external_issuer, external_session_id, grant_family, expires_at)
			VALUES ($1, 'billing-web', 'u-1', $2, $3, '["pwd"]', 'loa1', $4, 'https://idp.example.com', 'x-9', $5, $4)`,
			[]any{proofCode.String(), proofSignIn.String(), proofAt, proofAt.Add(12 * time.Hour), proofGrant.String()}},
		{`INSERT INTO scrty_op_browser_sessions (id, digest, user_ref, sign_in_family, authenticated_at, amr, acr,
			sign_in_absolute_expires_at, external_issuer, external_session_id, idle_expires_at, absolute_expires_at)
			VALUES ($1, $2, 'u-1', $3, $4, '["pwd"]', 'loa1', $5, 'https://idp.example.com', 'x-9', $5, $5)`,
			[]any{proofSignIn.String(), proofBrowser, proofSignIn.String(), proofAt, proofAt.Add(12 * time.Hour)}},
		{`INSERT INTO scrty_op_pending_requests (id, handle_digest, flow_digest, client_id, parked_at, expires_at,
			stage, sign_in) VALUES ($1, $2, '\x01', 'billing-web', $3, $4, 1, $5::jsonb)`,
			[]any{proofCode.String(), proofHandle, proofAt, proofAt.Add(time.Hour), proofOldDocument}},
		{`INSERT INTO scrty_op_device_authorizations (id, device_code_digest, client_id, issued_at, expires_at, state,
			user_ref, granted_scopes, sign_in, sign_in_family, external_issuer, external_session_id, grant_family)
			VALUES ($1, $2, 'billing-tv', $3, $4, 2, 'u-1', '["openid"]', $5::jsonb, $6, 'https://idp.example.com',
			'x-9', $7)`,
			[]any{proofDevice.String(), proofDeviceCode, proofAt, proofAt.Add(time.Hour), proofOldDocument,
				proofSignIn.String(), proofGrant.String()}},
	}
	for _, s := range statements {
		_, err := db.ExecContext(t.Context(), s.query, s.args...)
		require.NoError(t, err, s.query)
	}
}

// proofStores are one backend's stores of every record that keeps a sign-in.
type proofStores struct {
	grants   oidcprovider.GrantStore
	codes    oidcprovider.CodeStore
	browsers oidcprovider.BrowserSessionStore
	pending  oidcprovider.PendingRequestStore
	devices  oidcprovider.DeviceAuthorizationStore
}

// proofBackends opens every supported backend's stores over conn's database.
func proofBackends(t *testing.T, conn PostgresConn) map[string]proofStores {
	t.Helper()

	pool, err := pgxpool.New(t.Context(), conn.DSN)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	gdb, err := gormdb.Open(postgres.Open(conn.DSN), &gormdb.Config{DisableAutomaticPing: true})
	require.NoError(t, err)
	gsql, err := gdb.DB()
	require.NoError(t, err)
	t.Cleanup(func() { _ = gsql.Close() })

	must := func(s any, err error) any {
		t.Helper()
		require.NoError(t, err)
		return s
	}
	return map[string]proofStores{
		"sqlstore": {
			grants:   must(sqlstore.NewGrantStore(conn.DB)).(oidcprovider.GrantStore),
			codes:    must(sqlstore.NewCodeStore(conn.DB)).(oidcprovider.CodeStore),
			browsers: must(sqlstore.NewBrowserSessionStore(conn.DB)).(oidcprovider.BrowserSessionStore),
			pending:  must(sqlstore.NewPendingRequestStore(conn.DB)).(oidcprovider.PendingRequestStore),
			devices:  must(sqlstore.NewDeviceAuthorizationStore(conn.DB)).(oidcprovider.DeviceAuthorizationStore),
		},
		"pgxstore": {
			grants:   must(pgxstore.NewGrantStore(pool)).(oidcprovider.GrantStore),
			codes:    must(pgxstore.NewCodeStore(pool)).(oidcprovider.CodeStore),
			browsers: must(pgxstore.NewBrowserSessionStore(pool)).(oidcprovider.BrowserSessionStore),
			pending:  must(pgxstore.NewPendingRequestStore(pool)).(oidcprovider.PendingRequestStore),
			devices:  must(pgxstore.NewDeviceAuthorizationStore(pool)).(oidcprovider.DeviceAuthorizationStore),
		},
		"gormstore": {
			grants:   must(gormstore.NewGrantStore(gdb)).(oidcprovider.GrantStore),
			codes:    must(gormstore.NewCodeStore(gdb)).(oidcprovider.CodeStore),
			browsers: must(gormstore.NewBrowserSessionStore(gdb)).(oidcprovider.BrowserSessionStore),
			pending:  must(gormstore.NewPendingRequestStore(gdb)).(oidcprovider.PendingRequestStore),
			devices:  must(gormstore.NewDeviceAuthorizationStore(gdb)).(oidcprovider.DeviceAuthorizationStore),
		},
	}
}

// assertUnproved requires a sign-in read from a record written before the migration to
// carry no second-factor marker and no federated evidence, and to keep what it held.
func assertUnproved(t *testing.T, s oidcprovider.SignIn, what string) {
	t.Helper()

	assert.False(t, s.SecondFactorVerified, "%s: no second-factor marker", what)
	assert.Empty(t, s.ExternalProvider, "%s: no identity provider", what)
	assert.Nil(t, s.ExternalAMR, "%s: no upstream amr", what)
	assert.Empty(t, s.ExternalACR, "%s: no upstream acr", what)
	assert.Equal(t, []string{"pwd"}, s.AMR, "%s: the amr is kept", what)
	assert.Equal(t, "https://idp.example.com", s.ExternalIssuer, "%s: the upstream issuer is kept", what)
}

// relfilenodes reports the storage file of each table, which a rewrite replaces.
func relfilenodes(t *testing.T, db *sql.DB) []string {
	t.Helper()

	out := make([]string, 0, len(proofTables))
	for _, table := range proofTables {
		out = append(out, queryStrings(t, db, `SELECT pg_relation_filenode($1::regclass)::text`, table)...)
	}

	return out
}

// TestSignInProofMigration_PopulatedUpgrade pins the migration after the baseline on a
// database already holding records: it rewrites no table, every record written before it
// loads through every backend with no second-factor marker and no federated evidence, and
// its rollback leaves exactly the baseline's schema with every record kept.
func TestSignInProofMigration_PopulatedUpgrade(t *testing.T) {
	t.Parallel()

	set := migrate.SecurityState()
	conn := RunTestPostgres(t)
	db := conn.DB
	p := provider(t, db, set.FS(), set.Dir, set.VersionTable)
	rollBackAtCleanup(t, db, p, set.VersionTable)
	ctx := t.Context()

	_, err := p.UpTo(ctx, versionSecurityStateBaseline)
	require.NoError(t, err)
	seedBeforeSignInProof(t, db)
	baseline := catalogOf(t, db)
	files := relfilenodes(t, db)

	results, err := p.Up(ctx)
	require.NoError(t, err)
	require.Len(t, results, 1, "only the migration after the baseline is pending")
	assert.Equal(t, versionSignInProof, results[0].Source.Version)
	assert.Equal(t, files, relfilenodes(t, db), "adding the columns rewrote a table")
	for _, table := range proofTables {
		assert.Equal(t, []string{
			"second_factor_verified boolean NULL DEFAULT ", "external_provider text NULL DEFAULT ",
			"external_amr jsonb NULL DEFAULT ", "external_acr text NULL DEFAULT ",
		}, tableColumns(t, db, table, proofColumns), "%s: nullable, with no default", table)
		assert.Equal(t, 0, queryCount(t, db, `SELECT count(*) FROM `+table+` WHERE second_factor_verified IS NOT NULL
			OR external_provider IS NOT NULL OR external_amr IS NOT NULL OR external_acr IS NOT NULL`),
			"%s: an existing row was given a value", table)
	}

	for name, s := range proofBackends(t, conn) {
		t.Run(name, func(t *testing.T) {
			loadUnproved(ctx, t, s)
		})
	}

	// A grant stored over a revocation recorded before the upgrade takes its proof, and
	// keeps the revocation.
	grants, err := sqlstore.NewGrantStore(db)
	require.NoError(t, err)
	require.NoError(t, grants.Create(ctx, &oidcprovider.Grant{
		Family: proofTombstone, User: "u-1", ClientID: "billing-web", HoldsLineage: true, CreatedAt: proofAt,
		ExpiresAt: proofAt.Add(time.Hour), SecondFactorVerified: true, ExternalProvider: "corp",
		ExternalIssuer: "https://idp.example.com", ExternalAMR: []string{"mfa"}, ExternalACR: "urn:corp:loa:2",
	}))
	filled, err := grants.Load(ctx, proofTombstone)
	require.NoError(t, err)
	assert.True(t, filled.Revoked, "the revocation recorded first is kept")
	assert.True(t, filled.SecondFactorVerified)
	assert.Equal(t, "corp", filled.ExternalProvider)
	assert.Equal(t, []string{"mfa"}, filled.ExternalAMR)
	assert.Equal(t, "urn:corp:loa:2", filled.ExternalACR)

	_, err = p.Down(ctx)
	require.NoError(t, err)
	assertCatalogsEqual(t, baseline, catalogOf(t, db))
	for table, want := range map[string]int{
		"scrty_op_grants": 2, "scrty_op_authorization_codes": 1, "scrty_op_browser_sessions": 1,
		"scrty_op_pending_requests": 1, "scrty_op_device_authorizations": 1,
	} {
		assert.Equal(t, want, rowCount(t, db, table), "%s keeps its rows through the rollback", table)
	}
}

// loadUnproved loads every seeded record through s, each of which must read back with
// no proof and keep what it held.
func loadUnproved(ctx context.Context, t *testing.T, s proofStores) {
	t.Helper()

	grant, err := s.grants.Load(ctx, proofGrant)
	require.NoError(t, err)
	assert.False(t, grant.SecondFactorVerified)
	assert.Empty(t, grant.ExternalProvider)
	assert.Nil(t, grant.ExternalAMR)
	assert.Empty(t, grant.ExternalACR)
	assert.Equal(t, []string{"pwd"}, grant.AMR)
	assert.Equal(t, "https://idp.example.com", grant.ExternalIssuer)

	code, err := s.codes.Load(ctx, proofCode)
	require.NoError(t, err)
	assertUnproved(t, code.SignIn, "code")

	browser, err := s.browsers.Load(ctx, proofBrowser, proofAt)
	require.NoError(t, err)
	assertUnproved(t, browser.SignIn, "browser session")

	pending, err := s.pending.Load(ctx, proofHandle)
	require.NoError(t, err)
	require.NotNil(t, pending.SignIn)
	assertUnproved(t, *pending.SignIn, "pending request")

	device, err := s.devices.LoadByDeviceCode(ctx, proofDeviceCode)
	require.NoError(t, err)
	require.NotNil(t, device.Approval)
	assertUnproved(t, device.Approval.SignIn, "device authorization")
}
