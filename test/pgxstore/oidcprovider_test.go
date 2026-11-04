package pgxstore_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/internal/oplineage"
	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/store/pgxstore"
	"github.com/kartaladev/scrty/store/seal"
	"github.com/kartaladev/scrty/test/internal/storefix"
	"github.com/kartaladev/scrty/test/storetest"
	"github.com/kartaladev/scrty/token/onetime"
)

// opTime is the instant this file's own records are dated from.
var opTime = time.Date(2030, 2, 1, 9, 0, 0, 0, time.UTC)

// opID is the n-th identifier this file's own records use.
func opID(n int) id.ID { return id.MustParse(fmt.Sprintf("01926a4e-0000-7000-8000-%012x", n)) }

func newPendingStore(t *testing.T, pool *pgxpool.Pool, opts ...pgxstore.Option) oidcprovider.PendingRequestStore {
	t.Helper()

	return must.Must(pgxstore.NewPendingRequestStore(pool, opts...))
}

func newCodeStore(t *testing.T, pool *pgxpool.Pool, opts ...pgxstore.Option) oidcprovider.CodeStore {
	t.Helper()

	return must.Must(pgxstore.NewCodeStore(pool, opts...))
}

func newConsentStore(t *testing.T, pool *pgxpool.Pool, opts ...pgxstore.Option) oidcprovider.ConsentStore {
	t.Helper()

	return must.Must(pgxstore.NewConsentStore(pool, opts...))
}

func newGrantStore(t *testing.T, pool *pgxpool.Pool, opts ...pgxstore.Option) oidcprovider.GrantStore {
	t.Helper()

	return must.Must(pgxstore.NewGrantStore(pool, opts...))
}

func newAccessTokenStore(t *testing.T, pool *pgxpool.Pool, opts ...pgxstore.Option) oidcprovider.AccessTokenStore {
	t.Helper()

	return must.Must(pgxstore.NewAccessTokenStore(pool, opts...))
}

func newAssertionStore(t *testing.T, pool *pgxpool.Pool, opts ...pgxstore.Option) oidcprovider.AssertionIDStore {
	t.Helper()

	return must.Must(pgxstore.NewAssertionIDStore(pool, opts...))
}

func newBrowserStore(t *testing.T, pool *pgxpool.Pool, opts ...pgxstore.Option) oidcprovider.BrowserSessionStore {
	t.Helper()

	return must.Must(pgxstore.NewBrowserSessionStore(pool, opts...))
}

func newClientStore(t *testing.T, pool *pgxpool.Pool, opts ...pgxstore.Option) *pgxstore.ClientStore {
	t.Helper()

	return must.Must(pgxstore.NewClientStore(pool, opts...))
}

// lineageSessions is the session store behind the lineage store over db.
func lineageSessions(t *testing.T, pool *pgxpool.Pool, c seal.Cipher, opts ...pgxstore.Option) session.Store {
	t.Helper()

	lineages, err := pgxstore.NewRefreshTokenStore(pool, c, opts...)
	require.NoError(t, err)

	return oplineage.Sessions(lineages)
}

// withoutSessionsTable renames the sessions table away until the test ends, so that a
// lineage statement reaching it fails instead of passing on the wrong table.
func withoutSessionsTable(t *testing.T, conn database) {
	t.Helper()

	_, err := conn.DB.ExecContext(t.Context(), "ALTER TABLE sessions RENAME TO sessions_renamed_away")
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = conn.DB.ExecContext(context.WithoutCancel(t.Context()), "ALTER TABLE sessions_renamed_away RENAME TO sessions")
	})
}

// TestPgxStore runs every provider store through its conformance suite, and the race
// suites over two connection pools. Each subtest takes a database of its own.
func TestPgxStore(t *testing.T) {
	t.Parallel()

	suites := map[string]func(t *testing.T, conn database){
		"PendingRequests": func(t *testing.T, conn database) {
			storetest.PendingRequestSuite(t, func(t *testing.T) oidcprovider.PendingRequestStore {
				return newPendingStore(t, emptied(t, conn, pgschema.PendingRequestTable))
			})
		},
		"CodeRecords": func(t *testing.T, conn database) {
			storetest.CodeRecordSuite(t, func(t *testing.T) oidcprovider.CodeStore {
				return newCodeStore(t, emptied(t, conn, pgschema.CodeTable))
			})
		},
		"Consents": func(t *testing.T, conn database) {
			storetest.ConsentSuite(t, func(t *testing.T) oidcprovider.ConsentStore {
				return newConsentStore(t, emptied(t, conn, pgschema.ConsentTable))
			})
		},
		"Grants": func(t *testing.T, conn database) {
			storetest.GrantSuite(t, func(t *testing.T) oidcprovider.GrantStore {
				return newGrantStore(t, emptied(t, conn, pgschema.GrantTable))
			})
		},
		"AccessTokens": func(t *testing.T, conn database) {
			storetest.AccessTokenSuite(t, func(t *testing.T) oidcprovider.AccessTokenStore {
				return newAccessTokenStore(t, emptied(t, conn, pgschema.AccessTokenTable))
			})
		},
		"AssertionIDs": func(t *testing.T, conn database) {
			storetest.AssertionIDSuite(t, func(t *testing.T) oidcprovider.AssertionIDStore {
				return newAssertionStore(t, emptied(t, conn, pgschema.AssertionIDTable))
			})
		},
		"BrowserSessions": func(t *testing.T, conn database) {
			storetest.BrowserSessionSuite(t, func(t *testing.T) oidcprovider.BrowserSessionStore {
				return newBrowserStore(t, emptied(t, conn, pgschema.BrowserSessionTable))
			})
		},
		"Lineages": func(t *testing.T, conn database) {
			c := storefix.TestCipher(t)
			withoutSessionsTable(t, conn)
			storetest.RunSessionStoreSuite(t, func(t *testing.T, clk clock.Clock) session.Store {
				return lineageSessions(t, emptied(t, conn, pgschema.RefreshTokenTable), c, pgxstore.WithClock(clk))
			})
		},
		"Races/PendingRequests": func(t *testing.T, conn database) {
			storetest.RunAdvanceRace(t, durableHarness(conn, newPendingStore))
		},
		"Races/CodeTokens": func(t *testing.T, conn database) {
			storetest.RunCodeSpendRace(t, durableHarness(conn, func(_ *testing.T, pool *pgxpool.Pool, opts ...pgxstore.Option) onetime.Store {
				return must.Must(pgxstore.NewOneTimeStore(pool, opts...))
			}))
		},
		"Races/AssertionIDs": func(t *testing.T, conn database) {
			storetest.RunAssertionRecordRace(t, durableHarness(conn, newAssertionStore))
		},
		"Races/Grants": func(t *testing.T, conn database) {
			storetest.RunGrantRaces(t, durableHarness(conn, newGrantStore))
		},
		"Races/GrantLockOrder": func(t *testing.T, conn database) {
			storetest.RunGrantOrderRaces(t, durableHarness(conn, newGrantStore))
		},
		"Races/BrowserSessions": func(t *testing.T, conn database) {
			storetest.RunTouchRace(t, durableHarness(conn, newBrowserStore))
		},
		"Races/Lineages": func(t *testing.T, conn database) {
			c := storefix.TestCipher(t)
			withoutSessionsTable(t, conn)
			storetest.RunSessionSupersessionRace(t, durableHarness(conn, func(t *testing.T, pool *pgxpool.Pool, opts ...pgxstore.Option) session.Store {
				return lineageSessions(t, pool, c, opts...)
			}))
		},
	}

	for name, run := range suites {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			run(t, migrated(t))
		})
	}
}

// confidentialClient is a client that takes a secret, for this file's own cases. The
// suite holds a store to every field.
func confidentialClient(clientID string) oidcprovider.Client {
	return oidcprovider.Client{
		ID:           clientID,
		Name:         "Billing",
		Type:         oidcprovider.Confidential,
		AuthMethod:   oidcprovider.ClientSecretPost,
		RedirectURIs: []string{"https://rp.example.com/cb"},
		Scopes:       []string{"openid", "profile", "offline_access"},
		GrantTypes:   []oidcprovider.GrantType{oidcprovider.GrantAuthorizationCode, oidcprovider.GrantRefreshToken},
	}
}

// clientSecretBytes is a secret long enough for a consumer to supply.
var clientSecretBytes = []byte("a-consumer-supplied-secret-of-at-least-32-bytes")

// The rotation case of ClientStoreSuite runs only for a store that can rotate, so these
// keep it from being skipped here unnoticed.
var (
	_ storetest.ClientRotator = (*pgxstore.ClientStore)(nil)
	_ storetest.ClientRotator = (*oidcprovider.MemoryRegistry)(nil)
)

// TestPgxStore_Clients runs the client suite over the store and over the in-memory
// registry, so what differs between them fails for the one that differs.
func TestPgxStore_Clients(t *testing.T) {
	t.Parallel()

	conn := migrated(t)
	backends := map[string]func(t *testing.T) oidcprovider.ClientStore{
		"memory": func(*testing.T) oidcprovider.ClientStore { return must.Must(oidcprovider.NewMemoryRegistry(nil)) },
		"pgxstore": func(t *testing.T) oidcprovider.ClientStore {
			return newClientStore(t, emptied(t, conn, pgschema.ClientTable))
		},
	}

	for backend, newStore := range backends {
		t.Run(backend, func(t *testing.T) { storetest.ClientStoreSuite(t, newStore) })
	}
}

// TestPgxStore_ClientSecretsStoredForm pins what the secrets column holds: SecretBytes
// marshals redacted, so a stored form that marshals it would lose every digest. It holds
// for a secret a consumer supplies and for one the store generates, which are written by
// different paths.
func TestPgxStore_ClientSecretsStoredForm(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		// store writes a secret and returns the plaintext it was made from.
		store func(ctx context.Context, t *testing.T, s *pgxstore.ClientStore) string
	}{
		{"supplied", func(ctx context.Context, t *testing.T, s *pgxstore.ClientStore) string {
			c := confidentialClient("c-1")
			c.Secret = clientSecretBytes
			require.NoError(t, s.Put(ctx, c))

			return string(clientSecretBytes)
		}},
		{"generated", func(ctx context.Context, t *testing.T, s *pgxstore.ClientStore) string {
			require.NoError(t, s.Put(ctx, confidentialClient("c-1")))
			secret, err := s.GenerateSecret(ctx, "c-1")
			require.NoError(t, err)

			return secret
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			conn := migrated(t)
			secret := tc.store(ctx, t, newClientStore(t, conn.Pool))

			var stored string
			require.NoError(t, conn.DB.QueryRowContext(ctx, `SELECT secrets::text FROM op_clients WHERE client_id = 'c-1'`).Scan(&stored))

			assert.NotContains(t, stored, "REDACTED", "the digest must be stored, not its redacted form")
			assert.NotContains(t, stored, secret, "the secret itself must not be stored")

			digest := sha256.Sum256([]byte(secret))
			assert.Contains(t, stored, base64.RawURLEncoding.EncodeToString(digest[:]))
		})
	}
}

// TestPgxStore_LineageIsNotASession proves the two stores share no table, in both
// directions, whatever the identifier.
func TestPgxStore_LineageIsNotASession(t *testing.T) {
	t.Parallel()

	conn := migrated(t)
	db, pool := conn.DB, conn.Pool
	c := storefix.TestCipher(t)
	sessions := newSessionStore(t, pool, c)
	lineages := lineageSessions(t, pool, c)

	cases := []struct {
		name          string
		written, read session.Store
		table         string
	}{
		{name: "lineage_not_a_session", written: lineages, read: sessions, table: pgschema.RefreshTokenTable},
		{name: "a session is not a lineage", written: sessions, read: lineages, table: "sessions"},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			rec := opSession(fmt.Sprintf("identifier-%d", i), opID(100+i))
			require.NoError(t, tc.written.Create(ctx, rec))

			_, err := tc.read.Load(ctx, rec.ID)
			require.ErrorIs(t, err, session.ErrNotFound)

			var held int
			// table is one of this test's constants.
			require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM "+tc.table+" WHERE family_id = $1", rec.FamilyID).Scan(&held))
			assert.Equal(t, 1, held, "the record is in the table it was written to")

			_, err = tc.written.Load(ctx, rec.ID)
			require.NoError(t, err, "and the store that wrote it reads it")
		})
	}
}

// TestPgxStore_LineageInCallerTransaction proves a lineage store joined to a caller's
// transaction, by either route, still writes to the lineage table and not to sessions;
// that a plain session store on the same transaction still uses sessions; and that the
// caller's rollback removes both rows.
func TestPgxStore_LineageInCallerTransaction(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// join returns the options a store takes and the context its calls run on.
		join func(ctx context.Context, tx pgx.Tx) ([]pgxstore.Option, context.Context)
	}

	cases := []testCase{
		{
			name: "WithTx",
			join: func(ctx context.Context, tx pgx.Tx) ([]pgxstore.Option, context.Context) {
				return nil, pgxstore.WithTx(ctx, tx)
			},
		},
		{
			name: "WithTxResolver",
			join: func(ctx context.Context, tx pgx.Tx) ([]pgxstore.Option, context.Context) {
				return []pgxstore.Option{pgxstore.WithTxResolver(func(context.Context) (pgx.Tx, bool) { return tx, true })}, ctx
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			conn := migrated(t)
			ctx := t.Context()
			c := storefix.TestCipher(t)

			tx, err := conn.Pool.Begin(ctx)
			require.NoError(t, err)
			t.Cleanup(func() { _ = tx.Rollback(context.WithoutCancel(ctx)) })

			opts, runCtx := tc.join(ctx, tx)
			lineages := lineageSessions(t, conn.Pool, c, opts...)
			sessions := newSessionStore(t, conn.Pool, c, opts...)

			lineageRec := opSession("lineage-identifier", opID(200))
			sessionRec := opSession("session-identifier", opID(201))
			require.NoError(t, lineages.Create(runCtx, lineageRec))
			require.NoError(t, sessions.Create(runCtx, sessionRec))

			// count reads through the caller's transaction, which sees its own writes.
			count := func(table string, family id.ID) int {
				var n int
				// table is one of this test's constants.
				require.NoError(t, tx.QueryRow(ctx, "SELECT count(*) FROM "+table+" WHERE family_id = $1", family).Scan(&n))
				return n
			}

			assert.Equal(t, 1, count(pgschema.RefreshTokenTable, lineageRec.FamilyID), "the lineage is in the lineage table")
			assert.Zero(t, count("sessions", lineageRec.FamilyID), "and not in sessions")
			assert.Equal(t, 1, count("sessions", sessionRec.FamilyID), "the session is in sessions")
			assert.Zero(t, count(pgschema.RefreshTokenTable, sessionRec.FamilyID), "and not in the lineage table")

			got, err := lineages.Load(runCtx, lineageRec.ID)
			require.NoError(t, err, "the lineage store reads its own write")
			assert.Equal(t, lineageRec.FamilyID, got.FamilyID)
			_, err = lineages.Load(runCtx, sessionRec.ID)
			require.ErrorIs(t, err, session.ErrNotFound)
			_, err = sessions.Load(runCtx, lineageRec.ID)
			require.ErrorIs(t, err, session.ErrNotFound)

			require.NoError(t, tx.Rollback(ctx))

			var left int
			require.NoError(t, conn.DB.QueryRowContext(ctx, "SELECT (SELECT count(*) FROM "+pgschema.RefreshTokenTable+")+(SELECT count(*) FROM sessions)").Scan(&left))
			assert.Zero(t, left, "the caller's rollback removes both rows")
		})
	}
}

// opSession is a session a store can hold, with identifier as its credential.
func opSession(identifier string, family id.ID) *session.Session {
	return &session.Session{
		ID:                identifier,
		UserID:            "u-1",
		CreatedAt:         opTime,
		LastAccessedAt:    opTime,
		IdleExpiresAt:     time.Now().Add(time.Hour),
		AbsoluteExpiresAt: time.Now().Add(2 * time.Hour),
		AuthenticatedAt:   opTime,
		FamilyID:          family,
		FamilyCreatedAt:   opTime,
	}
}

// TestPgxStore_NoCredentialInAnyColumn reads every provider table directly, after a
// record of each kind was stored for a code, a handle, a flow secret, a browser session,
// a refresh token, an access token and a client secret, and looks for each secret in
// every column in the forms it could be written in.
func TestPgxStore_NoCredentialInAnyColumn(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	conn := migrated(t)
	db, pool := conn.DB, conn.Pool

	digest := func(secret string) []byte {
		sum := sha256.Sum256([]byte(secret))

		return sum[:]
	}

	const (
		handle, flow, browser = "rh-handle-secret-value", "flow-secret-value", "browser-secret-value"
		access, refresh       = "at-access-secret-value", "rt-refresh-secret-value"
	)

	signIn := oidcprovider.SignIn{
		User: "u-1", Family: opID(1), AuthenticatedAt: opTime, AbsoluteExpiresAt: opTime.Add(time.Hour),
	}
	require.NoError(t, newPendingStore(t, pool).Create(ctx, &oidcprovider.PendingRequest{
		ID: opID(2), HandleDigest: digest(handle), FlowDigest: digest(flow), ClientID: "c-1",
		ParkedAt: opTime, ExpiresAt: opTime.Add(time.Minute), SignIn: &signIn,
	}))
	require.NoError(t, newCodeStore(t, pool).Create(ctx, &oidcprovider.CodeRecord{
		TokenID: opID(3), ClientID: "c-1", SignIn: signIn, GrantFamily: opID(4), ExpiresAt: opTime.Add(time.Minute),
	}))
	require.NoError(t, newBrowserStore(t, pool).Put(ctx, &oidcprovider.BrowserSession{
		Digest: digest(browser), SignIn: signIn, IdleExpiresAt: opTime.Add(time.Minute), AbsoluteExpiresAt: opTime.Add(time.Hour),
	}))
	require.NoError(t, newAccessTokenStore(t, pool).Create(ctx, &oidcprovider.AccessTokenRecord{
		ID: opID(5), Digest: digest(access), GrantFamily: opID(4), ClientID: "c-1", User: "u-1",
		IssuedAt: opTime, ExpiresAt: opTime.Add(time.Minute),
	}))
	require.NoError(t, newGrantStore(t, pool).Create(ctx, &oidcprovider.Grant{
		Family: opID(4), User: "u-1", ClientID: "c-1", CodeID: opID(3), SignInFamily: opID(1), HoldsLineage: true,
		CreatedAt: opTime, ExpiresAt: opTime.Add(time.Hour),
	}))
	require.NoError(t, lineageSessions(t, pool, storefix.TestCipher(t)).Create(ctx, opSession(refresh, opID(4))))

	clients := newClientStore(t, pool)
	require.NoError(t, clients.Put(ctx, confidentialClient("c-1")))
	clientSecret, err := clients.GenerateSecret(ctx, "c-1")
	require.NoError(t, err)

	secrets := []string{handle, flow, browser, access, refresh, clientSecret}

	var seen int
	for _, table := range pgschema.OIDCProviderTables() {
		rows, err := db.QueryContext(ctx, "SELECT row_to_json(r)::text FROM "+table+" r") //nolint:gosec // table is one of pgschema's constants
		require.NoError(t, err)
		for rows.Next() {
			var row string
			require.NoError(t, rows.Scan(&row))
			seen++
			for _, secret := range secrets {
				assert.NotContains(t, row, secret, "table %s holds a secret in clear", table)
				assert.NotContains(t, row, hex.EncodeToString([]byte(secret)), "table %s holds a secret in hex", table)
				assert.NotContains(t, row, base64.RawURLEncoding.EncodeToString([]byte(secret)), "table %s holds a secret in base64", table)
			}
		}
		require.NoError(t, rows.Err())
		require.NoError(t, rows.Close())
	}
	assert.Equal(t, 7, seen, "every record stored above was read back")
}

// TestPgxStore_Unstorable holds every write and lookup to its answer for text PostgreSQL
// cannot hold, which the provider refuses first and a store must still survive: an error
// that repeats no part of the value, and nothing written.
func TestPgxStore_Unstorable(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	conn := migrated(t)
	db, pool := conn.DB, conn.Pool
	at := opTime

	for name, bad := range map[string]string{"a NUL byte": "bad\x00value", "invalid UTF-8": "bad\xffvalue"} {
		signIn := oidcprovider.SignIn{User: "u-1", Family: opID(1), AMR: []string{bad}}

		cases := []struct {
			name string
			call func() error
		}{
			{"pending request text", func() error {
				return newPendingStore(t, pool).Create(ctx, &oidcprovider.PendingRequest{ID: opID(2), HandleDigest: []byte{1}, ClientID: bad})
			}},
			{"pending request list", func() error {
				return newPendingStore(t, pool).Create(ctx, &oidcprovider.PendingRequest{ID: opID(2), HandleDigest: []byte{1}, Scopes: []string{bad}})
			}},
			{"pending request's sign-in", func() error {
				return newPendingStore(t, pool).Create(ctx, &oidcprovider.PendingRequest{ID: opID(2), HandleDigest: []byte{1}, SignIn: &signIn})
			}},
			{"advance's sign-in", func() error {
				return newPendingStore(t, pool).Advance(ctx, []byte{1}, oidcprovider.StageLogin, oidcprovider.StageDone, &signIn)
			}},
			{"code text", func() error {
				return newCodeStore(t, pool).Create(ctx, &oidcprovider.CodeRecord{TokenID: opID(3), Nonce: bad})
			}},
			{"code's sign-in", func() error {
				return newCodeStore(t, pool).Create(ctx, &oidcprovider.CodeRecord{TokenID: opID(3), SignIn: signIn})
			}},
			{"code listing by selector", func() error {
				_, err := newCodeStore(t, pool).UnspentBySignIn(ctx, oidcprovider.SignInSelector{User: "u-1", ExternalIssuer: bad}, false)
				return err
			}},
			{"code listing by client", func() error {
				_, err := newCodeStore(t, pool).UnspentByClient(ctx, "u-1", bad)
				return err
			}},
			{"consent user", func() error { return newConsentStore(t, pool).Give(ctx, "u-1", bad, nil, false, at) }},
			{"consent scope", func() error { return newConsentStore(t, pool).Give(ctx, "u-1", "c-1", []string{bad}, false, at) }},
			{"consent load", func() error {
				_, err := newConsentStore(t, pool).Load(ctx, "u-1", bad)
				return err
			}},
			{"consent revoke", func() error {
				_, err := newConsentStore(t, pool).Revoke(ctx, "u-1", bad)
				return err
			}},
			{"consent listing", func() error {
				_, err := newConsentStore(t, pool).ListByUser(ctx, "bad\x00user")
				return err
			}},
			{"grant text", func() error {
				return newGrantStore(t, pool).Create(ctx, &oidcprovider.Grant{Family: opID(4), ClientID: bad})
			}},
			{"grant list", func() error {
				return newGrantStore(t, pool).Create(ctx, &oidcprovider.Grant{Family: opID(4), AMR: []string{bad}})
			}},
			{"grant cause", func() error {
				return newGrantStore(t, pool).Revoke(ctx, opID(4), oidcprovider.RevocationCause(bad), at)
			}},
			{"access token text", func() error {
				return newAccessTokenStore(t, pool).Create(ctx, &oidcprovider.AccessTokenRecord{ID: opID(5), ClientID: bad})
			}},
			{"access token confirmation", func() error {
				return newAccessTokenStore(t, pool).Create(ctx, &oidcprovider.AccessTokenRecord{ID: opID(5), Confirmation: map[string]string{"jkt": bad}})
			}},
			{"assertion identifier", func() error {
				_, err := newAssertionStore(t, pool).Record(ctx, "c-1", bad, at)
				return err
			}},
			{"browser session's sign-in", func() error {
				return newBrowserStore(t, pool).Put(ctx, &oidcprovider.BrowserSession{Digest: []byte{1}, SignIn: signIn, IdleExpiresAt: at, AbsoluteExpiresAt: at})
			}},
			{"browser session selector", func() error {
				_, err := newBrowserStore(t, pool).DeleteBySignIn(ctx, oidcprovider.SignInSelector{User: "u-1", ExternalIssuer: bad})
				return err
			}},
			{"client text", func() error {
				c := confidentialClient("c-1")
				c.Name = bad
				return newClientStore(t, pool).Put(ctx, c)
			}},
			{"client metadata", func() error {
				c := confidentialClient("c-1")
				c.Metadata = map[string]string{"k": bad}
				return newClientStore(t, pool).Put(ctx, c)
			}},
			{"client lookup", func() error {
				_, err := newClientStore(t, pool).Client(ctx, bad)
				return err
			}},
			{"client delete", func() error { return newClientStore(t, pool).Delete(ctx, bad) }},
		}

		for _, tc := range cases {
			t.Run(name+"/"+tc.name, func(t *testing.T) {
				err := tc.call()
				require.Error(t, err)
				assert.NotContains(t, err.Error(), "bad", "an error must not repeat the value")
			})
		}
	}

	for _, table := range pgschema.OIDCProviderTables() {
		var held int
		// table is one of pgschema's constants.
		require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&held))
		assert.Zero(t, held, "table %s", table)
	}
}

// TestPgxStore_ErrorsCarryNoDigest makes each digest-keyed statement fail for real, by
// dropping its table, and requires the failure's text, and the text of every error it
// wraps, to carry no digest or bound secret in any form. pgx's own errors are in that
// tree: they name the statement and the server's reason, and are held here to name no
// argument.
func TestPgxStore_ErrorsCarryNoDigest(t *testing.T) {
	t.Parallel()

	digest := sha256.Sum256(clientSecretBytes)

	cases := []struct {
		name  string
		table string
		call  func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) error
	}{
		{"pending create", pgschema.PendingRequestTable, func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) error {
			return newPendingStore(t, pool).Create(ctx, &oidcprovider.PendingRequest{ID: opID(1), HandleDigest: digest[:], FlowDigest: digest[:]})
		}},
		{"pending load", pgschema.PendingRequestTable, func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) error {
			_, err := newPendingStore(t, pool).Load(ctx, digest[:])
			return err
		}},
		{"pending advance", pgschema.PendingRequestTable, func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) error {
			return newPendingStore(t, pool).Advance(ctx, digest[:], oidcprovider.StageLogin, oidcprovider.StageDone, nil)
		}},
		{"browser put", pgschema.BrowserSessionTable, func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) error {
			return newBrowserStore(t, pool).Put(ctx, &oidcprovider.BrowserSession{Digest: digest[:], IdleExpiresAt: opTime, AbsoluteExpiresAt: opTime})
		}},
		{"browser load", pgschema.BrowserSessionTable, func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) error {
			_, err := newBrowserStore(t, pool).Load(ctx, digest[:], opTime)
			return err
		}},
		{"browser touch", pgschema.BrowserSessionTable, func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) error {
			return newBrowserStore(t, pool).Touch(ctx, digest[:], opTime)
		}},
		{"browser delete", pgschema.BrowserSessionTable, func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) error {
			return newBrowserStore(t, pool).Delete(ctx, digest[:])
		}},
		{"access token create", pgschema.AccessTokenTable, func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) error {
			return newAccessTokenStore(t, pool).Create(ctx, &oidcprovider.AccessTokenRecord{ID: opID(1), Digest: digest[:]})
		}},
		{"client put", pgschema.ClientTable, func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) error {
			c := confidentialClient("c-1")
			c.Secret = clientSecretBytes
			return newClientStore(t, pool).Put(ctx, c)
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			conn := migrated(t)
			// The set's rollback drops with IF EXISTS, so it survives this.
			_, err := conn.DB.ExecContext(ctx, "DROP TABLE "+tc.table)
			require.NoError(t, err)

			err = tc.call(t, ctx, conn.Pool)
			require.Error(t, err)
			assert.False(t, errors.Is(err, oidcprovider.ErrNotFound), "a failure is never reported as absence")
			for _, text := range storefix.ErrorTexts(err) {
				assert.NotContains(t, text, string(digest[:]))
				assert.NotContains(t, text, hex.EncodeToString(digest[:]))
				assert.NotContains(t, text, base64.RawURLEncoding.EncodeToString(digest[:]))
				assert.NotContains(t, text, fmt.Sprintf("%v", digest[:]), "no decimal rendering of the digest")
				assert.NotContains(t, text, fmt.Sprintf("%#v", digest[:]), "no Go rendering of the digest")
				assert.NotContains(t, text, string(clientSecretBytes))
			}
		})
	}
}

// TestPgxStore_GrantRows pins the rows the migration's comments promise, and the cases a
// suite cannot reach through a port: NULL must read as different, a stored grant's zero
// time must never read as a tombstone, and a caller's transaction owns what is written.
func TestPgxStore_GrantRows(t *testing.T) {
	t.Parallel()

	at := opTime.Add(time.Minute)
	joined := func(t *testing.T, pool *pgxpool.Pool) oidcprovider.GrantStore {
		t.Helper()
		s := newGrantStore(t, pool)
		require.NoError(t, s.UseCodes(must.Must(oidcprovider.NewMemoryCodeStore())))

		return s
	}

	cases := []struct {
		name   string
		assert func(t *testing.T, ctx context.Context, conn database)
	}{
		{
			name: "every family but one selects a grant with no sign-in family",
			assert: func(t *testing.T, ctx context.Context, conn database) {
				s := joined(t, conn.Pool)
				require.NoError(t, s.Create(ctx, &oidcprovider.Grant{Family: opID(1), User: "u-1", CreatedAt: opTime}))

				var isNull bool
				require.NoError(t, conn.DB.QueryRowContext(ctx, `SELECT sign_in_family IS NULL FROM op_grants`).Scan(&isNull))
				require.True(t, isNull, "no family is held as NULL, as the schema has it")

				got, err := s.EndSignIns(ctx, oidcprovider.SignInSelector{User: "u-1", ExceptFamily: opID(9)}, at)
				require.NoError(t, err)
				require.Len(t, got, 1, "NULL is not the excepted family")
				assert.Equal(t, opID(1), got[0].Family)
			},
		},
		{
			name: "a stored grant with a zero created_at is not a tombstone",
			assert: func(t *testing.T, ctx context.Context, conn database) {
				s := joined(t, conn.Pool)
				require.NoError(t, s.Create(ctx, &oidcprovider.Grant{Family: opID(1), User: "u-1"}))

				var isNull bool
				require.NoError(t, conn.DB.QueryRowContext(ctx, `SELECT created_at IS NULL FROM op_grants`).Scan(&isNull))
				assert.False(t, isNull)
				require.Error(t, s.Create(ctx, &oidcprovider.Grant{Family: opID(1), User: "u-2"}))

				got, err := s.Load(ctx, opID(1))
				require.NoError(t, err)
				assert.Equal(t, "u-1", string(got.User))
				assert.True(t, got.CreatedAt.IsZero(), "and its zero time reads back as zero")
			},
		},
		{
			name: "holds_lineage is written as given",
			assert: func(t *testing.T, ctx context.Context, conn database) {
				s := joined(t, conn.Pool)
				require.NoError(t, s.Create(ctx, &oidcprovider.Grant{Family: opID(1), CreatedAt: opTime, HoldsLineage: true}))
				require.NoError(t, s.Create(ctx, &oidcprovider.Grant{Family: opID(2), CreatedAt: opTime}))

				for family, want := range map[id.ID]bool{opID(1): true, opID(2): false} {
					got, err := s.Load(ctx, family)
					require.NoError(t, err)
					assert.Equal(t, want, got.HoldsLineage)
				}
			},
		},
		{
			name: "a tombstone holds only its revocation, with created_at NULL",
			assert: func(t *testing.T, ctx context.Context, conn database) {
				s := joined(t, conn.Pool)
				require.NoError(t, s.Revoke(ctx, opID(1), oidcprovider.CauseCodeReplay, at))

				var created, signIn, code sql.NullString
				var holds bool
				require.NoError(t, conn.DB.QueryRowContext(ctx,
					`SELECT created_at::text, sign_in_family::text, code_id::text, holds_lineage FROM op_grants`).
					Scan(&created, &signIn, &code, &holds))
				assert.False(t, created.Valid)
				assert.False(t, signIn.Valid)
				assert.False(t, code.Valid)
				assert.False(t, holds)
			},
		},
		{
			name: "an end inside a caller's transaction is undone by its rollback, codes' revocations included",
			assert: func(t *testing.T, ctx context.Context, conn database) {
				codes := must.Must(oidcprovider.NewMemoryCodeStore())
				require.NoError(t, codes.Create(ctx, &oidcprovider.CodeRecord{
					TokenID: opID(50), GrantFamily: opID(2), SignIn: oidcprovider.SignIn{User: "u-1", Family: opID(7)},
				}))
				s := newGrantStore(t, conn.Pool)
				require.NoError(t, s.UseCodes(codes))
				require.NoError(t, s.Create(ctx, &oidcprovider.Grant{Family: opID(1), User: "u-1", SignInFamily: opID(7), CreatedAt: opTime}))

				tx, err := conn.Pool.Begin(ctx)
				require.NoError(t, err)
				ended, err := s.EndSignIns(pgxstore.WithTx(ctx, tx), oidcprovider.SignInSelector{Family: opID(7)}, at)
				require.NoError(t, err)
				require.Len(t, ended, 1)
				require.NoError(t, tx.Rollback(ctx))

				got, err := s.Load(ctx, opID(1))
				require.NoError(t, err)
				assert.False(t, got.Revoked)
				assert.True(t, got.SignInEndedAt.IsZero())
				_, err = s.Load(ctx, opID(2))
				require.ErrorIs(t, err, oidcprovider.ErrNotFound)
			},
		},
		{
			name: "a failed end inside a caller's transaction leaves it usable, with its earlier work and none of its own",
			assert: func(t *testing.T, ctx context.Context, conn database) {
				assertFailedUnit(ctx, t, conn, func(ctx context.Context, s oidcprovider.GrantStore) error {
					_, err := s.EndSignIns(ctx, oidcprovider.SignInSelector{User: "u-1"}, at)
					return err
				})
			},
		},
		{
			name: "a failed revocation inside a caller's transaction leaves it usable, with its earlier work and none of its own",
			assert: func(t *testing.T, ctx context.Context, conn database) {
				assertFailedUnit(ctx, t, conn, func(ctx context.Context, s oidcprovider.GrantStore) error {
					_, err := s.RevokeByUser(ctx, "u-1", oidcprovider.CauseRecovery, at)
					return err
				})
			},
		},
		{
			name: "an end revokes a stored grant only a code names, without marking or reporting it",
			assert: func(t *testing.T, ctx context.Context, conn database) {
				codes := must.Must(oidcprovider.NewMemoryCodeStore())
				require.NoError(t, codes.Create(ctx, &oidcprovider.CodeRecord{
					TokenID: opID(50), GrantFamily: opID(1), SignIn: oidcprovider.SignIn{User: "u-1", Family: opID(7)},
				}))
				s := newGrantStore(t, conn.Pool)
				require.NoError(t, s.UseCodes(codes))
				require.NoError(t, s.Create(ctx, &oidcprovider.Grant{Family: opID(1), User: "u-2", CreatedAt: opTime}))

				ended, err := s.EndSignIns(ctx, oidcprovider.SignInSelector{User: "u-1"}, at)
				require.NoError(t, err)
				assert.Empty(t, ended, "it is not a grant this end selected")

				got, err := s.Load(ctx, opID(1))
				require.NoError(t, err)
				assert.True(t, got.Revoked)
				assert.Equal(t, oidcprovider.CauseSignInEnded, got.RevokeCause)
				assert.True(t, got.SignInEndedAt.IsZero())
			},
		},
		{
			name: "a grant stored while an end waits for a row is left to the next end, as it could take no lock in order",
			assert: func(t *testing.T, ctx context.Context, conn database) {
				s := joined(t, conn.Pool)
				sel := oidcprovider.SignInSelector{User: "u-1"}
				require.NoError(t, s.Create(ctx, &oidcprovider.Grant{Family: opID(1), User: "u-1", CreatedAt: opTime}))

				blocker, err := conn.Pool.Begin(ctx)
				require.NoError(t, err)
				defer func() { _ = blocker.Rollback(context.WithoutCancel(ctx)) }()
				_, err = blocker.Exec(ctx, `SELECT 1 FROM op_grants WHERE family = $1 FOR UPDATE`, opID(1).String())
				require.NoError(t, err)

				var ended []oidcprovider.Grant
				var endErr error
				var wg sync.WaitGroup
				wg.Go(func() { ended, endErr = s.EndSignIns(ctx, sel, at) })
				require.Eventually(t, func() bool {
					var waiting int
					err := conn.DB.QueryRowContext(ctx, `SELECT count(*) FROM pg_stat_activity
WHERE datname = current_database() AND wait_event_type = 'Lock'`).Scan(&waiting)

					return err == nil && waiting == 1
				}, 20*time.Second, 5*time.Millisecond)

				require.NoError(t, s.Create(ctx, &oidcprovider.Grant{Family: opID(2), User: "u-1", CreatedAt: opTime}))
				require.NoError(t, blocker.Rollback(ctx))
				wg.Wait()

				require.NoError(t, endErr)
				require.Len(t, ended, 1)
				assert.Equal(t, opID(1), ended[0].Family)

				later, err := s.EndSignIns(ctx, sel, at)
				require.NoError(t, err)
				require.Len(t, later, 1, "the next end finds it")
				assert.Equal(t, opID(2), later[0].Family)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, t.Context(), migrated(t))
		})
	}
}

// assertFailedUnit makes a many-grant call fail on the server, by a trigger refusing the
// write to the stored grant it selects, after the unit has already recorded a revocation
// for an outstanding code. A caller's transaction must still answer, with its earlier
// revocation, and without the one the failed call recorded.
func assertFailedUnit(ctx context.Context, t *testing.T, conn database, call func(ctx context.Context, s oidcprovider.GrantStore) error) {
	t.Helper()

	stored, earlier, outstanding := opID(1), opID(2), opID(3)
	at := opTime.Add(time.Minute)

	codes := must.Must(oidcprovider.NewMemoryCodeStore())
	require.NoError(t, codes.Create(ctx, &oidcprovider.CodeRecord{
		TokenID: opID(50), GrantFamily: outstanding, SignIn: oidcprovider.SignIn{User: "u-1", Family: opID(7)},
	}))
	s := newGrantStore(t, conn.Pool)
	require.NoError(t, s.UseCodes(codes))
	require.NoError(t, s.Create(ctx, &oidcprovider.Grant{Family: stored, User: "u-1", CreatedAt: opTime}))

	_, err := conn.DB.ExecContext(ctx, `CREATE FUNCTION test_refuse_grant_write() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'refused by the test'; END $$;
CREATE TRIGGER test_refuse_grant_write BEFORE UPDATE ON op_grants
FOR EACH ROW EXECUTE FUNCTION test_refuse_grant_write()`)
	require.NoError(t, err)

	tx, err := conn.Pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	txCtx := pgxstore.WithTx(ctx, tx)
	require.NoError(t, s.Revoke(txCtx, earlier, oidcprovider.CauseReuse, at))

	err = call(txCtx, s)
	require.ErrorContains(t, err, "refused by the test", "the statement must have failed on the server")

	got, err := s.Load(txCtx, earlier)
	require.NoError(t, err, "the transaction still answers")
	assert.True(t, got.Revoked, "with its earlier work")

	_, err = s.Load(txCtx, outstanding)
	require.ErrorIs(t, err, oidcprovider.ErrNotFound, "and what the failed call recorded is undone")

	require.NoError(t, tx.Commit(ctx), "and it can still commit")
}

// isDeadlock reports whether err is PostgreSQL ending one side of a deadlock.
func isDeadlock(err error) bool {
	var pg *pgconn.PgError

	return errors.As(err, &pg) && pg.Code == "40P01"
}

// orderID is the n-th identifier of round r of the lock-order tests. Its order is its
// numeric order, within a round.
func orderID(r, n int) id.ID {
	return id.MustParse(fmt.Sprintf("01926a4e-%04x-7000-8000-%012x", r, n))
}

// orderFamilies is how many grants, and how many outstanding codes, a round holds.
const orderFamilies = 8

// grantCall is one call the lock-order tests race.
type grantCall func(ctx context.Context, s oidcprovider.GrantStore, r int) error

func orderUser(r int) identity.UserID { return identity.UserID(fmt.Sprintf("order-u-%d", r)) }

var (
	callEnd grantCall = func(ctx context.Context, s oidcprovider.GrantStore, r int) error {
		_, err := s.EndSignIns(ctx, oidcprovider.SignInSelector{User: orderUser(r)}, opTime.Add(time.Minute))
		return err
	}
	callRevokeUser grantCall = func(ctx context.Context, s oidcprovider.GrantStore, r int) error {
		_, err := s.RevokeByUser(ctx, orderUser(r), oidcprovider.CauseRecovery, opTime.Add(time.Minute))
		return err
	}
	callRevokeClient grantCall = func(ctx context.Context, s oidcprovider.GrantStore, r int) error {
		_, err := s.RevokeByUserAndClient(ctx, orderUser(r), "c-1", oidcprovider.CauseRecovery, opTime.Add(time.Minute))
		return err
	}
	// callSweep removes everything a round holds: its deadline and its revocation have
	// both passed.
	callSweep grantCall = func(ctx context.Context, s oidcprovider.GrantStore, _ int) error {
		_, err := s.DeleteExpired(ctx, opTime.Add(2*time.Hour), time.Hour)
		return err
	}
)

// orderFixture is the store a lock-order test races, and its codes.
type orderFixture struct {
	s     oidcprovider.GrantStore
	codes oidcprovider.CodeStore
}

// seedInterleaved gives round r's user stored grants at the odd families, and outstanding
// codes for the even ones, so what a call writes interleaves in family order. It stores
// them highest first, so a scan meets them in the opposite order to the family's.
func (f orderFixture) seedInterleaved(ctx context.Context, t *testing.T, r int) {
	t.Helper()

	for i := orderFamilies - 1; i >= 0; i-- {
		require.NoError(t, f.s.Create(ctx, &oidcprovider.Grant{
			Family: orderID(r, 2*i+1), User: orderUser(r), ClientID: "c-1", CreatedAt: opTime, ExpiresAt: opTime.Add(time.Hour),
		}))
		require.NoError(t, f.codes.Create(ctx, &oidcprovider.CodeRecord{
			TokenID: orderID(r, 1000+i), ClientID: "c-1", GrantFamily: orderID(r, 2*i),
			SignIn: oidcprovider.SignIn{User: orderUser(r), Family: opID(70)}, ExpiresAt: opTime.Add(time.Hour),
		}))
	}
}

// orderSignIn is one of the two sign-ins of round r in seedCrossed.
func orderSignIn(r, which int) id.ID { return orderID(r, 2000+which) }

// seedCrossed gives each of round r's two sign-ins the stored grants the other's
// outstanding codes name. Each end's two sets are then the other's the other way round,
// so an end that took either set first, always the same one, would still deadlock.
func (f orderFixture) seedCrossed(ctx context.Context, t *testing.T, r int) {
	t.Helper()

	for i := range orderFamilies {
		for which := range 2 {
			mine, theirs := orderID(r, 2*i+which), orderID(r, 2*i+1-which)
			require.NoError(t, f.s.Create(ctx, &oidcprovider.Grant{
				Family: mine, User: orderUser(r), ClientID: "c-1", SignInFamily: orderSignIn(r, which),
				CreatedAt: opTime, ExpiresAt: opTime.Add(time.Hour),
			}))
			require.NoError(t, f.codes.Create(ctx, &oidcprovider.CodeRecord{
				TokenID: orderID(r, 1000+2*i+which), ClientID: "c-1", GrantFamily: theirs,
				SignIn: oidcprovider.SignIn{User: orderUser(r), Family: orderSignIn(r, which)}, ExpiresAt: opTime.Add(time.Hour),
			}))
		}
	}
}

// assertAllRevoked requires every family a round holds to end revoked: neither call lost
// the other's work.
func (f orderFixture) assertAllRevoked(ctx context.Context, t *testing.T, r int) {
	t.Helper()

	for n := range 2 * orderFamilies {
		got, err := f.s.Load(ctx, orderID(r, n))
		require.NoError(t, err)
		assert.True(t, got.Revoked, "round %d: family %d was left live", r, n)
	}
}

// TestPgxStore_GrantLockOrder races the operations writing many grants, with nothing
// staged and no blocker, each pair over rounds of its own. Every grant of a round is
// written by both, so a pair not agreeing on one order deadlocks in most rounds, and
// PostgreSQL then ends one call with 40P01 and its write is lost. A round is one meeting,
// decided by a short window, so it takes many.
func TestPgxStore_GrantLockOrder(t *testing.T) {
	t.Parallel()

	const rounds = 30

	seedInterleaved := orderFixture.seedInterleaved
	// Whether a sweep's or a revocation's write lands first, a row is either gone or
	// revoked, so all a race with the sweep can show is that neither call fails.
	neitherFailed := func(orderFixture, context.Context, *testing.T, int) {}

	cases := []struct {
		name          string
		seed          func(f orderFixture, ctx context.Context, t *testing.T, r int)
		first, second grantCall
		assert        func(f orderFixture, ctx context.Context, t *testing.T, r int)
	}{
		{name: "an end and a user's revocation", seed: seedInterleaved, first: callEnd, second: callRevokeUser, assert: orderFixture.assertAllRevoked},
		{name: "an end and a client's revocation", seed: seedInterleaved, first: callEnd, second: callRevokeClient, assert: orderFixture.assertAllRevoked},
		{name: "a user's revocation and a client's", seed: seedInterleaved, first: callRevokeUser, second: callRevokeClient, assert: orderFixture.assertAllRevoked},
		{name: "two ends", seed: seedInterleaved, first: callEnd, second: callEnd, assert: orderFixture.assertAllRevoked},
		{name: "two of a user's revocations", seed: seedInterleaved, first: callRevokeUser, second: callRevokeUser, assert: orderFixture.assertAllRevoked},
		{name: "two of a client's revocations", seed: seedInterleaved, first: callRevokeClient, second: callRevokeClient, assert: orderFixture.assertAllRevoked},
		{
			name: "two ends of sign-ins naming each other's grants",
			seed: orderFixture.seedCrossed,
			first: func(ctx context.Context, s oidcprovider.GrantStore, r int) error {
				_, err := s.EndSignIns(ctx, oidcprovider.SignInSelector{Family: orderSignIn(r, 0)}, opTime.Add(time.Minute))
				return err
			},
			second: func(ctx context.Context, s oidcprovider.GrantStore, r int) error {
				_, err := s.EndSignIns(ctx, oidcprovider.SignInSelector{Family: orderSignIn(r, 1)}, opTime.Add(time.Minute))
				return err
			},
			assert: orderFixture.assertAllRevoked,
		},
		{name: "the sweep and a user's revocation", seed: seedInterleaved, first: callSweep, second: callRevokeUser, assert: neitherFailed},
		{name: "the sweep and an end", seed: seedInterleaved, first: callSweep, second: callEnd, assert: neitherFailed},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			conn := migrated(t)
			pool := conn.Pool
			f := orderFixture{s: newGrantStore(t, pool), codes: newCodeStore(t, pool)}
			require.NoError(t, f.s.UseCodes(f.codes))

			deadlocks := 0
			for r := range rounds {
				tc.seed(f, ctx, t, r)

				start := make(chan struct{})
				errs := make([]error, 2)
				var wg sync.WaitGroup
				for i, call := range []grantCall{tc.first, tc.second} {
					wg.Go(func() {
						<-start
						errs[i] = call(ctx, f.s, r)
					})
				}
				close(start)
				wg.Wait()

				for _, err := range errs {
					if isDeadlock(err) {
						deadlocks++
					} else {
						require.NoError(t, err, "round %d", r)
					}
				}
				if !isDeadlock(errs[0]) && !isDeadlock(errs[1]) {
					tc.assert(f, ctx, t, r)
				}
			}
			assert.Zero(t, deadlocks, "calls ended by a deadlock (40P01), in %d rounds", rounds)
		})
	}
}

// TestPgxStore_GrantLockOrderOverDifferentSets races pairs of calls holding different
// sets of one user's grants, one of them all of the user's and the other those of one
// client, so the sets overlap and neither holds the other's. Each call's set is large and
// stored in a random order, so a call taking its rows in the order it meets them takes
// them in an order of its own, and the pair deadlocks, which only an agreed order
// prevents. The pairs of TestPgxStore_GrantLockOrder hold identical sets, and so cannot
// tell a call that sorts its rows from one that scans them the same way as the other.
func TestPgxStore_GrantLockOrderOverDifferentSets(t *testing.T) {
	t.Parallel()

	const rounds, perClient = 20, 300

	cases := []struct {
		name          string
		first, second grantCall
	}{
		{name: "an end and a client's revocation", first: callEnd, second: callRevokeClient},
		{name: "a user's revocation and a client's", first: callRevokeUser, second: callRevokeClient},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			conn := migrated(t)
			db, pool := conn.DB, conn.Pool
			f := orderFixture{s: newGrantStore(t, pool), codes: newCodeStore(t, pool)}
			require.NoError(t, f.s.UseCodes(f.codes))

			deadlocks := 0
			for r := range rounds {
				// Two clients' grants alternate in family order and are stored in a
				// random one, so the client's set is a strict, interleaved subset.
				_, err := db.ExecContext(ctx, `INSERT INTO op_grants (family, user_ref, client_id, created_at, expires_at)
SELECT format('01926a4e-%s-7000-8000-%s', lpad(to_hex($1::int), 4, '0'), lpad(to_hex(i), 12, '0'))::uuid,
  $2, CASE WHEN i % 2 = 0 THEN 'c-1' ELSE 'c-2' END, $3::timestamptz, $4::timestamptz
FROM generate_series(1, $5::int) AS i ORDER BY random()`,
					r, string(orderUser(r)), opTime, opTime.Add(time.Hour), 2*perClient)
				require.NoError(t, err)

				start := make(chan struct{})
				errs := make([]error, 2)
				var wg sync.WaitGroup
				for i, call := range []grantCall{tc.first, tc.second} {
					wg.Go(func() {
						<-start
						errs[i] = call(ctx, f.s, r)
					})
				}
				close(start)
				wg.Wait()

				for _, err := range errs {
					if isDeadlock(err) {
						deadlocks++
					} else {
						require.NoError(t, err, "round %d", r)
					}
				}
			}
			assert.Zero(t, deadlocks, "calls ended by a deadlock (40P01), in %d rounds", rounds)
		})
	}
}

// TestPgxStore_GrantLockOrderStaged lines each pair up on a row a blocker holds, so that
// a pair not agreeing on one order is sure to deadlock when the blocker lets go: the
// first call holds rows past it, and the second rows before it.
func TestPgxStore_GrantLockOrderStaged(t *testing.T) {
	t.Parallel()

	before, middle, after := opID(1), opID(5), opID(9)
	at := opTime.Add(time.Minute)
	user := orderUser(0)

	stored := func(family id.ID) *oidcprovider.Grant {
		return &oidcprovider.Grant{Family: family, User: user, ClientID: "c-1", CreatedAt: opTime, ExpiresAt: opTime.Add(time.Hour)}
	}
	outstanding := func(n int, family id.ID) *oidcprovider.CodeRecord {
		return &oidcprovider.CodeRecord{
			TokenID: opID(50 + n), ClientID: "c-1", GrantFamily: family,
			SignIn: oidcprovider.SignIn{User: user, Family: opID(70)}, ExpiresAt: opTime.Add(time.Hour),
		}
	}

	// The end holds the code's family before the blocked one, and wants the stored grant
	// the revocation takes first.
	seedRevocation := func(t *testing.T, ctx context.Context, f orderFixture) id.ID {
		t.Helper()
		require.NoError(t, f.s.Create(ctx, stored(middle)))
		require.NoError(t, f.s.Revoke(ctx, after, oidcprovider.CauseReuse, at))
		require.NoError(t, f.codes.Create(ctx, outstanding(0, before)))
		require.NoError(t, f.codes.Create(ctx, outstanding(1, after)))

		return after
	}

	bothSucceeded := func(t *testing.T, errs [2]error) {
		t.Helper()
		assert.NoError(t, errs[0], "the first call")
		assert.NoError(t, errs[1], "the second call")
	}

	cases := []struct {
		name          string
		seed          func(t *testing.T, ctx context.Context, f orderFixture) id.ID
		first, second grantCall
		assert        func(t *testing.T, errs [2]error)
	}{
		{
			name: "an end and a user's revocation", seed: seedRevocation, first: callEnd, second: callRevokeUser,
			assert: bothSucceeded,
		},
		{
			name: "an end and a client's revocation", seed: seedRevocation, first: callEnd, second: callRevokeClient,
			assert: bothSucceeded,
		},
		{
			// Stored highest first, so a scan takes the rows in descending family order.
			name: "the sweep and a user's revocation",
			seed: func(t *testing.T, ctx context.Context, f orderFixture) id.ID {
				t.Helper()
				for _, family := range []id.ID{after, middle, before} {
					require.NoError(t, f.s.Create(ctx, stored(family)))
				}

				return middle
			},
			first: callSweep, second: callRevokeUser,
			assert: bothSucceeded,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			conn := migrated(t)
			db, pool := conn.DB, conn.Pool
			f := orderFixture{s: newGrantStore(t, pool), codes: newCodeStore(t, pool)}
			require.NoError(t, f.s.UseCodes(f.codes))
			held := tc.seed(t, ctx, f)

			awaitWaiters := func(n int) {
				t.Helper()
				require.Eventually(t, func() bool {
					var got int
					err := db.QueryRowContext(ctx, `SELECT count(*) FROM pg_stat_activity
WHERE datname = current_database() AND wait_event_type = 'Lock' AND pid <> pg_backend_pid()`).Scan(&got)

					return err == nil && got >= n
				}, 20*time.Second, 5*time.Millisecond)
			}

			blocker, err := db.BeginTx(ctx, nil)
			require.NoError(t, err)
			defer func() { _ = blocker.Rollback() }()
			_, err = blocker.ExecContext(ctx, `SELECT 1 FROM op_grants WHERE family = $1 FOR UPDATE`, held.String())
			require.NoError(t, err)

			var errs [2]error
			var wg sync.WaitGroup
			wg.Go(func() { errs[0] = tc.first(ctx, f.s, 0) })
			awaitWaiters(1)
			wg.Go(func() { errs[1] = tc.second(ctx, f.s, 0) })
			awaitWaiters(2)
			require.NoError(t, blocker.Rollback())
			wg.Wait()

			tc.assert(t, errs)
		})
	}
}

// TestPgxStore_ConsentsAccumulateConcurrently gives one consent many scopes at once. A
// store that reads the scopes and writes them back separately loses some.
func TestPgxStore_ConsentsAccumulateConcurrently(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	s := newConsentStore(t, migrated(t).Pool)

	const givers = 24
	errs := make(chan error, givers)
	want := make([]string, 0, givers)
	for i := range givers {
		scope := fmt.Sprintf("scope-%d", i)
		want = append(want, scope)
		go func() { errs <- s.Give(ctx, "u-1", "c-1", []string{scope, "openid"}, false, opTime) }()
	}
	for range givers {
		require.NoError(t, <-errs)
	}

	got, err := s.Load(ctx, "u-1", "c-1")
	require.NoError(t, err)
	assert.ElementsMatch(t, append(want, "openid"), got.Scopes, "no scope is lost, and none is held twice")
}

// TestPgxStore_IdentifierGenerator covers the override of each store minting its rows'
// uuid: the row holds what the consumer's generator gave.
func TestPgxStore_IdentifierGenerator(t *testing.T) {
	t.Parallel()

	minted := opID(77)
	gen := pgxstore.WithIDGenerator(oneOpID{minted})

	cases := []struct {
		name  string
		table string
		write func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) error
	}{
		{"consents", pgschema.ConsentTable, func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) error {
			return newConsentStore(t, pool, gen).Give(ctx, "u-1", "c-1", nil, false, opTime)
		}},
		{"assertion identifiers", pgschema.AssertionIDTable, func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) error {
			_, err := newAssertionStore(t, pool, gen).Record(ctx, "c-1", "jti", opTime)
			return err
		}},
		{"browser sessions", pgschema.BrowserSessionTable, func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) error {
			return newBrowserStore(t, pool, gen).Put(ctx, &oidcprovider.BrowserSession{Digest: []byte{1}, IdleExpiresAt: opTime, AbsoluteExpiresAt: opTime})
		}},
		{"clients", pgschema.ClientTable, func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) error {
			return newClientStore(t, pool, gen).Put(ctx, confidentialClient("c-1"))
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			conn := migrated(t)
			require.NoError(t, tc.write(t, ctx, conn.Pool))

			var got id.ID
			// table is one of pgschema's constants.
			require.NoError(t, conn.DB.QueryRowContext(ctx, "SELECT id FROM "+tc.table).Scan(&got))
			assert.Equal(t, minted, got)
		})
	}
}

// oneOpID is a generator giving one identifier.
type oneOpID struct{ value id.ID }

func (f oneOpID) NewID() (id.ID, error) { return f.value, nil }

// TestPgxStore_NewOIDCProviderStores holds every constructor to the package's wiring rules.
func TestPgxStore_NewOIDCProviderStores(t *testing.T) {
	t.Parallel()

	pool := unreachablePool(t)
	c := storefix.TestCipher(t)

	type store = struct{ built bool }
	type ctor = func(pool *pgxpool.Pool, opts ...pgxstore.Option) (store, error)

	wrap := func(build func(pool *pgxpool.Pool, opts ...pgxstore.Option) error) ctor {
		return func(pool *pgxpool.Pool, opts ...pgxstore.Option) (store, error) {
			err := build(pool, opts...)

			return store{built: err == nil}, err
		}
	}

	ctors := map[string]struct {
		build     ctor
		mintsRows bool
		takesClk  bool
	}{
		"pending requests": {build: wrap(func(pool *pgxpool.Pool, o ...pgxstore.Option) error {
			_, err := pgxstore.NewPendingRequestStore(pool, o...)
			return err
		})},
		"codes": {build: wrap(func(pool *pgxpool.Pool, o ...pgxstore.Option) error {
			_, err := pgxstore.NewCodeStore(pool, o...)
			return err
		})},
		"grants": {build: wrap(func(pool *pgxpool.Pool, o ...pgxstore.Option) error {
			_, err := pgxstore.NewGrantStore(pool, o...)
			return err
		})},
		"access tokens": {build: wrap(func(pool *pgxpool.Pool, o ...pgxstore.Option) error {
			_, err := pgxstore.NewAccessTokenStore(pool, o...)
			return err
		})},
		"consents": {mintsRows: true, build: wrap(func(pool *pgxpool.Pool, o ...pgxstore.Option) error {
			_, err := pgxstore.NewConsentStore(pool, o...)
			return err
		})},
		"assertion identifiers": {mintsRows: true, build: wrap(func(pool *pgxpool.Pool, o ...pgxstore.Option) error {
			_, err := pgxstore.NewAssertionIDStore(pool, o...)
			return err
		})},
		"browser sessions": {mintsRows: true, build: wrap(func(pool *pgxpool.Pool, o ...pgxstore.Option) error {
			_, err := pgxstore.NewBrowserSessionStore(pool, o...)
			return err
		})},
		"clients": {mintsRows: true, build: wrap(func(pool *pgxpool.Pool, o ...pgxstore.Option) error {
			_, err := pgxstore.NewClientStore(pool, o...)
			return err
		})},
		"lineages": {mintsRows: true, takesClk: true, build: wrap(func(pool *pgxpool.Pool, o ...pgxstore.Option) error {
			_, err := pgxstore.NewRefreshTokenStore(pool, c, o...)
			return err
		})},
	}

	refused := func(t *testing.T, err error, text string) {
		t.Helper()
		require.ErrorIs(t, err, pgxstore.ErrConfig)
		assert.EqualError(t, err, "pgxstore: invalid configuration: "+text)
	}

	for name, tc := range ctors {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			s, err := tc.build(pool)
			require.NoError(t, err, "a pool is all it needs")
			assert.True(t, s.built)

			_, err = tc.build(nil)
			refused(t, err, "the pool is nil")

			_, err = tc.build(pool, pgxstore.WithResealOnRead(false))
			refused(t, err, "WithResealOnRead does not apply to this store")

			_, err = tc.build(pool, pgxstore.WithClock(clock.System()))
			if tc.takesClk {
				require.NoError(t, err)
			} else {
				refused(t, err, "WithClock does not apply to this store")
			}

			_, err = tc.build(pool, pgxstore.WithIDGenerator(id.NewV7Generator()))
			if tc.mintsRows {
				require.NoError(t, err)
			} else {
				refused(t, err, "WithIDGenerator does not apply to this store")
			}
		})
	}

	t.Run("lineages need a cipher, and have no zero value to hand out", func(t *testing.T) {
		t.Parallel()

		got, err := pgxstore.NewRefreshTokenStore(pool, nil)
		refused(t, err, "the cipher is nil")
		assert.Nil(t, oplineage.Sessions(got))
	})
}

// TestPgxStore_RecordsRoundTrip holds what pgx's own codecs return to what was written:
// identifiers exactly, times as UTC at the microsecond whatever zone they were given in,
// a zero time as the zero time, and an empty or absent list as the absent one.
func TestPgxStore_RecordsRoundTrip(t *testing.T) {
	t.Parallel()

	zoned := time.Date(2030, 2, 1, 9, 30, 15, 123456789, time.FixedZone("UTC+7", 7*3600))
	stored := zoned.UTC().Truncate(time.Microsecond)

	cases := []struct {
		name   string
		assert func(t *testing.T, ctx context.Context, pool *pgxpool.Pool)
	}{
		{"a grant's identifiers and times", func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
			s := newGrantStore(t, pool)
			want := oidcprovider.Grant{
				Family: opID(1), User: "u-1", ClientID: "c-1", Scopes: []string{"openid"}, CodeID: opID(2), SignInFamily: opID(3),
				AuthTime: zoned, CreatedAt: zoned, ExpiresAt: zoned.Add(time.Hour), HoldsLineage: true,
			}
			require.NoError(t, s.Create(ctx, &want))

			got, err := s.Load(ctx, opID(1))
			require.NoError(t, err)
			assert.Equal(t, opID(2), got.CodeID)
			assert.Equal(t, opID(3), got.SignInFamily)
			assert.Equal(t, stored, got.AuthTime)
			assert.Equal(t, stored, got.CreatedAt)
			assert.Equal(t, stored.Add(time.Hour), got.ExpiresAt)
			assert.Equal(t, time.UTC, got.CreatedAt.Location())
		}},
		{"a grant's nil identifiers and zero times", func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
			s := newGrantStore(t, pool)
			require.NoError(t, s.Create(ctx, &oidcprovider.Grant{Family: opID(1), User: "u-1"}))

			got, err := s.Load(ctx, opID(1))
			require.NoError(t, err)
			assert.True(t, got.CodeID.IsZero())
			assert.True(t, got.SignInFamily.IsZero())
			assert.True(t, got.AuthTime.IsZero())
			assert.True(t, got.CreatedAt.IsZero())
			assert.True(t, got.ExpiresAt.IsZero())
			assert.True(t, got.RevokedAt.IsZero())
			assert.Nil(t, got.Scopes)
			assert.Nil(t, got.AMR)
		}},
		{"a request's empty and absent lists", func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
			s := newPendingStore(t, pool)
			require.NoError(t, s.Create(ctx, &oidcprovider.PendingRequest{
				ID: opID(1), HandleDigest: []byte{1}, Scopes: []string{}, Resources: nil, Prompt: []string{"login"},
				ParkedAt: zoned, ExpiresAt: zoned.Add(time.Minute),
			}))

			got, err := s.Load(ctx, []byte{1})
			require.NoError(t, err)
			assert.Nil(t, got.Scopes, "an empty list reads back as none")
			assert.Nil(t, got.Resources)
			assert.Equal(t, []string{"login"}, got.Prompt)
			assert.Nil(t, got.MaxAge)
			assert.Equal(t, stored, got.ParkedAt)
			assert.Equal(t, stored.Add(time.Minute), got.ExpiresAt)
			assert.Equal(t, []byte{}, got.FlowDigest, "a NOT NULL digest column reads back empty, never nil-as-absent")
		}},
		{"an access token's identifiers and times", func(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
			s := newAccessTokenStore(t, pool)
			require.NoError(t, s.Create(ctx, &oidcprovider.AccessTokenRecord{
				ID: opID(1), Digest: []byte{9}, GrantFamily: opID(2), ClientID: "c-1", IssuedAt: zoned, ExpiresAt: zoned.Add(time.Minute),
			}))

			got, err := s.Load(ctx, opID(1))
			require.NoError(t, err)
			assert.Equal(t, opID(1), got.ID)
			assert.Equal(t, opID(2), got.GrantFamily)
			assert.Equal(t, stored, got.IssuedAt)
			assert.Equal(t, stored.Add(time.Minute), got.ExpiresAt)
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, t.Context(), migrated(t).Pool)
		})
	}
}
