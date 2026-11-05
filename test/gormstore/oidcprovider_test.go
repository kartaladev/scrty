package gormstore_test

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

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	gormdb "gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/internal/oplineage"
	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/store/gormstore"
	"github.com/kartaladev/scrty/store/seal"
	"github.com/kartaladev/scrty/store/sqlstore"
	"github.com/kartaladev/scrty/test/internal/storefix"
	"github.com/kartaladev/scrty/test/storetest"
	"github.com/kartaladev/scrty/token/onetime"
)

// opTime is the instant this file's own records are dated from.
var opTime = time.Date(2030, 2, 1, 9, 0, 0, 0, time.UTC)

// opID is the n-th identifier this file's own records use.
func opID(n int) id.ID { return id.MustParse(fmt.Sprintf("01926a4e-0000-7000-8000-%012x", n)) }

func newPendingStore(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) oidcprovider.PendingRequestStore {
	t.Helper()

	return must.Must(gormstore.NewPendingRequestStore(db, opts...))
}

func newCodeStore(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) oidcprovider.CodeStore {
	t.Helper()

	return must.Must(gormstore.NewCodeStore(db, opts...))
}

func newConsentStore(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) oidcprovider.ConsentStore {
	t.Helper()

	return must.Must(gormstore.NewConsentStore(db, opts...))
}

func newGrantStore(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) oidcprovider.GrantStore {
	t.Helper()

	return must.Must(gormstore.NewGrantStore(db, opts...))
}

func newAccessTokenStore(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) oidcprovider.AccessTokenStore {
	t.Helper()

	return must.Must(gormstore.NewAccessTokenStore(db, opts...))
}

func newAssertionStore(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) oidcprovider.AssertionIDStore {
	t.Helper()

	return must.Must(gormstore.NewAssertionIDStore(db, opts...))
}

func newBrowserStore(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) oidcprovider.BrowserSessionStore {
	t.Helper()

	return must.Must(gormstore.NewBrowserSessionStore(db, opts...))
}

func newClientStore(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) *gormstore.ClientStore {
	t.Helper()

	return must.Must(gormstore.NewClientStore(db, opts...))
}

// lineageSessions is the session store behind the lineage store over db.
func lineageSessions(t *testing.T, db *gormdb.DB, c seal.Cipher, opts ...gormstore.Option) session.Store {
	t.Helper()

	lineages, err := gormstore.NewRefreshTokenStore(db, c, opts...)
	require.NoError(t, err)

	return oplineage.Sessions(lineages)
}

// TestGormStore runs every provider store through its conformance suite, and the race
// suites over two connection pools. Each subtest takes a database of its own.
func TestGormStore(t *testing.T) {
	t.Parallel()

	suites := map[string]func(t *testing.T, d database){
		"PendingRequests": func(t *testing.T, d database) {
			storetest.PendingRequestSuite(t, func(t *testing.T) oidcprovider.PendingRequestStore {
				return newPendingStore(t, emptied(t, d, pgschema.PendingRequestTable))
			})
		},
		"CodeRecords": func(t *testing.T, d database) {
			storetest.CodeRecordSuite(t, func(t *testing.T) oidcprovider.CodeStore {
				return newCodeStore(t, emptied(t, d, pgschema.CodeTable))
			})
		},
		"Consents": func(t *testing.T, d database) {
			storetest.ConsentSuite(t, func(t *testing.T) oidcprovider.ConsentStore {
				return newConsentStore(t, emptied(t, d, pgschema.ConsentTable))
			})
		},
		"Grants": func(t *testing.T, d database) {
			storetest.GrantSuite(t, func(t *testing.T) oidcprovider.GrantStore {
				return newGrantStore(t, emptied(t, d, pgschema.GrantTable))
			})
		},
		"AccessTokens": func(t *testing.T, d database) {
			storetest.AccessTokenSuite(t, func(t *testing.T) oidcprovider.AccessTokenStore {
				return newAccessTokenStore(t, emptied(t, d, pgschema.AccessTokenTable))
			})
		},
		"AssertionIDs": func(t *testing.T, d database) {
			storetest.AssertionIDSuite(t, func(t *testing.T) oidcprovider.AssertionIDStore {
				return newAssertionStore(t, emptied(t, d, pgschema.AssertionIDTable))
			})
		},
		"BrowserSessions": func(t *testing.T, d database) {
			storetest.BrowserSessionSuite(t, func(t *testing.T) oidcprovider.BrowserSessionStore {
				return newBrowserStore(t, emptied(t, d, pgschema.BrowserSessionTable))
			})
		},
		"Lineages": func(t *testing.T, d database) {
			c := storefix.TestCipher(t)
			storetest.RunSessionStoreSuite(t, func(t *testing.T, clk clock.Clock) session.Store {
				return lineageSessions(t, emptied(t, d, pgschema.RefreshTokenTable), c, gormstore.WithClock(clk))
			})
		},
		"Races/PendingRequests": func(t *testing.T, d database) {
			storetest.RunAdvanceRace(t, durableHarness(d, newPendingStore))
		},
		"Races/CodeTokens": func(t *testing.T, d database) {
			storetest.RunCodeSpendRace(t, durableHarness(d, func(_ *testing.T, db *gormdb.DB, opts ...gormstore.Option) onetime.Store {
				return must.Must(gormstore.NewOneTimeStore(db, opts...))
			}))
		},
		"Races/AssertionIDs": func(t *testing.T, d database) {
			storetest.RunAssertionRecordRace(t, durableHarness(d, newAssertionStore))
		},
		"Races/Grants": func(t *testing.T, d database) {
			storetest.RunGrantRaces(t, durableHarness(d, newGrantStore))
		},
		"Races/GrantLockOrder": func(t *testing.T, d database) {
			storetest.RunGrantOrderRaces(t, durableHarness(d, newGrantStore))
		},
		"Races/BrowserSessions": func(t *testing.T, d database) {
			storetest.RunTouchRace(t, durableHarness(d, newBrowserStore))
		},
		"Races/Lineages": func(t *testing.T, d database) {
			c := storefix.TestCipher(t)
			storetest.RunSessionSupersessionRace(t, durableHarness(d, func(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) session.Store {
				return lineageSessions(t, db, c, opts...)
			}))
		},
	}

	for name, run := range suites {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			run(t, migratedDB(t))
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
	_ storetest.ClientRotator = (*gormstore.ClientStore)(nil)
	_ storetest.ClientRotator = (*oidcprovider.MemoryRegistry)(nil)
)

// TestGormStore_Clients runs the client suite over the store and over the in-memory
// registry, so what differs between them fails for the one that differs.
func TestGormStore_Clients(t *testing.T) {
	t.Parallel()

	d := migratedDB(t)
	backends := map[string]func(t *testing.T) oidcprovider.ClientStore{
		"memory": func(*testing.T) oidcprovider.ClientStore { return must.Must(oidcprovider.NewMemoryRegistry(nil)) },
		"gormstore": func(t *testing.T) oidcprovider.ClientStore {
			return newClientStore(t, emptied(t, d, pgschema.ClientTable))
		},
	}

	for backend, newStore := range backends {
		t.Run(backend, func(t *testing.T) { storetest.ClientStoreSuite(t, newStore) })
	}
}

// TestGormStore_ClientSecretsStoredForm pins what the secrets column holds: SecretBytes
// marshals redacted, so a stored form that marshals it would lose every digest.
func TestGormStore_ClientSecretsStoredForm(t *testing.T) {
	t.Parallel()

	d := migratedDB(t)
	db, g := d.conn.DB, d.db
	s := newClientStore(t, g)

	c := confidentialClient("c-1")
	c.Secret = clientSecretBytes
	require.NoError(t, s.Put(t.Context(), c))

	var stored string
	require.NoError(t, db.QueryRowContext(t.Context(), `SELECT secrets::text FROM op_clients WHERE client_id = 'c-1'`).Scan(&stored))

	assert.NotContains(t, stored, "REDACTED", "the digest must be stored, not its redacted form")
	assert.NotContains(t, stored, string(clientSecretBytes), "the secret itself must not be stored")

	digest := sha256.Sum256(clientSecretBytes)
	assert.Contains(t, stored, base64.RawURLEncoding.EncodeToString(digest[:]))

	generated, err := s.GenerateSecret(t.Context(), "c-1")
	require.NoError(t, err)
	require.NoError(t, db.QueryRowContext(t.Context(), `SELECT secrets::text FROM op_clients WHERE client_id = 'c-1'`).Scan(&stored))

	assert.NotContains(t, stored, "REDACTED", "a generated secret's digest must be stored, not its redacted form")
	assert.NotContains(t, stored, generated)
	generatedDigest := sha256.Sum256([]byte(generated))
	assert.Contains(t, stored, base64.RawURLEncoding.EncodeToString(generatedDigest[:]))
}

// TestGormStore_LineageIsNotASession proves the two stores share no table, in both
// directions, whatever the identifier.
func TestGormStore_LineageIsNotASession(t *testing.T) {
	t.Parallel()

	d := migratedDB(t)
	db, g := d.conn.DB, d.db
	c := storefix.TestCipher(t)
	sessions := newSessionStore(t, g, c)
	lineages := lineageSessions(t, g, c)

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

// TestGormStore_NoCredentialInAnyColumn reads every provider table directly, after a
// record of each kind was stored for a code, a handle, a flow secret, a browser session,
// a refresh token, an access token and a client secret, and looks for each secret in
// every column in the forms it could be written in.
func TestGormStore_NoCredentialInAnyColumn(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	d := migratedDB(t)
	db, g := d.conn.DB, d.db

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
	require.NoError(t, newPendingStore(t, g).Create(ctx, &oidcprovider.PendingRequest{
		ID: opID(2), HandleDigest: digest(handle), FlowDigest: digest(flow), ClientID: "c-1",
		ParkedAt: opTime, ExpiresAt: opTime.Add(time.Minute), SignIn: &signIn,
	}))
	require.NoError(t, newCodeStore(t, g).Create(ctx, &oidcprovider.CodeRecord{
		TokenID: opID(3), ClientID: "c-1", SignIn: signIn, GrantFamily: opID(4), ExpiresAt: opTime.Add(time.Minute),
	}))
	require.NoError(t, newBrowserStore(t, g).Put(ctx, &oidcprovider.BrowserSession{
		Digest: digest(browser), SignIn: signIn, IdleExpiresAt: opTime.Add(time.Minute), AbsoluteExpiresAt: opTime.Add(time.Hour),
	}))
	require.NoError(t, newAccessTokenStore(t, g).Create(ctx, &oidcprovider.AccessTokenRecord{
		ID: opID(5), Digest: digest(access), GrantFamily: opID(4), ClientID: "c-1", User: "u-1",
		IssuedAt: opTime, ExpiresAt: opTime.Add(time.Minute),
	}))
	require.NoError(t, newGrantStore(t, g).Create(ctx, &oidcprovider.Grant{
		Family: opID(4), User: "u-1", ClientID: "c-1", CodeID: opID(3), SignInFamily: opID(1), HoldsLineage: true,
		CreatedAt: opTime, ExpiresAt: opTime.Add(time.Hour),
	}))
	require.NoError(t, lineageSessions(t, g, storefix.TestCipher(t)).Create(ctx, opSession(refresh, opID(4))))

	clients := newClientStore(t, g)
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

// TestGormStore_Unstorable holds every write and lookup to its answer for text PostgreSQL
// cannot hold, which the provider refuses first and a store must still survive: an error
// that repeats no part of the value, and nothing written.
func TestGormStore_Unstorable(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	d := migratedDB(t)
	db, g := d.conn.DB, d.db
	at := opTime

	for name, bad := range map[string]string{"a NUL byte": "bad\x00value", "invalid UTF-8": "bad\xffvalue"} {
		signIn := oidcprovider.SignIn{User: "u-1", Family: opID(1), AMR: []string{bad}}

		cases := []struct {
			name string
			call func() error
		}{
			{"pending request text", func() error {
				return newPendingStore(t, g).Create(ctx, &oidcprovider.PendingRequest{ID: opID(2), HandleDigest: []byte{1}, ClientID: bad})
			}},
			{"pending request list", func() error {
				return newPendingStore(t, g).Create(ctx, &oidcprovider.PendingRequest{ID: opID(2), HandleDigest: []byte{1}, Scopes: []string{bad}})
			}},
			{"pending request's sign-in", func() error {
				return newPendingStore(t, g).Create(ctx, &oidcprovider.PendingRequest{ID: opID(2), HandleDigest: []byte{1}, SignIn: &signIn})
			}},
			{"advance's sign-in", func() error {
				return newPendingStore(t, g).Advance(ctx, []byte{1}, oidcprovider.StageLogin, oidcprovider.StageDone, &signIn)
			}},
			{"code text", func() error {
				return newCodeStore(t, g).Create(ctx, &oidcprovider.CodeRecord{TokenID: opID(3), Nonce: bad})
			}},
			{"code's sign-in", func() error {
				return newCodeStore(t, g).Create(ctx, &oidcprovider.CodeRecord{TokenID: opID(3), SignIn: signIn})
			}},
			{"code listing by selector", func() error {
				_, err := newCodeStore(t, g).UnspentBySignIn(ctx, oidcprovider.SignInSelector{User: "u-1", ExternalIssuer: bad}, false)
				return err
			}},
			{"code listing by client", func() error {
				_, err := newCodeStore(t, g).UnspentByClient(ctx, "u-1", bad)
				return err
			}},
			{"consent user", func() error { return newConsentStore(t, g).Give(ctx, "u-1", bad, nil, false, at) }},
			{"consent scope", func() error { return newConsentStore(t, g).Give(ctx, "u-1", "c-1", []string{bad}, false, at) }},
			{"consent load", func() error {
				_, err := newConsentStore(t, g).Load(ctx, "u-1", bad)
				return err
			}},
			{"consent revoke", func() error {
				_, err := newConsentStore(t, g).Revoke(ctx, "u-1", bad)
				return err
			}},
			{"consent listing", func() error {
				_, err := newConsentStore(t, g).ListByUser(ctx, "bad\x00user")
				return err
			}},
			{"grant text", func() error {
				return newGrantStore(t, g).Create(ctx, &oidcprovider.Grant{Family: opID(4), ClientID: bad})
			}},
			{"grant certificate binding", func() error {
				return newGrantStore(t, g).Create(ctx, &oidcprovider.Grant{Family: opID(4), CertBinding: bad})
			}},
			{"grant list", func() error {
				return newGrantStore(t, g).Create(ctx, &oidcprovider.Grant{Family: opID(4), AMR: []string{bad}})
			}},
			{"grant cause", func() error {
				return revokeErr(newGrantStore(t, g).Revoke(ctx, opID(4), oidcprovider.RevocationCause(bad), at))
			}},
			{"access token text", func() error {
				return newAccessTokenStore(t, g).Create(ctx, &oidcprovider.AccessTokenRecord{ID: opID(5), ClientID: bad})
			}},
			{"access token confirmation", func() error {
				return newAccessTokenStore(t, g).Create(ctx, &oidcprovider.AccessTokenRecord{ID: opID(5), Confirmation: map[string]string{"jkt": bad}})
			}},
			{"assertion identifier", func() error {
				_, err := newAssertionStore(t, g).Record(ctx, "c-1", bad, at)
				return err
			}},
			{"browser session's sign-in", func() error {
				return newBrowserStore(t, g).Put(ctx, &oidcprovider.BrowserSession{Digest: []byte{1}, SignIn: signIn, IdleExpiresAt: at, AbsoluteExpiresAt: at})
			}},
			{"browser session selector", func() error {
				_, err := newBrowserStore(t, g).DeleteBySignIn(ctx, oidcprovider.SignInSelector{User: "u-1", ExternalIssuer: bad})
				return err
			}},
			{"client text", func() error {
				c := confidentialClient("c-1")
				c.Name = bad
				return newClientStore(t, g).Put(ctx, c)
			}},
			{"client metadata", func() error {
				c := confidentialClient("c-1")
				c.Metadata = map[string]string{"k": bad}
				return newClientStore(t, g).Put(ctx, c)
			}},
			{"client lookup", func() error {
				_, err := newClientStore(t, g).Client(ctx, bad)
				return err
			}},
			{"client delete", func() error { return newClientStore(t, g).Delete(ctx, bad) }},
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

// TestGormStore_ErrorsCarryNoDigest makes each digest-keyed statement fail for real, by
// dropping its table, and requires the failure's text to carry no digest.
func TestGormStore_ErrorsCarryNoDigest(t *testing.T) {
	t.Parallel()

	digest := sha256.Sum256(clientSecretBytes)

	cases := []struct {
		name  string
		table string
		call  func(t *testing.T, ctx context.Context, d database) error
	}{
		{"pending create", pgschema.PendingRequestTable, func(t *testing.T, ctx context.Context, d database) error {
			g := d.db
			return newPendingStore(t, g).Create(ctx, &oidcprovider.PendingRequest{ID: opID(1), HandleDigest: digest[:], FlowDigest: digest[:]})
		}},
		{"pending load", pgschema.PendingRequestTable, func(t *testing.T, ctx context.Context, d database) error {
			g := d.db
			_, err := newPendingStore(t, g).Load(ctx, digest[:])
			return err
		}},
		{"browser put", pgschema.BrowserSessionTable, func(t *testing.T, ctx context.Context, d database) error {
			g := d.db
			return newBrowserStore(t, g).Put(ctx, &oidcprovider.BrowserSession{Digest: digest[:], IdleExpiresAt: opTime, AbsoluteExpiresAt: opTime})
		}},
		{"browser touch", pgschema.BrowserSessionTable, func(t *testing.T, ctx context.Context, d database) error {
			g := d.db
			return newBrowserStore(t, g).Touch(ctx, digest[:], opTime)
		}},
		{"access token create", pgschema.AccessTokenTable, func(t *testing.T, ctx context.Context, d database) error {
			g := d.db
			return newAccessTokenStore(t, g).Create(ctx, &oidcprovider.AccessTokenRecord{ID: opID(1), Digest: digest[:]})
		}},
		{"client put", pgschema.ClientTable, func(t *testing.T, ctx context.Context, d database) error {
			g := d.db
			c := confidentialClient("c-1")
			c.Secret = clientSecretBytes
			return newClientStore(t, g).Put(ctx, c)
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			d := migratedDB(t)
			db := d.conn.DB
			// The set's rollback drops with IF EXISTS, so it survives this.
			_, err := db.ExecContext(ctx, "DROP TABLE "+tc.table)
			require.NoError(t, err)

			err = tc.call(t, ctx, d)
			require.Error(t, err)
			assert.False(t, errors.Is(err, oidcprovider.ErrNotFound), "a failure is never reported as absence")
			for _, text := range storefix.ErrorTexts(err) {
				assert.NotContains(t, text, string(digest[:]))
				assert.NotContains(t, text, hex.EncodeToString(digest[:]))
				assert.NotContains(t, text, base64.RawURLEncoding.EncodeToString(digest[:]))
			}
		})
	}
}

// TestGormStore_GrantRows pins the rows the migration's comments promise, and the cases a
// suite cannot reach through a port: NULL must read as different, a stored grant's zero
// time must never read as a tombstone, and a caller's transaction owns what is written.
func TestGormStore_GrantRows(t *testing.T) {
	t.Parallel()

	at := opTime.Add(time.Minute)
	joined := func(t *testing.T, g *gormdb.DB) oidcprovider.GrantStore {
		t.Helper()
		s := newGrantStore(t, g)
		require.NoError(t, s.UseCodes(must.Must(oidcprovider.NewMemoryCodeStore())))

		return s
	}

	cases := []struct {
		name   string
		assert func(t *testing.T, ctx context.Context, d database)
	}{
		{
			name: "every family but one selects a grant with no sign-in family",
			assert: func(t *testing.T, ctx context.Context, d database) {
				db := d.conn.DB
				s := joined(t, d.db)
				require.NoError(t, s.Create(ctx, &oidcprovider.Grant{Family: opID(1), User: "u-1", CreatedAt: opTime}))

				var isNull bool
				require.NoError(t, db.QueryRowContext(ctx, `SELECT sign_in_family IS NULL FROM op_grants`).Scan(&isNull))
				require.True(t, isNull, "no family is held as NULL, as the schema has it")

				got, err := s.EndSignIns(ctx, oidcprovider.SignInSelector{User: "u-1", ExceptFamily: opID(9)}, at)
				require.NoError(t, err)
				require.Len(t, got, 1, "NULL is not the excepted family")
				assert.Equal(t, opID(1), got[0].Family)
			},
		},
		{
			name: "a stored grant with a zero created_at is not a tombstone",
			assert: func(t *testing.T, ctx context.Context, d database) {
				db := d.conn.DB
				s := joined(t, d.db)
				require.NoError(t, s.Create(ctx, &oidcprovider.Grant{Family: opID(1), User: "u-1"}))

				var isNull bool
				require.NoError(t, db.QueryRowContext(ctx, `SELECT created_at IS NULL FROM op_grants`).Scan(&isNull))
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
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := joined(t, d.db)
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
			assert: func(t *testing.T, ctx context.Context, d database) {
				db := d.conn.DB
				s := joined(t, d.db)
				require.NoError(t, revokeErr(s.Revoke(ctx, opID(1), oidcprovider.CauseCodeReplay, at)))

				var created, signIn, code sql.NullString
				var holds bool
				require.NoError(t, db.QueryRowContext(ctx,
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
			assert: func(t *testing.T, ctx context.Context, d database) {
				g := d.db
				codes := must.Must(oidcprovider.NewMemoryCodeStore())
				require.NoError(t, codes.Create(ctx, &oidcprovider.CodeRecord{
					TokenID: opID(50), GrantFamily: opID(2), SignIn: oidcprovider.SignIn{User: "u-1", Family: opID(7)},
				}))
				s := newGrantStore(t, g)
				require.NoError(t, s.UseCodes(codes))
				require.NoError(t, s.Create(ctx, &oidcprovider.Grant{Family: opID(1), User: "u-1", SignInFamily: opID(7), CreatedAt: opTime}))

				tx := g.WithContext(ctx).Begin()
				require.NoError(t, tx.Error)
				ended, err := s.EndSignIns(gormstore.WithTx(ctx, tx), oidcprovider.SignInSelector{Family: opID(7)}, at)
				require.NoError(t, err)
				require.Len(t, ended, 1)
				require.NoError(t, tx.Rollback().Error)

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
			assert: func(t *testing.T, ctx context.Context, d database) {
				assertFailedUnit(ctx, t, d, func(ctx context.Context, s oidcprovider.GrantStore) error {
					_, err := s.EndSignIns(ctx, oidcprovider.SignInSelector{User: "u-1"}, at)
					return err
				})
			},
		},
		{
			name: "a failed revocation inside a caller's transaction leaves it usable, with its earlier work and none of its own",
			assert: func(t *testing.T, ctx context.Context, d database) {
				assertFailedUnit(ctx, t, d, func(ctx context.Context, s oidcprovider.GrantStore) error {
					_, err := s.RevokeByUser(ctx, "u-1", oidcprovider.CauseRecovery, at)
					return err
				})
			},
		},
		{
			name: "an end revokes a stored grant only a code names, without marking or reporting it",
			assert: func(t *testing.T, ctx context.Context, d database) {
				g := d.db
				codes := must.Must(oidcprovider.NewMemoryCodeStore())
				require.NoError(t, codes.Create(ctx, &oidcprovider.CodeRecord{
					TokenID: opID(50), GrantFamily: opID(1), SignIn: oidcprovider.SignIn{User: "u-1", Family: opID(7)},
				}))
				s := newGrantStore(t, g)
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
			assert: func(t *testing.T, ctx context.Context, d database) {
				db := d.conn.DB
				s := joined(t, d.db)
				sel := oidcprovider.SignInSelector{User: "u-1"}
				require.NoError(t, s.Create(ctx, &oidcprovider.Grant{Family: opID(1), User: "u-1", CreatedAt: opTime}))

				blocker, err := db.BeginTx(ctx, nil)
				require.NoError(t, err)
				defer func() { _ = blocker.Rollback() }()
				_, err = blocker.ExecContext(ctx, `SELECT 1 FROM op_grants WHERE family = $1 FOR UPDATE`, opID(1).String())
				require.NoError(t, err)

				var ended []oidcprovider.Grant
				var endErr error
				var wg sync.WaitGroup
				wg.Go(func() { ended, endErr = s.EndSignIns(ctx, sel, at) })
				require.Eventually(t, func() bool {
					var waiting int
					err := db.QueryRowContext(ctx, `SELECT count(*) FROM pg_stat_activity
WHERE datname = current_database() AND wait_event_type = 'Lock'`).Scan(&waiting)

					return err == nil && waiting == 1
				}, 20*time.Second, 5*time.Millisecond)

				require.NoError(t, s.Create(ctx, &oidcprovider.Grant{Family: opID(2), User: "u-1", CreatedAt: opTime}))
				require.NoError(t, blocker.Rollback())
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
			tc.assert(t, t.Context(), migratedDB(t))
		})
	}
}

// assertFailedUnit makes a many-grant call fail on the server, by a trigger refusing the
// write to the stored grant it selects, after the unit has already recorded a revocation
// for an outstanding code. A caller's transaction must still answer, with its earlier
// revocation, and without the one the failed call recorded.
func assertFailedUnit(ctx context.Context, t *testing.T, d database, call func(ctx context.Context, s oidcprovider.GrantStore) error) {
	t.Helper()

	stored, earlier, outstanding := opID(1), opID(2), opID(3)
	at := opTime.Add(time.Minute)

	codes := must.Must(oidcprovider.NewMemoryCodeStore())
	require.NoError(t, codes.Create(ctx, &oidcprovider.CodeRecord{
		TokenID: opID(50), GrantFamily: outstanding, SignIn: oidcprovider.SignIn{User: "u-1", Family: opID(7)},
	}))
	s := newGrantStore(t, d.db)
	require.NoError(t, s.UseCodes(codes))
	require.NoError(t, s.Create(ctx, &oidcprovider.Grant{Family: stored, User: "u-1", CreatedAt: opTime}))

	_, err := d.conn.DB.ExecContext(ctx, `CREATE FUNCTION test_refuse_grant_write() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'refused by the test'; END $$;
CREATE TRIGGER test_refuse_grant_write BEFORE UPDATE ON op_grants
FOR EACH ROW EXECUTE FUNCTION test_refuse_grant_write()`)
	require.NoError(t, err)

	tx := d.db.WithContext(ctx).Begin()
	require.NoError(t, tx.Error)
	defer func() { tx.Rollback() }()
	txCtx := gormstore.WithTx(ctx, tx)
	require.NoError(t, revokeErr(s.Revoke(txCtx, earlier, oidcprovider.CauseReuse, at)))

	err = call(txCtx, s)
	require.ErrorContains(t, err, "refused by the test", "the statement must have failed on the server")

	got, err := s.Load(txCtx, earlier)
	require.NoError(t, err, "the transaction still answers")
	assert.True(t, got.Revoked, "with its earlier work")

	_, err = s.Load(txCtx, outstanding)
	require.ErrorIs(t, err, oidcprovider.ErrNotFound, "and what the failed call recorded is undone")

	require.NoError(t, tx.Commit().Error, "and it can still commit")
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

// TestGormStore_GrantLockOrder races the operations writing many grants, with nothing
// staged and no blocker, each pair over rounds of its own. Every grant of a round is
// written by both, so a pair not agreeing on one order deadlocks in most rounds, and
// PostgreSQL then ends one call with 40P01 and its write is lost. A round is one meeting,
// decided by a short window, so it takes many.
func TestGormStore_GrantLockOrder(t *testing.T) {
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
			d := migratedDB(t)
			g := d.db
			f := orderFixture{s: newGrantStore(t, g), codes: newCodeStore(t, g)}
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

// TestGormStore_GrantLockOrderOverDifferentSets races pairs of calls holding different
// sets of one user's grants, one of them all of the user's and the other those of one
// client, so the sets overlap and neither holds the other's. Each call's set is large and
// stored in a random order, so a call taking its rows in the order it meets them takes
// them in an order of its own, and the pair deadlocks, which only an agreed order
// prevents. The pairs of TestGormStore_GrantLockOrder hold identical sets, and so cannot
// tell a call that sorts its rows from one that scans them the same way as the other.
func TestGormStore_GrantLockOrderOverDifferentSets(t *testing.T) {
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
			d := migratedDB(t)
			db, g := d.conn.DB, d.db
			f := orderFixture{s: newGrantStore(t, g), codes: newCodeStore(t, g)}
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

// TestGormStore_GrantLockOrderStaged lines each pair up on a row a blocker holds, so that
// a pair not agreeing on one order is sure to deadlock when the blocker lets go: the
// first call holds rows past it, and the second rows before it.
func TestGormStore_GrantLockOrderStaged(t *testing.T) {
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
		require.NoError(t, revokeErr(f.s.Revoke(ctx, after, oidcprovider.CauseReuse, at)))
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
			d := migratedDB(t)
			db, g := d.conn.DB, d.db
			f := orderFixture{s: newGrantStore(t, g), codes: newCodeStore(t, g)}
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

// TestGormStore_ConsentsAccumulateConcurrently gives one consent many scopes at once. A
// store that reads the scopes and writes them back separately loses some.
func TestGormStore_ConsentsAccumulateConcurrently(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	d := migratedDB(t)
	g := d.db
	s := newConsentStore(t, g)

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

// TestGormStore_IdentifierGenerator covers the override of each store minting its rows'
// uuid: the row holds what the consumer's generator gave.
func TestGormStore_IdentifierGenerator(t *testing.T) {
	t.Parallel()

	minted := opID(77)
	gen := gormstore.WithIDGenerator(oneOpID{minted})

	cases := []struct {
		name  string
		table string
		write func(t *testing.T, ctx context.Context, d database) error
	}{
		{"consents", pgschema.ConsentTable, func(t *testing.T, ctx context.Context, d database) error {
			g := d.db
			return newConsentStore(t, g, gen).Give(ctx, "u-1", "c-1", nil, false, opTime)
		}},
		{"assertion identifiers", pgschema.AssertionIDTable, func(t *testing.T, ctx context.Context, d database) error {
			g := d.db
			_, err := newAssertionStore(t, g, gen).Record(ctx, "c-1", "jti", opTime)
			return err
		}},
		{"browser sessions", pgschema.BrowserSessionTable, func(t *testing.T, ctx context.Context, d database) error {
			g := d.db
			return newBrowserStore(t, g, gen).Put(ctx, &oidcprovider.BrowserSession{Digest: []byte{1}, IdleExpiresAt: opTime, AbsoluteExpiresAt: opTime})
		}},
		{"clients", pgschema.ClientTable, func(t *testing.T, ctx context.Context, d database) error {
			g := d.db
			return newClientStore(t, g, gen).Put(ctx, confidentialClient("c-1"))
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			d := migratedDB(t)
			db := d.conn.DB
			require.NoError(t, tc.write(t, ctx, d))

			var got id.ID
			// table is one of pgschema's constants.
			require.NoError(t, db.QueryRowContext(ctx, "SELECT id FROM "+tc.table).Scan(&got))
			assert.Equal(t, minted, got)
		})
	}
}

// oneOpID is a generator giving one identifier.
type oneOpID struct{ value id.ID }

func (f oneOpID) NewID() (id.ID, error) { return f.value, nil }

// TestGormStore_NewOIDCProviderStores holds every constructor to the package's wiring rules.
func TestGormStore_NewOIDCProviderStores(t *testing.T) {
	t.Parallel()

	db := unreachableDB(t)
	c := storefix.TestCipher(t)

	type store = struct{ built bool }
	type ctor = func(db *gormdb.DB, opts ...gormstore.Option) (store, error)

	wrap := func(build func(db *gormdb.DB, opts ...gormstore.Option) error) ctor {
		return func(db *gormdb.DB, opts ...gormstore.Option) (store, error) {
			err := build(db, opts...)

			return store{built: err == nil}, err
		}
	}

	ctors := map[string]struct {
		build     ctor
		mintsRows bool
		takesClk  bool
	}{
		"pending requests": {build: wrap(func(db *gormdb.DB, o ...gormstore.Option) error {
			_, err := gormstore.NewPendingRequestStore(db, o...)
			return err
		})},
		"codes": {build: wrap(func(db *gormdb.DB, o ...gormstore.Option) error {
			_, err := gormstore.NewCodeStore(db, o...)
			return err
		})},
		"grants": {build: wrap(func(db *gormdb.DB, o ...gormstore.Option) error {
			_, err := gormstore.NewGrantStore(db, o...)
			return err
		})},
		"access tokens": {build: wrap(func(db *gormdb.DB, o ...gormstore.Option) error {
			_, err := gormstore.NewAccessTokenStore(db, o...)
			return err
		})},
		"consents": {mintsRows: true, build: wrap(func(db *gormdb.DB, o ...gormstore.Option) error {
			_, err := gormstore.NewConsentStore(db, o...)
			return err
		})},
		"assertion identifiers": {mintsRows: true, build: wrap(func(db *gormdb.DB, o ...gormstore.Option) error {
			_, err := gormstore.NewAssertionIDStore(db, o...)
			return err
		})},
		"browser sessions": {mintsRows: true, build: wrap(func(db *gormdb.DB, o ...gormstore.Option) error {
			_, err := gormstore.NewBrowserSessionStore(db, o...)
			return err
		})},
		"clients": {mintsRows: true, build: wrap(func(db *gormdb.DB, o ...gormstore.Option) error {
			_, err := gormstore.NewClientStore(db, o...)
			return err
		})},
		"lineages": {mintsRows: true, takesClk: true, build: wrap(func(db *gormdb.DB, o ...gormstore.Option) error {
			_, err := gormstore.NewRefreshTokenStore(db, c, o...)
			return err
		})},
	}

	refused := func(t *testing.T, err error, text string) {
		t.Helper()
		require.ErrorIs(t, err, gormstore.ErrConfig)
		assert.EqualError(t, err, "gormstore: invalid configuration: "+text)
	}

	for name, tc := range ctors {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			s, err := tc.build(db)
			require.NoError(t, err, "a handle is all it needs")
			assert.True(t, s.built)

			_, err = tc.build(nil)
			refused(t, err, "the database handle is nil")

			_, err = tc.build(db, gormstore.WithResealOnRead(false))
			refused(t, err, "WithResealOnRead does not apply to this store")

			_, err = tc.build(db, gormstore.WithClock(clock.System()))
			if tc.takesClk {
				require.NoError(t, err)
			} else {
				refused(t, err, "WithClock does not apply to this store")
			}

			_, err = tc.build(db, gormstore.WithIDGenerator(id.NewV7Generator()))
			if tc.mintsRows {
				require.NoError(t, err)
			} else {
				refused(t, err, "WithIDGenerator does not apply to this store")
			}
		})
	}

	t.Run("lineages need a cipher, and have no zero value to hand out", func(t *testing.T) {
		t.Parallel()

		got, err := gormstore.NewRefreshTokenStore(db, nil)
		refused(t, err, "the cipher is nil")
		assert.Nil(t, oplineage.Sessions(got))
	})
}

// openGormWith opens a *gorm.DB on the database at dsn with cfg, with a pool of poolSize, closed
// at cleanup.
func openGormWith(t *testing.T, dsn string, cfg *gormdb.Config) *gormdb.DB {
	t.Helper()

	cfg.DisableAutomaticPing = true
	db, err := gormdb.Open(postgres.Open(dsn), cfg)
	require.NoError(t, err)
	pool, err := db.DB()
	require.NoError(t, err)
	pool.SetMaxOpenConns(poolSize)
	t.Cleanup(func() { _ = pool.Close() })

	return db
}

// TestGormStore_LineageNeverReachesSessions runs the session suites over the lineage store
// with the sessions table renamed away: a lineage statement that still named it, through a
// model's table or a raw statement, would fail.
func TestGormStore_LineageNeverReachesSessions(t *testing.T) {
	t.Parallel()

	setup := func(t *testing.T) database {
		t.Helper()
		d := migratedDB(t)
		_, err := d.conn.DB.ExecContext(t.Context(), "ALTER TABLE sessions RENAME TO sessions_renamed_away")
		require.NoError(t, err)
		t.Cleanup(func() {
			// The set's rollback drops sessions, so it is named again for it.
			_, _ = d.conn.DB.ExecContext(context.WithoutCancel(t.Context()), "ALTER TABLE sessions_renamed_away RENAME TO sessions")
		})

		return d
	}

	t.Run("suite", func(t *testing.T) {
		d := setup(t)
		c := storefix.TestCipher(t)
		storetest.RunSessionStoreSuite(t, func(t *testing.T, clk clock.Clock) session.Store {
			return lineageSessions(t, emptied(t, d, pgschema.RefreshTokenTable), c, gormstore.WithClock(clk))
		})
	})

	t.Run("supersession race", func(t *testing.T) {
		d := setup(t)
		c := storefix.TestCipher(t)
		storetest.RunSessionSupersessionRace(t, durableHarness(d, func(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) session.Store {
			return lineageSessions(t, db, c, opts...)
		}))
	})
}

// TestGormStore_PreparedStatements runs the stores on a handle that prepares every statement,
// where gorm caches by statement text, and inside a transaction begun on it: pgschema's
// numbered placeholders must reach the server as written, the savepoints must bypass the
// prepared connection, and a failed unit must leave the caller's transaction usable.
func TestGormStore_PreparedStatements(t *testing.T) {
	t.Parallel()

	d := migratedDB(t)
	prepared := database{conn: d.conn, db: openGormWith(t, d.conn.DSN, &gormdb.Config{PrepareStmt: true})}
	c := storefix.TestCipher(t)

	t.Run("consents", func(t *testing.T) {
		storetest.ConsentSuite(t, func(t *testing.T) oidcprovider.ConsentStore {
			return newConsentStore(t, emptied(t, prepared, pgschema.ConsentTable))
		})
	})
	t.Run("grants", func(t *testing.T) {
		storetest.GrantSuite(t, func(t *testing.T) oidcprovider.GrantStore {
			return newGrantStore(t, emptied(t, prepared, pgschema.GrantTable))
		})
	})
	t.Run("browser sessions", func(t *testing.T) {
		storetest.BrowserSessionSuite(t, func(t *testing.T) oidcprovider.BrowserSessionStore {
			return newBrowserStore(t, emptied(t, prepared, pgschema.BrowserSessionTable))
		})
	})
	t.Run("lineages", func(t *testing.T) {
		storetest.RunSessionStoreSuite(t, func(t *testing.T, clk clock.Clock) session.Store {
			return lineageSessions(t, emptied(t, prepared, pgschema.RefreshTokenTable), c, gormstore.WithClock(clk))
		})
	})
	t.Run("a failed unit in a transaction", func(t *testing.T) {
		assertFailedUnit(t.Context(), t, migratedPrepared(t), func(ctx context.Context, s oidcprovider.GrantStore) error {
			_, err := s.EndSignIns(ctx, oidcprovider.SignInSelector{User: "u-1"}, opTime.Add(time.Minute))
			return err
		})
	})
}

// migratedPrepared is a database of its own with a handle that prepares statements.
func migratedPrepared(t *testing.T) database {
	t.Helper()

	d := migratedDB(t)

	return database{conn: d.conn, db: openGormWith(t, d.conn.DSN, &gormdb.Config{PrepareStmt: true})}
}

// valueLogger is a gorm logger that keeps everything it is given, statements with their
// bound values included, as gorm's own loggers print them.
type valueLogger struct {
	mu   sync.Mutex
	logs []string
}

func (l *valueLogger) LogMode(logger.LogLevel) logger.Interface { return l }

func (l *valueLogger) note(msg string, data ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.logs = append(l.logs, fmt.Sprintf(msg, data...))
}

func (l *valueLogger) Info(_ context.Context, msg string, data ...any)  { l.note(msg, data...) }
func (l *valueLogger) Warn(_ context.Context, msg string, data ...any)  { l.note(msg, data...) }
func (l *valueLogger) Error(_ context.Context, msg string, data ...any) { l.note(msg, data...) }

func (l *valueLogger) Trace(_ context.Context, _ time.Time, fc func() (string, int64), err error) {
	sqlText, _ := fc()
	l.note("%s %v", sqlText, err)
}

func (l *valueLogger) text() string {
	l.mu.Lock()
	defer l.mu.Unlock()

	return fmt.Sprint(l.logs)
}

// TestGormStore_LogsCarryNoValue makes statements fail for real on a handle whose logger
// records, and requires that nothing was logged: gorm's logger prints each statement with its
// bound values, which here are digests and secrets.
func TestGormStore_LogsCarryNoValue(t *testing.T) {
	t.Parallel()

	digest := sha256.Sum256(clientSecretBytes)

	cases := []struct {
		name  string
		table string
		call  func(t *testing.T, ctx context.Context, d database) error
	}{
		{"pending create", pgschema.PendingRequestTable, func(t *testing.T, ctx context.Context, d database) error {
			return newPendingStore(t, d.db).Create(ctx, &oidcprovider.PendingRequest{ID: opID(1), HandleDigest: digest[:], FlowDigest: digest[:]})
		}},
		{"pending load", pgschema.PendingRequestTable, func(t *testing.T, ctx context.Context, d database) error {
			_, err := newPendingStore(t, d.db).Load(ctx, digest[:])
			return err
		}},
		{"browser touch", pgschema.BrowserSessionTable, func(t *testing.T, ctx context.Context, d database) error {
			return newBrowserStore(t, d.db).Touch(ctx, digest[:], opTime)
		}},
		{"access token create", pgschema.AccessTokenTable, func(t *testing.T, ctx context.Context, d database) error {
			return newAccessTokenStore(t, d.db).Create(ctx, &oidcprovider.AccessTokenRecord{ID: opID(1), Digest: digest[:]})
		}},
		{"lineage create", pgschema.RefreshTokenTable, func(t *testing.T, ctx context.Context, d database) error {
			return lineageSessions(t, d.db, storefix.TestCipher(t)).Create(ctx, opSession("a-refresh-token-value", opID(4)))
		}},
		{"grant end", pgschema.GrantTable, func(t *testing.T, ctx context.Context, d database) error {
			s := newGrantStore(t, d.db)
			require.NoError(t, s.UseCodes(must.Must(oidcprovider.NewMemoryCodeStore())))
			_, err := s.EndSignIns(ctx, oidcprovider.SignInSelector{User: "u-1"}, opTime)
			return err
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			d := migratedDB(t)
			rec := &valueLogger{}
			d.db = d.db.Session(&gormdb.Session{Logger: rec})
			_, err := d.conn.DB.ExecContext(ctx, "DROP TABLE "+tc.table)
			require.NoError(t, err)

			require.Error(t, tc.call(t, ctx, d))
			assert.Empty(t, rec.text()[1:len(rec.text())-1], "nothing is logged, the statement and its values least of all")
		})
	}
}

// TestGormStore_RoundTripsAsSQLStore stores the same records through both adapters and
// requires they read back equal: the same times (UTC, truncated to the microsecond), the same
// nil and empty lists, the same zero values.
func TestGormStore_RoundTripsAsSQLStore(t *testing.T) {
	t.Parallel()

	local := time.FixedZone("UTC+7", 7*3600)
	at := time.Date(2030, 2, 1, 9, 0, 0, 123456789, local)
	signIn := func(amr []string) oidcprovider.SignIn {
		return oidcprovider.SignIn{User: "u-1", Family: opID(1), AuthenticatedAt: at, AMR: amr, AbsoluteExpiresAt: at.Add(time.Hour)}
	}
	maxAge := 30

	type adapters struct {
		grants   oidcprovider.GrantStore
		pending  oidcprovider.PendingRequestStore
		codes    oidcprovider.CodeStore
		tokens   oidcprovider.AccessTokenStore
		browsers oidcprovider.BrowserSessionStore
	}
	build := func(t *testing.T, d database, kind string) adapters {
		t.Helper()
		if kind == "sqlstore" {
			raw := d.conn.DB

			return adapters{
				grants: must.Must(sqlstore.NewGrantStore(raw)), pending: must.Must(sqlstore.NewPendingRequestStore(raw)),
				codes: must.Must(sqlstore.NewCodeStore(raw)), tokens: must.Must(sqlstore.NewAccessTokenStore(raw)),
				browsers: must.Must(sqlstore.NewBrowserSessionStore(raw)),
			}
		}

		return adapters{
			grants: newGrantStore(t, d.db), pending: newPendingStore(t, d.db), codes: newCodeStore(t, d.db),
			tokens: newAccessTokenStore(t, d.db), browsers: newBrowserStore(t, d.db),
		}
	}

	// read stores each record, and reads each back.
	read := func(t *testing.T, a adapters) []any {
		t.Helper()
		ctx := t.Context()
		var out []any
		for i, amr := range [][]string{nil, {}, {"pwd", "otp"}} {
			n := 10 * (i + 1)
			grant := &oidcprovider.Grant{
				Family: opID(n), User: "u-1", ClientID: "c-1", Scopes: amr, Resources: amr, AuthTime: at, AMR: amr,
				CreatedAt: at, ExpiresAt: at.Add(time.Hour), HoldsLineage: i == 2,
			}
			require.NoError(t, a.grants.Create(ctx, grant))
			require.NoError(t, revokeErr(a.grants.Revoke(ctx, opID(n+1), oidcprovider.CauseReuse, at)))
			require.NoError(t, a.pending.Create(ctx, &oidcprovider.PendingRequest{
				ID: opID(n + 2), HandleDigest: []byte{byte(n)}, FlowDigest: []byte{byte(n), 1}, ClientID: "c-1", Scopes: amr,
				Prompt: amr, UILocales: amr, MaxAge: &maxAge, ParkedAt: at, ExpiresAt: at.Add(time.Minute),
				SignIn: func() *oidcprovider.SignIn { s := signIn(amr); return &s }(),
			}))
			require.NoError(t, a.codes.Create(ctx, &oidcprovider.CodeRecord{
				TokenID: opID(n + 3), ClientID: "c-1", Scopes: amr, Resources: amr, SignIn: signIn(amr), GrantFamily: opID(n), ExpiresAt: at,
			}))
			require.NoError(t, a.tokens.Create(ctx, &oidcprovider.AccessTokenRecord{
				ID: opID(n + 4), Digest: []byte{byte(n), 2}, GrantFamily: opID(n), ClientID: "c-1", User: "u-1",
				Scopes: amr, Audience: amr, IssuedAt: at, ExpiresAt: at.Add(time.Minute),
			}))
			require.NoError(t, a.browsers.Put(ctx, &oidcprovider.BrowserSession{
				Digest: []byte{byte(n), 3}, SignIn: signIn(amr), IdleExpiresAt: at.Add(time.Minute), AbsoluteExpiresAt: at.Add(time.Hour),
			}))

			g, err := a.grants.Load(ctx, opID(n))
			require.NoError(t, err)
			tomb, err := a.grants.Load(ctx, opID(n+1))
			require.NoError(t, err)
			p, err := a.pending.Load(ctx, []byte{byte(n)})
			require.NoError(t, err)
			c, err := a.codes.Load(ctx, opID(n+3))
			require.NoError(t, err)
			tok, err := a.tokens.Load(ctx, opID(n+4))
			require.NoError(t, err)
			b, err := a.browsers.Load(ctx, []byte{byte(n), 3}, at)
			require.NoError(t, err)
			out = append(out, g, tomb, p, c, tok, b)
		}

		return out
	}

	d := migratedDB(t)
	want := read(t, build(t, d, "sqlstore"))
	for _, table := range pgschema.OIDCProviderTables() {
		_, err := d.conn.DB.ExecContext(t.Context(), "TRUNCATE "+table) //nolint:gosec // pgschema's constant
		require.NoError(t, err)
	}
	got := read(t, build(t, d, "gormstore"))

	require.Len(t, got, len(want))
	for i := range want {
		assert.Equal(t, want[i], got[i], "record %d", i)
	}
}

// TestGormStore_LineageSupersedeInATransactionOnAPreparedHandle supersedes a lineage inside a
// caller's transaction begun on a handle that prepares statements. The unit runs under a
// savepoint, which must reach the server as written and never be prepared and cached by name,
// and its writes must land in the lineage table and commit with the caller's.
func TestGormStore_LineageSupersedeInATransactionOnAPreparedHandle(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	d := migratedPrepared(t)
	store := lineageSessions(t, d.db, storefix.TestCipher(t))

	const sid = "lineage-in-tx"
	old := storefix.DurableSession(sid, supersedeAt)
	require.NoError(t, store.Create(ctx, old))

	tx := d.db.WithContext(ctx).Begin()
	require.NoError(t, tx.Error)
	defer func() { tx.Rollback() }()
	require.NoError(t, store.Supersede(gormstore.WithTx(ctx, tx), supersessionOf(old, sid+"-next", nil)))

	var prepared int
	require.NoError(t, tx.Raw(`SELECT count(*) FROM pg_prepared_statements WHERE statement ILIKE 'savepoint%' OR statement ILIKE 'release%' OR statement ILIKE 'rollback%'`).Row().Scan(&prepared))
	assert.Zero(t, prepared, "a savepoint is never prepared")
	require.NoError(t, tx.Commit().Error)

	var inLineage, inSessions int
	require.NoError(t, d.conn.DB.QueryRowContext(ctx, "SELECT count(*) FROM "+pgschema.RefreshTokenTable).Scan(&inLineage))
	require.NoError(t, d.conn.DB.QueryRowContext(ctx, "SELECT count(*) FROM sessions").Scan(&inSessions))
	assert.Equal(t, 2, inLineage)
	assert.Zero(t, inSessions)
}

// revokeErr is what a call to GrantStore.Revoke failed with, for a case that does not ask whether the
// call is what revoked the grant.
func revokeErr(_ bool, err error) error { return err }
