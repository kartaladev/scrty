// Package crossbackend_test proves guarantees that hold across all three
// durable backends together, over one shared PostgreSQL database: backends
// share one schema, a transaction attached through one backend is invisible
// to another, state outlives the process that wrote it, and a consumption on
// one backend is seen by another.
package crossbackend_test

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gormpg "gorm.io/driver/postgres"
	gormdb "gorm.io/gorm"

	"github.com/kartaladev/scrty/apikey"
	gormstore "github.com/kartaladev/scrty/gorm"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/migrate"
	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/onetime"
	pgxstore "github.com/kartaladev/scrty/pgx"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/seal"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/signingkey"
	"github.com/kartaladev/scrty/sqlstore"
	"github.com/kartaladev/scrty/test"
	"github.com/kartaladev/scrty/test/internal/storefix"
)

// crossBackendPoolSize is how many connections a pool opened in this package
// may use at once. Nothing here races more than a couple of callers, so this
// is comfortably wide, not tuned like the durable race suites' pools.
const crossBackendPoolSize = 8

// backendNames are the three backends every cross-backend guarantee runs
// over.
var backendNames = []string{"sqlstore", "pgx", "gorm"}

// migratedConn starts a PostgreSQL database with the security-state set
// applied, and returns the connection. The set is rolled back at cleanup.
func migratedConn(t *testing.T) test.PostgresConn {
	t.Helper()

	set := migrate.SecurityState()
	conn := test.RunTestPostgres(t, test.WithTestPostgresMigrations(set.FS(), set.Dir, set.VersionTable))
	conn.DB.SetMaxOpenConns(crossBackendPoolSize)

	return conn
}

// dialPgxPool opens a pgx pool of its own on dsn, with no cleanup registered:
// the caller decides when it closes, which the restart scenario needs to do
// itself, before the test's own cleanup would.
func dialPgxPool(t *testing.T, dsn string) *pgxpool.Pool {
	t.Helper()

	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	cfg.MaxConns = crossBackendPoolSize

	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	require.NoError(t, err)

	return pool
}

// openPgxPool is dialPgxPool, closed at cleanup.
func openPgxPool(t *testing.T, dsn string) *pgxpool.Pool {
	t.Helper()

	pool := dialPgxPool(t, dsn)
	t.Cleanup(pool.Close)

	return pool
}

// dialGormDB opens a *gorm.DB of its own on dsn, with no cleanup registered.
func dialGormDB(t *testing.T, dsn string) *gormdb.DB {
	t.Helper()

	db, err := gormdb.Open(gormpg.Open(dsn), &gormdb.Config{DisableAutomaticPing: true})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(crossBackendPoolSize)

	return db
}

// openGormDB is dialGormDB, closed at cleanup.
func openGormDB(t *testing.T, dsn string) *gormdb.DB {
	t.Helper()

	db := dialGormDB(t, dsn)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })

	return db
}

// testCipher returns a fresh AES-256-GCM cipher over one random key. Every
// row here that seals a value uses one; which key it is does not matter, so
// long as the seeding side and the reading side share it.
func testCipher(t *testing.T) seal.Cipher {
	t.Helper()

	return storefix.CipherOf(t, seal.WithEncryptionKey("k1", storefix.SealKey(t)))
}

// crossBackendID derives a stable identifier from seed: unique per seed and
// non-zero, as a durable store's primary key requires. It is a pure function
// of seed, so every call for the same seed agrees.
func crossBackendID(seed string) id.ID {
	sum := sha256.Sum256([]byte("cross-backend-id-of-" + seed))

	var v id.ID
	copy(v[:], sum[:16])

	return v
}

// backends is one migrated database reached through all three backends: db
// through sqlstore, pool through pgx, gdb through gorm. cipher seals every
// sealed value a row in this package writes.
type backends struct {
	conn   test.PostgresConn
	pool   *pgxpool.Pool
	gdb    *gormdb.DB
	cipher seal.Cipher
}

// apiKeyStore builds the API key store of the named backend.
func (b backends) apiKeyStore(t *testing.T, name string) apikey.Store {
	t.Helper()

	switch name {
	case "sqlstore":
		s, err := sqlstore.NewAPIKeyStore(b.conn.DB)
		require.NoError(t, err)
		return s
	case "pgx":
		s, err := pgxstore.NewAPIKeyStore(b.pool)
		require.NoError(t, err)
		return s
	case "gorm":
		s, err := gormstore.NewAPIKeyStore(b.gdb)
		require.NoError(t, err)
		return s
	default:
		t.Fatalf("unknown backend %q", name)
		return nil
	}
}

// sessionStore builds the session store of the named backend, over b's
// cipher.
func (b backends) sessionStore(t *testing.T, name string) session.Store {
	t.Helper()

	switch name {
	case "sqlstore":
		s, err := sqlstore.NewSessionStore(b.conn.DB, b.cipher)
		require.NoError(t, err)
		return s
	case "pgx":
		s, err := pgxstore.NewSessionStore(b.pool, b.cipher)
		require.NoError(t, err)
		return s
	case "gorm":
		s, err := gormstore.NewSessionStore(b.gdb, b.cipher)
		require.NoError(t, err)
		return s
	default:
		t.Fatalf("unknown backend %q", name)
		return nil
	}
}

// oneTimeStore builds the one-time token store of the named backend.
func (b backends) oneTimeStore(t *testing.T, name string) onetime.Store {
	t.Helper()

	switch name {
	case "sqlstore":
		s, err := sqlstore.NewOneTimeStore(b.conn.DB)
		require.NoError(t, err)
		return s
	case "pgx":
		s, err := pgxstore.NewOneTimeStore(b.pool)
		require.NoError(t, err)
		return s
	case "gorm":
		s, err := gormstore.NewOneTimeStore(b.gdb)
		require.NoError(t, err)
		return s
	default:
		t.Fatalf("unknown backend %q", name)
		return nil
	}
}

// signingKeyStore builds the signing-key store of the named backend, over b's
// cipher.
func (b backends) signingKeyStore(t *testing.T, name string) signingkey.KeyStore {
	t.Helper()

	switch name {
	case "sqlstore":
		s, err := sqlstore.NewSigningKeyStore(b.conn.DB, b.cipher)
		require.NoError(t, err)
		return s
	case "pgx":
		s, err := pgxstore.NewSigningKeyStore(b.pool, b.cipher)
		require.NoError(t, err)
		return s
	case "gorm":
		s, err := gormstore.NewSigningKeyStore(b.gdb, b.cipher)
		require.NoError(t, err)
		return s
	default:
		t.Fatalf("unknown backend %q", name)
		return nil
	}
}

// attemptStore builds the login-attempt store of the named backend.
func (b backends) attemptStore(t *testing.T, name string) policy.AttemptStore {
	t.Helper()

	switch name {
	case "sqlstore":
		s, err := sqlstore.NewAttemptStore(b.conn.DB)
		require.NoError(t, err)
		return s
	case "pgx":
		s, err := pgxstore.NewAttemptStore(b.pool)
		require.NoError(t, err)
		return s
	case "gorm":
		s, err := gormstore.NewAttemptStore(b.gdb)
		require.NoError(t, err)
		return s
	default:
		t.Fatalf("unknown backend %q", name)
		return nil
	}
}

// enrolmentStore builds the MFA enrolment store of the named backend, over
// b's cipher.
func (b backends) enrolmentStore(t *testing.T, name string) mfa.EnrolmentStore {
	t.Helper()

	switch name {
	case "sqlstore":
		s, err := sqlstore.NewEnrolmentStore(b.conn.DB, b.cipher)
		require.NoError(t, err)
		return s
	case "pgx":
		s, err := pgxstore.NewEnrolmentStore(b.pool, b.cipher)
		require.NoError(t, err)
		return s
	case "gorm":
		s, err := gormstore.NewEnrolmentStore(b.gdb, b.cipher)
		require.NoError(t, err)
		return s
	default:
		t.Fatalf("unknown backend %q", name)
		return nil
	}
}

// linkStore builds the OIDC link store of the named backend.
func (b backends) linkStore(t *testing.T, name string) oidc.LinkStore {
	t.Helper()

	switch name {
	case "sqlstore":
		s, err := sqlstore.NewLinkStore(b.conn.DB)
		require.NoError(t, err)
		return s
	case "pgx":
		s, err := pgxstore.NewLinkStore(b.pool)
		require.NoError(t, err)
		return s
	case "gorm":
		s, err := gormstore.NewLinkStore(b.gdb)
		require.NoError(t, err)
		return s
	default:
		t.Fatalf("unknown backend %q", name)
		return nil
	}
}

// flowStore builds the OIDC flow store of the named backend.
func (b backends) flowStore(t *testing.T, name string) oidc.FlowStore {
	t.Helper()

	switch name {
	case "sqlstore":
		s, err := sqlstore.NewFlowStore(b.conn.DB)
		require.NoError(t, err)
		return s
	case "pgx":
		s, err := pgxstore.NewFlowStore(b.pool)
		require.NoError(t, err)
		return s
	case "gorm":
		s, err := gormstore.NewFlowStore(b.gdb)
		require.NoError(t, err)
		return s
	default:
		t.Fatalf("unknown backend %q", name)
		return nil
	}
}

// handoffStore builds the OIDC handoff store of the named backend.
func (b backends) handoffStore(t *testing.T, name string) oidc.HandoffStore {
	t.Helper()

	switch name {
	case "sqlstore":
		s, err := sqlstore.NewHandoffStore(b.conn.DB)
		require.NoError(t, err)
		return s
	case "pgx":
		s, err := pgxstore.NewHandoffStore(b.pool)
		require.NoError(t, err)
		return s
	case "gorm":
		s, err := gormstore.NewHandoffStore(b.gdb)
		require.NoError(t, err)
		return s
	default:
		t.Fatalf("unknown backend %q", name)
		return nil
	}
}

// crossBackendAPIKey is a fully populated key record identified by seed, so
// every pair the schema-sharing row writes has an identifier of its own.
// Times carry microsecond precision, matching what PostgreSQL stores, so a
// backend that truncates further would be caught here.
func crossBackendAPIKey(seed string) apikey.Key {
	digest := sha256.Sum256([]byte("cross-backend-key-secret-of-" + seed))
	expires := time.Date(2031, 6, 15, 8, 30, 0, 654321000, time.UTC)
	lastUsed := time.Date(2030, 12, 1, 9, 0, 0, 111000000, time.UTC)

	return apikey.Key{
		ID:           crossBackendID("api-key-" + seed),
		Principal:    identity.UserID("svc-" + seed),
		Name:         "cross backend key " + seed,
		Scopes:       []string{"read", "write"},
		SecretDigest: digest[:],
		ExpiresAt:    &expires,
		LastUsedAt:   &lastUsed,
		CreatedAt:    time.Date(2030, 1, 1, 10, 0, 0, 123456000, time.UTC),
	}
}

// assertAPIKeyEqual asserts every field of got equals want, times compared by
// instant so a backend that returns another location still conforms.
func assertAPIKeyEqual(t *testing.T, want, got apikey.Key) {
	t.Helper()

	assert.Equal(t, want.ID, got.ID)
	assert.Equal(t, want.Principal, got.Principal)
	assert.Equal(t, want.Name, got.Name)
	assert.Equal(t, want.Scopes, got.Scopes)
	assert.Equal(t, want.SecretDigest, got.SecretDigest)
	assertInstant(t, "CreatedAt", want.CreatedAt, got.CreatedAt)
	assertInstantPtr(t, "ExpiresAt", want.ExpiresAt, got.ExpiresAt)
	assertInstantPtr(t, "RevokedAt", want.RevokedAt, got.RevokedAt)
	assertInstantPtr(t, "LastUsedAt", want.LastUsedAt, got.LastUsedAt)
}

// assertInstant asserts want and got name the same instant.
func assertInstant(t *testing.T, field string, want, got time.Time) {
	t.Helper()
	assert.True(t, want.Equal(got), "%s: got %v, want %v", field, got, want)
}

// assertInstantPtr is assertInstant for a nullable time, requiring both or
// neither to be nil.
func assertInstantPtr(t *testing.T, field string, want, got *time.Time) {
	t.Helper()

	if want == nil {
		assert.Nil(t, got, "%s should be nil", field)
		return
	}
	if assert.NotNil(t, got, "%s should not be nil", field) {
		assertInstant(t, field, *want, *got)
	}
}

// crossBackendSession is a federated session with identifier sid, holding a
// provider ID token, valid for an hour from now.
func crossBackendSession(sid string) *session.Session {
	now := time.Now().UTC()

	return &session.Session{
		ID:                sid,
		UserID:            identity.UserID("u-" + sid),
		CreatedAt:         now,
		LastAccessedAt:    now,
		IdleExpiresAt:     now.Add(5 * time.Minute),
		AbsoluteExpiresAt: now.Add(time.Hour),
		ExternalProvider:  "corp",
		ExternalIssuer:    "https://idp.example",
		ExternalSessionID: "sid-" + sid,
		ExternalIDToken:   "ID-TOKEN-" + sid,
		Data:              map[string]string{"tenant": "t-9"},
	}
}

// crossBackendToken is a fresh, unconsumed one-time token good for an hour.
func crossBackendToken(seed string) onetime.Token {
	secret := sha256.Sum256([]byte("cross-backend-token-secret-of-" + seed))
	issued := time.Now().UTC()

	return onetime.Token{
		ID:         crossBackendID("token-" + seed),
		Purpose:    "cross-backend",
		Subject:    "subject-" + seed,
		SecretHash: secret[:],
		IssuedAt:   issued,
		ExpiresAt:  issued.Add(time.Hour),
	}
}

// TestCrossBackend proves the guarantees that hold only once more than one
// backend is in play, over one migrated database shared by all three.
func TestCrossBackend(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		run  func(t *testing.T, b backends)
	}

	cases := []testCase{
		{name: "backends share one schema", run: testSchemaShared},
		{name: "transaction attached for another backend", run: testTransactionAttachedFor("sqlstore")},
		{name: "transaction attached for pgx, invisible to others", run: testTransactionAttachedFor("pgx")},
		{name: "transaction attached for gorm, invisible to others", run: testTransactionAttachedFor("gorm")},
		{name: "state survives a process restart", run: testSurvivesRestart},
		{name: "another replica sees a consumption", run: testAnotherReplicaSeesConsumption},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			conn := migratedConn(t)
			b := backends{
				conn:   conn,
				pool:   openPgxPool(t, conn.DSN),
				gdb:    openGormDB(t, conn.DSN),
				cipher: testCipher(t),
			}
			tc.run(t, b)
		})
	}
}

// testSchemaShared proves every ordered pair of backends agrees on the
// schema: whichever backend writes an API key, every other backend reads it
// back with every field equal.
func testSchemaShared(t *testing.T, b backends) {
	t.Helper()

	for _, writer := range backendNames {
		for _, reader := range backendNames {
			if writer == reader {
				continue
			}

			t.Run(writer+"_writes_"+reader+"_reads", func(t *testing.T) {
				t.Parallel()

				key := crossBackendAPIKey(writer + "-" + reader)
				require.NoError(t, b.apiKeyStore(t, writer).Put(t.Context(), key))

				got, err := b.apiKeyStore(t, reader).Get(t.Context(), key.ID)
				require.NoError(t, err)
				assertAPIKeyEqual(t, key, got)
			})
		}
	}
}

// beginAttached begins a transaction on the named backend's own handle and
// attaches it to a context under that backend's own context key. It returns
// the attached context and a function that rolls the transaction back.
func (b backends) beginAttached(t *testing.T, name string) (context.Context, func() error) {
	t.Helper()

	switch name {
	case "sqlstore":
		tx, err := b.conn.DB.BeginTx(t.Context(), nil)
		require.NoError(t, err)
		return sqlstore.WithTx(t.Context(), tx), tx.Rollback
	case "pgx":
		tx, err := b.pool.Begin(t.Context())
		require.NoError(t, err)
		return pgxstore.WithTx(t.Context(), tx), func() error { return tx.Rollback(t.Context()) }
	case "gorm":
		tx := b.gdb.WithContext(t.Context()).Begin()
		require.NoError(t, tx.Error)
		return gormstore.WithTx(t.Context(), tx), func() error { return tx.Rollback().Error }
	default:
		t.Fatalf("unknown backend %q", name)
		return nil, nil
	}
}

// testTransactionAttachedFor returns a scenario proving a transaction attached
// through the attacher backend is invisible to the stores of both other
// backends: saving a session through each other store under the attached
// context, then rolling the attached transaction back, still leaves the
// session in place.
func testTransactionAttachedFor(attacher string) func(t *testing.T, b backends) {
	return func(t *testing.T, b backends) {
		t.Helper()

		for _, saver := range backendNames {
			if saver == attacher {
				continue
			}

			t.Run(saver, func(t *testing.T) {
				// The attacher's own attachment: the saver's store cannot see a
				// transaction attached under a context key that is not its own.
				ctx, rollback := b.beginAttached(t, attacher)
				sid := "cross-backend-tx-" + attacher + "-" + saver
				require.NoError(t, b.sessionStore(t, saver).Create(ctx, crossBackendSession(sid)))

				require.NoError(t, rollback())

				got, err := b.sessionStore(t, attacher).Load(t.Context(), sid)
				require.NoError(t, err, "the session saved through %s must survive the %s rollback", saver, attacher)
				assert.Equal(t, sid, got.ID)
			})
		}
	}
}

// testSurvivesRestart proves state saved through one backend's store
// instance outlives that instance and its pool: a fresh instance over a new
// pool on the same database still loads it, as a new process would.
func testSurvivesRestart(t *testing.T, b backends) {
	t.Helper()

	const sid = "cross-backend-restart"

	pool1 := dialPgxPool(t, b.conn.DSN)
	store1, err := pgxstore.NewSessionStore(pool1, b.cipher)
	require.NoError(t, err)
	require.NoError(t, store1.Create(t.Context(), crossBackendSession(sid)))

	pool1.Close() // the process exits: the instance and its pool are gone.

	pool2 := openPgxPool(t, b.conn.DSN) // a new process opens a new pool.
	store2, err := pgxstore.NewSessionStore(pool2, b.cipher)
	require.NoError(t, err)

	got, err := store2.Load(t.Context(), sid)
	require.NoError(t, err)
	assert.Equal(t, sid, got.ID)
}

// testAnotherReplicaSeesConsumption proves single use crosses backends: a
// token consumed through one backend's store is refused by another backend's
// store, over the same database.
func testAnotherReplicaSeesConsumption(t *testing.T, b backends) {
	t.Helper()

	tok := crossBackendToken("replica")

	first := b.oneTimeStore(t, "sqlstore")
	require.NoError(t, first.Insert(t.Context(), tok))
	require.NoError(t, first.Consume(t.Context(), tok.ID, time.Now()))

	second := b.oneTimeStore(t, "pgx")
	err := second.Consume(t.Context(), tok.ID, time.Now())
	require.ErrorIs(t, err, onetime.ErrTokenNotFound, "a second replica must see the first consumption")
}
