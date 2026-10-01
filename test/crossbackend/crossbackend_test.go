// Package crossbackend_test proves guarantees that hold across all three
// durable backends together, over one shared PostgreSQL database: backends
// share one schema, a transaction attached through one backend is invisible
// to another, state outlives the process that wrote it, and a consumption on
// one backend is seen by another.
package crossbackend_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gormpg "gorm.io/driver/postgres"
	gormdb "gorm.io/gorm"

	"github.com/kartaladev/scrty/apikey"
	"github.com/kartaladev/scrty/factor"
	gormstore "github.com/kartaladev/scrty/gorm"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/migrate"
	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/onetime"
	pgxstore "github.com/kartaladev/scrty/pgx"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/recovery"
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

// clockedSessionStore is sessionStore, wired to clk instead of the system
// clock, so a test can move a durable store's own expiry judgement without
// waiting for it: each backend's session store judges expiry against its own
// clock option, separately from whatever session.Manager it is wrapped in.
func (b backends) clockedSessionStore(t *testing.T, name string, clk clock.Clock) session.Store {
	t.Helper()

	switch name {
	case "sqlstore":
		s, err := sqlstore.NewSessionStore(b.conn.DB, b.cipher, sqlstore.WithClock(clk))
		require.NoError(t, err)
		return s
	case "pgx":
		s, err := pgxstore.NewSessionStore(b.pool, b.cipher, pgxstore.WithClock(clk))
		require.NoError(t, err)
		return s
	case "gorm":
		s, err := gormstore.NewSessionStore(b.gdb, b.cipher, gormstore.WithClock(clk))
		require.NoError(t, err)
		return s
	default:
		t.Fatalf("unknown backend %q", name)
		return nil
	}
}

// recoveryCodeStore builds the saved recovery code store of the named
// backend.
func (b backends) recoveryCodeStore(t *testing.T, name string) recovery.CodeStore {
	t.Helper()

	switch name {
	case "sqlstore":
		s, err := sqlstore.NewRecoveryCodeStore(b.conn.DB)
		require.NoError(t, err)
		return s
	case "pgx":
		s, err := pgxstore.NewRecoveryCodeStore(b.pool)
		require.NoError(t, err)
		return s
	case "gorm":
		s, err := gormstore.NewRecoveryCodeStore(b.gdb)
		require.NoError(t, err)
		return s
	default:
		t.Fatalf("unknown backend %q", name)
		return nil
	}
}

// recoveryRecordStore builds the account recovery record store of the named
// backend.
func (b backends) recoveryRecordStore(t *testing.T, name string) recovery.RecordStore {
	t.Helper()

	switch name {
	case "sqlstore":
		s, err := sqlstore.NewRecoveryRecordStore(b.conn.DB)
		require.NoError(t, err)
		return s
	case "pgx":
		s, err := pgxstore.NewRecoveryRecordStore(b.pool)
		require.NoError(t, err)
		return s
	case "gorm":
		s, err := gormstore.NewRecoveryRecordStore(b.gdb)
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

// rawEmailCode reads the enrolment path's emailed-code column directly, out
// of band of every backend's own decoding, over the one PostgreSQL database
// every backend shares. It is how a test tells the column was really sealed,
// not merely re-typed: the raw envelope must never equal the plaintext code
// a caller proves the device with.
func (b backends) rawEmailCode(t *testing.T, user identity.UserID) string {
	t.Helper()

	var raw sql.NullString
	err := b.conn.DB.QueryRowContext(t.Context(),
		"SELECT email_code FROM mfa_enrolments WHERE user_id = $1", string(user)).Scan(&raw)
	require.NoError(t, err)
	require.True(t, raw.Valid, "email_code must be set once the device is proven with email confirmation on")

	return raw.String
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
		{name: "enrolment fields shared across backends", run: testEnrolmentFieldsShared},
		{name: "enrolment flow through session.Manager and mfa.TOTP", run: testEnrolmentDurableFlow},
		{name: "recovery-pending session shared across backends", run: testRecoveryPendingSessionShared},
		{name: "a recovery code spent on one backend is refused on the others", run: testRecoveryCodeSpentShared},
		{name: "a recovery completed on one backend is seen by the others", run: testRecoveryCompletionShared},
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

// testEnrolmentFieldsShared proves every ordered pair of backends agrees on
// the enrolment path's durable fields ("Backends share the enrolment
// fields"): an enrolment-only session carrying its enrolment-origin marker
// and generation, saved through the writer, loads through the reader with
// all three equal; and a device proven with an emailed code, sealed, through
// the writer's enrolment store is read back with the same code through the
// reader's, which also charges an attempt against it.
func testEnrolmentFieldsShared(t *testing.T, b backends) {
	t.Helper()

	for _, writer := range backendNames {
		for _, reader := range backendNames {
			if writer == reader {
				continue
			}

			t.Run(writer+"_writes_"+reader+"_reads", func(t *testing.T) {
				t.Parallel()

				ctx := t.Context()
				seed := "enrolment-" + writer + "-" + reader
				gen := crossBackendID("generation-" + seed)

				sess := crossBackendSession(seed)
				sess.MFA = session.MFAEnrolmentPending
				deadline := time.Now().UTC().Add(12 * time.Hour).Truncate(time.Microsecond)
				sess.EnrolmentOriginDeadline = deadline
				sess.EnrolmentGeneration = gen
				require.NoError(t, b.sessionStore(t, writer).Create(ctx, sess))

				got, err := b.sessionStore(t, reader).Load(ctx, seed)
				require.NoError(t, err)
				assert.Equal(t, session.MFAEnrolmentPending, got.MFA)
				assertInstant(t, "EnrolmentOriginDeadline", deadline, got.EnrolmentOriginDeadline)
				assert.Equal(t, gen, got.EnrolmentGeneration)

				user := identity.UserID("u-" + seed)
				begun := time.Now().UTC().Truncate(time.Microsecond)
				w := b.enrolmentStore(t, writer)
				require.NoError(t, w.PutPending(ctx, mfa.Enrolment{
					User: user, Secret: []byte("TOTP-SECRET"), CreatedAt: begun, Generation: gen,
				}))
				proofs, ok := w.(mfa.DeviceProofStore)
				require.True(t, ok, "the %s enrolment store must implement mfa.DeviceProofStore", writer)
				proven, err := proofs.ProveDevice(ctx, user, gen, 1000, []byte("314159"), begun.Add(10*time.Minute), begun)
				require.NoError(t, err)
				require.True(t, proven)

				r := b.enrolmentStore(t, reader)
				e, found, err := r.Get(ctx, user)
				require.NoError(t, err)
				require.True(t, found)
				assert.Equal(t, gen, e.Generation)
				assert.Equal(t, []byte("314159"), e.EmailCode, "the emailed code sealed through %s must open through %s", writer, reader)
				assertInstant(t, "DeviceProvenAt", begun, e.DeviceProvenAt)
				assertInstant(t, "EmailCodeUntil", begun.Add(10*time.Minute), e.EmailCodeUntil)

				charges, ok := r.(mfa.DeviceProofStore)
				require.True(t, ok, "the %s enrolment store must implement mfa.DeviceProofStore", reader)
				count, charged, err := charges.ChargeEmailCode(ctx, user, gen, begun.Add(time.Minute))
				require.NoError(t, err)
				assert.True(t, charged, "a code proven through %s must be charged through %s", writer, reader)
				assert.Equal(t, 1, count)
			})
		}
	}
}

// testRecoveryPendingSessionShared proves a recovery-pending session, with its
// confinement marker and recovery time, saved through sqlstore loads through
// both pgx and gorm with all three fields equal ("Recovery-pending session
// round trip").
func testRecoveryPendingSessionShared(t *testing.T, b backends) {
	t.Helper()

	const seed = "recovery-pending"

	sess := crossBackendSession(seed)
	sess.FirstFactor = factor.Recovery
	sess.MFA = session.MFARecoveryPending
	marker := time.Now().UTC().Add(11 * time.Hour).Truncate(time.Microsecond)
	recoveredAt := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	sess.EnrolmentOriginDeadline = marker
	sess.RecoveredAt = recoveredAt
	require.NoError(t, b.sessionStore(t, "sqlstore").Create(t.Context(), sess))

	for _, reader := range []string{"pgx", "gorm"} {
		t.Run(reader, func(t *testing.T) {
			t.Parallel()

			got, err := b.sessionStore(t, reader).Load(t.Context(), seed)
			require.NoError(t, err)
			assert.Equal(t, session.MFARecoveryPending, got.MFA)
			assertInstant(t, "EnrolmentOriginDeadline", marker, got.EnrolmentOriginDeadline)
			assertInstant(t, "RecoveredAt", recoveredAt, got.RecoveredAt)
		})
	}
}

// testRecoveryCodeSpentShared proves a saved recovery code spent through
// sqlstore is refused through pgx and through gorm, and no longer matches
// there, while the rest of the set does.
func testRecoveryCodeSpentShared(t *testing.T, b backends) {
	t.Helper()

	const user identity.UserID = "cross-backend-recovery-user"
	hashes := make([][]byte, 3)
	for i := range hashes {
		h := sha256.Sum256([]byte{byte(i)})
		hashes[i] = h[:]
	}
	at := time.Now().UTC().Truncate(time.Microsecond)

	writer := b.recoveryCodeStore(t, "sqlstore")
	require.NoError(t, writer.ReplaceSet(t.Context(), user, hashes, at))
	spent, err := writer.Spend(t.Context(), user, hashes[0], at)
	require.NoError(t, err)
	require.True(t, spent)

	for _, reader := range []string{"pgx", "gorm"} {
		t.Run(reader, func(t *testing.T) {
			t.Parallel()

			s := b.recoveryCodeStore(t, reader)
			ok, err := s.Spend(t.Context(), user, hashes[0], at.Add(time.Minute))
			require.NoError(t, err)
			assert.False(t, ok, "a code spent through sqlstore must be refused through %s", reader)
			matched, err := s.Match(t.Context(), user, hashes[0])
			require.NoError(t, err)
			assert.False(t, matched)
			matched, err = s.Match(t.Context(), user, hashes[1])
			require.NoError(t, err)
			assert.True(t, matched, "the unspent codes must still match through %s", reader)
		})
	}
}

// testRecoveryCompletionShared proves every ordered pair of backends agrees on
// a recovery record: one completed through the writer is found with every
// field through the reader, which refuses to complete or cancel it again and
// reports its completion as the user's latest.
func testRecoveryCompletionShared(t *testing.T, b backends) {
	t.Helper()

	for _, writer := range backendNames {
		for _, reader := range backendNames {
			if writer == reader {
				continue
			}

			t.Run(writer+"_writes_"+reader+"_reads", func(t *testing.T) {
				t.Parallel()

				ctx := t.Context()
				seed := "recovery-" + writer + "-" + reader
				started := time.Now().UTC().Truncate(time.Microsecond)
				r := recovery.Record{
					ID:        crossBackendID(seed),
					User:      identity.UserID("u-" + seed),
					StartedAt: started,
					NotBefore: started.Add(time.Hour),
					Proven:    []recovery.AuthenticatorRef{{Kind: "saved", ID: "code"}, {Kind: "password", ID: "p"}},
					Reported:  []recovery.AuthenticatorRef{{Kind: recovery.MFAKind, ID: "totp"}},
				}
				w := b.recoveryRecordStore(t, writer)
				require.NoError(t, w.Insert(ctx, r))
				completedAt := r.NotBefore.Add(time.Minute)
				ok, err := w.Complete(ctx, r.ID, completedAt)
				require.NoError(t, err)
				require.True(t, ok)

				rd := b.recoveryRecordStore(t, reader)
				got, err := rd.Find(ctx, r.ID)
				require.NoError(t, err)
				want := r
				want.CompletedAt = completedAt
				assert.Equal(t, want, *got)

				ok, err = rd.Complete(ctx, r.ID, completedAt.Add(time.Minute))
				require.NoError(t, err)
				assert.False(t, ok, "a record completed through %s must not complete again through %s", writer, reader)
				n, err := rd.Cancel(ctx, r.ID, completedAt.Add(time.Minute))
				require.NoError(t, err)
				assert.Zero(t, n)

				latest, found, err := rd.LatestCompletion(ctx, r.User)
				require.NoError(t, err)
				require.True(t, found)
				assertInstant(t, "LatestCompletion", completedAt, latest)
			})
		}
	}
}

// testEnrolmentDurableFlow proves the enrolment path's durable guarantees
// hold when driven the way a real chain drives them: through session.Manager,
// not a store's raw methods, and through mfa.TOTP's Enroller API, not the
// enrolment store's raw methods. Each backend runs, on its own database
// connection, one complete flow: a session is created, marked
// enrolment-pending and saved; loading it back shows the lowered deadlines,
// the marker and the generation the mark and a begin left; the device is
// proven with a valid code and an emailed code is issued; completing without
// that code is refused; the raw column the code is sealed into is never the
// plaintext; redeeming the emailed code enrols the user; and restoring the
// deadlines on satisfy, then rotating the handle, leaves a session that
// reloads with its ordinary deadlines and no marker or generation. An
// injected clock keeps every deadline computed here exact against what a
// reload reports, so timestamp truncation and the NULL/zero round trip of the
// enrolment-origin marker are pinned along the way.
func testEnrolmentDurableFlow(t *testing.T, b backends) {
	t.Helper()

	const (
		lifetime        = 15 * time.Minute
		idleTimeout     = time.Hour
		absoluteTimeout = 24 * time.Hour
	)

	for _, name := range backendNames {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()

			at := time.Now().UTC().Truncate(time.Microsecond)
			clk := storefix.NewClock(at)

			sessions, err := session.NewManager(
				session.WithStore(b.clockedSessionStore(t, name, clk)),
				session.WithClock(clk),
				session.WithIdleTimeout(idleTimeout),
				session.WithAbsoluteTimeout(absoluteTimeout),
			)
			require.NoError(t, err)

			method, err := mfa.NewTOTP(b.enrolmentStore(t, name), "Durable "+name, mfa.WithClock(clk))
			require.NoError(t, err)

			user := identity.UserID("u-enrolment-flow-" + name)

			s, err := sessions.Create(ctx, user, session.WithFirstFactor(factor.Password))
			require.NoError(t, err)

			sessions.MarkEnrolmentPending(s, lifetime)

			prov, gen, err := method.BeginEnrolmentGeneration(ctx, user, "durable-"+name+"@example.com")
			require.NoError(t, err)
			require.NotEmpty(t, prov.Secret)

			s.EnrolmentGeneration = gen
			require.NoError(t, sessions.Save(ctx, s))

			loaded, err := sessions.Load(ctx, s.ID)
			require.NoError(t, err)
			assert.Equal(t, session.MFAEnrolmentPending, loaded.MFA)
			assert.Equal(t, gen, loaded.EnrolmentGeneration)
			assertInstant(t, "AbsoluteExpiresAt", at.Add(lifetime), loaded.AbsoluteExpiresAt)
			assert.False(t, loaded.IdleExpiresAt.After(loaded.AbsoluteExpiresAt),
				"the idle deadline never outlives the lowered absolute one")
			assertInstant(t, "EnrolmentOriginDeadline", at.Add(absoluteTimeout), loaded.EnrolmentOriginDeadline)

			code, err := totp.GenerateCode(prov.Secret, at)
			require.NoError(t, err)

			const emailCodeTTL = 10 * time.Minute
			emailCode, err := method.ProveDevice(ctx, user, gen, code, true, emailCodeTTL)
			require.NoError(t, err)
			require.NotEmpty(t, emailCode)

			err = method.CompleteEnrolment(ctx, user, gen)
			require.ErrorIs(t, err, mfa.ErrInvalidCode,
				"completion without the emailed code must be refused")

			raw := b.rawEmailCode(t, user)
			assert.NotEmpty(t, raw)
			assert.NotEqual(t, emailCode, raw, "the raw email_code column must not be the plaintext code")

			require.NoError(t, method.RedeemEmailCode(ctx, user, gen, emailCode))

			enrolled, err := method.Enrolled(ctx, user)
			require.NoError(t, err)
			assert.True(t, enrolled, "redeeming the emailed code must enrol the user")

			loaded.MFA = session.MFASatisfied
			loaded.MFASatisfiedAt = at
			require.NoError(t, sessions.RestoreEnrolmentDeadlines(loaded))

			rotated, err := sessions.Rotate(ctx, loaded)
			require.NoError(t, err)

			reloaded, err := sessions.Load(ctx, rotated.ID)
			require.NoError(t, err)
			assert.Equal(t, session.MFASatisfied, reloaded.MFA)
			assert.True(t, reloaded.EnrolmentOriginDeadline.IsZero(),
				"the enrolment-origin marker must be cleared once restored, round-tripping NULL back to zero")
			assert.Equal(t, id.ID{}, reloaded.EnrolmentGeneration,
				"the enrolment generation must be cleared once restored")
			assertInstant(t, "AbsoluteExpiresAt", at.Add(absoluteTimeout), reloaded.AbsoluteExpiresAt)
			assertInstant(t, "IdleExpiresAt", at.Add(idleTimeout), reloaded.IdleExpiresAt)
		})
	}
}
