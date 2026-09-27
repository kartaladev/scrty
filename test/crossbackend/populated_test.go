package crossbackend_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"io/fs"
	"os"
	"testing"
	"time"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/apikey"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/migrate"
	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/onetime"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/seal"
	"github.com/kartaladev/scrty/signingkey"
	"github.com/kartaladev/scrty/sqlstore"
	"github.com/kartaladev/scrty/test"
)

// populatedFixtureDir and populatedVersionTable name the test-only migration
// set at test/testdata/migrations/populated: it adds a NOT NULL column with a
// default to every security-state table. It is applied only after this test
// has seeded a row in each table, so its Up runs against populated tables,
// not empty ones, which is the scenario "New non-nullable column on a
// populated table" pins.
const populatedVersionTable = "goose_populated_probe"

// populatedFixtureFS is the file system the fixture set's own directory lives
// under, relative to this package's directory: it is a sibling of the other
// test fixtures under test/testdata/migrations, not private to this package.
func populatedFixtureFS() fs.FS { return os.DirFS("../testdata/migrations") }

// applyPopulatedFixture applies the fixture set to db and rolls it back at
// cleanup. Cleanup runs before test.RunTestPostgres's own teardown (Go runs
// t.Cleanup functions last-registered-first, and this one is registered after
// migratedConn's), so by the time that teardown's leftover-table check runs,
// this set's ALTER TABLE statements are undone by DownTo(0) and its version
// table — which goose never drops on its own — is dropped here, leaving
// nothing of this fixture for that check to see.
func applyPopulatedFixture(t *testing.T, db *sql.DB) {
	t.Helper()

	sub, err := fs.Sub(populatedFixtureFS(), "populated")
	require.NoError(t, err)

	provider, err := goose.NewProvider(goose.DialectPostgres, db, sub, goose.WithTableName(populatedVersionTable))
	require.NoError(t, err)

	t.Cleanup(func() {
		// Not t.Context(): it may already be cancelled by the time cleanup
		// runs.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if _, err := provider.DownTo(ctx, 0); err != nil {
			t.Errorf("roll back the populated fixture: %v", err)
		}
		if _, err := db.ExecContext(ctx, "DROP TABLE IF EXISTS "+populatedVersionTable); err != nil {
			t.Errorf("drop the populated fixture's version table: %v", err)
		}
	})

	_, err = provider.Up(t.Context())
	require.NoError(t, err, "the fixture migration must apply over already-populated tables")
}

// populatedSeed is what seedPopulated wrote into each of the nine
// security-state tables, and what readBackPopulated needs to find it again.
// It seeds one OIDC flow per backend name, since completing a flow is the
// only way a FlowStore reads one back, and completing is single-use.
type populatedSeed struct {
	now          time.Time
	sessionID    string
	signingKID   string
	attemptUser  string
	mfaUser      identity.UserID
	apiKeyID     id.ID
	tokenID      id.ID
	linkProvider string
	linkIssuer   string
	linkSubject  string
	handoffToken string
	flowHandle   map[string]string // backend name -> its own flow's handle
	flowState    map[string]string // backend name -> its own flow's state
}

// seedPopulated inserts one row into each of the nine security-state tables
// through the sqlstore stores, before the fixture migration runs.
func seedPopulated(t *testing.T, db *sql.DB, c seal.Cipher) populatedSeed {
	t.Helper()

	ctx := t.Context()
	now := time.Date(2030, 1, 1, 10, 0, 0, 123456000, time.UTC)

	seed := populatedSeed{
		now:          now,
		sessionID:    "populated-session",
		signingKID:   "populated-kid",
		attemptUser:  "populated-user",
		mfaUser:      identity.UserID("populated-mfa-user"),
		apiKeyID:     crossBackendID("populated-api-key"),
		tokenID:      crossBackendID("populated-token"),
		linkProvider: "corp",
		linkIssuer:   "https://populated.example",
		linkSubject:  "populated-subject",
		handoffToken: "populated-handoff",
		flowHandle:   map[string]string{},
		flowState:    map[string]string{},
	}

	clock := func() time.Time { return now }

	sessions, err := sqlstore.NewSessionStore(db, c, sqlstore.WithClock(clock))
	require.NoError(t, err)
	require.NoError(t, sessions.Create(ctx, crossBackendSession(seed.sessionID)))

	keys, err := sqlstore.NewSigningKeyStore(db, c)
	require.NoError(t, err)
	require.NoError(t, keys.Store(ctx, signingkey.Record{
		Kid: seed.signingKID, Alg: "ES256", Private: []byte("PKCS8-populated"),
		PublicJWK: []byte(`{"kty":"EC","kid":"populated-kid"}`), CreatedAt: now,
	}))

	attempts, err := sqlstore.NewAttemptStore(db)
	require.NoError(t, err)
	require.NoError(t, attempts.RecordFailure(ctx, seed.attemptUser, now))

	enrolments, err := sqlstore.NewEnrolmentStore(db, c)
	require.NoError(t, err)
	require.NoError(t, enrolments.PutPending(ctx, mfa.Enrolment{
		User: seed.mfaUser, Secret: []byte("TOTP-SECRET-populated"), CreatedAt: now,
	}))

	apiKeys, err := sqlstore.NewAPIKeyStore(db)
	require.NoError(t, err)
	keyDigest := sha256.Sum256([]byte("populated-key-secret"))
	require.NoError(t, apiKeys.Put(ctx, apikey.Key{
		ID: seed.apiKeyID, Principal: "populated-principal", Name: "populated key",
		Scopes: []string{"read"}, SecretDigest: keyDigest[:], CreatedAt: now,
	}))

	tokens, err := sqlstore.NewOneTimeStore(db)
	require.NoError(t, err)
	tokenDigest := sha256.Sum256([]byte("populated-token-secret"))
	require.NoError(t, tokens.Insert(ctx, onetime.Token{
		ID: seed.tokenID, Purpose: "populated", Subject: "populated-subject",
		SecretHash: tokenDigest[:], IssuedAt: now, ExpiresAt: now.Add(time.Hour),
	}))

	links, err := sqlstore.NewLinkStore(db)
	require.NoError(t, err)
	linkID, err := id.NewV7Generator().NewID()
	require.NoError(t, err)
	require.NoError(t, links.Insert(ctx, oidc.Link{
		ID: linkID, Provider: seed.linkProvider, Issuer: seed.linkIssuer, Subject: seed.linkSubject,
		UserID: "populated-user", CreatedAt: now,
	}))

	handoffs, err := sqlstore.NewHandoffStore(db)
	require.NoError(t, err)
	handoffDigest := sha256.Sum256([]byte("populated-handoff-secret"))
	require.NoError(t, handoffs.Insert(ctx, oidc.HandoffRecord{
		ID: crossBackendID("populated-handoff-id"), TokenID: seed.handoffToken, SecretHash: handoffDigest[:],
		UserID: "populated-user", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}))

	flows, err := sqlstore.NewFlowStore(db, sqlstore.WithClock(clock))
	require.NoError(t, err)
	for _, name := range backendNames {
		state := "populated-state-" + name
		handle, err := flows.Begin(ctx, oidc.Flow{
			Provider: "corp", State: state, Nonce: "nonce-" + name, Verifier: "verifier-" + name,
			Next: "/next", ExpiresAt: now.Add(time.Hour),
		})
		require.NoError(t, err)
		seed.flowHandle[name] = handle
		seed.flowState[name] = state
	}

	return seed
}

// readBackPopulated proves every row seed describes reads back through the
// named backend's stores without error, once the fixture migration has run
// over them.
func readBackPopulated(t *testing.T, b backends, name string, seed populatedSeed) {
	t.Helper()

	ctx := t.Context()

	_, err := b.sessionStore(t, name).Load(ctx, seed.sessionID)
	require.NoError(t, err, "session")

	_, err = b.signingKeyStore(t, name).LoadAll(ctx)
	require.NoError(t, err, "signing keys")

	_, err = b.attemptStore(t, name).FailureCount(ctx, seed.attemptUser, seed.now.Add(-time.Minute))
	require.NoError(t, err, "login attempts")

	_, ok, err := b.enrolmentStore(t, name).Get(ctx, seed.mfaUser)
	require.NoError(t, err, "MFA enrolments")
	require.True(t, ok, "the seeded enrolment must still be found")

	_, err = b.apiKeyStore(t, name).Get(ctx, seed.apiKeyID)
	require.NoError(t, err, "API keys")

	_, err = b.oneTimeStore(t, name).FindByID(ctx, seed.tokenID)
	require.NoError(t, err, "one-time tokens")

	_, err = b.linkStore(t, name).FindByExternal(ctx, seed.linkProvider, seed.linkIssuer, seed.linkSubject)
	require.NoError(t, err, "OIDC links")

	_, err = b.handoffStore(t, name).FindByTokenID(ctx, seed.handoffToken)
	require.NoError(t, err, "OIDC handoffs")

	_, err = b.flowStore(t, name).Complete(ctx, seed.flowHandle[name], "corp", seed.flowState[name])
	require.NoError(t, err, "OIDC flows")
}

// TestPopulatedMigrationAddsNotNullColumn proves the populated-database
// migration rule: a migration that adds a NOT NULL column with a default
// applies over tables already holding rows, and every one of those rows still
// reads back through every backend's stores afterward.
func TestPopulatedMigrationAddsNotNullColumn(t *testing.T) {
	t.Parallel()

	set := migrate.SecurityState()
	conn := test.RunTestPostgres(t,
		test.WithTestPostgresMigrations(set.FS(), set.Dir, set.VersionTable),
		test.WithTestPostgresLeftoverTableCheck(),
	)
	conn.DB.SetMaxOpenConns(crossBackendPoolSize)

	c := testCipher(t)
	seed := seedPopulated(t, conn.DB, c)

	applyPopulatedFixture(t, conn.DB)

	b := backends{conn: conn, pool: openPgxPool(t, conn.DSN), gdb: openGormDB(t, conn.DSN), cipher: c}

	for _, name := range backendNames {
		t.Run(name, func(t *testing.T) {
			readBackPopulated(t, b, name, seed)
		})
	}
}
