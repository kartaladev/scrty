package sqlstore_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/onetime"
	"github.com/kartaladev/scrty/seal"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/signingkey"
	"github.com/kartaladev/scrty/sqlstore"
	"github.com/kartaladev/scrty/test"
	"github.com/kartaladev/scrty/test/internal/storefix"
	"github.com/kartaladev/scrty/test/storetest"
)

// runAmbient runs the ambient suite over the store newWith builds, on conn.
func runAmbient[S any](conn test.PostgresConn, newWith storeFactory[S], a storetest.Ambient[S]) func(t *testing.T) {
	return func(t *testing.T) {
		t.Parallel()

		h := durableHarness(conn, newWith)
		t.Run("sqlstore", func(t *testing.T) { storetest.RunAmbientTx(t, h, a) })
	}
}

func TestAmbientTx(t *testing.T) {
	t.Parallel()

	// Every store has a table of its own, so the stores share one database.
	conn := migratedDB(t)
	c := storefix.TestCipher(t)
	foreign := storefix.CipherOf(t, seal.WithEncryptionKey("k-foreign", storefix.SealKey(t)))

	t.Run("sessions", runAmbient(conn, func(t *testing.T, db *sql.DB, opts ...sqlstore.Option) session.Store {
		return newSessionStore(t, db, c, opts...)
	}, storefix.SessionAmbient()))
	t.Run("one-time tokens", runAmbient(conn, newOneTimeStore, storefix.OneTimeAmbient[*sqlstore.OneTimeStore]()))
	t.Run("login attempts", runAmbient(conn, newAttemptStore, storefix.AttemptAmbient[*sqlstore.AttemptStore]()))
	t.Run("signing keys", runAmbient(conn, func(t *testing.T, db *sql.DB, opts ...sqlstore.Option) signingkey.KeyStore {
		return newSigningKeyStore(t, db, c, opts...)
	}, storefix.SigningKeyAmbient(func() (signingkey.KeyStore, error) {
		return sqlstore.NewSigningKeyStore(conn.DB, foreign)
	})))
	t.Run("MFA enrolments", runAmbient(conn, func(t *testing.T, db *sql.DB, opts ...sqlstore.Option) mfa.EnrolmentStore {
		return newEnrolmentStore(t, db, c, opts...)
	}, storefix.EnrolmentAmbient()))
	t.Run("API keys", runAmbient(conn, newAPIKeyStore, storefix.APIKeyAmbient[*sqlstore.APIKeyStore]()))
	t.Run("OIDC links", runAmbient(conn, newLinkStore, storefix.LinkAmbient[*sqlstore.LinkStore]()))
	t.Run("OIDC flows", runAmbient(conn, newFlowStore, storefix.FlowAmbient[*sqlstore.FlowStore]()))
	t.Run("OIDC handoffs", runAmbient(conn, newHandoffStore, storefix.HandoffAmbient[*sqlstore.HandoffStore]()))
}

func TestAmbientTx_Scenarios(t *testing.T) {
	t.Parallel()

	conn := migratedDB(t)
	c := storefix.TestCipher(t)

	type testCase struct {
		name   string
		assert func(t *testing.T, ctx context.Context, db *sql.DB)
	}

	begin := func(t *testing.T, ctx context.Context, db *sql.DB) (context.Context, *sql.Tx) {
		t.Helper()
		tx, err := db.BeginTx(ctx, nil)
		require.NoError(t, err)
		t.Cleanup(func() { _ = tx.Rollback() })
		return sqlstore.WithTx(ctx, tx), tx
	}

	cases := []testCase{
		{
			name: "a session saved in a transaction the caller rolls back does not exist",
			assert: func(t *testing.T, ctx context.Context, db *sql.DB) {
				sessions := newSessionStore(t, db, c)
				txCtx, tx := begin(t, ctx, db)
				require.NoError(t, sessions.Create(txCtx, storefix.DurableSession("scenario-rolled-back", time.Now())))
				require.NoError(t, tx.Rollback())

				_, err := sessions.Load(ctx, "scenario-rolled-back")
				require.ErrorIs(t, err, session.ErrSessionNotFound)
			},
		},
		{
			name: "deleting a user's other sessions in a transaction the caller rolls back deletes none",
			assert: func(t *testing.T, ctx context.Context, db *sql.DB) {
				sessions := newSessionStore(t, db, c)
				keep, other := storefix.DurableSession("scenario-keep", time.Now()), storefix.DurableSession("scenario-other", time.Now())
				other.UserID = keep.UserID
				require.NoError(t, sessions.Create(ctx, keep))
				require.NoError(t, sessions.Create(ctx, other))

				txCtx, tx := begin(t, ctx, db)
				n, err := sessions.DeleteByUserExcept(txCtx, keep.UserID, keep.ID)
				require.NoError(t, err)
				require.Equal(t, 1, n)
				require.NoError(t, tx.Rollback())

				_, err = sessions.Load(ctx, other.ID)
				require.NoError(t, err, "the rolled-back delete must leave the other session")
				_, err = sessions.Load(ctx, keep.ID)
				require.NoError(t, err)
			},
		},
		{
			name: "a login attempt and a consumption in a transaction the caller commits are both kept",
			assert: func(t *testing.T, ctx context.Context, db *sql.DB) {
				attempts, tokens := newAttemptStore(t, db), newOneTimeStore(t, db)
				tok := storefix.AmbientToken(100)
				require.NoError(t, tokens.Insert(ctx, tok))
				since := time.Now().Add(-time.Minute)

				txCtx, tx := begin(t, ctx, db)
				require.NoError(t, attempts.RecordFailure(txCtx, "scenario-committed", time.Now()))
				require.NoError(t, tokens.Consume(txCtx, tok.ID, time.Now()))
				require.NoError(t, tx.Commit())

				n, err := attempts.FailureCount(ctx, "scenario-committed", since)
				require.NoError(t, err)
				assert.Equal(t, 1, n, "the attempt is missing after the commit")
				got, err := tokens.FindByID(ctx, tok.ID)
				require.NoError(t, err)
				assert.False(t, got.ConsumedAt.IsZero(), "the consumption is missing after the commit")
			},
		},
		{
			name: "a refused consumption between two saves leaves the transaction to commit both",
			assert: func(t *testing.T, ctx context.Context, db *sql.DB) {
				sessions, tokens := newSessionStore(t, db, c), newOneTimeStore(t, db)
				tok := storefix.AmbientToken(101)
				require.NoError(t, tokens.Insert(ctx, tok))
				require.NoError(t, tokens.Consume(ctx, tok.ID, time.Now()))

				txCtx, tx := begin(t, ctx, db)
				require.NoError(t, sessions.Create(txCtx, storefix.DurableSession("scenario-S", time.Now())))
				require.ErrorIs(t, tokens.Consume(txCtx, tok.ID, time.Now()), onetime.ErrTokenNotFound)
				require.NoError(t, sessions.Create(txCtx, storefix.DurableSession("scenario-T", time.Now())))
				require.NoError(t, tx.Commit())

				for _, sid := range []string{"scenario-S", "scenario-T"} {
					_, err := sessions.Load(ctx, sid)
					assert.NoError(t, err, "session %s is missing after the commit", sid)
				}
			},
		},
		{
			name: "every store creates, reads and deletes with only the security-state set applied",
			assert: func(t *testing.T, ctx context.Context, db *sql.DB) {
				assert.True(t, storefix.ExistsCtx(ctx, t, db, `SELECT to_regclass('users') IS NULL`), "a users table exists")
				assertConsumerOwnedIdentity(ctx, t, db, c)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, t.Context(), conn.DB)
		})
	}
}

// assertConsumerOwnedIdentity runs each store's create, read and delete (or,
// for the signing-key and API key stores, whose contracts delete nothing,
// its create, read and the write that retires the record) against db, which
// holds the security-state tables and no identity table.
func assertConsumerOwnedIdentity(ctx context.Context, t *testing.T, db *sql.DB, c seal.Cipher) {
	t.Helper()

	const user = "identity-user"

	sessions := newSessionStore(t, db, c)
	require.NoError(t, sessions.Create(ctx, storefix.DurableSession("identity-sid", time.Now())))
	_, err := sessions.Load(ctx, "identity-sid")
	require.NoError(t, err)
	require.NoError(t, sessions.Delete(ctx, "identity-sid"))

	tokens := newOneTimeStore(t, db)
	tok := storefix.AmbientToken(200)
	tok.Purpose, tok.IssuedAt, tok.ExpiresAt = "identity", time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)
	require.NoError(t, tokens.Insert(ctx, tok))
	_, err = tokens.FindByID(ctx, tok.ID)
	require.NoError(t, err)
	n, err := tokens.DeleteExpiredBefore(ctx, "identity", time.Now())
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	attempts := newAttemptStore(t, db)
	require.NoError(t, attempts.RecordFailure(ctx, user, time.Now()))
	n, err = attempts.FailureCount(ctx, user, time.Now().Add(-time.Minute))
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	require.NoError(t, attempts.Reset(ctx, user))

	keys := newSigningKeyStore(t, db, c)
	require.NoError(t, keys.Store(ctx, storefix.SigningKey("identity-kid", []byte("PKCS8-IDENTITY"))))
	_, err = keys.LoadAll(ctx)
	require.NoError(t, err)

	enrolments := newEnrolmentStore(t, db, c)
	require.NoError(t, enrolments.PutPending(ctx, storefix.Pending(user, "TOTP-SECRET")))
	_, ok, err := enrolments.Get(ctx, user)
	require.NoError(t, err)
	require.True(t, ok)
	require.NoError(t, enrolments.Delete(ctx, user))

	apiKeys := newAPIKeyStore(t, db)
	key := storefix.APIKey(200, user)
	require.NoError(t, apiKeys.Put(ctx, key))
	_, err = apiKeys.Get(ctx, key.ID)
	require.NoError(t, err)
	require.NoError(t, apiKeys.Revoke(ctx, key.ID, time.Now()))

	links := newLinkStore(t, db)
	require.NoError(t, links.Insert(ctx, storefix.Link(t, "corp", "https://identity.example", "s-1", user)))
	_, err = links.FindByExternal(ctx, "corp", "https://identity.example", "s-1")
	require.NoError(t, err)
	n, err = links.DeleteByUser(ctx, user)
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	clock := storefix.NewClock(storefix.OIDCStart)
	flows := newFlowStore(t, db, sqlstore.WithClock(clock))
	h, err := flows.Begin(ctx, storefix.Flow("identity", "identity-state"))
	require.NoError(t, err)
	_, err = flows.Complete(ctx, h, "identity", "identity-state")
	require.NoError(t, err)
	_, err = flows.DeleteExpired(ctx, storefix.OIDCStart.Add(time.Hour))
	require.NoError(t, err)

	handoffs := newHandoffStore(t, db)
	require.NoError(t, handoffs.Insert(ctx, storefix.Handoff(t, "identity-token")))
	_, err = handoffs.FindByTokenID(ctx, "identity-token")
	require.NoError(t, err)
	_, err = handoffs.DeleteExpired(ctx, storefix.OIDCStart.Add(time.Hour))
	require.NoError(t, err)
}
