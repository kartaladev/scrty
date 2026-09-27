package sqlstore_test

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/apikey"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/onetime"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/seal"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/signingkey"
	"github.com/kartaladev/scrty/sqlstore"
	"github.com/kartaladev/scrty/test"
	"github.com/kartaladev/scrty/test/storetest"
)

// exists reports whether query, a SELECT EXISTS over args, is true, read out
// of band.
func exists(t *testing.T, raw *sql.DB, query string, args ...any) bool {
	t.Helper()

	return existsCtx(t.Context(), t, raw, query, args...)
}

// existsCtx is exists under ctx.
func existsCtx(ctx context.Context, t *testing.T, raw *sql.DB, query string, args ...any) bool {
	t.Helper()

	var found bool
	require.NoError(t, raw.QueryRowContext(ctx, query, args...).Scan(&found))

	return found
}

// ambientSID is the identifier of the session record i of the ambient suite.
func ambientSID(i int) string { return fmt.Sprintf("ambient-sid-%d", i) }

// sessionAmbient is the ambient suite's view of the session store: record i
// is a session, and the refusal a save of a session that is not stored.
func sessionAmbient() storetest.Ambient[session.Store] {
	return storetest.Ambient[session.Store]{
		Write: func(ctx context.Context, s session.Store, i int) error {
			return s.Create(ctx, durableSession(ambientSID(i), time.Now()))
		},
		Present: func(t *testing.T, raw *sql.DB, i int) bool {
			return exists(t, raw, `SELECT EXISTS (SELECT 1 FROM sessions WHERE id_digest = $1)`, digest(ambientSID(i)))
		},
		Refuse: func(ctx context.Context, s session.Store) error {
			return s.Save(ctx, durableSession("ambient-sid-never-created", time.Now()))
		},
		Refusal: session.ErrSessionNotFound,
	}
}

// ambientToken is the one-time token record i of the ambient suite.
func ambientToken(i int) onetime.Token {
	tok := raceToken(0x10000 + i)
	tok.Purpose = "ambient"

	return tok
}

// oneTimeAmbient is the ambient suite's view of the one-time token store:
// record i is a token, and the refusal a consumption of a token that does
// not exist.
func oneTimeAmbient() storetest.Ambient[*sqlstore.OneTimeStore] {
	return storetest.Ambient[*sqlstore.OneTimeStore]{
		Write: func(ctx context.Context, s *sqlstore.OneTimeStore, i int) error {
			return s.Insert(ctx, ambientToken(i))
		},
		Present: func(t *testing.T, raw *sql.DB, i int) bool {
			return exists(t, raw, `SELECT EXISTS (SELECT 1 FROM one_time_tokens WHERE id = $1)`, ambientToken(i).ID)
		},
		Refuse: func(ctx context.Context, s *sqlstore.OneTimeStore) error {
			return s.Consume(ctx, ambientToken(999).ID, time.Now())
		},
		Refusal: onetime.ErrTokenNotFound,
	}
}

// attemptAmbient is the ambient suite's view of the login-attempt store:
// record i is a failure of its own user. The contract refuses nothing by a
// write, so the refusal is the reaper's refusal of a zero cutoff.
func attemptAmbient() storetest.Ambient[*sqlstore.AttemptStore] {
	user := func(i int) string { return fmt.Sprintf("ambient-user-%d", i) }

	return storetest.Ambient[*sqlstore.AttemptStore]{
		Write: func(ctx context.Context, s *sqlstore.AttemptStore, i int) error {
			return s.RecordFailure(ctx, user(i), time.Now())
		},
		Present: func(t *testing.T, raw *sql.DB, i int) bool {
			return exists(t, raw, `SELECT EXISTS (SELECT 1 FROM login_attempts WHERE username = $1)`, user(i))
		},
		Refuse: func(ctx context.Context, s *sqlstore.AttemptStore) error {
			// Refused before any statement runs, so this case cannot fail for this store;
			// the signing-key refusal is the one that runs a statement inside the transaction.
			_, err := s.DeleteAttemptsBefore(ctx, time.Time{})
			return err
		},
		Refusal: policy.ErrRetainSinceRequired,
	}
}

// signingKeyAmbient is the ambient suite's view of the signing-key store,
// over db: record i is a key. The contract refuses nothing by a write, so the
// refusal is a load that fails closed: a key sealed under a key the store's
// cipher does not hold is stored through the same context, and the load
// refuses the whole set with seal.ErrUnknownKeyID. It is read-side only, so it
// runs no failing statement either.
func signingKeyAmbient(db *sql.DB, foreign seal.Cipher) storetest.Ambient[signingkey.KeyStore] {
	kid := func(i int) string { return fmt.Sprintf("ambient-kid-%d", i) }

	return storetest.Ambient[signingkey.KeyStore]{
		Write: func(ctx context.Context, s signingkey.KeyStore, i int) error {
			return s.Store(ctx, signingKey(kid(i), []byte("PKCS8-"+kid(i))))
		},
		Present: func(t *testing.T, raw *sql.DB, i int) bool {
			return exists(t, raw, `SELECT EXISTS (SELECT 1 FROM signing_keys WHERE kid = $1)`, kid(i))
		},
		Refuse: func(ctx context.Context, s signingkey.KeyStore) error {
			other, err := sqlstore.NewSigningKeyStore(db, foreign)
			if err != nil {
				return err
			}
			if err := other.Store(ctx, signingKey("ambient-kid-foreign", []byte("PKCS8-FOREIGN"))); err != nil {
				return err
			}
			_, err = s.LoadAll(ctx)
			return err
		},
		Refusal: seal.ErrUnknownKeyID,
	}
}

// enrolmentAmbient is the ambient suite's view of the MFA store: record i is
// a pending enrolment, and the refusal a begin over a confirmed one.
func enrolmentAmbient() storetest.Ambient[mfa.EnrolmentStore] {
	user := func(i int) identity.UserID { return identity.UserID(fmt.Sprintf("ambient-user-%d", i)) }

	return storetest.Ambient[mfa.EnrolmentStore]{
		Write: func(ctx context.Context, s mfa.EnrolmentStore, i int) error {
			return s.PutPending(ctx, pending(user(i), "TOTP-SECRET"))
		},
		Present: func(t *testing.T, raw *sql.DB, i int) bool {
			return exists(t, raw, `SELECT EXISTS (SELECT 1 FROM mfa_enrolments WHERE user_id = $1)`, string(user(i)))
		},
		Refuse: func(ctx context.Context, s mfa.EnrolmentStore) error {
			if err := s.PutPending(ctx, pending("ambient-confirmed", "TOTP-SECRET")); err != nil {
				return err
			}
			if _, err := s.Confirm(ctx, "ambient-confirmed", 1000, enrolmentBegun); err != nil {
				return err
			}
			return s.PutPending(ctx, pending("ambient-confirmed", "TOTP-OTHER"))
		},
		Refusal: mfa.ErrAlreadyEnrolled,
	}
}

// apiKeyAmbient is the ambient suite's view of the API key store: record i
// is a key, and the refusal a revocation of a key that does not exist.
func apiKeyAmbient() storetest.Ambient[*sqlstore.APIKeyStore] {
	return storetest.Ambient[*sqlstore.APIKeyStore]{
		Write: func(ctx context.Context, s *sqlstore.APIKeyStore, i int) error {
			return s.Put(ctx, apiKey(i, "ambient-svc"))
		},
		Present: apiKeyPresent,
		Refuse: func(ctx context.Context, s *sqlstore.APIKeyStore) error {
			return s.Revoke(ctx, apiKey(999, "").ID, time.Now())
		},
		Refusal: apikey.ErrKeyNotFound,
	}
}

// linkAmbient is the ambient suite's view of the link store: record i is a
// link of its own subject, and the refusal a second insert of one link.
func linkAmbient() storetest.Ambient[*sqlstore.LinkStore] {
	gen := id.NewV7Generator()
	subject := func(i int) string { return fmt.Sprintf("ambient-subject-%d", i) }
	insert := func(ctx context.Context, s *sqlstore.LinkStore, subject string) error {
		linkID, err := gen.NewID()
		if err != nil {
			return err
		}
		return s.Insert(ctx, oidc.Link{
			ID: linkID, Provider: "corp", Issuer: "https://ambient.example", Subject: subject,
			UserID: "ambient-user", CreatedAt: oidcStart,
		})
	}

	return storetest.Ambient[*sqlstore.LinkStore]{
		Write: func(ctx context.Context, s *sqlstore.LinkStore, i int) error { return insert(ctx, s, subject(i)) },
		Present: func(t *testing.T, raw *sql.DB, i int) bool {
			return exists(t, raw, `SELECT EXISTS (SELECT 1 FROM oidc_links WHERE subject = $1)`, subject(i))
		},
		Refuse: func(ctx context.Context, s *sqlstore.LinkStore) error {
			if err := insert(ctx, s, "ambient-subject-twice"); err != nil {
				return err
			}
			return insert(ctx, s, "ambient-subject-twice")
		},
		Refusal: oidc.ErrLinkExists,
	}
}

// flowAmbient is the ambient suite's view of the flow store: record i is a
// flow of its own state, and the refusal a completion of an unknown handle.
func flowAmbient() storetest.Ambient[*sqlstore.FlowStore] {
	state := func(i int) string { return fmt.Sprintf("ambient-state-%d", i) }

	return storetest.Ambient[*sqlstore.FlowStore]{
		Write: func(ctx context.Context, s *sqlstore.FlowStore, i int) error {
			_, err := s.Begin(ctx, flow("ambient", state(i)))
			return err
		},
		Present: func(t *testing.T, raw *sql.DB, i int) bool {
			return exists(t, raw, `SELECT EXISTS (SELECT 1 FROM oidc_flows WHERE state = $1)`, state(i))
		},
		Refuse: func(ctx context.Context, s *sqlstore.FlowStore) error {
			_, err := s.Complete(ctx, "no-such-handle", "ambient", state(1))
			return err
		},
		Refusal: oidc.ErrInvalidState,
	}
}

// handoffAmbient is the ambient suite's view of the handoff store: record i
// is a record of its own token id, and the refusal a consumption of a token
// id that does not exist.
func handoffAmbient() storetest.Ambient[*sqlstore.HandoffStore] {
	gen := id.NewV7Generator()
	token := func(i int) string { return fmt.Sprintf("ambient-token-%d", i) }

	return storetest.Ambient[*sqlstore.HandoffStore]{
		Write: func(ctx context.Context, s *sqlstore.HandoffStore, i int) error {
			recID, err := gen.NewID()
			if err != nil {
				return err
			}
			return s.Insert(ctx, oidc.HandoffRecord{
				ID: recID, TokenID: token(i), SecretHash: []byte("digest"), UserID: "ambient-user",
				CreatedAt: oidcStart, ExpiresAt: oidcStart.Add(time.Minute),
			})
		},
		Present: func(t *testing.T, raw *sql.DB, i int) bool {
			return exists(t, raw, `SELECT EXISTS (SELECT 1 FROM oidc_handoffs WHERE token_id = $1)`, token(i))
		},
		Refuse: func(ctx context.Context, s *sqlstore.HandoffStore) error {
			return s.Consume(ctx, "ambient-token-never-issued", time.Now())
		},
		Refusal: oidc.ErrHandoffNotFound,
	}
}

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
	c := testCipher(t)

	t.Run("sessions", runAmbient(conn, func(t *testing.T, db *sql.DB, opts ...sqlstore.Option) session.Store {
		return newSessionStore(t, db, c, opts...)
	}, sessionAmbient()))
	t.Run("one-time tokens", runAmbient(conn, newOneTimeStore, oneTimeAmbient()))
	t.Run("login attempts", runAmbient(conn, newAttemptStore, attemptAmbient()))
	t.Run("signing keys", runAmbient(conn, func(t *testing.T, db *sql.DB, opts ...sqlstore.Option) signingkey.KeyStore {
		return newSigningKeyStore(t, db, c, opts...)
	}, signingKeyAmbient(conn.DB, cipherOf(t, seal.WithEncryptionKey("k-foreign", sealKey(t))))))
	t.Run("MFA enrolments", runAmbient(conn, func(t *testing.T, db *sql.DB, opts ...sqlstore.Option) mfa.EnrolmentStore {
		return newEnrolmentStore(t, db, c, opts...)
	}, enrolmentAmbient()))
	t.Run("API keys", runAmbient(conn, newAPIKeyStore, apiKeyAmbient()))
	t.Run("OIDC links", runAmbient(conn, newLinkStore, linkAmbient()))
	t.Run("OIDC flows", runAmbient(conn, newFlowStore, flowAmbient()))
	t.Run("OIDC handoffs", runAmbient(conn, newHandoffStore, handoffAmbient()))
}

func TestAmbientTx_Scenarios(t *testing.T) {
	t.Parallel()

	conn := migratedDB(t)
	c := testCipher(t)

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
				require.NoError(t, sessions.Create(txCtx, durableSession("scenario-rolled-back", time.Now())))
				require.NoError(t, tx.Rollback())

				_, err := sessions.Load(ctx, "scenario-rolled-back")
				require.ErrorIs(t, err, session.ErrSessionNotFound)
			},
		},
		{
			name: "a login attempt and a consumption in a transaction the caller commits are both kept",
			assert: func(t *testing.T, ctx context.Context, db *sql.DB) {
				attempts, tokens := newAttemptStore(t, db), newOneTimeStore(t, db)
				tok := ambientToken(100)
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
				tok := ambientToken(101)
				require.NoError(t, tokens.Insert(ctx, tok))
				require.NoError(t, tokens.Consume(ctx, tok.ID, time.Now()))

				txCtx, tx := begin(t, ctx, db)
				require.NoError(t, sessions.Create(txCtx, durableSession("scenario-S", time.Now())))
				require.ErrorIs(t, tokens.Consume(txCtx, tok.ID, time.Now()), onetime.ErrTokenNotFound)
				require.NoError(t, sessions.Create(txCtx, durableSession("scenario-T", time.Now())))
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
				assert.True(t, existsCtx(ctx, t, db, `SELECT to_regclass('users') IS NULL`), "a users table exists")
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
	require.NoError(t, sessions.Create(ctx, durableSession("identity-sid", time.Now())))
	_, err := sessions.Load(ctx, "identity-sid")
	require.NoError(t, err)
	require.NoError(t, sessions.Delete(ctx, "identity-sid"))

	tokens := newOneTimeStore(t, db)
	tok := ambientToken(200)
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
	require.NoError(t, keys.Store(ctx, signingKey("identity-kid", []byte("PKCS8-IDENTITY"))))
	_, err = keys.LoadAll(ctx)
	require.NoError(t, err)

	enrolments := newEnrolmentStore(t, db, c)
	require.NoError(t, enrolments.PutPending(ctx, pending(user, "TOTP-SECRET")))
	_, ok, err := enrolments.Get(ctx, user)
	require.NoError(t, err)
	require.True(t, ok)
	require.NoError(t, enrolments.Delete(ctx, user))

	apiKeys := newAPIKeyStore(t, db)
	key := apiKey(200, user)
	require.NoError(t, apiKeys.Put(ctx, key))
	_, err = apiKeys.Get(ctx, key.ID)
	require.NoError(t, err)
	require.NoError(t, apiKeys.Revoke(ctx, key.ID, time.Now()))

	links := newLinkStore(t, db)
	require.NoError(t, links.Insert(ctx, link(t, "corp", "https://identity.example", "s-1", user)))
	_, err = links.FindByExternal(ctx, "corp", "https://identity.example", "s-1")
	require.NoError(t, err)
	n, err = links.DeleteByUser(ctx, user)
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	clock := &testClock{now: oidcStart}
	flows := newFlowStore(t, db, sqlstore.WithClock(clock.Now))
	h, err := flows.Begin(ctx, flow("identity", "identity-state"))
	require.NoError(t, err)
	_, err = flows.Complete(ctx, h, "identity", "identity-state")
	require.NoError(t, err)
	_, err = flows.DeleteExpired(ctx, oidcStart.Add(time.Hour))
	require.NoError(t, err)

	handoffs := newHandoffStore(t, db)
	require.NoError(t, handoffs.Insert(ctx, handoff(t, "identity-token")))
	_, err = handoffs.FindByTokenID(ctx, "identity-token")
	require.NoError(t, err)
	_, err = handoffs.DeleteExpired(ctx, oidcStart.Add(time.Hour))
	require.NoError(t, err)
}
