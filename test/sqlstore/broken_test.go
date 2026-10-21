package sqlstore_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/onetime"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/seal"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/signingkey"
	"github.com/kartaladev/scrty/sqlstore"
	"github.com/kartaladev/scrty/test"
	"github.com/kartaladev/scrty/test/internal/storefix"
	"github.com/kartaladev/scrty/test/storetest"
)

// brokenVar names the environment variable that selects the one broken
// variant the child test runs, so each suite's verdict is attributable to
// that variant alone.
const brokenVar = "SQLSTORE_BROKEN"

// brokenVariants are the defects the sqlstore runs must catch. None of them is
// exported from sqlstore: each is built here, over the exported store or
// through the raw handle.
var brokenVariants = []storefix.BrokenVariant{
	{
		Name: "session-save-upserts",
		Run: func(t *testing.T) {
			db := migratedDB(t).DB
			c := storefix.TestCipher(t)
			t.Run("sqlstore", func(t *testing.T) {
				storetest.RunSessionStoreSuite(t, func(t *testing.T, clk clock.Clock) session.Store {
					return storefix.SaveUpsertsStore{Store: newSessionStore(t, emptied(t, db, "sessions"), c, sqlstore.WithClock(clk))}
				})
			})
		},
		FailsCase: "saving a deleted session is not found and does not bring it back",
	},
	{
		Name: "onetime-read-then-write-consume",
		Run: func(t *testing.T) {
			h := durableHarness(migratedDB(t),
				func(t *testing.T, db *sql.DB, opts ...sqlstore.Option) readThenWriteConsume {
					return readThenWriteConsume{OneTimeStore: newOneTimeStore(t, db, opts...), db: db}
				})
			t.Run("sqlstore", func(t *testing.T) {
				storetest.RunConsumeRace(t, h, storefix.ConsumeRace[readThenWriteConsume]())
			})
		},
		FailsCase: "exactly one consumption wins per record",
		FailsWith: "more than one successful consumption",
	},
	{
		Name: "signingkey-identity-cipher",
		Run: func(t *testing.T) {
			conn := migratedDB(t)
			h := durableHarness(conn, func(t *testing.T, db *sql.DB, opts ...sqlstore.Option) signingkey.KeyStore {
				return newSigningKeyStore(t, db, storefix.IdentityCipher{}, opts...)
			})
			t.Run("sqlstore", func(t *testing.T) {
				// The keyring the suite hands over is ignored: every store
				// "seals" through the identity cipher.
				storetest.RunSealedColumns(t, h, storefix.SealedSigningKeys(conn.DB,
					func(t *testing.T, db *sql.DB, _ seal.Cipher) signingkey.KeyStore {
						return newSigningKeyStore(t, db, storefix.IdentityCipher{})
					}))
			})
		},
		FailsCase: "the stored value, decoded, does not hold the plaintext",
		FailsWith: "the column holds the plaintext",
	},
	{
		Name: "mfa-identity-cipher",
		Run: func(t *testing.T) {
			conn := migratedDB(t)
			h := durableHarness(conn, func(t *testing.T, db *sql.DB, opts ...sqlstore.Option) mfa.EnrolmentStore {
				return newEnrolmentStore(t, db, storefix.IdentityCipher{}, opts...)
			})
			t.Run("sqlstore", func(t *testing.T) {
				storetest.RunSealedColumns(t, h, storefix.SealedEnrolments(conn.DB,
					func(t *testing.T, db *sql.DB, _ seal.Cipher) mfa.EnrolmentStore {
						return newEnrolmentStore(t, db, storefix.IdentityCipher{})
					}))
			})
		},
		FailsCase: "the stored value, decoded, does not hold the plaintext",
		FailsWith: "the decoded column holds the plaintext",
	},
	{
		Name: "signingkey-missing-aad-cipher",
		Run: func(t *testing.T) {
			conn := migratedDB(t)
			c := storefix.MissingAADCipher{Cipher: storefix.TestCipher(t)}
			h := durableHarness(conn, func(t *testing.T, db *sql.DB, opts ...sqlstore.Option) signingkey.KeyStore {
				return newSigningKeyStore(t, db, c, opts...)
			})
			t.Run("sqlstore", func(t *testing.T) {
				storetest.RunSealedColumns(t, h, storefix.SealedSigningKeys(conn.DB,
					func(t *testing.T, db *sql.DB, c seal.Cipher) signingkey.KeyStore {
						return newSigningKeyStore(t, db, storefix.MissingAADCipher{Cipher: c})
					}))
			})
		},
		FailsCase: "a sealed value copied to another record does not open there",
	},
	{
		Name: "mfa-missing-aad-cipher",
		Run: func(t *testing.T) {
			conn := migratedDB(t)
			c := storefix.MissingAADCipher{Cipher: storefix.TestCipher(t)}
			h := durableHarness(conn, func(t *testing.T, db *sql.DB, opts ...sqlstore.Option) mfa.EnrolmentStore {
				return newEnrolmentStore(t, db, c, opts...)
			})
			t.Run("sqlstore", func(t *testing.T) {
				// Every store the suite builds seals through the default
				// cipher over the suite's keyring, with the AAD dropped.
				storetest.RunSealedColumns(t, h, storefix.SealedEnrolments(conn.DB,
					func(t *testing.T, db *sql.DB, c seal.Cipher) mfa.EnrolmentStore {
						return newEnrolmentStore(t, db, storefix.MissingAADCipher{Cipher: c})
					}))
			})
		},
		FailsCase: "a sealed value copied to another record does not open there",
	},
	{
		Name: "mfa-email-code-identity-cipher",
		Run: func(t *testing.T) {
			conn := migratedDB(t)
			h := durableHarness(conn, func(t *testing.T, db *sql.DB, opts ...sqlstore.Option) mfa.EnrolmentStore {
				return newEnrolmentStore(t, db, storefix.IdentityCipher{}, opts...)
			})
			t.Run("sqlstore", func(t *testing.T) {
				storetest.RunSealedColumns(t, h, storefix.SealedEmailCodes(conn.DB,
					func(t *testing.T, db *sql.DB, _ seal.Cipher) mfa.EnrolmentStore {
						return newEnrolmentStore(t, db, storefix.IdentityCipher{})
					}))
			})
		},
		FailsCase: "the stored value, decoded, does not hold the plaintext",
		FailsWith: "the decoded column holds the plaintext",
	},
	{
		Name: "mfa-email-code-missing-aad-cipher",
		Run: func(t *testing.T) {
			conn := migratedDB(t)
			c := storefix.MissingAADCipher{Cipher: storefix.TestCipher(t)}
			h := durableHarness(conn, func(t *testing.T, db *sql.DB, opts ...sqlstore.Option) mfa.EnrolmentStore {
				return newEnrolmentStore(t, db, c, opts...)
			})
			t.Run("sqlstore", func(t *testing.T) {
				storetest.RunSealedColumns(t, h, storefix.SealedEmailCodes(conn.DB,
					func(t *testing.T, db *sql.DB, c seal.Cipher) mfa.EnrolmentStore {
						return newEnrolmentStore(t, db, storefix.MissingAADCipher{Cipher: c})
					}))
			})
		},
		FailsCase: "a sealed value copied to another record does not open there",
	},
	{
		Name: "mfa-read-then-write-accept-step",
		Run: func(t *testing.T) {
			c := storefix.TestCipher(t)
			h := durableHarness(migratedDB(t),
				func(t *testing.T, db *sql.DB, opts ...sqlstore.Option) readThenWriteAcceptStep {
					return readThenWriteAcceptStep{EnrolmentStore: newEnrolmentStore(t, db, c, opts...), db: db}
				})
			t.Run("sqlstore", func(t *testing.T) {
				storetest.RunStepAcceptRace(t, h, storefix.StepRace[readThenWriteAcceptStep]())
			})
		},
		FailsCase: "exactly one acceptance of a step wins per record",
		FailsWith: "more than one successful acceptance of a step",
	},
	{
		Name: "link-upsert-insert",
		Run: func(t *testing.T) {
			h := durableHarness(migratedDB(t), func(t *testing.T, db *sql.DB, opts ...sqlstore.Option) upsertLinkInsert {
				return upsertLinkInsert{LinkStore: newLinkStore(t, db, opts...), db: db}
			})
			t.Run("sqlstore", func(t *testing.T) {
				storetest.RunLinkInsertRace(t, h, storefix.LinkRace[upsertLinkInsert]())
			})
		},
		FailsCase: "exactly one insert wins per record",
		FailsWith: "more than one successful insert",
	},
	{
		Name: "session-store-bypasses-the-transaction",
		Run: func(t *testing.T) {
			c := storefix.TestCipher(t)
			h := durableHarness(migratedDB(t), func(t *testing.T, db *sql.DB, _ ...sqlstore.Option) session.Store {
				return newSessionStore(t, db, c, sqlstore.WithTxResolver(noTransaction))
			})
			t.Run("sqlstore", func(t *testing.T) { storetest.RunAmbientTx(t, h, storefix.SessionAmbient()) })
		},
		FailsCase: "a write inside a rolled back transaction is discarded",
		FailsWith: "the store did not write in it",
	},
	{
		// Every operation runs outside the caller's transaction, Supersede in
		// a transaction of the store's own.
		Name: "session-family-opens-its-own-transaction",
		Run: func(t *testing.T) {
			c := storefix.TestCipher(t)
			h := durableHarness(migratedDB(t), func(t *testing.T, db *sql.DB, _ ...sqlstore.Option) session.Store {
				return newSessionStore(t, db, c, sqlstore.WithTxResolver(noTransaction))
			})
			t.Run("sqlstore", func(t *testing.T) { storetest.RunSessionFamilyAmbientTx(t, h) })
		},
		FailsCase: "a supersession inside a rolled back transaction is discarded",
		FailsWith: "the store did not supersede in it",
	},
	{
		Name: "session-family-deletes-in-one-pass",
		Run: func(t *testing.T) {
			c := storefix.TestCipher(t)
			conn := migratedDB(t)
			h := durableHarness(conn, func(t *testing.T, db *sql.DB, opts ...sqlstore.Option) session.Store {
				return singlePassFamilyDelete{Store: newSessionStore(t, db, c, opts...), db: db}
			})
			h.Begin = beginTracked(conn.DB)
			t.Run("sqlstore", func(t *testing.T) { storetest.RunSessionFamilyRevocationRace(t, h) })
		},
		FailsCase: "a family revocation waiting on a supersession removes its successor",
		FailsWith: "the revocation did not see the successor",
	},
	{
		Name: "session-supersede-reads-the-successor-before-locking-it",
		Run: func(t *testing.T) {
			c := storefix.TestCipher(t)
			h := durableHarness(migratedDB(t), func(t *testing.T, db *sql.DB, opts ...sqlstore.Option) session.Store {
				return readThenSupersede{Store: newSessionStore(t, db, c, opts...), db: db}
			})
			t.Run("sqlstore", func(t *testing.T) { storetest.RunSessionSuccessorAdvanceRace(t, h) })
		},
		FailsCase: "a supersession requiring an unpresented successor that waited on its presentation is refused",
		FailsWith: "it judged the successor before locking it",
	},
	{
		Name: "session-mark-presented-reads-supersession-before-locking",
		Run: func(t *testing.T) {
			c := storefix.TestCipher(t)
			h := durableHarness(migratedDB(t), func(t *testing.T, db *sql.DB, opts ...sqlstore.Option) session.Store {
				return readThenMark{Store: newSessionStore(t, db, c, opts...), db: db}
			})
			t.Run("sqlstore", func(t *testing.T) { storetest.RunSessionPresentationRace(t, h) })
		},
		FailsCase: "a first presentation that waited on its session's supersession is refused",
		FailsWith: "it judged the session before locking it",
	},
	lockOrderVariant("session-supersede-locks-the-successor-first", false),
	lockOrderVariant("session-supersede-locks-in-statement-order", true),
}

// attachedTxKey is the context key beginTracked attaches its transaction
// under, beside sqlstore.WithTx, so a broken variant can write in it as the
// store does: sqlstore does not export its own lookup.
type attachedTxKey struct{}

// beginTracked is a harness Begin that begins a transaction of db and
// attaches it with sqlstore.WithTx and under attachedTxKey.
func beginTracked(db *sql.DB) func(t *testing.T) (context.Context, func() error, func() error) {
	return func(t *testing.T) (context.Context, func() error, func() error) {
		t.Helper()
		tx, err := db.BeginTx(t.Context(), nil)
		require.NoError(t, err)
		ctx := context.WithValue(sqlstore.WithTx(t.Context(), tx), attachedTxKey{}, tx)
		return ctx, tx.Commit, tx.Rollback
	}
}

// singlePassFamilyDelete revokes a family with one DELETE, as the store did
// before it repeated the delete: a delete that waited on an in-flight
// supersession cannot see the successor that supersession inserted. It runs
// in the transaction beginTracked attached, when there is one, as the store
// would.
type singlePassFamilyDelete struct {
	session.Store
	db *sql.DB
}

func (s singlePassFamilyDelete) DeleteFamily(ctx context.Context, family id.ID) (int, error) {
	var q sqlstore.DBTX = s.db
	if tx, ok := ctx.Value(attachedTxKey{}).(*sql.Tx); ok {
		q = tx
	}
	res, err := q.ExecContext(ctx, `DELETE FROM sessions WHERE family_id = $1`, family)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// readThenSupersede judges whether a supersession's observed successor was
// presented by reading it first, without a lock, and then supersedes without
// the store's own check: a presentation that commits while the supersession
// waits for the successor's row goes unnoticed.
type readThenSupersede struct {
	session.Store
	db *sql.DB
}

func (s readThenSupersede) Supersede(ctx context.Context, op session.Supersession) error {
	if op.RequireUnpresentedSuccessor && len(op.ObservedSuccessor) > 0 {
		var presented bool
		err := s.db.QueryRowContext(ctx, `SELECT first_presented_at IS NOT NULL FROM sessions WHERE id_digest = $1`,
			op.ObservedSuccessor).Scan(&presented)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if presented {
			return session.ErrSuccessorAdvanced
		}
	}
	op.RequireUnpresentedSuccessor = false
	return s.Store.Supersede(ctx, op)
}

// readThenWriteConsume consumes by reading the token, checking it is unspent,
// and then updating it unconditionally: two racers can both read "unspent"
// and both write.
type readThenWriteConsume struct {
	*sqlstore.OneTimeStore
	db *sql.DB
}

func (s readThenWriteConsume) Consume(ctx context.Context, tokenID id.ID, at time.Time) error {
	tok, err := s.FindByID(ctx, tokenID)
	if err != nil {
		return err
	}
	if !tok.ConsumedAt.IsZero() {
		return onetime.ErrTokenNotFound
	}
	_, err = s.db.ExecContext(ctx, `UPDATE one_time_tokens SET consumed_at = $2 WHERE id = $1`, tokenID, at)
	return err
}

// readThenWriteAcceptStep accepts a step by reading the enrolment, checking
// the step is later than the recorded one, and then updating it
// unconditionally: two racers can both read the old step and both write.
type readThenWriteAcceptStep struct {
	mfa.EnrolmentStore
	db *sql.DB
}

func (s readThenWriteAcceptStep) AcceptStep(ctx context.Context, user identity.UserID, step int64) (bool, error) {
	e, ok, err := s.Get(ctx, user)
	if err != nil || !ok || e.ConfirmedAt.IsZero() || e.LastStep >= step {
		return false, err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE mfa_enrolments SET last_step = $2 WHERE user_id = $1`, string(user), step)
	return err == nil, err
}

// upsertLinkInsert inserts a link or, when the external identity is linked
// already, moves it to the new user, and reports success either way: every
// racer "wins", and the last one owns the identity.
type upsertLinkInsert struct {
	*sqlstore.LinkStore
	db *sql.DB
}

func (s upsertLinkInsert) Insert(ctx context.Context, l oidc.Link) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO oidc_links (id, provider, issuer, subject, user_id, username, email,
  created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (provider, issuer, subject) DO UPDATE SET user_id = EXCLUDED.user_id`,
		l.ID, l.Provider, l.Issuer, l.Subject, string(l.UserID), l.Username, l.Email, l.CreatedAt)
	return err
}

// noTransaction is a resolver that never reports a transaction, so a store
// built with it writes through its own handle whatever the context carries.
func noTransaction(context.Context) (sqlstore.DBTX, bool) { return nil, false }

// TestBrokenSQLStore runs the broken variant named by the environment, and is
// the child half of TestSuitesCatchBrokenSQLStores. Without a variant named it
// skips.
func TestBrokenSQLStore(t *testing.T) {
	storefix.RunBrokenChild(t, brokenVar, "TestSuitesCatchBrokenSQLStores", brokenVariants)
}

// TestSuitesCatchBrokenSQLStores checks that the suites the sqlstore runs use
// fail against each broken variant, at the case guarding its defect. Each
// variant runs in its own process, because a failing suite reports through its
// own *testing.T and would fail this test with it.
func TestSuitesCatchBrokenSQLStores(t *testing.T) {
	t.Parallel()

	// The children each want PostgreSQL: start the one server they will share.
	test.EnsureTestPostgresServer(t)
	storefix.CatchBrokenVariants(t, brokenVar, "TestBrokenSQLStore", "sqlstore", brokenVariants)
}

// lockOrderVariant is a store whose re-rotation first locks the two rows it
// writes in an order of its own, through lockOutOfOrder, run through
// RunSessionSupersessionLockOrder on the harness whose row ids make that
// order the reverse of id order: locking the observed successor first on the
// default harness, and locking the old session first, the order the store's
// updates reach the rows in, on one with descending row ids (descending).
// Either deadlocks with the family revocation the case races it against.
func lockOrderVariant(name string, descending bool) storefix.BrokenVariant {
	return storefix.BrokenVariant{
		Name: name,
		Run: func(t *testing.T) {
			c := storefix.TestCipher(t)
			var ids []sqlstore.Option
			if descending {
				ids = append(ids, sqlstore.WithIDGenerator(storetest.DescendingIDs()))
			}
			h := durableHarness(migratedDB(t), func(t *testing.T, db *sql.DB, opts ...sqlstore.Option) session.Store {
				store := newSessionStore(t, db, c, append(opts, ids...)...)
				return lockOutOfOrder{Store: store, db: db, successorFirst: !descending}
			})
			t.Run("sqlstore", func(t *testing.T) { storetest.RunSessionSupersessionLockOrder(t, h) })
		},
		FailsCase: "a re-rotation and a family revocation over the same rows do not deadlock",
		FailsWith: "one side of a deadlock",
	}
}

// lockOutOfOrder supersedes through the store, but a re-rotation first locks
// Old and its observed successor, one statement each, in a transaction of
// its own that it attaches to the store: the successor first when
// successorFirst is set, Old first otherwise. The store's own id-ordered lock
// then finds both rows held already, so the order is the variant's.
type lockOutOfOrder struct {
	session.Store
	db             *sql.DB
	successorFirst bool
}

// rows returns the digests of the rows op writes, in the variant's order.
func (s lockOutOfOrder) rows(op session.Supersession) [][]byte {
	old := sha256.Sum256([]byte(op.Old))
	if s.successorFirst {
		return [][]byte{op.ObservedSuccessor, old[:]}
	}
	return [][]byte{old[:], op.ObservedSuccessor}
}

func (s lockOutOfOrder) Supersede(ctx context.Context, op session.Supersession) error {
	if len(op.ObservedSuccessor) == 0 {
		return s.Store.Supersede(ctx, op)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, digest := range s.rows(op) {
		if _, err := tx.ExecContext(ctx, `SELECT 1 FROM sessions WHERE id_digest = $1 FOR UPDATE`, digest); err != nil {
			return err
		}
	}
	if err := s.Store.Supersede(sqlstore.WithTx(ctx, tx), op); err != nil {
		return err
	}
	return tx.Commit()
}

// readThenMark records a first presentation by reading whether the session is
// superseded first, without a lock, and then running the update without the
// supersession condition: a supersession that commits while the mark waits
// for the session's row goes unnoticed, and the superseded session is marked.
type readThenMark struct {
	session.Store
	db *sql.DB
}

func (s readThenMark) MarkPresented(ctx context.Context, sessionID string, at time.Time) error {
	digest := sha256.Sum256([]byte(sessionID))
	var superseded bool
	if err := s.db.QueryRowContext(ctx, `SELECT superseded_at IS NOT NULL FROM sessions WHERE id_digest = $1`,
		digest[:]).Scan(&superseded); err != nil {
		return err
	}
	if superseded {
		return session.ErrSessionSuperseded
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET first_presented_at = $2 WHERE id_digest = $1 AND first_presented_at IS NULL`,
		digest[:], at)
	return err
}
