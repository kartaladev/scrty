package sqlstore_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

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
