package pgxstore_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/onetime"
	pgxstore "github.com/kartaladev/scrty/pgx"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/seal"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/signingkey"
	"github.com/kartaladev/scrty/test/internal/storefix"
	"github.com/kartaladev/scrty/test/storetest"
)

// brokenVar names the environment variable that selects the one broken
// variant the child test runs, so each suite's verdict is attributable to
// that variant alone.
const brokenVar = "PGXSTORE_BROKEN"

// brokenVariants are the defects the pgx runs must catch. None of them is
// exported from the pgx module: each is built here, over the exported store
// or through the pool.
var brokenVariants = []storefix.BrokenVariant{
	{
		Name: "session-save-upserts",
		Run: func(t *testing.T) {
			db := migrated(t)
			c := storefix.TestCipher(t)
			t.Run("pgx", func(t *testing.T) {
				storetest.RunSessionStoreSuite(t, func(t *testing.T, clk clock.Clock) session.Store {
					return storefix.SaveUpsertsStore{Store: newSessionStore(t, emptied(t, db, "sessions"), c, pgxstore.WithClock(clk))}
				})
			})
		},
		FailsCase: "saving a deleted session is not found and does not bring it back",
	},
	{
		Name: "onetime-read-then-write-consume",
		Run: func(t *testing.T) {
			h := durableHarness(migrated(t),
				func(t *testing.T, pool *pgxpool.Pool, opts ...pgxstore.Option) readThenWriteConsume {
					return readThenWriteConsume{OneTimeStore: newOneTimeStore(t, pool, opts...), pool: pool}
				})
			t.Run("pgx", func(t *testing.T) {
				storetest.RunConsumeRace(t, h, storefix.ConsumeRace[readThenWriteConsume]())
			})
		},
		FailsCase: "exactly one consumption wins per record",
		FailsWith: "more than one successful consumption",
	},
	{
		Name: "signingkey-identity-cipher",
		Run: func(t *testing.T) {
			db := migrated(t)
			h := durableHarness(db, func(t *testing.T, pool *pgxpool.Pool, opts ...pgxstore.Option) signingkey.KeyStore {
				return newSigningKeyStore(t, pool, storefix.IdentityCipher{}, opts...)
			})
			t.Run("pgx", func(t *testing.T) {
				// The keyring the suite hands over is ignored: every store
				// "seals" through the identity cipher.
				storetest.RunSealedColumns(t, h, storefix.SealedSigningKeys(db.Pool,
					func(t *testing.T, pool *pgxpool.Pool, _ seal.Cipher) signingkey.KeyStore {
						return newSigningKeyStore(t, pool, storefix.IdentityCipher{})
					}))
			})
		},
		FailsCase: "the stored value, decoded, does not hold the plaintext",
		FailsWith: "the column holds the plaintext",
	},
	{
		Name: "mfa-identity-cipher",
		Run: func(t *testing.T) {
			db := migrated(t)
			h := durableHarness(db, func(t *testing.T, pool *pgxpool.Pool, opts ...pgxstore.Option) mfa.EnrolmentStore {
				return newEnrolmentStore(t, pool, storefix.IdentityCipher{}, opts...)
			})
			t.Run("pgx", func(t *testing.T) {
				storetest.RunSealedColumns(t, h, storefix.SealedEnrolments(db.Pool,
					func(t *testing.T, pool *pgxpool.Pool, _ seal.Cipher) mfa.EnrolmentStore {
						return newEnrolmentStore(t, pool, storefix.IdentityCipher{})
					}))
			})
		},
		FailsCase: "the stored value, decoded, does not hold the plaintext",
		FailsWith: "the decoded column holds the plaintext",
	},
	{
		Name: "signingkey-missing-aad-cipher",
		Run: func(t *testing.T) {
			db := migrated(t)
			c := storefix.MissingAADCipher{Cipher: storefix.TestCipher(t)}
			h := durableHarness(db, func(t *testing.T, pool *pgxpool.Pool, opts ...pgxstore.Option) signingkey.KeyStore {
				return newSigningKeyStore(t, pool, c, opts...)
			})
			t.Run("pgx", func(t *testing.T) {
				storetest.RunSealedColumns(t, h, storefix.SealedSigningKeys(db.Pool,
					func(t *testing.T, pool *pgxpool.Pool, c seal.Cipher) signingkey.KeyStore {
						return newSigningKeyStore(t, pool, storefix.MissingAADCipher{Cipher: c})
					}))
			})
		},
		FailsCase: "a sealed value copied to another record does not open there",
	},
	{
		Name: "mfa-missing-aad-cipher",
		Run: func(t *testing.T) {
			db := migrated(t)
			c := storefix.MissingAADCipher{Cipher: storefix.TestCipher(t)}
			h := durableHarness(db, func(t *testing.T, pool *pgxpool.Pool, opts ...pgxstore.Option) mfa.EnrolmentStore {
				return newEnrolmentStore(t, pool, c, opts...)
			})
			t.Run("pgx", func(t *testing.T) {
				// Every store the suite builds seals through the default
				// cipher over the suite's keyring, with the AAD dropped.
				storetest.RunSealedColumns(t, h, storefix.SealedEnrolments(db.Pool,
					func(t *testing.T, pool *pgxpool.Pool, c seal.Cipher) mfa.EnrolmentStore {
						return newEnrolmentStore(t, pool, storefix.MissingAADCipher{Cipher: c})
					}))
			})
		},
		FailsCase: "a sealed value copied to another record does not open there",
	},
	{
		Name: "mfa-email-code-identity-cipher",
		Run: func(t *testing.T) {
			db := migrated(t)
			h := durableHarness(db, func(t *testing.T, pool *pgxpool.Pool, opts ...pgxstore.Option) mfa.EnrolmentStore {
				return newEnrolmentStore(t, pool, storefix.IdentityCipher{}, opts...)
			})
			t.Run("pgx", func(t *testing.T) {
				storetest.RunSealedColumns(t, h, storefix.SealedEmailCodes(db.Pool,
					func(t *testing.T, pool *pgxpool.Pool, _ seal.Cipher) mfa.EnrolmentStore {
						return newEnrolmentStore(t, pool, storefix.IdentityCipher{})
					}))
			})
		},
		FailsCase: "the stored value, decoded, does not hold the plaintext",
		FailsWith: "the decoded column holds the plaintext",
	},
	{
		Name: "mfa-email-code-missing-aad-cipher",
		Run: func(t *testing.T) {
			db := migrated(t)
			c := storefix.MissingAADCipher{Cipher: storefix.TestCipher(t)}
			h := durableHarness(db, func(t *testing.T, pool *pgxpool.Pool, opts ...pgxstore.Option) mfa.EnrolmentStore {
				return newEnrolmentStore(t, pool, c, opts...)
			})
			t.Run("pgx", func(t *testing.T) {
				storetest.RunSealedColumns(t, h, storefix.SealedEmailCodes(db.Pool,
					func(t *testing.T, pool *pgxpool.Pool, c seal.Cipher) mfa.EnrolmentStore {
						return newEnrolmentStore(t, pool, storefix.MissingAADCipher{Cipher: c})
					}))
			})
		},
		FailsCase: "a sealed value copied to another record does not open there",
	},
	{
		Name: "mfa-read-then-write-accept-step",
		Run: func(t *testing.T) {
			c := storefix.TestCipher(t)
			h := durableHarness(migrated(t),
				func(t *testing.T, pool *pgxpool.Pool, opts ...pgxstore.Option) readThenWriteAcceptStep {
					return readThenWriteAcceptStep{EnrolmentStore: newEnrolmentStore(t, pool, c, opts...), pool: pool}
				})
			t.Run("pgx", func(t *testing.T) {
				storetest.RunStepAcceptRace(t, h, storefix.StepRace[readThenWriteAcceptStep]())
			})
		},
		FailsCase: "exactly one acceptance of a step wins per record",
		FailsWith: "more than one successful acceptance of a step",
	},
	{
		Name: "link-upsert-insert",
		Run: func(t *testing.T) {
			h := durableHarness(migrated(t), func(t *testing.T, pool *pgxpool.Pool, opts ...pgxstore.Option) upsertLinkInsert {
				return upsertLinkInsert{LinkStore: newLinkStore(t, pool, opts...), pool: pool}
			})
			t.Run("pgx", func(t *testing.T) {
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
			h := durableHarness(migrated(t), func(t *testing.T, pool *pgxpool.Pool, _ ...pgxstore.Option) session.Store {
				return newSessionStore(t, pool, c, pgxstore.WithTxResolver(noTransaction))
			})
			t.Run("pgx", func(t *testing.T) { storetest.RunAmbientTx(t, h, storefix.SessionAmbient()) })
		},
		FailsCase: "a write inside a rolled back transaction is discarded",
		FailsWith: "the store did not write in it",
	},
}

// upsertLinkInsert inserts a link or, when the external identity is linked
// already, moves it to the new user, and reports success either way: every
// racer "wins", and the last one owns the identity.
type upsertLinkInsert struct {
	*pgxstore.LinkStore
	pool *pgxpool.Pool
}

func (s upsertLinkInsert) Insert(ctx context.Context, l oidc.Link) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO oidc_links (id, provider, issuer, subject, user_id, username, email,
  created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (provider, issuer, subject) DO UPDATE SET user_id = EXCLUDED.user_id`,
		l.ID.String(), l.Provider, l.Issuer, l.Subject, string(l.UserID), l.Username, l.Email, l.CreatedAt)
	return err
}

// noTransaction is a resolver that never reports a transaction, so a store
// built with it writes through its own pool whatever the context carries.
func noTransaction(context.Context) (pgx.Tx, bool) { return nil, false }

// readThenWriteAcceptStep accepts a step by reading the enrolment, checking
// the step is later than the recorded one, and then updating it
// unconditionally: two racers can both read the old step and both write.
type readThenWriteAcceptStep struct {
	mfa.EnrolmentStore
	pool *pgxpool.Pool
}

func (s readThenWriteAcceptStep) AcceptStep(ctx context.Context, user identity.UserID, step int64) (bool, error) {
	e, ok, err := s.Get(ctx, user)
	if err != nil || !ok || e.ConfirmedAt.IsZero() || e.LastStep >= step {
		return false, err
	}
	_, err = s.pool.Exec(ctx, `UPDATE mfa_enrolments SET last_step = $2 WHERE user_id = $1`, string(user), step)
	return err == nil, err
}

// readThenWriteConsume consumes by reading the token, checking it is unspent,
// and then updating it unconditionally: two racers can both read "unspent"
// and both write.
type readThenWriteConsume struct {
	*pgxstore.OneTimeStore
	pool *pgxpool.Pool
}

func (s readThenWriteConsume) Consume(ctx context.Context, tokenID id.ID, at time.Time) error {
	tok, err := s.FindByID(ctx, tokenID)
	if err != nil {
		return err
	}
	if !tok.ConsumedAt.IsZero() {
		return onetime.ErrTokenNotFound
	}
	_, err = s.pool.Exec(ctx, `UPDATE one_time_tokens SET consumed_at = $2 WHERE id = $1`, tokenID.String(), at)
	return err
}

// TestBrokenPgxStore runs the broken variant named by the environment, and is
// the child half of TestSuitesCatchBrokenPgxStores. Without a variant named it
// skips.
func TestBrokenPgxStore(t *testing.T) {
	storefix.RunBrokenChild(t, brokenVar, "TestSuitesCatchBrokenPgxStores", brokenVariants)
}

// TestSuitesCatchBrokenPgxStores checks that the suites the pgx runs use
// fail against each broken variant, at the case guarding its defect. Each
// variant runs in its own process, because a failing suite reports through its
// own *testing.T and would fail this test with it.
func TestSuitesCatchBrokenPgxStores(t *testing.T) {
	t.Parallel()

	storefix.CatchBrokenVariants(t, brokenVar, "TestBrokenPgxStore", "pgx", brokenVariants)
}
