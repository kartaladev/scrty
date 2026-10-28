package pgxstore_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/internal/storekit"
	"github.com/kartaladev/scrty/onetime"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/seal"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/signingkey"
	"github.com/kartaladev/scrty/store/pgxstore"
	"github.com/kartaladev/scrty/test"
	"github.com/kartaladev/scrty/test/internal/storefix"
	"github.com/kartaladev/scrty/test/storetest"
)

// brokenVar names the environment variable that selects the one broken
// variant the child test runs, so each suite's verdict is attributable to
// that variant alone.
const brokenVar = "PGXSTORE_BROKEN"

// brokenVariants are the defects the pgx runs must catch. None of them is
// exported from the pgxstore module: each is built here, over the exported store
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
	{
		// Every operation runs outside the caller's transaction, Supersede in
		// a transaction of the store's own.
		Name: "session-family-opens-its-own-transaction",
		Run: func(t *testing.T) {
			c := storefix.TestCipher(t)
			h := durableHarness(migrated(t), func(t *testing.T, pool *pgxpool.Pool, _ ...pgxstore.Option) session.Store {
				return newSessionStore(t, pool, c, pgxstore.WithTxResolver(noTransaction))
			})
			t.Run("pgx", func(t *testing.T) { storetest.RunSessionFamilyAmbientTx(t, h) })
		},
		FailsCase: "a supersession inside a rolled back transaction is discarded",
		FailsWith: "the store did not supersede in it",
	},
	{
		Name: "session-family-deletes-in-one-pass",
		Run: func(t *testing.T) {
			c := storefix.TestCipher(t)
			db := migrated(t)
			h := durableHarness(db, func(t *testing.T, pool *pgxpool.Pool, opts ...pgxstore.Option) session.Store {
				return singlePassFamilyDelete{Store: newSessionStore(t, pool, c, opts...), pool: pool}
			})
			h.Begin = beginTracked(db.Pool)
			t.Run("pgx", func(t *testing.T) { storetest.RunSessionFamilyRevocationRace(t, h) })
		},
		FailsCase: "a family revocation waiting on a supersession removes its successor",
		FailsWith: "the revocation did not see the successor",
	},
	{
		Name: "session-supersede-reads-the-successor-before-locking-it",
		Run: func(t *testing.T) {
			c := storefix.TestCipher(t)
			h := durableHarness(migrated(t), func(t *testing.T, pool *pgxpool.Pool, opts ...pgxstore.Option) session.Store {
				return readThenSupersede{Store: newSessionStore(t, pool, c, opts...), pool: pool}
			})
			t.Run("pgx", func(t *testing.T) { storetest.RunSessionSuccessorAdvanceRace(t, h) })
		},
		FailsCase: "a supersession requiring an unpresented successor that waited on its presentation is refused",
		FailsWith: "it judged the successor before locking it",
	},
	{
		Name: "session-mark-presented-reads-supersession-before-locking",
		Run: func(t *testing.T) {
			c := storefix.TestCipher(t)
			h := durableHarness(migrated(t), func(t *testing.T, pool *pgxpool.Pool, opts ...pgxstore.Option) session.Store {
				return readThenMark{Store: newSessionStore(t, pool, c, opts...), pool: pool}
			})
			t.Run("pgx", func(t *testing.T) { storetest.RunSessionPresentationRace(t, h) })
		},
		FailsCase: "a first presentation that waited on its session's supersession is refused",
		FailsWith: "it judged the session before locking it",
	},
	lockOrderVariant("session-supersede-locks-the-successor-first", false),
	lockOrderVariant("session-supersede-locks-in-statement-order", true),
	userDeleteVariant("session-user-delete-in-one-pass", deleteByUser,
		"deleting every session of a user waiting on a supersession removes its successor"),
	userDeleteVariant("session-user-except-delete-in-one-pass", deleteByUserExcept,
		"deleting a user's other sessions waiting on a supersession removes its successor"),
	userDeleteVariant("session-provider-sign-in-delete-in-one-pass", deleteByExternalSession,
		"deleting a provider sign-in's sessions waiting on a supersession removes its successor"),
	userDeleteVariant("session-user-issuer-delete-in-one-pass", deleteByUserAndExternalIssuer,
		"deleting a user's sessions from a provider waiting on a supersession removes its successor"),
}

// attachedTxKey is the context key beginTracked attaches its transaction
// under, beside pgxstore.WithTx, so a broken variant can write in it as the
// store does: pgxstore does not export its own lookup.
type attachedTxKey struct{}

// beginTracked is a harness Begin that begins a transaction of pool and
// attaches it with pgxstore.WithTx and under attachedTxKey. Its commit and
// rollback may run at cleanup, when t.Context() is already done.
func beginTracked(pool *pgxpool.Pool) func(t *testing.T) (context.Context, func() error, func() error) {
	return func(t *testing.T) (context.Context, func() error, func() error) {
		t.Helper()
		tx, err := pool.Begin(t.Context())
		require.NoError(t, err)
		end := context.WithoutCancel(t.Context())
		ctx := context.WithValue(pgxstore.WithTx(t.Context(), tx), attachedTxKey{}, tx)
		return ctx, func() error { return tx.Commit(end) }, func() error { return tx.Rollback(end) }
	}
}

// readThenSupersede judges whether a supersession's observed successor was
// presented by reading it first, without a lock, and then supersedes without
// the store's own check: a presentation that commits while the supersession
// waits for the successor's row goes unnoticed.
type readThenSupersede struct {
	session.Store
	pool *pgxpool.Pool
}

func (s readThenSupersede) Supersede(ctx context.Context, op session.Supersession) error {
	if op.RequireUnpresentedSuccessor && len(op.ObservedSuccessor) > 0 {
		var presented bool
		err := s.pool.QueryRow(ctx, `SELECT first_presented_at IS NOT NULL FROM sessions WHERE id_digest = $1`,
			op.ObservedSuccessor).Scan(&presented)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if presented {
			return session.ErrSuccessorAdvanced
		}
	}
	op.RequireUnpresentedSuccessor = false
	return s.Store.Supersede(ctx, op)
}

// singlePassFamilyDelete revokes a family with one DELETE, as the store did
// before it repeated the delete: a delete that waited on an in-flight
// supersession cannot see the successor that supersession inserted. It runs
// in the transaction beginTracked attached, when there is one, as the store
// would.
type singlePassFamilyDelete struct {
	session.Store
	pool *pgxpool.Pool
}

func (s singlePassFamilyDelete) DeleteFamily(ctx context.Context, family id.ID) (int, error) {
	const del = `DELETE FROM sessions WHERE family_id = $1`
	if tx, ok := ctx.Value(attachedTxKey{}).(pgx.Tx); ok {
		tag, err := tx.Exec(ctx, del, family.String())
		return int(tag.RowsAffected()), err
	}
	tag, err := s.pool.Exec(ctx, del, family.String())
	return int(tag.RowsAffected()), err
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

func (s readThenWriteAcceptStep) AcceptStep(
	ctx context.Context, user identity.UserID, gen id.ID, step int64,
) (bool, error) {
	e, ok, err := s.Get(ctx, user)
	if err != nil || !ok || e.ConfirmedAt.IsZero() || gen.IsZero() || e.Generation != gen || e.LastStep >= step {
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

	// The children each want PostgreSQL: start the one server they will share.
	test.EnsureTestPostgresServer(t)
	storefix.CatchBrokenVariants(t, brokenVar, "TestBrokenPgxStore", "pgx", brokenVariants)
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
			var ids []pgxstore.Option
			if descending {
				ids = append(ids, pgxstore.WithIDGenerator(storetest.DescendingIDs()))
			}
			h := durableHarness(migrated(t), func(t *testing.T, pool *pgxpool.Pool, opts ...pgxstore.Option) session.Store {
				store := newSessionStore(t, pool, c, append(opts, ids...)...)
				return lockOutOfOrder{Store: store, pool: pool, successorFirst: !descending}
			})
			t.Run("pgx", func(t *testing.T) { storetest.RunSessionSupersessionLockOrder(t, h) })
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
	pool           *pgxpool.Pool
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
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	for _, digest := range s.rows(op) {
		if _, err := tx.Exec(ctx, `SELECT 1 FROM sessions WHERE id_digest = $1 FOR UPDATE`, digest); err != nil {
			return err
		}
	}
	if err := s.Store.Supersede(pgxstore.WithTx(ctx, tx), op); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// readThenMark records a first presentation by reading whether the session is
// superseded first, without a lock, and then running the update without the
// supersession condition: a supersession that commits while the mark waits
// for the session's row goes unnoticed, and the superseded session is marked.
type readThenMark struct {
	session.Store
	pool *pgxpool.Pool
}

func (s readThenMark) MarkPresented(ctx context.Context, sessionID string, at time.Time) error {
	digest := sha256.Sum256([]byte(sessionID))
	var superseded bool
	if err := s.pool.QueryRow(ctx, `SELECT superseded_at IS NOT NULL FROM sessions WHERE id_digest = $1`,
		digest[:]).Scan(&superseded); err != nil {
		return err
	}
	if superseded {
		return session.ErrSessionSuperseded
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE sessions SET first_presented_at = $2 WHERE id_digest = $1 AND first_presented_at IS NULL`,
		digest[:], at)
	return err
}

// userDelete names one of a session store's user-wide deletes.
type userDelete int

const (
	deleteByUser userDelete = iota
	deleteByUserExcept
	deleteByExternalSession
	deleteByUserAndExternalIssuer
)

// userDeleteVariant is a store whose user-wide delete op runs its statement
// once, through singlePassUserDelete, run through RunSessionUserDeleteRace,
// whose case failsCase races that delete against a supersession.
func userDeleteVariant(name string, op userDelete, failsCase string) storefix.BrokenVariant {
	return storefix.BrokenVariant{
		Name: name,
		Run: func(t *testing.T) {
			c := storefix.TestCipher(t)
			h := durableHarness(migrated(t), func(t *testing.T, pool *pgxpool.Pool, opts ...pgxstore.Option) session.Store {
				return singlePassUserDelete{Store: newSessionStore(t, pool, c, opts...), pool: pool, op: op}
			})
			t.Run("pgx", func(t *testing.T) { storetest.RunSessionUserDeleteRace(t, h) })
		},
		FailsCase: failsCase,
		FailsWith: "the delete did not see the successor",
	}
}

// singlePassUserDelete runs its user-wide delete op as one statement, as the
// store did before it repeated it: a delete that waited on an in-flight
// supersession cannot see the successor that supersession inserted. Its other
// user-wide deletes are the store's own.
type singlePassUserDelete struct {
	session.Store
	pool *pgxpool.Pool
	op   userDelete
}

func (s singlePassUserDelete) DeleteByUser(ctx context.Context, user identity.UserID) error {
	if s.op != deleteByUser {
		return s.Store.DeleteByUser(ctx, user)
	}
	_, err := s.once(ctx, pgschema.SessionDeleteByUser, string(user))
	return err
}

func (s singlePassUserDelete) DeleteByUserExcept(ctx context.Context, user identity.UserID, keep string) (int, error) {
	if s.op != deleteByUserExcept {
		return s.Store.DeleteByUserExcept(ctx, user, keep)
	}
	return s.once(ctx, pgschema.SessionDeleteByUserExcept, string(user), storekit.SessionDigest(keep))
}

func (s singlePassUserDelete) DeleteByExternalSession(ctx context.Context, issuer, sessionID string) (int, error) {
	if s.op != deleteByExternalSession {
		return s.Store.DeleteByExternalSession(ctx, issuer, sessionID)
	}
	return s.once(ctx, pgschema.SessionDeleteByExternal, issuer, sessionID)
}

func (s singlePassUserDelete) DeleteByUserAndExternalIssuer(
	ctx context.Context, user identity.UserID, issuer string,
) (int, error) {
	if s.op != deleteByUserAndExternalIssuer {
		return s.Store.DeleteByUserAndExternalIssuer(ctx, user, issuer)
	}
	return s.once(ctx, pgschema.SessionDeleteByUserIssuer, string(user), issuer)
}

// once runs statement a single time and reports the rows it removed.
func (s singlePassUserDelete) once(ctx context.Context, statement string, args ...any) (int, error) {
	tag, err := s.pool.Exec(ctx, statement, args...)
	return int(tag.RowsAffected()), err
}
