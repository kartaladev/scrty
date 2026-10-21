package gormstore_test

import (
	"context"
	"errors"
	"testing"
	"time"

	gormdb "gorm.io/gorm"
	"gorm.io/gorm/clause"

	gormstore "github.com/kartaladev/scrty/gorm"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/onetime"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/seal"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/signingkey"
	"github.com/kartaladev/scrty/test"
	"github.com/kartaladev/scrty/test/internal/storefix"
	"github.com/kartaladev/scrty/test/storetest"
)

// brokenVar names the environment variable that selects the one broken
// variant the child test runs, so each suite's verdict is attributable to
// that variant alone.
const brokenVar = "GORMSTORE_BROKEN"

// brokenVariants are the defects the gorm runs must catch. None of them is
// exported from the gorm module: each is built here, over the exported store
// or through the test's own *gorm.DB.
var brokenVariants = []storefix.BrokenVariant{
	{
		Name: "session-save-is-gorm-save",
		Run: func(t *testing.T) {
			d := migratedDB(t)
			c := storefix.TestCipher(t)
			t.Run("gorm", func(t *testing.T) {
				storetest.RunSessionStoreSuite(t, func(t *testing.T, clk clock.Clock) session.Store {
					db := emptied(t, d, "sessions")
					return gormSaveStore{Store: newSessionStore(t, db, c, gormstore.WithClock(clk)), db: db}
				})
			})
		},
		FailsCase: "saving a deleted session is not found and does not bring it back",
	},
	{
		Name: "onetime-read-then-write-consume",
		Run: func(t *testing.T) {
			h := durableHarness(migratedDB(t),
				func(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) readThenWriteConsume {
					return readThenWriteConsume{OneTimeStore: newOneTimeStore(t, db, opts...), db: db}
				})
			t.Run("gorm", func(t *testing.T) {
				storetest.RunConsumeRace(t, h, storefix.ConsumeRace[readThenWriteConsume]())
			})
		},
		FailsCase: "exactly one consumption wins per record",
		FailsWith: "more than one successful consumption",
	},
	{
		Name: "signingkey-identity-cipher",
		Run: func(t *testing.T) {
			d := migratedDB(t)
			h := durableHarness(d, func(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) signingkey.KeyStore {
				return newSigningKeyStore(t, db, storefix.IdentityCipher{}, opts...)
			})
			t.Run("gorm", func(t *testing.T) {
				// The keyring the suite hands over is ignored: every store
				// "seals" through the identity cipher.
				storetest.RunSealedColumns(t, h, storefix.SealedSigningKeys(d.db,
					func(t *testing.T, db *gormdb.DB, _ seal.Cipher) signingkey.KeyStore {
						return newSigningKeyStore(t, db, storefix.IdentityCipher{})
					}))
			})
		},
		FailsCase: "the stored value, decoded, does not hold the plaintext",
		FailsWith: "the column holds the plaintext",
	},
	{
		Name: "signingkey-missing-aad-cipher",
		Run: func(t *testing.T) {
			d := migratedDB(t)
			c := storefix.MissingAADCipher{Cipher: storefix.TestCipher(t)}
			h := durableHarness(d, func(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) signingkey.KeyStore {
				return newSigningKeyStore(t, db, c, opts...)
			})
			t.Run("gorm", func(t *testing.T) {
				storetest.RunSealedColumns(t, h, storefix.SealedSigningKeys(d.db,
					func(t *testing.T, db *gormdb.DB, c seal.Cipher) signingkey.KeyStore {
						return newSigningKeyStore(t, db, storefix.MissingAADCipher{Cipher: c})
					}))
			})
		},
		FailsCase: "a sealed value copied to another record does not open there",
	},
	{
		Name: "mfa-identity-cipher",
		Run: func(t *testing.T) {
			d := migratedDB(t)
			h := durableHarness(d, func(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) mfa.EnrolmentStore {
				return newEnrolmentStore(t, db, storefix.IdentityCipher{}, opts...)
			})
			t.Run("gorm", func(t *testing.T) {
				storetest.RunSealedColumns(t, h, storefix.SealedEnrolments(d.db,
					func(t *testing.T, db *gormdb.DB, _ seal.Cipher) mfa.EnrolmentStore {
						return newEnrolmentStore(t, db, storefix.IdentityCipher{})
					}))
			})
		},
		FailsCase: "the stored value, decoded, does not hold the plaintext",
		FailsWith: "the decoded column holds the plaintext",
	},
	{
		Name: "mfa-missing-aad-cipher",
		Run: func(t *testing.T) {
			d := migratedDB(t)
			c := storefix.MissingAADCipher{Cipher: storefix.TestCipher(t)}
			h := durableHarness(d, func(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) mfa.EnrolmentStore {
				return newEnrolmentStore(t, db, c, opts...)
			})
			t.Run("gorm", func(t *testing.T) {
				// Every store the suite builds seals through the default
				// cipher over the suite's keyring, with the AAD dropped.
				storetest.RunSealedColumns(t, h, storefix.SealedEnrolments(d.db,
					func(t *testing.T, db *gormdb.DB, c seal.Cipher) mfa.EnrolmentStore {
						return newEnrolmentStore(t, db, storefix.MissingAADCipher{Cipher: c})
					}))
			})
		},
		FailsCase: "a sealed value copied to another record does not open there",
	},
	{
		Name: "mfa-email-code-identity-cipher",
		Run: func(t *testing.T) {
			d := migratedDB(t)
			h := durableHarness(d, func(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) mfa.EnrolmentStore {
				return newEnrolmentStore(t, db, storefix.IdentityCipher{}, opts...)
			})
			t.Run("gorm", func(t *testing.T) {
				storetest.RunSealedColumns(t, h, storefix.SealedEmailCodes(d.db,
					func(t *testing.T, db *gormdb.DB, _ seal.Cipher) mfa.EnrolmentStore {
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
			d := migratedDB(t)
			c := storefix.MissingAADCipher{Cipher: storefix.TestCipher(t)}
			h := durableHarness(d, func(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) mfa.EnrolmentStore {
				return newEnrolmentStore(t, db, c, opts...)
			})
			t.Run("gorm", func(t *testing.T) {
				storetest.RunSealedColumns(t, h, storefix.SealedEmailCodes(d.db,
					func(t *testing.T, db *gormdb.DB, c seal.Cipher) mfa.EnrolmentStore {
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
				func(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) readThenWriteAcceptStep {
					return readThenWriteAcceptStep{EnrolmentStore: newEnrolmentStore(t, db, c, opts...), db: db}
				})
			t.Run("gorm", func(t *testing.T) {
				storetest.RunStepAcceptRace(t, h, storefix.StepRace[readThenWriteAcceptStep]())
			})
		},
		FailsCase: "exactly one acceptance of a step wins per record",
		FailsWith: "more than one successful acceptance of a step",
	},
	{
		Name: "link-upsert-insert",
		Run: func(t *testing.T) {
			h := durableHarness(migratedDB(t), func(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) upsertLinkInsert {
				return upsertLinkInsert{LinkStore: newLinkStore(t, db, opts...), db: db}
			})
			t.Run("gorm", func(t *testing.T) {
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
			h := durableHarness(migratedDB(t), func(t *testing.T, db *gormdb.DB, _ ...gormstore.Option) session.Store {
				return newSessionStore(t, db, c, gormstore.WithTxResolver(noTransaction))
			})
			t.Run("gorm", func(t *testing.T) { storetest.RunAmbientTx(t, h, storefix.SessionAmbient()) })
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
			h := durableHarness(migratedDB(t), func(t *testing.T, db *gormdb.DB, _ ...gormstore.Option) session.Store {
				return newSessionStore(t, db, c, gormstore.WithTxResolver(noTransaction))
			})
			t.Run("gorm", func(t *testing.T) { storetest.RunSessionFamilyAmbientTx(t, h) })
		},
		FailsCase: "a supersession inside a rolled back transaction is discarded",
		FailsWith: "the store did not supersede in it",
	},
	{
		Name: "session-family-deletes-in-one-pass",
		Run: func(t *testing.T) {
			c := storefix.TestCipher(t)
			d := migratedDB(t)
			h := durableHarness(d, func(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) session.Store {
				return singlePassFamilyDelete{Store: newSessionStore(t, db, c, opts...), db: db}
			})
			h.Begin = beginTracked(d.db)
			t.Run("gorm", func(t *testing.T) { storetest.RunSessionFamilyRevocationRace(t, h) })
		},
		FailsCase: "a family revocation waiting on a supersession removes its successor",
		FailsWith: "the revocation did not see the successor",
	},
	{
		Name: "session-supersede-reads-the-successor-before-locking-it",
		Run: func(t *testing.T) {
			c := storefix.TestCipher(t)
			h := durableHarness(migratedDB(t), func(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) session.Store {
				return readThenSupersede{Store: newSessionStore(t, db, c, opts...), db: db}
			})
			t.Run("gorm", func(t *testing.T) { storetest.RunSessionSuccessorAdvanceRace(t, h) })
		},
		FailsCase: "a supersession requiring an unpresented successor that waited on its presentation is refused",
		FailsWith: "it judged the successor before locking it",
	},
}

// attachedTxKey is the context key beginTracked attaches its transaction
// under, beside gormstore.WithTx, so a broken variant can write in it as the
// store does: gormstore does not export its own lookup.
type attachedTxKey struct{}

// beginTracked is a harness Begin that begins a transaction of db and
// attaches it with gormstore.WithTx and under attachedTxKey.
func beginTracked(db *gormdb.DB) func(t *testing.T) (context.Context, func() error, func() error) {
	return func(t *testing.T) (context.Context, func() error, func() error) {
		t.Helper()
		tx := beginGorm(t.Context(), t, db)
		ctx := context.WithValue(gormstore.WithTx(t.Context(), tx), attachedTxKey{}, tx)
		return ctx, func() error { return tx.Commit().Error }, func() error { return tx.Rollback().Error }
	}
}

// readThenSupersede judges whether a supersession's observed successor was
// presented by reading it first, without a lock, and then supersedes without
// the store's own check: a presentation that commits while the supersession
// waits for the successor's row goes unnoticed.
type readThenSupersede struct {
	session.Store
	db *gormdb.DB
}

func (s readThenSupersede) Supersede(ctx context.Context, op session.Supersession) error {
	if op.RequireUnpresentedSuccessor && len(op.ObservedSuccessor) > 0 {
		var presented bool
		if err := s.db.WithContext(ctx).Raw(
			`SELECT first_presented_at IS NOT NULL FROM sessions WHERE id_digest = ?`, op.ObservedSuccessor,
		).Scan(&presented).Error; err != nil {
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
	db *gormdb.DB
}

func (s singlePassFamilyDelete) DeleteFamily(ctx context.Context, family id.ID) (int, error) {
	q := s.db
	if tx, ok := ctx.Value(attachedTxKey{}).(*gormdb.DB); ok {
		q = tx
	}
	res := q.WithContext(ctx).Exec(`DELETE FROM sessions WHERE family_id = ?`, family.String())
	return int(res.RowsAffected), res.Error
}

// savedSession is the part of a sessions row gormSaveStore writes: enough for
// a session to load again. Its other columns take their defaults.
type savedSession struct {
	ID                id.ID     `gorm:"column:id;type:uuid;primaryKey"`
	IDDigest          []byte    `gorm:"column:id_digest;type:bytea"`
	UserID            string    `gorm:"column:user_id;type:text"`
	CreatedAt         time.Time `gorm:"column:created_at;type:timestamptz;autoCreateTime:false"`
	LastAccessedAt    time.Time `gorm:"column:last_accessed_at;type:timestamptz"`
	IdleExpiresAt     time.Time `gorm:"column:idle_expires_at;type:timestamptz"`
	AbsoluteExpiresAt time.Time `gorm:"column:absolute_expires_at;type:timestamptz"`
}

func (savedSession) TableName() string { return "sessions" }

// gormSaveStore saves a session its Save does not find with gorm's own Save,
// which falls back to an insert when its update matches no row: a save racing
// a logout writes the revoked session back.
type gormSaveStore struct {
	session.Store
	db *gormdb.DB
}

func (s gormSaveStore) Save(ctx context.Context, sess *session.Session) error {
	err := s.Store.Save(ctx, sess)
	if !errors.Is(err, session.ErrSessionNotFound) {
		return err
	}

	rowID, err := id.NewV7Generator().NewID()
	if err != nil {
		return err
	}
	return s.db.WithContext(ctx).Save(&savedSession{
		ID:                rowID,
		IDDigest:          storefix.Digest(sess.ID),
		UserID:            string(sess.UserID),
		CreatedAt:         sess.CreatedAt,
		LastAccessedAt:    sess.LastAccessedAt,
		IdleExpiresAt:     sess.IdleExpiresAt,
		AbsoluteExpiresAt: sess.AbsoluteExpiresAt,
	}).Error
}

// readThenWriteConsume consumes by reading the token, checking it is unspent,
// and then updating it unconditionally: two racers can both read "unspent"
// and both write.
type readThenWriteConsume struct {
	*gormstore.OneTimeStore
	db *gormdb.DB
}

func (s readThenWriteConsume) Consume(ctx context.Context, tokenID id.ID, at time.Time) error {
	tok, err := s.FindByID(ctx, tokenID)
	if err != nil {
		return err
	}
	if !tok.ConsumedAt.IsZero() {
		return onetime.ErrTokenNotFound
	}
	return s.db.WithContext(ctx).Table("one_time_tokens").Where("id = ?", tokenID).Update("consumed_at", at).Error
}

// readThenWriteAcceptStep accepts a step by reading the enrolment, checking
// the step is later than the recorded one, and then updating it
// unconditionally: two racers can both read the old step and both write.
type readThenWriteAcceptStep struct {
	mfa.EnrolmentStore
	db *gormdb.DB
}

func (s readThenWriteAcceptStep) AcceptStep(ctx context.Context, user identity.UserID, step int64) (bool, error) {
	e, ok, err := s.Get(ctx, user)
	if err != nil || !ok || e.ConfirmedAt.IsZero() || e.LastStep >= step {
		return false, err
	}
	err = s.db.WithContext(ctx).Table("mfa_enrolments").Where("user_id = ?", string(user)).Update("last_step", step).Error
	return err == nil, err
}

// upsertLinkInsert inserts a link with gorm's upsert, which on a conflict
// moves the external identity to the new user, and reports success either
// way: every racer "wins", and the last one owns the identity.
type upsertLinkInsert struct {
	*gormstore.LinkStore
	db *gormdb.DB
}

// upsertedLink is the part of an oidc_links row upsertLinkInsert writes.
type upsertedLink struct {
	ID        id.ID     `gorm:"column:id;type:uuid;primaryKey"`
	Provider  string    `gorm:"column:provider;type:text"`
	Issuer    string    `gorm:"column:issuer;type:text"`
	Subject   string    `gorm:"column:subject;type:text"`
	UserID    string    `gorm:"column:user_id;type:text"`
	CreatedAt time.Time `gorm:"column:created_at;type:timestamptz;autoCreateTime:false"`
}

func (upsertedLink) TableName() string { return "oidc_links" }

func (s upsertLinkInsert) Insert(ctx context.Context, l oidc.Link) error {
	return s.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "provider"}, {Name: "issuer"}, {Name: "subject"}},
		DoUpdates: clause.AssignmentColumns([]string{"user_id"}),
	}).Create(&upsertedLink{
		ID: l.ID, Provider: l.Provider, Issuer: l.Issuer, Subject: l.Subject, UserID: string(l.UserID),
		CreatedAt: l.CreatedAt,
	}).Error
}

// TestBrokenGormStore runs the broken variant named by the environment, and is
// the child half of TestSuitesCatchBrokenGormStores. Without a variant named it
// skips.
func TestBrokenGormStore(t *testing.T) {
	storefix.RunBrokenChild(t, brokenVar, "TestSuitesCatchBrokenGormStores", brokenVariants)
}

// TestSuitesCatchBrokenGormStores checks that the suites the gorm runs use
// fail against each broken variant, at the case guarding its defect. Each
// variant runs in its own process, because a failing suite reports through its
// own *testing.T and would fail this test with it.
func TestSuitesCatchBrokenGormStores(t *testing.T) {
	t.Parallel()

	// The children each want PostgreSQL: start the one server they will share.
	test.EnsureTestPostgresServer(t)
	storefix.CatchBrokenVariants(t, brokenVar, "TestBrokenGormStore", "gorm", brokenVariants)
}
