package gormstore_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gormdb "gorm.io/gorm"
	"gorm.io/gorm/clause"

	gormstore "github.com/kartaladev/scrty/gorm"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/onetime"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/seal"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/signingkey"
	"github.com/kartaladev/scrty/test/storetest"
)

// brokenVar names the environment variable that selects the one broken
// variant the child test runs, so each suite's verdict is attributable to
// that variant alone.
const brokenVar = "GORMSTORE_BROKEN"

// brokenVariant is a durable store carrying one deliberate defect, the run
// that must fail, and the case of it that must catch the defect.
type brokenVariant struct {
	name      string
	run       func(t *testing.T)
	failsCase string
	// failsWith, when set, is text the child's output must carry.
	failsWith string
}

// brokenVariants are the defects the gorm runs must catch. None of them is
// exported from the gorm module: each is built here, over the exported store
// or through the test's own *gorm.DB.
var brokenVariants = []brokenVariant{
	{
		name: "session-save-is-gorm-save",
		run: func(t *testing.T) {
			d := migratedDB(t)
			c := testCipher(t)
			t.Run("gorm", func(t *testing.T) {
				storetest.RunSessionStoreSuite(t, func(t *testing.T, now func() time.Time) session.Store {
					db := emptied(t, d, "sessions")
					return gormSaveStore{Store: newSessionStore(t, db, c, gormstore.WithClock(now)), db: db}
				})
			})
		},
		failsCase: "saving a deleted session is not found and does not bring it back",
	},
	{
		name: "onetime-read-then-write-consume",
		run: func(t *testing.T) {
			h := durableHarness(migratedDB(t),
				func(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) readThenWriteConsume {
					return readThenWriteConsume{OneTimeStore: newOneTimeStore(t, db, opts...), db: db}
				})
			t.Run("gorm", func(t *testing.T) {
				storetest.RunConsumeRace(t, h, consumeRace[readThenWriteConsume]())
			})
		},
		failsCase: "exactly one consumption wins per record",
		failsWith: "more than one successful consumption",
	},
	{
		name: "signingkey-identity-cipher",
		run: func(t *testing.T) {
			d := migratedDB(t)
			h := durableHarness(d, func(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) signingkey.KeyStore {
				return newSigningKeyStore(t, db, identityCipher{}, opts...)
			})
			t.Run("gorm", func(t *testing.T) {
				// The keyring the suite hands over is ignored: every store
				// "seals" through the identity cipher.
				storetest.RunSealedColumns(t, h, sealedSigningKeys(d.db,
					func(t *testing.T, db *gormdb.DB, _ seal.Cipher) signingkey.KeyStore {
						return newSigningKeyStore(t, db, identityCipher{})
					}))
			})
		},
		failsCase: "the stored value, decoded, does not hold the plaintext",
		failsWith: "the column holds the plaintext",
	},
	{
		name: "signingkey-missing-aad-cipher",
		run: func(t *testing.T) {
			d := migratedDB(t)
			c := missingAADCipher{testCipher(t)}
			h := durableHarness(d, func(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) signingkey.KeyStore {
				return newSigningKeyStore(t, db, c, opts...)
			})
			t.Run("gorm", func(t *testing.T) {
				storetest.RunSealedColumns(t, h, sealedSigningKeys(d.db,
					func(t *testing.T, db *gormdb.DB, c seal.Cipher) signingkey.KeyStore {
						return newSigningKeyStore(t, db, missingAADCipher{c})
					}))
			})
		},
		failsCase: "a sealed value copied to another record does not open there",
	},
	{
		name: "mfa-identity-cipher",
		run: func(t *testing.T) {
			d := migratedDB(t)
			h := durableHarness(d, func(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) mfa.EnrolmentStore {
				return newEnrolmentStore(t, db, identityCipher{}, opts...)
			})
			t.Run("gorm", func(t *testing.T) {
				storetest.RunSealedColumns(t, h, sealedEnrolments(d.db,
					func(t *testing.T, db *gormdb.DB, _ seal.Cipher) mfa.EnrolmentStore {
						return newEnrolmentStore(t, db, identityCipher{})
					}))
			})
		},
		failsCase: "the stored value, decoded, does not hold the plaintext",
		failsWith: "the decoded column holds the plaintext",
	},
	{
		name: "mfa-missing-aad-cipher",
		run: func(t *testing.T) {
			d := migratedDB(t)
			c := missingAADCipher{testCipher(t)}
			h := durableHarness(d, func(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) mfa.EnrolmentStore {
				return newEnrolmentStore(t, db, c, opts...)
			})
			t.Run("gorm", func(t *testing.T) {
				// Every store the suite builds seals through the default
				// cipher over the suite's keyring, with the AAD dropped.
				storetest.RunSealedColumns(t, h, sealedEnrolments(d.db,
					func(t *testing.T, db *gormdb.DB, c seal.Cipher) mfa.EnrolmentStore {
						return newEnrolmentStore(t, db, missingAADCipher{c})
					}))
			})
		},
		failsCase: "a sealed value copied to another record does not open there",
	},
	{
		name: "mfa-read-then-write-accept-step",
		run: func(t *testing.T) {
			c := testCipher(t)
			h := durableHarness(migratedDB(t),
				func(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) readThenWriteAcceptStep {
					return readThenWriteAcceptStep{EnrolmentStore: newEnrolmentStore(t, db, c, opts...), db: db}
				})
			t.Run("gorm", func(t *testing.T) {
				storetest.RunStepAcceptRace(t, h, stepRace[readThenWriteAcceptStep]())
			})
		},
		failsCase: "exactly one acceptance of a step wins per record",
		failsWith: "more than one successful acceptance of a step",
	},
	{
		name: "link-upsert-insert",
		run: func(t *testing.T) {
			h := durableHarness(migratedDB(t), func(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) upsertLinkInsert {
				return upsertLinkInsert{LinkStore: newLinkStore(t, db, opts...), db: db}
			})
			t.Run("gorm", func(t *testing.T) {
				storetest.RunLinkInsertRace(t, h, linkRace[upsertLinkInsert]())
			})
		},
		failsCase: "exactly one insert wins per record",
		failsWith: "more than one successful insert",
	},
	{
		name: "session-store-bypasses-the-transaction",
		run: func(t *testing.T) {
			c := testCipher(t)
			h := durableHarness(migratedDB(t), func(t *testing.T, db *gormdb.DB, _ ...gormstore.Option) session.Store {
				return newSessionStore(t, db, c, gormstore.WithTxResolver(noTransaction))
			})
			t.Run("gorm", func(t *testing.T) { storetest.RunAmbientTx(t, h, sessionAmbient()) })
		},
		failsCase: "a write inside a rolled back transaction is discarded",
		failsWith: "the store did not write in it",
	},
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
		IDDigest:          digest(sess.ID),
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
	name, named := os.LookupEnv(brokenVar)
	if !named {
		t.Skipf("no variant named in %s; run through TestSuitesCatchBrokenGormStores", brokenVar)
	}

	for _, v := range brokenVariants {
		if v.name == name {
			t.Logf("variant under test: %q", name)
			v.run(t)
			return
		}
	}
	t.Fatalf("no broken variant is named %q", name)
}

// failedCase matches a failed case of the child's gorm run.
var failedCase = regexp.MustCompile(`--- FAIL: TestBrokenGormStore/gorm/(\S+)`)

// TestSuitesCatchBrokenGormStores checks that the suites the gorm runs use
// fail against each broken variant, at the case guarding its defect. Each
// variant runs in its own process, because a failing suite reports through its
// own *testing.T and would fail this test with it.
func TestSuitesCatchBrokenGormStores(t *testing.T) {
	t.Parallel()

	for _, v := range brokenVariants {
		t.Run(v.name, func(t *testing.T) {
			t.Parallel()

			//nolint:gosec // G204: this test binary re-executed with fixed arguments
			cmd := exec.CommandContext(t.Context(), os.Args[0],
				"-test.run=^TestBrokenGormStore$", "-test.count=1", "-test.v", "-test.timeout=5m")
			cmd.Env = append(os.Environ(), brokenVar+"="+v.name)
			out, err := cmd.CombinedOutput()
			output := string(out)

			// The child names its variant, so it skips only when
			// RunTestPostgres does: Docker is unavailable outside CI.
			if strings.Contains(output, "--- SKIP: TestBrokenGormStore") {
				t.Skipf("the child skipped, so nothing was checked:\n%s", output)
			}
			require.Error(t, err, "the suite passed a store carrying the %s defect:\n%s", v.name, output)

			var failed []string
			for _, m := range failedCase.FindAllStringSubmatch(output, -1) {
				failed = append(failed, m[1])
			}
			t.Logf("cases failed by %s: %v", v.name, failed)
			assert.Contains(t, failed, strings.ReplaceAll(v.failsCase, " ", "_"),
				"the suite failed, but not at the case that guards this defect:\n%s", output)
			if v.failsWith != "" {
				assert.Contains(t, output, v.failsWith, "the failure does not report the violation")
			}
		})
	}
}
