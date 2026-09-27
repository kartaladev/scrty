package gormstore_test

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gormdb "gorm.io/gorm"

	gormstore "github.com/kartaladev/scrty/gorm"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/seal"
	"github.com/kartaladev/scrty/test/storetest"
)

// newEnrolmentStore builds the MFA enrolment store over db, failing t on a
// refusal.
func newEnrolmentStore(t *testing.T, db *gormdb.DB, c seal.Cipher, opts ...gormstore.Option) mfa.EnrolmentStore {
	t.Helper()

	s, err := gormstore.NewEnrolmentStore(db, c, opts...)
	require.NoError(t, err)

	return s
}

// enrolmentBegun is when every enrolment here was begun.
var enrolmentBegun = time.Date(2030, 1, 1, 10, 0, 0, 0, time.UTC)

// pending is a pending enrolment of user carrying secret.
func pending(user identity.UserID, secret string) mfa.Enrolment {
	return mfa.Enrolment{User: user, Secret: []byte(secret), CreatedAt: enrolmentBegun}
}

// secretColumn is user's secret column as stored.
func secretColumn(ctx context.Context, t *testing.T, db *sql.DB, user identity.UserID) string {
	t.Helper()

	var s string
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT secret FROM mfa_enrolments WHERE user_id = $1`, string(user)).Scan(&s))

	return s
}

// setSecretColumn replaces user's secret column out of band.
func setSecretColumn(ctx context.Context, t *testing.T, db *sql.DB, user identity.UserID, secret string) {
	t.Helper()

	_, err := db.ExecContext(ctx, `UPDATE mfa_enrolments SET secret = $2 WHERE user_id = $1`, string(user), secret)
	require.NoError(t, err)
}

// stepRace is the race over AcceptStep: Seed confirms user i's enrolment at
// step 1000, and every racer records step 1002.
func stepRace[S mfa.EnrolmentStore]() storetest.Race[S] {
	return storetest.Race[S]{
		Seed: func(ctx context.Context, t *testing.T, s S, i int) string {
			user := identity.UserID(fmt.Sprintf("race-user-%d", i))
			require.NoError(t, s.PutPending(ctx, pending(user, "secret")))
			ok, err := s.Confirm(ctx, user, 1000, enrolmentBegun.Add(time.Minute))
			require.NoError(t, err)
			require.True(t, ok)
			return string(user)
		},
		Attempt: func(ctx context.Context, s S, key string, _ int) (bool, error) {
			return s.AcceptStep(ctx, identity.UserID(key), 1002)
		},
	}
}

// sealedEnrolments is the sealed-column suite's view of the MFA store, built
// by newWith over a cipher on db.
func sealedEnrolments(
	db *gormdb.DB, newWith func(t *testing.T, db *gormdb.DB, c seal.Cipher) mfa.EnrolmentStore,
) storetest.Sealed[mfa.EnrolmentStore] {
	return storetest.Sealed[mfa.EnrolmentStore]{
		Encoding: storetest.SealedBase64URL,
		Rotation: storetest.ResealOnRead,
		NewWithKeyring: func(t *testing.T, kr seal.Keyring) mfa.EnrolmentStore {
			c, err := seal.NewAEADCipher(kr)
			require.NoError(t, err)
			return newWith(t, db, c)
		},
		Put: func(ctx context.Context, s mfa.EnrolmentStore, owner string, secret []byte) error {
			return s.PutPending(ctx, mfa.Enrolment{User: identity.UserID(owner), Secret: secret, CreatedAt: enrolmentBegun})
		},
		Get: func(ctx context.Context, s mfa.EnrolmentStore, owner string) ([]byte, bool, error) {
			e, ok, err := s.Get(ctx, identity.UserID(owner))
			return e.Secret, ok, err
		},
		RawColumn: func(t *testing.T, raw *sql.DB, owner string) []byte {
			return []byte(secretColumn(t.Context(), t, raw, identity.UserID(owner)))
		},
		CopySealed: func(t *testing.T, raw *sql.DB, from, to string) {
			_, err := raw.ExecContext(t.Context(), `UPDATE mfa_enrolments
SET secret = (SELECT secret FROM mfa_enrolments WHERE user_id = $1) WHERE user_id = $2`, from, to)
			require.NoError(t, err)
		},
	}
}

func TestEnrolmentStore(t *testing.T) {
	t.Parallel()

	d := migratedDB(t)
	c := testCipher(t)

	t.Run("gorm", func(t *testing.T) {
		storetest.RunEnrolmentStoreSuite(t, func(t *testing.T) mfa.EnrolmentStore {
			return newEnrolmentStore(t, emptied(t, d, "mfa_enrolments"), c)
		})
	})
}

func TestEnrolmentStore_StepAcceptRace(t *testing.T) {
	t.Parallel()

	c := testCipher(t)
	h := durableHarness(migratedDB(t), func(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) mfa.EnrolmentStore {
		return newEnrolmentStore(t, db, c, opts...)
	})

	t.Run("gorm", func(t *testing.T) {
		storetest.RunStepAcceptRace(t, h, stepRace[mfa.EnrolmentStore]())
	})
}

func TestEnrolmentStore_SealedColumns(t *testing.T) {
	t.Parallel()

	d := migratedDB(t)
	c := testCipher(t)
	h := durableHarness(d, func(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) mfa.EnrolmentStore {
		return newEnrolmentStore(t, db, c, opts...)
	})

	t.Run("gorm", func(t *testing.T) {
		storetest.RunSealedColumns(t, h, sealedEnrolments(d.db,
			func(t *testing.T, db *gormdb.DB, c seal.Cipher) mfa.EnrolmentStore {
				return newEnrolmentStore(t, db, c)
			}))
	})
}

func TestNewEnrolmentStore(t *testing.T) {
	t.Parallel()

	db := unreachableDB(t)
	c := testCipher(t)

	type testCase struct {
		name   string
		db     *gormdb.DB
		cipher seal.Cipher
		opts   []gormstore.Option
		assert func(t *testing.T, s mfa.EnrolmentStore, err error)
	}

	refused := refusedConfig[mfa.EnrolmentStore]
	accepted := acceptedConfig[mfa.EnrolmentStore]

	cases := []testCase{
		{name: "a handle and a cipher are all it needs", db: db, cipher: c, assert: accepted},
		{
			name:   "it honours an id generator and re-sealing turned off",
			db:     db,
			cipher: c,
			opts: []gormstore.Option{
				gormstore.WithIDGenerator(id.NewV7Generator()),
				gormstore.WithResealOnRead(false),
			},
			assert: accepted,
		},
		{name: "a missing cipher is refused", db: db, assert: refused("the cipher is nil")},
		{name: "a typed nil cipher is refused", db: db, cipher: (*gatedCipher)(nil), assert: refused("the cipher is nil")},
		{name: "a missing handle is refused", cipher: c, assert: refused("the database handle is nil")},
		{
			name:   "a clock does not apply to MFA enrolments",
			db:     db,
			cipher: c,
			opts:   []gormstore.Option{gormstore.WithClock(time.Now)},
			assert: refused("WithClock does not apply to this store"),
		},
		{
			name:   "the store does not offer the enrolment path, whose fields it cannot keep",
			db:     db,
			cipher: c,
			assert: func(t *testing.T, s mfa.EnrolmentStore, err error) {
				require.NoError(t, err)
				_, proves := s.(mfa.DeviceProofStore)
				assert.False(t, proves, "the durable store must not implement mfa.DeviceProofStore yet")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s, err := gormstore.NewEnrolmentStore(tc.db, tc.cipher, tc.opts...)
			tc.assert(t, s, err)
		})
	}
}

// gatedCipher holds its first Open until the test releases it, so the test
// can write between a read and the re-seal that read would make.
type gatedCipher struct {
	seal.Cipher

	once             sync.Once
	opening, release chan struct{}
}

func newGatedCipher(c seal.Cipher) *gatedCipher {
	return &gatedCipher{Cipher: c, opening: make(chan struct{}), release: make(chan struct{})}
}

func (c *gatedCipher) Open(sealed, aad []byte) ([]byte, string, error) {
	c.once.Do(func() {
		close(c.opening)
		<-c.release
	})
	return c.Cipher.Open(sealed, aad)
}

func TestEnrolmentStore_Durable(t *testing.T) {
	t.Parallel()

	d := migratedDB(t)

	type testCase struct {
		name   string
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, ctx context.Context, d database, keys testKeys)
	}

	// refusedOpen asserts a read failed closed, for the reason want.
	refusedOpen := func(t *testing.T, e mfa.Enrolment, ok bool, err error, want error) {
		t.Helper()
		require.ErrorIs(t, err, want)
		assert.False(t, ok, "a secret that does not open must not read as an enrolment")
		assert.Zero(t, e)
	}

	cases := []testCase{
		{
			name: "a secret copied to another user's row does not open there",
			assert: func(t *testing.T, ctx context.Context, d database, keys testKeys) {
				s := newEnrolmentStore(t, d.db, keys.rotated(t))
				require.NoError(t, s.PutPending(ctx, pending("victim-copied", "TOTP-VICTIM")))
				require.NoError(t, s.PutPending(ctx, pending("attacker-copied", "TOTP-ATTACKER")))
				setSecretColumn(ctx, t, d.conn.DB, "attacker-copied", secretColumn(ctx, t, d.conn.DB, "victim-copied"))

				e, ok, err := s.Get(ctx, "attacker-copied")
				refusedOpen(t, e, ok, err, seal.ErrDecryptionFailed)
			},
		},
		{
			name: "an enrolment reassigned to another user does not open for that user",
			assert: func(t *testing.T, ctx context.Context, d database, keys testKeys) {
				s := newEnrolmentStore(t, d.db, keys.rotated(t))
				require.NoError(t, s.PutPending(ctx, pending("attacker-moved", "TOTP-ATTACKER")))
				_, err := d.conn.DB.ExecContext(ctx,
					`UPDATE mfa_enrolments SET user_id = 'victim-moved' WHERE user_id = 'attacker-moved'`)
				require.NoError(t, err)

				e, ok, err := s.Get(ctx, "victim-moved")
				refusedOpen(t, e, ok, err, seal.ErrDecryptionFailed)
			},
		},
		{
			name: "a sealed session ID token moved into the secret column does not open",
			assert: func(t *testing.T, ctx context.Context, d database, keys testKeys) {
				c := keys.rotated(t)
				sessions := newSessionStore(t, d.db, c)
				require.NoError(t, sessions.Create(ctx, durableSession("sid-moved", time.Now())))
				var token string
				require.NoError(t, d.conn.DB.QueryRowContext(ctx,
					`SELECT external_id_token FROM sessions WHERE id_digest = $1`, digest("sid-moved")).Scan(&token))

				s := newEnrolmentStore(t, d.db, c)
				require.NoError(t, s.PutPending(ctx, pending("table-moved", "TOTP-SECRET")))
				setSecretColumn(ctx, t, d.conn.DB, "table-moved", token)

				e, ok, err := s.Get(ctx, "table-moved")
				refusedOpen(t, e, ok, err, seal.ErrDecryptionFailed)
			},
		},
		{
			name: "a tampered byte does not open",
			assert: func(t *testing.T, ctx context.Context, d database, keys testKeys) {
				s := newEnrolmentStore(t, d.db, keys.rotated(t))
				require.NoError(t, s.PutPending(ctx, pending("tampered", "TOTP-SECRET")))
				sealed, err := base64.RawURLEncoding.DecodeString(secretColumn(ctx, t, d.conn.DB, "tampered"))
				require.NoError(t, err)
				sealed[len(sealed)-1] ^= 1
				setSecretColumn(ctx, t, d.conn.DB, "tampered", base64.RawURLEncoding.EncodeToString(sealed))

				e, ok, err := s.Get(ctx, "tampered")
				refusedOpen(t, e, ok, err, seal.ErrDecryptionFailed)
			},
		},
		{
			name: "a stored value that is not base64url is an error, never absence",
			assert: func(t *testing.T, ctx context.Context, d database, keys testKeys) {
				s := newEnrolmentStore(t, d.db, keys.rotated(t))
				require.NoError(t, s.PutPending(ctx, pending("not-base64", "TOTP-SECRET")))
				setSecretColumn(ctx, t, d.conn.DB, "not-base64", "***not base64***")

				e, ok, err := s.Get(ctx, "not-base64")
				require.Error(t, err)
				assert.False(t, ok)
				assert.Zero(t, e)
			},
		},
		{
			name: "a missing key is reported as an unknown key id, never as absence",
			assert: func(t *testing.T, ctx context.Context, d database, keys testKeys) {
				require.NoError(t, newEnrolmentStore(t, d.db, keys.underK1(t)).
					PutPending(ctx, pending("missing-key", "TOTP-SECRET")))

				e, ok, err := newEnrolmentStore(t, d.db, keys.onlyK2(t)).Get(ctx, "missing-key")
				refusedOpen(t, e, ok, err, seal.ErrUnknownKeyID)
			},
		},
		{
			name: "a read outside a transaction re-seals the secret under the active key",
			assert: func(t *testing.T, ctx context.Context, d database, keys testKeys) {
				require.NoError(t, newEnrolmentStore(t, d.db, keys.underK1(t)).
					PutPending(ctx, pending("reseal", "TOTP-SECRET")))

				e, ok, err := newEnrolmentStore(t, d.db, keys.rotated(t)).Get(ctx, "reseal")
				require.NoError(t, err)
				require.True(t, ok)
				assert.Equal(t, []byte("TOTP-SECRET"), e.Secret)

				e, ok, err = newEnrolmentStore(t, d.db, keys.onlyK2(t)).Get(ctx, "reseal")
				require.NoError(t, err, "the read did not re-seal under the active key")
				require.True(t, ok)
				assert.Equal(t, []byte("TOTP-SECRET"), e.Secret)
			},
		},
		{
			name: "a re-seal does not replace a secret a concurrent begin wrote",
			assert: func(t *testing.T, ctx context.Context, d database, keys testKeys) {
				require.NoError(t, newEnrolmentStore(t, d.db, keys.underK1(t)).
					PutPending(ctx, pending("reenrol", "TOTP-OLD")))

				gated := newGatedCipher(keys.rotated(t))
				reader := newEnrolmentStore(t, d.db, gated)
				type read struct {
					e   mfa.Enrolment
					err error
				}
				done := make(chan read, 1)
				go func() {
					e, _, err := reader.Get(ctx, "reenrol")
					done <- read{e, err}
				}()

				<-gated.opening
				writer := newEnrolmentStore(t, d.db, keys.rotated(t))
				require.NoError(t, writer.PutPending(ctx, pending("reenrol", "TOTP-NEW")))
				close(gated.release)
				got := <-done
				require.NoError(t, got.err)
				require.Equal(t, []byte("TOTP-OLD"), got.e.Secret, "the gated read opened the old secret")

				e, ok, err := writer.Get(ctx, "reenrol")
				require.NoError(t, err)
				require.True(t, ok)
				assert.Equal(t, []byte("TOTP-NEW"), e.Secret, "the re-seal overwrote the concurrent begin")
			},
		},
		{
			name: "a read inside a transaction attached with WithTx rewrites nothing",
			assert: func(t *testing.T, ctx context.Context, d database, keys testKeys) {
				require.NoError(t, newEnrolmentStore(t, d.db, keys.underK1(t)).
					PutPending(ctx, pending("in-tx", "TOTP-SECRET")))
				before := secretColumn(ctx, t, d.conn.DB, "in-tx")

				tx := beginGorm(ctx, t, d.db)
				_, ok, err := newEnrolmentStore(t, d.db, keys.rotated(t)).Get(gormstore.WithTx(ctx, tx), "in-tx")
				require.NoError(t, err)
				require.True(t, ok)
				require.NoError(t, tx.Commit().Error)

				assert.Equal(t, before, secretColumn(ctx, t, d.conn.DB, "in-tx"), "the read inside a transaction re-sealed")
			},
		},
		{
			name: "a read inside a transaction a resolver reports rewrites nothing",
			assert: func(t *testing.T, ctx context.Context, d database, keys testKeys) {
				require.NoError(t, newEnrolmentStore(t, d.db, keys.underK1(t)).
					PutPending(ctx, pending("resolved", "TOTP-SECRET")))
				before := secretColumn(ctx, t, d.conn.DB, "resolved")

				tx := beginGorm(ctx, t, d.db)
				s := newEnrolmentStore(t, d.db, keys.rotated(t), gormstore.WithTxResolver(resolving(tx)))
				_, ok, err := s.Get(ctx, "resolved")
				require.NoError(t, err)
				require.True(t, ok)
				require.NoError(t, tx.Commit().Error)

				assert.Equal(t, before, secretColumn(ctx, t, d.conn.DB, "resolved"), "the read inside a transaction re-sealed")
			},
		},
		{
			name: "with re-sealing turned off a read rewrites nothing, and the secret still opens only with k1",
			assert: func(t *testing.T, ctx context.Context, d database, keys testKeys) {
				require.NoError(t, newEnrolmentStore(t, d.db, keys.underK1(t)).
					PutPending(ctx, pending("reseal-off", "TOTP-SECRET")))
				before := secretColumn(ctx, t, d.conn.DB, "reseal-off")

				_, ok, err := newEnrolmentStore(t, d.db, keys.rotated(t), gormstore.WithResealOnRead(false)).
					Get(ctx, "reseal-off")
				require.NoError(t, err)
				require.True(t, ok)

				assert.Equal(t, before, secretColumn(ctx, t, d.conn.DB, "reseal-off"), "the read re-sealed")
				_, _, err = newEnrolmentStore(t, d.db, keys.onlyK2(t)).Get(ctx, "reseal-off")
				assert.ErrorIs(t, err, seal.ErrUnknownKeyID)
			},
		},
		{
			name: "a confirmation never moves a step recorded out of band backwards",
			assert: func(t *testing.T, ctx context.Context, d database, keys testKeys) {
				s := newEnrolmentStore(t, d.db, keys.rotated(t))
				require.NoError(t, s.PutPending(ctx, pending("step-kept", "TOTP-SECRET")))
				_, err := d.conn.DB.ExecContext(ctx,
					`UPDATE mfa_enrolments SET last_step = 2000 WHERE user_id = 'step-kept'`)
				require.NoError(t, err)

				ok, err := s.Confirm(ctx, "step-kept", 1000, enrolmentBegun.Add(time.Minute))
				require.NoError(t, err)
				require.True(t, ok)

				e, ok, err := s.Get(ctx, "step-kept")
				require.NoError(t, err)
				require.True(t, ok)
				assert.Equal(t, int64(2000), e.LastStep, "the confirmation moved the recorded step backwards")
			},
		},
		{
			name: "a repeated begin clears a step recorded on the pending enrolment",
			assert: func(t *testing.T, ctx context.Context, d database, keys testKeys) {
				s := newEnrolmentStore(t, d.db, keys.rotated(t))
				require.NoError(t, s.PutPending(ctx, pending("step-cleared", "TOTP-OLD")))
				_, err := d.conn.DB.ExecContext(ctx,
					`UPDATE mfa_enrolments SET last_step = 2000 WHERE user_id = 'step-cleared'`)
				require.NoError(t, err)

				require.NoError(t, s.PutPending(ctx, pending("step-cleared", "TOTP-NEW")))

				e, ok, err := s.Get(ctx, "step-cleared")
				require.NoError(t, err)
				require.True(t, ok)
				assert.Zero(t, e.LastStep, "the repeated begin kept the recorded step")
			},
		},
		{
			name: "a lookup on a database that cannot answer is an error, never absence",
			assert: func(t *testing.T, ctx context.Context, _ database, keys testKeys) {
				e, ok, err := newEnrolmentStore(t, unreachableDB(t), keys.rotated(t)).Get(ctx, "unreachable")
				require.Error(t, err)
				assert.False(t, ok, "a failed lookup must not read as not enrolled")
				assert.Zero(t, e)
			},
		},
		{
			name: "a lookup under a cancelled context fails with the cancellation, never absence",
			ctx:  cancelled,
			assert: func(t *testing.T, ctx context.Context, d database, keys testKeys) {
				e, ok, err := newEnrolmentStore(t, d.db, keys.rotated(t)).Get(ctx, "cancelled")
				require.ErrorIs(t, err, context.Canceled)
				assert.False(t, ok, "a cancelled lookup must not read as not enrolled")
				assert.Zero(t, e)
			},
		},
		{
			name: "a user reference PostgreSQL text cannot hold is refused without echoing it",
			assert: func(t *testing.T, ctx context.Context, d database, keys testKeys) {
				s := newEnrolmentStore(t, d.db, keys.rotated(t))
				err := s.PutPending(ctx, pending("nul\x00canary-7b21", "TOTP-SECRET"))
				require.Error(t, err)
				assert.NotContains(t, err.Error(), "canary-7b21")

				var n int
				require.NoError(t, d.conn.DB.QueryRowContext(ctx,
					`SELECT count(*) FROM mfa_enrolments WHERE user_id LIKE 'nul%'`).Scan(&n))
				assert.Zero(t, n, "nothing is written")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}
			tc.assert(t, ctx, d, newTestKeys(t))
		})
	}
}

// missingAADCipher seals through the default cipher but drops the additional
// data, so a value opens in any record: the sealed-column suite must catch it.
type missingAADCipher struct{ seal.Cipher }

func (c missingAADCipher) Seal(plaintext, _ []byte) ([]byte, error) {
	return c.Cipher.Seal(plaintext, nil)
}

func (c missingAADCipher) Open(sealed, _ []byte) ([]byte, string, error) {
	return c.Cipher.Open(sealed, nil)
}
