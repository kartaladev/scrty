package pgxstore_test

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/mfa"
	pgxstore "github.com/kartaladev/scrty/pgx"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/seal"
	"github.com/kartaladev/scrty/test/internal/storefix"
	"github.com/kartaladev/scrty/test/storetest"
)

// newEnrolmentStore builds the MFA enrolment store over pool, failing t on a
// refusal.
func newEnrolmentStore(t *testing.T, pool *pgxpool.Pool, c seal.Cipher, opts ...pgxstore.Option) mfa.EnrolmentStore {
	t.Helper()

	s, err := pgxstore.NewEnrolmentStore(pool, c, opts...)
	require.NoError(t, err)

	return s
}

func TestEnrolmentStore(t *testing.T) {
	t.Parallel()

	db := migrated(t)
	c := storefix.TestCipher(t)

	t.Run("pgx", func(t *testing.T) {
		storetest.RunEnrolmentStoreSuite(t, func(t *testing.T) mfa.EnrolmentStore {
			return newEnrolmentStore(t, emptied(t, db, "mfa_enrolments"), c)
		})
	})
}

func TestEnrolmentStore_StepAcceptRace(t *testing.T) {
	t.Parallel()

	c := storefix.TestCipher(t)
	h := durableHarness(migrated(t), func(t *testing.T, pool *pgxpool.Pool, opts ...pgxstore.Option) mfa.EnrolmentStore {
		return newEnrolmentStore(t, pool, c, opts...)
	})

	t.Run("pgx", func(t *testing.T) {
		storetest.RunStepAcceptRace(t, h, storefix.StepRace[mfa.EnrolmentStore]())
	})
}

func TestEnrolmentStore_SealedColumns(t *testing.T) {
	t.Parallel()

	db := migrated(t)
	c := storefix.TestCipher(t)
	h := durableHarness(db, func(t *testing.T, pool *pgxpool.Pool, opts ...pgxstore.Option) mfa.EnrolmentStore {
		return newEnrolmentStore(t, pool, c, opts...)
	})

	t.Run("pgx", func(t *testing.T) {
		storetest.RunSealedColumns(t, h, storefix.SealedEnrolments(db.Pool,
			func(t *testing.T, pool *pgxpool.Pool, c seal.Cipher) mfa.EnrolmentStore {
				return newEnrolmentStore(t, pool, c)
			}))
	})
}

func TestNewEnrolmentStore(t *testing.T) {
	t.Parallel()

	pool := unreachablePool(t)
	c := storefix.TestCipher(t)

	type testCase struct {
		name   string
		pool   *pgxpool.Pool
		cipher seal.Cipher
		opts   []pgxstore.Option
		assert func(t *testing.T, s mfa.EnrolmentStore, err error)
	}

	refused := refusedConfig[mfa.EnrolmentStore]
	accepted := storefix.AcceptedConfig[mfa.EnrolmentStore]

	cases := []testCase{
		{name: "a pool and a cipher are all it needs", pool: pool, cipher: c, assert: accepted},
		{
			name:   "it honours an id generator and re-sealing turned off",
			pool:   pool,
			cipher: c,
			opts: []pgxstore.Option{
				pgxstore.WithIDGenerator(id.NewV7Generator()),
				pgxstore.WithResealOnRead(false),
			},
			assert: accepted,
		},
		{name: "a missing cipher is refused", pool: pool, assert: refused("the cipher is nil")},
		{name: "a missing pool is refused", cipher: c, assert: refused("the pool is nil")},
		{
			name:   "a clock does not apply to MFA enrolments",
			pool:   pool,
			cipher: c,
			opts:   []pgxstore.Option{pgxstore.WithClock(time.Now)},
			assert: refused("WithClock does not apply to this store"),
		},
		{
			name:   "the store does not offer the enrolment path, whose fields it cannot keep",
			pool:   pool,
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

			s, err := pgxstore.NewEnrolmentStore(tc.pool, tc.cipher, tc.opts...)
			tc.assert(t, s, err)
		})
	}
}

func TestEnrolmentStore_Durable(t *testing.T) {
	t.Parallel()

	db := migrated(t)
	unreachable := unreachablePool(t)

	type testCase struct {
		name   string
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, ctx context.Context, db database, keys storefix.Keys)
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
			assert: func(t *testing.T, ctx context.Context, db database, keys storefix.Keys) {
				s := newEnrolmentStore(t, db.Pool, keys.Rotated(t))
				require.NoError(t, s.PutPending(ctx, storefix.Pending("victim-copied", "TOTP-VICTIM")))
				require.NoError(t, s.PutPending(ctx, storefix.Pending("attacker-copied", "TOTP-ATTACKER")))
				storefix.SetSecretColumn(ctx, t, db.DB, "attacker-copied", storefix.SecretColumn(ctx, t, db.DB, "victim-copied"))

				e, ok, err := s.Get(ctx, "attacker-copied")
				refusedOpen(t, e, ok, err, seal.ErrDecryptionFailed)
			},
		},
		{
			name: "an enrolment reassigned to another user does not open for that user",
			assert: func(t *testing.T, ctx context.Context, db database, keys storefix.Keys) {
				s := newEnrolmentStore(t, db.Pool, keys.Rotated(t))
				require.NoError(t, s.PutPending(ctx, storefix.Pending("attacker-moved", "TOTP-ATTACKER")))
				_, err := db.DB.ExecContext(ctx,
					`UPDATE mfa_enrolments SET user_id = 'victim-moved' WHERE user_id = 'attacker-moved'`)
				require.NoError(t, err)

				e, ok, err := s.Get(ctx, "victim-moved")
				refusedOpen(t, e, ok, err, seal.ErrDecryptionFailed)
			},
		},
		{
			name: "a sealed session ID token moved into the secret column does not open",
			assert: func(t *testing.T, ctx context.Context, db database, keys storefix.Keys) {
				c := keys.Rotated(t)
				sessions := newSessionStore(t, db.Pool, c)
				require.NoError(t, sessions.Create(ctx, storefix.DurableSession("sid-moved", time.Now())))
				var token string
				require.NoError(t, db.DB.QueryRowContext(ctx,
					`SELECT external_id_token FROM sessions WHERE id_digest = $1`, storefix.Digest("sid-moved")).Scan(&token))

				s := newEnrolmentStore(t, db.Pool, c)
				require.NoError(t, s.PutPending(ctx, storefix.Pending("table-moved", "TOTP-SECRET")))
				storefix.SetSecretColumn(ctx, t, db.DB, "table-moved", token)

				e, ok, err := s.Get(ctx, "table-moved")
				refusedOpen(t, e, ok, err, seal.ErrDecryptionFailed)
			},
		},
		{
			name: "a tampered byte does not open",
			assert: func(t *testing.T, ctx context.Context, db database, keys storefix.Keys) {
				s := newEnrolmentStore(t, db.Pool, keys.Rotated(t))
				require.NoError(t, s.PutPending(ctx, storefix.Pending("tampered", "TOTP-SECRET")))
				sealed, err := base64.RawURLEncoding.DecodeString(storefix.SecretColumn(ctx, t, db.DB, "tampered"))
				require.NoError(t, err)
				sealed[len(sealed)-1] ^= 1
				storefix.SetSecretColumn(ctx, t, db.DB, "tampered", base64.RawURLEncoding.EncodeToString(sealed))

				e, ok, err := s.Get(ctx, "tampered")
				refusedOpen(t, e, ok, err, seal.ErrDecryptionFailed)
			},
		},
		{
			name: "a stored value that is not base64url is an error, never absence",
			assert: func(t *testing.T, ctx context.Context, db database, keys storefix.Keys) {
				s := newEnrolmentStore(t, db.Pool, keys.Rotated(t))
				require.NoError(t, s.PutPending(ctx, storefix.Pending("not-base64", "TOTP-SECRET")))
				storefix.SetSecretColumn(ctx, t, db.DB, "not-base64", "***not base64***")

				e, ok, err := s.Get(ctx, "not-base64")
				require.Error(t, err)
				assert.False(t, ok)
				assert.Zero(t, e)
			},
		},
		{
			name: "a confirmation time that is infinite is an error, never unconfirmed",
			assert: func(t *testing.T, ctx context.Context, db database, keys storefix.Keys) {
				s := newEnrolmentStore(t, db.Pool, keys.Rotated(t))
				require.NoError(t, s.PutPending(ctx, storefix.Pending("infinite", "TOTP-SECRET")))
				_, err := db.DB.ExecContext(ctx,
					`UPDATE mfa_enrolments SET confirmed_at = 'infinity' WHERE user_id = 'infinite'`)
				require.NoError(t, err)

				e, ok, err := s.Get(ctx, "infinite")
				require.Error(t, err)
				assert.False(t, ok)
				assert.Zero(t, e)
			},
		},
		{
			name: "a missing key is reported as an unknown key id, never as absence",
			assert: func(t *testing.T, ctx context.Context, db database, keys storefix.Keys) {
				require.NoError(t, newEnrolmentStore(t, db.Pool, keys.UnderK1(t)).
					PutPending(ctx, storefix.Pending("missing-key", "TOTP-SECRET")))

				e, ok, err := newEnrolmentStore(t, db.Pool, keys.OnlyK2(t)).Get(ctx, "missing-key")
				refusedOpen(t, e, ok, err, seal.ErrUnknownKeyID)
			},
		},
		{
			name: "a read outside a transaction re-seals the secret under the active key",
			assert: func(t *testing.T, ctx context.Context, db database, keys storefix.Keys) {
				require.NoError(t, newEnrolmentStore(t, db.Pool, keys.UnderK1(t)).
					PutPending(ctx, storefix.Pending("reseal", "TOTP-SECRET")))

				e, ok, err := newEnrolmentStore(t, db.Pool, keys.Rotated(t)).Get(ctx, "reseal")
				require.NoError(t, err)
				require.True(t, ok)
				assert.Equal(t, []byte("TOTP-SECRET"), e.Secret)

				e, ok, err = newEnrolmentStore(t, db.Pool, keys.OnlyK2(t)).Get(ctx, "reseal")
				require.NoError(t, err, "the read did not re-seal under the active key")
				require.True(t, ok)
				assert.Equal(t, []byte("TOTP-SECRET"), e.Secret)
			},
		},
		{
			name: "a re-seal does not replace a secret a concurrent begin wrote",
			assert: func(t *testing.T, ctx context.Context, db database, keys storefix.Keys) {
				require.NoError(t, newEnrolmentStore(t, db.Pool, keys.UnderK1(t)).
					PutPending(ctx, storefix.Pending("reenrol", "TOTP-OLD")))

				gated := storefix.NewGatedCipher(keys.Rotated(t))
				reader := newEnrolmentStore(t, db.Pool, gated)
				type read struct {
					e   mfa.Enrolment
					err error
				}
				done := make(chan read, 1)
				go func() {
					e, _, err := reader.Get(ctx, "reenrol")
					done <- read{e, err}
				}()

				<-gated.Opening()
				writer := newEnrolmentStore(t, db.Pool, keys.Rotated(t))
				require.NoError(t, writer.PutPending(ctx, storefix.Pending("reenrol", "TOTP-NEW")))
				gated.Release()
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
			assert: func(t *testing.T, ctx context.Context, db database, keys storefix.Keys) {
				require.NoError(t, newEnrolmentStore(t, db.Pool, keys.UnderK1(t)).
					PutPending(ctx, storefix.Pending("in-tx", "TOTP-SECRET")))
				before := storefix.SecretColumn(ctx, t, db.DB, "in-tx")

				tx := beginTx(ctx, t, db.Pool)
				_, ok, err := newEnrolmentStore(t, db.Pool, keys.Rotated(t)).Get(pgxstore.WithTx(ctx, tx), "in-tx")
				require.NoError(t, err)
				require.True(t, ok)
				require.NoError(t, tx.Commit(ctx))

				assert.Equal(t, before, storefix.SecretColumn(ctx, t, db.DB, "in-tx"), "the read inside a transaction re-sealed")
			},
		},
		{
			name: "a read inside a transaction a resolver reports rewrites nothing",
			assert: func(t *testing.T, ctx context.Context, db database, keys storefix.Keys) {
				require.NoError(t, newEnrolmentStore(t, db.Pool, keys.UnderK1(t)).
					PutPending(ctx, storefix.Pending("resolved", "TOTP-SECRET")))
				before := storefix.SecretColumn(ctx, t, db.DB, "resolved")

				tx := beginTx(ctx, t, db.Pool)
				s := newEnrolmentStore(t, db.Pool, keys.Rotated(t),
					pgxstore.WithTxResolver(func(context.Context) (pgx.Tx, bool) { return tx, true }))
				_, ok, err := s.Get(ctx, "resolved")
				require.NoError(t, err)
				require.True(t, ok)
				require.NoError(t, tx.Commit(ctx))

				assert.Equal(t, before, storefix.SecretColumn(ctx, t, db.DB, "resolved"), "the read inside a transaction re-sealed")
			},
		},
		{
			name: "with re-sealing turned off a read rewrites nothing, and the secret still opens only with k1",
			assert: func(t *testing.T, ctx context.Context, db database, keys storefix.Keys) {
				require.NoError(t, newEnrolmentStore(t, db.Pool, keys.UnderK1(t)).
					PutPending(ctx, storefix.Pending("reseal-off", "TOTP-SECRET")))
				before := storefix.SecretColumn(ctx, t, db.DB, "reseal-off")

				_, ok, err := newEnrolmentStore(t, db.Pool, keys.Rotated(t), pgxstore.WithResealOnRead(false)).
					Get(ctx, "reseal-off")
				require.NoError(t, err)
				require.True(t, ok)

				assert.Equal(t, before, storefix.SecretColumn(ctx, t, db.DB, "reseal-off"), "the read re-sealed")
				_, _, err = newEnrolmentStore(t, db.Pool, keys.OnlyK2(t)).Get(ctx, "reseal-off")
				assert.ErrorIs(t, err, seal.ErrUnknownKeyID)
			},
		},
		{
			name: "a confirmation never moves a step recorded out of band backwards",
			assert: func(t *testing.T, ctx context.Context, db database, keys storefix.Keys) {
				s := newEnrolmentStore(t, db.Pool, keys.Rotated(t))
				require.NoError(t, s.PutPending(ctx, storefix.Pending("step-kept", "TOTP-SECRET")))
				_, err := db.DB.ExecContext(ctx,
					`UPDATE mfa_enrolments SET last_step = 2000 WHERE user_id = 'step-kept'`)
				require.NoError(t, err)

				ok, err := s.Confirm(ctx, "step-kept", 1000, storefix.EnrolmentBegun.Add(time.Minute))
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
			assert: func(t *testing.T, ctx context.Context, db database, keys storefix.Keys) {
				s := newEnrolmentStore(t, db.Pool, keys.Rotated(t))
				require.NoError(t, s.PutPending(ctx, storefix.Pending("step-cleared", "TOTP-OLD")))
				_, err := db.DB.ExecContext(ctx,
					`UPDATE mfa_enrolments SET last_step = 2000 WHERE user_id = 'step-cleared'`)
				require.NoError(t, err)

				require.NoError(t, s.PutPending(ctx, storefix.Pending("step-cleared", "TOTP-NEW")))

				e, ok, err := s.Get(ctx, "step-cleared")
				require.NoError(t, err)
				require.True(t, ok)
				assert.Zero(t, e.LastStep, "the repeated begin kept the recorded step")
			},
		},
		{
			name: "a lookup on a database that cannot answer is an error, never absence",
			assert: func(t *testing.T, ctx context.Context, _ database, keys storefix.Keys) {
				e, ok, err := newEnrolmentStore(t, unreachable, keys.Rotated(t)).Get(ctx, "unreachable")
				require.Error(t, err)
				assert.False(t, ok, "a failed lookup must not read as not enrolled")
				assert.Zero(t, e)
			},
		},
		{
			name: "a lookup under a cancelled context fails with the cancellation, never absence",
			ctx:  storefix.Cancelled,
			assert: func(t *testing.T, ctx context.Context, db database, keys storefix.Keys) {
				e, ok, err := newEnrolmentStore(t, db.Pool, keys.Rotated(t)).Get(ctx, "cancelled")
				require.ErrorIs(t, err, context.Canceled)
				assert.False(t, ok, "a cancelled lookup must not read as not enrolled")
				assert.Zero(t, e)
			},
		},
		{
			name: "a user reference PostgreSQL text cannot hold is refused without echoing it",
			assert: func(t *testing.T, ctx context.Context, db database, keys storefix.Keys) {
				s := newEnrolmentStore(t, db.Pool, keys.Rotated(t))
				err := s.PutPending(ctx, storefix.Pending("nul\x00canary-7b21", "TOTP-SECRET"))
				require.Error(t, err)
				assert.NotContains(t, err.Error(), "canary-7b21")

				var n int
				require.NoError(t, db.DB.QueryRowContext(ctx,
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
			tc.assert(t, ctx, db, storefix.NewKeys(t))
		})
	}
}
