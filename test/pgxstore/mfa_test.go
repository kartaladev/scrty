package pgxstore_test

import (
	"context"
	"database/sql"
	"encoding/base64"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	pgxstore "github.com/kartaladev/scrty/pgx"
	"github.com/kartaladev/scrty/pkg/clock"
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
	t.Run("pgx device proofs", func(t *testing.T) {
		storetest.RunDeviceProofSuite(t, func(t *testing.T) storetest.DeviceProofEnrolmentStore {
			return storetest.RequireDeviceProof(t, newEnrolmentStore(t, emptied(t, db, "mfa_enrolments"), c))
		})
	})
}

// provingHarness is the durable harness over the enrolment store as the
// enrolment path's races need it: with its device-proof port.
func provingHarness(t *testing.T) storetest.DurableHarness[storetest.DeviceProofEnrolmentStore] {
	t.Helper()

	c := storefix.TestCipher(t)

	return durableHarness(migrated(t),
		func(t *testing.T, pool *pgxpool.Pool, opts ...pgxstore.Option) storetest.DeviceProofEnrolmentStore {
			return storetest.RequireDeviceProof(t, newEnrolmentStore(t, pool, c, opts...))
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

func TestEnrolmentStore_VerifyChargeRace(t *testing.T) {
	t.Parallel()

	c := storefix.TestCipher(t)
	h := durableHarness(migrated(t), func(t *testing.T, pool *pgxpool.Pool, opts ...pgxstore.Option) mfa.EnrolmentStore {
		return newEnrolmentStore(t, pool, c, opts...)
	})

	t.Run("pgx", func(t *testing.T) {
		storetest.RunVerifyChargeRace(t, h, storefix.VerifyChargeRace[mfa.EnrolmentStore]())
	})
}

func TestEnrolmentStore_CompleteRace(t *testing.T) {
	t.Parallel()

	h := provingHarness(t)

	t.Run("pgx", func(t *testing.T) {
		storetest.RunCompleteRace(t, h, storefix.CompleteRace[storetest.DeviceProofEnrolmentStore]())
	})
}

func TestEnrolmentStore_ChargeRace(t *testing.T) {
	t.Parallel()

	h := provingHarness(t)

	t.Run("pgx", func(t *testing.T) {
		storetest.RunChargeRace(t, h, storefix.ChargeRace[storetest.DeviceProofEnrolmentStore]())
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
	t.Run("pgx emailed code", func(t *testing.T) {
		codes := storefix.SealedEmailCodes(db.Pool,
			func(t *testing.T, pool *pgxpool.Pool, c seal.Cipher) mfa.EnrolmentStore {
				return newEnrolmentStore(t, pool, c)
			})
		storetest.RunSealedColumns(t, h, codes)
		storefix.RunEmailCodeBindings(t, db.DB, codes)
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
			name:   "it honours a clock, which decides an emailed code's expiry",
			pool:   pool,
			cipher: c,
			opts:   []pgxstore.Option{pgxstore.WithClock(clock.System())},
			assert: accepted,
		},
		{
			name:   "the store offers the enrolment path",
			pool:   pool,
			cipher: c,
			assert: func(t *testing.T, s mfa.EnrolmentStore, err error) {
				require.NoError(t, err)
				_, proves := s.(mfa.DeviceProofStore)
				assert.True(t, proves, "the durable store must implement mfa.DeviceProofStore")
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
			// The code's expiry is in the past by the wall clock, so with the
			// default clock the store would treat it as already expired and
			// never try to open it. An injected clock still before the
			// expiry it decided by must be the one the wrapper consults, not
			// the wall clock: it must still try to open the code, and fail
			// closed once k1 is gone.
			name: "WithClock, not the wall clock, decides whether an emailed code is opened",
			assert: func(t *testing.T, ctx context.Context, db database, keys storefix.Keys) {
				user := identity.UserID("clock-injected")
				until := proveUnderK1(ctx, t, db.Pool, keys, user, time.Now().Add(-time.Hour))

				before := until.Add(-time.Minute)
				s := newEnrolmentStore(t, db.Pool, keys.OnlyK2(t), pgxstore.WithClock(storefix.NewClock(before)))
				e, ok, err := s.Get(ctx, user)
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
			name: "a charge on a database that cannot answer is an error, never a refusal",
			assert: func(t *testing.T, ctx context.Context, _ database, keys storefix.Keys) {
				p := storetest.RequireDeviceProof(t, newEnrolmentStore(t, unreachable, keys.Rotated(t)))
				count, charged, err := p.ChargeEmailCode(ctx, "unreachable-charge", id.Nil, time.Now())
				require.Error(t, err)
				assert.False(t, charged, "a failed charge must not read as refused")
				assert.Zero(t, count)
			},
		},
		{
			name: "a device proof on a database that cannot answer is an error, never a refusal",
			assert: func(t *testing.T, ctx context.Context, _ database, keys storefix.Keys) {
				p := storetest.RequireDeviceProof(t, newEnrolmentStore(t, unreachable, keys.Rotated(t)))
				now := time.Now()
				proven, err := p.ProveDevice(ctx, "unreachable-prove", id.Nil, 1000, []byte("314159"), now.Add(10*time.Minute), now)
				require.Error(t, err)
				assert.False(t, proven, "a failed device proof must not read as refused")
			},
		},
		{
			name: "a completion on a database that cannot answer is an error, never a refusal",
			assert: func(t *testing.T, ctx context.Context, _ database, keys storefix.Keys) {
				p := storetest.RequireDeviceProof(t, newEnrolmentStore(t, unreachable, keys.Rotated(t)))
				completed, err := p.Complete(ctx, "unreachable-complete", id.Nil, time.Now())
				require.Error(t, err)
				assert.False(t, completed, "a failed completion must not read as refused")
			},
		},
		{
			// A proven enrolment with no generation, as an out-of-band begin
			// through PutPending with id.Nil leaves it once a proof is
			// written beside it: the nil generation must match it in none
			// of the three writes.
			name: "an enrolment begun without a generation is never proven, completed or charged through the nil generation",
			assert: func(t *testing.T, ctx context.Context, db database, keys storefix.Keys) {
				s := newEnrolmentStore(t, db.Pool, keys.Rotated(t))
				require.NoError(t, s.PutPending(ctx, storefix.Pending("nil-gen-begun", "TOTP-SECRET")))
				assertNilGenerationRefused(ctx, t, db.DB, s, "nil-gen-begun")
			},
		},
		{
			// The all-zero UUID written into the column out of band is what
			// id.Nil would be bound as if it were sent as its text.
			name: "an enrolment holding the all-zero generation is never matched by the nil generation",
			assert: func(t *testing.T, ctx context.Context, db database, keys storefix.Keys) {
				s := newEnrolmentStore(t, db.Pool, keys.Rotated(t))
				require.NoError(t, s.PutPending(ctx, storefix.Pending("nil-gen-zero", "TOTP-SECRET")))
				_, err := db.DB.ExecContext(ctx,
					`UPDATE mfa_enrolments SET generation = '00000000-0000-0000-0000-000000000000' WHERE user_id = $1`,
					"nil-gen-zero")
				require.NoError(t, err)
				assertNilGenerationRefused(ctx, t, db.DB, s, "nil-gen-zero")
			},
		},
		{
			// ProveDevice writes a validly sealed code and a future expiry;
			// taking device_proven_at back to NULL out of band, leaving the
			// rest untouched, isolates "device_proven_at IS NOT NULL" as the
			// only condition standing between the charge and this row.
			name: "a charge against an outstanding, unexpired code with no device proof is refused",
			assert: func(t *testing.T, ctx context.Context, db database, keys storefix.Keys) {
				assertOutOfBandChargeRefused(ctx, t, db, keys, "charge-unproven",
					`UPDATE mfa_enrolments SET device_proven_at = NULL WHERE user_id = $1`,
					"a charge against an unproven enrolment must be refused")
			},
		},
		{
			// Confirming the row out of band, without going through
			// Complete, leaves the sealed code and its future expiry in
			// place; the only reason left for the charge to be refused is
			// "confirmed_at IS NULL".
			name: "a charge against a confirmed enrolment's outstanding, unexpired code is refused",
			assert: func(t *testing.T, ctx context.Context, db database, keys storefix.Keys) {
				assertOutOfBandChargeRefused(ctx, t, db, keys, "charge-confirmed",
					`UPDATE mfa_enrolments SET confirmed_at = email_code_until + interval '1 hour' WHERE user_id = $1`,
					"a charge against a confirmed enrolment must be refused")
			},
		},
		{
			name: "a device-proof time that is infinite is an error, never unproven",
			assert: func(t *testing.T, ctx context.Context, db database, keys storefix.Keys) {
				s := newEnrolmentStore(t, db.Pool, keys.Rotated(t))
				require.NoError(t, s.PutPending(ctx, storefix.Pending("infinite-proof", "TOTP-SECRET")))
				_, err := db.DB.ExecContext(ctx,
					`UPDATE mfa_enrolments SET device_proven_at = 'infinity' WHERE user_id = 'infinite-proof'`)
				require.NoError(t, err)

				e, ok, err := s.Get(ctx, "infinite-proof")
				require.Error(t, err)
				assert.False(t, ok)
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

// assertNilGenerationRefused requires the three device-proof writes naming
// the nil generation to be refused against user's enrolment, and to leave its
// row unchanged: first a proof of the pending enrolment, then, with a proof
// and an outstanding code written beside it out of band, a completion and a
// charge.
func assertNilGenerationRefused(
	ctx context.Context, t *testing.T, raw *sql.DB, s mfa.EnrolmentStore, user identity.UserID,
) {
	t.Helper()

	p := storetest.RequireDeviceProof(t, s)
	at := storefix.EnrolmentBegun.Add(time.Minute)

	proven, err := p.ProveDevice(ctx, user, id.Nil, 1000, []byte("314159"), at.Add(10*time.Minute), at)
	require.NoError(t, err)
	assert.False(t, proven, "a proof naming the nil generation matched an enrolment without one")

	_, err = raw.ExecContext(ctx, `UPDATE mfa_enrolments
SET device_proven_at = $2, email_code = 'b3V0LW9mLWJhbmQ', email_code_until = $3 WHERE user_id = $1`,
		string(user), at, at.Add(10*time.Minute))
	require.NoError(t, err)
	before := enrolmentRow(ctx, t, raw, user)

	completed, err := p.Complete(ctx, user, id.Nil, at)
	require.NoError(t, err)
	assert.False(t, completed, "a completion naming the nil generation matched an enrolment without one")

	count, charged, err := p.ChargeEmailCode(ctx, user, id.Nil, at)
	require.NoError(t, err)
	assert.False(t, charged, "a charge naming the nil generation matched an enrolment without one")
	assert.Zero(t, count)

	assert.Equal(t, before, enrolmentRow(ctx, t, raw, user), "a refused write changed the row")
}

// assertOutOfBandChargeRefused begins user's enrolment on a fresh generation,
// proves its device with an emailed code, applies change (a statement taking
// the user as $1) out of band, and requires a charge before the code expires
// to be refused, reporting why, and to leave the row unchanged.
func assertOutOfBandChargeRefused(
	ctx context.Context, t *testing.T, db database, keys storefix.Keys, user identity.UserID, change, why string,
) {
	t.Helper()

	s := newEnrolmentStore(t, db.Pool, keys.Rotated(t))
	p := storetest.RequireDeviceProof(t, s)
	g, err := id.NewV7Generator().NewID()
	require.NoError(t, err)

	e := storefix.Pending(user, "TOTP-SECRET")
	e.Generation = g
	require.NoError(t, s.PutPending(ctx, e))

	provenAt := storefix.EnrolmentBegun.Add(time.Minute)
	until := storefix.EnrolmentBegun.Add(11 * time.Minute)
	proven, err := p.ProveDevice(ctx, user, g, 1000, []byte("314159"), until, provenAt)
	require.NoError(t, err)
	require.True(t, proven)

	_, err = db.DB.ExecContext(ctx, change, string(user))
	require.NoError(t, err)
	before := enrolmentRow(ctx, t, db.DB, user)

	count, charged, err := p.ChargeEmailCode(ctx, user, g, provenAt.Add(time.Minute))
	require.NoError(t, err)
	assert.False(t, charged, why)
	assert.Zero(t, count)
	assert.Equal(t, before, enrolmentRow(ctx, t, db.DB, user), "a refused charge changed the row")
}

// enrolmentRow is user's enrolment row as JSON, read out of band.
func enrolmentRow(ctx context.Context, t *testing.T, raw *sql.DB, user identity.UserID) string {
	t.Helper()

	var row string
	require.NoError(t, raw.QueryRowContext(ctx,
		`SELECT row_to_json(e)::text FROM mfa_enrolments e WHERE user_id = $1`, string(user)).Scan(&row))

	return row
}

// proveUnderK1 begins user's enrolment and proves its device with an emailed
// code expiring at until, both under k1 alone, then reads it once through the
// rotated keyring, which re-seals the secret under k2 and leaves the code
// under k1, as an ordinary rotation does before k1 is removed. It returns the
// code's expiry as stored.
func proveUnderK1(
	ctx context.Context, t *testing.T, pool *pgxpool.Pool, keys storefix.Keys, user identity.UserID, until time.Time,
) time.Time {
	t.Helper()

	g, err := id.NewV7Generator().NewID()
	require.NoError(t, err)
	e := storefix.Pending(user, "TOTP-SECRET")
	e.Generation = g

	s := newEnrolmentStore(t, pool, keys.UnderK1(t))
	require.NoError(t, s.PutPending(ctx, e))
	until = until.UTC().Truncate(time.Microsecond)
	proven, err := storetest.RequireDeviceProof(t, s).
		ProveDevice(ctx, user, g, 1000, []byte("314159"), until, until.Add(-10*time.Minute))
	require.NoError(t, err)
	require.True(t, proven)

	_, ok, err := newEnrolmentStore(t, pool, keys.Rotated(t)).Get(ctx, user)
	require.NoError(t, err)
	require.True(t, ok)

	return until
}
