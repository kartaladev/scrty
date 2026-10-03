package gormstore_test

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	gormdb "gorm.io/gorm"

	"github.com/kartaladev/scrty/apikey"
	gormstore "github.com/kartaladev/scrty/gorm"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/onetime"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/seal"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/signingkey"
	"github.com/kartaladev/scrty/test/internal/storefix"
	"github.com/kartaladev/scrty/test/storetest"
)

// recordingPool is the connection pool beneath a *gorm.DB: every statement
// gorm sends, and every transaction it begins, passes through it and is
// recorded, whatever gorm's logger or callbacks do.
type recordingPool struct {
	db *sql.DB

	mu    sync.Mutex
	stmts []string
}

func (p *recordingPool) record(stmt string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stmts = append(p.stmts, stmt)
}

// take returns what was recorded since the last take, and forgets it.
func (p *recordingPool) take() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	stmts := p.stmts
	p.stmts = nil
	return stmts
}

func (p *recordingPool) PrepareContext(ctx context.Context, query string) (*sql.Stmt, error) {
	p.record("PREPARE " + query)
	return p.db.PrepareContext(ctx, query)
}

func (p *recordingPool) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	p.record(query)
	return p.db.ExecContext(ctx, query, args...)
}

func (p *recordingPool) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	p.record(query)
	return p.db.QueryContext(ctx, query, args...)
}

func (p *recordingPool) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	p.record(query)
	return p.db.QueryRowContext(ctx, query, args...)
}

func (p *recordingPool) BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error) {
	p.record("BEGIN")
	return p.db.BeginTx(ctx, opts)
}

// storeSet is one of each gorm store, on one handle.
type storeSet struct {
	sessions   session.Store
	tokens     *gormstore.OneTimeStore
	attempts   *gormstore.AttemptStore
	keys       signingkey.KeyStore
	enrolments mfa.EnrolmentStore
	apiKeys    *gormstore.APIKeyStore
	links      *gormstore.LinkStore
	flows      *gormstore.FlowStore
	handoffs   *gormstore.HandoffStore
}

func newStoreSet(t *testing.T, db *gormdb.DB, c seal.Cipher) storeSet {
	t.Helper()

	return storeSet{
		sessions:   newSessionStore(t, db, c),
		tokens:     newOneTimeStore(t, db),
		attempts:   newAttemptStore(t, db),
		keys:       newSigningKeyStore(t, db, c),
		enrolments: newEnrolmentStore(t, db, c),
		apiKeys:    newAPIKeyStore(t, db),
		links:      newLinkStore(t, db),
		flows:      newFlowStore(t, db),
		handoffs:   newHandoffStore(t, db),
	}
}

// TestStores_OneStatementPerOperation pins that every store operation, a
// refused one included, reaches the database as exactly one statement: no
// SELECT before a write, no BEGIN and COMMIT of gorm's default transaction,
// no statement of a hook. A refusal is that statement's zero rows affected.
//
// Each case seeds through stores on an ordinary handle, then runs one
// operation through stores whose handle records every statement reaching its
// pool.
func TestStores_OneStatementPerOperation(t *testing.T) {
	t.Parallel()

	d := migratedDB(t)
	keys := storefix.NewKeys(t)
	c := keys.Rotated(t)
	pool := &recordingPool{db: d.conn.DB}
	recorded, err := gormdb.Open(postgres.New(postgres.Config{Conn: pool}), &gormdb.Config{DisableAutomaticPing: true})
	require.NoError(t, err)

	seed, counted := newStoreSet(t, d.db, c), newStoreSet(t, recorded, c)
	now := time.Now()

	type testCase struct {
		name string
		// run seeds through seed, and runs the operation under test through
		// counted after calling started.
		run    func(ctx context.Context, t *testing.T, seed, counted storeSet, started func()) error
		assert func(t *testing.T, err error, stmts []string)
	}

	// statements asserts the operation ran exactly the statements expect, in
	// order and compared by their whole text with whitespace collapsed, and
	// returned nil or refusal. The whole text pins every guard of a WHERE
	// clause, not just the kind of statement.
	statements := func(refusal error, expect ...string) func(t *testing.T, err error, stmts []string) {
		return func(t *testing.T, err error, stmts []string) {
			t.Helper()
			if refusal == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, refusal)
			}
			assert.Equal(t, expect, normalized(stmts))
		}
	}
	one := func(expect string) func(t *testing.T, err error, stmts []string) { return statements(nil, expect) }
	refused := func(refusal error, expect string) func(t *testing.T, err error, stmts []string) {
		return statements(refusal, expect)
	}

	// with seeds nothing and runs op.
	with := func(op func(ctx context.Context, s storeSet) error) func(context.Context, *testing.T, storeSet, storeSet, func()) error {
		return func(ctx context.Context, _ *testing.T, _, counted storeSet, started func()) error {
			started()
			return op(ctx, counted)
		}
	}
	// ignoring drops a result an operation returns beside its error.
	ignoring := func(_ any, err error) error { return err }
	errNotStored := errors.New("the enrolment was not written")
	flag := func(ok bool, err error) error {
		if err == nil && !ok {
			return errNotStored
		}
		return err
	}

	cases := []testCase{
		{name: "session create", run: with(func(ctx context.Context, s storeSet) error {
			return s.sessions.Create(ctx, storefix.DurableSession("stmt-sid-create", now))
		}), assert: one(`INSERT INTO "sessions" ("id","id_digest","user_id","created_at","last_accessed_at","idle_expires_at","absolute_expires_at","first_factor","mfa_state","mfa_satisfied_at","password_change_pending","external_provider","external_issuer","external_session_id","external_id_token","data","enrolment_origin_deadline","enrolment_generation","recovered_at","mfa_at_first_factor","federated_amr","federated_acr") VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22) ON CONFLICT ("id_digest") DO NOTHING`)},
		{name: "session create of a stored identifier", run: func(ctx context.Context, t *testing.T, seed, counted storeSet, started func()) error {
			require.NoError(t, seed.sessions.Create(ctx, storefix.DurableSession("stmt-sid-dup", now)))
			started()
			err := counted.sessions.Create(ctx, storefix.DurableSession("stmt-sid-dup", now))
			require.Error(t, err)
			return nil
		}, assert: one(`INSERT INTO "sessions" ("id","id_digest","user_id","created_at","last_accessed_at","idle_expires_at","absolute_expires_at","first_factor","mfa_state","mfa_satisfied_at","password_change_pending","external_provider","external_issuer","external_session_id","external_id_token","data","enrolment_origin_deadline","enrolment_generation","recovered_at","mfa_at_first_factor","federated_amr","federated_acr") VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22) ON CONFLICT ("id_digest") DO NOTHING`)},
		{name: "session save", run: func(ctx context.Context, t *testing.T, seed, counted storeSet, started func()) error {
			require.NoError(t, seed.sessions.Create(ctx, storefix.DurableSession("stmt-sid-save", now)))
			started()
			return counted.sessions.Save(ctx, storefix.DurableSession("stmt-sid-save", now))
		}, assert: one(`UPDATE "sessions" SET "user_id"=$1,"created_at"=$2,"last_accessed_at"=$3,"idle_expires_at"=$4,"absolute_expires_at"=$5,"first_factor"=$6,"mfa_state"=$7,"mfa_satisfied_at"=$8,"password_change_pending"=$9,"external_provider"=$10,"external_issuer"=$11,"external_session_id"=$12,"external_id_token"=$13,"data"=$14,"enrolment_origin_deadline"=$15,"enrolment_generation"=$16,"recovered_at"=$17,"federated_amr"=$18,"federated_acr"=$19 WHERE id_digest = $20`)},
		{name: "session save of a session that is gone", run: with(func(ctx context.Context, s storeSet) error {
			return s.sessions.Save(ctx, storefix.DurableSession("stmt-sid-gone", now))
		}), assert: refused(session.ErrSessionNotFound, `UPDATE "sessions" SET "user_id"=$1,"created_at"=$2,"last_accessed_at"=$3,"idle_expires_at"=$4,"absolute_expires_at"=$5,"first_factor"=$6,"mfa_state"=$7,"mfa_satisfied_at"=$8,"password_change_pending"=$9,"external_provider"=$10,"external_issuer"=$11,"external_session_id"=$12,"external_id_token"=$13,"data"=$14,"enrolment_origin_deadline"=$15,"enrolment_generation"=$16,"recovered_at"=$17,"federated_amr"=$18,"federated_acr"=$19 WHERE id_digest = $20`)},
		{name: "session load", run: func(ctx context.Context, t *testing.T, seed, counted storeSet, started func()) error {
			require.NoError(t, seed.sessions.Create(ctx, storefix.DurableSession("stmt-sid-load", now)))
			started()
			return ignoring(counted.sessions.Load(ctx, "stmt-sid-load"))
		}, assert: one(`SELECT * FROM "sessions" WHERE id_digest = $1 LIMIT $2`)},
		{name: "session delete", run: with(func(ctx context.Context, s storeSet) error {
			return s.sessions.Delete(ctx, "stmt-sid-delete")
		}), assert: one(`DELETE FROM "sessions" WHERE id_digest = $1`)},
		{name: "session delete by user", run: with(func(ctx context.Context, s storeSet) error {
			return s.sessions.DeleteByUser(ctx, "stmt-user")
		}), assert: one(`DELETE FROM "sessions" WHERE user_id = $1`)},
		{name: "session count", run: with(func(ctx context.Context, s storeSet) error {
			return ignoring(s.sessions.CountActiveByUser(ctx, "stmt-user"))
		}), assert: one(`SELECT count(*) FROM "sessions" WHERE user_id = $1 AND idle_expires_at > $2 AND absolute_expires_at > $3`)},
		{name: "session purge", run: with(func(ctx context.Context, s storeSet) error {
			return ignoring(s.sessions.DeleteExpired(ctx))
		}), assert: one(`DELETE FROM "sessions" WHERE idle_expires_at <= $1 OR absolute_expires_at <= $2`)},
		{name: "session delete by provider session", run: with(func(ctx context.Context, s storeSet) error {
			return ignoring(s.sessions.DeleteByExternalSession(ctx, "https://idp.example", "stmt-ext"))
		}), assert: one(`DELETE FROM "sessions" WHERE external_issuer = $1 AND external_session_id = $2 AND external_issuer <> '' AND external_session_id <> ''`)},
		{name: "session delete by user and issuer", run: with(func(ctx context.Context, s storeSet) error {
			return ignoring(s.sessions.DeleteByUserAndExternalIssuer(ctx, "stmt-user", "https://idp.example"))
		}), assert: one(`DELETE FROM "sessions" WHERE user_id = $1 AND external_issuer = $2 AND external_issuer <> ''`)},

		{name: "one-time insert", run: with(func(ctx context.Context, s storeSet) error {
			return s.tokens.Insert(ctx, storefix.RaceToken(0x50000))
		}), assert: one(`INSERT INTO "one_time_tokens" ("id","purpose","subject","secret_hash","binding_hash","issued_at","expires_at","consumed_at") VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT ("id") DO NOTHING`)},
		{name: "one-time find", run: with(func(ctx context.Context, s storeSet) error {
			return ignoring(s.tokens.FindByID(ctx, storefix.RaceToken(0x5000f).ID))
		}), assert: refused(onetime.ErrTokenNotFound, `SELECT * FROM "one_time_tokens" WHERE id = $1 LIMIT $2`)},
		{name: "one-time consume", run: func(ctx context.Context, t *testing.T, seed, counted storeSet, started func()) error {
			require.NoError(t, seed.tokens.Insert(ctx, storefix.RaceToken(0x50001)))
			started()
			return counted.tokens.Consume(ctx, storefix.RaceToken(0x50001).ID, now)
		}, assert: one(`UPDATE "one_time_tokens" SET "consumed_at"=$1 WHERE id = $2 AND consumed_at IS NULL`)},
		{name: "one-time consume of a spent token", run: func(ctx context.Context, t *testing.T, seed, counted storeSet, started func()) error {
			require.NoError(t, seed.tokens.Insert(ctx, storefix.RaceToken(0x50002)))
			require.NoError(t, seed.tokens.Consume(ctx, storefix.RaceToken(0x50002).ID, now))
			started()
			return counted.tokens.Consume(ctx, storefix.RaceToken(0x50002).ID, now)
		}, assert: refused(onetime.ErrTokenNotFound, `UPDATE "one_time_tokens" SET "consumed_at"=$1 WHERE id = $2 AND consumed_at IS NULL`)},
		{name: "one-time count", run: with(func(ctx context.Context, s storeSet) error {
			return ignoring(s.tokens.CountRecentBySubject(ctx, "p", "stmt-subject", now))
		}), assert: one(`SELECT count(*) FROM "one_time_tokens" WHERE purpose = $1 AND subject = $2 AND issued_at >= $3`)},
		{name: "one-time purge", run: with(func(ctx context.Context, s storeSet) error {
			return ignoring(s.tokens.DeleteExpiredBefore(ctx, "p", now))
		}), assert: one(`DELETE FROM "one_time_tokens" WHERE purpose = $1 AND expires_at <= $2 AND issued_at < $3`)},

		{name: "attempt record", run: with(func(ctx context.Context, s storeSet) error {
			return s.attempts.RecordFailure(ctx, "stmt-user", now)
		}), assert: one(`INSERT INTO "login_attempts" ("id","username","attempted_at") VALUES ($1,$2,$3)`)},
		{name: "attempt count", run: with(func(ctx context.Context, s storeSet) error {
			return ignoring(s.attempts.FailureCount(ctx, "stmt-user", now.Add(-time.Hour)))
		}), assert: one(`SELECT count(*) FROM "login_attempts" WHERE username = $1 AND attempted_at > $2`)},
		{name: "attempt reset", run: with(func(ctx context.Context, s storeSet) error {
			return s.attempts.Reset(ctx, "stmt-user")
		}), assert: one(`DELETE FROM "login_attempts" WHERE username = $1`)},
		{name: "attempt purge", run: with(func(ctx context.Context, s storeSet) error {
			return ignoring(s.attempts.DeleteAttemptsBefore(ctx, now.Add(-time.Hour)))
		}), assert: one(`DELETE FROM "login_attempts" WHERE attempted_at < $1`)},

		{name: "signing key store", run: with(func(ctx context.Context, s storeSet) error {
			return s.keys.Store(ctx, storefix.SigningKey("stmt-kid", []byte("PKCS8")))
		}), assert: one(`INSERT INTO "signing_keys" ("id","kid","alg","private_key","public_jwk","created_at") VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT ("kid") DO UPDATE SET "alg"="excluded"."alg","private_key"="excluded"."private_key","public_jwk"="excluded"."public_jwk","created_at"="excluded"."created_at"`)},
		{name: "signing key store replacing a kid", run: func(ctx context.Context, t *testing.T, seed, counted storeSet, started func()) error {
			require.NoError(t, seed.keys.Store(ctx, storefix.SigningKey("stmt-kid-replaced", []byte("PKCS8-OLD"))))
			started()
			return counted.keys.Store(ctx, storefix.SigningKey("stmt-kid-replaced", []byte("PKCS8-NEW")))
		}, assert: one(`INSERT INTO "signing_keys" ("id","kid","alg","private_key","public_jwk","created_at") VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT ("kid") DO UPDATE SET "alg"="excluded"."alg","private_key"="excluded"."private_key","public_jwk"="excluded"."public_jwk","created_at"="excluded"."created_at"`)},
		{name: "signing key load", run: with(func(ctx context.Context, s storeSet) error {
			return ignoring(s.keys.LoadAll(ctx))
		}), assert: one(`SELECT * FROM "signing_keys" ORDER BY created_at, kid`)},

		{name: "signing key load re-sealing two keys sealed under a retired key: the read, then one conditional update per key", run: func(ctx context.Context, t *testing.T, _, counted storeSet, started func()) error {
			retired := newSigningKeyStore(t, d.db, keys.UnderK1(t))
			require.NoError(t, retired.Store(ctx, storefix.SigningKey("stmt-kid-reseal-1", []byte("PKCS8-1"))))
			require.NoError(t, retired.Store(ctx, storefix.SigningKey("stmt-kid-reseal-2", []byte("PKCS8-2"))))
			started()
			return ignoring(counted.keys.LoadAll(ctx))
		}, assert: statements(nil,
			`SELECT * FROM "signing_keys" ORDER BY created_at, kid`,
			`UPDATE "signing_keys" SET "private_key"=$1 WHERE kid = $2 AND private_key = $3`,
			`UPDATE "signing_keys" SET "private_key"=$1 WHERE kid = $2 AND private_key = $3`)},

		{name: "MFA begin", run: with(func(ctx context.Context, s storeSet) error {
			return s.enrolments.PutPending(ctx, storefix.Pending("stmt-mfa-begin", "TOTP"))
		}), assert: one(`INSERT INTO "mfa_enrolments" ("id","user_id","secret","confirmed_at","last_step","created_at","generation","device_proven_at","email_code","email_code_until","email_code_attempts","verify_attempts","verify_window_until") VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) ON CONFLICT ("user_id") DO UPDATE SET "secret"="excluded"."secret","created_at"="excluded"."created_at","generation"="excluded"."generation","last_step"=$14,"device_proven_at"=$15,"email_code"=$16,"email_code_until"=$17,"email_code_attempts"=$18,"verify_attempts"=$19,"verify_window_until"=$20 WHERE mfa_enrolments.confirmed_at IS NULL`)},
		{name: "MFA begin over a confirmed enrolment", run: func(ctx context.Context, t *testing.T, seed, counted storeSet, started func()) error {
			require.NoError(t, seed.enrolments.PutPending(ctx, storefix.Pending("stmt-mfa-confirmed", "TOTP")))
			require.NoError(t, flag(seed.enrolments.Confirm(ctx, "stmt-mfa-confirmed", 1000, now)))
			started()
			return counted.enrolments.PutPending(ctx, storefix.Pending("stmt-mfa-confirmed", "TOTP-OTHER"))
		}, assert: refused(mfa.ErrAlreadyEnrolled, `INSERT INTO "mfa_enrolments" ("id","user_id","secret","confirmed_at","last_step","created_at","generation","device_proven_at","email_code","email_code_until","email_code_attempts","verify_attempts","verify_window_until") VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) ON CONFLICT ("user_id") DO UPDATE SET "secret"="excluded"."secret","created_at"="excluded"."created_at","generation"="excluded"."generation","last_step"=$14,"device_proven_at"=$15,"email_code"=$16,"email_code_until"=$17,"email_code_attempts"=$18,"verify_attempts"=$19,"verify_window_until"=$20 WHERE mfa_enrolments.confirmed_at IS NULL`)},
		{name: "MFA get", run: func(ctx context.Context, t *testing.T, seed, counted storeSet, started func()) error {
			require.NoError(t, seed.enrolments.PutPending(ctx, storefix.Pending("stmt-mfa-get", "TOTP")))
			started()
			return flag(ignoringTwo(counted.enrolments.Get(ctx, "stmt-mfa-get")))
		}, assert: one(`SELECT * FROM "mfa_enrolments" WHERE user_id = $1 LIMIT $2`)},
		{name: "MFA confirm", run: func(ctx context.Context, t *testing.T, seed, counted storeSet, started func()) error {
			require.NoError(t, seed.enrolments.PutPending(ctx, storefix.Pending("stmt-mfa-confirm", "TOTP")))
			started()
			return flag(counted.enrolments.Confirm(ctx, "stmt-mfa-confirm", 1000, now))
		}, assert: one(`UPDATE "mfa_enrolments" SET "confirmed_at"=$1,"email_code"=$2,"last_step"=GREATEST(last_step, $3) WHERE user_id = $4 AND confirmed_at IS NULL`)},
		{name: "MFA accept step", run: func(ctx context.Context, t *testing.T, seed, counted storeSet, started func()) error {
			require.NoError(t, seed.enrolments.PutPending(ctx, storefix.Pending("stmt-mfa-step", "TOTP")))
			require.NoError(t, flag(seed.enrolments.Confirm(ctx, "stmt-mfa-step", 1000, now)))
			started()
			return flag(counted.enrolments.AcceptStep(ctx, "stmt-mfa-step", 1001))
		}, assert: one(`UPDATE "mfa_enrolments" SET "last_step"=$1 WHERE user_id = $2 AND confirmed_at IS NOT NULL AND last_step < $3`)},
		{name: "MFA accept of a step already accepted", run: func(ctx context.Context, t *testing.T, seed, counted storeSet, started func()) error {
			require.NoError(t, seed.enrolments.PutPending(ctx, storefix.Pending("stmt-mfa-stale", "TOTP")))
			require.NoError(t, flag(seed.enrolments.Confirm(ctx, "stmt-mfa-stale", 1000, now)))
			started()
			return flag(counted.enrolments.AcceptStep(ctx, "stmt-mfa-stale", 1000))
		}, assert: refused(errNotStored, `UPDATE "mfa_enrolments" SET "last_step"=$1 WHERE user_id = $2 AND confirmed_at IS NOT NULL AND last_step < $3`)},
		{name: "MFA device proof", run: func(ctx context.Context, t *testing.T, seed, counted storeSet, started func()) error {
			gen := begunOn(ctx, t, seed, "stmt-mfa-prove")
			started()
			return flag(proofs(t, counted).ProveDevice(ctx, "stmt-mfa-prove", gen, 1000, []byte("314159"), now.Add(10*time.Minute), now))
		}, assert: one(proveStmt)},
		{name: "MFA device proof on another generation", run: func(ctx context.Context, t *testing.T, seed, counted storeSet, started func()) error {
			begunOn(ctx, t, seed, "stmt-mfa-prove-stale")
			started()
			return flag(proofs(t, counted).ProveDevice(ctx, "stmt-mfa-prove-stale", id.MustParse("01926a4e-0000-7000-8000-0000000000ff"), 1000, nil, time.Time{}, now))
		}, assert: refused(errNotStored, proveStmt)},
		{name: "MFA completion", run: func(ctx context.Context, t *testing.T, seed, counted storeSet, started func()) error {
			gen := provenOn(ctx, t, seed, "stmt-mfa-complete", now)
			started()
			return flag(proofs(t, counted).Complete(ctx, "stmt-mfa-complete", gen, now))
		}, assert: one(`UPDATE "mfa_enrolments" SET "confirmed_at"=$1,"email_code"=$2 WHERE user_id = $3 AND generation = $4 AND device_proven_at IS NOT NULL AND confirmed_at IS NULL`)},
		{name: "MFA charge", run: func(ctx context.Context, t *testing.T, seed, counted storeSet, started func()) error {
			gen := provenOn(ctx, t, seed, "stmt-mfa-charge", now)
			started()
			_, ok, err := proofs(t, counted).ChargeEmailCode(ctx, "stmt-mfa-charge", gen, now)
			return flag(ok, err)
		}, assert: one(chargeStmt)},
		{name: "MFA charge with no code outstanding", run: func(ctx context.Context, t *testing.T, seed, counted storeSet, started func()) error {
			gen := begunOn(ctx, t, seed, "stmt-mfa-charge-none")
			started()
			_, ok, err := proofs(t, counted).ChargeEmailCode(ctx, "stmt-mfa-charge-none", gen, now)
			return flag(ok, err)
		}, assert: refused(errNotStored, chargeStmt)},
		{name: "MFA verification charge", run: func(ctx context.Context, t *testing.T, seed, counted storeSet, started func()) error {
			require.NoError(t, seed.enrolments.PutPending(ctx, storefix.Pending("stmt-mfa-vcharge", "TOTP")))
			require.NoError(t, flag(seed.enrolments.Confirm(ctx, "stmt-mfa-vcharge", 1000, now)))
			started()
			_, ok, err := counted.enrolments.ChargeVerifyAttempt(ctx, "stmt-mfa-vcharge", now, 5, 15*time.Minute)
			return flag(ok, err)
		}, assert: one(verifyChargeStmt)},
		{name: "MFA verification charge against a pending enrolment", run: func(ctx context.Context, t *testing.T, seed, counted storeSet, started func()) error {
			require.NoError(t, seed.enrolments.PutPending(ctx, storefix.Pending("stmt-mfa-vcharge-pending", "TOTP")))
			started()
			_, ok, err := counted.enrolments.ChargeVerifyAttempt(ctx, "stmt-mfa-vcharge-pending", now, 5, 15*time.Minute)
			return flag(ok, err)
		}, assert: refused(errNotStored, verifyChargeStmt)},
		{name: "MFA verification give-back", run: func(ctx context.Context, t *testing.T, seed, counted storeSet, started func()) error {
			require.NoError(t, seed.enrolments.PutPending(ctx, storefix.Pending("stmt-mfa-vrefund", "TOTP")))
			require.NoError(t, flag(seed.enrolments.Confirm(ctx, "stmt-mfa-vrefund", 1000, now)))
			until, _, err := seed.enrolments.ChargeVerifyAttempt(ctx, "stmt-mfa-vrefund", now, 5, 15*time.Minute)
			require.NoError(t, err)
			started()
			return flag(counted.enrolments.RefundVerifyAttempt(ctx, "stmt-mfa-vrefund", until))
		}, assert: one(verifyRefundStmt)},
		{name: "MFA delete", run: with(func(ctx context.Context, s storeSet) error {
			return s.enrolments.Delete(ctx, "stmt-mfa-delete")
		}), assert: one(`DELETE FROM "mfa_enrolments" WHERE user_id = $1`)},
		{name: "MFA get re-sealing a secret sealed under a retired key: the read, then one conditional update", run: func(ctx context.Context, t *testing.T, _, counted storeSet, started func()) error {
			require.NoError(t, newEnrolmentStore(t, d.db, keys.UnderK1(t)).PutPending(ctx, storefix.Pending("stmt-mfa-reseal", "TOTP")))
			started()
			return flag(ignoringTwo(counted.enrolments.Get(ctx, "stmt-mfa-reseal")))
		}, assert: statements(nil, `SELECT * FROM "mfa_enrolments" WHERE user_id = $1 LIMIT $2`, `UPDATE "mfa_enrolments" SET "secret"=$1 WHERE user_id = $2 AND secret = $3`)},

		{name: "API key put", run: with(func(ctx context.Context, s storeSet) error {
			return s.apiKeys.Put(ctx, storefix.APIKey(0x500, "stmt-svc"))
		}), assert: one(`INSERT INTO "api_keys" ("id","user_id","name","scopes","secret_digest","expires_at","revoked_at","last_used_at","created_at") VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`)},
		{name: "API key get", run: with(func(ctx context.Context, s storeSet) error {
			return ignoring(s.apiKeys.Get(ctx, storefix.APIKey(0x501, "").ID))
		}), assert: refused(apikey.ErrKeyNotFound, `SELECT * FROM "api_keys" WHERE id = $1 LIMIT $2`)},
		{name: "API key revoke", run: func(ctx context.Context, t *testing.T, seed, counted storeSet, started func()) error {
			require.NoError(t, seed.apiKeys.Put(ctx, storefix.APIKey(0x502, "stmt-svc")))
			started()
			return counted.apiKeys.Revoke(ctx, storefix.APIKey(0x502, "").ID, now)
		}, assert: one(`UPDATE "api_keys" SET "revoked_at"=COALESCE(revoked_at, $1) WHERE id = $2`)},
		{name: "API key revoke of an unknown key", run: with(func(ctx context.Context, s storeSet) error {
			return s.apiKeys.Revoke(ctx, storefix.APIKey(0x503, "").ID, now)
		}), assert: refused(apikey.ErrKeyNotFound, `UPDATE "api_keys" SET "revoked_at"=COALESCE(revoked_at, $1) WHERE id = $2`)},
		{name: "API key touch", run: with(func(ctx context.Context, s storeSet) error {
			return s.apiKeys.TouchLastUsed(ctx, storefix.APIKey(0x504, "").ID, now)
		}), assert: refused(apikey.ErrKeyNotFound, `UPDATE "api_keys" SET "last_used_at"=$1 WHERE id = $2`)},
		{name: "API key list", run: with(func(ctx context.Context, s storeSet) error {
			return ignoring(s.apiKeys.List(ctx, "stmt-svc"))
		}), assert: one(`SELECT * FROM "api_keys" WHERE user_id = $1 ORDER BY created_at, id`)},

		{name: "link insert", run: func(ctx context.Context, t *testing.T, _, counted storeSet, started func()) error {
			l := storefix.Link(t, "corp", "https://stmt.example", "s-insert", "stmt-user")
			started()
			return counted.links.Insert(ctx, l)
		}, assert: one(`INSERT INTO "oidc_links" ("id","provider","issuer","subject","user_id","username","email","created_at") VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT ("provider","issuer","subject") DO NOTHING`)},
		{name: "link insert of a linked identity", run: func(ctx context.Context, t *testing.T, seed, counted storeSet, started func()) error {
			require.NoError(t, seed.links.Insert(ctx, storefix.Link(t, "corp", "https://stmt.example", "s-dup", "u1")))
			started()
			return counted.links.Insert(ctx, storefix.Link(t, "corp", "https://stmt.example", "s-dup", "u2"))
		}, assert: refused(oidc.ErrLinkExists, `INSERT INTO "oidc_links" ("id","provider","issuer","subject","user_id","username","email","created_at") VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT ("provider","issuer","subject") DO NOTHING`)},
		{name: "link find", run: with(func(ctx context.Context, s storeSet) error {
			return ignoring(s.links.FindByExternal(ctx, "corp", "https://stmt.example", "s-missing"))
		}), assert: refused(oidc.ErrLinkNotFound, `SELECT * FROM "oidc_links" WHERE provider = $1 AND issuer = $2 AND subject = $3 LIMIT $4`)},
		{name: "link delete by user", run: with(func(ctx context.Context, s storeSet) error {
			return ignoring(s.links.DeleteByUser(ctx, "stmt-user"))
		}), assert: one(`DELETE FROM "oidc_links" WHERE user_id = $1 AND user_id <> ''`)},

		{name: "flow begin", run: with(func(ctx context.Context, s storeSet) error {
			return ignoring(s.flows.Begin(ctx, storefix.Flow("p1", "stmt-state-begin")))
		}), assert: one(`INSERT INTO "oidc_flows" ("id","handle","provider","state","nonce","verifier","next","expires_at","completed_at") VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`)},
		{name: "flow complete", run: func(ctx context.Context, t *testing.T, seed, counted storeSet, started func()) error {
			h, err := seed.flows.Begin(ctx, storefix.Flow("p1", "stmt-state-complete"))
			require.NoError(t, err)
			started()
			return ignoring(counted.flows.Complete(ctx, h, "p1", "stmt-state-complete"))
		}, assert: one(`UPDATE oidc_flows SET completed_at = $4 WHERE handle = $1 AND provider = $2 AND state = $3 AND $3 <> '' AND completed_at IS NULL AND expires_at > $4 RETURNING provider, state, nonce, verifier, next, expires_at`)},
		{name: "flow complete refused", run: with(func(ctx context.Context, s storeSet) error {
			return ignoring(s.flows.Complete(ctx, "stmt-no-such-handle", "p1", "s"))
		}), assert: refused(oidc.ErrInvalidState, `UPDATE oidc_flows SET completed_at = $4 WHERE handle = $1 AND provider = $2 AND state = $3 AND $3 <> '' AND completed_at IS NULL AND expires_at > $4 RETURNING provider, state, nonce, verifier, next, expires_at`)},
		{name: "flow purge", run: with(func(ctx context.Context, s storeSet) error {
			return ignoring(s.flows.DeleteExpired(ctx, storefix.OIDCStart))
		}), assert: one(`DELETE FROM "oidc_flows" WHERE expires_at < $1`)},

		{name: "handoff insert", run: func(ctx context.Context, t *testing.T, _, counted storeSet, started func()) error {
			rec := storefix.Handoff(t, "stmt-token-insert")
			started()
			return counted.handoffs.Insert(ctx, rec)
		}, assert: one(`INSERT INTO "oidc_handoffs" ("id","token_id","secret_hash","user_id","provider","issuer","session_id","id_token","next","expires_at","created_at","consumed_at","amr","acr") VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`)},
		{name: "handoff find", run: with(func(ctx context.Context, s storeSet) error {
			return ignoring(s.handoffs.FindByTokenID(ctx, "stmt-token-missing"))
		}), assert: refused(oidc.ErrHandoffNotFound, `SELECT * FROM "oidc_handoffs" WHERE token_id = $1 AND token_id <> '' LIMIT $2`)},
		{name: "handoff consume", run: func(ctx context.Context, t *testing.T, seed, counted storeSet, started func()) error {
			require.NoError(t, seed.handoffs.Insert(ctx, storefix.Handoff(t, "stmt-token-consume")))
			started()
			return counted.handoffs.Consume(ctx, "stmt-token-consume", now)
		}, assert: one(`UPDATE "oidc_handoffs" SET "consumed_at"=$1 WHERE token_id = $2 AND token_id <> '' AND consumed_at IS NULL`)},
		{name: "handoff consume refused", run: with(func(ctx context.Context, s storeSet) error {
			return s.handoffs.Consume(ctx, "stmt-token-missing", now)
		}), assert: refused(oidc.ErrHandoffNotFound, `UPDATE "oidc_handoffs" SET "consumed_at"=$1 WHERE token_id = $2 AND token_id <> '' AND consumed_at IS NULL`)},
		{name: "handoff purge", run: with(func(ctx context.Context, s storeSet) error {
			return ignoring(s.handoffs.DeleteExpired(ctx, storefix.OIDCStart))
		}), assert: one(`DELETE FROM "oidc_handoffs" WHERE expires_at < $1`)},
	}

	// The cases share one recording pool, so they run one after another.
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			pool.take()
			err := tc.run(ctx, t, seed, counted, func() { pool.take() })
			tc.assert(t, err, pool.take())
		})
	}

	t.Run("the recorder sees what reaches the pool", func(t *testing.T) {
		pool.take()
		require.NoError(t, recorded.WithContext(t.Context()).Transaction(func(tx *gormdb.DB) error {
			return tx.Exec("SELECT 1").Error
		}))
		assert.Equal(t, []string{"BEGIN"}, normalized(pool.take()),
			"statements inside a transaction run on it, so the pool sees only its BEGIN")
		require.NoError(t, recorded.WithContext(t.Context()).Exec("SELECT 1").Error)
		assert.Equal(t, []string{"SELECT 1"}, normalized(pool.take()))
	})
}

// The enrolment path's conditional writes, as the device-proof rows pin them.
const (
	proveStmt  = `UPDATE "mfa_enrolments" SET "device_proven_at"=$1,"email_code"=$2,"email_code_attempts"=$3,"email_code_until"=$4,"last_step"=$5 WHERE user_id = $6 AND generation = $7 AND confirmed_at IS NULL AND device_proven_at IS NULL AND last_step < $8`
	chargeStmt = `UPDATE "mfa_enrolments" SET "email_code_attempts"=email_code_attempts + 1 WHERE user_id = $1 AND generation = $2 AND confirmed_at IS NULL AND device_proven_at IS NOT NULL AND email_code IS NOT NULL AND email_code_until > $3 AND email_code_attempts < $4 RETURNING "email_code_attempts"`

	// The TOTP verification statements run verbatim from the shared schema
	// statements, so they are pinned as written there.
	verifyChargeStmt = `UPDATE mfa_enrolments SET verify_attempts = CASE WHEN verify_window_until IS NULL OR verify_window_until <= $2 THEN 1 ELSE verify_attempts + 1 END, verify_window_until = CASE WHEN verify_window_until IS NULL OR verify_window_until <= $2 THEN $3 ELSE verify_window_until END WHERE user_id = $1 AND confirmed_at IS NOT NULL AND (verify_window_until IS NULL OR verify_window_until <= $2 OR verify_attempts < $4) RETURNING verify_window_until`
	verifyRefundStmt = `UPDATE mfa_enrolments SET verify_attempts = verify_attempts - 1 WHERE user_id = $1 AND verify_window_until = $2 AND verify_attempts > 0`
)

// proofs is s's enrolment store as the enrolment path's port.
func proofs(t *testing.T, s storeSet) mfa.DeviceProofStore {
	t.Helper()

	return storetest.RequireDeviceProof(t, s.enrolments)
}

// begunOn begins user's enrolment through s on a generation of its own, and
// returns the generation.
func begunOn(ctx context.Context, t *testing.T, s storeSet, user identity.UserID) id.ID {
	t.Helper()

	gen, err := id.NewV7Generator().NewID()
	require.NoError(t, err)
	e := storefix.Pending(user, "TOTP")
	e.Generation = gen
	require.NoError(t, s.enrolments.PutPending(ctx, e))

	return gen
}

// provenOn is begunOn followed by a device proof at now, with an emailed code
// good for ten minutes.
func provenOn(ctx context.Context, t *testing.T, s storeSet, user identity.UserID, now time.Time) id.ID {
	t.Helper()

	gen := begunOn(ctx, t, s, user)
	ok, err := proofs(t, s).ProveDevice(ctx, user, gen, 1000, []byte("314159"), now.Add(10*time.Minute), now)
	require.NoError(t, err)
	require.True(t, ok)

	return gen
}

// ignoringTwo drops the enrolment Get returns beside its found flag.
func ignoringTwo(_ mfa.Enrolment, ok bool, err error) (bool, error) { return ok, err }

// normalized is each statement with every run of whitespace collapsed to one
// space, and no leading or trailing space.
func normalized(stmts []string) []string {
	out := make([]string, len(stmts))
	for i, stmt := range stmts {
		out[i] = strings.Join(strings.Fields(stmt), " ")
	}
	return out
}
