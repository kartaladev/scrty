package pgxstore_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/onetime"
	pgxstore "github.com/kartaladev/scrty/pgx"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/seal"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/signingkey"
	"github.com/kartaladev/scrty/test/storetest"
)

// brokenVar names the environment variable that selects the one broken
// variant the child test runs, so each suite's verdict is attributable to
// that variant alone.
const brokenVar = "PGXSTORE_BROKEN"

// brokenVariant is a durable store carrying one deliberate defect, the run
// that must fail, and the case of it that must catch the defect.
type brokenVariant struct {
	name      string
	run       func(t *testing.T)
	failsCase string
	// failsWith, when set, is text the child's output must carry.
	failsWith string
}

// brokenVariants are the defects the pgx runs must catch. None of them is
// exported from the pgx module: each is built here, over the exported store
// or through the pool.
var brokenVariants = []brokenVariant{
	{
		name: "session-save-upserts",
		run: func(t *testing.T) {
			db := migrated(t)
			c := testCipher(t)
			t.Run("pgx", func(t *testing.T) {
				storetest.RunSessionStoreSuite(t, func(t *testing.T, now func() time.Time) session.Store {
					return saveUpsertsStore{newSessionStore(t, emptied(t, db, "sessions"), c, pgxstore.WithClock(now))}
				})
			})
		},
		failsCase: "saving a deleted session is not found and does not bring it back",
	},
	{
		name: "onetime-read-then-write-consume",
		run: func(t *testing.T) {
			h := durableHarness(migrated(t),
				func(t *testing.T, pool *pgxpool.Pool, opts ...pgxstore.Option) readThenWriteConsume {
					return readThenWriteConsume{OneTimeStore: newOneTimeStore(t, pool, opts...), pool: pool}
				})
			t.Run("pgx", func(t *testing.T) {
				storetest.RunConsumeRace(t, h, consumeRace[readThenWriteConsume]())
			})
		},
		failsCase: "exactly one consumption wins per record",
		failsWith: "more than one successful consumption",
	},
	{
		name: "signingkey-identity-cipher",
		run: func(t *testing.T) {
			db := migrated(t)
			h := durableHarness(db, func(t *testing.T, pool *pgxpool.Pool, opts ...pgxstore.Option) signingkey.KeyStore {
				return newSigningKeyStore(t, pool, identityCipher{}, opts...)
			})
			t.Run("pgx", func(t *testing.T) {
				// The keyring the suite hands over is ignored: every store
				// "seals" through the identity cipher.
				storetest.RunSealedColumns(t, h, sealedSigningKeys(db,
					func(t *testing.T, pool *pgxpool.Pool, _ seal.Cipher) signingkey.KeyStore {
						return newSigningKeyStore(t, pool, identityCipher{})
					}))
			})
		},
		failsCase: "the stored value, decoded, does not hold the plaintext",
		failsWith: "the column holds the plaintext",
	},
	{
		name: "mfa-identity-cipher",
		run: func(t *testing.T) {
			db := migrated(t)
			h := durableHarness(db, func(t *testing.T, pool *pgxpool.Pool, opts ...pgxstore.Option) mfa.EnrolmentStore {
				return newEnrolmentStore(t, pool, identityCipher{}, opts...)
			})
			t.Run("pgx", func(t *testing.T) {
				storetest.RunSealedColumns(t, h, sealedEnrolments(db,
					func(t *testing.T, pool *pgxpool.Pool, _ seal.Cipher) mfa.EnrolmentStore {
						return newEnrolmentStore(t, pool, identityCipher{})
					}))
			})
		},
		failsCase: "the stored value, decoded, does not hold the plaintext",
		failsWith: "the decoded column holds the plaintext",
	},
	{
		name: "signingkey-missing-aad-cipher",
		run: func(t *testing.T) {
			db := migrated(t)
			c := missingAADCipher{testCipher(t)}
			h := durableHarness(db, func(t *testing.T, pool *pgxpool.Pool, opts ...pgxstore.Option) signingkey.KeyStore {
				return newSigningKeyStore(t, pool, c, opts...)
			})
			t.Run("pgx", func(t *testing.T) {
				storetest.RunSealedColumns(t, h, sealedSigningKeys(db,
					func(t *testing.T, pool *pgxpool.Pool, c seal.Cipher) signingkey.KeyStore {
						return newSigningKeyStore(t, pool, missingAADCipher{c})
					}))
			})
		},
		failsCase: "a sealed value copied to another record does not open there",
	},
	{
		name: "mfa-missing-aad-cipher",
		run: func(t *testing.T) {
			db := migrated(t)
			c := missingAADCipher{testCipher(t)}
			h := durableHarness(db, func(t *testing.T, pool *pgxpool.Pool, opts ...pgxstore.Option) mfa.EnrolmentStore {
				return newEnrolmentStore(t, pool, c, opts...)
			})
			t.Run("pgx", func(t *testing.T) {
				// Every store the suite builds seals through the default
				// cipher over the suite's keyring, with the AAD dropped.
				storetest.RunSealedColumns(t, h, sealedEnrolments(db,
					func(t *testing.T, pool *pgxpool.Pool, c seal.Cipher) mfa.EnrolmentStore {
						return newEnrolmentStore(t, pool, missingAADCipher{c})
					}))
			})
		},
		failsCase: "a sealed value copied to another record does not open there",
	},
	{
		name: "mfa-read-then-write-accept-step",
		run: func(t *testing.T) {
			c := testCipher(t)
			h := durableHarness(migrated(t),
				func(t *testing.T, pool *pgxpool.Pool, opts ...pgxstore.Option) readThenWriteAcceptStep {
					return readThenWriteAcceptStep{EnrolmentStore: newEnrolmentStore(t, pool, c, opts...), pool: pool}
				})
			t.Run("pgx", func(t *testing.T) {
				storetest.RunStepAcceptRace(t, h, stepRace[readThenWriteAcceptStep]())
			})
		},
		failsCase: "exactly one acceptance of a step wins per record",
		failsWith: "more than one successful acceptance of a step",
	},
	{
		name: "link-upsert-insert",
		run: func(t *testing.T) {
			h := durableHarness(migrated(t), func(t *testing.T, pool *pgxpool.Pool, opts ...pgxstore.Option) upsertLinkInsert {
				return upsertLinkInsert{LinkStore: newLinkStore(t, pool, opts...), pool: pool}
			})
			t.Run("pgx", func(t *testing.T) {
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
			h := durableHarness(migrated(t), func(t *testing.T, pool *pgxpool.Pool, _ ...pgxstore.Option) session.Store {
				return newSessionStore(t, pool, c, pgxstore.WithTxResolver(noTransaction))
			})
			t.Run("pgx", func(t *testing.T) { storetest.RunAmbientTx(t, h, sessionAmbient()) })
		},
		failsCase: "a write inside a rolled back transaction is discarded",
		failsWith: "the store did not write in it",
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

// saveUpsertsStore creates a session its Save does not find, so a save racing
// a logout writes the revoked session back.
type saveUpsertsStore struct{ session.Store }

func (s saveUpsertsStore) Save(ctx context.Context, sess *session.Session) error {
	err := s.Store.Save(ctx, sess)
	if errors.Is(err, session.ErrSessionNotFound) {
		return s.Create(ctx, sess)
	}
	return err
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
	name, named := os.LookupEnv(brokenVar)
	if !named {
		t.Skipf("no variant named in %s; run through TestSuitesCatchBrokenPgxStores", brokenVar)
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

// failedCase matches a failed case of the child's pgx run.
var failedCase = regexp.MustCompile(`--- FAIL: TestBrokenPgxStore/pgx/(\S+)`)

// TestSuitesCatchBrokenPgxStores checks that the suites the pgx runs use fail
// against each broken variant, at the case guarding its defect. Each variant
// runs in its own process, because a failing suite reports through its own
// *testing.T and would fail this test with it.
func TestSuitesCatchBrokenPgxStores(t *testing.T) {
	t.Parallel()

	for _, v := range brokenVariants {
		t.Run(v.name, func(t *testing.T) {
			t.Parallel()

			//nolint:gosec // G204: this test binary re-executed with fixed arguments
			cmd := exec.CommandContext(t.Context(), os.Args[0],
				"-test.run=^TestBrokenPgxStore$", "-test.count=1", "-test.v", "-test.timeout=5m")
			cmd.Env = append(os.Environ(), brokenVar+"="+v.name)
			out, err := cmd.CombinedOutput()
			output := string(out)

			// The child names its variant, so it skips only when
			// RunTestPostgres does: Docker is unavailable outside CI.
			if strings.Contains(output, "--- SKIP: TestBrokenPgxStore") {
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
