package test_test

import (
	"database/sql"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	gormdb "gorm.io/gorm"

	"github.com/kartaladev/scrty/apikey"
	"github.com/kartaladev/scrty/expiry"
	gormstore "github.com/kartaladev/scrty/gorm"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/migrate"
	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/onetime"
	"github.com/kartaladev/scrty/pgx"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/seal"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/signingkey"
	"github.com/kartaladev/scrty/sqlstore"
	"github.com/kartaladev/scrty/test"
	"github.com/kartaladev/scrty/test/internal/storefix"
)

// expiryStores is every store an expiry sweep touches or must leave alone, as
// one adapter builds them over a single database.
type expiryStores struct {
	sessions   session.Store
	oneTime    onetime.Store
	attempts   policy.AttemptStore
	apiKeys    apikey.Store
	links      oidc.LinkStore
	enrolments mfa.EnrolmentStore
	signing    signingkey.KeyStore
}

const (
	tokenPurpose  = "expiry-tasks" //nolint:gosec // a purpose label, not a credential
	tokenSubject  = "token-subject"
	failedAccount = "alice"
	// lockoutWindow is the sliding lock's window, which is also how far back the
	// attempt purge keeps failures.
	lockoutWindow = 15 * time.Minute
)

// mustStore returns the store a constructor built. A constructor refusing a
// configuration this file wrote itself is a wiring mistake in the test, so it
// panics, which the testing package reports as a failure of the running case.
func mustStore[S any](s S, err error) S {
	if err != nil {
		panic(err)
	}

	return s
}

// expiryAdapters builds each adapter's stores over one migrated database, and
// returns the database's plain handle for counting rows out of band.
var expiryAdapters = []struct {
	name string
	open func(t *testing.T, conn test.PostgresConn, c seal.Cipher, clk clock.Clock) expiryStores
}{
	{
		name: "sqlstore",
		open: func(_ *testing.T, conn test.PostgresConn, c seal.Cipher, clk clock.Clock) expiryStores {
			db := conn.DB
			return expiryStores{
				sessions: mustStore(sqlstore.NewSessionStore(db, c, sqlstore.WithClock(clk))),
				oneTime:  mustStore(sqlstore.NewOneTimeStore(db, sqlstore.WithClock(clk))),
				attempts: mustStore(sqlstore.NewAttemptStore(db)),
				apiKeys:  mustStore(sqlstore.NewAPIKeyStore(db)),
				links:    mustStore(sqlstore.NewLinkStore(db)),
				enrolments: mustStore(
					sqlstore.NewEnrolmentStore(db, c, sqlstore.WithClock(clk))),
				signing: mustStore(sqlstore.NewSigningKeyStore(db, c)),
			}
		},
	},
	{
		name: "pgx",
		open: func(t *testing.T, conn test.PostgresConn, c seal.Cipher, clk clock.Clock) expiryStores {
			cfg, err := pgxpool.ParseConfig(conn.DSN)
			require.NoError(t, err)
			pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
			require.NoError(t, err)
			t.Cleanup(pool.Close)

			return expiryStores{
				sessions: mustStore(pgx.NewSessionStore(pool, c, pgx.WithClock(clk))),
				oneTime:  mustStore(pgx.NewOneTimeStore(pool, pgx.WithClock(clk))),
				attempts: mustStore(pgx.NewAttemptStore(pool)),
				apiKeys:  mustStore(pgx.NewAPIKeyStore(pool)),
				links:    mustStore(pgx.NewLinkStore(pool)),
				enrolments: mustStore(
					pgx.NewEnrolmentStore(pool, c, pgx.WithClock(clk))),
				signing: mustStore(pgx.NewSigningKeyStore(pool, c)),
			}
		},
	},
	{
		name: "gorm",
		open: func(t *testing.T, conn test.PostgresConn, c seal.Cipher, clk clock.Clock) expiryStores {
			db, err := gormdb.Open(postgres.Open(conn.DSN), &gormdb.Config{DisableAutomaticPing: true})
			require.NoError(t, err)
			sqlDB, err := db.DB()
			require.NoError(t, err)
			t.Cleanup(func() { _ = sqlDB.Close() })

			return expiryStores{
				sessions: mustStore(gormstore.NewSessionStore(db, c, gormstore.WithClock(clk))),
				oneTime:  mustStore(gormstore.NewOneTimeStore(db, gormstore.WithClock(clk))),
				attempts: mustStore(gormstore.NewAttemptStore(db)),
				apiKeys:  mustStore(gormstore.NewAPIKeyStore(db)),
				links:    mustStore(gormstore.NewLinkStore(db)),
				enrolments: mustStore(
					gormstore.NewEnrolmentStore(db, c, gormstore.WithClock(clk))),
				signing: mustStore(gormstore.NewSigningKeyStore(db, c)),
			}
		},
	},
}

// countRows counts the rows of table matching where, over the plain handle.
// table and where are this file's own constants, never input.
func countRows(t *testing.T, db *sql.DB, table, where string) int {
	t.Helper()

	q := "SELECT count(*) FROM " + table
	if where != "" {
		q += " WHERE " + where
	}

	var n int
	require.NoError(t, db.QueryRowContext(t.Context(), q).Scan(&n))

	return n
}

// TestExpiryTasks runs the built-in expiry tasks through a runner over every
// durable adapter on PostgreSQL. Each case seeds expired and live state of the
// swept kinds plus state of the kinds a sweep must never touch, runs the tasks
// once, and counts what is left in the tables.
func TestExpiryTasks(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// open builds one adapter's stores over conn.
		open   func(t *testing.T, conn test.PostgresConn, c seal.Cipher, clk clock.Clock) expiryStores
		assert func(t *testing.T, db *sql.DB, st expiryStores, mgr *onetime.Manager, report expiry.Report, issuedBefore int)
	}

	assertSwept := func(t *testing.T, db *sql.DB, st expiryStores, mgr *onetime.Manager, report expiry.Report, issuedBefore int) {
		t.Helper()

		// Every task ran, in the order declared, and reported what it removed.
		require.Len(t, report.Results, 3)
		want := []struct {
			name    string
			removed int
		}{
			{"sessions", 1},
			{"one-time-tokens:" + tokenPurpose, 1},
			{"login-attempts", 3},
		}
		for i, w := range want {
			assert.Equal(t, w.name, report.Results[i].Task)
			assert.Equal(t, w.removed, report.Results[i].Removed, w.name)
			assert.NoError(t, report.Results[i].Err, w.name)
			assert.False(t, report.Results[i].Skipped, w.name)
		}

		// Sessions: the expired one is gone, the live one is present and loads.
		assert.Equal(t, 1, countRows(t, db, "sessions", ""), "live session present, expired one gone")
		_, err := st.sessions.Load(t.Context(), "live-session")
		assert.NoError(t, err, "the live session still loads")
		_, err = st.sessions.Load(t.Context(), "expired-session")
		assert.ErrorIs(t, err, session.ErrSessionNotFound, "the expired session is gone, not merely expired")

		// One-time tokens: the one past its expiry and its window is gone; the
		// one expired but inside the window and the live one remain, and so does
		// every issuance the window still counts.
		assert.Equal(t, 2, countRows(t, db, "one_time_tokens", "purpose = '"+tokenPurpose+"'"),
			"the in-window and live tokens remain")
		issuedAfter, err := mgr.IssuedCount(t.Context(), tokenSubject)
		require.NoError(t, err)
		assert.Equal(t, issuedBefore, issuedAfter, "the sweep freed no issuance quota")
		assert.Equal(t, 2, issuedAfter)

		// Login failures: the three outside the window are gone and the two
		// inside it are still counted.
		assert.Equal(t, 2, countRows(t, db, "login_attempts", "username = '"+failedAccount+"'"),
			"the in-window failures remain")

		// State a sweep never owns is untouched, expired or not.
		assert.Equal(t, 1, countRows(t, db, "api_keys", "expires_at IS NOT NULL"), "the expired API key remains")
		assert.Equal(t, 1, countRows(t, db, "oidc_links", ""), "the OIDC link remains")
		assert.Equal(t, 1, countRows(t, db, "mfa_enrolments", ""), "the MFA enrolment remains")
		assert.Equal(t, 1, countRows(t, db, "signing_keys", ""), "the signing key remains")
	}

	cases := make([]testCase, 0, len(expiryAdapters))
	for _, a := range expiryAdapters {
		cases = append(cases, testCase{name: a.name, open: a.open, assert: assertSwept})
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			set := migrate.SecurityState()
			conn := test.RunTestPostgres(t, test.WithTestPostgresMigrations(set.FS(), set.Dir, set.VersionTable))

			start := time.Date(2030, 1, 1, 10, 0, 0, 0, time.UTC)
			clk := clockwork.NewFakeClockAt(start)
			st := tc.open(t, conn, storefix.TestCipher(t), clk)

			mgr, err := onetime.NewManager(tokenPurpose, onetime.WithStore(st.oneTime), onetime.WithClock(clk))
			require.NoError(t, err)
			lockout, err := policy.NewAccountLockoutPolicy(
				policy.WithAttemptStore(st.attempts),
				policy.WithLockoutClock(clk),
				policy.WithSlidingLockout(5, lockoutWindow),
			)
			require.NoError(t, err)

			// Time line (start = T, default TTL 15m, issuance window 1h):
			//   T       an old token is issued, and three failures are recorded;
			//   T+90m   a token is issued that will have expired, but is inside
			//           the window, at the sweep;
			//   T+110m  a live token is issued and two failures are recorded;
			//   T+115m  the sweep runs, so those failures are 5m old: inside the
			//           15m window, yet older than a sweep that ignored the
			//           window would keep.
			_, _, err = mgr.Issue(ctx, tokenSubject)
			require.NoError(t, err)
			for range 3 {
				require.NoError(t, lockout.RecordFailure(ctx, failedAccount))
			}
			clk.Advance(90 * time.Minute)
			_, _, err = mgr.Issue(ctx, tokenSubject)
			require.NoError(t, err)
			clk.Advance(20 * time.Minute)
			_, _, err = mgr.Issue(ctx, tokenSubject)
			require.NoError(t, err)
			for range 2 {
				require.NoError(t, lockout.RecordFailure(ctx, failedAccount))
			}
			clk.Advance(5 * time.Minute)
			now := clk.Now()

			// Sessions, judged by the store's clock: one past both deadlines and
			// one live.
			expired := storefix.DurableSession("expired-session", now.Add(-3*time.Hour))
			expired.IdleExpiresAt = now.Add(-2 * time.Hour)
			expired.AbsoluteExpiresAt = now.Add(-time.Hour)
			require.NoError(t, st.sessions.Create(ctx, expired))
			require.NoError(t, st.sessions.Create(ctx, storefix.DurableSession("live-session", now)))

			// State the sweep must never own, including one record already
			// expired.
			key := storefix.APIKey(1, identity.UserID("key-owner"))
			pastExpiry := now.Add(-time.Hour)
			key.ExpiresAt = &pastExpiry
			require.NoError(t, st.apiKeys.Put(ctx, key))
			require.NoError(t, st.links.Insert(ctx, storefix.Link(t, "corp", "https://idp.example", "subject-1", "link-owner")))
			require.NoError(t, st.enrolments.PutPending(ctx, storefix.Pending("mfa-owner", "enrolment-secret")))
			require.NoError(t, st.signing.Store(ctx, storefix.SigningKey("kid-1", []byte("private-material"))))

			issuedBefore, err := mgr.IssuedCount(ctx, tokenSubject)
			require.NoError(t, err)
			require.Equal(t, 2, issuedBefore, "precondition: the old token is already outside the window")
			require.Equal(t, 3, countRows(t, conn.DB, "one_time_tokens", ""), "precondition: all three tokens are stored")
			require.Equal(t, 5, countRows(t, conn.DB, "login_attempts", ""), "precondition: all five failures are stored")

			runner, err := expiry.NewRunner([]expiry.Task{
				session.ExpiryTask(st.sessions),
				onetime.ExpiryTask(mgr),
				policy.LockoutExpiryTask(lockout),
			})
			require.NoError(t, err)

			report, err := runner.RunOnce(ctx)
			require.NoError(t, err)

			tc.assert(t, conn.DB, st, mgr, report, issuedBefore)
		})
	}
}

// TestExpiryLockoutStreaks runs the lockout task through a runner over the
// sqlstore attempt store, with a consecutive-failure cap, and checks which
// streaks the sweep keeps: a hold always, a recent count, and not an
// inactive count. Every case gets a database of its own.
func TestExpiryLockoutStreaks(t *testing.T) {
	t.Parallel()

	const (
		capLimit = 100
		holdName = "ada"
		day      = 24 * time.Hour
		// retention is the policy's default retention for a count below the cap.
		retention = 30 * day
	)

	type env struct {
		db      *sql.DB
		lockout *policy.AccountLockoutPolicy
		streaks policy.FailureStreakStore
		clk     *clockwork.FakeClock
	}

	type testCase struct {
		name string
		// failures is how many consecutive failures are seeded, the newest of
		// them newestAge before the sweep.
		failures  int
		newestAge time.Duration
		assert    func(t *testing.T, e env)
	}

	cases := []testCase{
		{
			name:      "a hold survives every sweep",
			failures:  capLimit,
			newestAge: 90 * day,
			assert: func(t *testing.T, e env) {
				s, err := e.streaks.FailureStreak(t.Context(), holdName, e.clk.Now().Add(-retention))
				require.NoError(t, err)
				assert.True(t, s.Held(), "the streak is still held")
				assert.Equal(t, capLimit, s.Failures)

				d := e.lockout.Evaluate(t.Context(), &policy.Input{Username: holdName, Now: e.clk.Now()})
				assert.Equal(t, policy.Deny, d.Outcome)
				assert.ErrorIs(t, d.Reason, policy.ErrAccountHeld)
				assert.Equal(t, 1, countRows(t, e.db, "login_failure_streaks", "held_at IS NOT NULL"))
			},
		},
		{
			name:      "a recent consecutive count survives",
			failures:  10,
			newestAge: 29 * day,
			assert: func(t *testing.T, e env) {
				s, err := e.streaks.FailureStreak(t.Context(), holdName, e.clk.Now().Add(-retention))
				require.NoError(t, err)
				assert.Equal(t, 10, s.Failures)
				assert.False(t, s.Held())
			},
		},
		{
			name:      "an inactive consecutive count is deleted",
			failures:  10,
			newestAge: 31 * day,
			assert: func(t *testing.T, e env) {
				assert.Equal(t, 0, countRows(t, e.db, "login_failure_streaks", ""), "the streak row is gone")

				require.NoError(t, e.lockout.Attempts().RecordFailure(t.Context(), holdName, e.clk.Now()))
				s, err := e.streaks.FailureStreak(t.Context(), holdName, e.clk.Now().Add(-retention))
				require.NoError(t, err)
				assert.Equal(t, 1, s.Failures, "the next failure starts a new count")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			set := migrate.SecurityState()
			conn := test.RunTestPostgres(t, test.WithTestPostgresMigrations(set.FS(), set.Dir, set.VersionTable))

			now := time.Date(2030, 6, 1, 10, 0, 0, 0, time.UTC)
			// The clock starts at the newest failure's instant, so every add
			// is judged against the cutoff of its own instant.
			clk := clockwork.NewFakeClockAt(now.Add(-tc.newestAge))

			store, err := sqlstore.NewAttemptStore(conn.DB)
			require.NoError(t, err)
			lockout, err := policy.NewAccountLockoutPolicy(
				policy.WithAttemptStore(store),
				policy.WithLockoutClock(clk),
				policy.WithLockoutCap(capLimit),
			)
			require.NoError(t, err)

			for range tc.failures {
				require.NoError(t, lockout.Attempts().RecordFailure(ctx, holdName, clk.Now()))
			}
			clk.Advance(tc.newestAge)
			require.Equal(t, now, clk.Now())

			runner, err := expiry.NewRunner([]expiry.Task{policy.LockoutExpiryTask(lockout)})
			require.NoError(t, err)
			report, err := runner.RunOnce(ctx)
			require.NoError(t, err)
			require.Len(t, report.Results, 1)
			require.NoError(t, report.Results[0].Err)

			tc.assert(t, env{db: conn.DB, lockout: lockout, streaks: store, clk: clk})
		})
	}
}
