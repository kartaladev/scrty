package test_test

import (
	"context"
	"database/sql"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	gormdb "gorm.io/gorm"

	"github.com/kartaladev/scrty/authenticate/apikey"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/expiry"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/store/gormstore"
	"github.com/kartaladev/scrty/store/migrate"
	"github.com/kartaladev/scrty/store/pgxstore"
	"github.com/kartaladev/scrty/store/seal"
	"github.com/kartaladev/scrty/store/sqlstore"
	"github.com/kartaladev/scrty/test"
	"github.com/kartaladev/scrty/test/internal/storefix"
	"github.com/kartaladev/scrty/token/onetime"
	"github.com/kartaladev/scrty/token/signingkey"
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
				sessions: mustStore(pgxstore.NewSessionStore(pool, c, pgxstore.WithClock(clk))),
				oneTime:  mustStore(pgxstore.NewOneTimeStore(pool, pgxstore.WithClock(clk))),
				attempts: mustStore(pgxstore.NewAttemptStore(pool)),
				apiKeys:  mustStore(pgxstore.NewAPIKeyStore(pool)),
				links:    mustStore(pgxstore.NewLinkStore(pool)),
				enrolments: mustStore(
					pgxstore.NewEnrolmentStore(pool, c, pgxstore.WithClock(clk))),
				signing: mustStore(pgxstore.NewSigningKeyStore(pool, c)),
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
		assert func(t *testing.T, db *sql.DB, st expiryStores, mgr *onetime.Tokens, report expiry.Report, issuedBefore int)
	}

	assertSwept := func(t *testing.T, db *sql.DB, st expiryStores, mgr *onetime.Tokens, report expiry.Report, issuedBefore int) {
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
		assert.ErrorIs(t, err, session.ErrNotFound, "the expired session is gone, not merely expired")

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

			mgr, err := onetime.New(tokenPurpose, onetime.WithStore(st.oneTime), onetime.WithClock(clk))
			require.NoError(t, err)
			lockoutPolicy, err := lockout.New(
				lockout.WithAttemptStore(st.attempts),
				lockout.WithClock(clk),
				lockout.WithSliding(5, lockoutWindow),
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
				require.NoError(t, lockoutPolicy.RecordFailure(ctx, failedAccount))
			}
			clk.Advance(90 * time.Minute)
			_, _, err = mgr.Issue(ctx, tokenSubject)
			require.NoError(t, err)
			clk.Advance(20 * time.Minute)
			_, _, err = mgr.Issue(ctx, tokenSubject)
			require.NoError(t, err)
			for range 2 {
				require.NoError(t, lockoutPolicy.RecordFailure(ctx, failedAccount))
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
				lockout.ExpiryTask(lockoutPolicy),
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
		lockout *lockout.Policy
		streaks lockout.FailureStreakStore
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
				assert.ErrorIs(t, d.Reason, lockout.ErrAccountHeld)
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
			lockoutPolicy, err := lockout.New(
				lockout.WithAttemptStore(store),
				lockout.WithClock(clk),
				lockout.WithFailureStreakLimit(capLimit),
			)
			require.NoError(t, err)

			for range tc.failures {
				require.NoError(t, lockoutPolicy.Attempts().RecordFailure(ctx, holdName, clk.Now()))
			}
			clk.Advance(tc.newestAge)
			require.Equal(t, now, clk.Now())

			runner, err := expiry.NewRunner([]expiry.Task{lockout.ExpiryTask(lockoutPolicy)})
			require.NoError(t, err)
			report, err := runner.RunOnce(ctx)
			require.NoError(t, err)
			require.Len(t, report.Results, 1)
			require.NoError(t, report.Results[0].Err)

			tc.assert(t, env{db: conn.DB, lockout: lockoutPolicy, streaks: store, clk: clk})
		})
	}
}

// opStores is every store a provider's expiry tasks sweep, as one adapter builds
// them over a single database.
type opStores struct {
	pending    oidcprovider.PendingRequestStore
	codes      oidcprovider.CodeStore
	grants     oidcprovider.GrantStore
	tokens     onetime.Store
	access     oidcprovider.AccessTokenStore
	assertions oidcprovider.AssertionIDStore
	browser    oidcprovider.BrowserSessionStore
	lineage    oidcprovider.RefreshTokenStore
}

// opAdapters builds each adapter's provider stores over one migrated database.
var opAdapters = []struct {
	name string
	open func(t *testing.T, conn test.PostgresConn, c seal.Cipher, clk clock.Clock) opStores
}{
	{
		name: "sqlstore",
		open: func(_ *testing.T, conn test.PostgresConn, c seal.Cipher, clk clock.Clock) opStores {
			db, w := conn.DB, sqlstore.WithClock(clk)
			return opStores{
				pending:    mustStore(sqlstore.NewPendingRequestStore(db)),
				codes:      mustStore(sqlstore.NewCodeStore(db)),
				grants:     mustStore(sqlstore.NewGrantStore(db)),
				tokens:     mustStore(sqlstore.NewOneTimeStore(db, w)),
				access:     mustStore(sqlstore.NewAccessTokenStore(db)),
				assertions: mustStore(sqlstore.NewAssertionIDStore(db)),
				browser:    mustStore(sqlstore.NewBrowserSessionStore(db)),
				lineage:    mustStore(sqlstore.NewRefreshTokenStore(db, c, w)),
			}
		},
	},
	{
		name: "pgx",
		open: func(t *testing.T, conn test.PostgresConn, c seal.Cipher, clk clock.Clock) opStores {
			cfg, err := pgxpool.ParseConfig(conn.DSN)
			require.NoError(t, err)
			pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
			require.NoError(t, err)
			t.Cleanup(pool.Close)
			w := pgxstore.WithClock(clk)

			return opStores{
				pending:    mustStore(pgxstore.NewPendingRequestStore(pool)),
				codes:      mustStore(pgxstore.NewCodeStore(pool)),
				grants:     mustStore(pgxstore.NewGrantStore(pool)),
				tokens:     mustStore(pgxstore.NewOneTimeStore(pool, w)),
				access:     mustStore(pgxstore.NewAccessTokenStore(pool)),
				assertions: mustStore(pgxstore.NewAssertionIDStore(pool)),
				browser:    mustStore(pgxstore.NewBrowserSessionStore(pool)),
				lineage:    mustStore(pgxstore.NewRefreshTokenStore(pool, c, w)),
			}
		},
	},
	{
		name: "gorm",
		open: func(t *testing.T, conn test.PostgresConn, c seal.Cipher, clk clock.Clock) opStores {
			db, err := gormdb.Open(postgres.Open(conn.DSN), &gormdb.Config{DisableAutomaticPing: true})
			require.NoError(t, err)
			sqlDB, err := db.DB()
			require.NoError(t, err)
			t.Cleanup(func() { _ = sqlDB.Close() })
			w := gormstore.WithClock(clk)

			return opStores{
				pending:    mustStore(gormstore.NewPendingRequestStore(db)),
				codes:      mustStore(gormstore.NewCodeStore(db)),
				grants:     mustStore(gormstore.NewGrantStore(db)),
				tokens:     mustStore(gormstore.NewOneTimeStore(db, w)),
				access:     mustStore(gormstore.NewAccessTokenStore(db)),
				assertions: mustStore(gormstore.NewAssertionIDStore(db)),
				browser:    mustStore(gormstore.NewBrowserSessionStore(db)),
				lineage:    mustStore(gormstore.NewRefreshTokenStore(db, c, w)),
			}
		},
	},
}

const (
	opIssuer      = "https://id.example.com"
	opClient      = "billing-web"
	opSecret      = "0123456789abcdef0123456789abcdef"
	opRedirect    = "https://rp.example.com/cb"
	opChallenge   = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	opVerifier    = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	opCodePurpose = "oidc-provider.code"
)

// opUsers answers every lookup with an active user. The provider only reads the user
// at a resume.
type opUsers struct{ identity.UserLoader }

func (opUsers) LoadByUserID(_ context.Context, user identity.UserID) (*identity.Details, error) {
	return &identity.Details{ID: user, Active: true}, nil
}

// opKeys stands for the signing keys, which no case here reaches.
type opKeys struct{ signingkey.KeySource }

// opEnv is a provider over one adapter's stores, its runner and the clock they share.
type opEnv struct {
	p        *oidcprovider.Provider
	clk      *clockwork.FakeClock
	db       *sql.DB
	st       opStores
	consents *oidcprovider.MemoryConsentStore
	runner   *expiry.Runner
}

func newID() id.ID {
	v, err := id.NewV7Generator().NewID()
	if err != nil {
		panic(err)
	}

	return v
}

func newOpEnv(t *testing.T, open func(*testing.T, test.PostgresConn, seal.Cipher, clock.Clock) opStores) *opEnv {
	t.Helper()

	set := migrate.SecurityState()
	conn := test.RunTestPostgres(t, test.WithTestPostgresMigrations(set.FS(), set.Dir, set.VersionTable))
	clk := clockwork.NewFakeClockAt(time.Date(2030, 1, 1, 10, 0, 0, 0, time.UTC))
	st := open(t, conn, storefix.TestCipher(t), clk)
	consents := mustStore(oidcprovider.NewMemoryConsentStore())

	p, err := oidcprovider.New(oidcprovider.Deps{
		Issuer: opIssuer,
		Clients: []oidcprovider.Client{{
			ID: opClient, Type: oidcprovider.Confidential, Secret: []byte(opSecret),
			RedirectURIs: []string{opRedirect}, Scopes: []string{"openid"},
			GrantTypes: []oidcprovider.GrantType{oidcprovider.GrantAuthorizationCode, oidcprovider.GrantRefreshToken},
		}},
		Keys:         opKeys{},
		Users:        opUsers{},
		LoginURL:     opIssuer + "/login",
		ConsentURL:   opIssuer + "/consent",
		LogoutURL:    opIssuer + "/logout",
		LoggedOutURL: opIssuer + "/bye",
	},
		oidcprovider.WithClock(clk),
		oidcprovider.WithPendingRequestStore(st.pending),
		oidcprovider.WithCodeStore(st.codes),
		oidcprovider.WithGrantStore(st.grants),
		oidcprovider.WithCodeTokenStore(st.tokens),
		oidcprovider.WithAccessTokenStore(st.access),
		oidcprovider.WithAssertionIDStore(st.assertions),
		oidcprovider.WithBrowserSessionStore(st.browser),
		oidcprovider.WithRefreshTokenStore(st.lineage),
		oidcprovider.WithConsentStore(consents),
	)
	require.NoError(t, err)

	runner, err := expiry.NewRunner(oidcprovider.ExpiryTasks(p))
	require.NoError(t, err)

	return &opEnv{p: p, clk: clk, db: conn.DB, st: st, consents: consents, runner: runner}
}

// run runs every task once, and returns each one's outcome by name.
func (e *opEnv) run(t *testing.T) map[string]expiry.Result {
	t.Helper()

	report, err := e.runner.RunOnce(t.Context())
	require.NoError(t, err)
	out := make(map[string]expiry.Result, len(report.Results))
	for _, r := range report.Results {
		require.NoError(t, r.Err, r.Task)
		out[r.Task] = r
	}

	return out
}

func (e *opEnv) authorize(t *testing.T) (handle, flow string) {
	t.Helper()

	res, err := e.p.Authorize(t.Context(), oidcprovider.AuthorizeInput{Params: url.Values{
		"client_id": {opClient}, "redirect_uri": {opRedirect}, "response_type": {"code"},
		"scope": {"openid"}, "state": {"s"}, "code_challenge": {opChallenge}, "code_challenge_method": {"S256"},
	}})
	require.NoError(t, err)
	loc, err := url.Parse(res.Location)
	require.NoError(t, err)

	return loc.Query().Get("req"), res.FlowSecret
}

// issueCode has a user sign in and returns the code the provider answers with, and the
// family of the grant it would create.
func (e *opEnv) issueCode(t *testing.T) (string, id.ID) {
	t.Helper()

	now := e.clk.Now()
	require.NoError(t, e.consents.Give(t.Context(), "u-1", opClient, []string{"openid"}, false, now))
	handle, flow := e.authorize(t)
	signIn := oidcprovider.SignIn{
		User: "u-1", Family: newID(), AuthenticatedAt: now, AMR: []string{"pwd"}, ACR: "urn:example:acr",
		AbsoluteExpiresAt: now.Add(8 * time.Hour),
	}
	res, err := e.p.Resume(t.Context(), oidcprovider.ResumeInput{
		Handle: handle, FlowSecret: flow, SignIn: &signIn, IdleTimeout: 15 * time.Minute,
	})
	require.NoError(t, err)
	loc, err := url.Parse(res.RedirectTo)
	require.NoError(t, err)
	code := loc.Query().Get("code")
	require.NotEmpty(t, code, res.RedirectTo)

	rawID, _, _ := strings.Cut(code, ".")
	tokenID, err := id.Parse(rawID)
	require.NoError(t, err)
	record, err := e.st.codes.Load(t.Context(), tokenID)
	require.NoError(t, err)

	return code, record.GrantFamily
}

// spend uses the code up, as a first exchange does.
func (e *opEnv) spend(t *testing.T, code string) {
	t.Helper()

	tokens, err := onetime.New(opCodePurpose, onetime.WithStore(e.st.tokens), onetime.WithClock(e.clk))
	require.NoError(t, err)
	checked, err := tokens.Check(t.Context(), code, "")
	require.NoError(t, err)
	require.NoError(t, tokens.Consume(t.Context(), checked))
}

// replay presents the spent code again, as its own client with every binding right.
func (e *opEnv) replay(t *testing.T, code string) {
	t.Helper()

	_, err := e.p.Token(t.Context(), oidcprovider.TokenRequest{
		Credentials: oidcprovider.ClientCredentials{
			Authorization: "Basic " + base64.StdEncoding.EncodeToString([]byte(opClient+":"+opSecret)),
		},
		Form: url.Values{
			"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {opRedirect},
			"code_verifier": {opVerifier},
		},
	})
	var refusal *oidcprovider.Error
	require.ErrorAs(t, err, &refusal)
	require.Equal(t, oidcprovider.CodeInvalidGrant, refusal.Code)
}

func (e *opEnv) grant(holdsLineage bool, created, expires time.Time) *oidcprovider.Grant {
	return &oidcprovider.Grant{
		Family: newID(), User: "u-1", ClientID: opClient, Scopes: []string{"openid"},
		AuthTime: created, AMR: []string{"pwd"}, ACR: "urn:example:acr", SignInFamily: newID(),
		CodeID: newID(), HoldsLineage: holdsLineage, CreatedAt: created, ExpiresAt: expires,
	}
}

func grantRows(t *testing.T, e *opEnv, g *oidcprovider.Grant) int {
	t.Helper()

	return countRows(t, e.db, "op_grants", "family = '"+g.Family.String()+"'")
}

// TestExpiryTasks_OIDCProvider runs a provider's expiry tasks through a runner over each
// durable adapter on PostgreSQL. Every case gets a database of its own.
func TestExpiryTasks_OIDCProvider(t *testing.T) {
	t.Parallel()

	const minute = time.Minute

	type testCase struct {
		name   string
		assert func(t *testing.T, e *opEnv)
	}

	cases := []testCase{
		{
			name: "the tasks run in order under their names, each without error",
			assert: func(t *testing.T, e *opEnv) {
				report, err := e.runner.RunOnce(t.Context())
				require.NoError(t, err)
				names := make([]string, 0, len(report.Results))
				for _, r := range report.Results {
					assert.NoError(t, r.Err, r.Task)
					names = append(names, r.Task)
				}
				assert.Equal(t, []string{
					"oidc-provider.pending-requests", "oidc-provider.browser-sessions", "oidc-provider.codes",
					"oidc-provider.grants", "oidc-provider.refresh-tokens", "oidc-provider.orphaned-grants",
					"oidc-provider.access-tokens", "oidc-provider.assertion-ids",
				}, names)
			},
		},
		{
			name: "a valid replay inside the minute past a code's expiry still revokes after the codes task ran",
			assert: func(t *testing.T, e *opEnv) {
				code, family := e.issueCode(t)
				e.clk.Advance(5 * time.Second)
				e.spend(t, code)
				// The code lived 60s and expired 25s ago.
				e.clk.Advance(time.Minute + 20*time.Second)
				e.run(t)

				e.replay(t, code)

				g, err := e.st.grants.Load(t.Context(), family)
				require.NoError(t, err, "the replay recorded a revocation")
				assert.True(t, g.Revoked)
				assert.Equal(t, oidcprovider.CauseCodeReplay, g.RevokeCause)
			},
		},
		{
			name: "a replay past the minute revokes nothing, and the codes task removed the token and the record",
			assert: func(t *testing.T, e *opEnv) {
				code, family := e.issueCode(t)
				e.clk.Advance(5 * time.Second)
				e.spend(t, code)
				// The code expired a minute and a half ago.
				e.clk.Advance(2*time.Minute + 25*time.Second)
				res := e.run(t)

				assert.Equal(t, 2, res["oidc-provider.codes"].Removed, "the token and the record")
				assert.Zero(t, countRows(t, e.db, "op_authorization_codes", ""))
				e.replay(t, code)
				_, err := e.st.grants.Load(t.Context(), family)
				assert.ErrorIs(t, err, oidcprovider.ErrNotFound, "no grant was revoked")
			},
		},
		{
			name: "pending requests, browser sessions, opaque tokens and assertion identifiers lose only what expired",
			assert: func(t *testing.T, e *opEnv) {
				ctx := t.Context()
				e.authorize(t)
				e.clk.Advance(11 * minute)
				e.authorize(t)
				now := e.clk.Now()

				session := func(idle, abs time.Time) *oidcprovider.BrowserSession {
					return &oidcprovider.BrowserSession{
						Digest: []byte(newID().String()),
						SignIn: oidcprovider.SignIn{
							User: "u-1", Family: newID(), AuthenticatedAt: now.Add(-time.Hour),
							AMR: []string{"pwd"}, ACR: "a", AbsoluteExpiresAt: abs,
						},
						IdleExpiresAt: idle, AbsoluteExpiresAt: abs,
					}
				}
				require.NoError(t, e.st.browser.Put(ctx, session(now.Add(-minute), now.Add(time.Hour))))
				require.NoError(t, e.st.browser.Put(ctx, session(now.Add(minute), now.Add(time.Hour))))

				token := func(expires time.Time) *oidcprovider.AccessTokenRecord {
					return &oidcprovider.AccessTokenRecord{
						ID: newID(), Digest: []byte(newID().String()), GrantFamily: newID(), ClientID: opClient,
						User: "u-1", Scopes: []string{"openid"}, IssuedAt: now.Add(-time.Hour), ExpiresAt: expires,
					}
				}
				require.NoError(t, e.st.access.Create(ctx, token(now.Add(-minute))))
				require.NoError(t, e.st.access.Create(ctx, token(now.Add(minute))))

				for jti, until := range map[string]time.Time{"old": now.Add(-minute), "new": now.Add(minute)} {
					fresh, err := e.st.assertions.Record(ctx, opClient, jti, until)
					require.NoError(t, err)
					require.True(t, fresh)
				}

				res := e.run(t)

				for task, table := range map[string]string{
					"oidc-provider.pending-requests": "op_pending_requests",
					"oidc-provider.browser-sessions": "op_browser_sessions",
					"oidc-provider.access-tokens":    "op_access_tokens",
					"oidc-provider.assertion-ids":    "op_client_assertions",
				} {
					assert.Equal(t, 1, res[task].Removed, task)
					assert.Equal(t, 1, countRows(t, e.db, table, ""), table)
				}
			},
		},
		{
			name: "a revoked grant is kept until the longest code lifetime and a minute have passed",
			assert: func(t *testing.T, e *opEnv) {
				ctx := t.Context()
				now := e.clk.Now()
				revoked := e.grant(false, now, now.Add(365*24*time.Hour))
				require.NoError(t, e.st.grants.Create(ctx, revoked))
				require.NoError(t, e.st.grants.Revoke(ctx, revoked.Family, oidcprovider.CauseCodeReplay, now))
				expired := e.grant(false, now.Add(-2*time.Hour), now.Add(-time.Hour))
				require.NoError(t, e.st.grants.Create(ctx, expired))

				e.clk.Advance(5 * minute)
				e.run(t)
				assert.Equal(t, 1, grantRows(t, e, revoked), "kept: a code of the longest lifetime could still name it")
				assert.Zero(t, grantRows(t, e, expired), "an expired grant goes")

				e.clk.Advance(7 * minute)
				e.run(t)
				assert.Zero(t, grantRows(t, e, revoked), "gone once no code could name it")
			},
		},
		{
			name: "the orphan sweep removes an old grant with no lineage, and spares one recorded to hold none",
			assert: func(t *testing.T, e *opEnv) {
				ctx := t.Context()
				now := e.clk.Now()
				orphan := e.grant(true, now, now.Add(time.Hour))
				holdsNone := e.grant(false, now, now.Add(time.Hour))
				require.NoError(t, e.st.grants.Create(ctx, orphan))
				require.NoError(t, e.st.grants.Create(ctx, holdsNone))
				e.clk.Advance(10 * minute)
				young := e.grant(true, e.clk.Now(), e.clk.Now().Add(time.Hour))
				require.NoError(t, e.st.grants.Create(ctx, young))
				e.clk.Advance(minute)

				res := e.run(t)

				assert.Equal(t, 1, res["oidc-provider.orphaned-grants"].Removed)
				assert.Zero(t, grantRows(t, e, orphan), "the lineage is missing and the grant is past the cutoff")
				assert.Equal(t, 1, grantRows(t, e, holdsNone), "a grant recorded to hold no lineage is no orphan (R10)")
				assert.Equal(t, 1, grantRows(t, e, young), "a grant inside the cutoff may be mid-exchange")
			},
		},
	}

	for _, a := range opAdapters {
		for _, tc := range cases {
			t.Run(a.name+"/"+tc.name, func(t *testing.T) {
				t.Parallel()

				tc.assert(t, newOpEnv(t, a.open))
			})
		}
	}
}
