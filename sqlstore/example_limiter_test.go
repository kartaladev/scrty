package sqlstore_test

import (
	"context"
	"database/sql"
	"log"
	"time"

	"github.com/kartaladev/scrty/expiry"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/sqlstore"
)

// ExampleNewLimiterFactory builds the factory every flow takes its limiter
// from, checks the database at startup, hands the factory to the chain, and
// runs the factory as the table's pruner. It needs a PostgreSQL primary with
// the security-state migration set applied, so it has no output to check.
func ExampleNewLimiterFactory() {
	ctx := context.Background()

	// The consumer opens the handle with the PostgreSQL driver of their
	// choice. It must reach only the primary: a standby undercounts.
	db, err := sql.Open("pgx", "postgres://app@primary.db.internal/app")
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	// The defaults: the database's clock, refusal while the database cannot
	// be reached, a 250ms operation and lock timeout. Construction performs
	// no I/O.
	factory, err := sqlstore.NewLimiterFactory(db)
	if err != nil {
		log.Fatal(err)
	}

	// Second-factor flows keep a per-replica bound during an outage rather
	// than refuse every sign-in, so they take a factory of their own over the
	// same handle.
	secondFactor, err := sqlstore.NewLimiterFactory(db,
		sqlstore.WithLimiterOnUnavailable(ratelimit.UnavailableFallBackToLocal),
		sqlstore.WithLimiterOperationTimeout(100*time.Millisecond),
	)
	if err != nil {
		log.Fatal(err)
	}

	// At startup, before traffic: the primary, the server version, the
	// table, that it is logged, and the role's privileges.
	if err := factory.Verify(ctx); err != nil {
		log.Fatal(err)
	}

	// Every flow the chain guards builds its limiter from the factory, under
	// its own namespace, limit and window.
	chainOpt := httpsec.WithRateLimiterFactory(factory)
	_, _ = chainOpt, secondFactor // httpsec.New(chainOpt, ...), mfa.WithVerifyLimiterFactory(secondFactor), ...

	// One prune covers every namespace in the table, whichever factory built
	// its limiters, so one task is enough.
	runner, err := expiry.NewRunner([]expiry.Task{ratelimit.ExpiryTask(factory)})
	if err != nil {
		log.Fatal(err)
	}
	if _, err := runner.RunOnce(ctx); err != nil {
		log.Print(err)
	}
}
