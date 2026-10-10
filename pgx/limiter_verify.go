package pgx

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/ratelimit"
)

var (
	_ ratelimit.Verifier = (*LimiterFactory)(nil)
	_ ratelimit.Verifier = (*Limiter)(nil)
)

// sqlStateInsufficientPrivilege is the SQLSTATE of a statement the role may
// not run (insufficient_privilege).
const sqlStateInsufficientPrivilege = "42501"

// limiterCheck is what Verify checks with: the pool, and the clock and lock
// timeout the limiter's statements run with, so the probe runs them as the
// limiter does.
type limiterCheck struct {
	pool        *pgxpool.Pool
	clock       clock.Clock // nil: the database's clock
	lockTimeout string
}

func newLimiterCheck(pool *pgxpool.Pool, cfg limiterConfig) limiterCheck {
	return limiterCheck{pool: pool, clock: cfg.clock, lockTimeout: lockTimeout(cfg.unavailable.Timeout)}
}

// limiterServerFacts is what Verify reads about the server, in one query.
type limiterServerFacts struct {
	inRecovery  bool
	version     int
	tableExists bool
	logged      bool
}

// check refuses the facts of a server the limiter cannot hold its limits on,
// in this order: a standby, a server older than PostgreSQL 15, a bucket table
// that does not resolve through search_path, and an unlogged one.
func (f limiterServerFacts) check() error {
	switch {
	case f.inRecovery:
		return fmt.Errorf("%w: the server is a standby (in recovery); the limiter must run on the primary, "+
			"because a standby lags, so it undercounts, and refuses writes", ratelimit.ErrConfig)
	case f.version < pgschema.LimiterMinServerVersion:
		return fmt.Errorf("%w: the server's server_version_num is %d, older than PostgreSQL 15 (%d), the oldest the limiter supports",
			ratelimit.ErrConfig, f.version, pgschema.LimiterMinServerVersion)
	case !f.tableExists:
		return fmt.Errorf("%w: the table %s does not resolve through the connection's search_path; "+
			"apply the security-state migration set (migrate.SecurityState) to this database",
			ratelimit.ErrConfig, pgschema.LimiterTable)
	case !f.logged:
		return fmt.Errorf("%w: the table %s is unlogged, so a crash or a failover would reset every limit to zero; "+
			"make it logged again with ALTER TABLE %s SET LOGGED",
			ratelimit.ErrConfig, pgschema.LimiterTable, pgschema.LimiterTable)
	}
	return nil
}

func (c limiterCheck) verify(ctx context.Context) error {
	var facts limiterServerFacts
	err := c.pool.QueryRow(ctx, pgschema.LimiterServerFacts).
		Scan(&facts.inRecovery, &facts.version, &facts.tableExists, &facts.logged)
	if err != nil {
		return diag.Wrap(err, "pgx: verify: the server's state could not be read")
	}
	if err := facts.check(); err != nil {
		return err
	}
	return c.probe(ctx)
}

// probe runs the limiter's record, check and delete statements once, on a
// probe key of its own: an empty namespace, which no limiter can have, and a
// random key. The record proves INSERT and UPDATE, the check SELECT, and the
// delete the probe row, with the DELETE privilege the prune needs. The probe row is deleted in the same
// call; if the delete is what fails, the row is left for the prune, which
// removes it as soon as it runs, its window being one microsecond.
func (c limiterCheck) probe(ctx context.Context) error {
	var buf [16]byte
	_, _ = rand.Read(buf[:]) // crypto/rand.Read never returns an error
	key := "verify-" + hex.EncodeToString(buf[:])
	now := limiterNow(c.clock)

	if _, err := c.pool.Exec(ctx, pgschema.LimiterRecord, "", key, 1, int64(1), now, c.lockTimeout); err != nil {
		return probeError(err, "record")
	}
	var n int
	if err := c.pool.QueryRow(ctx, pgschema.LimiterCheck, "", key, int64(1), now).Scan(&n); err != nil {
		return probeError(err, "check")
	}
	if _, err := c.pool.Exec(ctx, pgschema.LimiterDeleteKey, "", key); err != nil {
		return probeError(err, "delete")
	}
	return nil
}

// probeError classifies an error from the probe's step. A permission refusal
// (SQLSTATE 42501) is a configuration error naming the statement refused;
// anything else, a server that cannot be reached included, is not. Neither
// repeats the server's text.
func probeError(err error, step string) error {
	var st sqlStater // *pgconn.PgError reports its SQLSTATE this way
	if errors.As(err, &st) && st.SQLState() == sqlStateInsufficientPrivilege {
		return diag.Wrap(err, fmt.Sprintf("ratelimit: invalid configuration: the role may not run the limiter's %s statement on %s; "+
			"grant it SELECT, INSERT, UPDATE and DELETE on the table", step, pgschema.LimiterTable), ratelimit.ErrConfig)
	}
	return diag.Wrap(err, fmt.Sprintf("pgx: verify: the limiter's %s statement could not run on a probe key", step))
}
