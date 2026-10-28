//go:generate mockgen -source=runner.go -package=pglimiter_test -destination=runner_mock_test.go -typed

package pglimiter

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/ratelimit"
)

// Row is one result row; *sql.Row and pgx.Row both satisfy it.
type Row interface {
	Scan(dest ...any) error
}

// Result is what a statement run by Runner.Exec reports. A sql.Result
// satisfies it; the pgx adapter wraps its command tag.
//
// Not every database/sql driver reports a row count, so the core calls
// RowsAffected only for a statement whose outcome depends on the count: the
// prune's batch, whose count is what the prune reports and what ends its
// loop, so an unreadable count fails the batch. The record and the probe's
// statements never call it: their success is their call's error alone.
type Result interface {
	RowsAffected() (int64, error)
}

// Runner runs the limiter's statements over one adapter's handle. Each
// adapter implements it over its own: sqlstore over a *sql.DB, pgx over a
// *pgxpool.Pool. Neither joins a caller's transaction.
type Runner interface {
	// Exec runs a statement that returns no rows, and reports its Result.
	Exec(ctx context.Context, sql string, args ...any) (Result, error)
	// ExecReadCommitted runs a statement that returns no rows as the only
	// statement of a transaction of its own, begun at READ COMMITTED (the
	// isolation carried in the BEGIN, not a statement of its own), whatever
	// the database's default isolation is, and commits it.
	ExecReadCommitted(ctx context.Context, sql string, args ...any) error
	// QueryRow runs a statement that returns at most one row. Its error, if
	// any, is reported by the row's Scan.
	QueryRow(ctx context.Context, sql string, args ...any) Row
}

// sqlStater is a driver error that reports its SQLSTATE, as *pgconn.PgError
// does, under either adapter.
type sqlStater interface{ SQLState() string }

// sqlStateInsufficientPrivilege is the SQLSTATE of a statement the role may
// not run (insufficient_privilege).
const sqlStateInsufficientPrivilege = "42501"

// backend talks to the database; the decorator from internal/unavailable wraps
// it with the operation timeout, the breaker and the unavailable modes.
type backend struct {
	r           Runner
	prefix      string
	namespace   string
	limit       int
	windowUS    int64
	clock       clock.Clock // nil: the database's clock
	lockTimeout string
}

// NewBackend returns the limiter the unavailable decorator wraps: it counts
// limit failures per key within window, in namespace, through r, with cfg's
// clock and the lock timeout of cfg's operation timeout. Its errors start
// with prefix. The window must already be in whole microseconds, and the
// policy and cfg already validated (ValidatePolicy, Config.Validate).
func NewBackend(r Runner, prefix, namespace string, limit int, window time.Duration, cfg Config) ratelimit.Limiter {
	return &backend{
		r:           r,
		prefix:      prefix,
		namespace:   namespace,
		limit:       limit,
		windowUS:    window.Microseconds(),
		clock:       cfg.Clock,
		lockTimeout: LockTimeout(cfg.Unavailable.Timeout),
	}
}

// Exceeded reports whether key holds the limit's number of failures within
// the window. An error answers true, wrapped as "<prefix>: rate-limit check".
func (b *backend) Exceeded(ctx context.Context, key string) (bool, error) {
	var n int
	err := b.r.QueryRow(ctx, pgschema.LimiterCheck,
		b.namespace, pgschema.LimiterKey(key), b.windowUS, Now(b.clock)).Scan(&n)
	if err != nil {
		return true, fmt.Errorf("%s: rate-limit check: %w", b.prefix, err)
	}
	return n >= b.limit, nil
}

// RecordFailure counts one failure for key, in a READ COMMITTED transaction
// of its own: at a stronger default isolation, records racing on one key
// would fail with a serialization failure. An error is wrapped as
// "<prefix>: rate-limit record".
func (b *backend) RecordFailure(ctx context.Context, key string) error {
	err := b.r.ExecReadCommitted(ctx, pgschema.LimiterRecord,
		b.namespace, pgschema.LimiterKey(key), b.limit, b.windowUS, Now(b.clock), b.lockTimeout)
	if err != nil {
		return fmt.Errorf("%s: rate-limit record: %w", b.prefix, err)
	}
	return nil
}

// Verify checks, through r, that the database can hold the limiter's limits,
// as the adapters' Verify methods document: it reads the server's facts and
// refuses them (Facts.Check), then probes the limiter's record, check and
// delete statements with cfg's clock and lock timeout.
//
// A refusal, a permission refusal included, wraps ratelimit.ErrConfig. A
// database that cannot be reached, or a ctx that ends, is an error with fixed
// text starting with prefix that keeps the cause but does not wrap
// ratelimit.ErrConfig. No error repeats the server's text.
func Verify(ctx context.Context, r Runner, prefix string, cfg Config) error {
	var facts Facts
	err := r.QueryRow(ctx, pgschema.LimiterServerFacts).
		Scan(&facts.InRecovery, &facts.Version, &facts.Encoding, &facts.Persistence)
	if err != nil {
		return diag.Wrap(err, prefix+": verify: the server's state could not be read")
	}
	if err := facts.Check(); err != nil {
		return err
	}
	return probe(ctx, r, prefix, Now(cfg.Clock), LockTimeout(cfg.Unavailable.Timeout))
}

// probe runs the limiter's record, check and delete statements once, on a
// probe key of its own: an empty namespace, which no limiter can have, and a
// random key. The record proves INSERT and UPDATE, the check SELECT, and the
// delete the probe row, with the DELETE privilege the prune needs. The probe
// row is deleted in the same call; if the delete is what fails, the row is
// left for the prune, which removes it as soon as it runs, its window being
// one microsecond.
func probe(ctx context.Context, r Runner, prefix string, now any, lockTimeout string) error {
	var buf [16]byte
	_, _ = rand.Read(buf[:]) // crypto/rand.Read never returns an error
	key := "verify-" + hex.EncodeToString(buf[:])

	if err := r.ExecReadCommitted(ctx, pgschema.LimiterRecord, "", key, 1, int64(1), now, lockTimeout); err != nil {
		return probeError(err, prefix, "record")
	}
	var n int
	if err := r.QueryRow(ctx, pgschema.LimiterCheck, "", key, int64(1), now).Scan(&n); err != nil {
		return probeError(err, prefix, "check")
	}
	if _, err := r.Exec(ctx, pgschema.LimiterDeleteKey, "", key); err != nil {
		return probeError(err, prefix, "delete")
	}
	return nil
}

// probeError classifies an error from the probe's step. A permission refusal
// (SQLSTATE 42501) is a configuration error naming the statement refused;
// anything else, a server that cannot be reached included, is not. Neither
// repeats the server's text.
func probeError(err error, prefix, step string) error {
	var st sqlStater
	if errors.As(err, &st) && st.SQLState() == sqlStateInsufficientPrivilege {
		return diag.Wrap(err, fmt.Sprintf("ratelimit: invalid configuration: the role may not run the limiter's %s statement on %s; "+
			"grant it SELECT, INSERT, UPDATE and DELETE on the table", step, pgschema.LimiterTable), ratelimit.ErrConfig)
	}
	return diag.Wrap(err, fmt.Sprintf("%s: verify: the limiter's %s statement could not run on a probe key", prefix, step))
}

// Facts is what Verify reads about the server, in one query
// (pgschema.LimiterServerFacts).
type Facts struct {
	// InRecovery is whether the server is a standby.
	InRecovery bool
	// Version is the server's server_version_num.
	Version int
	// Encoding is the database's server_encoding.
	Encoding string
	// Persistence is the relpersistence of the bucket table that resolves
	// through the connection's search_path: "p" permanent, "u" unlogged, "t"
	// temporary, or "" when no such table resolves.
	Persistence string
}

// Check refuses the facts of a server the limiter cannot hold its limits on,
// in this order: a standby, a server older than PostgreSQL 15, a database whose
// encoding is not UTF8, a bucket table that does not resolve through
// search_path, a temporary one and an unlogged one. Every
// refusal wraps ratelimit.ErrConfig.
func (f Facts) Check() error {
	switch {
	case f.InRecovery:
		return fmt.Errorf("%w: the server is a standby (in recovery); the limiter must run on the primary, "+
			"because a standby lags, so it undercounts, and refuses writes", ratelimit.ErrConfig)
	case f.Version < pgschema.LimiterMinServerVersion:
		return fmt.Errorf("%w: the server's server_version_num is %d, older than PostgreSQL 15 (%d), the oldest the limiter supports",
			ratelimit.ErrConfig, f.Version, pgschema.LimiterMinServerVersion)
	case f.Encoding != "UTF8":
		return fmt.Errorf("%w: the database's server encoding is %s; the limiter needs UTF8, "+
			"the encoding every key and namespace is stored in", ratelimit.ErrConfig, f.Encoding)
	case f.Persistence == "":
		return fmt.Errorf("%w: the table %s does not resolve through the connection's search_path; "+
			"apply the security-state migration set (migrate.SecurityState) to this database",
			ratelimit.ErrConfig, pgschema.LimiterTable)
	case f.Persistence == "t":
		return fmt.Errorf("%w: the table %s resolves to a temporary table, which shadows the migration's "+
			"and lasts only for its session; drop it", ratelimit.ErrConfig, pgschema.LimiterTable)
	case f.Persistence == "u":
		return fmt.Errorf("%w: the table %s is unlogged, so a crash or a failover would reset every limit to zero; "+
			"make it logged again with ALTER TABLE %s SET LOGGED",
			ratelimit.ErrConfig, pgschema.LimiterTable, pgschema.LimiterTable)
	}
	return nil
}

// DefaultPruneBatchSize is how many keys one prune batch deletes at most when
// no option sets it.
const DefaultPruneBatchSize = 1000

// Prune deletes idle keys in batches of cfg.PruneBatchSize, each its own
// statement and so its own transaction, and returns how many keys the batches
// that committed removed. The time is read once, before the first batch: the
// configured clock, or the database's. It stops on a short batch, on an ended
// ctx, or on the first failed batch; the count it returns with an error is a
// lower bound, every key of it removed. Its errors start with prefix, and none
// repeats the server's text.
func Prune(ctx context.Context, r Runner, prefix string, cfg Config) (int, error) {
	now := Now(cfg.Clock)
	if now == nil {
		var t time.Time
		if err := r.QueryRow(ctx, pgschema.LimiterClock).Scan(&t); err != nil {
			return 0, diag.Wrap(err, prefix+": rate-limit prune: the database clock could not be read")
		}
		now = t
	}

	total := 0
	for {
		res, err := r.Exec(ctx, pgschema.LimiterPrune, now, cfg.PruneBatchSize)
		if err != nil {
			return total, diag.Wrap(err, prefix+": rate-limit prune: a batch could not be deleted")
		}
		n, err := res.RowsAffected()
		if err != nil {
			return total, diag.Wrap(err, prefix+": rate-limit prune: a batch's row count could not be read")
		}
		total += int(n)
		if n < int64(cfg.PruneBatchSize) {
			return total, nil
		}
		if err := ctx.Err(); err != nil {
			return total, fmt.Errorf("%s: rate-limit prune: stopped after %d keys: %w", prefix, total, err)
		}
	}
}
