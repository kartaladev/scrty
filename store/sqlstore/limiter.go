package sqlstore

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/internal/pglimiter"
	"github.com/kartaladev/scrty/internal/unavailable"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/ratelimit"
)

// Limiter is a ratelimit.Limiter whose counts live in PostgreSQL, in the
// rate_limit_buckets table of the security-state migration set
// (migrate.SecurityState), so one limit holds across every replica that
// shares the database. The pgx adapter's limiter keeps the same rows in the
// same table, so the two count together.
//
// It keeps the in-memory limiter's semantics: per key, at most the limit's
// number of the newest failure stamps; a failure counts while it is strictly
// younger than the window; a key is exceeded once it holds the limit. Stamps
// are stored to the microsecond. A check is one primary-key read, and a
// record one upsert, each one round trip. A charge is one conditional upsert
// that decides and records in one statement, and a refund one update, so a
// flow that charges first holds its limit under any concurrency (Charge). It
// is safe for concurrent use.
//
// # Primary only
//
// The handle must reach only the primary. A standby lags, so a check answered
// there undercounts and a source can pass its limit, and it refuses every
// record. Verify refuses a standby, but cannot see a pooler or proxy that
// routes some connections to one later.
//
// # Transactions
//
// The limiter runs every statement on the *sql.DB it was built with. Unlike
// the package's stores, it never joins a transaction attached with WithTx,
// and has no WithTxResolver: a failure recorded inside the request's
// transaction would roll back when the request fails, which is exactly when
// it must count. There is no option to change this, because joining the
// transaction would break that guarantee.
//
// # Startup
//
// Constructors perform no I/O. Call Verify at startup, before traffic: it
// refuses a standby, an unsupported server, a database that is not UTF8, a
// missing, unlogged or temporary table, and a role that may not run the
// limiter's statements.
//
// # Pruning
//
// A key's row stays after its failures stop counting, until a prune deletes
// it. The prune belongs to LimiterFactory, which covers every namespace in
// the table: run ratelimit.ExpiryTask(factory). A consumer who builds
// limiters with NewLimiter only builds a factory over the same handle for the
// prune.
type Limiter struct {
	limiter ratelimit.Limiter
	check   limiterCheck

	// limit and window are the policy NewLimiter was given, kept so Policy
	// can report them; the wrapped limiter does not expose its own.
	limit  int
	window time.Duration
}

var (
	_ ratelimit.Limiter        = (*Limiter)(nil)
	_ ratelimit.PolicyReporter = (*Limiter)(nil)
)

// NewLimiter returns a Limiter counting up to limit failures per key within
// window, in namespace, over db.
//
// The namespace keeps one flow's buckets apart from every other's, and is
// required: two flows sharing a namespace would share their buckets. It may
// not contain a colon, as for every shared limiter, so a namespace valid on
// one shared backend is valid on the other. Keys are stored as given, except
// that a key longer than 512 bytes, one that itself starts with
// "sha256:", or one that is not valid UTF-8 or contains a NUL byte (which
// PostgreSQL's text type cannot store), is stored as "sha256:" and the hex
// digest of the key.
//
// Maximums: a limit of at most 400 and a namespace of at most 64 bytes,
// counted in bytes, not characters. They keep the widest row under 4 kB, which
// the migration's storage parameter (toast_tuple_target) keeps in-line, so a
// record never rewrites an out-of-line array. They have no override; a flow
// needing a larger limit belongs on the Redis limiter.
//
// Every replica must configure a namespace with the same limit and window.
// Replicas that disagree, as during a rollout, each count with their own
// window. Each record carries the longest window the key has been recorded
// with, and a key is pruned only once its newest failure is that long past,
// so a shorter-window record never removes failures that a longer-window
// replica still counts. Replicas that disagree on the limit trim the row to
// the lower limit when they record, so a higher-limit replica undercounts
// until its own records refill it.
//
// Defaults, each replaced by its option: time from the database's
// clock_timestamp(), read once per statement (WithLimiterClock); refusal of
// every check while the database cannot be reached
// (WithLimiterOnUnavailable); a 250ms operation timeout, which is also the
// record's lock timeout (WithLimiterOperationTimeout); a 1s probe interval
// (WithLimiterProbeInterval); sampled allow-mode logging every minute
// (WithLimiterUnavailableLogInterval); and slog.Default()
// (WithLimiterLogger).
//
// The window is counted in whole microseconds, the precision stamps are
// stored in; any part of it below a microsecond is dropped.
//
// It performs no I/O. A nil handle, an empty namespace or one containing a
// colon, a NUL byte or invalid UTF-8, or longer than 64 bytes, a limit below 1 or above 400, a window
// shorter than one microsecond, or an option it refuses, such as an operation
// timeout above 2147483647ms, is an error wrapping ratelimit.ErrConfig, and
// the Limiter is nil.
func NewLimiter(db *sql.DB, namespace string, limit int, window time.Duration, opts ...LimiterOption) (*Limiter, error) {
	cfg := newLimiterConfig(opts)
	if nilcheck.IsNil(db) {
		return nil, fmt.Errorf("%w: the database handle is nil", ratelimit.ErrConfig)
	}
	if err := pglimiter.ValidatePolicy(namespace, limit, window); err != nil {
		return nil, err
	}
	if err := cfg.core.Validate(); err != nil {
		return nil, err
	}

	window = window.Truncate(time.Microsecond)
	r := limiterRunner{db: db}
	wrapped, err := unavailable.Wrap(pglimiter.NewBackend(r, "sqlstore", namespace, limit, window, cfg.core),
		namespace, limit, window, cfg.core.Unavailable)
	if err != nil {
		return nil, err
	}

	return &Limiter{
		limiter: wrapped,
		check:   limiterCheck{runner: r, cfg: cfg.core},
		limit:   limit,
		window:  window,
	}, nil
}

// LimiterOption configures a Limiter or a LimiterFactory. Every default
// NewLimiter applies has an option here that replaces it. A nil LimiterOption
// is skipped.
//
// The limiter has an option type of its own, apart from the stores' Option,
// because the stores' options (WithTxResolver, WithIDGenerator, ...) mean
// nothing to it: it never joins a transaction, and stores no record with an
// identity.
type LimiterOption func(*limiterConfig)

// limiterConfig is what the limiter options describe: the shared limiter's
// configuration, kept inside a type of this package so LimiterOption names no
// internal type.
type limiterConfig struct {
	core pglimiter.Config
}

// newLimiterConfig returns the configuration opts describe, over the
// defaults (pglimiter.DefaultConfig), which start the decorator from
// unavailable.DefaultConfig.
func newLimiterConfig(opts []LimiterOption) limiterConfig {
	cfg := limiterConfig{core: pglimiter.DefaultConfig()}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return cfg
}

// WithLimiterClock makes the limiter stamp failures, compute its window and
// prune from clk, passed to the database as a parameter, in place of the
// default: the database's clock_timestamp(), read once per statement.
//
// The default orders every replica's stamps by one clock, the primary's. With
// an application clock, a replica whose clock runs ahead writes stamps the
// others count for longer, and one that runs behind counts failures that have
// already expired, so the replicas' clocks must agree to well within the
// window. It serves tests, and deployments that trust their own clock
// discipline more than the database's. clk is read to whole microseconds, the
// precision the limiter stores.
//
// clk also becomes the clock the outage handling measures its probe interval
// and record-error hold by, which otherwise is the system clock.
//
// A nil clock, typed nil included, fails construction with
// ratelimit.ErrConfig.
func WithLimiterClock(clk clock.Clock) LimiterOption {
	return func(c *limiterConfig) {
		c.core.Clock = clk
		c.core.ClockSet = true
		c.core.Unavailable.Clock = clk
	}
}

// WithLimiterOnUnavailable sets what the limiter does while the database
// cannot be reached. Default: ratelimit.UnavailableRefuse, which answers
// every check as exceeded, so every guarded flow refuses until the database
// is back.
//
// ratelimit.UnavailableFallbackToLocal counts in this process for the outage,
// so the effective limit is multiplied by the number of replicas while it
// lasts; it is the recommended mode for second-factor flows, whose users
// would otherwise be locked out of sign-in by an outage.
// ratelimit.UnavailableAllow lifts the limit for the outage, and suits only a
// flow with another bound in front of it.
//
// A mode other than the three ratelimit declares fails construction with
// ratelimit.ErrConfig.
func WithLimiterOnUnavailable(m ratelimit.UnavailableMode) LimiterOption {
	return func(c *limiterConfig) { c.core.Unavailable.Mode = m }
}

// WithLimiterOperationTimeout bounds each call to the database, records
// included, even when the caller's context has no deadline. Default: 250ms.
//
// A record also tells the server to stop waiting for a row another session
// holds after the same time (lock_timeout, transaction-local, in whole
// milliseconds and at least one), so a held row cannot queue records behind
// it on the server after the caller has given up.
//
// Only a call cut off by this timeout counts as an outage. A caller whose own
// deadline is shorter ends first, and is not taken for one; a deployment
// whose request deadlines are shorter than this timeout lowers it below them.
//
// A zero or negative timeout, or one above 2147483647ms (about 24.8 days),
// the most PostgreSQL accepts for lock_timeout, fails construction with
// ratelimit.ErrConfig.
func WithLimiterOperationTimeout(d time.Duration) LimiterOption {
	return func(c *limiterConfig) { c.core.Unavailable.Timeout = d }
}

// WithLimiterProbeInterval sets how long the limiter answers from its
// unavailable mode, without calling the database, after a call has failed;
// then one call probes it. Default: 1s. It applies in every mode, so that
// refusing during an outage costs nothing and does not exhaust the
// connection pool.
//
// A zero or negative interval fails construction with ratelimit.ErrConfig.
func WithLimiterProbeInterval(d time.Duration) LimiterOption {
	return func(c *limiterConfig) { c.core.Unavailable.ProbeInterval = d }
}

// WithLimiterUnavailableLogInterval sets how long, in
// ratelimit.UnavailableAllow mode, one written outage record suppresses
// further ones for the namespace. Default: ratelimit.DefaultLogInterval, one
// minute.
//
// Each written record, and a summary when the database is back, carries how
// many records were suppressed. An interval of zero or less writes every
// record, for a consumer whose own handler samples. The other modes write
// only their transitions, and are not sampled.
func WithLimiterUnavailableLogInterval(d time.Duration) LimiterOption {
	return func(c *limiterConfig) { c.core.Unavailable.LogInterval = d }
}

// WithLimiterLogger sets where the limiter writes its outage records: the
// move to and from a degraded mode. Default: slog.Default().
//
// A nil logger fails construction with ratelimit.ErrConfig, because the
// outage records would be lost.
func WithLimiterLogger(l *slog.Logger) LimiterOption {
	return func(c *limiterConfig) { c.core.Unavailable.Logger = l }
}

// WithLimiterPruneBatchSize sets how many keys one batch of the factory's
// prune removes. Each batch is its own transaction, and holds its victims'
// row locks only until it commits, so a record on a key being pruned waits at
// most one batch. Default: 1,000, whose batches took about 3ms each over a
// million idle keys; batches of 5,000 or more ran over 100ms, near the
// default operation timeout. On an overloaded server one batch can outlast
// the operation timeout, and a record behind it then fails as unavailable.
// A size below 1 fails construction with ratelimit.ErrConfig.
//
// Only a factory's prune uses it, but NewLimiter refuses a size below 1 too,
// as it refuses every invalid option.
func WithLimiterPruneBatchSize(n int) LimiterOption {
	return func(c *limiterConfig) { c.core.PruneBatchSize = n }
}

// Exceeded reports whether key holds the limit's number of failures within
// the window. It writes nothing and takes no row lock.
//
// An ended context answers true with its error before any I/O. While the
// database cannot be reached the answer comes from the unavailable mode
// (WithLimiterOnUnavailable): by default true, with an error wrapping
// ratelimit.ErrBackendUnavailable.
func (l *Limiter) Exceeded(ctx context.Context, key string) (bool, error) {
	return l.limiter.Exceeded(ctx, key)
}

// RecordFailure counts one failure for key. The caller's cancellation is
// ignored, because a caller that hangs up must still be charged for its
// attempt; the call is bounded by the operation timeout
// (WithLimiterOperationTimeout) instead, and the server stops waiting for a
// row another session holds after the same time.
//
// A failure that could not be recorded, a lock wait given up included, is an
// error handled by the unavailable mode: by default this replica holds the
// key as exceeded for one window, so a database that rejects writes but still
// answers reads cannot leave the source unthrottled.
func (l *Limiter) RecordFailure(ctx context.Context, key string) error {
	return l.limiter.RecordFailure(ctx, key)
}

// Charge records one failure for key and reports the key below its limit, or
// reports it at its limit and records nothing, in one conditional upsert on
// the key's row: concurrent charges of one key, from any replica, never hold
// more failures in the window than the limit. It implements ratelimit.Charger.
// The receipt carries the stamp as stored, to the microsecond; a refused charge
// returns the zero Receipt.
//
// An ended context is refused with its error before any I/O, and nothing is
// recorded. The caller's cancellation bounds the call, as for Exceeded, and so
// does the operation timeout (WithLimiterOperationTimeout), which is also the
// statement's lock timeout. While the database cannot be reached the answer
// comes from the unavailable mode (WithLimiterOnUnavailable): by default true,
// with an error wrapping ratelimit.ErrBackendUnavailable; in fall-back mode
// the charge is made on this replica's local count.
func (l *Limiter) Charge(ctx context.Context, key string) (ratelimit.Receipt, bool, error) {
	return l.limiter.Charge(ctx, key)
}

// Refund removes the one failure r recorded, while it is still in the
// window, in one statement on the key's row; of two failures stamped at the
// same instant it removes one. The zero Receipt does nothing. It implements
// ratelimit.Charger.
//
// The caller's cancellation is ignored, as for RecordFailure, and the call is
// bounded by the operation timeout instead. A refund that cannot reach the
// database is an error wrapping ratelimit.ErrBackendUnavailable, and the
// failure stays counted; in fall-back mode, during an outage, the refund is
// made on this replica's local count.
func (l *Limiter) Refund(ctx context.Context, r ratelimit.Receipt) error {
	return l.limiter.Refund(ctx, r)
}

// Policy reports the limit and window the limiter was built with
// (NewLimiter's arguments), the window in the whole microseconds it is
// counted in. Both are fixed at construction.
func (l *Limiter) Policy() (limit int, window time.Duration) {
	return l.limit, l.window
}

// Verify checks the database behind the limiter's handle, as
// LimiterFactory.Verify does. Call it at startup and refuse to serve on
// error.
func (l *Limiter) Verify(ctx context.Context) error { return l.check.verify(ctx) }

// limiterRunner runs the shared limiter's statements on the *sql.DB, never
// in a caller's transaction.
type limiterRunner struct{ db *sql.DB }

func (r limiterRunner) Exec(ctx context.Context, q string, args ...any) (pglimiter.Result, error) {
	return r.db.ExecContext(ctx, q, args...)
}

// ExecReadCommitted runs q as the only statement of a READ COMMITTED
// transaction of its own on the *sql.DB, whatever the database's default
// isolation is, and commits it. The transaction is rolled back on every other
// way out.
func (r limiterRunner) ExecReadCommitted(ctx context.Context, q string, args ...any) error {
	tx, err := beginReadCommitted(ctx, r.db)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, q, args...); err != nil {
		return err
	}

	return tx.Commit()
}

func (r limiterRunner) QueryRow(ctx context.Context, q string, args ...any) pglimiter.Row {
	return r.db.QueryRowContext(ctx, q, args...)
}

// QueryRowReadCommitted returns a row that, when scanned, runs q as the only
// statement of a READ COMMITTED transaction of its own on the *sql.DB, scans
// its one row and commits. The transaction is rolled back on every other way
// out.
func (r limiterRunner) QueryRowReadCommitted(ctx context.Context, q string, args ...any) pglimiter.Row {
	return readCommittedRow(func(dest ...any) error {
		tx, err := beginReadCommitted(ctx, r.db)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()

		if err := tx.QueryRowContext(ctx, q, args...).Scan(dest...); err != nil {
			return err
		}

		return tx.Commit()
	})
}

// readCommittedRow is a row whose Scan runs the statement it stands for.
type readCommittedRow func(dest ...any) error

func (f readCommittedRow) Scan(dest ...any) error { return f(dest...) }

var (
	_ ratelimit.Verifier = (*LimiterFactory)(nil)
	_ ratelimit.Verifier = (*Limiter)(nil)
)

// limiterCheck is what Verify checks with, and a factory's prune runs with:
// the runner over the handle, and the configuration whose clock and lock
// timeout the limiter's statements run with, so the probe runs them as the
// limiter does, and whose clock and batch size the prune uses.
type limiterCheck struct {
	runner limiterRunner
	cfg    pglimiter.Config
}

func (c limiterCheck) verify(ctx context.Context) error {
	return pglimiter.Verify(ctx, c.runner, "sqlstore", c.cfg)
}
