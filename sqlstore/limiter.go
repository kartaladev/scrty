package sqlstore

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/internal/pgschema"
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
// record one upsert, each one round trip. It is safe for concurrent use.
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
// refuses a standby, an unsupported server, a missing or unlogged table, and
// a role that may not run the limiter's statements.
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
// Maximums: a limit of at most 128 and a namespace of at most 64 bytes,
// counted in bytes, not characters. They keep the widest row under
// PostgreSQL's TOAST threshold, so a record never rewrites an out-of-line
// array. They have no override; a flow needing a larger limit belongs on the
// Redis limiter.
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
// colon, a NUL byte or invalid UTF-8, or longer than 64 bytes, a limit below 1 or above 128, a window
// shorter than one microsecond, or an option it refuses, such as an operation
// timeout above 2147483647ms, is an error wrapping ratelimit.ErrConfig, and
// the Limiter is nil.
func NewLimiter(db *sql.DB, namespace string, limit int, window time.Duration, opts ...LimiterOption) (*Limiter, error) {
	cfg := newLimiterConfig(opts)
	if err := validateLimiter(db, namespace, limit, window, cfg); err != nil {
		return nil, err
	}

	window = window.Truncate(time.Microsecond)
	b := &limiterBackend{
		db:          db,
		namespace:   namespace,
		limit:       limit,
		windowUS:    window.Microseconds(),
		clock:       cfg.clock,
		lockTimeout: lockTimeout(cfg.unavailable.Timeout),
	}
	wrapped, err := unavailable.Wrap(b, namespace, limit, window, cfg.unavailable)
	if err != nil {
		return nil, err
	}

	return &Limiter{
		limiter: wrapped,
		check:   newLimiterCheck(db, cfg),
		limit:   limit,
		window:  window,
	}, nil
}

func validateLimiter(db *sql.DB, namespace string, limit int, window time.Duration, cfg limiterConfig) error {
	switch {
	case nilcheck.IsNil(db):
		return fmt.Errorf("%w: the database handle is nil", ratelimit.ErrConfig)
	case namespace == "":
		return fmt.Errorf("%w: the namespace is empty, so this limiter would share buckets with every other", ratelimit.ErrConfig)
	case strings.Contains(namespace, ":"):
		return fmt.Errorf("%w: the namespace %q contains a colon, which separates it from the key", ratelimit.ErrConfig, namespace)
	case !utf8.ValidString(namespace) || strings.ContainsRune(namespace, 0):
		return fmt.Errorf("%w: the namespace must be valid UTF-8 without NUL bytes, which PostgreSQL's text type cannot store", ratelimit.ErrConfig)
	case len(namespace) > pgschema.LimiterMaxNamespace:
		return fmt.Errorf("%w: the namespace is %d bytes, longer than the %d bytes a bucket's row holds",
			ratelimit.ErrConfig, len(namespace), pgschema.LimiterMaxNamespace)
	case limit <= 0:
		return fmt.Errorf("%w: a limit of %d throttles every source from its first attempt", ratelimit.ErrConfig, limit)
	case limit > pgschema.LimiterMaxLimit:
		return fmt.Errorf("%w: a limit of %d is above %d, the most failure stamps a bucket's row holds",
			ratelimit.ErrConfig, limit, pgschema.LimiterMaxLimit)
	case window < time.Microsecond:
		return fmt.Errorf("%w: a window of %s is shorter than the microsecond stamps are stored in", ratelimit.ErrConfig, window)
	case cfg.unavailable.Timeout.Milliseconds() > pgschema.LimiterMaxLockTimeoutMS:
		return fmt.Errorf("%w: an operation timeout of %s is above the lock_timeout PostgreSQL accepts, at most %dms",
			ratelimit.ErrConfig, cfg.unavailable.Timeout, pgschema.LimiterMaxLockTimeoutMS)
	case cfg.clockSet && nilcheck.IsNil(cfg.clock):
		return fmt.Errorf("%w: the limiter clock is nil", ratelimit.ErrConfig)
	}
	return nil
}

// lockTimeout is the record's lock_timeout for an operation timeout d: whole
// milliseconds, at least one, since zero would turn the setting off.
func lockTimeout(d time.Duration) string {
	return fmt.Sprintf("%dms", max(d.Milliseconds(), 1))
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

// limiterBackend talks to the database; the decorator from
// internal/unavailable wraps it with the operation timeout, the breaker and
// the unavailable modes.
type limiterBackend struct {
	db          *sql.DB
	namespace   string
	limit       int
	windowUS    int64
	clock       clock.Clock // nil: the database's clock
	lockTimeout string
}

// now is the statements' now parameter: nil, which they read as the
// database's clock_timestamp(), or the application clock in whole
// microseconds.
func (b *limiterBackend) now() any {
	return limiterNow(b.clock)
}

// limiterNow is the now parameter for clk: nil for the database's clock.
func limiterNow(clk clock.Clock) any {
	if clk == nil {
		return nil
	}
	return clk.Now().UTC().Truncate(time.Microsecond)
}

func (b *limiterBackend) Exceeded(ctx context.Context, key string) (bool, error) {
	var n int
	err := b.db.QueryRowContext(ctx, pgschema.LimiterCheck,
		b.namespace, pgschema.LimiterKey(key), b.windowUS, b.now()).Scan(&n)
	if err != nil {
		return true, fmt.Errorf("sqlstore: rate-limit check: %w", err)
	}
	return n >= b.limit, nil
}

func (b *limiterBackend) RecordFailure(ctx context.Context, key string) error {
	_, err := b.db.ExecContext(ctx, pgschema.LimiterRecord,
		b.namespace, pgschema.LimiterKey(key), b.limit, b.windowUS, b.now(), b.lockTimeout)
	if err != nil {
		return fmt.Errorf("sqlstore: rate-limit record: %w", err)
	}
	return nil
}
