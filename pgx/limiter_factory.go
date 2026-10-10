package pgx

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/ratelimit"
)

// LimiterFactory builds the PostgreSQL limiter of each flow that asks for
// one, so a consumer replaces the storage of every flow without restating any
// flow's limit or window. Pass it to httpsec.WithRateLimiterFactory, or to the
// component options of the mfa, recovery and passkey packages.
//
// A namespace asked for twice with the same limit and window gives a second
// limiter over the same buckets, exactly as another replica would: two chains
// built from one factory, or a flow constructed twice, count together. Asked
// for with a different limit or window, it is refused, because one bucket
// cannot hold two policies. The factory cannot see other processes, so every
// replica must still configure a namespace the same way.
//
// The factory is also the table's pruner: hand it to ratelimit.ExpiryTask, and
// run that task in the deployment's expiry.Runner. One prune covers every
// namespace in the table, whichever factory or NewLimiter call built its
// limiters, so a deployment needs one such task however many factories it
// has. A consumer who built limiters with NewLimiter only builds a factory
// over the same pool for the prune.
//
// Like the limiters it builds, it needs a pool that reaches only the
// primary, ignores any transaction a caller has attached, and should be
// checked with Verify at startup; see Limiter.
//
// It is safe for concurrent use.
type LimiterFactory struct {
	pool  *pgxpool.Pool
	opts  []LimiterOption
	clock clock.Clock // nil: the database's clock
	check limiterCheck

	mu sync.Mutex
	// built holds the policy each namespace was first built with.
	built map[string]limiterPolicy
}

// limiterPolicy is the limit and window a namespace was built with.
type limiterPolicy struct {
	limit  int
	window time.Duration
}

func (p limiterPolicy) String() string { return fmt.Sprintf("%d per %s", p.limit, p.window) }

var (
	_ ratelimit.LimiterFactory = (*LimiterFactory)(nil)
	_ ratelimit.Pruner         = (*LimiterFactory)(nil)
)

// limiterFactoryProbeNamespace is the namespace of the limiter
// NewLimiterFactory builds, and discards, to check the pool and options
// once.
const limiterFactoryProbeNamespace = "factory"

// NewLimiterFactory returns a LimiterFactory whose limiters count in the
// rate_limit_buckets table of the database behind pool, each configured by
// opts. The defaults are NewLimiter's: the database's clock, refusal while
// the database cannot be reached, a 250ms operation timeout, a 1s probe
// interval, sampled allow-mode logging every minute, and slog.Default().
//
// It checks pool and opts as NewLimiter would, so a wiring mistake fails here
// rather than at the first flow's constructor: a nil pool (a typed nil included), or an option
// NewLimiter refuses, is an error wrapping ratelimit.ErrConfig. It performs
// no I/O; call Verify before traffic to check the database itself.
//
// pool must reach only the primary, and the security-state migration set
// (migrate.SecurityState) must have been applied to its database; Verify
// checks both.
func NewLimiterFactory(pool *pgxpool.Pool, opts ...LimiterOption) (*LimiterFactory, error) {
	opts = slices.Clone(opts)
	if _, err := NewLimiter(pool, limiterFactoryProbeNamespace, 1, time.Second, opts...); err != nil {
		return nil, err
	}

	cfg := newLimiterConfig(opts)
	return &LimiterFactory{
		pool:  pool,
		opts:  opts,
		clock: cfg.clock,
		check: newLimiterCheck(pool, cfg),
		built: map[string]limiterPolicy{},
	}, nil
}

// NewLimiter returns a limiter counting up to limit failures per key within
// window in namespace, as NewLimiter does with the factory's pool and
// options. The returned limiter is a *Limiter.
//
// A namespace this factory has already built with a different limit or
// window is an error wrapping ratelimit.ErrConfig, naming the namespace and
// both policies; so is anything NewLimiter refuses, a limit above 128 or a
// namespace longer than 64 bytes included. A refused request does not claim
// the namespace. On error the limiter is nil.
func (f *LimiterFactory) NewLimiter(namespace string, limit int, window time.Duration) (ratelimit.Limiter, error) {
	// The window is counted in whole microseconds, so 1m and 1m+500ns are one
	// policy.
	asked := limiterPolicy{limit: limit, window: window.Truncate(time.Microsecond)}

	f.mu.Lock()
	defer f.mu.Unlock()

	if p, ok := f.built[namespace]; ok && p != asked {
		return nil, fmt.Errorf("%w: namespace %q is already built with %s, and was asked for %s; one bucket cannot hold two policies",
			ratelimit.ErrConfig, namespace, p, asked)
	}
	l, err := NewLimiter(f.pool, namespace, limit, window, f.opts...)
	if err != nil {
		return nil, err
	}
	f.built[namespace] = asked

	return l, nil
}

// Prune deletes every key, in every namespace of the table, whose newest
// failure is at least the longest window any instance recorded the key with
// old, as the factory's clock tells (the database's by default, or
// WithLimiterClock's), and reports how many it deleted. No instance still
// counts any failure of such a key, so a prune never frees quota. It accepts
// no cutoff.
//
// It is one statement. Rows another session holds, such as a record in
// flight, are skipped rather than waited for, and kept until a later prune. It
// reads the whole table, so its cost grows with the number of keys; it applies
// no operation timeout of its own, and is bounded by ctx, which an
// expiry.Runner bounds with its run timeout.
//
// Run it through ratelimit.ExpiryTask(f). A database failure is an error
// wrapping the driver's, with nothing deleted.
func (f *LimiterFactory) Prune(ctx context.Context) (int, error) {
	tag, err := f.pool.Exec(ctx, pgschema.LimiterPrune, limiterNow(f.clock))
	if err != nil {
		return 0, fmt.Errorf("pgx: rate-limit prune: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// Verify checks, before traffic, that the database behind the factory's
// pool can hold its limits; no constructor calls it, because constructors
// perform no I/O. Call it at startup and refuse to serve on error.
//
// It checks, in order, and refuses with an error wrapping ratelimit.ErrConfig
// that names the cause:
//   - a server in recovery: a standby lags, so it undercounts, and refuses
//     writes;
//   - a server older than PostgreSQL 15 (server_version_num 150000);
//   - a rate_limit_buckets table that does not resolve through the
//     connection's search_path, naming the security-state migration set; a
//     table of that name in a schema outside the search_path does not count;
//   - an unlogged table, which a crash truncates and a standby never
//     receives, so a failover would reset every limit to zero;
//   - a role that may not run the limiter's record, check or prune
//     statements (SQLSTATE 42501), naming the statement refused.
//
// The last check runs each statement once, on a probe row of its own: an
// empty namespace, which no limiter can have, and a random key. The row is
// deleted in the same call.
//
// A database that cannot be reached, or a ctx that ends, is an error that does
// not wrap ratelimit.ErrConfig. No error repeats the server's text.
//
// What Verify cannot see: a pooler or proxy that later routes some of the
// pool's connections to a standby. The pool must reach only the primary.
func (f *LimiterFactory) Verify(ctx context.Context) error { return f.check.verify(ctx) }
