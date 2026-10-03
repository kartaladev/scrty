// Package scrtyredis is a ratelimit.Limiter over Redis or Valkey, so one limit
// holds across every replica of an application instead of per process.
//
// # Wiring
//
// NewLimiterFactory builds a ratelimit.LimiterFactory over a go-redis client.
// Hand it to httpsec.WithRateLimiterFactory, or to the factory options of the
// mfa, recovery and passkey packages, and every flow builds its own limiter in
// its own namespace with its own limit and window; only the storage changes.
// NewLimiter builds one limiter directly, for a flow wired by hand.
//
// Construction performs no I/O. Call Verify on the factory or a limiter at
// startup, before traffic, and refuse to serve when it fails: it checks the
// server version, the eviction policy, and that the scripts load and run once
// on a probe key.
//
// The client must set ContextTimeoutEnabled in its options:
//
//	client := redis.NewClient(&redis.Options{Addr: addr, ContextTimeoutEnabled: true})
//
// Without it go-redis reads past a context's deadline, so neither the
// operation timeout (WithOperationTimeout) nor Verify's ctx bounds a call to a
// server that hangs, and a check waits the server out. The constructors refuse
// a *redis.Client, *redis.ClusterClient or *redis.Ring that leaves it off; a
// client of another type cannot be inspected, and must honour context
// deadlines itself.
//
// # Semantics
//
// The limiter keeps the in-memory limiter's sliding window: per key, at most
// the limit's number of the newest failure stamps, each counting while it is
// strictly younger than the window. Stamps are stored to the microsecond, and
// windows are counted in whole microseconds. Time is the server's, read with
// TIME inside each operation, so every replica orders its stamps by one clock;
// WithLimiterClock replaces it.
//
// One namespace holds one policy. A factory refuses a namespace asked for
// twice with a different limit or window. It cannot see other processes, so
// every replica must configure each namespace the same way.
//
// # Server requirements
//
// The server must be Redis 7.0 or later, or Valkey 7.2 or later.
//
// Every command must go to the primary: a replica lags, and a check answered
// there undercounts, so a source can pass its limit. A *redis.ClusterClient
// with ReadOnly, RouteByLatency or RouteRandomly set is refused at
// construction; other client types do not expose where they send reads, and
// must be configured to send them to the primary.
//
// The server must run with maxmemory-policy noeviction. Any evicting policy,
// volatile-* included because every limiter key has a lifetime, can drop a key
// whose failures still count, and so disarm that source's limit. Verify refuses
// one, and warns when it cannot read the policy (WithEvictionPolicyCheck).
// Under noeviction a full server rejects writes while it still answers reads;
// a failure that could not be recorded is then held against its key on this
// replica for one window, so the source stays refused.
//
// Under ACLs, the limiter needs EVAL, EVALSHA, EVAL_RO, EVALSHA_RO and
// SCRIPT LOAD on keys under its prefix (DefaultKeyPrefix unless WithKeyPrefix
// replaces it), and the commands its scripts run, because the server checks
// those against the caller's ACL too: TIME, ZRANGE, ZADD, ZREMRANGEBYRANK,
// ZREM, PTTL, PEXPIRE and ZCOUNT. Verify also needs INFO and CONFIG GET. As
// ACL rules, for the default prefix:
//
//	~scrty:ratelimit:* +eval +evalsha +eval_ro +evalsha_ro +script|load
//	+time +zrange +zadd +zremrangebyrank +zrem +pttl +pexpire +zcount
//	+info +config|get
//
// Verify runs both scripts once, so a missing permission fails it, with
// ratelimit.ErrConfig naming what is missing, rather than every record.
//
// On a cluster, Verify reads INFO and CONFIG GET from one node only, so it
// checks that node's version and eviction policy alone: every node must be
// configured alike.
//
// # Outages
//
// While the server cannot be reached the limiter fails closed by default:
// every check is answered as exceeded, so every guarded flow refuses, and a
// circuit breaker answers without waiting for the operation timeout until a
// probe finds the server back (WithOnUnavailable, WithOperationTimeout,
// WithUnavailableProbeInterval). For second-factor flows,
// ratelimit.UnavailableFallBackToLocal is recommended instead: it keeps a
// per-replica bound during the outage rather than locking every user out of
// sign-in. The mode applies to every flow built from one factory, so keep the
// default refusal for the source-keyed flows the chain guards, and give
// second-factor flows a factory of their own over the same client.
package scrtyredis
