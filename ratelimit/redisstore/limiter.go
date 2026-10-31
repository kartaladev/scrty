package redisstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/internal/unavailable"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/ratelimit"
)

// maxRawKeyLen is the longest key stored as given. A longer key is stored as
// hashedKeyPrefix and its hex digest, the same on every replica.
const maxRawKeyLen = 512

// Limiter is a ratelimit.Limiter whose counts live in Redis or Valkey, so one
// limit holds across every replica that shares the server.
//
// It keeps the in-memory limiter's semantics: per key, at most the limit's
// number of the newest failure stamps; a failure counts while it is strictly
// younger than the window; a key is exceeded once it holds the limit. Stamps
// are stored to the microsecond. A charge decides and records in one script,
// so a flow that charges first holds its limit under any concurrency
// (Charge). It is safe for concurrent use.
type Limiter struct {
	limiter ratelimit.Limiter
	check   serverCheck

	// limit and window are the policy NewLimiter was given, kept so Policy can
	// report them; the wrapped limiter does not expose its own.
	limit  int
	window time.Duration
}

var (
	_ ratelimit.Limiter        = (*Limiter)(nil)
	_ ratelimit.PolicyReporter = (*Limiter)(nil)
)

// NewLimiter returns a Limiter counting up to limit failures per key within
// window, in namespace, over client.
//
// The namespace keeps one flow's buckets apart from every other's, and is
// required: two flows sharing a namespace would share their buckets. Every
// stored key is the prefix (DefaultKeyPrefix unless WithKeyPrefix replaces
// it), the namespace, a colon and the caller's key; keys are stored as given,
// except that a key longer than 512 bytes, or one that itself starts with
// "sha256:", is stored as "sha256:" and the hex digest of the key.
//
// Every replica must configure a namespace with the same limit and window.
// Replicas that disagree, as during a rollout, each count with their own
// window. Each record carries the longest window the key has been recorded
// with, and the key lives at least that long after its newest failure, so a
// shorter-window record never expires failures that a longer-window replica
// recorded and still counts. What this cannot cover: a key recorded only by
// shorter-window replicas lives for the shorter window, even though a
// longer-window replica checking it would have counted those failures for
// longer.
//
// The client must send every command to the primary. A replica lags, and a
// check answered there undercounts, so a source can pass its limit. A
// *redis.ClusterClient with ReadOnly, RouteByLatency or RouteRandomly set is
// refused; other client types do not expose where they send reads, and must be
// configured to send them to the primary.
//
// The client must set ContextTimeoutEnabled in its options. Without it
// go-redis reads past a context's deadline, so neither the operation timeout
// (WithOperationTimeout) nor a caller's deadline bounds a call to a server
// that hangs. A *redis.Client (a failover client included), a
// *redis.ClusterClient or a *redis.Ring that leaves it off is refused; any
// other implementation of redis.UniversalClient cannot be inspected, and must
// honour context deadlines itself.
//
// The window is counted in whole microseconds, the precision stamps are
// stored in; any part of it below a microsecond is dropped.
//
// It performs no I/O. A nil client (typed nil included), a cluster client
// reading from replicas, a client without ContextTimeoutEnabled, an empty
// namespace or one containing a colon, a
// non-positive limit, a window shorter than one microsecond, or an option it
// refuses is an error wrapping ratelimit.ErrConfig.
func NewLimiter(client redis.UniversalClient, namespace string, limit int, window time.Duration, opts ...Option) (*Limiter, error) {
	cfg := newConfig(opts)
	if err := validate(client, namespace, limit, window, cfg); err != nil {
		return nil, err
	}

	b := &backend{
		client:   client,
		prefix:   cfg.prefix + namespace + ":",
		limit:    strconv.Itoa(limit),
		limitN:   int64(limit),
		windowUS: strconv.FormatInt(window.Microseconds(), 10),
		clock:    cfg.clock,
	}
	wrapped, err := unavailable.Wrap(b, namespace, limit, window, cfg.unavailable)
	if err != nil {
		return nil, err
	}

	return &Limiter{
		limiter: wrapped,
		check:   newServerCheck(client, cfg),
		limit:   limit,
		window:  window.Truncate(time.Microsecond),
	}, nil
}

func validate(client redis.UniversalClient, namespace string, limit int, window time.Duration, cfg config) error {
	switch {
	case nilcheck.IsNil(client):
		return fmt.Errorf("%w: the Redis client is nil", ratelimit.ErrConfig)
	case namespace == "":
		return fmt.Errorf("%w: the namespace is empty, so this limiter would share buckets with every other", ratelimit.ErrConfig)
	case strings.Contains(namespace, ":"):
		return fmt.Errorf("%w: the namespace %q contains a colon, which separates it from the key", ratelimit.ErrConfig, namespace)
	case limit <= 0:
		return fmt.Errorf("%w: a limit of %d throttles every source from its first attempt", ratelimit.ErrConfig, limit)
	case window < time.Microsecond:
		return fmt.Errorf("%w: a window of %s is shorter than the microsecond stamps are stored in", ratelimit.ErrConfig, window)
	case cfg.prefix == "":
		return fmt.Errorf("%w: the key prefix is empty, so the limiter's keys would be unmarked", ratelimit.ErrConfig)
	case cfg.clockSet && nilcheck.IsNil(cfg.clock):
		return fmt.Errorf("%w: the limiter clock is nil", ratelimit.ErrConfig)
	}
	if err := replicaReads(client); err != nil {
		return err
	}
	return contextTimeouts(client)
}

// contextTimeouts refuses a client whose options leave ContextTimeoutEnabled
// off, for the client types that expose it. Without it go-redis reads past a
// context's deadline, so neither the operation timeout nor a caller's deadline
// bounds a call to a server that hangs: a check would wait the server out and
// answer from whatever it finally says.
func contextTimeouts(client redis.UniversalClient) error {
	var enabled bool
	switch c := client.(type) {
	case *redis.Client:
		enabled = c.Options().ContextTimeoutEnabled
	case *redis.ClusterClient:
		enabled = c.Options().ContextTimeoutEnabled
	case *redis.Ring:
		enabled = c.Options().ContextTimeoutEnabled
	default:
		return nil
	}
	if enabled {
		return nil
	}
	return fmt.Errorf("%w: the client leaves ContextTimeoutEnabled off, so a context's deadline does not bound a call to a server that hangs; "+
		"set ContextTimeoutEnabled in the client's options", ratelimit.ErrConfig)
}

// replicaReads refuses a client that sends reads to replicas, where go-redis
// exposes the setting: a cluster client. A lagging replica undercounts, so a
// check answered there can let a source past its limit. The routing options
// are named before ReadOnly, which go-redis turns on with either of them.
func replicaReads(client redis.UniversalClient) error {
	cc, ok := client.(*redis.ClusterClient)
	if !ok {
		return nil
	}
	opts := cc.Options()
	var setting string
	switch {
	case opts.RouteByLatency:
		setting = "RouteByLatency"
	case opts.RouteRandomly:
		setting = "RouteRandomly"
	case opts.ReadOnly:
		setting = "ReadOnly"
	default:
		return nil
	}
	return fmt.Errorf("%w: the cluster client sets %s, which sends reads to replicas; the limiter must read from the primary, because a lagging replica undercounts",
		ratelimit.ErrConfig, setting)
}

// Exceeded reports whether key holds the limit's number of failures within
// the window. It writes nothing, and leaves the key's lifetime as it is.
//
// An ended context answers true with its error before any I/O. While the
// server cannot be reached the answer comes from the unavailable mode
// (WithOnUnavailable): by default true, with an error wrapping
// ratelimit.ErrBackendUnavailable.
func (l *Limiter) Exceeded(ctx context.Context, key string) (bool, error) {
	return l.limiter.Exceeded(ctx, key)
}

// RecordFailure counts one failure for key, and keeps the key at least one
// window from now. The caller's cancellation is ignored, because a caller that
// hangs up must still be charged for its attempt; the call is bounded by the
// operation timeout (WithOperationTimeout) instead.
//
// A failure that could not be recorded is an error, handled by the
// unavailable mode: by default this replica holds the key as exceeded for one
// window, so a server that rejects writes but still answers reads cannot leave
// the source unthrottled.
func (l *Limiter) RecordFailure(ctx context.Context, key string) error {
	return l.limiter.RecordFailure(ctx, key)
}

// Charge records one failure for key and reports the key below its limit, or
// reports it at its limit and records nothing, in one script the server runs
// without interleaving any other command: concurrent charges of one key, from
// any replica, never hold more failures in the window than the limit. It
// implements ratelimit.Charger. An accepted charge also keeps the key at least
// one window from now, as RecordFailure does. The receipt carries the stamp as
// stored, to the microsecond; a refused charge returns the zero Receipt.
//
// An ended context is refused with its error before any I/O, and nothing is
// recorded. The caller's cancellation bounds the call, as for Exceeded, and so
// does the operation timeout (WithOperationTimeout). While the server cannot
// be reached the answer comes from the unavailable mode (WithOnUnavailable):
// by default true, with an error wrapping ratelimit.ErrBackendUnavailable; in
// fall-back mode the charge is made on this replica's local count.
func (l *Limiter) Charge(ctx context.Context, key string) (ratelimit.Receipt, bool, error) {
	return l.limiter.Charge(ctx, key)
}

// Refund removes the one failure r recorded, while it is still in the window,
// in one script; of two failures stamped in the same microsecond it removes
// one. It leaves the key's lifetime as it is. The zero Receipt does nothing.
// It implements ratelimit.Charger.
//
// The caller's cancellation is ignored, as for RecordFailure, and the call is
// bounded by the operation timeout instead. A refund that cannot reach the
// server is an error wrapping ratelimit.ErrBackendUnavailable, and the failure
// stays counted; in fall-back mode, during an outage, the refund is made on
// this replica's local count.
func (l *Limiter) Refund(ctx context.Context, r ratelimit.Receipt) error {
	return l.limiter.Refund(ctx, r)
}

// Policy reports the limit and window the limiter was built with
// (NewLimiter's arguments), the window in the whole microseconds it is counted
// in. Both are fixed at construction.
func (l *Limiter) Policy() (limit int, window time.Duration) {
	return l.limit, l.window
}

// backend talks to the server; the decorator from internal/unavailable wraps
// it with the operation timeout, the breaker and the unavailable modes.
type backend struct {
	client redis.UniversalClient
	// prefix is the key prefix and the namespace, with its separator.
	prefix   string
	limit    string
	limitN   int64
	windowUS string
	// clock is nil in server-clock mode.
	clock clock.Clock
}

// now is the script's "now" argument: empty for the server's TIME, or the
// application clock in whole microseconds.
func (b *backend) now() string {
	if b.clock == nil {
		return ""
	}
	return strconv.FormatInt(b.clock.Now().UnixMicro(), 10)
}

func (b *backend) Exceeded(ctx context.Context, key string) (bool, error) {
	n, err := exceededScript.RunRO(ctx, b.client, []string{b.key(key)}, b.now(), b.windowUS).Int64()
	if err != nil {
		return true, err
	}
	return n >= b.limitN, nil
}

func (b *backend) RecordFailure(ctx context.Context, key string) error {
	return recordScript.Run(ctx, b.client, []string{b.key(key)}, b.now(), b.windowUS, b.limit, memberSuffix()).Err()
}

// Charge runs chargeScript. A refusal is the zero Receipt; an accepted charge
// carries the stored stamp, in whole microseconds, and the caller's key.
func (b *backend) Charge(ctx context.Context, key string) (ratelimit.Receipt, bool, error) {
	stamp, err := chargeScript.Run(ctx, b.client, []string{b.key(key)}, b.now(), b.windowUS, b.limit, memberSuffix()).Int64()
	switch {
	case err != nil:
		return ratelimit.Receipt{}, true, err
	case stamp < 0:
		return ratelimit.Receipt{}, true, nil
	}
	return ratelimit.NewReceipt(key, time.UnixMicro(stamp)), false, nil
}

// Refund runs refundScript for r's stamp in whole microseconds. The zero
// Receipt sends nothing.
func (b *backend) Refund(ctx context.Context, r ratelimit.Receipt) error {
	if r.Stamp().IsZero() {
		return nil
	}
	return refundScript.Run(ctx, b.client, []string{b.key(r.Key())}, b.now(), b.windowUS,
		strconv.FormatInt(r.Stamp().UnixMicro(), 10)).Err()
}

func (b *backend) key(key string) string {
	return b.prefix + mappedKey(key)
}

// memberSuffix is the random part of a stamp's member, so that two failures
// stamped in the same microsecond are kept as two.
func memberSuffix() string {
	var buf [8]byte
	_, _ = rand.Read(buf[:]) // crypto/rand.Read never returns an error
	return hex.EncodeToString(buf[:])
}

// hashedKeyPrefix marks a stored key that is a digest of the caller's key.
const hashedKeyPrefix = "sha256:"

// mappedKey is the caller's key as stored: as given up to maxRawKeyLen bytes,
// and hashedKeyPrefix with the hex digest beyond. A key that already starts
// with hashedKeyPrefix is hashed too, whatever its length, so a short key
// spelled like a digest never shares the bucket of the long key it spells.
func mappedKey(key string) string {
	if len(key) <= maxRawKeyLen && !strings.HasPrefix(key, hashedKeyPrefix) {
		return key
	}
	sum := sha256.Sum256([]byte(key))
	return hashedKeyPrefix + hex.EncodeToString(sum[:])
}

// storageKey is the stored key for key in namespace under prefix.
func storageKey(prefix, namespace, key string) string {
	return prefix + namespace + ":" + mappedKey(key)
}

// The scripts keep, per key, one sorted set of failure stamps. Each score is a
// stamp in microseconds. Each member is "<stamp>:<carried window>:<suffix>":
// the stamp, the longest window in microseconds any instance had recorded the
// key with when this member was added, and a random suffix, so two failures in
// the same microsecond are two members. Only the scripts that record or refund
// read a member's carried window; a member that does not have that shape is
// ignored. Each script touches only the one key it declares, so it runs on
// Redis Cluster without hash tags.
//
// Each reads "now" from ARGV[1], or from the server's TIME when ARGV[1] is
// empty, and the window in microseconds from ARGV[2].
//
// A stamp is about 1.7e15 microseconds, exact in Lua's double but not in its
// default number-to-string conversion, which keeps 14 significant digits. A
// number concatenated into a string is therefore formatted with %.0f; one
// passed to redis.call as a number is converted by the server at full
// precision.

// recordScript records one failure. ARGV[3] is the limit and ARGV[4] the
// member's random suffix. It adds now, keeps the newest limit stamps, and
// makes the key live at least the carried window from now.
//
// It does not drop stamps older than its own window. They are already outside
// what exceededScript counts with that window, and the newest-limit cap
// bounds the set, so the count is the same either way; but another replica
// configured with a longer window, as during a rollout, still counts them, and
// a shorter-window replica trimming by its own window would disarm that
// replica's limit.
//
// For the same reason the lifetime covers the longest window the key has been
// recorded with, not only the recording instance's own. The carried window is
// the largest of this instance's window and the one every remaining member
// carries, so a shorter-window record made late in a longer window cannot
// expire the key while the longer-window replica still counts it. Every member
// is read, not only the newest, so a member stamped below the newest, under
// application-clock skew, cannot drop the carried window; the newest-limit cap
// bounds that scan. Only durations are compared, so it holds in both clock
// modes.
//
// The invariant is that the newest member always carries the longest window
// seen. The trim can remove the member that carried it, when application-clock
// skew stamps a longer-window record below a shorter-window one, so after the
// trim the newest survivor is rewritten, same score, stamp and suffix, to carry
// the carried window if it carries less.
//
// The lifetime, rounded up to whole milliseconds, is only ever extended: it is
// set only when the key's remaining lifetime is shorter. PTTL answers -1 for a
// key with no lifetime at all, which is shorter, so such a key gains one;
// PEXPIRE ... GT alone would leave it without, because GT reads no lifetime as
// an infinite one.
var recordScript = redis.NewScript(luaNow + luaRecord + `
return 1
`)

// luaNow sets now from ARGV[1], or from the server's TIME when it is empty.
const luaNow = `
local now
if ARGV[1] == '' then
  local t = redis.call('TIME')
  now = tonumber(t[1]) * 1000000 + tonumber(t[2])
else
  now = tonumber(ARGV[1])
end
`

// luaCarriedWindow sets carried to the largest of window and the window every
// member of KEYS[1] carries.
const luaCarriedWindow = `
local carried = window
for _, m in ipairs(redis.call('ZRANGE', KEYS[1], 0, -1)) do
  local w = tonumber(string.match(m, '^[^:]+:([^:]+):'))
  if w and w > carried then carried = w end
end
`

// luaCarryOnNewest rewrites the newest member of KEYS[1], same score, stamp
// and suffix, to carry the carried window if it carries less.
const luaCarryOnNewest = `
local newest = redis.call('ZRANGE', KEYS[1], -1, -1, 'WITHSCORES')
if newest[1] then
  local stamp, w, suffix = string.match(newest[1], '^([^:]+):([^:]+):(.*)$')
  w = tonumber(w)
  if w and w < carried then
    redis.call('ZREM', KEYS[1], newest[1])
    redis.call('ZADD', KEYS[1], newest[2],
      stamp .. ':' .. string.format('%.0f', carried) .. ':' .. suffix)
  end
end
`

// luaRecord is recordScript's body after now is set: it adds now, keeps the
// newest limit stamps, keeps the carried window on the newest member and
// extends the key's lifetime, as recordScript's comment describes.
const luaRecord = `
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
` + luaCarriedWindow + `
redis.call('ZADD', KEYS[1], now,
  string.format('%.0f', now) .. ':' .. string.format('%.0f', carried) .. ':' .. ARGV[4])
redis.call('ZREMRANGEBYRANK', KEYS[1], 0, -(limit + 1))
` + luaCarryOnNewest + `
local ttl_ms = math.ceil(carried / 1000)
if redis.call('PTTL', KEYS[1]) < ttl_ms then
  redis.call('PEXPIRE', KEYS[1], ttl_ms)
end
`

// chargeScript records one failure only while the key holds fewer than the
// limit within the window, deciding and recording in one script, which the
// server runs without interleaving any other command. Its arguments are
// recordScript's. It counts the stamps strictly after now - window, as
// exceededScript does; at the limit it returns -1 and writes nothing, the
// key's lifetime included. Below it, it records exactly as recordScript does
// and returns now, the stamp it stored, in microseconds.
//
// Like recordScript it does not drop stamps older than its own window, so a
// longer-window replica keeps counting them. The stamp it adds is never the
// one the newest-limit trim removes: every member at or after now is inside
// the window, and fewer than limit are.
var chargeScript = redis.NewScript(luaNow + `
if redis.call('ZCOUNT', KEYS[1], string.format('(%.0f', now - tonumber(ARGV[2])), '+inf') >= tonumber(ARGV[3]) then
  return -1
end
` + luaRecord + `
return now
`)

// refundScript removes one member whose stamp is ARGV[3], in microseconds,
// while that stamp is strictly after now - window, and returns how many it
// removed: 1, or 0 when the stamp has left the window or is not held. Of two
// members with one stamp it removes one. It reads now and the window as the
// other scripts do.
//
// The member it removes may be the one carrying the longest window, so, as
// after recordScript's trim, the newest survivor is rewritten to carry the
// window the members carried before the removal. It leaves the key's
// lifetime as it is: lifetimes are only ever extended.
var refundScript = redis.NewScript(luaNow + `
local window = tonumber(ARGV[2])
if tonumber(ARGV[3]) <= now - window then
  return 0
end
local victim = redis.call('ZRANGE', KEYS[1], ARGV[3], ARGV[3], 'BYSCORE', 'LIMIT', 0, 1)
if not victim[1] then
  return 0
end
` + luaCarriedWindow + `
redis.call('ZREM', KEYS[1], victim[1])
` + luaCarryOnNewest + `
return 1
`)

// exceededScript counts the stamps strictly after now - window. It writes
// nothing, the key's lifetime included, and runs with EVALSHA_RO.
var exceededScript = redis.NewScript(`
local now
if ARGV[1] == '' then
  local t = redis.call('TIME')
  now = tonumber(t[1]) * 1000000 + tonumber(t[2])
else
  now = tonumber(ARGV[1])
end
return redis.call('ZCOUNT', KEYS[1], string.format('(%.0f', now - tonumber(ARGV[2])), '+inf')
`)
