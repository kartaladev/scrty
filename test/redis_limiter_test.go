package test

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/ratelimit"
	scrtyredis "github.com/kartaladev/scrty/redis"
)

// recordScriptGTOnly is the record script with its lifetime step written as
// PEXPIRE ... GT alone. GT reads a key with no lifetime as living forever, so
// such a key never gains one. It is kept as the broken twin of the "no
// lifetime" case, which must fail against it.
var recordScriptGTOnly = redis.NewScript(`
local now
if ARGV[1] == '' then
  local t = redis.call('TIME')
  now = tonumber(t[1]) * 1000000 + tonumber(t[2])
else
  now = tonumber(ARGV[1])
end
redis.call('ZADD', KEYS[1], now, string.format('%.0f', now) .. ':' .. ARGV[4])
redis.call('ZREMRANGEBYRANK', KEYS[1], 0, -(tonumber(ARGV[3]) + 1))
redis.call('PEXPIRE', KEYS[1], math.ceil(tonumber(ARGV[2]) / 1000), 'GT')
return 1
`)

// recordScriptOwnWindowOnly is the record script that sets the key's
// lifetime from the recording instance's own window only, as long as that is
// longer than what is left. A shorter-window record made late in a longer
// window then expires the key while the longer-window instance still counts
// it. It is kept as the broken twin of the "late shorter-window record" case,
// which must fail against it.
var recordScriptOwnWindowOnly = redis.NewScript(`
local now
if ARGV[1] == '' then
  local t = redis.call('TIME')
  now = tonumber(t[1]) * 1000000 + tonumber(t[2])
else
  now = tonumber(ARGV[1])
end
local window_us = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
redis.call('ZADD', KEYS[1], now, string.format('%.0f', now) .. ':' .. ARGV[4])
redis.call('ZREMRANGEBYRANK', KEYS[1], 0, -(limit + 1))
local ttl_ms = math.ceil(window_us / 1000)
if redis.call('PTTL', KEYS[1]) < ttl_ms then
  redis.call('PEXPIRE', KEYS[1], ttl_ms)
end
return 1
`)

// redisRecorder records one failure for key through some implementation of
// the record operation, configured with limit and window.
type redisRecorder func(t *testing.T, client *redis.Client, namespace string, limit int, window time.Duration) func(key string)

// limiterRecorder records through the Redis limiter itself.
func limiterRecorder(t *testing.T, client *redis.Client, namespace string, limit int, window time.Duration) func(string) {
	t.Helper()
	l := newTestRedisLimiter(t, client, namespace, limit, window)
	return func(key string) { require.NoError(t, l.RecordFailure(t.Context(), key)) }
}

// scriptRecorder records by running script directly with the limiter's
// arguments, in server-clock mode, under the default prefix.
func scriptRecorder(script *redis.Script) redisRecorder {
	var n atomic.Int64
	return func(t *testing.T, client *redis.Client, namespace string, limit int, window time.Duration) func(string) {
		return func(key string) {
			err := script.Run(t.Context(), client, []string{scrtyredis.DefaultKeyPrefix + namespace + ":" + key},
				"", strconv.FormatInt(window.Microseconds(), 10), strconv.Itoa(limit), fmt.Sprintf("%016x", n.Add(1))).Err()
			require.NoError(t, err)
		}
	}
}

func newTestRedisLimiter(t *testing.T, client *redis.Client, namespace string, limit int, window time.Duration, opts ...scrtyredis.Option) *scrtyredis.Limiter {
	t.Helper()
	opts = append([]scrtyredis.Option{
		scrtyredis.WithOperationTimeout(redisTestTimeout),
		scrtyredis.WithLogger(slog.New(slog.DiscardHandler)),
	}, opts...)
	l, err := scrtyredis.NewLimiter(client, namespace, limit, window, opts...)
	require.NoError(t, err)
	return l
}

// storedKey is where the limiter keeps key in namespace under the default
// prefix; keys in these tests are short, so they are stored as given.
func storedKey(namespace, key string) string {
	return scrtyredis.DefaultKeyPrefix + namespace + ":" + key
}

// exceededScriptRefreshing is the check script with a lifetime refresh added,
// as a "touch on read" cache would do. It is kept as the broken twin of the
// "check leaves the lifetime alone" case, which must fail against it.
var exceededScriptRefreshing = redis.NewScript(`
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000000 + tonumber(t[2])
redis.call('PEXPIRE', KEYS[1], math.ceil(tonumber(ARGV[2]) / 1000))
return redis.call('ZCOUNT', KEYS[1], string.format('(%.0f', now - tonumber(ARGV[2])), '+inf')
`)

// redisChecker asks whether key is exceeded through some implementation of
// the check operation, configured with limit and window.
type redisChecker func(t *testing.T, client *redis.Client, namespace string, limit int, window time.Duration) func(key string)

func limiterChecker(t *testing.T, client *redis.Client, namespace string, limit int, window time.Duration) func(string) {
	t.Helper()
	l := newTestRedisLimiter(t, client, namespace, limit, window)
	return func(key string) {
		_, err := l.Exceeded(t.Context(), key)
		require.NoError(t, err)
	}
}

func scriptChecker(script *redis.Script) redisChecker {
	return func(t *testing.T, client *redis.Client, namespace string, _ int, window time.Duration) func(string) {
		return func(key string) {
			require.NoError(t, script.Run(t.Context(), client, []string{storedKey(namespace, key)},
				"", strconv.FormatInt(window.Microseconds(), 10)).Err())
		}
	}
}

// pttlProbe is a client hook that sends every script call inside MULTI with
// a PTTL of key after it, and keeps the PTTL of the last call that succeeded.
// Servers from Redis 7.2 and Valkey 7.2 hold the clock still within MULTI, so
// that PTTL is exactly the lifetime the script set, with no time elapsed
// between the two.
type pttlProbe struct {
	client *redis.Client
	key    string

	mu  sync.Mutex
	ttl time.Duration
}

func (p *pttlProbe) DialHook(next redis.DialHook) redis.DialHook { return next }

func (p *pttlProbe) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

func (p *pttlProbe) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if name := strings.ToLower(cmd.Name()); name != "evalsha" && name != "eval" {
			return next(ctx, cmd)
		}
		var pttl *redis.DurationCmd
		// The pipeline runs through the pipeline hook, not this one.
		_, _ = p.client.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			_ = pipe.Process(ctx, cmd)
			pttl = pipe.PTTL(ctx, p.key)
			return nil
		})
		// A NOSCRIPT answer fails cmd, and Script.Run retries with EVAL,
		// which comes back through this hook.
		if err := cmd.Err(); err != nil {
			return err
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		p.ttl = pttl.Val()
		return nil
	}
}

// recordedTTL records one failure for key "k" through record, configured
// with window, and returns the lifetime the record set on the key, read in
// the same MULTI. It skips on Redis 7.0, which does not hold the clock still
// within MULTI; the rounding is Lua arithmetic, the same on every server.
func recordedTTL(t *testing.T, client *redis.Client, record redisRecorder, namespace string, window time.Duration) time.Duration {
	t.Helper()

	info := serverInfo(t, client)
	if _, valkey := info["valkey_version"]; !valkey && strings.HasPrefix(info["redis_version"], "7.0.") {
		t.Skip("Redis 7.0 does not hold the clock still within MULTI, so the lifetime a script set cannot be read exactly")
	}

	opts := *client.Options()
	hooked := redis.NewClient(&opts)
	t.Cleanup(func() { _ = hooked.Close() })
	probe := &pttlProbe{client: hooked, key: storedKey(namespace, "k")}
	hooked.AddHook(probe)

	record(t, hooked, namespace, 3, window)("k")

	probe.mu.Lock()
	defer probe.mu.Unlock()
	return probe.ttl
}

// TestRedisLimiter_TTL pins the key lifetime against real servers. Each case
// with a broken twin runs against it as a control, so the case is seen to
// tell the two apart.
func TestRedisLimiter_TTL(t *testing.T) {
	t.Parallel()

	const ns = "ttl"

	type testCase struct {
		name   string
		record redisRecorder
		check  redisChecker
		assert func(t *testing.T, client *redis.Client, record, check func(key string))
	}

	// noLifetime seeds a stamp with no lifetime, as a restore or a
	// hand-written key leaves one, records once, and reports the lifetime.
	noLifetime := func(t *testing.T, client *redis.Client, record func(string)) time.Duration {
		t.Helper()
		ctx := t.Context()
		require.NoError(t, client.ZAdd(ctx, storedKey(ns, "k"), redis.Z{Score: 1, Member: "1:seed"}).Err())
		require.Equal(t, time.Duration(-1), client.PTTL(ctx, storedKey(ns, "k")).Val())
		record("k")
		return client.PTTL(ctx, storedKey(ns, "k")).Val()
	}

	// checkedLifetime records once, sets the lifetime to 30s, half the
	// window, checks a few times, and reports the lifetime left and how long
	// that took, which the lifetime has rightly run down by.
	checkedLifetime := func(t *testing.T, client *redis.Client, record, check func(string)) (ttl, elapsed time.Duration) {
		t.Helper()
		ctx := t.Context()
		record("k")
		start := time.Now()
		require.NoError(t, client.PExpire(ctx, storedKey(ns, "k"), 30*time.Second).Err())
		for range 3 {
			check("k")
		}
		ttl = client.PTTL(ctx, storedKey(ns, "k")).Val()
		return ttl, time.Since(start)
	}

	// lateShortRecord: an instance with a 3s window records; one with a 1s
	// window records 2.5s later; 1.2s after that, it reports whether the 3s
	// instance still counts the key exceeded. Both have limit 1, so the 3s
	// instance answers true only if the key, and the second failure inside
	// its window, still exist. The window is real, because a fake clock
	// cannot drive key expiry.
	lateShortRecord := func(t *testing.T, client *redis.Client, record redisRecorder) bool {
		t.Helper()
		const lateNS = "late"
		long := record(t, client, lateNS, 1, 3*time.Second)
		short := record(t, client, lateNS, 1, time.Second)
		reader := newTestRedisLimiter(t, client, lateNS, 1, 3*time.Second)

		long("k")
		time.Sleep(2500 * time.Millisecond)
		short("k")
		time.Sleep(1200 * time.Millisecond)
		got, err := reader.Exceeded(t.Context(), "k")
		require.NoError(t, err)
		return got
	}

	// skewedLongRecord: with an application clock, a 1s instance on the true
	// clock records; a 3s instance whose clock is 50ms slow records 10ms later,
	// so its stamp is the older one; the 1s instance records again at 2.5s. At
	// 3.7s a 3s reader reports whether the key is exceeded and, when it is,
	// that it still exists. With limit 1 the slow stamp is trimmed at once, so
	// only a carried window rewritten onto the survivor keeps the key for the
	// 3s window; with a larger limit nothing is trimmed and the carried window
	// must be read from every member. The window is real, because a fake clock
	// cannot drive key expiry.
	skewedLongRecord := func(t *testing.T, client *redis.Client, limit int) (exceeded bool, ttl time.Duration) {
		t.Helper()
		const skewNS = "skew"
		short := newTestRedisLimiter(t, client, skewNS, limit, time.Second, scrtyredis.WithLimiterClock(fastClock{}))
		long := newTestRedisLimiter(t, client, skewNS, limit, 3*time.Second, scrtyredis.WithLimiterClock(fastClock{skew: -50 * time.Millisecond}))
		reader := newTestRedisLimiter(t, client, skewNS, limit, 3*time.Second, scrtyredis.WithLimiterClock(fastClock{}))

		require.NoError(t, short.RecordFailure(t.Context(), "k"))
		time.Sleep(10 * time.Millisecond)
		require.NoError(t, long.RecordFailure(t.Context(), "k"))
		time.Sleep(2490 * time.Millisecond)
		require.NoError(t, short.RecordFailure(t.Context(), "k"))
		time.Sleep(1200 * time.Millisecond)
		got, err := reader.Exceeded(t.Context(), "k")
		require.NoError(t, err)
		return got, client.PTTL(t.Context(), storedKey(skewNS, "k")).Val()
	}

	cases := []testCase{
		{
			name: "a late shorter-window record keeps the key for the longer window",
			assert: func(t *testing.T, client *redis.Client, _, _ func(string)) {
				assert.True(t, lateShortRecord(t, client, limiterRecorder),
					"the key expired one short window after the late record, while the long window still counts it")
			},
		},
		{
			name: "control: a lifetime set from the recording window alone expires the key early",
			assert: func(t *testing.T, client *redis.Client, _, _ func(string)) {
				assert.False(t, lateShortRecord(t, client, scriptRecorder(recordScriptOwnWindowOnly)),
					"the key outlived the short record; the control no longer shows the hazard")
			},
		},
		{
			name:   "a key with no lifetime gains one on the next record",
			record: limiterRecorder,
			assert: func(t *testing.T, client *redis.Client, record, _ func(string)) {
				ttl := noLifetime(t, client, record)
				assert.Greater(t, ttl, 59*time.Second, "the key did not gain a lifetime of one window")
				assert.LessOrEqual(t, ttl, time.Minute)
			},
		},
		{
			name:   "control: PEXPIRE GT alone leaves a key with no lifetime without one",
			record: scriptRecorder(recordScriptGTOnly),
			assert: func(t *testing.T, client *redis.Client, record, _ func(string)) {
				assert.Equal(t, time.Duration(-1), noLifetime(t, client, record))
			},
		},
		{
			name:   "a check leaves the lifetime unchanged",
			record: limiterRecorder,
			check:  limiterChecker,
			assert: func(t *testing.T, client *redis.Client, record, check func(string)) {
				ttl, elapsed := checkedLifetime(t, client, record, check)
				assert.LessOrEqual(t, ttl, 30*time.Second, "a check extended the lifetime")
				assert.GreaterOrEqual(t, ttl, 30*time.Second-elapsed-5*time.Millisecond, "a check shortened the lifetime")
			},
		},
		{
			name:   "control: a check that refreshes the lifetime is caught",
			record: limiterRecorder,
			check:  scriptChecker(exceededScriptRefreshing),
			assert: func(t *testing.T, client *redis.Client, record, check func(string)) {
				ttl, _ := checkedLifetime(t, client, record, check)
				assert.Greater(t, ttl, 59*time.Second)
			},
		},
		{
			// 1500µs is 1.5ms: the key must live the whole window, so the
			// lifetime in milliseconds is rounded up, never down.
			name: "a window that is not whole milliseconds gets a lifetime rounded up",
			assert: func(t *testing.T, client *redis.Client, _, _ func(string)) {
				assert.Equal(t, 2*time.Millisecond, recordedTTL(t, client, limiterRecorder, ns, 1500*time.Microsecond))
			},
		},
		{
			name: "a trimmed longer-window member leaves its window on the survivor",
			assert: func(t *testing.T, client *redis.Client, _, _ func(string)) {
				exceeded, _ := skewedLongRecord(t, client, 1)
				assert.True(t, exceeded, "the key expired one short window after the late record, while the long window still counts it")
			},
		},
		{
			name: "a longer-window member stamped below the newest keeps the key for its window",
			assert: func(t *testing.T, client *redis.Client, _, _ func(string)) {
				_, ttl := skewedLongRecord(t, client, 3)
				assert.Greater(t, ttl, time.Second, "the key's lifetime ignored the older member's longer window")
			},
		},
		{
			// The newest member always carries the longest window, so a scan
			// of every member only matters for a set written without that
			// guarantee. Such a set is seeded by hand: an older member
			// carrying 3m under a newest one carrying 1m, the key left with
			// 500ms. A 1m record must still extend the key to 3m.
			name:   "every member is read for the carried window, not only the newest",
			record: limiterRecorder,
			assert: func(t *testing.T, client *redis.Client, record, _ func(string)) {
				ctx := t.Context()
				require.NoError(t, client.ZAdd(ctx, storedKey(ns, "k"),
					redis.Z{Score: 1000, Member: "1000:180000000:old"},
					redis.Z{Score: 2000, Member: "2000:60000000:new"},
				).Err())
				require.NoError(t, client.PExpire(ctx, storedKey(ns, "k"), 500*time.Millisecond).Err())
				record("k")
				assert.Greater(t, client.PTTL(ctx, storedKey(ns, "k")).Val(), 2*time.Minute,
					"the lifetime ignored an older member's longer window")
			},
		},
		{
			name:   "a second record does not lengthen the lifetime beyond the window",
			record: limiterRecorder,
			assert: func(t *testing.T, client *redis.Client, record, _ func(string)) {
				record("k")
				record("k")
				ttl := client.PTTL(t.Context(), storedKey(ns, "k")).Val()
				assert.Greater(t, ttl, time.Duration(0))
				assert.LessOrEqual(t, ttl, time.Minute, "the lifetime was read from a stamp, not a window")
			},
		},
		{
			name:   "a record with a shorter window keeps a longer lifetime",
			record: limiterRecorder,
			assert: func(t *testing.T, client *redis.Client, record, _ func(string)) {
				ctx := t.Context()
				record("k") // one-minute window
				require.NoError(t, client.PExpire(ctx, storedKey(ns, "k"), 15*time.Minute).Err())
				record("k")
				assert.Greater(t, client.PTTL(ctx, storedKey(ns, "k")).Val(), 14*time.Minute,
					"a one-minute record cut short a fifteen-minute lifetime")
			},
		},
	}

	for _, image := range redisServerImages {
		for _, tc := range cases {
			t.Run(image+"/"+tc.name, func(t *testing.T) {
				t.Parallel()

				client := RunTestRedis(t, WithTestRedisImage(image)).Client
				var record, check func(string)
				if tc.record != nil {
					record = tc.record(t, client, ns, 3, time.Minute)
				}
				if tc.check != nil {
					check = tc.check(t, client, ns, 3, time.Minute)
				}
				tc.assert(t, client, record, check)
			})
		}
	}
}

// TestRedisLimiter_ServerClock pins that, by default, time comes from the
// server: a stamp ages by the server's clock, so a replica whose host clock
// runs fast cannot write one that the others count for longer. The cases wait
// out a short real window, because a fake clock cannot move the server's TIME.
func TestRedisLimiter_ServerClock(t *testing.T) {
	t.Parallel()

	const (
		ns     = "server-clock"
		window = 1500 * time.Millisecond
	)

	type testCase struct {
		name string
		// writerOpts configure the instance that records first.
		writerOpts []scrtyredis.Option
		assert     func(t *testing.T, writer, reader *scrtyredis.Limiter)
	}

	exceeded := func(t *testing.T, l *scrtyredis.Limiter) bool {
		t.Helper()
		got, err := l.Exceeded(t.Context(), "k")
		require.NoError(t, err)
		return got
	}

	// skewScenario: the writer records at 0s; the reader records at 1s,
	// which also keeps the key alive past the check; the reader checks at
	// 1.8s, when the writer's failure is one window old by the server's
	// clock and the reader's is not. Limit 2, so the answer is whether the
	// writer's failure still counts.
	skewScenario := func(t *testing.T, writer, reader *scrtyredis.Limiter) bool {
		t.Helper()
		require.NoError(t, writer.RecordFailure(t.Context(), "k"))
		time.Sleep(time.Second)
		require.NoError(t, reader.RecordFailure(t.Context(), "k"))
		require.True(t, exceeded(t, reader), "the reader does not count the writer's failure inside the window")
		time.Sleep(800 * time.Millisecond)
		return exceeded(t, reader)
	}

	cases := []testCase{
		{
			name: "two instances count one failure, and both see it leave the window",
			assert: func(t *testing.T, writer, reader *scrtyredis.Limiter) {
				require.NoError(t, writer.RecordFailure(t.Context(), "k"))
				require.NoError(t, writer.RecordFailure(t.Context(), "k"))
				assert.True(t, exceeded(t, writer), "the recording instance does not count its failures")
				assert.True(t, exceeded(t, reader), "another instance does not count the failures")
				time.Sleep(window + 300*time.Millisecond)
				assert.False(t, exceeded(t, writer), "the failures still count one window later")
				assert.False(t, exceeded(t, reader), "the failures still count one window later, on the other instance")
			},
		},
		{
			name: "skewed replica: a failure no longer counts one window later",
			// No WithLimiterClock: whatever the writer's host clock reads,
			// the stamp is the server's.
			assert: func(t *testing.T, writer, reader *scrtyredis.Limiter) {
				assert.False(t, skewScenario(t, writer, reader), "the writer's failure still counts one window later")
			},
		},
		{
			// The control: the writer stamps by a host clock 30 seconds
			// fast, so its failure still counts one window later. This is
			// the hazard the server-clock default removes.
			name:       "control: a writer stamping by a fast host clock is still counted one window later",
			writerOpts: []scrtyredis.Option{scrtyredis.WithLimiterClock(fastClock{skew: 30 * time.Second})},
			assert: func(t *testing.T, writer, reader *scrtyredis.Limiter) {
				assert.True(t, skewScenario(t, writer, reader), "the fast stamp aged by the server's clock; the control no longer shows the hazard")
			},
		},
	}

	for _, image := range redisServerImages {
		for _, tc := range cases {
			t.Run(image+"/"+tc.name, func(t *testing.T) {
				t.Parallel()

				client := RunTestRedis(t, WithTestRedisImage(image)).Client
				writer := newTestRedisLimiter(t, client, ns, 2, window, tc.writerOpts...)
				reader := newTestRedisLimiter(t, client, ns, 2, window)
				tc.assert(t, writer, reader)
			})
		}
	}
}

// fastClock is a host clock running skew ahead of real time.
type fastClock struct{ skew time.Duration }

func (c fastClock) Now() time.Time { return time.Now().Add(c.skew) }

// TestRedisLimiter_Factory pins that limiters a factory builds count in the
// server: two built for one namespace share its buckets, as two replicas do,
// and limiters of different namespaces do not.
func TestRedisLimiter_Factory(t *testing.T) {
	t.Parallel()

	const (
		limit  = 2
		window = time.Minute
	)

	type testCase struct {
		name string
		// second is the namespace the second limiter is built for; the first
		// is always "api-key".
		second string
		assert func(t *testing.T, first, second ratelimit.Limiter)
	}

	exceeded := func(t *testing.T, l ratelimit.Limiter) bool {
		t.Helper()
		got, err := l.Exceeded(t.Context(), "203.0.113.7")
		require.NoError(t, err)
		return got
	}

	cases := []testCase{
		{
			name:   "two limiters for one namespace see each other's failures",
			second: "api-key",
			assert: func(t *testing.T, first, second ratelimit.Limiter) {
				require.NoError(t, first.RecordFailure(t.Context(), "203.0.113.7"))
				assert.False(t, exceeded(t, second), "one failure already exceeds a limit of two")
				require.NoError(t, second.RecordFailure(t.Context(), "203.0.113.7"))
				assert.True(t, exceeded(t, first), "the first limiter does not count the second's failure")
				assert.True(t, exceeded(t, second), "the second limiter does not count the first's failure")
			},
		},
		{
			name:   "limiters of different namespaces keep their buckets apart",
			second: "magic-link",
			assert: func(t *testing.T, first, second ratelimit.Limiter) {
				for range limit {
					require.NoError(t, first.RecordFailure(t.Context(), "203.0.113.7"))
				}
				assert.True(t, exceeded(t, first), "the first limiter does not count its own failures")
				assert.False(t, exceeded(t, second), "another namespace counts the first namespace's failures")
			},
		},
	}

	for _, image := range redisServerImages {
		for _, tc := range cases {
			t.Run(image+"/"+tc.name, func(t *testing.T) {
				t.Parallel()

				client := RunTestRedis(t, WithTestRedisImage(image)).Client
				f, err := scrtyredis.NewLimiterFactory(client,
					scrtyredis.WithOperationTimeout(redisTestTimeout),
					scrtyredis.WithLogger(slog.New(slog.DiscardHandler)))
				require.NoError(t, err)
				first, err := f.NewLimiter("api-key", limit, window)
				require.NoError(t, err)
				second, err := f.NewLimiter(tc.second, limit, window)
				require.NoError(t, err)
				tc.assert(t, first, second)
			})
		}
	}
}
