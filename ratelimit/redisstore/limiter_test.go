package redisstore_test

import (
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/ratelimit/redisstore"
)

func TestNewLimiter(t *testing.T) {
	t.Parallel()

	var nilClient *redis.Client
	var nilCluster *redis.ClusterClient
	var nilRing *redis.Ring
	var nilFake *clockwork.FakeClock

	type testCase struct {
		name      string
		client    func(t *testing.T) redis.UniversalClient // nil means a recording client
		namespace string
		limit     int
		window    time.Duration
		opts      []redisstore.Option
		assert    func(t *testing.T, l *redisstore.Limiter, err error)
	}

	refused := func(want string) func(t *testing.T, l *redisstore.Limiter, err error) {
		return func(t *testing.T, l *redisstore.Limiter, err error) {
			require.ErrorIs(t, err, ratelimit.ErrConfig)
			assert.Contains(t, err.Error(), want)
			assert.Nil(t, l)
		}
	}
	accepted := func(t *testing.T, l *redisstore.Limiter, err error) {
		require.NoError(t, err)
		assert.NotNil(t, l)
	}

	cases := []testCase{
		{name: "defaults accepted", namespace: "api-key", limit: 5, window: time.Minute, assert: accepted},
		{
			name: "a nil option among valid ones is skipped", namespace: "api-key", limit: 5, window: time.Minute,
			opts:   []redisstore.Option{redisstore.WithKeyPrefix("app:rl:"), nil, redisstore.WithLogger(quietLogger())},
			assert: accepted,
		},
		{
			name: "every option accepted", namespace: "api-key", limit: 5, window: time.Minute,
			opts: []redisstore.Option{
				redisstore.WithKeyPrefix("app:rl:"),
				redisstore.WithClock(clockwork.NewFakeClock()),
				redisstore.WithOnUnavailable(ratelimit.UnavailableFallbackToLocal),
				redisstore.WithOperationTimeout(time.Second),
				redisstore.WithProbeInterval(5 * time.Second),
				redisstore.WithUnavailableLogInterval(10 * time.Second),
				redisstore.WithLogger(quietLogger()),
			},
			assert: accepted,
		},
		{
			name:      "cluster client reading from the primary accepted",
			client:    clusterClient(nil),
			namespace: "api-key", limit: 5, window: time.Minute,
			assert: accepted,
		},
		{
			// A lagging replica undercounts, so a limit read there is not
			// the limit.
			name:      "cluster client reading from replicas (ReadOnly)",
			client:    clusterClient(func(o *redis.ClusterOptions) { o.ReadOnly = true }),
			namespace: "api-key", limit: 5, window: time.Minute,
			assert: refused("ReadOnly"),
		},
		{
			name:      "cluster client routing reads by latency (RouteByLatency)",
			client:    clusterClient(func(o *redis.ClusterOptions) { o.RouteByLatency = true }),
			namespace: "api-key", limit: 5, window: time.Minute,
			assert: refused("RouteByLatency"),
		},
		{
			name:      "cluster client routing reads at random (RouteRandomly)",
			client:    clusterClient(func(o *redis.ClusterOptions) { o.RouteRandomly = true }),
			namespace: "api-key", limit: 5, window: time.Minute,
			assert: refused("RouteRandomly"),
		},
		{
			name:      "ring client accepted",
			client:    ringClient(nil),
			namespace: "api-key", limit: 5, window: time.Minute,
			assert: accepted,
		},
		{
			// go-redis reads past a context's deadline without it, so
			// neither the operation timeout nor a caller's deadline would
			// bound a call to a server that hangs.
			name:      "client without ContextTimeoutEnabled",
			client:    plainClient(noClientContextTimeout),
			namespace: "api-key", limit: 5, window: time.Minute,
			assert: refused("ContextTimeoutEnabled"),
		},
		{
			name:      "cluster client without ContextTimeoutEnabled",
			client:    clusterClient(noClusterContextTimeout),
			namespace: "api-key", limit: 5, window: time.Minute,
			assert: refused("ContextTimeoutEnabled"),
		},
		{
			name:      "ring client without ContextTimeoutEnabled",
			client:    ringClient(noRingContextTimeout),
			namespace: "api-key", limit: 5, window: time.Minute,
			assert: refused("ContextTimeoutEnabled"),
		},
		{
			name:      "nil client",
			client:    func(*testing.T) redis.UniversalClient { return nil },
			namespace: "api-key", limit: 5, window: time.Minute,
			assert: refused("client"),
		},
		{
			name:      "typed nil client",
			client:    func(*testing.T) redis.UniversalClient { return nilClient },
			namespace: "api-key", limit: 5, window: time.Minute,
			assert: refused("client"),
		},
		{
			name:      "typed nil cluster client",
			client:    func(*testing.T) redis.UniversalClient { return nilCluster },
			namespace: "api-key", limit: 5, window: time.Minute,
			assert: refused("client"),
		},
		{
			name:      "typed nil ring client",
			client:    func(*testing.T) redis.UniversalClient { return nilRing },
			namespace: "api-key", limit: 5, window: time.Minute,
			assert: refused("client"),
		},
		{name: "empty namespace", namespace: "", limit: 5, window: time.Minute, assert: refused("namespace")},
		{
			// "a:b" with key "c" and "a" with key "b:c" would share one bucket.
			name: "namespace containing the separator", namespace: "api:key", limit: 5, window: time.Minute,
			assert: refused("namespace"),
		},
		{name: "zero limit", namespace: "api-key", limit: 0, window: time.Minute, assert: refused("limit")},
		{name: "negative limit", namespace: "api-key", limit: -1, window: time.Minute, assert: refused("limit")},
		{name: "zero window", namespace: "api-key", limit: 5, window: 0, assert: refused("window")},
		{name: "negative window", namespace: "api-key", limit: 5, window: -time.Second, assert: refused("window")},
		{
			name: "window below the stored microsecond", namespace: "api-key", limit: 5, window: 500 * time.Nanosecond,
			assert: refused("microsecond"),
		},
		{
			name: "empty prefix", namespace: "api-key", limit: 5, window: time.Minute,
			opts:   []redisstore.Option{redisstore.WithKeyPrefix("")},
			assert: refused("prefix"),
		},
		{
			name: "nil clock", namespace: "api-key", limit: 5, window: time.Minute,
			opts:   []redisstore.Option{redisstore.WithClock(nil)},
			assert: refused("clock"),
		},
		{
			name: "typed nil clock", namespace: "api-key", limit: 5, window: time.Minute,
			opts:   []redisstore.Option{redisstore.WithClock(nilFake)},
			assert: refused("clock"),
		},
		{
			name: "unknown unavailable mode", namespace: "api-key", limit: 5, window: time.Minute,
			opts:   []redisstore.Option{redisstore.WithOnUnavailable(ratelimit.UnavailableMode(99))},
			assert: refused("mode"),
		},
		{
			name: "zero operation timeout", namespace: "api-key", limit: 5, window: time.Minute,
			opts:   []redisstore.Option{redisstore.WithOperationTimeout(0)},
			assert: refused("timeout"),
		},
		{
			name: "negative probe interval", namespace: "api-key", limit: 5, window: time.Minute,
			opts:   []redisstore.Option{redisstore.WithProbeInterval(-time.Second)},
			assert: refused("probe interval"),
		},
		{
			name: "nil logger", namespace: "api-key", limit: 5, window: time.Minute,
			opts:   []redisstore.Option{redisstore.WithLogger(nil)},
			assert: refused("logger"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var client redis.UniversalClient
			var rec *recorder
			if tc.client != nil {
				client = tc.client(t)
			} else {
				client, rec = recordingClient(t, int64(0))
			}

			l, err := redisstore.NewLimiter(client, tc.namespace, tc.limit, tc.window, tc.opts...)
			tc.assert(t, l, err)

			if rec != nil {
				assert.Empty(t, rec.commands(), "construction sent a command")
				assert.Zero(t, rec.dialled(), "construction dialled the server")
			}
		})
	}
}

func TestStorageKey(t *testing.T) {
	t.Parallel()

	const prefix, ns = redisstore.DefaultKeyPrefix, "ns"

	type testCase struct {
		name   string
		key    string
		assert func(t *testing.T, stored string)
	}

	hashed := func(t *testing.T, stored string) {
		t.Helper()
		digest, ok := strings.CutPrefix(stored, prefix+ns+":sha256:")
		require.True(t, ok, "stored as %q, not hashed", stored)
		_, err := hex.DecodeString(digest)
		require.NoError(t, err)
		assert.Len(t, digest, 64)
	}

	cases := []testCase{
		{
			name: "short key stored as given",
			key:  "203.0.113.7",
			assert: func(t *testing.T, stored string) {
				assert.Equal(t, "scrty:ratelimit:ns:203.0.113.7", stored)
			},
		},
		{
			name: "key of exactly 512 bytes stored as given",
			key:  strings.Repeat("k", redisstore.MaxRawKeyLen),
			assert: func(t *testing.T, stored string) {
				assert.Equal(t, prefix+ns+":"+strings.Repeat("k", 512), stored)
			},
		},
		{name: "key of 513 bytes hashed", key: strings.Repeat("k", 513), assert: hashed},
		{
			name: "two different 600-byte keys do not collide",
			key:  strings.Repeat("a", 599) + "1",
			assert: func(t *testing.T, stored string) {
				hashed(t, stored)
				other := redisstore.StorageKey(prefix, ns, strings.Repeat("a", 599)+"2")
				hashed(t, other)
				assert.NotEqual(t, stored, other)
			},
		},
		{
			// A short key spelled like a hashed one must not land in the
			// bucket of the long key whose digest it spells.
			name: "a short key spelled like a hashed key does not collide with it",
			key:  strings.Repeat("y", 600),
			assert: func(t *testing.T, stored string) {
				hashed(t, stored)
				spelled := strings.TrimPrefix(stored, prefix+ns+":")
				assert.NotEqual(t, stored, redisstore.StorageKey(prefix, ns, spelled))
			},
		},
		{
			// The overlap WithKeyPrefix documents: a prefix nested inside
			// another shares buckets with it, which is why its godoc forbids
			// one prefix beginning with another.
			name: "a nested prefix shares a bucket with its parent",
			key:  "x",
			assert: func(t *testing.T, stored string) {
				assert.Equal(t, redisstore.StorageKey(prefix, "staging", "ns:x"),
					redisstore.StorageKey(prefix+"staging:", ns, "x"))
				assert.Equal(t, prefix+ns+":x", stored)
			},
		},
		{
			name: "a hashed key is the same on every call",
			key:  strings.Repeat("z", 600),
			assert: func(t *testing.T, stored string) {
				assert.Equal(t, stored, redisstore.StorageKey(prefix, ns, strings.Repeat("z", 600)))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, redisstore.StorageKey(prefix, ns, tc.key))
		})
	}
}

// TestLimiter_ScriptCalls pins what each call sends, without a server:
// one declared key, and the arguments the scripts read. In server-clock mode
// the "now" argument is empty, so the stamp comes from the server's TIME and
// no host clock is read: a replica whose host clock runs fast cannot write a
// stamp that others count for longer.
func TestLimiter_ScriptCalls(t *testing.T) {
	t.Parallel()

	at := time.Unix(1_700_000_000, 123_456_000)

	type testCase struct {
		name   string
		reply  int64
		opts   []redisstore.Option
		call   func(t *testing.T, l *redisstore.Limiter) (exceeded bool, err error)
		assert func(t *testing.T, cmds [][]any, exceeded bool, err error)
	}

	record := func(t *testing.T, l *redisstore.Limiter) (bool, error) {
		require.NoError(t, l.RecordFailure(t.Context(), "k"))
		return false, l.RecordFailure(t.Context(), "k")
	}
	check := func(t *testing.T, l *redisstore.Limiter) (bool, error) {
		return l.Exceeded(t.Context(), "k")
	}
	// script returns the command name, the declared keys and the arguments.
	script := func(t *testing.T, cmds [][]any, i int) (string, []any, []any) {
		t.Helper()
		require.Greater(t, len(cmds), i, "command %d was never sent", i)
		cmd := cmds[i]
		require.GreaterOrEqual(t, len(cmd), 3)
		n, ok := cmd[2].(int)
		require.True(t, ok, "numkeys %v", cmd[2])
		return strings.ToLower(cmd[0].(string)), cmd[3 : 3+n], cmd[3+n:]
	}
	const key = "scrty:ratelimit:api-key:k"

	cases := []testCase{
		{
			name: "record, server clock", reply: 1, call: record,
			assert: func(t *testing.T, cmds [][]any, _ bool, err error) {
				require.NoError(t, err)
				require.Len(t, cmds, 2)
				name, keys, args := script(t, cmds, 0)
				assert.Equal(t, "evalsha", name)
				assert.Equal(t, []any{key}, keys)
				require.Len(t, args, 4)
				assert.Equal(t, "", args[0], "the host clock was sent instead of the server's TIME")
				assert.Equal(t, "60000000", args[1], "window in microseconds")
				assert.Equal(t, "3", args[2], "limit")
				_, _, again := script(t, cmds, 1)
				assert.Len(t, args[3], 16, "member suffix")
				assert.NotEqual(t, args[3], again[3], "two records shared one member suffix")
			},
		},
		{
			name: "record, application clock", reply: 1, call: record,
			opts: []redisstore.Option{redisstore.WithClock(clockwork.NewFakeClockAt(at))},
			assert: func(t *testing.T, cmds [][]any, _ bool, err error) {
				require.NoError(t, err)
				_, _, args := script(t, cmds, 0)
				assert.Equal(t, strconv.FormatInt(at.UnixMicro(), 10), args[0])
			},
		},
		{
			name: "check, server clock, read-only script", reply: 2, call: check,
			assert: func(t *testing.T, cmds [][]any, exceeded bool, err error) {
				require.NoError(t, err)
				assert.False(t, exceeded, "two of three is not exceeded")
				require.Len(t, cmds, 1)
				name, keys, args := script(t, cmds, 0)
				assert.Equal(t, "evalsha_ro", name)
				assert.Equal(t, []any{key}, keys)
				assert.Equal(t, []any{"", "60000000"}, args)
			},
		},
		{
			name: "check, application clock", reply: 3, call: check,
			opts: []redisstore.Option{redisstore.WithClock(clockwork.NewFakeClockAt(at))},
			assert: func(t *testing.T, cmds [][]any, exceeded bool, err error) {
				require.NoError(t, err)
				assert.True(t, exceeded, "three of three is exceeded")
				_, _, args := script(t, cmds, 0)
				assert.Equal(t, []any{strconv.FormatInt(at.UnixMicro(), 10), "60000000"}, args)
			},
		},
		{
			name: "check with a custom prefix", reply: 0, call: check,
			opts: []redisstore.Option{redisstore.WithKeyPrefix("app:")},
			assert: func(t *testing.T, cmds [][]any, _ bool, err error) {
				require.NoError(t, err)
				_, keys, _ := script(t, cmds, 0)
				assert.Equal(t, []any{"app:api-key:k"}, keys)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			client, rec := recordingClient(t, tc.reply)
			opts := append([]redisstore.Option{redisstore.WithLogger(quietLogger())}, tc.opts...)
			l, err := redisstore.NewLimiter(client, "api-key", 3, time.Minute, opts...)
			require.NoError(t, err)

			exceeded, err := tc.call(t, l)
			tc.assert(t, rec.commands(), exceeded, err)
		})
	}
}

// TestLimiter_Policy pins the "Shared limiter" scenario: the limiter reports,
// through the optional contract, the limit and window it was built with, the
// window as the backend counts it. Construction does no I/O, so a client
// pointed at nothing is enough.
func TestLimiter_Policy(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		window time.Duration
		assert func(t *testing.T, limit int, window time.Duration)
	}

	cases := []testCase{
		{
			name:   "limit and window as built",
			window: 15 * time.Minute,
			assert: func(t *testing.T, limit int, window time.Duration) {
				assert.Equal(t, 10, limit)
				assert.Equal(t, 15*time.Minute, window)
			},
		},
		{
			name:   "window finer than the backend counts is truncated",
			window: 15*time.Minute + 500*time.Nanosecond,
			assert: func(t *testing.T, limit int, window time.Duration) {
				assert.Equal(t, 10, limit)
				assert.Equal(t, 15*time.Minute, window)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			client, _ := recordingClient(t, nil)
			l, err := redisstore.NewLimiter(client, "ns", 10, tc.window)
			require.NoError(t, err)

			var r ratelimit.PolicyReporter = l
			limit, window := r.Policy()
			tc.assert(t, limit, window)
		})
	}
}
