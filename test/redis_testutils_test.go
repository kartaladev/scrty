package test

import (
	"os"
	"strings"
	"testing"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// serverInfo returns the INFO server section's fields of the server behind c.
func serverInfo(t *testing.T, c *redis.Client) map[string]string {
	t.Helper()

	raw, err := c.Info(t.Context(), "server").Result()
	require.NoError(t, err)
	fields := map[string]string{}
	for line := range strings.SplitSeq(raw, "\r\n") {
		if k, v, ok := strings.Cut(line, ":"); ok {
			fields[k] = v
		}
	}
	return fields
}

// imageVersion is the server version an image reference pins, and the INFO
// field that reports it: valkey_version for a Valkey image, redis_version for
// a Redis one. ok is false for any other reference.
func imageVersion(ref string) (field, version string, ok bool) {
	for repo, field := range map[string]string{"redis:": "redis_version", "valkey/valkey:": "valkey_version"} {
		if tag, found := strings.CutPrefix(ref, repo); found {
			return field, strings.TrimSuffix(tag, "-alpine"), true
		}
	}
	return "", "", false
}

func TestRunTestRedis(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []TestOption
		assert func(t *testing.T, a, b RedisConn)
	}

	cases := []testCase{
		{
			name: "ping",
			assert: func(t *testing.T, a, _ RedisConn) {
				require.NoError(t, a.Client.Ping(t.Context()).Err())
			},
		},
		{
			// CI moves the default through RedisImageEnv, so the case
			// follows it when it is set, Valkey included.
			name: "default image is the newest Redis",
			assert: func(t *testing.T, a, _ RedisConn) {
				want := RedisImage
				if ref := os.Getenv(RedisImageEnv); ref != "" {
					want = ref
				}
				field, version, ok := imageVersion(want)
				if !ok {
					t.Skipf("%s is neither a redis: nor a valkey/valkey: reference", want)
				}
				assert.Equal(t, version, serverInfo(t, a.Client)[field])
			},
		},
		{
			// Both sides write the same key: isolation must come from the
			// databases being different, not from the keys.
			name: "two calls on one server are isolated",
			assert: func(t *testing.T, a, b RedisConn) {
				ctx := t.Context()
				require.Equal(t, serverInfo(t, a.Client)["run_id"], serverInfo(t, b.Client)["run_id"], "the server is not shared")
				require.NoError(t, a.Client.Set(ctx, "probe", "a", 0).Err())
				require.NoError(t, b.Client.Set(ctx, "probe", "b", 0).Err())
				assert.Equal(t, "a", a.Client.Get(ctx, "probe").Val())
				assert.Equal(t, "b", b.Client.Get(ctx, "probe").Val())
			},
		},
		{
			name: "image option selects Valkey 8",
			opts: []TestOption{WithTestRedisImage(Valkey8Image)},
			assert: func(t *testing.T, a, _ RedisConn) {
				assert.True(t, strings.HasPrefix(serverInfo(t, a.Client)["valkey_version"], "8."), "not a Valkey 8 server")
			},
		},
		{
			name: "image option selects Redis 7",
			opts: []TestOption{WithTestRedisImage(Redis7Image)},
			assert: func(t *testing.T, a, _ RedisConn) {
				assert.True(t, strings.HasPrefix(serverInfo(t, a.Client)["redis_version"], "7."), "not a Redis 7 server")
			},
		},
		{
			name: "own container is a server of its own",
			opts: []TestOption{WithTestRedisOwnContainer()},
			assert: func(t *testing.T, a, b RedisConn) {
				assert.NotEqual(t, serverInfo(t, a.Client)["run_id"], serverInfo(t, b.Client)["run_id"])
			},
		},
		{
			// Docker maps a restarted container to a new host port, so a
			// client that kept the first address would never reconnect.
			name: "stop and start keep the client usable",
			opts: []TestOption{WithTestRedisOwnContainer()},
			assert: func(t *testing.T, a, _ RedisConn) {
				require.NoError(t, a.Client.Ping(t.Context()).Err())
				a.Stop(t)
				require.Error(t, a.Client.Ping(t.Context()).Err(), "the server answered while stopped")
				a.Start(t)
				require.NoError(t, a.Client.Ping(t.Context()).Err(), "the client did not reach the restarted server")
			},
		},
		{
			// The shared limiter refuses a client that ignores context
			// deadlines, so every client the helper hands out sets it.
			name: "a shared server's client honours context deadlines",
			assert: func(t *testing.T, a, _ RedisConn) {
				assert.True(t, a.Client.Options().ContextTimeoutEnabled)
			},
		},
		{
			name: "an own container's client honours context deadlines",
			opts: []TestOption{WithTestRedisOwnContainer()},
			assert: func(t *testing.T, a, _ RedisConn) {
				assert.True(t, a.Client.Options().ContextTimeoutEnabled)
			},
		},
		{
			name: "server args reach the server",
			opts: []TestOption{WithTestRedisOwnContainer(), WithTestRedisServerArgs("--maxmemory-policy", "allkeys-lru")},
			assert: func(t *testing.T, a, _ RedisConn) {
				got, err := a.Client.ConfigGet(t.Context(), "maxmemory-policy").Result()
				require.NoError(t, err)
				assert.Equal(t, "allkeys-lru", got["maxmemory-policy"])
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			a := RunTestRedis(t, tc.opts...)
			b := RunTestRedis(t, tc.opts...)
			tc.assert(t, a, b)
		})
	}
}

// TestRunTestRedis_Refusals pins what RunTestRedis and RedisConn refuse on a
// shared server: flags and restarts there would reach every other caller. The
// refusals end the test with t.Fatal, which a test cannot observe on its own
// *testing.T, so the checks behind them are exercised directly.
func TestRunTestRedis_Refusals(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		check  func() error
		assert func(t *testing.T, err error)
	}

	refused := func(want string) func(t *testing.T, err error) {
		return func(t *testing.T, err error) {
			require.Error(t, err)
			assert.Contains(t, err.Error(), want)
		}
	}

	cases := []testCase{
		{
			name:   "server args on a shared server",
			check:  (&testConfig{serverArgs: []string{"--maxmemory", "2mb"}}).redisConfigError,
			assert: refused("WithTestRedisOwnContainer"),
		},
		{
			name:  "server args on an own container",
			check: (&testConfig{ownContainer: true, serverArgs: []string{"--maxmemory", "2mb"}}).redisConfigError,
			assert: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
		},
		{
			name:  "no server args on a shared server",
			check: (&testConfig{}).redisConfigError,
			assert: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "stop or start on a shared server",
			check: func() error {
				_, err := RedisConn{}.own()
				return err
			},
			assert: refused("shared"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.check())
		})
	}
}

// TestRunTestRedis_FlushesAtCleanup is not parallel, so no other test in this
// process can take the database between the subtest's cleanup and the check.
func TestRunTestRedis_FlushesAtCleanup(t *testing.T) {
	var opts *redis.Options
	t.Run("writes", func(t *testing.T) {
		c := RunTestRedis(t).Client
		require.NoError(t, c.Set(t.Context(), "left", "behind", 0).Err())
		opts = c.Options()
	})
	require.NotNil(t, opts)

	again := redis.NewClient(&redis.Options{Addr: opts.Addr, DB: opts.DB})
	t.Cleanup(func() { _ = again.Close() })
	n, err := again.DBSize(t.Context()).Result()
	require.NoError(t, err)
	assert.Zero(t, n, "database %d still holds keys after its test ended", opts.DB)
}
