package test

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/ratelimit"
	scrtyredis "github.com/kartaladev/scrty/redis"
)

// redisBelowFloorImage is a Redis older than the shared limiter's floor,
// Redis 7.0, pinned like the supported images.
const redisBelowFloorImage = "redis:6.2.14-alpine"

// logRecord is one record a logRecorder kept.
type logRecord struct {
	level   slog.Level
	message string
}

// logRecorder is a slog handler that keeps every record it is given.
type logRecorder struct {
	mu      sync.Mutex
	records []logRecord
}

func (r *logRecorder) Enabled(context.Context, slog.Level) bool { return true }

func (r *logRecorder) Handle(_ context.Context, rec slog.Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = append(r.records, logRecord{level: rec.Level, message: rec.Message})
	return nil
}

func (r *logRecorder) WithAttrs([]slog.Attr) slog.Handler { return r }
func (r *logRecorder) WithGroup(string) slog.Handler      { return r }

// at returns the records kept at level.
func (r *logRecorder) at(level slog.Level) []logRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []logRecord
	for _, rec := range r.records {
		if rec.level == level {
			out = append(out, rec)
		}
	}
	return out
}

// cachedScripts is how many scripts the server behind c holds in its script
// cache, from INFO memory.
func cachedScripts(t *testing.T, c *redis.Client) string {
	t.Helper()

	raw, err := c.Info(t.Context(), "memory").Result()
	require.NoError(t, err)
	for line := range strings.SplitSeq(raw, "\r\n") {
		if v, ok := strings.CutPrefix(line, "number_of_cached_scripts:"); ok {
			return v
		}
	}
	t.Fatal("INFO memory has no number_of_cached_scripts")
	return ""
}

// aclPassword is the password of the users aclClient creates.
const aclPassword = "verify-pw"

// aclClient creates user "limiter" with rules on the server behind admin,
// and returns a client that authenticates as it.
func aclClient(t *testing.T, admin *redis.Client, rules []string) *redis.Client {
	t.Helper()

	args := []any{"ACL", "SETUSER", "limiter", "reset"}
	for _, r := range rules {
		args = append(args, r)
	}
	require.NoError(t, admin.Do(t.Context(), args...).Err())

	opts := *admin.Options()
	opts.Username, opts.Password = "limiter", aclPassword
	client := redis.NewClient(&opts)
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// TestRedisVerify pins what Verify checks on a real server: the version
// floor, an eviction policy that cannot drop a live key, and that both
// scripts load. Each case starts a server of its own with the flags it
// needs, and verifies it through both the factory and a limiter, each with a
// logger of its own.
func TestRedisVerify(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name  string
		image string // empty means the default image
		args  []string
		opts  []scrtyredis.Option
		// acl, when set, are the ACL rules of a user Verify runs as, in
		// place of the default user.
		acl []string
		// assert runs once for the factory and once for a limiter; logs
		// holds only that subject's records. client is the one Verify ran
		// with.
		assert func(t *testing.T, client *redis.Client, err error, logs *logRecorder)
	}

	// aclUser is the rules of a user granted the commands the limiter
	// sends and Verify reads with, on keys under the default prefix, and
	// extra besides.
	aclUser := func(extra ...string) []string {
		return append([]string{
			"on", ">" + aclPassword, "~" + scrtyredis.DefaultKeyPrefix + "*",
			"+eval", "+evalsha", "+eval_ro", "+evalsha_ro", "+script|load", "+info", "+config|get",
		}, extra...)
	}

	noWarning := func(t *testing.T, logs *logRecorder) {
		t.Helper()
		assert.Empty(t, logs.at(slog.LevelWarn), "Verify wrote a warning")
	}
	refused := func(want ...string) func(t *testing.T, _ *redis.Client, err error, logs *logRecorder) {
		return func(t *testing.T, _ *redis.Client, err error, logs *logRecorder) {
			require.ErrorIs(t, err, ratelimit.ErrConfig)
			for _, w := range want {
				assert.Contains(t, err.Error(), w)
			}
			noWarning(t, logs)
		}
	}

	cases := []testCase{
		{
			name:   "server older than the floor",
			image:  redisBelowFloorImage,
			assert: refused("Redis 6.2.14", "Redis 7.0"),
		},
		{
			name:   "allkeys eviction policy",
			args:   []string{"--maxmemory-policy", "allkeys-lru"},
			assert: refused("maxmemory-policy", "allkeys-lru", "noeviction"),
		},
		{
			name:   "volatile eviction policy, which reaches every limiter key",
			args:   []string{"--maxmemory-policy", "volatile-lru"},
			assert: refused("maxmemory-policy", "volatile-lru", "noeviction"),
		},
		{
			name: "noeviction passes, and both scripts are loaded",
			args: []string{"--maxmemory-policy", "noeviction"},
			assert: func(t *testing.T, client *redis.Client, err error, logs *logRecorder) {
				require.NoError(t, err)
				noWarning(t, logs)
				assert.Equal(t, "2", cachedScripts(t, client), "Verify did not load both scripts")
			},
		},
		{
			name: "unreadable policy passes with one warning naming noeviction",
			args: []string{"--rename-command", "CONFIG", ""},
			assert: func(t *testing.T, _ *redis.Client, err error, logs *logRecorder) {
				require.NoError(t, err)
				warns := logs.at(slog.LevelWarn)
				require.Len(t, warns, 1, "Verify did not write exactly one warning")
				assert.Contains(t, warns[0].message, "noeviction")
			},
		},
		{
			name: "eviction check disabled: unreadable policy passes without a warning",
			args: []string{"--rename-command", "CONFIG", ""},
			opts: []scrtyredis.Option{scrtyredis.WithEvictionPolicyCheck(false)},
			assert: func(t *testing.T, _ *redis.Client, err error, logs *logRecorder) {
				require.NoError(t, err)
				noWarning(t, logs)
			},
		},
		{
			name: "eviction check disabled: an evicting policy is not read",
			args: []string{"--maxmemory-policy", "allkeys-lru"},
			opts: []scrtyredis.Option{scrtyredis.WithEvictionPolicyCheck(false)},
			assert: func(t *testing.T, _ *redis.Client, err error, logs *logRecorder) {
				require.NoError(t, err)
				noWarning(t, logs)
			},
		},
		{
			name:   "scripts cannot be loaded",
			args:   []string{"--rename-command", "SCRIPT", ""},
			assert: refused("load"),
		},
		{
			// Redis checks a script's commands against the caller's ACL
			// only when the script runs, so loading them proves nothing.
			name: "ACL user without the commands the scripts run",
			acl:  aclUser(),
			assert: func(t *testing.T, _ *redis.Client, err error, logs *logRecorder) {
				require.ErrorIs(t, err, ratelimit.ErrConfig)
				assert.Contains(t, err.Error(), "TIME", "the missing permission is not named")
				assert.NotContains(t, err.Error(), "NOPERM", "the server's text was repeated")
				noWarning(t, logs)
			},
		},
		{
			name: "ACL user granted the documented commands passes, and can record and check",
			acl:  aclUser("+time", "+zrange", "+zadd", "+zremrangebyrank", "+zrem", "+pttl", "+pexpire", "+zcount"),
			assert: func(t *testing.T, client *redis.Client, err error, logs *logRecorder) {
				require.NoError(t, err)
				noWarning(t, logs)

				l, err := scrtyredis.NewLimiter(client, "api-key", 1, time.Minute, scrtyredis.WithLogger(slog.New(logs)))
				require.NoError(t, err)
				require.NoError(t, l.RecordFailure(t.Context(), "k"))
				exceeded, err := l.Exceeded(t.Context(), "k")
				require.NoError(t, err)
				assert.True(t, exceeded)
			},
		},
		{
			name:  "Valkey at its floor passes, judged by valkey_version",
			image: ValkeyMinImage,
			assert: func(t *testing.T, client *redis.Client, err error, logs *logRecorder) {
				require.NoError(t, err)
				noWarning(t, logs)
				// The pinned Valkey reports its own version apart from the
				// Redis version it is compatible with; Verify must read the
				// former, which TestCheckVersion pins below the floor.
				assert.Equal(t, "7.2.11", serverInfo(t, client)["valkey_version"])
			},
		},
	}

	subjects := []struct {
		name  string
		build func(t *testing.T, client *redis.Client, opts []scrtyredis.Option) ratelimit.Verifier
	}{
		{
			name: "factory",
			build: func(t *testing.T, client *redis.Client, opts []scrtyredis.Option) ratelimit.Verifier {
				f, err := scrtyredis.NewLimiterFactory(client, opts...)
				require.NoError(t, err)
				return f
			},
		},
		{
			name: "limiter",
			build: func(t *testing.T, client *redis.Client, opts []scrtyredis.Option) ratelimit.Verifier {
				l, err := scrtyredis.NewLimiter(client, "api-key", 5, time.Minute, opts...)
				require.NoError(t, err)
				return l
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			testOpts := []TestOption{WithTestRedisOwnContainer()}
			if tc.image != "" {
				testOpts = append(testOpts, WithTestRedisImage(tc.image))
			}
			if len(tc.args) > 0 {
				testOpts = append(testOpts, WithTestRedisServerArgs(tc.args...))
			}
			client := RunTestRedis(t, testOpts...).Client
			if tc.acl != nil {
				client = aclClient(t, client, tc.acl)
			}

			for _, s := range subjects {
				t.Run(s.name, func(t *testing.T) {
					logs := &logRecorder{}
					opts := append([]scrtyredis.Option{
						scrtyredis.WithOperationTimeout(redisTestTimeout),
						scrtyredis.WithLogger(slog.New(logs)),
					}, tc.opts...)
					v := s.build(t, client, opts)
					tc.assert(t, client, v.Verify(t.Context()), logs)
				})
			}
		})
	}
}
