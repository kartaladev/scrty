package redisstore_test

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/ratelimit/redisstore"
)

// TestVerify_Probe pins the probe run Verify ends with, without a server: the
// record script, then the check script, on one probe key no limiter key can
// be, with limit 1 and a one-millisecond window.
func TestVerify_Probe(t *testing.T) {
	t.Parallel()

	at := time.Unix(1_700_000_000, 0)

	type testCase struct {
		name   string
		opts   []redisstore.Option
		assert func(t *testing.T, record, check []any)
	}

	// probeKey asserts key is prefix, an empty namespace, "verify" and 16 hex
	// digits. A limiter key has a non-empty namespace after the prefix, so a
	// colon there cannot be one.
	probeKey := func(t *testing.T, prefix string, key any) {
		t.Helper()
		s, ok := key.(string)
		require.True(t, ok, "key %v", key)
		assert.Regexp(t, "^"+regexp.QuoteMeta(prefix)+":verify:[0-9a-f]{16}$", s)
		suffix := s[strings.LastIndex(s, ":")+1:]
		assert.NotEqual(t, redisstore.StorageKey(prefix, "verify", suffix), s, "the probe key is a limiter's key")
	}

	cases := []testCase{
		{
			name: "default prefix, server clock",
			assert: func(t *testing.T, record, check []any) {
				probeKey(t, redisstore.DefaultKeyPrefix, record[3])
				assert.Equal(t, record[3], check[3], "the check ran on another key than the record")
				assert.Equal(t, []any{"", "1000", "1"}, record[4:7], "now, window in µs, limit")
				assert.Equal(t, []any{"", "1000"}, check[4:])
			},
		},
		{
			name: "custom prefix",
			opts: []redisstore.Option{redisstore.WithKeyPrefix("app:rl:")},
			assert: func(t *testing.T, record, _ []any) {
				probeKey(t, "app:rl:", record[3])
			},
		},
		{
			name: "application clock, as the limiter runs the scripts",
			opts: []redisstore.Option{redisstore.WithClock(clockwork.NewFakeClockAt(at))},
			assert: func(t *testing.T, record, check []any) {
				now := strconv.FormatInt(at.UnixMicro(), 10)
				assert.Equal(t, now, record[4])
				assert.Equal(t, now, check[4])
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			client, rec := recordingClient(t, int64(1))
			rec.info = "# Server\r\nredis_version:8.0.0\r\n"
			opts := append([]redisstore.Option{redisstore.WithLogger(quietLogger())}, tc.opts...)
			l, err := redisstore.NewLimiter(client, "api-key", 5, time.Minute, opts...)
			require.NoError(t, err)

			require.NoError(t, l.Verify(t.Context()))

			var scripts [][]any
			for _, cmd := range rec.commands() {
				if name := strings.ToLower(cmd[0].(string)); name == "evalsha" || name == "evalsha_ro" {
					scripts = append(scripts, cmd)
				}
			}
			require.Len(t, scripts, 2, "the probe did not run both scripts once")
			assert.Equal(t, "evalsha", strings.ToLower(scripts[0][0].(string)), "the record script did not run first")
			assert.Equal(t, "evalsha_ro", strings.ToLower(scripts[1][0].(string)))
			assert.Equal(t, 1, scripts[0][2], "the probe declared more than one key")
			tc.assert(t, scripts[0], scripts[1])
		})
	}
}

// serverError stands for an error reply from the server.
type serverError string

func (e serverError) Error() string { return string(e) }
func (serverError) RedisError()     {}

// TestProbeError pins how Verify classifies a failed probe run: an ACL
// refusal, worded as each server words it, is a configuration error naming
// what is missing without repeating the server's text; anything else is not.
func TestProbeError(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		err    error
		assert func(t *testing.T, err error)
	}

	refused := func(want string, server error) func(t *testing.T, err error) {
		return func(t *testing.T, err error) {
			require.ErrorIs(t, err, ratelimit.ErrConfig)
			assert.Contains(t, err.Error(), want)
			assert.NotContains(t, err.Error(), server.Error(), "the server's text was repeated")
			assert.NotContains(t, err.Error(), "limiter@", "the server's text was repeated")
			assert.NotContains(t, strings.ToUpper(err.Error()), "SECRET_CMD", "a command the server named was repeated")
		}
	}
	notConfig := func(t *testing.T, err error) {
		require.Error(t, err)
		assert.NotErrorIs(t, err, ratelimit.ErrConfig)
	}

	redis72 := serverError("ERR ACL failure in script: User limiter@ has no permissions to run the 'time' command script: 8a2f, on @user_script:4.")
	redis70 := serverError("ERR The user executing the script can't run this command or subcommand script: 104a, on @user_script:1.")
	keys := serverError("NOPERM this user has no permissions to access one of the keys used as arguments")
	direct := serverError("NOPERM User limiter@ has no permissions to run the 'evalsha' command")
	unknown := serverError("ERR ACL failure in script: User limiter@ has no permissions to run the 'secret_cmd' command")

	cases := []testCase{
		{name: "a script's command refused, named by the server", err: redis72, assert: refused("the TIME command", redis72)},
		{
			// Redis 7.0 does not name the command, so every one the
			// scripts run is listed.
			name: "a script's command refused, unnamed by Redis 7.0", err: redis70,
			assert: refused("TIME, ZRANGE, ZADD, ZREMRANGEBYRANK, ZREM, PTTL, PEXPIRE, ZCOUNT", redis70),
		},
		{name: "a key refused", err: keys, assert: refused("keys under its prefix", keys)},
		{name: "a script command refused", err: direct, assert: refused("the EVALSHA command", direct)},
		{
			// A name outside the limiter's own commands is not repeated.
			name:   "an unknown command name is not repeated",
			err:    unknown,
			assert: refused("TIME, ZRANGE, ZADD, ZREMRANGEBYRANK, ZREM, PTTL, PEXPIRE, ZCOUNT", unknown),
		},
		{name: "a full server is not a configuration error", err: serverError("OOM command not allowed when used memory > 'maxmemory'."), assert: notConfig},
		{name: "an unreachable server is not a configuration error", err: errors.New("dial tcp: connection refused"), assert: notConfig},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, redisstore.ProbeError(tc.err))
		})
	}
}

// TestCheckVersion pins the server version floor against the INFO server
// text each server sends. The servers themselves are covered by
// TestRedisVerify in the test module; this covers versions no pinned image
// reports, such as a Valkey whose redis_version alone would pass.
func TestCheckVersion(t *testing.T) {
	t.Parallel()

	info := func(lines ...string) string {
		s := "# Server\r\n"
		for _, l := range lines {
			s += l + "\r\n"
		}
		return s
	}

	type testCase struct {
		name   string
		info   string
		assert func(t *testing.T, err error)
	}

	accepted := func(t *testing.T, err error) { require.NoError(t, err) }
	refused := func(want ...string) func(t *testing.T, err error) {
		return func(t *testing.T, err error) {
			require.ErrorIs(t, err, ratelimit.ErrConfig)
			for _, w := range want {
				assert.Contains(t, err.Error(), w)
			}
		}
	}

	cases := []testCase{
		{name: "Redis 7.0.0 is the floor", info: info("redis_version:7.0.0", "redis_mode:standalone"), assert: accepted},
		{name: "Redis 8", info: info("redis_version:8.10.2"), assert: accepted},
		{name: "Redis 10", info: info("redis_version:10.0.0"), assert: accepted},
		{name: "Redis 6.2 is refused", info: info("redis_version:6.2.14"), assert: refused("Redis 6.2.14", "Redis 7.0")},
		{name: "Redis 6.10 is refused, compared as numbers", info: info("redis_version:6.10.0"), assert: refused("Redis 7.0")},
		{name: "Valkey 7.2.0 is the floor", info: info("redis_version:7.2.4", "valkey_version:7.2.0"), assert: accepted},
		{name: "Valkey 8 reports redis_version 7.2.4", info: info("redis_version:7.2.4", "server_name:valkey", "valkey_version:8.1.10"), assert: accepted},
		{
			name:   "Valkey is judged by valkey_version, not redis_version",
			info:   info("redis_version:7.2.4", "valkey_version:7.1.9"),
			assert: refused("Valkey 7.1.9", "Valkey 7.2"),
		},
		{name: "no version field", info: info("redis_mode:standalone"), assert: refused("version")},
		{name: "an unparsable version names the floor", info: info("redis_version:seven"), assert: refused(`"seven"`, "Redis 7.0")},
		{
			name:   "an unparsable Valkey version names Valkey's floor",
			info:   info("redis_version:7.2.4", "valkey_version:eight"),
			assert: refused(`"eight"`, "Valkey 7.2"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, redisstore.CheckVersion(tc.info))
		})
	}
}
