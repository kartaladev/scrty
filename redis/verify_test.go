package scrtyredis_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/ratelimit"
	scrtyredis "github.com/kartaladev/scrty/redis"
)

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

			tc.assert(t, scrtyredis.CheckVersion(tc.info))
		})
	}
}
