package test

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/ratelimit"
	scrtyredis "github.com/kartaladev/scrty/redis"
	"github.com/kartaladev/scrty/test/ratelimittest"
)

// redisServerImages are the servers the shared limiter supports and is tested
// against: the oldest supported Redis and Valkey (the floor Verify enforces),
// the newest Redis 7, the newest Redis, and the newest Valkey 8.
var redisServerImages = []string{RedisMinImage, Redis7Image, RedisImage, ValkeyMinImage, Valkey8Image}

// redisTestTimeout is the operation timeout the integration tests give the
// limiter. The default 250ms is a production bound; under the race detector
// and a busy Docker host a healthy call can take longer, and a call cut off
// would be taken for an outage the test did not stage.
const redisTestTimeout = 5 * time.Second

// redisHarness adapts the Redis limiter to the conformance suite in
// application-clock mode, over one client.
//
// Every namespace a subtest asks for shares one key prefix, derived from the
// subtest's name, so a limiter that ignored its namespace would count two
// namespaces together and the suite would catch it. New clears only the keys
// of its own namespace under that prefix, so a namespace the suite builds
// again starts empty while the subtest's other namespaces keep their counts.
// SecondInstance builds a limiter over the same prefix, as another process
// configured the same way would; it shares no state with the first instance
// except the server.
type redisHarness struct {
	client *redis.Client
	clock  *clockwork.FakeClock
}

func newRedisHarness(client *redis.Client) *redisHarness {
	return &redisHarness{
		client: client,
		// Whole seconds, so the clock reads on whole microseconds however
		// the suite advances it.
		clock: clockwork.NewFakeClockAt(time.Unix(1_700_000_000, 0)),
	}
}

// scopePrefix is the key prefix of t's scope: a digest of the subtest's name,
// so that no character of the name is read as a glob when the scope is
// cleared.
func scopePrefix(t *testing.T) string {
	t.Helper()

	sum := sha256.Sum256([]byte(t.Name()))
	return "conformance:" + hex.EncodeToString(sum[:8]) + ":"
}

// clearNamespace deletes the keys namespace holds under prefix, and no other
// namespace's.
func (h *redisHarness) clearNamespace(t *testing.T, prefix, namespace string) {
	t.Helper()

	ctx := t.Context()
	iter := h.client.Scan(ctx, 0, prefix+namespace+":*", 100).Iterator()
	for iter.Next(ctx) {
		require.NoError(t, h.client.Del(ctx, iter.Val()).Err())
	}
	require.NoError(t, iter.Err())
}

func (h *redisHarness) build(t *testing.T, prefix, namespace string, limit int, window time.Duration) ratelimit.Limiter {
	t.Helper()

	l, err := scrtyredis.NewLimiter(h.client, namespace, limit, window,
		scrtyredis.WithKeyPrefix(prefix),
		scrtyredis.WithLimiterClock(h.clock),
		scrtyredis.WithOperationTimeout(redisTestTimeout),
		scrtyredis.WithLogger(slog.New(slog.DiscardHandler)))
	require.NoError(t, err)
	return l
}

func (h *redisHarness) newLimiter(t *testing.T, namespace string, limit int, window time.Duration) ratelimit.Limiter {
	t.Helper()

	prefix := scopePrefix(t)
	h.clearNamespace(t, prefix, namespace)
	return h.build(t, prefix, namespace, limit, window)
}

func (h *redisHarness) secondInstance(t *testing.T, namespace string, limit int, window time.Duration) ratelimit.Limiter {
	t.Helper()

	return h.build(t, scopePrefix(t), namespace, limit, window)
}

func (h *redisHarness) harness() ratelimittest.Harness {
	return ratelimittest.Harness{
		New:            h.newLimiter,
		Advance:        h.clock.Advance,
		SecondInstance: h.secondInstance,
	}
}

func TestRateLimitConformance_Redis(t *testing.T) {
	t.Parallel()

	for _, image := range redisServerImages {
		t.Run(image, func(t *testing.T) {
			t.Parallel()

			h := newRedisHarness(RunTestRedis(t, WithTestRedisImage(image)).Client).harness()
			require.NotNil(t, h.SecondInstance, "the cross-instance scenarios would be skipped")
			ratelimittest.Run(t, h)
		})
	}
}
