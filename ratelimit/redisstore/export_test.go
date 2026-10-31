package redisstore

import (
	"context"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/kartaladev/scrty/internal/unavailable"
	"github.com/kartaladev/scrty/ratelimit"
)

// StorageKey exposes storageKey to the external tests.
var StorageKey = storageKey

// DecoratorConfig returns the decorator configuration opts produce.
func DecoratorConfig(opts ...Option) unavailable.Config {
	return newConfig(opts).unavailable
}

// MaxRawKeyLen is the longest key stored as given.
const MaxRawKeyLen = maxRawKeyLen

// CheckVersion exposes checkVersion, the server version floor, to the
// external tests; info is the text of INFO server.
var CheckVersion = checkVersion

// ProbeError exposes probeError, how Verify classifies a failed probe run.
var ProbeError = probeError

// BackendCharge runs one charge through the server-facing backend alone,
// without the decorator that wraps it in a Limiter, so a test sees the answer
// the backend itself gives.
func BackendCharge(ctx context.Context, client redis.UniversalClient, namespace string, limit int, window time.Duration, key string) (ratelimit.Receipt, bool, error) {
	b := &backend{
		client:   client,
		prefix:   newConfig(nil).prefix + namespace + ":",
		limit:    strconv.Itoa(limit),
		limitN:   int64(limit),
		windowUS: strconv.FormatInt(window.Microseconds(), 10),
	}

	return b.Charge(ctx, key)
}
