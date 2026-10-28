package noalias

import (
	"github.com/redis/go-redis/v9"

	"github.com/kartaladev/scrty/ratelimit/redisstore"
)

// NewLimiters builds a limiter factory over a Redis client.
func NewLimiters(client redis.UniversalClient) (*redisstore.Factory, error) {
	return redisstore.NewLimiterFactory(client)
}
