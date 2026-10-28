module example.com/fixture/noaliasredis

go 1.27

require (
	github.com/kartaladev/scrty/ratelimit/redisstore v0.0.0
	github.com/redis/go-redis/v9 v9.22.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/kartaladev/scrty v0.0.0 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
)

replace (
	github.com/kartaladev/scrty => ../../..
	github.com/kartaladev/scrty/ratelimit/redisstore => ../../../ratelimit/redisstore
)
