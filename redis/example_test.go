package scrtyredis_test

import (
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/kartaladev/scrty/ratelimit"
	scrtyredis "github.com/kartaladev/scrty/redis"
)

// Example_sharedLimiter builds the factory every flow takes its limiter from.
// Nothing here talks to the server, so it runs without one: construction
// performs no I/O, and Verify is the step that does.
func Example_sharedLimiter() {
	// ContextTimeoutEnabled is required: without it a context's deadline
	// does not bound a call to a server that hangs, and the constructors
	// refuse the client.
	client := redis.NewClient(&redis.Options{Addr: "localhost:6379", ContextTimeoutEnabled: true})
	defer func() { _ = client.Close() }()

	// The default refuses every check while the server cannot be reached,
	// which suits the source-keyed flows the chain guards.
	factory, err := scrtyredis.NewLimiterFactory(client)
	if err != nil {
		panic(err)
	}

	// WithOnUnavailable applies to every flow built from the factory it is
	// given to, so second-factor flows, which should keep a per-replica bound
	// during an outage rather than refuse every sign-in, take a factory of
	// their own over the same client.
	secondFactor, err := scrtyredis.NewLimiterFactory(client,
		scrtyredis.WithOnUnavailable(ratelimit.UnavailableFallBackToLocal),
	)
	if err != nil {
		panic(err)
	}

	// At startup, before traffic, check the server: its version, its
	// maxmemory-policy, and that the scripts load and run.
	//
	//	if err := factory.Verify(ctx); err != nil {
	//		log.Fatal(err)
	//	}
	//
	// Then hand each factory to the flows it serves, which build their own
	// limiters with their own namespace, limit and window:
	//
	//	chain, err := httpsec.New(httpsec.WithRateLimiterFactory(factory), ...)
	//	throttle, err := mfa.NewVerifyThrottle(mfa.WithVerifyLimiterFactory(secondFactor), ...)
	_ = secondFactor

	limiter, err := factory.NewLimiter("api-key", 20, time.Minute)
	fmt.Println(limiter != nil, err)

	// The same namespace with another policy is a wiring mistake.
	_, err = factory.NewLimiter("api-key", 5, time.Minute)
	fmt.Println(err != nil)
	// Output:
	// true <nil>
	// true
}
