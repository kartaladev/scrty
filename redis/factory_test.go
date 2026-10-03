package scrtyredis_test

import (
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/ratelimit"
	scrtyredis "github.com/kartaladev/scrty/redis"
)

func TestNewLimiterFactory(t *testing.T) {
	t.Parallel()

	var nilClient *redis.Client
	var nilRing *redis.Ring

	type testCase struct {
		name   string
		client func(t *testing.T) redis.UniversalClient // nil means a recording client
		opts   []scrtyredis.Option
		assert func(t *testing.T, f *scrtyredis.Factory, rec *recorder, err error)
	}

	refused := func(want string) func(t *testing.T, f *scrtyredis.Factory, _ *recorder, err error) {
		return func(t *testing.T, f *scrtyredis.Factory, _ *recorder, err error) {
			require.ErrorIs(t, err, ratelimit.ErrConfig)
			assert.Contains(t, err.Error(), want)
			assert.Nil(t, f)
		}
	}

	cases := []testCase{
		{
			name: "a nil option among valid ones is skipped",
			opts: []scrtyredis.Option{scrtyredis.WithKeyPrefix("app:rl:"), nil, scrtyredis.WithLogger(quietLogger())},
			assert: func(t *testing.T, f *scrtyredis.Factory, _ *recorder, err error) {
				require.NoError(t, err)
				assert.NotNil(t, f)
			},
		},
		{
			name: "defaults accepted without I/O",
			assert: func(t *testing.T, f *scrtyredis.Factory, rec *recorder, err error) {
				require.NoError(t, err)
				require.NotNil(t, f)
				assert.Empty(t, rec.commands(), "construction sent a command")
				assert.Zero(t, rec.dialled(), "construction dialled the server")
			},
		},
		{
			name:   "nil client",
			client: func(*testing.T) redis.UniversalClient { return nil },
			assert: refused("client is nil"),
		},
		{
			name:   "typed nil client",
			client: func(*testing.T) redis.UniversalClient { return nilClient },
			assert: refused("client is nil"),
		},
		{
			name:   "typed nil ring",
			client: func(*testing.T) redis.UniversalClient { return nilRing },
			assert: refused("client is nil"),
		},
		{
			name:   "cluster client reading from replicas",
			client: clusterClient(func(o *redis.ClusterOptions) { o.ReadOnly = true }),
			assert: refused("ReadOnly"),
		},
		{
			name:   "cluster client routing by latency",
			client: clusterClient(func(o *redis.ClusterOptions) { o.RouteByLatency = true }),
			assert: refused("RouteByLatency"),
		},
		{
			name:   "cluster client routing at random",
			client: clusterClient(func(o *redis.ClusterOptions) { o.RouteRandomly = true }),
			assert: refused("RouteRandomly"),
		},
		{
			name:   "client without ContextTimeoutEnabled",
			client: plainClient(noClientContextTimeout),
			assert: refused("ContextTimeoutEnabled"),
		},
		{
			name:   "cluster client without ContextTimeoutEnabled",
			client: clusterClient(noClusterContextTimeout),
			assert: refused("ContextTimeoutEnabled"),
		},
		{
			name:   "ring client without ContextTimeoutEnabled",
			client: ringClient(noRingContextTimeout),
			assert: refused("ContextTimeoutEnabled"),
		},
		{
			name:   "empty prefix refused at the factory, not at the first limiter",
			opts:   []scrtyredis.Option{scrtyredis.WithKeyPrefix("")},
			assert: refused("prefix is empty"),
		},
		{
			name:   "unknown unavailable mode refused at the factory",
			opts:   []scrtyredis.Option{scrtyredis.WithOnUnavailable(ratelimit.UnavailableMode(42))},
			assert: refused("unknown unavailable mode"),
		},
		{
			name:   "non-positive operation timeout refused at the factory",
			opts:   []scrtyredis.Option{scrtyredis.WithOperationTimeout(0)},
			assert: refused("operation timeout"),
		},
		{
			name:   "nil logger refused at the factory",
			opts:   []scrtyredis.Option{scrtyredis.WithLogger(nil)},
			assert: refused("logger is nil"),
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

			f, err := scrtyredis.NewLimiterFactory(client, append([]scrtyredis.Option{scrtyredis.WithLogger(quietLogger())}, tc.opts...)...)
			tc.assert(t, f, rec, err)
		})
	}
}

func TestFactory_NewLimiter(t *testing.T) {
	t.Parallel()

	type request struct {
		namespace string
		limit     int
		window    time.Duration
	}

	type result struct {
		limiter ratelimit.Limiter
		err     error
	}

	type testCase struct {
		name     string
		requests []request
		// concurrently, when set, sends the requests from that many
		// goroutines at once, goroutine i sending request i modulo their
		// number, over concurrentRounds fresh factories; assert then runs
		// once per round.
		concurrently int
		// assert receives one result per request, in order; concurrently,
		// one per goroutine.
		assert func(t *testing.T, rec *recorder, results []result)
	}

	const concurrentRounds = 200

	accepted := func(t *testing.T, r result) {
		t.Helper()
		require.NoError(t, r.err)
		assert.NotNil(t, r.limiter)
	}
	refused := func(t *testing.T, r result, want ...string) {
		t.Helper()
		require.ErrorIs(t, r.err, ratelimit.ErrConfig)
		for _, w := range want {
			assert.Contains(t, r.err.Error(), w)
		}
		// A nil interface, never a typed nil a flow would take for a limiter.
		assert.True(t, r.limiter == nil, "a refused request returned a non-nil limiter")
	}

	cases := []testCase{
		{
			name:     "one namespace, no I/O",
			requests: []request{{"api-key", 20, time.Minute}},
			assert: func(t *testing.T, rec *recorder, results []result) {
				accepted(t, results[0])
				assert.Empty(t, rec.commands(), "building a limiter sent a command")
				assert.Zero(t, rec.dialled(), "building a limiter dialled the server")
			},
		},
		{
			name:     "the same namespace with the same policy, twice",
			requests: []request{{"api-key", 20, time.Minute}, {"api-key", 20, time.Minute}},
			assert: func(t *testing.T, _ *recorder, results []result) {
				accepted(t, results[0])
				accepted(t, results[1])
			},
		},
		{
			name:     "conflicting limit for one namespace",
			requests: []request{{"api-key", 20, time.Minute}, {"api-key", 5, time.Minute}},
			assert: func(t *testing.T, _ *recorder, results []result) {
				accepted(t, results[0])
				refused(t, results[1], `"api-key"`, "20 per 1m0s", "5 per 1m0s")
			},
		},
		{
			name:     "conflicting window for one namespace",
			requests: []request{{"api-key", 20, time.Minute}, {"api-key", 20, time.Hour}},
			assert: func(t *testing.T, _ *recorder, results []result) {
				accepted(t, results[0])
				refused(t, results[1], `"api-key"`, "20 per 1m0s", "20 per 1h0m0s")
			},
		},
		{
			name:     "different namespaces keep their own policies",
			requests: []request{{"api-key", 20, time.Minute}, {"mfa-verify", 5, 15 * time.Minute}},
			assert: func(t *testing.T, _ *recorder, results []result) {
				accepted(t, results[0])
				accepted(t, results[1])
			},
		},
		{
			name:     "a refused request does not claim the namespace",
			requests: []request{{"api-key", 0, time.Minute}, {"api-key", 20, time.Minute}},
			assert: func(t *testing.T, _ *recorder, results []result) {
				refused(t, results[0], "limit of 0")
				accepted(t, results[1])
			},
		},
		{
			// Two policies race for one namespace: whichever is built
			// first owns it, and only its requests are served.
			name:         "two policies for one namespace, concurrently",
			requests:     []request{{"api-key", 5, time.Minute}, {"api-key", 6, time.Minute}},
			concurrently: 16,
			assert: func(t *testing.T, _ *recorder, results []result) {
				served := map[int]int{}
				for i, r := range results {
					if r.err == nil {
						served[5+i%2]++
						continue
					}
					refused(t, r, `"api-key"`)
				}
				require.Len(t, served, 1, "not exactly one policy won the namespace: %v", served)
				for _, n := range served {
					assert.Equal(t, 8, n, "a request with the winning policy was refused")
				}
			},
		},
		{
			name:     "empty namespace",
			requests: []request{{"", 20, time.Minute}},
			assert: func(t *testing.T, _ *recorder, results []result) {
				refused(t, results[0], "namespace is empty")
			},
		},
		{
			name:     "namespace containing a colon",
			requests: []request{{"api:key", 20, time.Minute}},
			assert: func(t *testing.T, _ *recorder, results []result) {
				refused(t, results[0], "colon")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			client, rec := recordingClient(t, int64(0))

			if tc.concurrently > 0 {
				for range concurrentRounds {
					f, err := scrtyredis.NewLimiterFactory(client, scrtyredis.WithLogger(quietLogger()))
					require.NoError(t, err)

					results := make([]result, tc.concurrently)
					start := make(chan struct{})
					var wg sync.WaitGroup
					for i := range results {
						wg.Go(func() {
							<-start
							r := tc.requests[i%len(tc.requests)]
							l, err := f.NewLimiter(r.namespace, r.limit, r.window)
							results[i] = result{limiter: l, err: err}
						})
					}
					close(start)
					wg.Wait()
					tc.assert(t, rec, results)
				}
				return
			}

			f, err := scrtyredis.NewLimiterFactory(client, scrtyredis.WithLogger(quietLogger()))
			require.NoError(t, err)

			results := make([]result, 0, len(tc.requests))
			for _, r := range tc.requests {
				l, err := f.NewLimiter(r.namespace, r.limit, r.window)
				results = append(results, result{limiter: l, err: err})
			}
			tc.assert(t, rec, results)
		})
	}
}
