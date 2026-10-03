package test

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/ratelimit"
	scrtyredis "github.com/kartaladev/scrty/redis"
)

// Settings of the fault tests. The operation timeout is long, so that a call
// which waited it out and one the breaker answered at once cannot be confused
// under -race; the probe interval is short, so that a case can wait it out.
const (
	faultTimeout       = 2 * time.Second
	faultProbeInterval = 200 * time.Millisecond
	faultLimit         = 3
	faultWindow        = time.Minute
	faultSource        = "203.0.113.7"

	// hungTimeout is the operation timeout of the hung-server cases, and
	// hungMargin how much later than it a call may still return.
	hungTimeout = 250 * time.Millisecond
	hungMargin  = 200 * time.Millisecond
	// hungFor is how long a hung server stays unresponsive.
	hungFor = 5 * time.Second
)

// debugArgs let the server run DEBUG for a client that is not local, which
// the hung-server cases need to make it stop answering.
var debugArgs = []string{"--enable-debug-command", "yes"}

// uninspectedClient hides a client's concrete type, as a consumer's own
// redis.UniversalClient implementation would, so the constructors cannot
// read its options. The control case uses it to build a limiter over a client
// that leaves ContextTimeoutEnabled off.
type uninspectedClient struct{ *redis.Client }

// hang makes the server behind conn stop answering for hungFor, through a
// connection of its own, and returns once it has. The cleanup waits for the
// server to answer again.
func hang(t *testing.T, conn RedisConn) {
	t.Helper()

	opts := *conn.Client.Options()
	opts.ReadTimeout = hungFor + 5*time.Second
	opts.ContextTimeoutEnabled = false
	sleeper := redis.NewClient(&opts)
	require.NoError(t, sleeper.Ping(t.Context()).Err())

	done := make(chan error, 1)
	go func() {
		// Not t.Context(): the sleep must outlast the assertions.
		done <- sleeper.Do(context.Background(), "DEBUG", "SLEEP", strconv.Itoa(int(hungFor/time.Second))).Err()
	}()
	t.Cleanup(func() {
		if err := <-done; err != nil {
			t.Errorf("DEBUG SLEEP failed: %s", err)
		}
		_ = sleeper.Close()
	})

	// The sleep has begun once the server stops answering a PING.
	probe := redis.NewClient(&redis.Options{Addr: opts.Addr, Dialer: opts.Dialer, ReadTimeout: 20 * time.Millisecond, MaxRetries: -1})
	defer func() { _ = probe.Close() }()
	require.Eventually(t, func() bool { return probe.Ping(context.Background()).Err() != nil },
		time.Second, 10*time.Millisecond, "the server kept answering")
}

// commandCounter is a client hook counting the commands the client sends, so
// a test sees whether a call reached the network at all.
type commandCounter struct{ n atomic.Int64 }

func (c *commandCounter) DialHook(next redis.DialHook) redis.DialHook { return next }

func (c *commandCounter) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		c.n.Add(1)
		return next(ctx, cmd)
	}
}

func (c *commandCounter) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

// fillMemory writes filler keys until the server, at its maxmemory under
// noeviction, refuses a write as out of memory, and fails the test if it
// never does.
func fillMemory(t *testing.T, client *redis.Client) {
	t.Helper()

	filler := strings.Repeat("x", 16<<10)
	for i := range 4096 {
		err := client.Set(t.Context(), fmt.Sprintf("filler:%d", i), filler, 0).Err()
		if err == nil {
			continue
		}
		require.ErrorContains(t, err, "OOM", "a filler write failed other than for lack of memory")
		return
	}
	t.Fatal("the server never ran out of memory")
}

// attempt runs one guarded attempt from faultSource that fails: it reports
// whether the guard admitted it, and records the failure when it did.
func attempt(t *testing.T, guard *ratelimit.SourceGuard) bool {
	t.Helper()

	src, err := guard.Check(t.Context(), faultSource)
	if err != nil {
		require.ErrorIs(t, err, ratelimit.ErrThrottled)
		return false
	}
	guard.RecordFailure(t.Context(), src)
	return true
}

// TestRedisLimiter_Fault pins what the Redis limiter does when the server
// fails under it: out of memory, so that writes fail while reads succeed, and
// stopped, in each unavailable mode. Each case starts a server of its own.
func TestRedisLimiter_Fault(t *testing.T) {
	t.Parallel()

	type env struct {
		conn     RedisConn
		commands *commandCounter
		logs     *logRecorder
		// build returns a limiter over conn's client for namespace
		// "api-key", with the fault settings, a logger writing to logs and
		// opts.
		build func(opts ...scrtyredis.Option) *scrtyredis.Limiter
		// buildOn is build over client in place of conn's.
		buildOn func(client redis.UniversalClient, opts ...scrtyredis.Option) *scrtyredis.Limiter
	}

	type testCase struct {
		name   string
		args   []string
		assert func(t *testing.T, e env)
	}

	// outOfMemory fills the server's memory, then fails faultSource ten
	// times through a guard over a limiter built with opts. Between attempts
	// it waits out the probe interval, so that every check after the first
	// reaches the server, whose reads still succeed and count nothing. It
	// returns which attempts the guard admitted.
	outOfMemory := func(t *testing.T, e env, opts ...scrtyredis.Option) []bool {
		t.Helper()

		fillMemory(t, e.conn.Client)
		guard, err := ratelimit.NewSourceGuard("api-key", e.build(opts...),
			ratelimit.WithSourceGuardLogger(slog.New(slog.DiscardHandler)))
		require.NoError(t, err)

		admitted := make([]bool, 10)
		for i := range admitted {
			admitted[i] = attempt(t, guard)
			time.Sleep(faultProbeInterval + 100*time.Millisecond)
		}
		return admitted
	}

	// cutOff hangs the server under l, then checks once: it returns how long
	// the check took, its answer and its error.
	cutOff := func(t *testing.T, e env, l *scrtyredis.Limiter) (time.Duration, bool, error) {
		t.Helper()

		// A pooled connection, so the check below waits on a read rather
		// than on a dial.
		_, err := l.Exceeded(t.Context(), faultSource)
		require.NoError(t, err)
		hang(t, e.conn)

		start := time.Now()
		exceeded, err := l.Exceeded(t.Context(), faultSource)
		return time.Since(start), exceeded, err
	}

	cases := []testCase{
		{
			name: "a hung server is cut off at the operation timeout, and the breaker opens",
			args: debugArgs,
			assert: func(t *testing.T, e env) {
				l := e.build(scrtyredis.WithOperationTimeout(hungTimeout))
				elapsed, exceeded, err := cutOff(t, e, l)
				assert.Less(t, elapsed, hungTimeout+hungMargin, "the check waited past the operation timeout")
				assert.True(t, exceeded)
				require.ErrorIs(t, err, ratelimit.ErrBackendUnavailable)

				// The breaker is open: the next check is answered at once,
				// without the server.
				sent := e.commands.n.Load()
				start := time.Now()
				exceeded, err = l.Exceeded(t.Context(), faultSource)
				assert.Less(t, time.Since(start), 50*time.Millisecond, "the second check waited for the server")
				assert.True(t, exceeded)
				require.ErrorIs(t, err, ratelimit.ErrBackendUnavailable)
				assert.Equal(t, sent, e.commands.n.Load(), "the second check called the server inside the probe interval")
			},
		},
		{
			name: "Verify honours its caller's deadline against a hung server",
			args: debugArgs,
			assert: func(t *testing.T, e env) {
				l := e.build()
				require.NoError(t, l.Verify(t.Context()))
				hang(t, e.conn)

				ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
				defer cancel()
				start := time.Now()
				err := l.Verify(ctx)
				elapsed := time.Since(start)
				require.Error(t, err)
				assert.Less(t, elapsed, 200*time.Millisecond+hungMargin, "Verify waited past its caller's deadline")
			},
		},
		{
			// The control: the client must set ContextTimeoutEnabled,
			// because go-redis reads past a context's deadline without it.
			// The constructors refuse such a client where they can read its
			// options; this one hides them, so the limiter is built, and the
			// check is not cut off. It shows the case above would fail
			// without the option.
			name: "control: a client without ContextTimeoutEnabled is not cut off",
			args: debugArgs,
			assert: func(t *testing.T, e env) {
				opts := *e.conn.Client.Options()
				opts.ContextTimeoutEnabled = false
				client := redis.NewClient(&opts)
				t.Cleanup(func() { _ = client.Close() })

				elapsed, _, _ := cutOff(t, e, e.buildOn(uninspectedClient{client}, scrtyredis.WithOperationTimeout(hungTimeout)))
				assert.Greater(t, elapsed, time.Second, "the check was cut off although the client ignores context deadlines")
			},
		},
		{
			name: "writes fail while reads succeed: refused after the first unrecorded failure",
			args: []string{"--maxmemory", "2mb", "--maxmemory-policy", "noeviction"},
			assert: func(t *testing.T, e env) {
				admitted := outOfMemory(t, e)
				assert.Equal(t, []bool{true, false, false, false, false, false, false, false, false, false}, admitted,
					"the source was admitted after a failure the server could not record")

				// Reads still reach the server: a source that never failed is
				// answered by it, not refused.
				other := e.build()
				exceeded, err := other.Exceeded(t.Context(), "198.51.100.1")
				require.NoError(t, err, "a read failed while the server was out of memory")
				assert.False(t, exceeded)

				// And the writes fail for lack of memory, not for another
				// reason.
				err = other.RecordFailure(t.Context(), "198.51.100.1")
				require.ErrorIs(t, err, ratelimit.ErrBackendUnavailable)
				var reply redis.Error
				require.ErrorAs(t, err, &reply, "the record failed without a server reply")
				assert.Contains(t, reply.Error(), "OOM")
			},
		},
		{
			// The control: allow mode drops a failure it could not record,
			// which is the naive behaviour, so the source is never refused.
			// It shows the case above would fail without the hold.
			name: "control: allow mode drops failed records, so the source is never refused",
			args: []string{"--maxmemory", "2mb", "--maxmemory-policy", "noeviction"},
			assert: func(t *testing.T, e env) {
				admitted := outOfMemory(t, e, scrtyredis.WithOnUnavailable(ratelimit.UnavailableAllow))
				assert.NotContains(t, admitted, false, "the source was refused although its failures were dropped")
			},
		},
		{
			name: "refuse while stopped: refused as throttled, then without waiting for the timeout",
			assert: func(t *testing.T, e env) {
				l := e.build()
				guard, err := ratelimit.NewSourceGuard("api-key", l,
					ratelimit.WithSourceGuardLogger(slog.New(slog.DiscardHandler)))
				require.NoError(t, err)
				e.conn.Stop(t)

				_, err = guard.Check(t.Context(), faultSource)
				require.ErrorIs(t, err, ratelimit.ErrThrottled, "a guard over a stopped server admitted the attempt")
				assert.ErrorIs(t, err, ratelimit.ErrBackendUnavailable)

				sent := e.commands.n.Load()
				start := time.Now()
				exceeded, err := l.Exceeded(t.Context(), faultSource)
				elapsed := time.Since(start)
				assert.True(t, exceeded)
				require.ErrorIs(t, err, ratelimit.ErrBackendUnavailable)
				assert.Less(t, elapsed, 50*time.Millisecond, "the second check waited for the server")
				assert.Equal(t, sent, e.commands.n.Load(), "the second check called the server inside the probe interval")
			},
		},
		{
			name: "fall back while stopped, and recover",
			assert: func(t *testing.T, e env) {
				l := e.build(scrtyredis.WithOnUnavailable(ratelimit.UnavailableFallBackToLocal))
				e.conn.Stop(t)

				for range faultLimit {
					require.NoError(t, l.RecordFailure(t.Context(), faultSource), "a failure was not counted locally")
				}
				exceeded, err := l.Exceeded(t.Context(), faultSource)
				require.NoError(t, err)
				assert.True(t, exceeded, "three local failures do not exceed a limit of three")
				errs := e.logs.at(slog.LevelError)
				require.Len(t, errs, 1, "the fall-back was not recorded exactly once")
				assert.Contains(t, errs[0].message, "counting locally")

				e.conn.Start(t)
				// Failures only the server holds, recorded by another
				// instance after the restart.
				other := e.build()
				for range faultLimit {
					require.NoError(t, other.RecordFailure(t.Context(), "198.51.100.1"))
				}
				time.Sleep(faultProbeInterval + 100*time.Millisecond)

				sent := e.commands.n.Load()
				exceeded, err = l.Exceeded(t.Context(), "198.51.100.1")
				require.NoError(t, err)
				assert.True(t, exceeded, "the check after the probe interval did not use the server's answer")
				assert.Greater(t, e.commands.n.Load(), sent, "the check after the probe interval did not reach the server")
				exceeded, err = l.Exceeded(t.Context(), faultSource)
				require.NoError(t, err)
				assert.True(t, exceeded, "the failures counted locally during the outage were forgotten")
				warns := e.logs.at(slog.LevelWarn)
				require.Len(t, warns, 1, "the recovery was not recorded exactly once")
				assert.Contains(t, warns[0].message, "available again")
			},
		},
		{
			name: "allow while stopped: not exceeded, one error record",
			assert: func(t *testing.T, e env) {
				l := e.build(scrtyredis.WithOnUnavailable(ratelimit.UnavailableAllow))
				e.conn.Stop(t)

				for range 5 {
					require.NoError(t, l.RecordFailure(t.Context(), faultSource))
					exceeded, err := l.Exceeded(t.Context(), faultSource)
					require.NoError(t, err)
					assert.False(t, exceeded, "allow mode refused during the outage")
				}
				errs := e.logs.at(slog.LevelError)
				require.Len(t, errs, 1, "the outage was not recorded exactly once")
				assert.Contains(t, errs[0].message, "allowing every attempt")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			testOpts := []TestOption{WithTestRedisOwnContainer()}
			if len(tc.args) > 0 {
				testOpts = append(testOpts, WithTestRedisServerArgs(tc.args...))
			}
			conn := RunTestRedis(t, testOpts...)
			commands := &commandCounter{}
			conn.Client.AddHook(commands)
			logs := &logRecorder{}

			buildOn := func(client redis.UniversalClient, opts ...scrtyredis.Option) *scrtyredis.Limiter {
				opts = append([]scrtyredis.Option{
					scrtyredis.WithOperationTimeout(faultTimeout),
					scrtyredis.WithUnavailableProbeInterval(faultProbeInterval),
					scrtyredis.WithLogger(slog.New(logs)),
				}, opts...)
				l, err := scrtyredis.NewLimiter(client, "api-key", faultLimit, faultWindow, opts...)
				require.NoError(t, err)
				return l
			}

			tc.assert(t, env{
				conn:     conn,
				commands: commands,
				logs:     logs,
				build: func(opts ...scrtyredis.Option) *scrtyredis.Limiter {
					return buildOn(conn.Client, opts...)
				},
				buildOn: buildOn,
			})
		})
	}
}
