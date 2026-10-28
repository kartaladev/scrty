package redisstore_test

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"testing"

	"github.com/redis/go-redis/v9"
)

// recorder stands in for the network under a real go-redis client: it records
// every command the client would send, answers each script call with reply,
// and refuses to dial, so a test sees exactly what the limiter asks the
// server and proves when it asks nothing.
type recorder struct {
	mu    sync.Mutex
	cmds  [][]any
	dials int
	reply any
	// info is the reply to INFO; CONFIG GET answers noeviction, and SCRIPT
	// LOAD a digest, so Verify can run against a recorder.
	info string
}

func (r *recorder) DialHook(redis.DialHook) redis.DialHook {
	return func(context.Context, string, string) (net.Conn, error) {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.dials++
		return nil, errors.New("recorder: dial attempted")
	}
}

func (r *recorder) ProcessHook(redis.ProcessHook) redis.ProcessHook {
	return func(_ context.Context, cmd redis.Cmder) error {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.cmds = append(r.cmds, cmd.Args())
		switch c := cmd.(type) {
		case *redis.Cmd:
			c.SetVal(r.reply)
		case *redis.StringCmd:
			c.SetVal(r.info) // INFO, and SCRIPT LOAD, whose digest is unused
		case *redis.MapStringStringCmd:
			c.SetVal(map[string]string{"maxmemory-policy": "noeviction"})
		}
		return nil
	}
}

func (r *recorder) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

func (r *recorder) commands() [][]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([][]any(nil), r.cmds...)
}

func (r *recorder) dialled() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.dials
}

// recordingClient returns a client over a recorder, pointed at an address
// nothing listens on.
func recordingClient(t *testing.T, reply any) (*redis.Client, *recorder) {
	t.Helper()

	rec := &recorder{reply: reply}
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", MaxRetries: -1, ContextTimeoutEnabled: true})
	client.AddHook(rec)
	t.Cleanup(func() { _ = client.Close() })
	return client, rec
}

func quietLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

// clusterClient returns a NewLimiter client factory for a cluster client
// whose options, ContextTimeoutEnabled set, set changes, pointed at an
// address nothing listens on. Building one performs no I/O.
func clusterClient(set func(*redis.ClusterOptions)) func(t *testing.T) redis.UniversalClient {
	return func(t *testing.T) redis.UniversalClient {
		opts := &redis.ClusterOptions{Addrs: []string{"127.0.0.1:1"}, ContextTimeoutEnabled: true}
		if set != nil {
			set(opts)
		}
		c := redis.NewClusterClient(opts)
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
}

// plainClient returns a NewLimiter client factory for a single-node client
// whose options, ContextTimeoutEnabled set, set changes, pointed at an
// address nothing listens on.
func plainClient(set func(*redis.Options)) func(t *testing.T) redis.UniversalClient {
	return func(t *testing.T) redis.UniversalClient {
		opts := &redis.Options{Addr: "127.0.0.1:1", ContextTimeoutEnabled: true}
		if set != nil {
			set(opts)
		}
		c := redis.NewClient(opts)
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
}

// ringClient returns a NewLimiter client factory for a ring whose options,
// ContextTimeoutEnabled set, set changes, over one shard nothing listens on.
func ringClient(set func(*redis.RingOptions)) func(t *testing.T) redis.UniversalClient {
	return func(t *testing.T) redis.UniversalClient {
		opts := &redis.RingOptions{Addrs: map[string]string{"shard": "127.0.0.1:1"}, ContextTimeoutEnabled: true}
		if set != nil {
			set(opts)
		}
		c := redis.NewRing(opts)
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
}

// Setters that leave each client type's ContextTimeoutEnabled off.
var (
	noClientContextTimeout  = func(o *redis.Options) { o.ContextTimeoutEnabled = false }
	noClusterContextTimeout = func(o *redis.ClusterOptions) { o.ContextTimeoutEnabled = false }
	noRingContextTimeout    = func(o *redis.RingOptions) { o.ContextTimeoutEnabled = false }
)
