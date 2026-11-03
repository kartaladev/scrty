package httpsec

// Internal tests and benchmarks of the default replay store's shards. They
// read the shards directly, which the external tests cannot.

import (
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// shardLen is how many records the shard at index i holds.
func (m *memoryReplayStore) shardLen(i int) int {
	s := &m.shards[i]

	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.seen)
}

// TestMemoryReplayStore_SweepsOnlyItsShard pins that a sweep walks only the
// shard the Record that triggered it landed on: expired records in every
// other shard stay until a Record on their own shard sweeps them.
//
// Standalone: one scenario, not a row of inputs.
func TestMemoryReplayStore_SweepsOnlyItsShard(t *testing.T) {
	t.Parallel()

	base := time.Unix(1_700_000_000, 0)
	var now atomic.Pointer[time.Time]
	now.Store(&base)
	m := newMemoryReplayStore(func() time.Time { return *now.Load() })

	var before [replayShardCount]int
	for i := range 16 * replayShardCount {
		key := replayKey("j-"+strconv.Itoa(i), "jkt")
		fresh, err := m.Record(t.Context(), key, base.Add(time.Second))
		require.NoError(t, err)
		require.True(t, fresh)
		before[replayShardIndex(key)]++
	}
	for i, n := range before {
		require.Positive(t, n, "shard %d holds a record before the sweep", i)
	}

	later := base.Add(2 * replaySweepInterval)
	now.Store(&later)

	trigger := replayKey("j-trigger", "jkt")
	fresh, err := m.Record(t.Context(), trigger, later.Add(time.Minute))
	require.NoError(t, err)
	require.True(t, fresh)

	swept := replayShardIndex(trigger)
	for i := range replayShardCount {
		if i == swept {
			assert.Equal(t, 1, m.shardLen(i), "the swept shard holds only the trigger")

			continue
		}
		assert.Equal(t, before[i], m.shardLen(i), "shard %d is not swept by another shard's Record", i)
	}
}

// TestMemoryReplayStore_SameKeyAtOnce pins that the same key recorded by many
// goroutines at once is fresh for exactly one. Run it with -race.
//
// Standalone: a barrier test, not a row of inputs.
func TestMemoryReplayStore_SameKeyAtOnce(t *testing.T) {
	t.Parallel()

	base := time.Unix(1_700_000_000, 0)
	m := newMemoryReplayStore(func() time.Time { return base })
	key := replayKey("j-1", "jkt")

	const recorders = 64

	var (
		start sync.WaitGroup
		done  sync.WaitGroup
		fresh atomic.Int64
	)

	start.Add(1)
	for range recorders {
		done.Add(1)
		go func() {
			defer done.Done()

			start.Wait()

			ok, err := m.Record(t.Context(), key, base.Add(time.Minute))
			assert.NoError(t, err)
			if ok {
				fresh.Add(1)
			}
		}()
	}
	start.Done()
	done.Wait()

	assert.EqualValues(t, 1, fresh.Load(), "exactly one Record is fresh")
}

// replayBenchSizes are the store sizes the benchmarks fill: 600,000 is about
// 5,000 proofs a second kept for two minutes.
var replayBenchSizes = []int{10_000, 100_000, 600_000}

// fillReplayStore fills a store with n records kept until until, with no
// sweep due before the far future.
func fillReplayStore(b *testing.B, n int, now, until time.Time) *memoryReplayStore {
	b.Helper()

	m := newMemoryReplayStore(func() time.Time { return now })
	for i := range n {
		key := replayKey("j-"+strconv.Itoa(i), "jkt")
		m.shards[replayShardIndex(key)].seen[key] = until
	}
	for i := range m.shards {
		m.shards[i].nextSweep = now.Add(100 * 365 * 24 * time.Hour)
	}

	return m
}

// BenchmarkReplayRecordNormal times a Record that sweeps nothing, against a
// filled store.
func BenchmarkReplayRecordNormal(b *testing.B) {
	for _, n := range replayBenchSizes {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			base := time.Unix(1_700_000_000, 0)
			until := base.Add(3 * time.Minute)
			m := fillReplayStore(b, n, base, until)
			keys := make([]string, b.N)
			for i := range keys {
				keys[i] = replayKey("new-"+strconv.Itoa(i), "jkt")
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := range b.N {
				_, _ = m.Record(b.Context(), keys[i], until)
			}
		})
	}
}

// BenchmarkReplayRecordSweep times the one Record that sweeps its shard, which
// holds every other Record on that shard waiting. "live" deletes nothing;
// "expired" deletes every record the shard holds. Only the swept shard is
// refilled between iterations, with the timer stopped.
func BenchmarkReplayRecordSweep(b *testing.B) {
	for _, mode := range []string{"live", "expired"} {
		for _, n := range replayBenchSizes {
			b.Run(mode+"/"+strconv.Itoa(n), func(b *testing.B) {
				base := time.Unix(1_700_000_000, 0)
				until := base.Add(3 * time.Minute)
				if mode == "expired" {
					until = base.Add(-time.Second)
				}
				m := fillReplayStore(b, n, base, until)
				trigger := replayKey("j-trigger", "jkt")
				s := &m.shards[replayShardIndex(trigger)]
				filled := make(map[string]time.Time, len(s.seen))
				for k, v := range s.seen {
					filled[k] = v
				}

				b.ReportAllocs()
				b.ResetTimer()
				for range b.N {
					b.StopTimer()
					delete(s.seen, trigger)
					for k, v := range filled {
						s.seen[k] = v
					}
					s.nextSweep = base
					b.StartTimer()

					_, _ = m.Record(b.Context(), trigger, base.Add(3*time.Minute))
				}
			})
		}
	}
}
