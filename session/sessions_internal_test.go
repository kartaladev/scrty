package session

import (
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestKeyedMutexReclaimsEntries pins that the per-identifier lock keeps
// nothing it is not using. A map that only ever grows would be a leak keyed by
// session identifier: one dead mutex for every session ever rotated, held for
// the life of the process.
func TestKeyedMutexReclaimsEntries(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		use  func(k *keyedMutex)
	}

	cases := []testCase{
		{
			name: "one key taken and released in turn",
			use: func(k *keyedMutex) {
				for range 4 {
					k.lock("s-1")()
				}
			},
		},
		{
			name: "many holders of one key",
			use: func(k *keyedMutex) {
				var wg sync.WaitGroup

				wg.Add(8)
				for range 8 {
					go func() {
						defer wg.Done()
						unlock := k.lock("s-1")
						unlock()
					}()
				}
				wg.Wait()
			},
		},
		{
			name: "many keys at once",
			use: func(k *keyedMutex) {
				var wg sync.WaitGroup

				wg.Add(8)
				for i := range 8 {
					go func() {
						defer wg.Done()
						unlock := k.lock("s-" + strconv.Itoa(i))
						unlock()
					}()
				}
				wg.Wait()
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var k keyedMutex
			tc.use(&k)

			k.mu.Lock()
			defer k.mu.Unlock()

			assert.Empty(t, k.held, "every released key must leave the map")
		})
	}
}
