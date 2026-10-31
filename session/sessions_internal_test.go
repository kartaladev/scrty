package session

import (
	"strconv"
	"sync"
	"testing"
	"time"

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

// TestRotatedHandlesForgetEndedWindows pins that the memory of rotated
// handles keeps only windows still open: a handle is recognised until its
// window ends and not after, and an entry whose window has ended leaves the
// memory at the next call, even when its window ends before one remembered
// earlier. A memory that only grew would be a leak keyed by every session
// ever rotated.
func TestRotatedHandlesForgetEndedWindows(t *testing.T) {
	t.Parallel()

	at := time.Date(2026, time.March, 2, 9, 0, 0, 0, time.UTC)

	type testCase struct {
		name   string
		use    func(r *rotatedHandles)
		assert func(t *testing.T, r *rotatedHandles)
	}

	cases := []testCase{
		{
			name: "recognised inside the window, not at its end",
			use: func(r *rotatedHandles) {
				r.remember([]byte("a"), at.Add(30*time.Second), at)
			},
			assert: func(t *testing.T, r *rotatedHandles) {
				assert.True(t, r.recent([]byte("a"), at.Add(29*time.Second)))
				assert.False(t, r.recent([]byte("b"), at.Add(29*time.Second)), "an unknown handle is not recent")
				assert.False(t, r.recent([]byte("a"), at.Add(30*time.Second)))
				assert.Empty(t, r.until)
				assert.Empty(t, r.byEnd)
			},
		},
		{
			name: "a window capped earlier is forgotten before one that began first",
			use: func(r *rotatedHandles) {
				r.remember([]byte("a"), at.Add(30*time.Second), at)
				r.remember([]byte("b"), at.Add(5*time.Second), at.Add(time.Second))
				r.remember([]byte("c"), at.Add(40*time.Second), at.Add(10*time.Second))
			},
			assert: func(t *testing.T, r *rotatedHandles) {
				assert.Len(t, r.until, 2, "b's window ended before c was remembered")
				assert.Len(t, r.byEnd, 2)
				assert.NotContains(t, r.until, "b")

				assert.False(t, r.recent([]byte("x"), at.Add(time.Minute)))
				assert.Empty(t, r.until, "every window has ended")
				assert.Empty(t, r.byEnd)
			},
		},
		{
			name: "a window already ended is not remembered",
			use: func(r *rotatedHandles) {
				r.remember([]byte("a"), at, at)
			},
			assert: func(t *testing.T, r *rotatedHandles) {
				assert.False(t, r.recent([]byte("a"), at))
				assert.Empty(t, r.until)
				assert.Empty(t, r.byEnd)
			},
		},
		{
			name: "concurrent rotations of distinct handles are all remembered",
			use: func(r *rotatedHandles) {
				var wg sync.WaitGroup

				wg.Add(16)
				for i := range 16 {
					go func() {
						defer wg.Done()
						r.remember([]byte(strconv.Itoa(i)), at.Add(30*time.Second), at)
						r.recent([]byte(strconv.Itoa(i)), at)
					}()
				}
				wg.Wait()
			},
			assert: func(t *testing.T, r *rotatedHandles) {
				assert.Len(t, r.until, 16)
				assert.False(t, r.recent([]byte("0"), at.Add(30*time.Second)))
				assert.Empty(t, r.until)
				assert.Empty(t, r.byEnd)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var r rotatedHandles
			tc.use(&r)
			tc.assert(t, &r)
		})
	}
}
