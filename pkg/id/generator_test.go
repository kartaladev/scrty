package id_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/rand/v2"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/pkg/id"
)

var t0 = time.Date(2022, 2, 22, 19, 22, 22, 0, time.UTC)

func frozen(at time.Time) func() time.Time { return func() time.Time { return at } }

func seeded(seed byte) *rand.ChaCha8 { return rand.NewChaCha8([32]byte{seed}) }

func TestV7Generator_Layout(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		assert func(t *testing.T, newGen func() *id.V7Generator)
	}

	cases := []testCase{
		{
			name: "version, variant and millisecond timestamp",
			assert: func(t *testing.T, newGen func() *id.V7Generator) {
				got, err := newGen().NewID()
				require.NoError(t, err)
				assert.Equal(t, byte(7), got[6]>>4, "version")
				assert.Equal(t, byte(0b10), got[8]>>6, "variant")
				var ms [8]byte
				copy(ms[2:], got[:6])
				assert.Equal(t, uint64(1645557742000), binary.BigEndian.Uint64(ms[:]))
				assert.False(t, got.IsZero())
			},
		},
		{
			name: "identically configured generators produce the same sequence",
			assert: func(t *testing.T, newGen func() *id.V7Generator) {
				a, b := newGen(), newGen()
				for range 10 {
					x, errA := a.NewID()
					y, errB := b.NewID()
					require.NoError(t, errA)
					require.NoError(t, errB)
					assert.Equal(t, x, y)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, func() *id.V7Generator {
				return id.NewV7Generator(id.WithClock(frozen(t0)), id.WithRandom(seeded(1)))
			})
		})
	}
}

func assertStrictlyIncreasing(t *testing.T, ids []id.ID) {
	t.Helper()
	for n := 1; n < len(ids); n++ {
		prev, cur := ids[n-1], ids[n]
		require.Negative(t, bytes.Compare(prev[:], cur[:]), "bytes at %d", n)
		require.Negative(t, strings.Compare(prev.String(), cur.String()), "string at %d", n)
	}
}

func TestV7Generator_Ordering(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		drive  func(t *testing.T) []id.ID
		assert func(t *testing.T, ids []id.ID)
	}

	cases := []testCase{
		{
			name: "many identifiers within one millisecond",
			drive: func(t *testing.T) []id.ID {
				gen := id.NewV7Generator(id.WithClock(frozen(t0)), id.WithRandom(seeded(2)))
				ids := make([]id.ID, 100_000)
				for n := range ids {
					v, err := gen.NewID()
					require.NoError(t, err)
					ids[n] = v
				}
				return ids
			},
			assert: assertStrictlyIncreasing,
		},
		{
			name: "time source moves backwards",
			drive: func(t *testing.T) []id.ID {
				now := t0
				gen := id.NewV7Generator(id.WithClock(func() time.Time { return now }), id.WithRandom(seeded(3)))
				first, err := gen.NewID()
				require.NoError(t, err)
				now = t0.Add(-time.Second)
				second, err := gen.NewID()
				require.NoError(t, err)
				return []id.ID{first, second}
			},
			assert: assertStrictlyIncreasing,
		},
		{
			name: "later time sorts later across generators",
			drive: func(t *testing.T) []id.ID {
				early, err := id.NewV7Generator(id.WithClock(frozen(t0))).NewID()
				require.NoError(t, err)
				late, err := id.NewV7Generator(id.WithClock(frozen(t0.Add(time.Millisecond)))).NewID()
				require.NoError(t, err)
				return []id.ID{early, late}
			},
			assert: assertStrictlyIncreasing,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, tc.drive(t))
		})
	}
}

func TestV7Generator_Concurrent(t *testing.T) {
	t.Parallel()

	const workers, perWorker = 64, 1_000
	gen := id.NewV7Generator()
	results := make(chan id.ID, workers*perWorker)

	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for range perWorker {
				v, err := gen.NewID()
				if err != nil {
					t.Error(err)
					return
				}
				results <- v
			}
		})
	}
	wg.Wait()
	close(results)

	seen := make(map[id.ID]struct{}, workers*perWorker)
	all := make([]id.ID, 0, workers*perWorker)
	for v := range results {
		_, dup := seen[v]
		assert.False(t, dup, "duplicate %s", v)
		seen[v] = struct{}{}
		all = append(all, v)
	}

	byBytes := slices.Clone(all)
	slices.SortFunc(byBytes, func(a, b id.ID) int { return bytes.Compare(a[:], b[:]) })
	byString := slices.Clone(all)
	slices.SortFunc(byString, func(a, b id.ID) int { return strings.Compare(a.String(), b.String()) })

	assert.Len(t, seen, workers*perWorker)
	assert.Equal(t, byBytes, byString)
}

func TestV7Generator_RandomSourceFailure(t *testing.T) {
	t.Parallel()

	errEntropy := errors.New("entropy exhausted")
	gen := id.NewV7Generator(id.WithRandom(iotest.ErrReader(errEntropy)))

	got, err := gen.NewID()

	require.ErrorIs(t, err, errEntropy)
	assert.True(t, got.IsZero())
}
