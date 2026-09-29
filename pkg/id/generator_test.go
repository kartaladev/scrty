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

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/pkg/id"
)

var t0 = time.Date(2022, 2, 22, 19, 22, 22, 0, time.UTC)

func seeded(seed byte) *rand.ChaCha8 { return rand.NewChaCha8([32]byte{seed}) }

// idTimestampMS extracts the 48-bit millisecond timestamp a V7Generator wrote
// into the identifier's first six bytes.
func idTimestampMS(t *testing.T, got id.ID) int64 {
	t.Helper()

	var ms [8]byte
	copy(ms[2:], got[:6])

	return int64(binary.BigEndian.Uint64(ms[:])) //nolint:gosec // 48-bit field read back
}

// nilClockID is a consumer clock type whose Now never dereferences its
// receiver, so (*nilClockID)(nil) is a typed nil that does not panic on its
// own: it is id.WithClock's nil handling under test, not this type's safety.
type nilClockID struct{}

func (*nilClockID) Now() time.Time { return time.Time{} }

// fixedClockID is a consumer's own read-only clock: the "Read-only source for
// a read-only component" scenario (time-source spec).
type fixedClockID struct{ at time.Time }

func (c fixedClockID) Now() time.Time { return c.at }

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
				return id.NewV7Generator(id.WithClock(clockwork.NewFakeClockAt(t0)), id.WithRandom(seeded(1)))
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
				gen := id.NewV7Generator(id.WithClock(clockwork.NewFakeClockAt(t0)), id.WithRandom(seeded(2)))
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
				clk := clockwork.NewFakeClockAt(t0)
				gen := id.NewV7Generator(id.WithClock(clk), id.WithRandom(seeded(3)))
				first, err := gen.NewID()
				require.NoError(t, err)
				clk.Advance(-time.Second) // t0 - 1s
				second, err := gen.NewID()
				require.NoError(t, err)
				return []id.ID{first, second}
			},
			assert: assertStrictlyIncreasing,
		},
		{
			name: "later time sorts later across generators",
			drive: func(t *testing.T) []id.ID {
				early, err := id.NewV7Generator(id.WithClock(clockwork.NewFakeClockAt(t0))).NewID()
				require.NoError(t, err)
				late, err := id.NewV7Generator(id.WithClock(clockwork.NewFakeClockAt(t0.Add(time.Millisecond)))).NewID()
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

// TestV7Generator_ClockOption pins WithClock's four time-source shapes
// (time-source spec): the default, a consumer's own read-only clock, and the
// two absent-source shapes that id.WithClock keeps the system clock for
// rather than refusing (D2's exception for a constructor that cannot fail).
func TestV7Generator_ClockOption(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []id.V7Option
		assert func(t *testing.T, got id.ID, before, after time.Time)
	}

	fromSystemClock := func(t *testing.T, got id.ID, before, after time.Time) {
		t.Helper()

		ms := idTimestampMS(t, got)
		assert.GreaterOrEqual(t, ms, before.UnixMilli(), "earlier than the system time before construction")
		assert.LessOrEqual(t, ms, after.UnixMilli(), "later than the system time after construction")
	}

	cases := []testCase{
		{
			name:   "default clock reads the system time",
			opts:   nil,
			assert: fromSystemClock,
		},
		{
			name: "a consumer's own read-only clock is the generator's source",
			opts: []id.V7Option{id.WithClock(fixedClockID{at: t0})},
			assert: func(t *testing.T, got id.ID, _, _ time.Time) {
				t.Helper()
				assert.Equal(t, t0.UnixMilli(), idTimestampMS(t, got))
			},
		},
		{
			name:   "a nil clock keeps the system clock",
			opts:   []id.V7Option{id.WithClock(nil)},
			assert: fromSystemClock,
		},
		{
			name:   "a typed-nil clock keeps the system clock",
			opts:   []id.V7Option{id.WithClock((*nilClockID)(nil))},
			assert: fromSystemClock,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gen := id.NewV7Generator(tc.opts...)
			before := time.Now()
			got, err := gen.NewID()
			after := time.Now()
			require.NoError(t, err)

			tc.assert(t, got, before, after)
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
