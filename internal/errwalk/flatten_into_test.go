package errwalk_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/errwalk"
)

// types returns the dynamic type of each node of c.
func types(c errwalk.Chain) []string {
	out := make([]string, len(c))
	for i, e := range c {
		out[i] = fmt.Sprintf("%T", e)
	}

	return out
}

// requireSameWalk asserts that two walks of the same shape, built twice, came
// out alike: the same abort reason and panic value, no chain on an abort, and
// otherwise the same nodes in the same order.
func requireSameWalk(t *testing.T, want errwalk.Chain, wantAbort error, got errwalk.Chain, gotAbort error) {
	t.Helper()

	require.Equal(t, errwalk.Reason(wantAbort), errwalk.Reason(gotAbort), "abort reason")
	require.Equal(t, wantAbort == nil, gotAbort == nil, "abort presence")

	if wantAbort != nil {
		assert.Nil(t, got, "an aborted walk returns no chain")

		var wantPanic, gotPanic *errwalk.PanicError
		if errors.As(wantAbort, &wantPanic) {
			require.ErrorAs(t, gotAbort, &gotPanic)
			assert.Equal(t, wantPanic.Value, gotPanic.Value, "recovered value")
			assert.NotEmpty(t, gotPanic.Frames, "frames")
		}

		return
	}

	assert.Equal(t, names(want), names(got), "node text, in order")
	assert.Equal(t, types(want), types(got), "node types, in order")
}

// TestFlattenInto_SameAsFlatten pins that FlattenInto walks every Flatten shape
// exactly as Flatten does, whatever buffer it is given: no buffer, one too
// small that must grow, and one with stale contents that must not show.
func TestFlattenInto_SameAsFlatten(t *testing.T) {
	t.Parallel()

	type bufferCase struct {
		name string
		buf  func() []error
	}

	stale := func() []error {
		var buf [16]error
		for i := range buf {
			buf[i] = fmt.Errorf("stale %d", i)
		}

		return buf[:]
	}

	buffers := []bufferCase{
		{name: "nil buffer", buf: func() []error { return nil }},
		{name: "zero capacity", buf: func() []error { return make([]error, 0) }},
		{name: "capacity 2 grows", buf: func() []error { return make([]error, 0, 2) }},
		{name: "16 stale entries", buf: stale},
	}

	// Each walk gets a build of its own: Flatten's, then one per buffer.
	builds := make([][]flattenCase, 1+len(buffers))
	for i := range builds {
		builds[i] = flattenCases()
	}

	for i, ref := range builds[0] {
		t.Run(ref.name, func(t *testing.T) {
			t.Parallel()

			want, _, wantAbort := flattenWithin(t, errwalk.Flatten, ref.err, 2*time.Second)

			for j, bc := range buffers {
				t.Run(bc.name, func(t *testing.T) {
					tc := builds[1+j][i]
					require.Equal(t, ref.name, tc.name)

					into := func(err error) (errwalk.Chain, error) { return errwalk.FlattenInto(bc.buf(), err) }

					got, elapsed, gotAbort := flattenWithin(t, into, tc.err, 2*time.Second)
					tc.assert(t, got, gotAbort, elapsed)
					requireSameWalk(t, want, wantAbort, got, gotAbort)
				})
			}
		})
	}
}

// TestFlattenInto_NoHeapForShortChains pins that a chain that fits the
// caller's stack buffer is walked without a heap allocation, the pending
// entries included.
//
// It is not parallel: testing.AllocsPerRun counts every allocation in the
// process, so no other test may run during the measurement.
func TestFlattenInto_NoHeapForShortChains(t *testing.T) { //nolint:paralleltest // allocation counts are process-wide
	type testCase struct {
		name   string
		err    error
		assert func(t *testing.T, allocs float64, entries int, abort error)
	}

	noHeap := func(want int) func(t *testing.T, allocs float64, entries int, abort error) {
		return func(t *testing.T, allocs float64, entries int, abort error) {
			t.Helper()
			require.NoError(t, abort)
			assert.Equal(t, want, entries, "entries")
			assert.Zero(t, allocs, "heap allocations per walk")
		}
	}

	cases := []testCase{
		{
			name:   "1 entry",
			err:    errors.New("bare"),
			assert: noHeap(1),
		},
		{
			// wrap -> join -> (leaf, wrap -> leaf, leaf): 6 entries, 3 of them
			// pending at once.
			name: "6 entries: wraps and a join",
			err: fmt.Errorf("outer: %w", errors.Join(
				errors.New("a"),
				fmt.Errorf("inner: %w", errors.New("b")),
				errors.New("c"),
			)),
			assert: noHeap(6),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var (
				entries int
				last    error
			)

			allocs := testing.AllocsPerRun(1000, func() {
				var buf [16]error

				c, abort := errwalk.FlattenInto(buf[:], tc.err)
				entries, last = len(c), abort
			})
			tc.assert(t, allocs, entries, last)

			// The chain is backed by the caller's buffer.
			var held [16]error

			c, abort := errwalk.FlattenInto(held[:], tc.err)
			require.NoError(t, abort)
			require.NotEmpty(t, c)
			assert.Same(t, &held[0], &c[0], "the chain is backed by the caller's buffer")
		})
	}
}
