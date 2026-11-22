package errwalk_test

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/errwalk"
)

// one is a node with a single cause. It counts its Unwrap calls.
type one struct {
	name  string
	next  error
	calls int
}

func (e *one) Error() string { return e.name }

func (e *one) Unwrap() error {
	e.calls++

	return e.next
}

// many is a node with several causes. It counts its Unwrap calls.
type many struct {
	name  string
	kids  []error
	calls int
}

func (e *many) Error() string { return e.name }

func (e *many) Unwrap() []error {
	e.calls++

	return e.kids
}

// bomb panics in every method, so a walk that calls any method of a nil *bomb
// fails the test with that panic.
type bomb struct{}

func (*bomb) Error() string          { panic("bomb: Error called") }
func (*bomb) Unwrap() error          { panic("bomb: Unwrap called") }
func (*bomb) Is(error) bool          { panic("bomb: Is called") }
func (*bomb) As(any) bool            { panic("bomb: As called") }
func (*bomb) Format(fmt.State, rune) { panic("bomb: Format called") }

// mapErr and sliceErr are error types whose nil value is a nil map or slice.
// Their methods are safe on nil, and they are not nil pointers.
type mapErr map[string]string

func (mapErr) Error() string { return "map error" }

type sliceErr []error

func (sliceErr) Error() string     { return "slice error" }
func (s sliceErr) Unwrap() []error { return s }

// cycleOne unwraps to itself through Unwrap() error.
type cycleOne struct{}

func (*cycleOne) Error() string   { return "cycle one" }
func (e *cycleOne) Unwrap() error { return e }

// cycleMany unwraps to itself through Unwrap() []error.
type cycleMany struct{}

func (*cycleMany) Error() string     { return "cycle many" }
func (e *cycleMany) Unwrap() []error { return []error{e} }

// lateBound unwraps to an error set after construction, to close a cycle.
type lateBound struct{ err error }

func (*lateBound) Error() string   { return "late bound" }
func (e *lateBound) Unwrap() error { return e.err }

type panicUnwrap struct{}

func (panicUnwrap) Error() string { return "panic unwrap" }
func (panicUnwrap) Unwrap() error { panic("unwrap boom") }

type panicUnwrapMany struct{}

func (panicUnwrapMany) Error() string   { return "panic unwrap many" }
func (panicUnwrapMany) Unwrap() []error { panic("unwrap many boom") }

func leaf(name string) *one { return &one{name: name} }

// linear builds a chain of n nodes through Unwrap() error.
func linear(n int) error {
	var err error
	for i := n; i > 0; i-- {
		err = &one{name: fmt.Sprintf("n%d", i), next: err}
	}

	return err
}

// fanout nests errors.Join(f, f) n levels deep: no cycle, 2^n paths.
func fanout(n int) error {
	f := errors.New("fan leaf")
	for range n {
		f = errors.Join(f, f)
	}

	return f
}

func repeat(err error, n int) []error {
	out := make([]error, n)
	for i := range out {
		out[i] = err
	}

	return out
}

func names(c errwalk.Chain) []string {
	out := make([]string, len(c))
	for i, e := range c {
		out[i] = e.Error()
	}

	return out
}

// walkFunc is a walk under test: Flatten, or FlattenInto with some buffer.
type walkFunc func(err error) (errwalk.Chain, error)

// flattenWithin runs walk under a deadline, so a walk that hangs fails the
// test instead of the whole run.
func flattenWithin(t *testing.T, walk walkFunc, err error, d time.Duration) (errwalk.Chain, time.Duration, error) {
	t.Helper()

	type result struct {
		c     errwalk.Chain
		abort error
	}

	done := make(chan result, 1)
	start := time.Now()

	go func() {
		c, abort := walk(err)
		done <- result{c: c, abort: abort}
	}()

	select {
	case r := <-done:
		return r.c, time.Since(start), r.abort
	case <-time.After(d):
		t.Fatalf("the walk did not return within %s", d)

		return nil, 0, nil
	}
}

func requireBudget(t *testing.T, c errwalk.Chain, abort error) {
	t.Helper()
	require.ErrorIs(t, abort, errwalk.ErrBudget)
	assert.Equal(t, "budget", errwalk.Reason(abort))
	assert.Nil(t, c, "an aborted walk returns no chain")
}

// flattenCase is one shape of error chain with the outcome a walk of it must
// have.
type flattenCase struct {
	name   string
	err    error
	assert func(t *testing.T, c errwalk.Chain, abort error, elapsed time.Duration)
}

// flattenCases builds every walk shape afresh. Some nodes count their Unwrap
// calls and a case asserts the count, so one build serves one walk.
func flattenCases() []flattenCase {
	// order: root, then depth first, through both Unwrap forms. a1 ends its
	// branch with a nil Unwrap() error; the nil entry in root's kids is free.
	a1 := leaf("a1")
	a := &one{name: "a", next: a1}
	b1, b2 := leaf("b1"), leaf("b2")
	b := &many{name: "b", kids: []error{b1, b2}}
	c := leaf("c")
	ordered := &many{name: "root", kids: []error{a, nil, b, c}}

	// nils builds a root with n nil entries and a leaf: n+2 entries in all.
	nils := func(n int) error {
		return &many{name: "root", kids: append(make([]error, n), leaf("after nils"))}
	}

	var nilBomb *bomb
	bombKids := &many{name: "root", kids: append(repeat(nilBomb, 3), leaf("after bombs"))}
	bombFlood := &many{name: "root", kids: append(repeat(nilBomb, 2*errwalk.Budget), leaf("after bombs"))}

	// self is one node holding 20,000 cached copies of itself.
	self := &many{name: "self", kids: make([]error, 20_000)}
	for i := range self.kids {
		self.kids[i] = self
	}

	// lateBoom is the 1,001st entry, and its Unwrap would panic.
	lateBoom := &many{name: "root", kids: append(repeat(leaf("filler"), errwalk.Budget-1), panicUnwrap{})}
	bombCause := &one{name: "root", next: nilBomb}

	var nilMap mapErr
	var nilSlice sliceErr
	nilCollections := &many{name: "root", kids: []error{nilMap, nilSlice}}

	joinTail := &lateBound{}
	joinCycle := errors.Join(errors.New("join head"), joinTail)
	joinTail.err = joinCycle

	return []flattenCase{
		{
			name: "root first, then depth first, each Unwrap called once",
			err:  ordered,
			assert: func(t *testing.T, got errwalk.Chain, abort error, _ time.Duration) {
				require.NoError(t, abort)
				assert.Equal(t, []string{"root", "a", "a1", "b", "b1", "b2", "c"}, names(got))
				for _, n := range []interface{ Error() string }{ordered, a, a1, b, b1, b2, c} {
					var calls int
					switch v := n.(type) {
					case *one:
						calls = v.calls
					case *many:
						calls = v.calls
					}
					assert.Equal(t, 1, calls, "Unwrap calls on %s", n.Error())
				}
			},
		},
		{
			name: "nil entries in Unwrap() []error are skipped but count",
			err:  nils(3),
			assert: func(t *testing.T, got errwalk.Chain, abort error, _ time.Duration) {
				require.NoError(t, abort)
				assert.Equal(t, []string{"root", "after nils"}, names(got))
			},
		},
		{
			name: "998 nil entries, a root and a leaf are 1000 entries and succeed",
			err:  nils(errwalk.Budget - 2),
			assert: func(t *testing.T, got errwalk.Chain, abort error, _ time.Duration) {
				require.NoError(t, abort)
				assert.Equal(t, []string{"root", "after nils"}, names(got))
			},
		},
		{
			name: "999 nil entries, a root and a leaf are 1001 entries and abort",
			err:  nils(errwalk.Budget - 1),
			assert: func(t *testing.T, got errwalk.Chain, abort error, _ time.Duration) {
				requireBudget(t, got, abort)
			},
		},
		{
			name: "2000 nil entries and a leaf abort with budget",
			err:  nils(2 * errwalk.Budget),
			assert: func(t *testing.T, got errwalk.Chain, abort error, _ time.Duration) {
				requireBudget(t, got, abort)
			},
		},
		{
			name: "a million nil entries abort with budget in under 50ms",
			err:  nils(1_000_000),
			assert: func(t *testing.T, got errwalk.Chain, abort error, elapsed time.Duration) {
				requireBudget(t, got, abort)
				assert.Less(t, elapsed, 50*time.Millisecond)
				t.Logf("a million nil entries aborted after %s", elapsed)
			},
		},
		{
			name: "a node with 20000 copies of itself aborts with budget",
			err:  self,
			assert: func(t *testing.T, got errwalk.Chain, abort error, elapsed time.Duration) {
				requireBudget(t, got, abort)
				t.Logf("20000 self copies aborted after %s", elapsed)
			},
		},
		{
			name: "the 1001st entry aborts with budget before its Unwrap is called",
			err:  lateBoom,
			assert: func(t *testing.T, got errwalk.Chain, abort error, _ time.Duration) {
				requireBudget(t, got, abort)
			},
		},
		{
			name: "a nil pointer among kids is skipped and uncalled",
			err:  bombKids,
			assert: func(t *testing.T, got errwalk.Chain, abort error, _ time.Duration) {
				require.NoError(t, abort)
				assert.Equal(t, []string{"root", "after bombs"}, names(got))
			},
		},
		{
			name: "a flood of nil pointers counts and aborts with budget",
			err:  bombFlood,
			assert: func(t *testing.T, got errwalk.Chain, abort error, _ time.Duration) {
				requireBudget(t, got, abort)
			},
		},
		{
			name: "a nil pointer from Unwrap() error is skipped and uncalled",
			err:  bombCause,
			assert: func(t *testing.T, got errwalk.Chain, abort error, _ time.Duration) {
				require.NoError(t, abort)
				assert.Equal(t, []string{"root"}, names(got))
			},
		},
		{
			name: "a nil pointer root gives an empty chain",
			err:  nilBomb,
			assert: func(t *testing.T, got errwalk.Chain, abort error, _ time.Duration) {
				require.NoError(t, abort)
				assert.Empty(t, got)
			},
		},
		{
			name: "a nil interface gives an empty chain",
			err:  nil,
			assert: func(t *testing.T, got errwalk.Chain, abort error, _ time.Duration) {
				require.NoError(t, abort)
				assert.Empty(t, got)
			},
		},
		{
			name: "a nil map or slice error is not skipped",
			err:  nilCollections,
			assert: func(t *testing.T, got errwalk.Chain, abort error, _ time.Duration) {
				require.NoError(t, abort)
				assert.Equal(t, []string{"root", "map error", "slice error"}, names(got))
			},
		},
		{
			name: "a chain of exactly Budget nodes succeeds",
			err:  linear(errwalk.Budget),
			assert: func(t *testing.T, got errwalk.Chain, abort error, _ time.Duration) {
				require.NoError(t, abort)
				require.Len(t, got, errwalk.Budget)
				assert.Equal(t, "n1", got[0].Error())
				assert.Equal(t, fmt.Sprintf("n%d", errwalk.Budget), got[len(got)-1].Error())
			},
		},
		{
			name: "a chain of Budget+1 nodes aborts",
			err:  linear(errwalk.Budget + 1),
			assert: func(t *testing.T, got errwalk.Chain, abort error, _ time.Duration) {
				requireBudget(t, got, abort)
			},
		},
		{
			name: "repeats count: root plus Budget-1 repeats succeeds",
			err:  &many{name: "root", kids: repeat(leaf("shared"), errwalk.Budget-1)},
			assert: func(t *testing.T, got errwalk.Chain, abort error, _ time.Duration) {
				require.NoError(t, abort)
				assert.Len(t, got, errwalk.Budget)
			},
		},
		{
			name: "repeats count: root plus Budget repeats aborts",
			err:  &many{name: "root", kids: repeat(leaf("shared"), errwalk.Budget)},
			assert: func(t *testing.T, got errwalk.Chain, abort error, _ time.Duration) {
				requireBudget(t, got, abort)
			},
		},
		{
			name: "a self-cycle through Unwrap() error aborts with budget",
			err:  &cycleOne{},
			assert: func(t *testing.T, got errwalk.Chain, abort error, _ time.Duration) {
				requireBudget(t, got, abort)
			},
		},
		{
			name: "a self-cycle through Unwrap() []error aborts with budget",
			err:  &cycleMany{},
			assert: func(t *testing.T, got errwalk.Chain, abort error, _ time.Duration) {
				requireBudget(t, got, abort)
			},
		},
		{
			name: "a cycle through errors.Join aborts with budget",
			err:  joinCycle,
			assert: func(t *testing.T, got errwalk.Chain, abort error, _ time.Duration) {
				requireBudget(t, got, abort)
			},
		},
		{
			name: "25 levels of errors.Join fan-out abort with budget in under 100ms",
			err:  fanout(25),
			assert: func(t *testing.T, got errwalk.Chain, abort error, elapsed time.Duration) {
				requireBudget(t, got, abort)
				assert.Less(t, elapsed, 100*time.Millisecond)
				t.Logf("fan-out of 25 levels aborted after %s", elapsed)
			},
		},
		{
			name: "a panicking Unwrap() error aborts with the recovered value",
			err:  &one{name: "root", next: panicUnwrap{}},
			assert: func(t *testing.T, got errwalk.Chain, abort error, _ time.Duration) {
				var pe *errwalk.PanicError
				require.ErrorAs(t, abort, &pe)
				assert.Equal(t, "unwrap boom", pe.Value)
				assert.ErrorIs(t, abort, errwalk.ErrPanic)
				assert.Equal(t, "panic", errwalk.Reason(abort))
				assert.NotContains(t, abort.Error(), "boom", "the error text never carries the panic value")
				assert.Nil(t, got, "an aborted walk returns no chain")
			},
		},
		{
			name: "a panicking Unwrap() []error aborts with the recovered value",
			err:  panicUnwrapMany{},
			assert: func(t *testing.T, got errwalk.Chain, abort error, _ time.Duration) {
				var pe *errwalk.PanicError
				require.ErrorAs(t, abort, &pe)
				assert.Equal(t, "unwrap many boom", pe.Value)
				assert.Equal(t, "panic", errwalk.Reason(abort))
				assert.Nil(t, got)
			},
		},
	}
}

func TestFlatten(t *testing.T) {
	t.Parallel()

	for _, tc := range flattenCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, elapsed, abort := flattenWithin(t, errwalk.Flatten, tc.err, 2*time.Second)
			tc.assert(t, got, abort, elapsed)
		})
	}
}

// TestFlatten_AllocationIsBounded pins that one node holding 20,000 cached
// copies of itself aborts without allocating in proportion to the walk. It is
// not parallel, so no other test allocates during the measurement.
func TestFlatten_AllocationIsBounded(t *testing.T) {
	self := &many{name: "self", kids: make([]error, 20_000)}
	for i := range self.kids {
		self.kids[i] = self
	}

	runtime.GC()

	var before, after runtime.MemStats

	runtime.ReadMemStats(&before)
	c, abort := errwalk.Flatten(self)
	runtime.ReadMemStats(&after)

	requireBudget(t, c, abort)

	allocated := after.TotalAlloc - before.TotalAlloc
	t.Logf("20000 self copies allocated %d bytes", allocated)
	assert.Less(t, allocated, uint64(1<<20), "allocation must be bounded by the budget, not the walk")
}

// rec records the order in which errors.Is consults its Is method.
type rec struct {
	name string
	log  *[]string
}

func (e *rec) Error() string { return e.name }

func (e *rec) Is(error) bool {
	*e.log = append(*e.log, e.name)

	return false
}

type recOne struct {
	rec
	next error
}

func (e *recOne) Unwrap() error { return e.next }

type recMany struct {
	rec
	kids []error
}

func (e *recMany) Unwrap() []error { return e.kids }

// TestFlatten_OrderMatchesStdlib compares the walk order with the order in
// which errors.Is consults each node.
func TestFlatten_OrderMatchesStdlib(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name  string
		build func(log *[]string) error
	}

	cases := []testCase{
		{
			name: "nested joins",
			build: func(log *[]string) error {
				l := func(n string) *rec { return &rec{name: n, log: log} }

				return &recMany{rec: *l("r"), kids: []error{
					&recMany{rec: *l("j1"), kids: []error{l("a"), &recMany{rec: *l("j2"), kids: []error{l("b"), l("c")}}}},
					l("d"),
				}}
			},
		},
		{
			name: "a wrap inside a join",
			build: func(log *[]string) error {
				l := func(n string) rec { return rec{name: n, log: log} }

				return &recMany{rec: l("r"), kids: []error{
					&recOne{rec: l("w"), next: &recOne{rec: l("w2"), next: &rec{name: "leaf", log: log}}},
					&rec{name: "x", log: log},
				}}
			},
		},
		{
			name: "a join inside a wrap",
			build: func(log *[]string) error {
				l := func(n string) rec { return rec{name: n, log: log} }

				return &recOne{rec: l("w"), next: &recMany{rec: l("j"), kids: []error{
					&rec{name: "a", log: log},
					&recOne{rec: l("w2"), next: &rec{name: "b", log: log}},
				}}}
			},
		},
		{
			name: "a diamond with repeats",
			build: func(log *[]string) error {
				shared := &recOne{rec: rec{name: "shared", log: log}, next: &rec{name: "tail", log: log}}
				left := &recOne{rec: rec{name: "left", log: log}, next: shared}
				right := &recMany{rec: rec{name: "right", log: log}, kids: []error{shared, nil, shared}}

				return &recMany{rec: rec{name: "top", log: log}, kids: []error{left, right}}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var log []string

			root := tc.build(&log)

			require.False(t, errors.Is(root, errors.New("never")))

			chain, abort := errwalk.Flatten(root)
			require.NoError(t, abort)
			require.NotEmpty(t, log)
			assert.Equal(t, log, names(chain))
		})
	}
}

// isMethod matches its target through an Is method.
type isMethod struct{ match error }

func (isMethod) Error() string          { return "is method" }
func (e isMethod) Is(target error) bool { return target == e.match }

type panicIs struct{}

func (panicIs) Error() string { return "panic is" }
func (panicIs) Is(error) bool { panic("is boom") }

// boxErr has a comparable type, but == panics when v holds a slice.
type boxErr struct{ v any }

func (boxErr) Error() string { return "box" }

// target is the type the As cases look for.
type target struct{ name string }

func (e *target) Error() string { return e.name }

// asMethod presents give as a *target through its As method, nil included.
type asMethod struct{ give *target }

func (asMethod) Error() string { return "as method" }

func (e asMethod) As(dst any) bool {
	p, ok := dst.(**target)
	if !ok {
		return false
	}
	*p = e.give

	return true
}

// asDeclines has an As method that never matches.
type asDeclines struct{}

func (asDeclines) Error() string { return "as declines" }
func (asDeclines) As(any) bool   { return false }

type panicAs struct{}

func (panicAs) Error() string { return "panic as" }
func (panicAs) As(any) bool   { panic("as boom") }

func requirePanic(t *testing.T, abort error, value any) {
	t.Helper()

	var pe *errwalk.PanicError
	require.ErrorAs(t, abort, &pe)
	assert.Equal(t, value, pe.Value)
	assert.Equal(t, "panic", errwalk.Reason(abort))
}

func TestMatch(t *testing.T) {
	t.Parallel()

	t.Run("Is", func(t *testing.T) {
		t.Parallel()

		type testCase struct {
			name   string
			chain  errwalk.Chain
			target error
			assert func(t *testing.T, ok bool, abort error)
		}

		sentinel := errors.New("sentinel")
		other := errors.New("other")
		incomparable := sliceErr{sentinel}

		cases := []testCase{
			{
				name:   "by == on a later node",
				chain:  errwalk.Chain{other, sentinel},
				target: sentinel,
				assert: func(t *testing.T, ok bool, abort error) {
					require.NoError(t, abort)
					assert.True(t, ok)
				},
			},
			{
				name:   "by the node's Is method",
				chain:  errwalk.Chain{other, isMethod{match: sentinel}},
				target: sentinel,
				assert: func(t *testing.T, ok bool, abort error) {
					require.NoError(t, abort)
					assert.True(t, ok)
				},
			},
			{
				name:   "no node matches",
				chain:  errwalk.Chain{other, isMethod{match: other}},
				target: sentinel,
				assert: func(t *testing.T, ok bool, abort error) {
					require.NoError(t, abort)
					assert.False(t, ok)
				},
			},
			{
				name:   "a nil target matches nothing",
				chain:  errwalk.Chain{other},
				target: nil,
				assert: func(t *testing.T, ok bool, abort error) {
					require.NoError(t, abort)
					assert.False(t, ok)
				},
			},
			{
				name:   "a panicking Is method aborts with the value",
				chain:  errwalk.Chain{other, panicIs{}, sentinel},
				target: sentinel,
				assert: func(t *testing.T, ok bool, abort error) {
					t.Helper()
					requirePanic(t, abort, "is boom")
					assert.False(t, ok)
				},
			},
			{
				name:   "a panicking Is on the second node, after the first said no, aborts with its frames",
				chain:  errwalk.Chain{isMethod{match: other}, panicIs{}, sentinel},
				target: sentinel,
				assert: func(t *testing.T, ok bool, abort error) {
					t.Helper()
					requirePanic(t, abort, "is boom")
					assert.False(t, ok)

					var pe *errwalk.PanicError
					require.ErrorAs(t, abort, &pe)

					functions := frameFunctions(pe.Frames)
					require.GreaterOrEqual(t, len(functions), 2, "frames: %v", functions)
					assert.Equal(t, "runtime.gopanic", functions[0])
					assert.Contains(t, functions[1], "errwalk_test.panicIs.Is")
				},
			},
			{
				name:   "a match ahead of a panicking Is method wins, in list order",
				chain:  errwalk.Chain{sentinel, panicIs{}},
				target: sentinel,
				assert: func(t *testing.T, ok bool, abort error) {
					require.NoError(t, abort)
					assert.True(t, ok)
				},
			},
			{
				name:   "an incomparable target does not panic",
				chain:  errwalk.Chain{incomparable},
				target: incomparable,
				assert: func(t *testing.T, ok bool, abort error) {
					require.NoError(t, abort)
					assert.False(t, ok)
				},
			},
			{
				name:   "an incomparable node does not panic",
				chain:  errwalk.Chain{sliceErr{other}, sentinel},
				target: sentinel,
				assert: func(t *testing.T, ok bool, abort error) {
					require.NoError(t, abort)
					assert.True(t, ok)
				},
			},
			{
				name:   "a comparable type holding an incomparable value aborts with panic",
				chain:  errwalk.Chain{boxErr{v: []int{1}}, sentinel},
				target: boxErr{v: []int{1}},
				assert: func(t *testing.T, ok bool, abort error) {
					var pe *errwalk.PanicError
					require.ErrorAs(t, abort, &pe)
					assert.Equal(t, "panic", errwalk.Reason(abort))
					assert.False(t, ok)
				},
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				var (
					ok    bool
					abort error
				)
				require.NotPanics(t, func() { ok, abort = errwalk.Is(tc.chain, tc.target) })
				tc.assert(t, ok, abort)
			})
		}
	})

	t.Run("As", func(t *testing.T) {
		t.Parallel()

		type testCase struct {
			name   string
			chain  errwalk.Chain
			assert func(t *testing.T, got *target, ok bool, abort error)
		}

		other := errors.New("other")

		cases := []testCase{
			{
				name:  "by type",
				chain: errwalk.Chain{other, &target{name: "direct"}},
				assert: func(t *testing.T, got *target, ok bool, abort error) {
					require.NoError(t, abort)
					require.True(t, ok)
					assert.Equal(t, "direct", got.name)
				},
			},
			{
				name:  "by the node's As method",
				chain: errwalk.Chain{other, asMethod{give: &target{name: "method"}}},
				assert: func(t *testing.T, got *target, ok bool, abort error) {
					require.NoError(t, abort)
					require.True(t, ok)
					assert.Equal(t, "method", got.name)
				},
			},
			{
				name:  "first in list order: method ahead of type",
				chain: errwalk.Chain{asMethod{give: &target{name: "method"}}, &target{name: "direct"}},
				assert: func(t *testing.T, got *target, ok bool, abort error) {
					require.NoError(t, abort)
					require.True(t, ok)
					assert.Equal(t, "method", got.name)
				},
			},
			{
				name:  "first in list order: type ahead of method",
				chain: errwalk.Chain{&target{name: "direct"}, asMethod{give: &target{name: "method"}}},
				assert: func(t *testing.T, got *target, ok bool, abort error) {
					require.NoError(t, abort)
					require.True(t, ok)
					assert.Equal(t, "direct", got.name)
				},
			},
			{
				name:  "an As that sets a nil pointer is no match, and the scan continues",
				chain: errwalk.Chain{asMethod{give: nil}, &target{name: "after nil"}},
				assert: func(t *testing.T, got *target, ok bool, abort error) {
					require.NoError(t, abort)
					require.True(t, ok)
					assert.Equal(t, "after nil", got.name)
				},
			},
			{
				name:  "an As that sets a nil pointer alone is no match",
				chain: errwalk.Chain{asMethod{give: nil}},
				assert: func(t *testing.T, got *target, ok bool, abort error) {
					require.NoError(t, abort)
					assert.False(t, ok)
					assert.Nil(t, got)
				},
			},
			{
				name:  "an As that declines lets the scan continue",
				chain: errwalk.Chain{asDeclines{}, &target{name: "after decline"}},
				assert: func(t *testing.T, got *target, ok bool, abort error) {
					require.NoError(t, abort)
					require.True(t, ok)
					assert.Equal(t, "after decline", got.name)
				},
			},
			{
				name:  "a panicking As method aborts with the value",
				chain: errwalk.Chain{other, panicAs{}, &target{name: "unreached"}},
				assert: func(t *testing.T, got *target, ok bool, abort error) {
					requirePanic(t, abort, "as boom")
					assert.False(t, ok)
					assert.Nil(t, got)
				},
			},
			{
				name:  "no node matches",
				chain: errwalk.Chain{other, asDeclines{}},
				assert: func(t *testing.T, got *target, ok bool, abort error) {
					require.NoError(t, abort)
					assert.False(t, ok)
					assert.Nil(t, got)
				},
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				var (
					got   *target
					ok    bool
					abort error
				)
				require.NotPanics(t, func() { got, ok, abort = errwalk.As[*target](tc.chain) })
				tc.assert(t, got, ok, abort)
			})
		}
	})
}

func TestReason(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		abort  error
		assert func(t *testing.T, got string)
	}

	_, budgetAbort := errwalk.Flatten(&cycleOne{})

	cases := []testCase{
		{
			name:   "no abort",
			abort:  nil,
			assert: func(t *testing.T, got string) { assert.Empty(t, got) },
		},
		{
			name:   "an error wrapping ErrBudget that this package did not return",
			abort:  fmt.Errorf("%w: test", errwalk.ErrBudget),
			assert: func(t *testing.T, got string) { assert.Empty(t, got) },
		},
		{
			name:   "an error wrapping ErrPanic that this package did not return",
			abort:  fmt.Errorf("%w: test", errwalk.ErrPanic),
			assert: func(t *testing.T, got string) { assert.Empty(t, got) },
		},
		{
			name:   "a budget abort from Flatten",
			abort:  budgetAbort,
			assert: func(t *testing.T, got string) { assert.Equal(t, "budget", got) },
		},
		{
			name:   "a panic abort",
			abort:  &errwalk.PanicError{Value: "x"},
			assert: func(t *testing.T, got string) { assert.Equal(t, "panic", got) },
		},
		{
			name:   "any other error",
			abort:  errors.New("unrelated"),
			assert: func(t *testing.T, got string) { assert.Empty(t, got) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, errwalk.Reason(tc.abort))
		})
	}
}

func TestPanicError_TextIsFixed(t *testing.T) {
	t.Parallel()

	a := (&errwalk.PanicError{Value: "secret-a"}).Error()
	b := (&errwalk.PanicError{Value: 42}).Error()

	assert.Equal(t, a, b)
	assert.False(t, strings.Contains(a, "secret"))
}

// deepPanicUnwrap panics depth calls below its own Unwrap, in descendAndPanic.
type deepPanicUnwrap struct{ depth int }

func (deepPanicUnwrap) Error() string { return "deep panic unwrap" }

func (e deepPanicUnwrap) Unwrap() error {
	descendAndPanic(e.depth)

	return nil
}

//go:noinline
func descendAndPanic(depth int) {
	if depth > 0 {
		descendAndPanic(depth - 1)

		return
	}

	panic("deep boom")
}

// frameFunctions resolves pcs to the function names they name, innermost
// first.
func frameFunctions(pcs []uintptr) []string {
	if len(pcs) == 0 {
		return nil
	}

	var out []string

	frames := runtime.CallersFrames(pcs)
	for {
		frame, more := frames.Next()
		out = append(out, frame.Function)

		if !more {
			return out
		}
	}
}

// TestFlatten_PanicCarriesFrames pins that a recovered panic carries the
// panicking stack, captured where it panicked: the first frame is the
// runtime's gopanic and the panicking method follows, not only errwalk's own
// functions or whoever reads the abort later.
func TestFlatten_PanicCarriesFrames(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// abort runs the walk or match that meets the panic.
		abort  func() error
		assert func(t *testing.T, functions []string)
	}

	startsAtGopanicThen := func(method string) func(t *testing.T, functions []string) {
		return func(t *testing.T, functions []string) {
			t.Helper()
			require.GreaterOrEqual(t, len(functions), 2, "frames: %v", functions)
			assert.Equal(t, "runtime.gopanic", functions[0], "the frames start at the panic")
			assert.Contains(t, functions[1], method, "the panicking method is next")
			assert.LessOrEqual(t, len(functions), errwalk.FrameLimit)
		}
	}

	cases := []testCase{
		{
			name: "a panicking Unwrap() error",
			abort: func() error {
				_, abort := errwalk.Flatten(panicUnwrap{})

				return abort
			},
			assert: startsAtGopanicThen("errwalk_test.panicUnwrap.Unwrap"),
		},
		{
			name: "a panicking Unwrap() []error",
			abort: func() error {
				_, abort := errwalk.Flatten(panicUnwrapMany{})

				return abort
			},
			assert: startsAtGopanicThen("errwalk_test.panicUnwrapMany.Unwrap"),
		},
		{
			name: "a panicking Is",
			abort: func() error {
				_, abort := errwalk.Is(errwalk.Chain{panicIs{}}, errors.New("target"))

				return abort
			},
			assert: startsAtGopanicThen("errwalk_test.panicIs.Is"),
		},
		{
			name: "a panicking As",
			abort: func() error {
				_, _, abort := errwalk.As[*one](errwalk.Chain{panicAs{}})

				return abort
			},
			assert: startsAtGopanicThen("errwalk_test.panicAs.As"),
		},
		{
			name: "a == that panics names errwalk's comparison, through the runtime",
			abort: func() error {
				_, abort := errwalk.Is(errwalk.Chain{boxErr{v: []int{1}}}, boxErr{v: []int{1}})

				return abort
			},
			assert: func(t *testing.T, functions []string) {
				t.Helper()
				require.NotEmpty(t, functions)
				assert.True(t, strings.HasPrefix(functions[0], "runtime."), "a runtime error starts in the runtime: %v", functions)
				assert.Contains(t, strings.Join(functions, "\n"), "errwalk.Is")
			},
		},
		{
			name: "a panic deeper than the limit keeps the innermost frames, bounded",
			abort: func() error {
				_, abort := errwalk.Flatten(deepPanicUnwrap{depth: 4 * errwalk.FrameLimit})

				return abort
			},
			assert: func(t *testing.T, functions []string) {
				t.Helper()
				require.Len(t, functions, errwalk.FrameLimit)
				assert.Equal(t, "runtime.gopanic", functions[0])
				assert.Contains(t, functions[1], "errwalk_test.descendAndPanic")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var pe *errwalk.PanicError
			require.ErrorAs(t, tc.abort(), &pe)
			tc.assert(t, frameFunctions(pe.Frames))
		})
	}
}
