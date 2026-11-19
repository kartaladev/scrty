package errwalk_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/errwalk"
)

// acceptsAll has an Is method that reports true for every target.
type acceptsAll struct{}

func (acceptsAll) Error() string { return "accepts all" }
func (acceptsAll) Is(error) bool { return true }

// isNilTarget has an Is method that reports true only for a nil *target.
type isNilTarget struct{}

func (isNilTarget) Error() string { return "is nil target" }

func (isNilTarget) Is(t error) bool {
	p, ok := t.(*target) //nolint:errorlint // the test inspects the exact target it was handed

	return ok && p == nil
}

// panicsFor has an Is method that panics for one target and says no to every
// other.
type panicsFor struct{ target error }

func (panicsFor) Error() string { return "panics for" }

func (e panicsFor) Is(t error) bool {
	if t == e.target { //nolint:errorlint // identity of the target it was handed
		panic("is boom")
	}

	return false
}

func TestIndex(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		chain   errwalk.Chain
		targets errwalk.Targets
		assert  func(t *testing.T, index int, abort error)
	}

	a := errors.New("a")
	b := errors.New("b")
	other := errors.New("other")
	incomparable := sliceErr{a}

	matches := func(want int) func(t *testing.T, index int, abort error) {
		return func(t *testing.T, index int, abort error) {
			t.Helper()
			require.NoError(t, abort)
			assert.Equal(t, want, index)
		}
	}

	panics := func(method string) func(t *testing.T, index int, abort error) {
		return func(t *testing.T, index int, abort error) {
			t.Helper()
			requirePanic(t, abort, "is boom")
			assert.Equal(t, -1, index)

			var pe *errwalk.PanicError
			require.ErrorAs(t, abort, &pe)

			functions := frameFunctions(pe.Frames)
			require.GreaterOrEqual(t, len(functions), 2, "frames: %v", functions)
			assert.Equal(t, "runtime.gopanic", functions[0])
			assert.Contains(t, functions[1], method)
		}
	}

	// source is a slice the test changes after building targets from it.
	source := []error{b}
	copied := errwalk.NewTargets(source...)
	source[0] = a

	cases := []testCase{
		{
			name:    "the first target in target order wins, though a later one matches an earlier node",
			chain:   errwalk.Chain{b, a},
			targets: errwalk.NewTargets(a, b),
			assert:  matches(0),
		},
		{
			name:    "a target matched by == on a later node",
			chain:   errwalk.Chain{other, a},
			targets: errwalk.NewTargets(b, a),
			assert:  matches(1),
		},
		{
			name:    "a target matched by a node's Is method",
			chain:   errwalk.Chain{other, isMethod{match: b}},
			targets: errwalk.NewTargets(a, b),
			assert:  matches(1),
		},
		{
			name:    "no target matches",
			chain:   errwalk.Chain{other, isMethod{match: other}},
			targets: errwalk.NewTargets(a, b),
			assert:  matches(-1),
		},
		{
			name:    "an incomparable target is not compared with ==, and does not panic",
			chain:   errwalk.Chain{incomparable},
			targets: errwalk.NewTargets(incomparable),
			assert:  matches(-1),
		},
		{
			name:    "an incomparable target is still matched by a node's Is method",
			chain:   errwalk.Chain{incomparable, acceptsAll{}},
			targets: errwalk.NewTargets(incomparable),
			assert:  matches(0),
		},
		{
			name:    "a typed-nil target is handed to Is methods, as Is does",
			chain:   errwalk.Chain{other, isNilTarget{}},
			targets: errwalk.NewTargets(a, (*target)(nil)),
			assert:  matches(1),
		},
		{
			name:    "a typed-nil target no node accepts matches nothing",
			chain:   errwalk.Chain{other, &target{name: "t"}},
			targets: errwalk.NewTargets((*target)(nil)),
			assert:  matches(-1),
		},
		{
			name:    "a nil target keeps its position and matches nothing",
			chain:   errwalk.Chain{acceptsAll{}},
			targets: errwalk.NewTargets(nil, a),
			assert:  matches(1),
		},
		{
			name:    "an empty chain matches nothing",
			chain:   errwalk.Chain{},
			targets: errwalk.NewTargets(a, b),
			assert:  matches(-1),
		},
		{
			name:    "no targets match nothing",
			chain:   errwalk.Chain{a},
			targets: errwalk.Targets{},
			assert:  matches(-1),
		},
		{
			name:    "the targets are copied when built",
			chain:   errwalk.Chain{b},
			targets: copied,
			assert:  matches(0),
		},
		{
			name:    "a match for the first target ahead of a panicking node wins",
			chain:   errwalk.Chain{a, panicIs{}},
			targets: errwalk.NewTargets(a, b),
			assert:  matches(0),
		},
		{
			name:    "a panic on node 1 for target 0 aborts with its frames, though target 1 matches node 0",
			chain:   errwalk.Chain{b, panicIs{}},
			targets: errwalk.NewTargets(a, b),
			assert:  panics("errwalk_test.panicIs.Is"),
		},
		{
			name:    "a panic on node 2 for target 1, after target 0 said no everywhere, aborts with its frames",
			chain:   errwalk.Chain{isMethod{match: other}, other, panicsFor{target: b}},
			targets: errwalk.NewTargets(a, b),
			assert:  panics("errwalk_test.panicsFor.Is"),
		},
		{
			name:    "a comparable type holding an incomparable value aborts",
			chain:   errwalk.Chain{boxErr{v: []int{1}}},
			targets: errwalk.NewTargets(a, boxErr{v: []int{1}}),
			assert: func(t *testing.T, index int, abort error) {
				t.Helper()

				var pe *errwalk.PanicError
				require.ErrorAs(t, abort, &pe)
				assert.Equal(t, "panic", errwalk.Reason(abort))
				assert.Equal(t, -1, index)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var (
				index int
				abort error
			)
			require.NotPanics(t, func() { index, abort = errwalk.Index(tc.chain, tc.targets) })
			tc.assert(t, index, abort)
		})
	}
}

// TestIndex_AgreesWithIsPerTarget pins that Index gives what calling Is once
// per target, in order, gives: the first target that matches, or the abort of
// the first Is that panics. It runs every ordering of a fixed set of targets
// over every chain built from a fixed set of nodes, up to three long.
func TestIndex_AgreesWithIsPerTarget(t *testing.T) {
	t.Parallel()

	a := errors.New("a")
	b := errors.New("b")
	c := errors.New("c")

	nodes := []error{a, b, c, isMethod{match: b}, isMethod{match: c}, acceptsAll{}, panicIs{}, errors.New("other")}
	targetSets := [][]error{
		{a, b, c},
		{c, b, a},
		{b, nil, a},
		{c},
		{},
		{errors.New("unknown"), a},
	}

	reference := func(chain errwalk.Chain, targets []error) (int, error) {
		for j, target := range targets {
			found, abort := errwalk.Is(chain, target)
			if abort != nil {
				return -1, abort
			}

			if found {
				return j, nil
			}
		}

		return -1, nil
	}

	var chains []errwalk.Chain

	chains = append(chains, errwalk.Chain{})
	for _, x := range nodes {
		chains = append(chains, errwalk.Chain{x})
		for _, y := range nodes {
			chains = append(chains, errwalk.Chain{x, y})
			for _, z := range nodes {
				chains = append(chains, errwalk.Chain{x, y, z})
			}
		}
	}

	compared := 0

	for _, targets := range targetSets {
		prepared := errwalk.NewTargets(targets...)

		for _, chain := range chains {
			wantIndex, wantAbort := reference(chain, targets)
			gotIndex, gotAbort := errwalk.Index(chain, prepared)

			require.Equal(t, wantIndex, gotIndex, "chain %v, targets %v", chain, targets)
			require.Equal(t, errwalk.Reason(wantAbort), errwalk.Reason(gotAbort), "chain %v, targets %v", chain, targets)

			compared++
		}
	}

	t.Logf("compared %d chain and target combinations", compared)
}
