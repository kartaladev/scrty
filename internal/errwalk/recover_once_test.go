package errwalk_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/errwalk"
)

// TestIs_RecoverOncePerCall pins that one Is, As, Index or Flatten call arms
// one deferred recover around its whole scan or walk, however long the chain
// and however many targets, rather than one per node comparison, method call
// or target. A recover armed per node was the cost that
// dominated classification time; any panic in the scan aborts the whole call
// either way, so one is enough.
//
// It is not parallel: the arm counter is process-wide.
func TestIs_RecoverOncePerCall(t *testing.T) { //nolint:paralleltest // the arm counter is process-wide
	type testCase struct {
		name   string
		match  func() error
		assert func(t *testing.T, arms int, abort error)
	}

	sentinel := errors.New("sentinel")

	// long has 40 nodes that all take both steps of Is and say no: a
	// comparable node of the target's own type, and a node with Is and As
	// methods.
	long := make(errwalk.Chain, 0, 40)
	for range 20 {
		long = append(long, errors.New("other"), isMethod{match: errors.New("x")})
	}

	declines := make(errwalk.Chain, 0, 40)
	for range 40 {
		declines = append(declines, asDeclines{})
	}

	armedOnce := func(t *testing.T, arms int, abort error) {
		t.Helper()
		require.NoError(t, abort)
		assert.Equal(t, 1, arms, "recovers armed by one call")
	}

	cases := []testCase{
		{
			name: "Is over 40 nodes that do not match",
			match: func() error {
				found, abort := errwalk.Is(long, sentinel)
				if found {
					return errors.New("unexpected match")
				}

				return abort
			},
			assert: armedOnce,
		},
		{
			name: "Is with a match on the last node",
			match: func() error {
				_, abort := errwalk.Is(append(long[:len(long):len(long)], sentinel), sentinel)

				return abort
			},
			assert: armedOnce,
		},
		{
			name: "As over 40 nodes whose As declines",
			match: func() error {
				_, found, abort := errwalk.As[*target](declines)
				if found {
					return errors.New("unexpected match")
				}

				return abort
			},
			assert: armedOnce,
		},
		{
			name: "Index over 40 targets and 40 nodes that do not match",
			match: func() error {
				targets := make([]error, 0, 40)
				for range 40 {
					targets = append(targets, errors.New("absent"))
				}

				index, abort := errwalk.Index(long, errwalk.NewTargets(targets...))
				if index != -1 {
					return errors.New("unexpected match")
				}

				return abort
			},
			assert: armedOnce,
		},
		{
			name: "Index with a panic on the second node for the second target",
			match: func() error {
				_, abort := errwalk.Index(errwalk.Chain{isMethod{match: errors.New("x")}, panicsFor{target: sentinel}}, errwalk.NewTargets(errors.New("absent"), sentinel))

				return abort
			},
			assert: func(t *testing.T, arms int, abort error) {
				t.Helper()
				requirePanic(t, abort, "is boom")
				assert.Equal(t, 1, arms, "recovers armed by one call")
			},
		},
		{
			name: "Flatten over a chain of 40 links",
			match: func() error {
				c, abort := errwalk.Flatten(linear(40))
				if len(c) != 40 {
					return errors.New("unexpected chain length")
				}

				return abort
			},
			assert: armedOnce,
		},
		{
			name: "Flatten over a join of 40 members",
			match: func() error {
				members := make([]error, 0, 40)
				for range 40 {
					members = append(members, &one{name: "member", next: errors.New("cause")})
				}

				c, abort := errwalk.Flatten(errors.Join(members...))
				if len(c) != 81 {
					return errors.New("unexpected chain length")
				}

				return abort
			},
			assert: armedOnce,
		},
		{
			name: "Flatten with a panic on the third link",
			match: func() error {
				_, abort := errwalk.Flatten(&one{name: "1", next: &one{name: "2", next: panicUnwrap{}}})

				return abort
			},
			assert: func(t *testing.T, arms int, abort error) {
				t.Helper()
				requirePanic(t, abort, "unwrap boom")
				assert.Equal(t, 1, arms, "recovers armed by one call")
			},
		},
		{
			name: "Is with a panic on the second node",
			match: func() error {
				_, abort := errwalk.Is(errwalk.Chain{isMethod{match: errors.New("x")}, panicIs{}}, sentinel)

				return abort
			},
			assert: func(t *testing.T, arms int, abort error) {
				t.Helper()
				requirePanic(t, abort, "is boom")
				assert.Equal(t, 1, arms, "recovers armed by one call")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			arms := errwalk.CountArms(t)

			abort := tc.match()
			tc.assert(t, *arms, abort)
		})
	}
}
