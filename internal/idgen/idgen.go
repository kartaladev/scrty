// Package idgen asks an [id.Generator] for a new identifier and refuses the
// nil identifier.
package idgen

import (
	"errors"

	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/pkg/id"
)

//go:generate mockgen -source=../../pkg/id/generator.go -destination=idgentest/generator_mock.go -package=idgentest -typed

// ErrNil is returned by [New] when the generator answers the nil identifier
// without an error. Its text is fixed and carries no consumer data.
var ErrNil = errors.New("the identifier generator returned the nil identifier")

// ErrNoGenerator is returned by [New] when it is given no generator, including
// an interface that holds a nil pointer. A component validates its generator
// when it is built, so reaching this is a wiring mistake that escaped that
// check; it is reported, not turned into a panic.
var ErrNoGenerator = errors.New("no identifier generator was given")

// New asks g for a new identifier and refuses the nil identifier.
//
// The nil identifier ([id.Nil]) means "no identifier". A generator that
// answers it with no error would make every record it numbers share one
// identifier, for example every grant of the OpenID Provider joining one grant
// family, so that revoking one family revokes other users' grants. New treats
// that answer as a failing dependency.
//
// The contract:
//   - the generator's error comes back unchanged, whatever identifier came with
//     it, so errors.Is on the consumer's error holds and [ErrNil] does not
//     match;
//   - no error and [id.Nil] gives [ErrNil];
//   - otherwise the identifier comes back with a nil error;
//   - a nil g, including a nil pointer held in a non-nil interface, gives
//     [ErrNoGenerator]; New does not panic on it.
//
// New writes no record: the caller reports a failure as it reports any
// generator failure. It recovers no panic: a generator that panics takes the
// caller's goroutine with it, as it did before.
func New(g id.Generator) (id.ID, error) {
	if nilcheck.IsNil(g) {
		return id.Nil, ErrNoGenerator
	}
	got, err := g.NewID()
	if err != nil {
		return got, err
	}
	if got == id.Nil {
		return id.Nil, ErrNil
	}
	return got, nil
}
