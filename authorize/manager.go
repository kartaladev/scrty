package authorize

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/kartaladev/scrty/internal/nilcheck"
)

// Manager runs authorizers in the order it was given them and lets the first
// one that does not decline decide.
//
// It is itself an Authorizer, so a consumer puts one in the request context
// with WithAuthorizer and every guard downstream reaches the same decision
// rather than being wired with an authorizer of its own.
//
// When every authorizer declines, the manager denies. That is the whole reason
// the declination is a distinct error: an attempt nobody was configured to
// judge is one the consumer never described, and allowing it would turn a gap
// in the wiring into an open door.
type Manager struct {
	authorizers []Authorizer
}

var _ Authorizer = (*Manager)(nil)

// NewManager returns a manager over authorizers, consulted in the order given.
//
// It refuses a call with no authorizers, and one with any absent authorizer,
// including an interface holding a nil pointer. Neither is filtered out
// quietly: a manager that skipped an absent authorizer would run fewer checks
// than the consumer wrote, and the missing one is exactly the check a wiring
// mistake removes. Failing here costs a constructor error; filtering costs a
// decision nobody made, on every request, for as long as it goes unnoticed.
//
// The manager holds its own copy of the slice, so a caller that reuses the
// slice it passed cannot swap an authorizer out from under a built manager.
func NewManager(authorizers ...Authorizer) (*Manager, error) {
	if len(authorizers) == 0 {
		return nil, fmt.Errorf("%w: a manager with no authorizers denies everything", ErrConfig)
	}

	for i, a := range authorizers {
		if nilcheck.IsNil(a) {
			return nil, fmt.Errorf("%w: authorizer %d is absent", ErrConfig, i)
		}
	}

	return &Manager{authorizers: slices.Clone(authorizers)}, nil
}

// Authorize offers attrs to each authorizer in turn and returns the first
// answer that is not a declination, unchanged.
//
// An authorizer's error is returned as it came, so an outage inside a
// consumer's own authorizer still matches its cause and is never rewritten as a
// decision about the caller. Only the case where every authorizer declined
// produces an error of this package's own, and that error is a denial.
func (m *Manager) Authorize(ctx context.Context, attrs Attributes) error {
	for _, a := range m.authorizers {
		err := a.Authorize(ctx, attrs)
		if errors.Is(err, ErrUnsupportedAttributes) {
			continue
		}

		return err
	}

	return fmt.Errorf("%w: no authorizer judges attributes of type %T", ErrAccessDenied, attrs)
}
