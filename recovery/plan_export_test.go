package recovery

import (
	"context"

	"github.com/kartaladev/scrty/identity"
)

// This file exposes the reset planner to the package's black-box tests. The
// Recoverer's options are its public face; until they exist, the tests reach
// the planner here. It is a test file, so nothing here reaches a production
// build.

// ResetMode names the planner's three modes for the tests.
type ResetMode = resetMode

// The planner's modes.
const (
	ResetAll      = resetAll
	ResetReported = resetReported
	ResetCustom   = resetCustom
)

// Planner wraps the unexported planner.
type Planner struct{ p planner }

// NewPlanner exposes the planner's validating constructor.
func NewPlanner(kinds []AuthenticatorKind, mode ResetMode, policy ResetPolicy) (Planner, error) {
	p, err := newPlanner(kinds, mode, policy)

	return Planner{p: p}, err
}

// Plan exposes the plan computed before anything is spent.
func (p Planner) Plan(ctx context.Context, user identity.UserID, reported, proven []AuthenticatorRef) ([]AuthenticatorRef, error) {
	return p.p.plan(ctx, user, reported, proven)
}

// Execute exposes the removals run at completion.
func (p Planner) Execute(ctx context.Context, user identity.UserID, plan []AuthenticatorRef) error {
	return p.p.execute(ctx, user, plan)
}
