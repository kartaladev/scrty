package recovery

import (
	"context"
	"time"

	"github.com/kartaladev/scrty/identity"
)

// This file exposes what the package's tests need and consumers must not have.
// It is a test file, so nothing here reaches a production build.

// The recovery's check and spend phases are exposed so the tests can pin each
// phase apart from the completion that Recover runs after them.

// Verified is the outcome of the check phase.
type Verified = verified

// Verify exposes the check phase: steps 1 to 5, nothing spent.
func (r *Recoverer) Verify(ctx context.Context, req Request) (*Verified, error) {
	return r.verify(ctx, req)
}

// Spend exposes the spend phase.
func (r *Recoverer) Spend(ctx context.Context, v *Verified) error {
	return r.spend(ctx, v)
}

// CheckIssued exposes the write-free check of an issued code for user.
func (r *Recoverer) CheckIssued(ctx context.Context, user identity.UserID, presented string) error {
	_, err := r.checkIssued(ctx, user, presented)

	return err
}

// User reports whom the recovery is for.
func (v *Verified) User() identity.UserID { return v.user }

// Proofs reports the proofs presented, in canonical order.
func (v *Verified) Proofs() []ProofKind { return v.proofs }

// Plan reports the authenticators the recovery will remove.
func (v *Verified) Plan() []AuthenticatorRef { return v.plan }

// Proven reports the authenticators the user proved.
func (v *Verified) Proven() []AuthenticatorRef { return v.proven }

// Reported reports the authenticators the user reported lost.
func (v *Verified) Reported() []AuthenticatorRef { return v.reported }

// Hold reports how long the risk hook asked the recovery to be held.
func (v *Verified) Hold() time.Duration { return v.hold }

// The reset planner is exposed here. The Recoverer's options are its public
// face; until they exist, the tests reach the planner here.

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

// CodeBytes is the entropy a saved code carries, pinned by the tests.
const CodeBytes = codeBytes

// NewCode exposes the saved-code generator.
var NewCode = newCode

// ParseCode exposes the saved-code parser.
var ParseCode = parseCode

// Check exposes the throttled, write-free check the recovery flow runs before
// anything is spent.
func (c *Codes) Check(ctx context.Context, user identity.UserID, presented string) ([32]byte, error) {
	return c.check(ctx, user, presented)
}

// Spend exposes the conditional spend the recovery flow runs last.
func (c *Codes) Spend(ctx context.Context, user identity.UserID, hash [32]byte) error {
	return c.spend(ctx, user, hash)
}
