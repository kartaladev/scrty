package recovery

import (
	"context"
	"time"

	"github.com/kartaladev/scrty/identity"
)

// This file exposes the recovery's check and spend phases to the package's
// black-box tests, so they can pin each phase apart from the completion that
// Recover runs after them. It is a test file, so nothing here reaches a
// production build.

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
