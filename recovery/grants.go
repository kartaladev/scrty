package recovery

//go:generate mockgen -source=grants.go -destination=grants_mock_test.go -package=recovery_test -typed

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/depfault"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/hangup"
	"github.com/kartaladev/scrty/internal/nilcheck"
)

// ErrDependency marks a recovery that a dependency stopped once its proofs had
// passed their checks and before its issued and saved codes were spent, so the
// same proofs succeed when presented again. Today that is the first grant
// revocation alone (WithGrantRevoker). An MFA proof is the one exception: its
// verification comes first and spends it, so a retry needs the next MFA code. It
// is never a refusal: nothing is counted against the user or, on a chain, against
// the source. Errors match it through errors.Is, beside the dependency's own
// error.
var ErrDependency = errors.New("recovery: a dependency stopped the recovery")

// grantRevocationCause is the cause a recovery revokes grants with.
const grantRevocationCause = "recovery"

// GrantRevoker revokes every grant an application holds for a user, those with
// offline access included. *oidcprovider.Provider satisfies it. It is what lets
// a recovery end what a stolen account's applications still hold, without this
// package knowing about an OpenID Provider.
type GrantRevoker interface {
	// RevokeUserGrants revokes every grant of user, recording cause. Revoking
	// what is already revoked is not an error, and a recovery relies on that: it
	// calls this twice, and a caller may call it again after
	// Result.GrantsNotRevoked.
	RevokeUserGrants(ctx context.Context, user identity.UserID, cause string) error
}

// WithGrantRevoker revokes the recovered user's application grants whenever a
// recovery completes, those with offline access included. The default is no
// revoker, and no change: a recovery revokes nothing when no provider is in
// use. httpsec's account recovery supplies the chain's provider, and a revoker
// given here replaces it.
//
// The revoker is called twice. The first call runs once the proofs pass every
// check and the credential is issued, immediately before the issued and saved
// codes are spent, on the caller's context. A failure there is a dependency
// failure (ErrDependency) behind fixed text of this package, still matching
// through errors.Is and errors.As: nothing is spent, recorded, removed, ended or
// sent, nothing is counted against the user, and the same proofs succeed when
// presented again. The cost is that it is not free of effect: a proof holder
// who then loses a race to spend, or whose spend fails, has still ended the
// grants, and so has one whose client hung up during a revocation that
// succeeded: with no MFA proof the recovery then returns the context's error,
// spending nothing, and the same proofs succeed on a retry. Only someone
// holding valid proofs reaches it, and ending them is what they came to do.
//
// An MFA proof changes that order, as nothing but its verification can judge its
// code and verifying spends it. It is verified before the first call, so a wrong
// code ends nothing, and the first call then runs detached from the caller's
// cancellation, as a proof is spent. A failure of that call has spent the MFA
// code and nothing else, so a retry needs the next one.
//
// The second call runs once the sessions were ended, detached from the caller's
// cancellation, as a live session could have minted a grant in between. Its
// failure does not stop the recovery, whose proofs are already spent: the
// session is stored, the saved set replaced and the notice sent,
// Result.GrantsNotRevoked is set, and the failure is logged and reported as
// event.GrantRevokeFailed. There is no option to abort there instead, as it
// would spend the proofs for nothing.
//
// A held recovery revokes nothing when it starts, as the real user may yet
// cancel it, and takes the same two steps at its finish, where a first failure
// leaves the record pending and the completion token usable. A finish that then
// loses the conditional write to the real user's cancel has already ended the
// grants by its first revocation, which runs before that write.
//
// A nil revoker, typed nil included, is a configuration error.
func WithGrantRevoker(revoker GrantRevoker) Option {
	return func(c *config) { c.grants, c.grantsSet = revoker, true }
}

// WithoutRecoveryGrantRevocation keeps the user's application grants when a
// recovery completes, replacing the default of revoking them whenever a revoker
// is present. It wins over WithGrantRevoker, so a consumer can keep grants on a
// chain that supplies its provider. With no revoker it changes nothing.
//
// This weakens recovery. A user recovers because they lost control of their
// account, and a grant kept is a way back in for whoever took it, for as long as
// its refresh token lives.
func WithoutRecoveryGrantRevocation() Option {
	return func(c *config) { c.keepGrants = true }
}

// revokeGrantsFirst revokes user's grants before the issued and saved codes are
// spent, and does nothing with no revoker. ctx is the caller's own, unless an MFA
// proof was already spent (revokeThenSpend). A failure is logged and returned
// behind fixed text, a dependency failure: at ERROR, or at DEBUG when ctx's own
// end cut it short. It is marked depfault.ErrFailed too, so a revoker's error
// that wraps a refusal reports no refusal.
//
// A bound above zero runs the revoker under a context detached from ctx's
// cancellation that ends after bound; the failure is still logged and
// classified under ctx, so the bound's own end is never read as a hang-up. Zero
// runs the revoker on ctx itself.
func (r *Recoverer) revokeGrantsFirst(ctx context.Context, user identity.UserID, bound time.Duration) error {
	if r.grants == nil {
		return nil
	}

	call := func(c context.Context) error { return r.grants.RevokeUserGrants(c, user, grantRevocationCause) }

	err := maybeBounded(ctx, bound, call)
	if err == nil {
		return nil
	}

	level := slog.LevelError
	if hangup.ByCaller(ctx, err) {
		level = slog.LevelDebug
	}

	r.logger.LogAttrs(ctx, level, msgGrantsFailed, diag.Failure("grant-revoker", err)...)

	return diag.Wrap(err, errTextGrants, ErrDependency, depfault.ErrFailed)
}

// validateGrants checks the grant revoker and settles whether one is used.
func (r *Recoverer) validateGrants(c *config) error {
	if c.grantsSet && nilcheck.IsNil(c.grants) {
		return fmt.Errorf("%w: WithGrantRevoker was given no revoker", ErrConfig)
	}

	if !c.keepGrants {
		r.grants = c.grants
	}

	return nil
}
