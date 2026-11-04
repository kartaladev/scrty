package recovery

//go:generate mockgen -source=grants.go -destination=grants_mock_test.go -package=recovery_test -typed

import (
	"context"
	"fmt"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/nilcheck"
)

// grantRevocationCause is the cause a completed recovery revokes grants with.
const grantRevocationCause = "recovery"

// GrantRevoker revokes every grant an application holds for a user, those with
// offline access included. *oidcprovider.Provider satisfies it. It is what lets
// a recovery end what a stolen account's applications still hold, without this
// package knowing about an OpenID Provider.
type GrantRevoker interface {
	// RevokeUserGrants revokes every grant of user, recording cause. Revoking
	// what is already revoked is not an error.
	RevokeUserGrants(ctx context.Context, user identity.UserID, cause string) error
}

// WithGrantRevoker revokes the recovered user's application grants whenever a
// recovery completes, those with offline access included. The default is no
// revoker, and no change: a recovery revokes nothing when no provider is in
// use. httpsec's account recovery supplies the chain's provider, and a revoker
// given here replaces it.
//
// The revocation runs once the sessions were ended, before the saved set is
// replaced. A held recovery revokes nothing until its finish. A failure is
// returned behind fixed text of this package, still matching through errors.Is
// and errors.As, with the earlier steps done, so the saved set is left as it
// was and the session is not stored.
//
// A nil revoker, typed nil included, is a configuration error.
func WithGrantRevoker(g GrantRevoker) Option {
	return func(c *config) { c.grants, c.grantsSet = g, true }
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
