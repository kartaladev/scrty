package password

import (
	"context"
	"errors"
	"fmt"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/nilcheck"
)

// ConditionalProvisionerRehash returns a write for a login's rehash option
// (httpsec.WithLoginRehash and its Basic and re-proof equivalents) that stores
// the upgraded hash only while the hash it replaces is still the stored one.
//
// A login that verified the old password can finish after a password change
// stored a new one. An unconditional write would then put the old password
// back. This write is one call to the store, an update conditional on the
// replaced hash ([identity.WithUserPasswordIf]), which the store decides in
// the write itself, so a change that commits at any point before it is never
// overwritten. When the stored hash is no longer the replaced one
// ([identity.ErrNotUpdated]), nothing is written and the write returns nil: the
// change is the newer truth, and the next login upgrades it. A user who has
// since gone ([identity.ErrUserNotFound]) is left alone the same way. Any other
// error is returned, for the login to log; it never changes the login's
// outcome.
//
// The update names the user by username, as [identity.UserProvisioner.Update]
// does. A username reissued to another person between the login and the write
// does not let the write reach that person when the encoder salts its hashes,
// as every built-in one does: their stored hash is not the replaced one, so the
// condition fails. With a consumer encoder that is unsalted, two people's
// hashes can be equal only for the same password, which the write then stores
// again unchanged.
//
// Only the password is written; the password's age is not moved, because a
// rehash re-encodes the same password and is not a password change.
//
// The library's identity stores honour the condition, and the identity
// conformance suite checks that a consumer's store does. A store that ignores
// it turns this into an unconditional write.
//
// Default: with no rehash write configured, nothing is rehashed. This is the
// ready-made write, not the default. A nil or typed-nil store is a wiring
// mistake, reported here, before traffic, as an error wrapping [ErrConfig] with
// no write returned, as [ProvisionerWrite] does. The returned write refuses a
// nil user the same way and updates nothing.
func ConditionalProvisionerRehash(
	store identity.UserProvisioner,
) (func(ctx context.Context, user *identity.Details, replaced, upgraded []byte) error, error) {
	if nilcheck.IsNil(store) {
		return nil, fmt.Errorf("%w: a user provisioner is required", ErrConfig)
	}

	return func(ctx context.Context, user *identity.Details, replaced, upgraded []byte) error {
		if user == nil {
			return fmt.Errorf("%w: a user record is required", ErrConfig)
		}

		_, err := store.Update(ctx, user.Username,
			identity.WithUserPasswordIf(replaced),
			identity.WithUserPassword(upgraded),
		)

		switch {
		case err == nil, errors.Is(err, identity.ErrNotUpdated), errors.Is(err, identity.ErrUserNotFound):
			return nil
		default:
			return fmt.Errorf("password: storing the upgraded hash: %w", err)
		}
	}, nil
}
