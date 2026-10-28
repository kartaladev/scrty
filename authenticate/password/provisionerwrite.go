package password

//go:generate mockgen -destination=provisioner_mock_test.go -package=password_test -typed github.com/kartaladev/scrty/identity UserProvisioner

import (
	"context"
	"fmt"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/nilcheck"
)

// ProvisionerWrite returns the default [WriteFunc] for [ReuseGuard.Change]: it
// calls p.Update for user.Username with
// [identity.WithUserPasswordChange](hash, changedAt), naming the new hash and
// the time of the change and nothing else, and returns Update's error
// unchanged.
//
// This is the path on which a change records its time by default, so
// password-age policy sees every change made through the guard. It joins a
// transaction attached to ctx exactly when p's Update does, so with a store
// that backs both the users and the [History], one transaction covers the
// retire and the write.
//
// A consumer whose users live in their own storage passes their own WriteFunc
// instead. One that ignores changedAt leaves the stored password-changed time
// as it was, and so gives up password-age policy for that user.
//
// A nil or typed-nil p is refused here, at wiring time, with an error wrapping
// [ErrConfig]. The returned write refuses a nil user the same way and updates
// nothing.
func ProvisionerWrite(p identity.UserProvisioner) (WriteFunc, error) {
	if nilcheck.IsNil(p) {
		return nil, fmt.Errorf("%w: a user provisioner is required", ErrConfig)
	}

	return func(ctx context.Context, user *identity.Details, hash []byte, changedAt time.Time) error {
		if user == nil {
			return fmt.Errorf("%w: a user record is required", ErrConfig)
		}

		_, err := p.Update(ctx, user.Username, identity.WithUserPasswordChange(hash, changedAt))

		return err
	}, nil
}
