package authenticate

import (
	"context"
	"log/slog"
	"sync"

	"github.com/kartaladev/scrty/authenticate/password"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
)

// upgradeKey is the context key a password upgrade request travels under.
type upgradeKey struct{}

// PasswordUpgrade is the handle RequestPasswordUpgrade returns: where the
// password provider leaves the replacement hash it prepared for one request.
//
// The hash travels here and not on [Authentication], which never carries one.
// It is safe for use by the goroutine that made the request and the one the
// provider runs on.
type PasswordUpgrade struct {
	mu        sync.Mutex
	user      *identity.Details
	replaced  []byte
	upgraded  []byte
	available bool
}

// RequestPasswordUpgrade returns ctx marked so that a password provider which
// verifies the password it is given, and whose encoder reports the stored hash
// as outdated ([github.com/kartaladev/scrty/authenticate/password.Upgrader]),
// encodes the password again with its current encoder and leaves the result in
// the returned handle.
//
// Without this mark the provider encodes nothing and retains nothing: the
// extra key derivation is spent only for a caller that asked for it. A provider
// that refuses the credentials, whose encoder is not an Upgrader, or whose
// stored hash is current leaves the handle empty.
func RequestPasswordUpgrade(ctx context.Context) (context.Context, *PasswordUpgrade) {
	u := &PasswordUpgrade{}

	return context.WithValue(ctx, upgradeKey{}, u), u
}

// Result returns the user as the loader reported it, the stored hash the
// upgrade replaces and the new hash, and whether the provider prepared one. The
// slices belong to the caller.
func (u *PasswordUpgrade) Result() (user *identity.Details, replaced, upgraded []byte, ok bool) {
	u.mu.Lock()
	defer u.mu.Unlock()

	return u.user, u.replaced, u.upgraded, u.available
}

// prepareUpgrade leaves the replacement hash for a password that has just
// verified, when the caller asked for one and the encoder says the stored hash
// is outdated. It never fails the authentication: the password was already
// proved, so a failure here is logged, by its Go type and never its text, and
// the old hash stays in place.
func (a *UsernamePasswordAuthenticator) prepareUpgrade(
	ctx context.Context,
	details *identity.Details,
	presented string,
) {
	u, ok := ctx.Value(upgradeKey{}).(*PasswordUpgrade)
	if !ok || u == nil {
		return
	}

	up, ok := a.enc.(password.Upgrader)
	if !ok || !up.NeedsUpgrade(details.Password) {
		return
	}

	upgraded, err := a.enc.Encode(presented)
	if err != nil {
		a.logger.LogAttrs(ctx, slog.LevelError, "password hash could not be upgraded",
			diag.Failure("password-upgrade", err)...)

		return
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	u.user = details
	u.replaced = details.Password
	u.upgraded = upgraded
	u.available = true
}
