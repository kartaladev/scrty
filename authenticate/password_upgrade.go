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
// password provider leaves what an upgrade of one request's password needs,
// and where the caller reads the replacement hash once it wants it.
//
// The hash travels here and not on [Authentication], which never carries one.
// It is safe for use by the goroutine that made the request and the one the
// provider runs on.
type PasswordUpgrade struct {
	mu sync.Mutex

	// Left by the provider once the password verified and the stored hash is
	// outdated; presented is cleared as soon as Result has encoded it.
	pending   bool
	ctx       context.Context // the request's, for the record an encoding failure writes
	enc       password.Encoder
	logger    *slog.Logger
	presented string

	// The answer, decided on the first Result and cached.
	settled   bool
	user      *identity.Details
	replaced  []byte
	upgraded  []byte
	available bool
}

// RequestPasswordUpgrade returns ctx marked so that a password provider which
// verifies the password it is given, and whose encoder reports the stored hash
// as outdated ([github.com/kartaladev/scrty/authenticate/password.Upgrader]),
// leaves in the returned handle what encoding the password again with its
// current encoder needs.
//
// The encoding itself, an extra key derivation, is spent only when the caller
// asks for it through [PasswordUpgrade.Result], once the request's outcome is
// decided: a login refused afterwards never asks, and pays nothing. Until then
// the handle holds the presented password, for the request's lifetime and no
// longer; the first Result drops it.
//
// Without this mark the provider retains nothing. A provider that refuses the
// credentials, whose encoder is not an Upgrader, or whose stored hash is
// current leaves the handle empty.
func RequestPasswordUpgrade(ctx context.Context) (context.Context, *PasswordUpgrade) {
	u := &PasswordUpgrade{}

	return context.WithValue(ctx, upgradeKey{}, u), u
}

// Result returns the user as the loader reported it, the stored hash the
// upgrade replaces and the new hash, and whether one was prepared. The slices
// belong to the caller.
//
// The first call encodes the password the provider left, at most once, then
// drops it; every later call returns the same answer and encodes nothing. An
// encoder that fails is logged, by its Go type and never its text, and the
// answer is ok == false.
func (u *PasswordUpgrade) Result() (user *identity.Details, replaced, upgraded []byte, ok bool) {
	u.mu.Lock()
	defer u.mu.Unlock()

	if !u.settled {
		u.settle()
	}

	return u.user, u.replaced, u.upgraded, u.available
}

// Discard ends the handle without encoding. It clears the presented password
// and the request's context the provider left, and settles the handle with no
// answer: a later [PasswordUpgrade.Result] returns ok == false and never
// encodes.
//
// A login layer calls it when the request ends, on every outcome, so a login
// refused after its password verified does not leave the password reachable,
// through the context handed to the user loader, until the handle is collected.
// It is idempotent, safe on a nil handle, and after a Result it changes
// nothing: that answer is kept. By default, with no call, the handle holds the
// password until the first Result drops it.
func (u *PasswordUpgrade) Discard() {
	if u == nil {
		return
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	if !u.settled {
		u.user, u.replaced = nil, nil
	}

	u.settled = true
	u.pending = false
	u.presented = ""
	u.ctx = nil
	u.enc = nil
	u.logger = nil
}

// settle decides the answer: it encodes a pending password and drops it, and
// marks the handle settled. The caller holds u.mu.
func (u *PasswordUpgrade) settle() {
	u.settled = true

	if !u.pending {
		return
	}

	presented, ctx := u.presented, u.ctx
	u.pending, u.presented, u.ctx = false, "", nil

	upgraded, err := u.enc.Encode(presented)
	if err != nil {
		u.logger.LogAttrs(ctx, slog.LevelError, "password hash could not be upgraded",
			diag.Failure("password-upgrade", err)...)

		u.user, u.replaced = nil, nil

		return
	}

	u.upgraded = upgraded
	u.available = true
}

// prepareUpgrade leaves in the caller's handle what upgrading a password that
// has just verified needs, when the caller asked for it and the encoder says
// the stored hash is outdated. It encodes nothing: [PasswordUpgrade.Result]
// does, when the caller asks. A handle already settled is left as it is, so no
// password is held where nothing will read it.
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

	u.mu.Lock()
	defer u.mu.Unlock()

	if u.settled {
		return
	}

	u.pending = true
	u.ctx = ctx
	u.enc = a.enc
	u.logger = a.logger
	u.presented = presented
	u.user = details
	u.replaced = details.Password
}
