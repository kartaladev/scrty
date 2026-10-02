package passkey

import (
	"context"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/session"
)

// SessionRevoker ends sessions: what the manager needs to end a user's other
// sessions after a passkey removal and all of them after a suspected clone.
//
// *session.Manager satisfies it. Wire the same manager the chain uses, the one
// given to httpsec.PasskeyDeps.Sessions, so that a session ended here is the
// session the chain no longer loads. With no revoker, the manager is only
// valid when both revocations are turned off
// (WithoutSessionRevocationOnRemoval, WithoutSessionRevocationOnClone).
type SessionRevoker interface {
	// DeleteByUser ends every session of user.
	DeleteByUser(ctx context.Context, user identity.UserID) error
	// DeleteByUserExcept ends every session of user but the one with
	// identifier keep, and reports how many it ended.
	DeleteByUserExcept(ctx context.Context, user identity.UserID, keep string) (int, error)
}

var _ SessionRevoker = (*session.Manager)(nil)

// WithoutSessionRevocationOnRemoval keeps the user's other sessions when a
// passkey is removed, replacing the default of ending every session but the
// removing one.
func WithoutSessionRevocationOnRemoval() Option {
	return func(m *Manager) { m.keepOnRemoval = true }
}

// WithoutSessionRevocationOnClone keeps the user's sessions when a suspected
// clone suspends a passkey, replacing the default of ending every one of them,
// the session that presented the clone included.
func WithoutSessionRevocationOnClone() Option {
	return func(m *Manager) { m.keepOnClone = true }
}
