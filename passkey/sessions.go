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

// RemoveOption chooses, for one removal, whether the user's other sessions
// end. Without one, the manager's default decides: end them, unless
// WithoutSessionRevocationOnRemoval was given. When several are given, the
// last one wins.
type RemoveOption func(*removeConfig)

// removeConfig is what a removal's options chose.
type removeConfig struct {
	choice removeChoice
}

// removeChoice is a removal's choice about the user's other sessions.
type removeChoice uint8

const (
	removeDefault removeChoice = iota
	removeEnd
	removeKeep
)

// KeepOtherSessions keeps the user's other sessions for this removal, whatever
// the manager's default.
func KeepOtherSessions() RemoveOption {
	return func(c *removeConfig) { c.choice = removeKeep }
}

// EndOtherSessions ends the user's other sessions for this removal, whatever
// the manager's default.
func EndOtherSessions() RemoveOption {
	return func(c *removeConfig) { c.choice = removeEnd }
}

// endsOtherSessions resolves a removal's options against the manager's
// default: the last option given wins, and a nil option is skipped.
func (m *Manager) endsOtherSessions(opts []RemoveOption) bool {
	var c removeConfig

	for _, o := range opts {
		if o != nil {
			o(&c)
		}
	}

	switch c.choice {
	case removeEnd:
		return true
	case removeKeep:
		return false
	default:
		return !m.keepOnRemoval
	}
}
