package passkey

//go:generate mockgen -source=manage.go -destination=manage_mock_test.go -package=passkey_test -typed

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

// Summary is one passkey as its user is shown it. It carries no public key,
// credential ID, user handle or attestation statement.
type Summary struct {
	// ID is the passkey's library identifier, which Rename and Remove take and
	// a recovery's reported loss names.
	ID id.ID
	// Name is the passkey's name, as stored.
	Name string
	// State is active, pending or suspended.
	State State
	// CreatedAt is when the passkey was registered, and LastUsedAt when an
	// assertion from it was last accepted; zero when never.
	CreatedAt  time.Time
	LastUsedAt time.Time
	// BackupEligible and BackupState are the authenticator's backup flags: a
	// synced passkey is backup-eligible.
	BackupEligible bool
	BackupState    bool
	// Transports are the transports the authenticator reported.
	Transports []string
	// AAGUID identifies the authenticator model: 16 bytes, or nil.
	AAGUID []byte
}

// List lists user's passkeys in every state, in the store's order: oldest
// first. A store failure is an error, never an empty list.
//
// It admits no session: the caller serves it to full sessions only.
func (m *Passkeys) List(ctx context.Context, user identity.UserID) ([]Summary, error) {
	all, err := m.credentials.List(ctx, user)
	if err != nil {
		return nil, diag.Wrap(err, "passkey: could not list the user's passkeys")
	}

	out := make([]Summary, 0, len(all))

	for _, c := range all {
		if c == nil {
			continue
		}

		out = append(out, Summary{
			ID:             c.ID,
			Name:           c.Name,
			State:          c.State,
			CreatedAt:      c.CreatedAt,
			LastUsedAt:     c.LastUsedAt,
			BackupEligible: c.BackupEligible,
			BackupState:    c.BackupState,
			Transports:     c.Transports,
			AAGUID:         c.AAGUID,
		})
	}

	return out, nil
}

// Rename names user's passkey cid, in any state, under the registration's
// name rules (NormalizeName): the name is trimmed, and one that is empty,
// longer than 64 characters or holds a control or format character is
// replaced by the default name for the date the passkey was registered, never
// truncated or refused.
//
// A cid that names no passkey of user — another user's, or none — is
// ErrNotFound, and nothing changes. Renaming changes no authenticator, so it
// admits no session: the caller serves it to full sessions only.
func (m *Passkeys) Rename(ctx context.Context, user identity.UserID, cid id.ID, name string) error {
	c, err := m.findOwn(ctx, user, cid)
	if err != nil {
		return err
	}

	renamed, err := m.credentials.Rename(ctx, user, cid, NormalizeName(name, c.CreatedAt))
	if err != nil {
		return diag.Wrap(err, "passkey: could not rename the passkey")
	}

	if !renamed {
		return ErrNotFound
	}

	return nil
}

// Remove removes s's user's passkey cid, in any state — a suspended passkey
// included — and queues the Removed notice naming it.
//
// Removal changes the user's authenticators, so s must be a full session at
// the account's assurance, as for a registration (see the package
// documentation's Admission section): when the user can use any of the
// configured MFA methods (rc.MFAMethods, or Deps.MFAMethods when rc lists
// none), or holds an active passkey while a passkey route can meet the second
// factor, s must have met its second factor, and its latest
// authentication, the later of its creation and its second factor, must be
// within the management freshness window (WithManagementFreshness, 15 minutes
// by default). A recovery-pending or enrolment-only session, a session with a
// pending MFA challenge or owing a password change, and no session at all are
// refused too. Every such refusal is ErrReauthenticationRequired; a failed MFA
// or passkey lookup refuses with fixed text, and a nil entry in rc.MFAMethods
// with ErrConfig.
//
// A cid that names no passkey of the user — another user's, or none — is
// ErrNotFound, and nothing changes. A notice that cannot be queued is logged
// and does not undo the removal.
//
// By default, a removal also ends every other session of the user: every
// session but s, which stays as it is, neither rotated nor marked.
// WithoutSessionRevocationOnRemoval makes keeping them the default, and opts
// decide for this removal: KeepOtherSessions keeps them and EndOtherSessions
// ends them, whatever the default, the last one given winning. When they end,
// they end before the passkey is deleted, so a failure to end them refuses the
// removal with fixed text, leaves the passkey for a retry and queues no
// notice. After the delete they are ended a second time, catching a login
// that finished in between; that pass runs under a context the caller cannot
// cancel, and its failure is logged and does not undo the removal. The Removed
// notice says whether they were ended (Notice.SessionsEnded). Asking to end
// them of a manager wired with no session revoker is ErrConfig, and changes
// nothing.
//
// Removing a passwordless user's last active passkey leaves them only account
// recovery to sign in with.
func (m *Passkeys) Remove(
	ctx context.Context, s *session.Session, cid id.ID, rc RegistrationContext, opts ...RemoveOption,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if err := m.admitRemoval(ctx, s, rc); err != nil {
		return err
	}

	c, err := m.findOwn(ctx, s.UserID, cid)
	if err != nil {
		return err
	}

	end := m.endsOtherSessions(opts)
	if end && nilcheck.IsNil(m.sessions) {
		return fmt.Errorf("%w: a session revoker is required to end the user's other sessions", ErrConfig)
	}

	if end {
		if _, err := m.sessions.DeleteByUserExcept(ctx, s.UserID, s.ID); err != nil {
			return diag.Wrap(err, "passkey: could not end the user's other sessions")
		}
	}

	removed, err := m.credentials.Delete(ctx, s.UserID, cid)
	if err != nil {
		return diag.Wrap(err, "passkey: could not remove the passkey")
	}

	if !removed {
		return ErrNotFound
	}

	if end {
		m.endOtherSessionsAgain(ctx, s, cid)
	}

	m.notify(ctx, noticeRemoved, c, nil, end)

	return nil
}

// endOtherSessionsAgain ends s's user's other sessions a second time, after
// the passkey is gone: a login that finished between the first pass and the
// delete left a session the first pass could not see, while one that records
// its assertion after the delete is refused. It runs under a context the
// caller cannot cancel, and its failure is logged and does not undo the
// removal.
func (m *Passkeys) endOtherSessionsAgain(ctx context.Context, s *session.Session, cid id.ID) {
	ctx = context.WithoutCancel(ctx)

	if _, err := m.sessions.DeleteByUserExcept(ctx, s.UserID, s.ID); err != nil {
		m.sampled(ctx, slog.LevelError, "remove|sessions-not-ended", msgSessionsNotEnded,
			append(diag.Failure("remove", err), credentialAttr(cid))...)
	}
}

// admitRemoval admits only a full session, by admit's rule for one: a
// confined session, which admit lets register, may not remove.
func (m *Passkeys) admitRemoval(ctx context.Context, s *session.Session, rc RegistrationContext) error {
	if s == nil || s.MFA == session.MFARecoveryPending || s.MFA == session.MFAEnrolmentPending {
		return ErrReauthenticationRequired
	}

	return m.admit(ctx, s, rc)
}

// findOwn returns user's credential cid, or ErrNotFound when it is not one.
func (m *Passkeys) findOwn(ctx context.Context, user identity.UserID, cid id.ID) (*Credential, error) {
	c, err := m.credentials.Find(ctx, user, cid)

	switch {
	case errors.Is(err, ErrNotFound):
		return nil, ErrNotFound
	case err != nil:
		return nil, diag.Wrap(err, "passkey: could not look up the passkey")
	case c == nil || c.User != user:
		return nil, ErrNotFound
	}

	return c, nil
}

// SessionRevoker ends sessions: what the manager needs to end a user's other
// sessions after a passkey removal and all of them after a suspected clone.
//
// *session.Sessions satisfies it. Wire the same manager the chain uses, the one
// given to httpsec.PasskeyDeps.Sessions, so that a session ended here is the
// session the chain no longer loads. With no revoker, the manager is only
// valid when both revocations are turned off
// (WithoutSessionRevocationOnRemoval, WithoutSessionRevocationOnClone).
type SessionRevoker interface {
	// DeleteByUser ends every session of user.
	DeleteByUser(ctx context.Context, user identity.UserID) error
	// DeleteByUserExcept ends every session of user but the one with
	// identifier keep and, when keep was renewed, its family's current
	// session, and reports how many it ended. The removing sign-in survives
	// whichever of its identifiers the request presented; its other,
	// superseded sessions end with the user's other sign-ins.
	DeleteByUserExcept(ctx context.Context, user identity.UserID, keep string) (int, error)
}

var _ SessionRevoker = (*session.Sessions)(nil)

// WithoutSessionRevocationOnRemoval keeps the user's other sessions when a
// passkey is removed, replacing the default of ending every session but the
// removing one.
func WithoutSessionRevocationOnRemoval() Option {
	return func(m *Passkeys) { m.keepOnRemoval = true }
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
func (m *Passkeys) endsOtherSessions(opts []RemoveOption) bool {
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
