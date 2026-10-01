package passkey

import (
	"context"
	"errors"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
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
func (m *Manager) List(ctx context.Context, user identity.UserID) ([]Summary, error) {
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
// name rules (NormaliseName): the name is trimmed, and one that is empty,
// longer than 64 characters or holds a control character is replaced by the
// default name for the date the passkey was registered, never truncated or
// refused.
//
// A cid that names no passkey of user — another user's, or none — is
// ErrNotFound, and nothing changes. Renaming changes no authenticator, so it
// admits no session: the caller serves it to full sessions only.
func (m *Manager) Rename(ctx context.Context, user identity.UserID, cid id.ID, name string) error {
	c, err := m.findOwn(ctx, user, cid)
	if err != nil {
		return err
	}

	renamed, err := m.credentials.Rename(ctx, user, cid, NormaliseName(name, c.CreatedAt))
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
// the account's assurance, as for a registration: when the user can use any
// configured MFA method, s must have met its second factor, and its latest
// authentication, the later of its creation and its second factor, must be
// within the management freshness window (WithManagementFreshness, 15 minutes
// by default). A recovery-pending or enrolment-only session, a session with a
// pending challenge, and no session at all are refused too. Every such refusal
// is ErrReauthenticationRequired.
//
// A cid that names no passkey of the user — another user's, or none — is
// ErrNotFound, and nothing changes. A notice that cannot be queued is logged
// and does not undo the removal.
//
// Removing a passwordless user's last active passkey leaves them only account
// recovery to sign in with.
func (m *Manager) Remove(ctx context.Context, s *session.Session, cid id.ID) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if err := m.admitRemoval(ctx, s); err != nil {
		return err
	}

	c, err := m.findOwn(ctx, s.UserID, cid)
	if err != nil {
		return err
	}

	removed, err := m.credentials.Delete(ctx, s.UserID, cid)
	if err != nil {
		return diag.Wrap(err, "passkey: could not remove the passkey")
	}

	if !removed {
		return ErrNotFound
	}

	m.notify(ctx, noticeRemoved, c, nil)

	return nil
}

// admitRemoval admits only a full session, by admit's rule for one: a
// confined session, which admit lets register, may not remove.
func (m *Manager) admitRemoval(ctx context.Context, s *session.Session) error {
	if s == nil || s.MFA == session.MFARecoveryPending || s.MFA == session.MFAEnrolmentPending {
		return ErrReauthenticationRequired
	}

	return m.admit(ctx, s)
}

// findOwn returns user's credential cid, or ErrNotFound when it is not one.
func (m *Manager) findOwn(ctx context.Context, user identity.UserID, cid id.ID) (*Credential, error) {
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
