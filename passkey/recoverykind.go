package passkey

import (
	"context"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/recovery"
)

// recoveryKindName is the passkey authenticator kind's name, the "passkey" of
// a reference such as "passkey:<library id>".
const recoveryKindName = "passkey"

// recoveryKind is the passkey authenticator kind of the account-recovery
// reset; see (*Manager).RecoveryKind.
type recoveryKind struct{ m *Manager }

var (
	_ recovery.AuthenticatorKind = recoveryKind{}
	_ recovery.UsableLister      = recoveryKind{}
)

// RecoveryKind returns the passkey authenticator kind, for the account-recovery
// reset and the way-back check. Register it with
// recovery.WithAuthenticatorKinds and in recovery.WayBackDeps.Kinds; do not
// also pass the MFA method to recovery.MFAEnrolments.
//
// The kind is named "passkey", and names each passkey by its library
// identifier, as {Kind: "passkey", ID: <id>}, so a reported loss reads
// "passkey:<id>"; the identifiers are the ones List reports.
//
//   - Held lists every passkey the user holds, in every state, so the default
//     reset removes them all.
//   - Usable, which also makes the kind a recovery.UsableLister, lists only
//     the active ones: a pending or suspended passkey is never a way back in.
//   - Remove deletes the named passkeys of the user. A reference to a passkey
//     the user does not hold, of another kind, or whose identifier does not
//     parse is ignored.
//
// A failed listing is an error, never an empty list. A passkey is never a
// recovery proof.
func (m *Manager) RecoveryKind() recovery.AuthenticatorKind { return recoveryKind{m: m} }

// Kind reports "passkey".
func (recoveryKind) Kind() string { return recoveryKindName }

// Held lists every passkey user holds, in every state.
func (k recoveryKind) Held(ctx context.Context, user identity.UserID) ([]recovery.AuthenticatorRef, error) {
	all, err := k.m.credentials.List(ctx, user)
	if err != nil {
		return nil, diag.Wrap(err, "passkey: could not list the user's passkeys")
	}

	return refsOf(all), nil
}

// Usable lists the active passkeys user holds.
func (k recoveryKind) Usable(ctx context.Context, user identity.UserID) ([]recovery.AuthenticatorRef, error) {
	active, err := k.m.activeCredentials(ctx, user)
	if err != nil {
		return nil, err
	}

	return refsOf(active), nil
}

// Remove deletes user's passkeys named by refs, stopping at the first store
// failure.
func (k recoveryKind) Remove(ctx context.Context, user identity.UserID, refs []recovery.AuthenticatorRef) error {
	for _, ref := range refs {
		if ref.Kind != recoveryKindName {
			continue
		}

		cid, err := id.Parse(ref.ID)
		if err != nil {
			continue
		}

		if _, err := k.m.credentials.Delete(ctx, user, cid); err != nil {
			return diag.Wrap(err, "passkey: could not remove a passkey")
		}
	}

	return nil
}

// refsOf names each credential as the passkey kind does.
func refsOf(creds []*Credential) []recovery.AuthenticatorRef {
	refs := make([]recovery.AuthenticatorRef, 0, len(creds))

	for _, c := range creds {
		if c != nil {
			refs = append(refs, recovery.AuthenticatorRef{Kind: recoveryKindName, ID: c.ID.String()})
		}
	}

	return refs
}
