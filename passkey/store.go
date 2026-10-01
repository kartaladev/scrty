package passkey

import (
	"context"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
)

// CredentialStore keeps passkey credentials.
//
// The library uses NewMemoryCredentialStore when a consumer supplies none.
// Any implementation of this contract may be used in its place; durable ones
// seal the emailed code at rest, and a read that cannot open a sealed code is
// an error, never a missing code.
//
// Every state change is one conditional write, decided by the store rather
// than by a read before it, so concurrent callers cannot both pass a guard. A
// write that is refused changes nothing and reports false with a nil error;
// a write to a credential that does not exist, or that is not the named
// user's, is refused the same way. The error is reserved for the store
// failing.
type CredentialStore interface {
	// Insert stores c. It returns ErrDuplicateCredential when c's credential
	// ID, or its library ID, is already stored, whatever user holds it; the
	// write decides, so of concurrent inserts of one credential ID exactly one
	// succeeds.
	Insert(ctx context.Context, c *Credential) error
	// FindByCredentialID returns the credential with the WebAuthn credential
	// ID credID, or ErrNotFound.
	FindByCredentialID(ctx context.Context, credID []byte) (*Credential, error)
	// Find returns user's credential cid, or ErrNotFound when there is none or
	// it is another user's.
	Find(ctx context.Context, user identity.UserID, cid id.ID) (*Credential, error)
	// List returns user's credentials in every state, ordered by
	// CreatedAt, ties broken by the library ID (SQL: ORDER BY created_at, id).
	List(ctx context.Context, user identity.UserID) ([]*Credential, error)
	// Count counts user's credentials in every state.
	Count(ctx context.Context, user identity.UserID) (int, error)
	// RecordAssertion sets the counter, the backup-state flag and the last-use
	// time of credential cid, only where it is active and its stored counter
	// is lower than signCount or both are zero. It reports whether this call
	// recorded it, so of concurrent recordings of one counter exactly one
	// reports true.
	RecordAssertion(ctx context.Context, cid id.ID, signCount uint32, backupState bool, at time.Time) (bool, error)
	// RecordUse sets the backup-state flag and the last-use time of
	// credential cid without touching its counter, only where it is active
	// (SQL: UPDATE ... SET backup_state, last_used_at WHERE id = cid AND
	// state = active). It reports whether this call changed a credential; a
	// credential that is missing, pending or suspended is false and nil. The
	// library calls it for an accepted assertion whose counter write was
	// refused and then allowed as a clone.
	RecordUse(ctx context.Context, cid id.ID, backupState bool, at time.Time) (bool, error)
	// Suspend moves credential cid from active to suspended, and reports
	// whether this call did. Suspension is terminal.
	Suspend(ctx context.Context, cid id.ID) (bool, error)
	// ClearReason clears the pending reason r of user's credential cid, only
	// where r is exactly one reason, AwaitingSavedCodes or AwaitingEmailCode,
	// and the credential is pending with it set; any other r, such as zero, a
	// combination or an unknown bit, is refused and changes nothing. Clearing the last reason
	// makes it active in the same write, and clearing AwaitingEmailCode drops
	// its emailed code. It returns the state that results and true, or the
	// zero State and false when refused.
	ClearReason(ctx context.Context, user identity.UserID, cid id.ID, r PendingReason) (State, bool, error)
	// ChargeEmailAttempt charges one attempt against the emailed code of
	// user's credential cid, only where the credential is pending with
	// AwaitingEmailCode set, the code is outstanding, at is before its expiry
	// and fewer than MaxEmailCodeAttempts are charged. It returns the stored
	// code, with the attempt counted, for the caller to compare, and true; or
	// nil and false when refused.
	ChargeEmailAttempt(ctx context.Context, user identity.UserID, cid id.ID, at time.Time) (*EmailCode, bool, error)
	// Rename sets the name of user's credential cid, and reports whether it
	// exists. The name is stored as given; callers normalise it.
	Rename(ctx context.Context, user identity.UserID, cid id.ID, name string) (bool, error)
	// Delete removes user's credential cid, and reports whether this call
	// removed it.
	Delete(ctx context.Context, user identity.UserID, cid id.ID) (bool, error)
	// DeleteAwaitingSavedCodes removes every credential of user whose
	// AwaitingSavedCodes reason is set, and reports how many it removed.
	DeleteAwaitingSavedCodes(ctx context.Context, user identity.UserID) (int, error)
	// DeleteUser removes every credential of user, and reports how many it
	// removed.
	DeleteUser(ctx context.Context, user identity.UserID) (int, error)
}
