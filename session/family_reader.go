package session

import (
	"context"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
)

// FamilyReader is what a Store may also offer, so a read of one sign-in does
// not list every sign-in of the user. It is optional, and a Store gains nothing
// it must implement. Sessions.SignInState uses it when the store has it, and
// uses Store.ListByUser, the default, when it does not; the answers are the
// same. The stores of this repository offer it, and so does the store
// NewEncryptedStore returns, whatever it wraps.
//
// What it buys over the default is a smaller read: it costs one family's rows
// instead of all of the user's, and a row of another family that the store
// cannot read cannot fail it.
//
// A store offering it must agree with its own ListByUser: a family read at now
// answers exactly the sessions of that family a listing at now answers, as a
// sign-in renews, rotates and ends. The conformance suite holds a store to it.
//
//go:generate mockgen -source=family_reader.go -package=session_test -destination=family_reader_mock_test.go -typed
type FamilyReader interface {
	// ListByFamily is Store.ListByUser's contract narrowed to one family: this
	// user's sessions of family that are not superseded and are before both of
	// their own deadlines at now, the time the caller passes. The reference is
	// matched exactly as the consumer supplied it, and no other user's session
	// is ever returned, even of the same family. No match is an empty result,
	// not an error, and so is the nil family, which names no family and which
	// the store need not ask anyone about.
	//
	// As with a listing, the order is unspecified, the sessions returned belong
	// to the caller, an ID may be empty, and no sealed field is opened, so a
	// sealing store answers with its key retired and its sessions carry
	// neither token. A store that cannot read one of the family's rows fails
	// the call rather than skipping the row. A row of another family does not
	// fail it.
	ListByFamily(ctx context.Context, user identity.UserID, family id.ID, now time.Time) ([]*Session, error)
}

// readFamily answers one family's sessions from store: through its family read
// when it has one, and otherwise through its listing, the rest of which the
// caller filters out as it filters whatever a store answers.
func readFamily(ctx context.Context, store Store, user identity.UserID, family id.ID, now time.Time) ([]*Session, error) {
	if reader, ok := store.(FamilyReader); ok {
		return reader.ListByFamily(ctx, user, family, now)
	}

	return store.ListByUser(ctx, user, now)
}
