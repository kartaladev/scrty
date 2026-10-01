package recovery

//go:generate mockgen -source=store.go -destination=store_mock_test.go -package=recovery_test -typed

import (
	"context"
	"time"

	"github.com/kartaladev/scrty/identity"
)

// CodeStore keeps the hashes of each user's saved recovery codes.
//
// It holds, per user reference, the SHA-256 hash of each code's 16 bytes, when
// it was stored and, once spent, when it was spent. It never sees a code: what
// it holds cannot be presented.
//
// A hash matches only within its own user's set. An unknown code and a spent
// code have the same outcome — false with no error — so nothing above the
// store can tell them apart. An error means the question could not be
// answered, never that the answer was no.
//
// MemoryCodeStore is the default. A consumer supplies a durable one when codes
// must survive a restart or be shared across replicas; any implementation of
// this contract is usable in its place. An implementation must be safe for
// concurrent use.
type CodeStore interface {
	// ReplaceSet removes every code of user and stores hashes as the user's new
	// set, all stamped at, in one operation: a reader never sees a mix of the
	// two sets, and a failure leaves the previous set whole. Inside a caller's
	// transaction, a failure undoes only this operation's own statements.
	//
	// The store keeps its own copies of hashes; the caller may reuse or wipe
	// the slices afterwards.
	ReplaceSet(ctx context.Context, user identity.UserID, hashes [][]byte, at time.Time) error

	// Match reports whether user holds an unspent code whose hash is hash.
	// It writes nothing, whether it matches or not.
	Match(ctx context.Context, user identity.UserID, hash []byte) (bool, error)

	// Spend marks user's code whose hash is hash as spent at at, by one
	// conditional write on "not yet spent", and reports whether this call spent
	// it. Of any number of concurrent spends of one code at most one reports
	// true. A refused spend changes nothing, so the first spending time is
	// kept.
	Spend(ctx context.Context, user identity.UserID, hash []byte, at time.Time) (bool, error)

	// Remaining counts user's unspent codes. A user with no set has none.
	Remaining(ctx context.Context, user identity.UserID) (int, error)

	// DeleteUser removes every code of user, spent or not, and reports how
	// many were removed.
	DeleteUser(ctx context.Context, user identity.UserID) (int, error)
}
