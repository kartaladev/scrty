package password

//go:generate mockgen -source=history.go -destination=history_mock_test.go -package=password_test -typed

import (
	"context"
	"errors"
	"time"

	"github.com/kartaladev/scrty/identity"
)

// History keeps the hashes a user's password had before its current one.
//
// It is the storage behind [ReuseGuard]. The library ships no in-process
// implementation: a consumer supplies one over their own storage, or uses a
// store that implements it. Nothing reads or writes history unless the consumer
// builds a guard over it, so password history is off by default.
//
// The hashes are credential material. An implementation must never log them or
// quote them in an error, and returns them only through RecentPasswords.
type History interface {
	// RecentPasswords returns up to n of the user's retired hashes, newest
	// first. A user with none returns an empty slice and no error. A failure,
	// including a user reference the store cannot read, is an error, never an
	// empty history: the guard refuses the change rather than check nothing.
	RecentPasswords(ctx context.Context, user identity.UserID, n int) ([][]byte, error)

	// RetirePassword records hash as the user's newest retired hash, then keeps
	// only the newest keep entries. Recording the same bytes as the current
	// newest entry adds nothing, so a retried change does not count one password
	// twice. keep == 0 records nothing and removes every entry.
	RetirePassword(ctx context.Context, user identity.UserID, hash []byte, keep int) error

	// ForgetPasswords removes every retired hash of the user. A consumer's user
	// deletion calls it together with deleting the user.
	ForgetPasswords(ctx context.Context, user identity.UserID) error
}

var (
	// ErrPasswordReused refuses a new password that matches the user's current
	// password or one of their recent ones. Its text is fixed and carries no
	// password, hash or user reference.
	ErrPasswordReused = errors.New("password: matches a recent password")

	// ErrHistoryUnavailable refuses a change whose history could not be read or
	// recorded. The guard fails closed: it never reads a failure as "no
	// history". The error it returns reports this fixed text only, while the
	// [History] port's own error stays reachable through [errors.Is] and
	// [errors.As], so text a store put in its error never reaches a response or
	// a log line through the guard.
	ErrHistoryUnavailable = errors.New("password: password history could not be read or written")

	// ErrConfig reports a wiring mistake: a missing port, encoder, matcher or
	// clock, a depth below one, or a missing user record or write function
	// handed to a check or change. The message names the mistake, never a value.
	ErrConfig = errors.New("password: invalid configuration")
)

// WriteFunc stores user's new password hash and the time it changed.
//
// [ReuseGuard.Change] calls it last, after the reuse check and after the
// current hash has been retired, and returns its error unchanged. user is the
// record the caller passed to Change; hash is the new hash, already encoded;
// changedAt is read from the guard's clock ([WithReuseClock], default
// clock.System()).
//
// [ProvisionerWrite] builds one over any [identity.UserProvisioner] that
// records both the hash and changedAt. That is the only path on which the time
// is recorded by default. A WriteFunc that ignores changedAt leaves the stored
// password-changed time as it was, which exempts the user from password-age
// policy: a password-age check keeps reading the old time, or none, however
// often the password changes.
type WriteFunc func(ctx context.Context, user *identity.Details, hash []byte, changedAt time.Time) error
