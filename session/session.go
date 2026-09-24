package session

import (
	"strconv"
	"time"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/identity"
)

// MFAState is how far a second-factor challenge has got on one session.
//
// It is library-owned state: a Manager writes it, and nothing reads it out of
// the consumer's data map, so no key a consumer happens to choose can forge or
// erase it. The zero value is MFANone, which is what a session established with
// a single factor reports.
type MFAState int

// The second-factor states a session can be in.
const (
	// MFANone means no second factor has been asked for on this session.
	MFANone MFAState = iota

	// MFAPending means a second factor has been asked for and not yet given.
	// A session in this state has authenticated a first factor and nothing
	// more, so it is not a fully authenticated session.
	MFAPending

	// MFASatisfied means a second factor was given and accepted.
	MFASatisfied
)

// String returns the constant's own name, so a log line reads "pending" rather
// than "1". An unnamed value prints its number rather than passing itself off
// as one of the three.
func (s MFAState) String() string {
	switch s {
	case MFANone:
		return "none"
	case MFAPending:
		return "pending"
	case MFASatisfied:
		return "satisfied"
	default:
		return "MFAState(" + strconv.Itoa(int(s)) + ")"
	}
}

// Session is one authenticated caller's session.
//
// Every field below the consumer's Data map belongs to the library: the
// Manager writes them and the Store persists them unchanged. Data belongs to
// the consumer, and nothing here reads it — see its own contract.
type Session struct {
	// ID is the bearer identifier the caller presents. It is 32 bytes from the
	// operating system's cryptographically secure random source, encoded
	// URL-safe without padding, so it is 43 characters long and unguessable.
	ID string

	// UserID references the user this session belongs to. It is the
	// consumer's own reference, matched byte-for-byte and never parsed.
	UserID identity.UserID

	// CreatedAt is when the session was created, read from the manager's
	// clock.
	CreatedAt time.Time

	// LastAccessedAt is when activity was last recorded, which Touch moves.
	LastAccessedAt time.Time

	// IdleExpiresAt is the deadline activity extends, never past
	// AbsoluteExpiresAt.
	IdleExpiresAt time.Time

	// AbsoluteExpiresAt is the deadline nothing extends. A session in constant
	// use still ends at the hour it was always going to end.
	AbsoluteExpiresAt time.Time

	// FirstFactor is the kind of factor the login that established this
	// session used. The empty kind means none was recorded; there is no
	// default, and what an unrecorded first factor means for access is the
	// security-policy capability's decision, not this package's.
	FirstFactor factor.Kind

	// MFA is how far a second-factor challenge has got. Library-owned.
	MFA MFAState

	// MFASatisfiedAt is when the second factor was accepted, read from the
	// manager's clock. It is zero until then, including while a challenge is
	// pending. Library-owned, like MFA itself: a consumer cannot set it
	// through Data, so a satisfied second factor is something the library
	// recorded and not something a consumer key can claim.
	MFASatisfiedAt time.Time

	// PasswordChangePending marks that this session owes a password change.
	// Library-owned.
	PasswordChangePending bool

	// ExternalProvider names the identity provider a federated login came
	// from, as the consumer configured it.
	ExternalProvider string

	// ExternalIssuer is the issuer the provider's token was verified against.
	// Deleting by provider session matches on it, so two providers cannot end
	// each other's sessions.
	ExternalIssuer string

	// ExternalSessionID is the provider's own session identifier, which may be
	// empty: not every provider issues one.
	ExternalSessionID string

	// ExternalIDToken is the provider's raw ID token. It is a credential in
	// its own right, which is why NewEncryptedStore exists to seal exactly
	// this field before it reaches a durable store.
	ExternalIDToken string

	// Data is the consumer's own map. The library stores and returns it
	// byte-for-byte, and never reads, adds, renames or removes an entry. No
	// library state is kept in it: the first factor, the second-factor state
	// and the password-change marker are fields above, so a consumer key can
	// neither forge nor erase a challenge state.
	//
	// It is map[string]string rather than a map of arbitrary values because
	// "returned unchanged" has to survive a durable store, where a number
	// comes back a float and "0042" comes back 42.
	Data map[string]string
}

// clone returns a session sharing no map with s, so neither side can reach the
// other's state by writing to what it handed over or read back.
func (s *Session) clone() *Session {
	if s == nil {
		return nil
	}

	out := *s
	if s.Data != nil {
		out.Data = make(map[string]string, len(s.Data))
		for k, v := range s.Data {
			out.Data[k] = v
		}
	}

	return &out
}

// expired reports whether now is at or past either deadline.
//
// The comparison is not-before rather than after, so a session is gone at its
// deadline rather than one instant later: a deadline is the first moment the
// session is no longer valid.
func (s *Session) expired(now time.Time) bool {
	return !now.Before(s.IdleExpiresAt) || !now.Before(s.AbsoluteExpiresAt)
}
