package onetime

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/kartaladev/scrty/pkg/id"
)

// ErrInvalidToken is returned for every presented token a manager will not
// honour, whatever the reason: a malformed string, a record that does not
// exist, one issued for another purpose, one already spent, one past its
// expiry, a secret that does not match, a binding that does not match, and a
// store that could not answer.
//
// The reasons are deliberately indistinguishable. A caller who could tell them
// apart could ask a manager which record identifiers exist, and which of them
// are still unspent, without holding a single valid token.
var ErrInvalidToken = errors.New("onetime: invalid token")

// ErrSubjectRequired is returned by Issue when no subject was given. A token
// belonging to nobody could never be counted, audited or revoked, so it is
// refused rather than stored.
var ErrSubjectRequired = errors.New("onetime: a subject is required")

// Token is one issued credential as a store holds it. It carries no secret: the
// secret exists only in the string Issue returned to the caller, and only the
// hashes below are ever written down.
type Token struct {
	// ID is the record identifier, and the first half of the string presented
	// for redemption. It comes from a replaceable id.Generator, so a consumer
	// can correlate a token with their own records.
	ID id.ID

	// Purpose is the issuing manager's purpose. A manager honours only the
	// records carrying its own, which is what lets several managers share one
	// store without honouring each other's tokens.
	Purpose string

	// Subject is whoever the token was issued for, exactly as the caller gave
	// it. The library stores and returns it unchanged and never interprets it:
	// an address, an account identifier or an opaque handle are all the same
	// to this package, and only the consumer knows which it is.
	Subject string

	// SecretHash is sha256 of the presented secret. The secret itself is never
	// stored, so a store that leaks yields nothing that can be presented.
	SecretHash []byte

	// BindingHash is sha256 of the value the token was bound to, or nil when it
	// was issued unbound. Absent is not the same as empty: hashing an absent
	// binding to sha256("") would let any holder satisfy it by presenting
	// nothing at all.
	BindingHash []byte

	// IssuedAt is when the token was minted, read from the manager's clock. It
	// is what IssuedCount counts over and what a purge's cutoff is compared
	// against.
	IssuedAt time.Time

	// ExpiresAt is IssuedAt plus the manager's time-to-live. A check at or
	// after this instant is refused.
	ExpiresAt time.Time

	// ConsumedAt is when the token was spent, or the zero time while it is
	// still unspent. A store sets it once and never moves it, so the first
	// consumption's time survives every later attempt.
	ConsumedAt time.Time
}

// Checked is the proof that a token passed Check. It is what Consume takes.
//
// Its fields are unexported and it has no exported constructor, so the only way
// to hold a non-empty one is to have been given it by Check. That makes
// check-then-consume structural instead of a rule each caller has to remember:
// there is no way to spell "spend this token" that skips the check, and a
// zero Checked a caller declares for themselves names no record and is refused.
type Checked struct {
	token Token
}

// Token returns the record the check matched. It carries no secret, so a caller
// may log or pass it on freely.
func (c Checked) Token() Token { return c.token }

// Check is a caller's own refusal check, run by Redeem after the token has been
// checked and before it is spent.
//
// Its error is returned to Redeem's caller unchanged and leaves the token
// redeemable, so a holder refused for a reason they can fix — a rate limit, a
// pending enrolment — does not also lose their credential.
type Check func(ctx context.Context, tok Token) error

// hash returns sha256 of value. It is the one description of how this package
// reduces a secret or a binding to something storable, so issuance and checking
// cannot drift apart.
func hash(value string) []byte {
	sum := sha256.Sum256([]byte(value))

	return sum[:]
}
