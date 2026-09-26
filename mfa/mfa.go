package mfa

import (
	"context"
	"errors"
	"fmt"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/policy"
)

// ErrInvalidCode is returned for every code a method refuses: a wrong code, a
// code from outside the accepted window, a malformed one, a code for a user
// with no confirmed enrolment, and a code already spent within its time step.
//
// The cases are deliberately indistinguishable. Telling them apart would say
// whether a user exists and whether they have enrolled, to a caller who has
// only guessed a code.
var ErrInvalidCode = errors.New("mfa: invalid code")

// ErrAlreadyEnrolled refuses an enrolment for a user who already has a
// confirmed one. The existing enrolment is left exactly as it was: replacing a
// working second factor silently is how a user is locked out of their account.
var ErrAlreadyEnrolled = errors.New("mfa: this user already has a confirmed enrolment")

// ErrSameChannel refuses a verification whose method delivers on the very
// channel the session's first factor arrived on. Two factors on one channel are
// one factor, so the code is refused before it is read.
var ErrSameChannel = errors.New("mfa: the second factor arrives on the first factor's own channel")

// ErrVerifyThrottled refuses a verification because this user has accumulated
// too many failures, or because the limiter could not say. An undecidable
// limiter is an outage, and letting guesses through during one would turn a
// dependency failure into an open door.
var ErrVerifyThrottled = errors.New("mfa: too many failed verifications for this user")

// ErrConfig reports a configuration this package refuses: a dependency an
// operation needs and was not given, where an explicit option is the way to
// do without it.
var ErrConfig = errors.New("mfa: invalid configuration")

// ErrEmailCodeInvalid refuses an emailed enrolment code: a wrong one, a
// malformed one, an expired one, one presented after its attempts ran out, and
// one presented for a generation that is no longer current.
//
// The cases are deliberately indistinguishable, for the reason ErrInvalidCode's
// are, and each has already been charged as an attempt by the time it is
// returned.
//
// It wraps ErrInvalidCode, so a caller that maps the invalid second-factor code
// refusal answers an emailed one the same way; its own message still tells an
// operator which code was refused.
var ErrEmailCodeInvalid = fmt.Errorf("%w: the emailed code is wrong or expired", ErrInvalidCode)

// ErrEnrolmentThrottled refuses an enrolment step because this user has begun
// or failed too many, or because the limiter could not say. Like
// ErrVerifyThrottled, an undecidable limiter refuses rather than admits.
var ErrEnrolmentThrottled = errors.New("mfa: too many enrolment attempts for this user")

// Method is one way a user proves a second factor.
//
// # The channel
//
// Channel is the medium this method's codes travel over, and it must be
// constant for the method's lifetime and never empty. It is compared with the
// channel of the first factor the session was established with: a code that
// arrives the same way the first factor did is not a second factor, and the
// verify endpoint refuses one outright.
//
// The values are factor's. This package defines no channel of its own, so there
// is one vocabulary to read. The built-in TOTP method reports
// factor.AuthenticatorApp, which is the channel of no first-factor kind the
// library names. A consumer's method reports whichever factor channel its codes
// travel over — factor.Email for an emailed one-time code, for one.
//
// # Enrolment answers
//
// Enrolled reports false only when the store definitively holds no confirmed
// enrolment. A store failure, or an enrolment whose secret cannot be read, is an
// error. Reporting either as false would let a login through on its first factor
// for exactly the users who had enrolled, which is the downgrade this whole
// capability exists to prevent.
//
// An implementation is expected to be safe for concurrent use.
type Method interface {
	// Name identifies the method in logs and in a consumer's own routing.
	Name() string

	// Channel reports the medium this method's codes travel over. Constant,
	// never empty.
	Channel() factor.Channel

	// Enrolled reports whether user has a confirmed, readable enrolment.
	Enrolled(ctx context.Context, user identity.UserID) (bool, error)

	// Verify checks code for user. A wrong, reused or malformed code returns
	// ErrInvalidCode.
	Verify(ctx context.Context, user identity.UserID, code string) error
}

// LookupFor adapts a Method to the lookup the security policies consult.
//
// A Method already has the two methods policy.MFAMethodLookup needs, so this is
// a validating constructor rather than a translation: it is the one place a
// method with no channel is caught. An empty channel equals the channel of an
// unrecorded first factor, so every session established without a recorded kind
// would be refused at verify as a same-channel attempt — a wiring mistake whose
// symptom appears far from its cause, which is why it is refused here.
//
// The returned lookup carries the method's contract unchanged: Enrolled is true
// only for a confirmed, readable enrolment, and a store failure is an error
// rather than a false. There is no default: a lookup describes one method, and
// the library cannot guess which.
func LookupFor(m Method) (policy.MFAMethodLookup, error) {
	if nilcheck.IsNil(m) {
		return nil, errors.New("mfa: lookup requires a method")
	}

	if m.Channel() == "" {
		return nil, fmt.Errorf("mfa: method %q reports no channel", m.Name())
	}

	return m, nil
}
