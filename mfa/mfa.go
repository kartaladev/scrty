package mfa

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

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
	// Name identifies the method in logs, in the library's per-method paths
	// and in a consumer's own routing. It is one path segment of lowercase
	// letters, digits and hyphens, starting with a letter or digit, unique
	// among the methods served, and constant.
	Name() string

	// Channel reports the medium this method's codes travel over. Constant,
	// never empty.
	Channel() factor.Channel

	// Enrolled reports whether user has a confirmed, readable enrolment.
	Enrolled(ctx context.Context, user identity.UserID) (bool, error)

	// Response declares how the verification response is carried and the
	// largest body accepted. Constant for the method's lifetime.
	Response() ResponseFormat

	// Verify checks response for user. The response is the bytes the library
	// read as Response declares: a form field's value, or a whole JSON body.
	// A wrong, reused or malformed response returns ErrInvalidCode.
	Verify(ctx context.Context, user identity.UserID, response []byte) error
}

// ChallengeMethod is a Method whose response answers a challenge the server
// issued, such as a WebAuthn assertion or an emailed code bound to one attempt.
//
// The library owns the pending challenge: it issues it as a single-use token
// bound to the session, hands its string to BeginChallenge, and on verify
// checks the challenge PresentedChallenge extracts against the one it issued,
// spending it on every attempt, before Verify is called. The method owns its
// protocol: what the client is sent, and how the answer is checked.
//
// An implementation is expected to be safe for concurrent use.
type ChallengeMethod interface {
	Method

	// BeginChallenge returns the JSON the client needs to answer, built around
	// challenge, a server-issued random string the library will later match.
	BeginChallenge(ctx context.Context, user identity.UserID, challenge string) (json.RawMessage, error)

	// PresentedChallenge extracts from response the challenge the client
	// answered. A response it cannot read is an error, and the verification is
	// refused as an invalid code.
	PresentedChallenge(response []byte) (string, error)
}

// LookupsFor validates methods and returns them, in the same order, as the
// lookups the security policies consult.
//
// A Method already has everything policy.MFAMethodLookup needs, so this is a
// validating constructor rather than a translation: it is the one place a
// wrongly declared method is caught, at construction rather than at a user's
// first verification. Every refusal wraps ErrConfig and names the method's
// position. It refuses:
//   - an empty set;
//   - an absent method, nil or typed nil;
//   - an empty channel. An empty channel equals the channel of an unrecorded
//     first factor, so every session established without a recorded kind would
//     be refused at verify as a same-channel attempt;
//   - a name that is not one path segment of lowercase letters, digits and
//     hyphens, starting with a letter or digit;
//   - two methods sharing a name;
//   - a response format not built by FormField or JSONBody, a limit of zero or
//     less or above 1 MiB, or a form field with no name.
//
// Each returned lookup carries its method's contract unchanged: Enrolled is
// true only for a confirmed, readable enrolment, and a store failure is an
// error rather than a false. There is no default set: the library cannot guess
// which methods a consumer serves.
func LookupsFor(methods ...Method) ([]policy.MFAMethodLookup, error) {
	if len(methods) == 0 {
		return nil, fmt.Errorf("%w: at least one method is required", ErrConfig)
	}

	lookups := make([]policy.MFAMethodLookup, 0, len(methods))
	seen := make(map[string]struct{}, len(methods))

	for i, m := range methods {
		if nilcheck.IsNil(m) {
			return nil, fmt.Errorf("%w: method %d is nil", ErrConfig, i)
		}

		name := m.Name()
		if !methodName.MatchString(name) {
			return nil, fmt.Errorf("%w: method %d is named %q, which is not one path segment "+
				"of lowercase letters, digits and hyphens", ErrConfig, i, name)
		}

		if _, dup := seen[name]; dup {
			return nil, fmt.Errorf("%w: method %d is named %q, as an earlier method is", ErrConfig, i, name)
		}

		seen[name] = struct{}{}

		if m.Channel() == "" {
			return nil, fmt.Errorf("%w: method %d (%q) reports no channel", ErrConfig, i, name)
		}

		if err := checkResponse(m.Response()); err != nil {
			return nil, fmt.Errorf("%w: method %d (%q) %w", ErrConfig, i, name, err)
		}

		lookups = append(lookups, m)
	}

	return lookups, nil
}

// methodName is one path segment: lowercase letters, digits and hyphens,
// starting with a letter or digit.
var methodName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// maxResponseLimit is the largest body a method may declare: 1 MiB.
const maxResponseLimit = 1 << 20

// checkResponse refuses a format FormField or JSONBody would not describe.
func checkResponse(f ResponseFormat) error {
	switch f.Kind() {
	case ResponseFormField:
		if f.Field() == "" {
			return errors.New("declares a form field with no name")
		}
	case ResponseJSONBody:
	default:
		return errors.New("declares a response format not built by FormField or JSONBody")
	}

	if f.Limit() <= 0 || f.Limit() > maxResponseLimit {
		return fmt.Errorf("declares a response limit of %d bytes, outside (0, %d]", f.Limit(), maxResponseLimit)
	}

	return nil
}
