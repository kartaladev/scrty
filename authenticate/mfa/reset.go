package mfa

//go:generate mockgen -source=reset.go -destination=reset_mock_test.go -package=mfa_test -typed
//go:generate mockgen -destination=sender_mock_test.go -package=mfa_test -typed github.com/kartaladev/scrty/notify Sender
//go:generate mockgen -destination=userloader_mock_test.go -package=mfa_test -typed github.com/kartaladev/scrty/identity UserLoader

import (
	"context"
	"fmt"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/notify"
	"github.com/kartaladev/scrty/pkg/clock"
)

// SessionRevoker ends every session of a user. *session.Manager and every
// session.Store satisfy it through their DeleteByUser.
type SessionRevoker interface {
	// DeleteByUser removes every session of user.
	DeleteByUser(ctx context.Context, user identity.UserID) error
}

// EnrolmentRemover removes a user's enrolment, pending or confirmed. TOTP
// satisfies it through RemoveEnrolment.
type EnrolmentRemover interface {
	// RemoveEnrolment removes user's enrolment. Removing an absent one is not
	// an error.
	RemoveEnrolment(ctx context.Context, user identity.UserID) error
}

// ResetDeps is what ResetEnrolment works through. Which fields are required
// depends on the options: every dependency a step needs must be given unless
// that step is turned off by its explicit option, and a missing one is an
// ErrConfig before anything is written. A nil dependency is never read as an
// opt-out.
type ResetDeps struct {
	// Enrolments removes the user's enrolment on every method to reset, in
	// order. Always required: an empty list, or an absent entry, is an
	// ErrConfig.
	Enrolments []EnrolmentRemover

	// Sessions ends the user's sessions. Required unless
	// WithoutSessionRevocation.
	Sessions SessionRevoker

	// Users loads the user's details for the contact address. Required unless
	// WithoutResetNotification.
	Users identity.UserLoader

	// Sender queues the notification. Required unless
	// WithoutResetNotification.
	Sender notify.Sender

	// Contact resolves the notification's address. Nil means
	// UsernameAsAddress.
	Contact ContactResolver
}

// resetConfig is what the options set. The zero value is not the default;
// newResetConfig is.
type resetConfig struct {
	revokeSessions bool
	notify         bool
	clock          clock.Clock
	message        func(at time.Time) (subject, body string)
	// messageUnset records a WithResetMessage given a nil builder, which is
	// refused as ErrConfig rather than read as the default.
	messageUnset bool
}

func newResetConfig(opts []ResetOption) resetConfig {
	c := resetConfig{revokeSessions: true, notify: true, clock: clock.System(), message: defaultResetMessage}

	for _, opt := range opts {
		if opt != nil {
			opt(&c)
		}
	}

	return c
}

// ResetOption configures ResetEnrolment. A nil option is ignored.
type ResetOption func(*resetConfig)

// WithoutSessionRevocation keeps the user's sessions, replacing the default of
// deleting every one of them.
//
// What it gives up: a session that satisfied MFA with the lost or compromised
// authenticator stays usable until it expires. It is for a consumer who
// revokes sessions elsewhere, as part of the same administrative action.
func WithoutSessionRevocation() ResetOption {
	return func(c *resetConfig) { c.revokeSessions = false }
}

// WithoutResetNotification sends nothing, replacing the default of notifying
// the user at their contact address.
//
// What it gives up: the user learns of the reset only when they next sign in.
// A reset they did not ask for — an operator deceived by someone posing as
// them — then goes unnoticed until the attacker has used it.
func WithoutResetNotification() ResetOption {
	return func(c *resetConfig) { c.notify = false }
}

// WithResetClock replaces the source of the instant the notification names.
// The default is clock.System(). A nil clock, typed nil included, is ignored,
// keeping the default: the reset has no configuration error to return before
// it removes the enrolment.
func WithResetClock(clk clock.Clock) ResetOption {
	return func(c *resetConfig) {
		if !nilcheck.IsNil(clk) {
			c.clock = clk
		}
	}
}

// WithResetMessage replaces the default subject and body of the reset
// notification with what build returns for the instant of the reset.
//
// The default is "Your sign-in verification was reset", with a plain-text body
// that names the time of the reset, says the user will be asked to set up the
// second step again, and tells them to contact their administrator if they did
// not ask for it. It carries no code, secret, provisioning URI or user
// reference; a consumer's builder is given only the time, and whatever else it
// writes into the message is its own choice.
//
// The library still sets the recipient, from the contact resolver: a builder
// cannot address the message elsewhere. A nil builder is an ErrConfig,
// returned before anything is removed.
func WithResetMessage(build func(at time.Time) (subject, body string)) ResetOption {
	return func(c *resetConfig) {
		c.message, c.messageUnset = build, build == nil
	}
}

// The notification a reset sends. It names when the reset happened and
// nothing else about the account: no code, secret, provisioning URI or user
// reference.
const (
	resetSubject  = "Your sign-in verification was reset"
	resetBodyText = "The second sign-in step on your account was reset at %s.\n\n" +
		"You will be asked to set it up again the next time you sign in.\n" +
		"If you did not ask for this, contact your administrator at once.\n"
)

// defaultResetMessage is the message a reset sends unless WithResetMessage
// replaces it.
func defaultResetMessage(at time.Time) (subject, body string) {
	return resetSubject, fmt.Sprintf(resetBodyText, at.UTC().Format(time.RFC1123))
}

// ResetEnrolment resets user's second factors: an operator's action for a user
// who lost their authenticator, or whose authenticator is suspected to be in
// someone else's hands.
//
// In order, it:
//
//  1. removes the user's enrolment on every remover in ResetDeps.Enrolments,
//     in order;
//  2. deletes every session of the user, so a session that satisfied MFA with
//     the lost authenticator ends (default; WithoutSessionRevocation keeps
//     them);
//  3. notifies the user at the address the contact resolver gives, by default
//     the username (default; WithoutResetNotification turns it off).
//
// The removals come first and are never undone. A removal that fails stops the
// reset and is returned: the sessions are kept and no notification is sent,
// because telling the user their second factors were reset would be false
// while one remains; the removals already done stay done. Any failure after
// the removals — deleting sessions, loading the user, resolving the address or
// sending the message — is returned after them, never swallowed, and the steps
// after the failing one are not run. Either way the caller retries the reset,
// which removes an absent enrolment without error. The user's MFA requirement is
// untouched: with the enrolment path on, their next login enters the
// enrolment-only state, and with it off they are refused until enrolled out of
// band.
//
// A dependency's failure, the removal's included, comes back with fixed text
// of the package's own naming the step, never the dependency's text, which may
// quote the user's address. The dependency's error still matches through
// errors.Is and errors.As.
//
// Every dependency and option is checked before anything is written: an empty
// list of removers, an absent remover, a missing dependency that a step needs,
// or a nil WithResetMessage builder, is an ErrConfig and every enrolment stays
// in place.
//
// The sender is used as given: it need not be non-blocking. Unlike a sign-in
// flow, a reset is named by an operator, so its response time reveals nothing
// about which accounts exist; a sender that waits for delivery only makes the
// operator wait, and its failure is returned like any other.
//
// The library does not expose this over HTTP. A consumer puts it behind their
// own authorised administrative route.
func ResetEnrolment(ctx context.Context, user identity.UserID, deps ResetDeps, opts ...ResetOption) error {
	c := newResetConfig(opts)

	if err := deps.check(c); err != nil {
		return err
	}

	// A failed removal stops the reset: ending the sessions and telling the
	// user their second factors were reset would be false while one remains.
	// The removals already done stay done.
	for _, e := range deps.Enrolments {
		if err := e.RemoveEnrolment(ctx, user); err != nil {
			return diag.Wrap(err, "mfa: reset could not remove the enrolment")
		}
	}

	if c.revokeSessions {
		if err := deps.Sessions.DeleteByUser(ctx, user); err != nil {
			return diag.Wrap(err, "mfa: reset removed the enrolment but could not end the sessions")
		}
	}

	if !c.notify {
		return nil
	}

	return deps.notify(ctx, user, c.clock.Now(), c.message)
}

// check refuses a dependency a configured step needs and was not given.
func (d ResetDeps) check(c resetConfig) error {
	if len(d.Enrolments) == 0 {
		return fmt.Errorf("%w: reset requires at least one enrolment remover", ErrConfig)
	}

	for i, e := range d.Enrolments {
		if nilcheck.IsNil(e) {
			return fmt.Errorf("%w: reset enrolment remover %d is nil", ErrConfig, i)
		}
	}

	if c.revokeSessions && nilcheck.IsNil(d.Sessions) {
		return fmt.Errorf("%w: reset requires a session revoker, or WithoutSessionRevocation", ErrConfig)
	}

	if c.messageUnset {
		return fmt.Errorf("%w: reset message builder must not be nil", ErrConfig)
	}

	if c.notify && (nilcheck.IsNil(d.Sender) || nilcheck.IsNil(d.Users)) {
		return fmt.Errorf("%w: reset notification requires a sender and a user loader, "+
			"or WithoutResetNotification", ErrConfig)
	}

	return nil
}

// notify sends the reset notification to the user's contact address.
func (d ResetDeps) notify(
	ctx context.Context, user identity.UserID, at time.Time,
	message func(at time.Time) (subject, body string),
) error {
	details, err := d.Users.LoadByUserID(ctx, user)
	if err != nil {
		return diag.Wrap(err, "mfa: reset could not load the user to notify")
	}

	contact := d.Contact
	if contact == nil {
		contact = UsernameAsAddress
	}

	to, err := contact(ctx, details)
	if err != nil {
		return diag.Wrap(err, "mfa: reset could not resolve the address to notify")
	}

	subject, body := message(at)

	if err := d.Sender.Send(ctx, notify.Message{To: to, Subject: subject, TextBody: body}); err != nil {
		return diag.Wrap(err, "mfa: reset could not queue the notification")
	}

	return nil
}
