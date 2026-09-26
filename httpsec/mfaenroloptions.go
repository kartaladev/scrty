package httpsec

import (
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/notify"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
)

// The paths the enrolment endpoints answer POST requests on when the consumer
// names none. They are constants rather than bare literals so a client, a test
// or a proxy rule naming the same endpoint names the same thing this package
// does.
const (
	// DefaultEnrolmentBeginPath begins, or begins again, a pending enrolment.
	DefaultEnrolmentBeginPath = "/mfa/enrol/begin"

	// DefaultEnrolmentConfirmPath proves the device with a code from it.
	DefaultEnrolmentConfirmPath = "/mfa/enrol/confirm"

	// DefaultEnrolmentEmailConfirmPath completes the enrolment with the code
	// emailed to the user once their device was proven.
	DefaultEnrolmentEmailConfirmPath = "/mfa/enrol/confirm-email"
)

// The limits the default in-memory enrolment limiters count against.
const (
	// Begins, every call counted: each one generates a secret and can lead to
	// an email, so this is what bounds the mail one user can be sent.
	defaultEnrolmentBeginLimit  = 5
	defaultEnrolmentBeginWindow = time.Hour

	// Failed confirmations, device codes and emailed codes alike.
	defaultEnrolmentConfirmLimit  = 5
	defaultEnrolmentConfirmWindow = 15 * time.Minute
)

// defaultEnrolmentLogInterval is the window the enrolment path's own records
// are sampled over.
const defaultEnrolmentLogInterval = time.Minute

// enrolmentEmailCodeTTL is how long an emailed enrolment code is accepted after
// the device proof that issued it: long enough to switch to a mailbox and read
// it, short enough that a code lying in an inbox soon stops being worth taking.
const enrolmentEmailCodeTTL = 10 * time.Minute

// EnrolmentDeps are the collaborators the enrolment path is wired to.
//
// The MFA method and the session manager are not among them: the method is the
// one EnableMFA was given, because the verify endpoint that completes the
// upgrade must verify the very factor that was enrolled, and the sessions are
// the chain's own.
type EnrolmentDeps struct {
	// Users loads the session user's details, which the label and contact
	// resolvers read. Required.
	Users identity.UserLoader

	// Sender delivers the emailed code and the notification. Required while
	// either is on, which is the default; it must not wait for delivery unless
	// WithEnrolmentSynchronousDelivery accepts one that does.
	Sender notify.Sender
}

// EnrolmentOption configures the enrolment path. Each replaces one of the
// defaults named on EnableMFAEnrolment.
type EnrolmentOption func(*enrolmentInterceptor) error

// EnableMFAEnrolment lets a user who must use a second factor, and has no
// usable enrolment, enrol one from a confined, short-lived session.
//
// It is one half of the path, and does nothing without the other: the MFA
// requirement policy must be built with policy.WithMFAEnrolmentPath, which is
// what raises the enrolment challenge that marks a session enrolment-only. Each
// half without the other is a configuration error from New. The path is off
// unless both are set, because it gives a password alone the power to begin
// binding a second factor.
//
// A session in the enrolment-pending state reaches only POST on the three
// enrolment paths and the chain's logout. Every other request — the verify
// endpoint, the password-change resolve endpoint, the authorizer, every
// consumer interceptor after OrderMFAEnrolment and the handler — is refused
// with a ChallengeError of kind policy.ChallengeMFAEnrolment carrying the
// session. There is no option to let further routes through. Consumer
// interceptors registered between the bearer slot and OrderMFAEnrolment do run
// for such a session, and see its principal.
//
// Defaults, each replaced by the option named:
//   - the endpoints answer POST on DefaultEnrolmentBeginPath,
//     DefaultEnrolmentConfirmPath and DefaultEnrolmentEmailConfirmPath
//     (WithEnrolmentBeginPath, WithEnrolmentConfirmPath,
//     WithEnrolmentEmailConfirmPath), and read only the "code" field of an
//     "application/x-www-form-urlencoded" POST body, never the URL query. This
//     is a limit, not a default: a body of any other type, multipart and JSON
//     included, one that does not parse, and one without the field are
//     refused with ErrCredentialsMissing (400), and are not counted as failed
//     confirmations;
//   - an enrolment-only session lives at most 15 minutes from the mark
//     (WithEnrolmentSessionTTL);
//   - begins are limited to 5 per hour per user, every call counted
//     (WithEnrolmentBeginLimiter), and failed confirmations to 5 per 15
//     minutes per user (WithEnrolmentConfirmLimiter), each by an in-memory
//     limiter of this path's own;
//   - a proven device completes only once a 6-digit code emailed to the user
//     is entered within 10 minutes (WithoutEmailConfirmation);
//   - the user is notified when an enrolment completes
//     (WithoutEnrolmentNotification);
//   - both messages are plain text from the library's renderer
//     (WithEnrolmentMessages), sent to the username as the address
//     (WithContactResolver), and the provisioning URI is labelled with the
//     username (WithLabelResolver);
//   - the sender must not wait for delivery
//     (WithEnrolmentSynchronousDelivery);
//   - every endpoint refusal is logged by a fixed reason, at most once per
//     reason per minute (WithEnrolmentLogInterval). A refusal a dependency
//     caused — the user loader, a resolver, the method's store, the session
//     manager, a limiter — also carries the error's Go type, never its own
//     text, which may quote the user's address or reference; a consumer who
//     wants that text logs it inside their own implementation of the
//     dependency. A refusal with no dependency behind it (a wrong code, an
//     enrolled user, the same channel twice) carries no type, since there is
//     no dependency error to name.
//
// The emailed code's bounds are fixed, not defaults: 6 digits, accepted for 10
// minutes after the device is proven, and for at most mfa.MaxEmailCodeFailures
// (5) attempts. Together they set the chance of guessing a code, which is the
// guarantee the path makes, and an option could only weaken it, so there is
// none; the one override is turning the step off with
// WithoutEmailConfirmation. The expiry the code message names is read from the
// chain's clock; the one that decides is the one the method stored. A sender
// that refuses to queue the code fails the confirm request, and the code is
// voided (mfa.VoidEmailCode), so that proof can never complete and the user
// begins again. The exception is a store that fails while voiding: the code
// then keeps the attempts it has left, until it expires or a begin replaces
// it, and the failure is logged by the fixed reason "not-voided" and the
// error's Go type, never the store's own text.
//
// The method enrolled is the one EnableMFA was given, which must implement
// mfa.Enroller over a store that implements mfa.DeviceProofStore. New refuses
// the chain when there is no EnableMFA, when its method cannot enrol, when its
// store cannot record a device proof, when there is no session manager, and
// when the lifetime is longer than that manager's absolute timeout.
//
// It must also be the method the MFA requirement policy looks up (the
// policy.MFAMethodLookup given to policy.NewMFARequirementPolicy), which New
// cannot check. If the two differ, the policy's same-channel test can admit a
// login to the path that begin then refuses as same-channel, and that user
// stays confined until the enrolment-only session ends.
func EnableMFAEnrolment(d EnrolmentDeps, opts ...EnrolmentOption) Option {
	const option = "EnableMFAEnrolment"

	return func(c *config) error {
		i := &enrolmentInterceptor{
			users:             d.Users,
			sender:            d.Sender,
			now:               time.Now,
			beginPath:         DefaultEnrolmentBeginPath,
			confirmPath:       DefaultEnrolmentConfirmPath,
			emailPath:         DefaultEnrolmentEmailConfirmPath,
			lifetime:          defaultEnrolmentLifetime,
			logInterval:       defaultEnrolmentLogInterval,
			emailConfirmation: true,
			notification:      true,
			contact:           mfa.UsernameAsAddress,
			label:             mfa.UsernameAsAddress,
			messages:          plainEnrolmentMessages{},
		}

		for _, opt := range opts {
			if opt == nil {
				continue
			}
			if err := opt(i); err != nil {
				return err
			}
		}

		if err := eachInterceptor(c, func(*enrolmentInterceptor) error {
			return newConfigError("%s was given twice; one chain has one enrolment path", option)
		}); err != nil {
			return err
		}

		c.enable(option, func() error { return i.check(option) })

		c.enrolmentLifetime = i.lifetime

		c.register(i, OrderMFAEnrolment)
		c.enableGate(policy.ChallengeMFAEnrolment)
		c.wire(i.wire)

		return nil
	}
}

// WithEnrolmentBeginPath answers begins on path instead.
//
// Default: DefaultEnrolmentBeginPath. Only POST on that exact path begins an
// enrolment. An empty path is refused, and so is one another enrolment
// endpoint or logout answers on: whichever matched first would swallow the
// other.
func WithEnrolmentBeginPath(path string) EnrolmentOption {
	return func(i *enrolmentInterceptor) error {
		if path == "" {
			return newConfigError("WithEnrolmentBeginPath was given no path, so an " +
				"enrolment-only session could never begin an enrolment")
		}

		i.beginPath = path

		return nil
	}
}

// WithEnrolmentConfirmPath answers device proofs on path instead.
//
// Default: DefaultEnrolmentConfirmPath. The same rules as
// WithEnrolmentBeginPath apply.
func WithEnrolmentConfirmPath(path string) EnrolmentOption {
	return func(i *enrolmentInterceptor) error {
		if path == "" {
			return newConfigError("WithEnrolmentConfirmPath was given no path, so an " +
				"enrolment-only session could never prove its device")
		}

		i.confirmPath = path

		return nil
	}
}

// WithEnrolmentEmailConfirmPath answers emailed codes on path instead.
//
// Default: DefaultEnrolmentEmailConfirmPath. The same rules as
// WithEnrolmentBeginPath apply. With WithoutEmailConfirmation the endpoint does
// not exist, and a request to path is refused like any other route.
func WithEnrolmentEmailConfirmPath(path string) EnrolmentOption {
	return func(i *enrolmentInterceptor) error {
		if path == "" {
			return newConfigError("WithEnrolmentEmailConfirmPath was given no path, so an " +
				"emailed code could never be entered")
		}

		i.emailPath = path

		return nil
	}
}

// WithEnrolmentSessionTTL lets an enrolment-only session live at most d from
// the moment it is marked.
//
// Default: 15 minutes, long enough to install an authenticator app and read an
// email, short enough that a token for a session that reaches nothing but
// enrolment is worth little. The session's own absolute deadline is lowered to
// it, so every session store enforces it with no knowledge of enrolment; a
// successful verification gives the normal deadline back.
//
// A lifetime of zero or less is refused here, and one longer than the session
// manager's absolute timeout is refused by New: the first would end every
// enrolment-only session at once, and the second could not be what was meant,
// since the lowered deadline never rises above the one the session already
// has.
//
// # Stated limit
//
// An enrolment-only session is a session like any other to a
// policy.ConcurrentSessionPolicy: it counts against the same cap, so whoever
// holds a password can occupy a required user's cap slots by beginning
// enrolments that are never confirmed. Each occupied slot lasts at most d, so
// the exposure is bounded, but not removed, by this option.
//
// The enrolment endpoints answer the request themselves, so the step that
// touches a session's idle deadline does not run for an enrolment-only
// session. With a session manager whose idle timeout is shorter than d, a user
// who is actively enrolling can still idle out mid-enrolment, and must log in
// again; keep d within the idle timeout, or accept that.
func WithEnrolmentSessionTTL(d time.Duration) EnrolmentOption {
	return func(i *enrolmentInterceptor) error {
		if d <= 0 {
			return newConfigError("WithEnrolmentSessionTTL was given %s; an enrolment-only "+
				"session needs a lifetime greater than zero", d)
		}

		i.lifetime = d

		return nil
	}
}

// WithEnrolmentBeginLimiter counts begins through l, keyed by
// EnrolmentBeginThrottleKey.
//
// Default: an in-memory limiter of 5 per hour, per replica. Unlike every other
// limiter the library wires, it counts every call rather than only failures:
// each begin generates a secret and can lead to an email, so a count of
// failures would not bound either. The trade-off is stated: whoever holds a
// user's password can spend that user's begin budget, locking them out of the
// path for an hour. A limiter that cannot decide refuses the begin.
//
// A nil limiter, including an interface holding a nil pointer, is refused: it
// would read as "no limit" while the consumer believed they had replaced one.
func WithEnrolmentBeginLimiter(l ratelimit.Limiter) EnrolmentOption {
	return func(i *enrolmentInterceptor) error {
		if err := requireDep("WithEnrolmentBeginLimiter", "limiter", l); err != nil {
			return err
		}

		i.beginLimiter = l

		return nil
	}
}

// WithEnrolmentConfirmLimiter counts failed confirmations through l, keyed by
// EnrolmentConfirmThrottleKey.
//
// Default: an in-memory limiter of 5 failures per 15 minutes, per replica. It
// counts wrong device codes and wrong emailed codes, and is separate from the
// verification throttle of EnableMFA, so failing to enrol never locks a user
// out of verifying an enrolment they already have. A failure is recorded even
// when the caller has gone away, and a limiter that cannot decide refuses the
// confirmation.
//
// A nil limiter, including an interface holding a nil pointer, is refused.
func WithEnrolmentConfirmLimiter(l ratelimit.Limiter) EnrolmentOption {
	return func(i *enrolmentInterceptor) error {
		if err := requireDep("WithEnrolmentConfirmLimiter", "limiter", l); err != nil {
			return err
		}

		i.confirmLimiter = l

		return nil
	}
}

// WithoutEmailConfirmation completes an enrolment as soon as its device is
// proven, replacing the default of requiring a code emailed to the user as
// well.
//
// What it gives up: the emailed code is what makes the mailbox owner take part
// in every binding. Without it, whoever holds the password alone binds a
// second factor of their choosing, and the notification — if it is still on —
// is the only signal the account's owner gets.
//
// What the default does not give: after a magic-link login, or a federated one
// admitted by the path's allowlist, the first factor already proved control of
// the mailbox (a provider account usually includes it), so the emailed code
// adds no assurance there. The step still runs; this is stated rather than
// skipped silently.
//
// Turning the step off is the only control over it. Its bounds — 6 digits, 10
// minutes after the device is proven, 5 attempts — are fixed and have no
// option, because each could only be loosened, and together they are the
// guessing bound the step exists to give.
func WithoutEmailConfirmation() EnrolmentOption {
	return func(i *enrolmentInterceptor) error {
		i.emailConfirmation = false

		return nil
	}
}

// WithoutEnrolmentNotification sends nothing when an enrolment completes,
// replacing the default of notifying the user at their contact address.
//
// What it gives up: nothing then tells the user a second factor was bound to
// their account, so a binding they did not make goes unnoticed until it is
// used against them.
func WithoutEnrolmentNotification() EnrolmentOption {
	return func(i *enrolmentInterceptor) error {
		i.notification = false

		return nil
	}
}

// WithEnrolmentSynchronousDelivery accepts a sender that waits for delivery.
//
// The default is to refuse one, as magic links do. A sender that waits puts the
// mail server into the enrolment endpoints' response time, and a slow or
// unreachable server then holds a request, and a limiter slot, for as long as
// it likes. Wrapping the sender in notify.NewQueuedSender, which declares
// itself non-blocking, needs no option here.
func WithEnrolmentSynchronousDelivery() EnrolmentOption {
	return func(i *enrolmentInterceptor) error {
		i.acceptSync = true

		return nil
	}
}

// WithContactResolver sends the emailed code and the notification to the
// address r returns for the session's user.
//
// Default: mfa.UsernameAsAddress, the username unchanged, which is the
// convention magic links already rely on. A consumer whose usernames are not
// addresses reads the address from their own records here. The address is
// never written to a log. A nil resolver is refused.
func WithContactResolver(r mfa.ContactResolver) EnrolmentOption {
	return func(i *enrolmentInterceptor) error {
		if r == nil {
			return newConfigError("WithContactResolver was given no resolver; omit the " +
				"option to keep the username as the address")
		}

		i.contact = r

		return nil
	}
}

// WithLabelResolver labels the provisioning URI with what r returns for the
// session's user. The label is never read from the request.
//
// Default: mfa.UsernameAsAddress. A username containing ':' is refused by the
// TOTP method as a label, and the begin then fails storing nothing; a
// deployment whose usernames may contain one supplies its own resolver. A nil
// resolver is refused.
func WithLabelResolver(r mfa.LabelResolver) EnrolmentOption {
	return func(i *enrolmentInterceptor) error {
		if r == nil {
			return newConfigError("WithLabelResolver was given no resolver; omit the " +
				"option to keep the username as the label")
		}

		i.label = r

		return nil
	}
}

// WithEnrolmentMessages renders the emailed code and the notification with r.
//
// Default: the library's own plain-text messages. The code message carries the
// code and when it stops being accepted; the notification names the method and
// the time, and carries no code, secret or provisioning URI. The library still
// sets the recipient, from the contact resolver, so a renderer cannot address
// a message elsewhere. A nil renderer is refused.
func WithEnrolmentMessages(r EnrolmentMessages) EnrolmentOption {
	return func(i *enrolmentInterceptor) error {
		if err := requireDep("WithEnrolmentMessages", "message renderer", r); err != nil {
			return err
		}

		i.messages = r

		return nil
	}
}

// WithEnrolmentLogInterval writes at most one record per enrolment refusal
// reason per d.
//
// Default: one minute. It governs the records the enrolment path writes — its
// endpoints' refusals, a limiter that cannot record, a notification that could
// not be sent — and nothing else: MFA verification records keep the window
// WithMFALogInterval sets, and the chain's own refusal records the one
// WithRefusalLogInterval sets. What a window holds back is written as one
// summary record, naming the reason and the count, when the reason goes quiet.
//
// An interval of zero or less writes every record, which is the documented way
// to ask for the full stream: it is a choice about volume, not a fault. No
// record, sampled or not, carries a code, a secret, a provisioning URI, an
// address or the user reference.
func WithEnrolmentLogInterval(d time.Duration) EnrolmentOption {
	return func(i *enrolmentInterceptor) error {
		i.logInterval = d

		return nil
	}
}
