// Package mfa lets a user prove a second factor after the first.
//
// A Method is one way of proving it. The package ships one, TOTP: RFC 6238
// time-based codes from an authenticator app, with an enrolment store behind
// it. A consumer implements Method themselves for anything else — an emailed
// one-time code, a hardware token — and every component here that takes a
// method takes theirs on the same terms.
//
// # The channel
//
// Every method declares the channel its codes travel over, using factor's
// vocabulary rather than one of this package's own. The channel is what makes a
// second factor second: a code that arrives the way the first factor did proves
// nothing the first factor had not already proved, so a method whose channel
// matches the login's is not a second factor at all. A method that reports no
// channel is refused at construction rather than at verification, because an
// empty channel equals the channel of an unrecorded first factor and the
// symptom would appear far from the cause.
//
// # A lost enrolment must never downgrade a user
//
// The requirement to use a second factor lives with the user, in identity's
// requirement lookup, and nothing in this package can clear it. RemoveEnrolment
// deletes an enrolment record and no more.
//
// That split only holds if an enrolment that cannot be read is reported as an
// error. A method returns false from Enrolled only when its store definitively
// holds no confirmed enrolment; a store outage, or a secret that will not open,
// is an error. A caller reads false as "this user has no second factor" and
// completes the login on its first factor, so answering false on a failure
// would silently downgrade exactly the users who had enrolled — the one outcome
// this capability exists to prevent.
//
// # What is guarded
//
// A code is accepted at most once per user per time step, decided by the
// store's conditional write rather than by a read the caller trusts, so
// concurrent verifications of one code yield one success. Failed verifications
// are throttled per user reference: by the time a second factor is being
// checked the attacker already holds the first, so the user is the resource
// under attack, not the address the guesses arrive from.
//
// That choice has a price, and it is a real one. An attacker who holds a
// user's password can spend the failures on purpose and lock that user out of
// MFA verification for the rest of the window — five failures wide and fifteen
// minutes long by default. It is accepted because the alternative counts an
// address the attacker changes at will, which stops nobody. Both halves are
// replaceable: WithVerifyLimiter takes a limiter of the consumer's own, with
// its own count and window, and VerifyThrottleKey names the bucket so an
// administrative unlock can clear it.
//
// No record written here carries a presented code, an enrolment secret or a
// provisioning URI.
//
// # The enrolment path
//
// Enroller is what a method offers to be enrolled from a confined session:
// begin on a new generation, prove the device, and complete — by default only
// after a code emailed to the user's contact address has proven the mailbox.
// Each step after the begin names the begin's generation, and the store decides
// it by a conditional write on DeviceProofStore, so a proof made against one
// provisioned secret can never confirm another. An emailed code is charged an
// attempt before it is compared, so however many requests race, no more than
// MaxEmailCodeFailures presented codes are ever compared against one. TOTP
// implements Enroller; MemoryEnrolmentStore implements DeviceProofStore.
// ContactResolver and LabelResolver default to UsernameAsAddress.
//
// ResetEnrolment is the operator's reset: remove the enrolment, end the user's
// sessions, notify them — each of the last two on by default, off only by an
// explicit option.
//
// # Defaults and ports
//
// Every default has an option that replaces it, and every option names the
// default it replaces. TOTPOption covers the built-in method: six digits, a
// thirty-second step, time.Now and crypto/rand. ThrottleOption covers the
// throttle: the in-memory limiter above, a one-minute log-sampling window and
// slog.Default.
//
// Two things have no default the library can supply. EnrolmentStore is the one
// a method cannot invent, so NewTOTP takes it as an argument;
// NewMemoryEnrolmentStore is what a test or a single process passes, and it
// keeps enrolments in this process only. Method itself has no default beyond
// TOTP: a Method describes one way of proving a factor, and which one a
// deployment uses is the consumer's to name.
package mfa
