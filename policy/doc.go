// Package policy holds the rules a deployment applies around authentication,
// as opposed to the decision of who the caller is.
//
// An Engine evaluates the policies registered for one phase of a request and
// reduces what they return to a single decision: a denial outranks a
// challenge, and a challenge outranks an allow, so no policy's allow can
// overrule another policy's refusal. A phase with nothing registered allows.
// Each policy declares the phases it runs in and is asked in no other, so a
// rule written for the moment of login does not quietly start running on every
// request. The engine also tells each policy which phase it is being asked in,
// through the context, so a rule that answers differently at login and on a
// later request can tell the two apart without the consumer wiring anything.
//
// A denial always carries a reason, substituted by the engine where a policy
// left none. A caller that reports that reason as its own error returns nil for
// a reasonless denial and lets through the very request it was refusing;
// closing that in the engine closes it for every policy at once, rather than
// asking each one to remember.
//
// The policies that ship here lock an account after repeated login failures,
// end idle sessions, challenge a password that is overdue for a change, cap how
// many sessions one user may hold at once, and challenge or refuse a login
// whose second factor is enrolled or required. Each names its own options, so a
// threshold, a window or a log interval governs one policy and never two. The
// store the lockout policy counts failures in is a port, with an in-memory
// implementation as its default.
//
// # A store that fails
//
// When a store or lookup the consumer supplies cannot answer, the policy
// denies, and the denial's reason carries fixed text of this package's own,
// never the store's error text: that text is written by code the library does
// not know and can quote values it never saw. The policy's sentinel, where it
// has one, and the store's error both stay reachable through errors.Is and
// errors.As, so matching and the status a caller maps the reason to are
// unchanged. The records a policy writes about such a failure carry a fixed
// reason and the error's Go type, never its text. A consumer who wants the
// store's full error logs it inside their own implementation of the port.
//
// The second-factor policies' records name the user, by the opaque reference
// identity.UserID the consumer supplied, on purpose: an operator needs to know
// whose login was refused or challenged, and the reference is the consumer's
// own identifier rather than an address or a name.
package policy
