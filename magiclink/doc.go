// Package magiclink signs a user in by a single-use link sent to their email
// address.
//
// Two things shape the whole package.
//
// Requesting a link tells the caller nothing. Request returns no error, and
// every branch — an unknown address, a disabled user, an outage in the user
// store, a reached issuance limit, a failed token write, a failed send, and a
// link that went out — returns the same result. A caller that cannot see which
// branch it took cannot leak it to the client, and so cannot be used to
// enumerate which addresses have accounts. Each cause is logged server-side.
// The same reasoning refuses a sender that waits for delivery: response time
// would reveal what the result does not, so NewManager requires a sender that
// declares it does not block, unless the consumer accepts the channel
// explicitly with WithSynchronousDelivery.
//
// Redeeming a link checks everything before it spends anything. Redemption
// runs on the one-time-token capability's check-then-consume ordering, with
// account resolution placed inside it as the first refusal check: the token is
// checked, the user is loaded by the reference the link records, the
// consumer's own checks run, and only then is the token consumed, atomically.
// A refusal or a failure at any earlier step leaves the link redeemable until
// it expires, so a policy that denies today costs the holder nothing tomorrow,
// and of several racing redemptions of one link at most one succeeds.
//
// A link authenticates only the user it was minted for. The token's subject is
// the user reference, redemption loads by that reference, and a miss, a
// disabled user or an identifier that does not match is refused. A username or
// address later given to somebody else therefore cannot inherit a live link.
//
// Every refusal is the same error, ErrInvalidLink, and no error and no log
// record written here carries the token, the binding value or the submitted
// address.
//
// # What the uniform result does not close
//
// Timing. Every branch of Request returns the same thing, but the branches do
// not cost the same: an address that resolves goes on to read the user store
// and write a token, and one that resolves to nothing stops earlier. A small
// difference in response time therefore remains, and an attacker patient
// enough to measure it can still learn which addresses have accounts.
//
// The non-blocking sender removes the largest part of that difference — the
// delivery, which is a network round trip to a mail server and dwarfs
// everything else — but it does not remove the store work. The rest is stated
// here rather than closed, because closing it means answering on a fixed
// schedule, and a fixed schedule slow enough to cover a store outage makes
// every honest request that slow too.
//
// # Defaults and ports
//
// Every default has an option that replaces it, and every option names the
// default it replaces: the confirm path, the issuance limit, the renderer, the
// address resolver, same-device binding, the random source and the logger.
//
// Four things are arguments rather than options, because the library cannot
// invent them: the one-time-token manager, which also owns a link's lifetime
// and issuance window; the user loader; the sender, which must declare itself
// non-blocking unless WithSynchronousDelivery accepts one that does not; and
// the link base URL. AddressResolver has a default — the submitted address is
// passed to the user loader as a username, exactly as submitted — and Renderer
// has one too. Check has none and needs none: a redemption with no consumer
// checks runs none, and the library adds no policy of its own beyond resolving
// the account.
package magiclink
