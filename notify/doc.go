// Package notify sends the email scrty's own flows need.
//
// Sender is the port. Every library component that sends email depends on it
// and on nothing else, so a consumer who already has a transactional-email API
// client wires that in and none of the built-in transports run at all.
//
// Two senders come with the package. SMTPSender speaks SMTP submission: it
// refuses a recipient, sender or subject carrying a line break before it
// touches the network, fixes one absolute deadline covering the dial and the
// whole exchange, requires STARTTLS unless the consumer opts out, encodes a
// non-ASCII subject so it arrives unchanged, and adds no header naming this
// library or any product. QueuedSender wraps any other sender and hands each
// message to a small pool of workers, so a flow's response time does not
// depend on a mail server — which is what keeps a magic-link request from
// taking measurably longer for an address that has an account than for one
// that does not. It reports NonBlocking, and SMTPSender deliberately does not.
//
// Every default here is replaceable and every option names the default it
// replaces: the port itself through the Sender a component is given, and
// within each built-in sender its port, its credentials, its timeout and its
// logger, through SMTPOption and QueuedOption. Sender has no default of its
// own — a component that sends email is handed one, because a library that
// chose a mail server would be choosing where a consumer's sign-in links go.
//
// # What each bounds, and what neither does
//
// SMTPSender bounds time: no send outlives its deadline, and there is no
// option that removes it. QueuedSender bounds memory and concurrency: a fixed
// queue and a fixed number of workers, so a burst drops messages rather than
// growing without limit, and a dropped message is logged and reported, never
// silently lost.
//
// QueuedSender's bound on one delivery reaches only as far as the sender it
// wraps allows. It works by cancelling the context that sender was handed, so
// it bounds a sender that honours cancellation mid-transfer, as SMTPSender
// does. A sender that ignores its context runs for as long as it likes: Go
// offers no way to stop a goroutine from outside, so a few such sends occupy
// every worker indefinitely and the queue behind them fills and then drops.
// The bound is a contract with the inner sender, not a guarantee over it.
//
// Neither bounds durability: messages live in memory only, and a crash, or a
// shutdown that skips Close or gives its drain too little time, loses whatever
// is still queued — silently, because the send already returned nil. A
// consumer who needs delivery to survive that supplies a Sender backed by a
// durable queue.
//
// No log record written here carries a message body or subject: the body of a
// sign-in message is a live credential.
package notify
