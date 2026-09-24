package notify

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Message is one email. Every field is the consumer's content: the library
// stores and sends it unchanged, and interprets none of it.
//
// TextBody is plain text. There is no HTML body and no template system: the
// messages the library itself sends carry a link and a sentence, and anything
// richer is the consumer's renderer's business.
type Message struct {
	// To is the recipient address. A flow that knows the address it was asked
	// about forces this field, so a renderer cannot redirect a sign-in link.
	To string

	// From is the sender address. Empty means the sender's configured default
	// is used; a sender with no default refuses a message that names none.
	From string

	// Subject is the subject header, encoded by the sender when it is not
	// ASCII.
	Subject string

	// TextBody is the plain-text body, normalised to CRLF by the sender.
	TextBody string
}

// Sender delivers a Message.
//
// This is the port every library component that sends email depends on. A
// consumer's own implementation — a transactional-email API client, a queue, a
// test double — receives every message such a component would have sent,
// unchanged, and the built-in SMTP sender is then not used at all.
//
// There is no default. A component that sends email takes a Sender as an
// argument rather than inventing one, because a library that picked a mail
// server on its own would be picking where a consumer's sign-in links go.
// NewSMTPSender and NewQueuedSender are what a consumer with nothing else
// reaches for.
//
// An implementation is expected to be safe for concurrent use.
type Sender interface {
	Send(ctx context.Context, msg Message) error
}

// NonBlocking is implemented by senders whose Send returns without waiting for
// delivery.
//
// A flow whose response time would otherwise reveal whether an address has an
// account asks for this before it will use a sender. Reporting true is a
// promise: Send must not wait on the network. QueuedSender reports true;
// SMTPSender does not implement this interface at all.
type NonBlocking interface {
	NonBlocking() bool
}

var (
	// ErrUnsafeHeaderValue refuses a message whose recipient, sender or
	// subject contains a carriage return or line feed, before anything is
	// sent. The value is never stripped or escaped instead: escaping changes
	// the caller's content silently, and header folding is easy to get subtly
	// wrong.
	ErrUnsafeHeaderValue = errors.New("notify: header value contains a line break")

	// ErrQueueFull reports that a queued sender dropped a message because its
	// queue was full. It never blocks waiting for space.
	ErrQueueFull = errors.New("notify: send queue is full")

	// ErrSenderClosed refuses a send to a sender that has been closed.
	ErrSenderClosed = errors.New("notify: sender is closed")
)

// ErrConfig is wrapped by every error a constructor in this package returns
// for a wiring mistake, so a consumer can tell a contradictory configuration
// from a failure at send time without matching on message text.
var ErrConfig = errors.New("notify: invalid configuration")

// refuseUnsafeHeaders rejects a message whose header fields could inject
// headers of their own.
//
// Only the fields that become headers are checked. The body is data: a line
// break in it is content, and it is normalised to CRLF rather than refused.
func refuseUnsafeHeaders(msg Message) error {
	for _, f := range []struct {
		name  string
		value string
	}{
		{"recipient", msg.To},
		{"sender", msg.From},
		{"subject", msg.Subject},
	} {
		// The error names the field but never quotes the value: the value is
		// attacker-supplied, and it goes into whatever records the caller's
		// error.
		if strings.ContainsAny(f.value, "\r\n") {
			return fmt.Errorf("%w: %s", ErrUnsafeHeaderValue, f.name)
		}
	}

	return nil
}
