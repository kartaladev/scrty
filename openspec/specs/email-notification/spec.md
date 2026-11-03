# email-notification Specification

## Purpose

Delivers the email messages scrty's flows send, such as sign-in links, through a transport the consumer can replace. The default SMTP transport is bounded in time, refuses header injection and requires encryption by default, and a queued sender keeps delivery out of the caller's response time.

## Requirements

### Requirement: Sending is a replaceable port
Every library component that sends email SHALL depend only on the sending port. A consumer-supplied implementation SHALL receive every message such a component sends, unchanged, and the built-in SMTP sender SHALL then not be used.

#### Scenario: Consumer transport
- **WHEN** the magic-link flow is configured with a consumer's sender that posts to a transactional-email API
- **THEN** that sender receives the sign-in message
- **AND** no SMTP connection is attempted

### Requirement: Header values that could inject headers are refused
A message SHALL carry a recipient address, a sender address, a subject and a plain-text body. The SMTP sender SHALL refuse, before any network activity, a message whose recipient, sender or subject contains a carriage return or line feed. The refusal SHALL be an error identifiable as an unsafe header value, and nothing SHALL be sent. The value SHALL NOT be stripped or escaped instead.

#### Scenario: Line feed in the subject
- **WHEN** a message with subject `Hello\r\nBcc: attacker@example.com` is sent through the SMTP sender
- **THEN** sending fails with the unsafe-header-value error
- **AND** no connection to the SMTP server is made

#### Scenario: Line feed in the recipient
- **WHEN** a message with recipient `a@example.com\nBcc: b@example.com` is sent
- **THEN** sending fails with the unsafe-header-value error

### Requirement: Message content is encoded faithfully
The SMTP sender SHALL send the plain-text body as UTF-8 with CRLF line endings. A bare carriage return, a bare line feed and a CRLF in the body SHALL each become one CRLF, so no bare carriage return reaches the transfer. It SHALL encode a subject containing non-ASCII characters so that it arrives unchanged. It SHALL add no header naming scrty or any product.

#### Scenario: Non-ASCII subject
- **WHEN** a message with subject `Masuk ke akun Anda — tautan` is delivered to a test SMTP server
- **THEN** the received message's decoded subject is exactly `Masuk ke akun Anda — tautan`

#### Scenario: Bare line feeds normalised
- **WHEN** a message whose body contains `line one\nline two` is delivered
- **THEN** the received body separates the lines with CRLF

#### Scenario: No product header
- **WHEN** any message is delivered through the SMTP sender
- **THEN** no received header value contains `scrty`

#### Scenario: Bare carriage returns normalised
- **WHEN** a message whose body contains `hello\r.\r\nMAIL FROM` is delivered
- **THEN** the transfer carries no bare carriage return, and the body's lines are separated by CRLF with the leading dot escaped

### Requirement: SMTP wiring mistakes fail at construction
Constructing the SMTP sender SHALL fail with a configuration error when no server host is given, when the port is outside 1 to 65535, or when the deadline is zero or less. The default port SHALL be 587. A message that names no sender address SHALL use the configured default sender address. A message with neither SHALL fail to send, before any network activity, with an error identifiable as a configuration error, since neither the consumer's wiring nor the message names a sender.

#### Scenario: Missing host
- **WHEN** an SMTP sender is constructed without a host
- **THEN** construction fails with a configuration error

#### Scenario: Zero deadline
- **WHEN** an SMTP sender is constructed with a deadline of zero
- **THEN** construction fails with a configuration error

#### Scenario: Message overrides the default sender address
- **WHEN** a sender configured with default sender address `no-reply@example.com` sends a message whose sender address is `support@example.com`
- **THEN** the delivered message's sender is `support@example.com`

#### Scenario: Message names a sender and no default exists
- **WHEN** a sender with no default sender address sends a message whose sender address is `support@example.com`
- **THEN** the message is delivered with that sender, and no configuration error is returned

#### Scenario: Default sender address used
- **WHEN** a sender configured with default `no-reply@example.com` sends a message that names none
- **THEN** the delivered message's sender is `no-reply@example.com`

#### Scenario: No sender address anywhere
- **WHEN** a sender with no default sender address sends a message that names none
- **THEN** sending fails with an error identifiable as a configuration error
- **AND** no connection is made

### Requirement: One deadline bounds the whole send
The SMTP sender SHALL fix one absolute deadline before dialling, covering the dial and the whole exchange from the server's greeting through the end of the session. The deadline SHALL be the configured duration from the start of the send, or the caller's context deadline when that is earlier. Cancelling the caller's context SHALL abort a send in progress, including mid-transfer. A context already ended SHALL fail the send before any network activity. The default duration SHALL be 30 seconds, replaceable by an option. There SHALL be no way to disable the bound.

#### Scenario: Server that never greets
- **WHEN** a sender with a 2-second deadline sends to a server that accepts the connection and never replies
- **THEN** the send fails with a timeout within about 2 seconds

#### Scenario: Slow dial does not extend the bound
- **WHEN** a sender with a 2-second deadline sends to an address whose connection completes after 1.5 seconds and whose server then never replies
- **THEN** the send fails within about 2 seconds of starting, not 2 seconds after connecting

#### Scenario: Earlier context deadline wins
- **WHEN** a sender with the default 30-second deadline sends with a context whose deadline is 1 second away, to a server that never replies
- **THEN** the send fails within about 1 second

#### Scenario: Cancellation mid-transfer
- **WHEN** the caller's context is cancelled while the server is waiting to greet
- **THEN** the send returns promptly with an error

### Requirement: SMTP connections are encrypted by default
By default, the SMTP sender SHALL require the server to offer STARTTLS, and SHALL upgrade before authenticating or sending any message data. It SHALL verify the server certificate against the configured host. When the server does not offer STARTTLS, or the upgrade fails, the send SHALL fail and SHALL NOT continue in plaintext.

A consumer SHALL be able to choose opportunistic encryption instead. The sender then upgrades when the server offers STARTTLS and otherwise continues in plaintext. Credentials SHALL NOT be sent over an unencrypted connection except to a loopback host.

#### Scenario: Server without STARTTLS
- **WHEN** a sender with default options sends to a server that does not offer STARTTLS
- **THEN** the send fails
- **AND** no message data is sent

#### Scenario: Consumer chooses opportunistic encryption for a local relay
- **WHEN** a sender is configured for opportunistic encryption and sends to a local test server that does not offer STARTTLS
- **THEN** the message is delivered

#### Scenario: Server offers STARTTLS but cannot speak TLS
- **WHEN** a sender sends to a server that offers STARTTLS but fails the handshake
- **THEN** the send fails

### Requirement: A queued sender returns without waiting for delivery
The library SHALL provide a sender that wraps any other sender, queues each message for a bounded pool of workers, and returns as soon as the message is queued. It SHALL declare itself non-blocking to components that ask. It SHALL:
- keep the caller's context values but not its cancellation, and bound each delivery by its own send timeout;
- when the queue is full, drop the message, log an error and return a queue-full error, never waiting for space;
- log delivery failures, recover from a panic in the wrapped sender, and replace a worker whose wrapped sender ends its goroutine, so the pool neither shrinks below nor grows past its configured size, and no failed message is delivered again;
- after shutdown, refuse new messages with a shut-down error. A message sent while shutdown begins SHALL either be queued and delivered by the drain, or be refused with the shut-down error; it SHALL never be accepted and then dropped;
- on shutdown, deliver messages already queued, waiting no longer than the context given to shutdown allows, and return that context's error if the drain has not finished by then.

Shutdown SHALL be terminal and idempotent: a later shutdown SHALL return no error once the drain has finished. The defaults SHALL be 2 workers, a queue of 256 messages and a 30-second send timeout, each replaceable by an option. Construction SHALL fail with a configuration error for an absent wrapped sender, or a worker count, queue size or send timeout of zero or less.

#### Scenario: Returns before a slow delivery
- **WHEN** a message is sent through a queued sender wrapping a sender that takes 5 seconds
- **THEN** the send returns within 50 milliseconds

#### Scenario: Request ends after queuing
- **WHEN** a message is queued and the caller's context is cancelled immediately after
- **THEN** the wrapped sender still delivers the message

#### Scenario: Full queue
- **WHEN** a queued sender with a queue of 1 and one busy worker receives two further messages
- **THEN** the second of them returns the queue-full error without blocking

#### Scenario: Close drains
- **WHEN** three messages are queued and the sender is shut down with a context that allows 10 seconds
- **THEN** shutdown returns no error after all three are delivered
- **AND** a later send returns the shut-down error

#### Scenario: Shutdown bounded by its context
- **WHEN** a message is queued for a wrapped sender that takes 5 seconds and the sender is shut down with a context that allows 1 second
- **THEN** shutdown returns that context's error after about 1 second

#### Scenario: Shutdown twice
- **WHEN** a queued sender that has finished draining is shut down again
- **THEN** the second shutdown returns no error

#### Scenario: Sends racing shutdown
- **WHEN** many messages are sent concurrently while the sender is shut down with a context that allows the drain to finish
- **THEN** every send either returned no error and its message was delivered, or returned the shut-down error
- **AND** no send panics

#### Scenario: Wrapped sender panics
- **WHEN** the wrapped sender panics while delivering one message and a second message is then queued
- **THEN** the second message is delivered

#### Scenario: Wrapped sender ends its goroutine
- **WHEN** a queued sender with one worker wraps a sender that ends its goroutine while delivering the first message, and a second message is then queued
- **THEN** the second message is delivered
- **AND** the failed delivery of the first message is logged

#### Scenario: Several workers end their goroutines
- **WHEN** a queued sender with two workers wraps a sender that ends its goroutine while delivering each of the first two messages, and a third message is then queued
- **THEN** the third message is delivered
- **AND** shutdown drains and returns no error, and no worker goroutine is left running

#### Scenario: Only worker ends its goroutine during the drain
- **WHEN** a one-worker sender holds three queued messages, shutdown begins with a sufficient context, and the wrapped sender ends its goroutine on the first
- **THEN** the other two are delivered, shutdown returns no error, and no worker goroutine remains

#### Scenario: Goroutine ended after shutdown gave up
- **WHEN** shutdown has returned its context's error, and the delivery still under way then ends its goroutine with a message still queued
- **THEN** the queued message is delivered, a later shutdown returns no error, and no worker goroutine remains

#### Scenario: A blocking log handler does not shrink the pool
- **WHEN** a one-worker sender's log handler blocks while recording an ended goroutine, and another message is queued
- **THEN** that message is delivered

#### Scenario: Pool does not grow
- **WHEN** a sender with two workers has seen one delivery panic and one end its goroutine
- **THEN** no more than two deliveries run at once, and neither failed message is delivered again

#### Scenario: An idle worker holds no delivered message
- **WHEN** a message whose body contains a sign-in link has been delivered and its worker is idle
- **THEN** the sender no longer keeps that message reachable

#### Scenario: Consumer sizing
- **WHEN** a queued sender is configured with 8 workers
- **THEN** up to 8 deliveries run at the same time

#### Scenario: Zero workers
- **WHEN** a queued sender is constructed with zero workers
- **THEN** construction fails with a configuration error

### Requirement: Send logs carry no message body and no recipient
Logs written by the built-in senders SHALL NOT contain the message body, the recipient address, or the text of a delivery failure, which a mail server's reply routinely quotes the recipient in. A failure record SHALL name the stage that failed and the error's type, as the diagnostic-redaction capability requires. A delivery whose goroutine ended has no error to name, so its record SHALL carry a fixed reason instead.

#### Scenario: Failed delivery of a sign-in link
- **WHEN** delivery of a message whose body contains a sign-in link fails
- **THEN** no written log record contains the link

#### Scenario: Recipient rejected
- **WHEN** an SMTP server rejects the recipient with `550 5.1.1 <alice@example.com>: Recipient address rejected`
- **THEN** no written log record contains `alice@example.com`

#### Scenario: Ended goroutine's record carries nothing from the sender
- **WHEN** a wrapped sender ends its goroutine while delivering a message whose body contains a sign-in link
- **THEN** one record is written with the fixed reason `goexit`
- **AND** it contains no body, subject or recipient

### Requirement: Delivery failures are reported by default
The built-in senders SHALL write their failure records to the application's own default logger unless the consumer supplies another. A dropped queued message, a failed delivery, a recovered panic and a delivery whose goroutine ended SHALL all be reported this way.

A dropped message is a sign-in link that never arrives, and the caller has already been told the send succeeded, so a default that discarded these records would make the failure invisible at both ends. A consumer who wants them silenced SHALL be able to supply a discarding logger explicitly.

#### Scenario: A dropped message is reported without configuration
- **WHEN** a queued sender with no logger configured drops a message because its queue is full
- **THEN** a record of the drop is written to the default logger

#### Scenario: An ended goroutine is reported without configuration
- **WHEN** a queued sender with no logger configured wraps a sender that ends its goroutine while delivering
- **THEN** a record of the lost delivery is written to the default logger

#### Scenario: Silence is available but must be asked for
- **WHEN** a consumer supplies a discarding logger
- **THEN** no record is written

### Requirement: Passkey notices are sent through the sending port
The passkey component SHALL send every notice it owes through the library's sending port, never through a channel of its own: the binding notice, the removal notice, the suspected-clone notice and the emailed confirmation code. It SHALL require a sender that declares itself non-blocking, such as the queued sender, unless the consumer explicitly accepts synchronous delivery. A notice the sender refuses to queue SHALL be logged without its body or recipient. Only the emailed confirmation code SHALL fail its request when it cannot be queued, because the user cannot complete the step without it. Every other notice's failure SHALL leave the operation that caused it standing.

#### Scenario: Queued notice
- **WHEN** a passkey is suspended as a suspected clone, with a queued sender wrapping a slow SMTP sender
- **THEN** the login refusal returns without waiting for delivery, and the notice is delivered

#### Scenario: Refused notice is logged without its content
- **WHEN** the queue is full when a binding notice is sent to `ana@example.com`
- **THEN** an error record is written that contains neither the notice's body nor `ana@example.com`
- **AND** the passkey stays active
