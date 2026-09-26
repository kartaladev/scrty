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
The SMTP sender SHALL send the plain-text body as UTF-8 with CRLF line endings. It SHALL encode a subject containing non-ASCII characters so that it arrives unchanged. It SHALL add no header naming scrty or any product.

#### Scenario: Non-ASCII subject
- **WHEN** a message with subject `Masuk ke akun Anda — tautan` is delivered to a test SMTP server
- **THEN** the received message's decoded subject is exactly `Masuk ke akun Anda — tautan`

#### Scenario: Bare line feeds normalised
- **WHEN** a message whose body contains `line one\nline two` is delivered
- **THEN** the received body separates the lines with CRLF

#### Scenario: No product header
- **WHEN** any message is delivered through the SMTP sender
- **THEN** no received header value contains `scrty`

### Requirement: SMTP wiring mistakes fail at construction
Constructing the SMTP sender SHALL fail with a configuration error when no server host is given, when the port is outside 1 to 65535, or when the deadline is zero or less. The default port SHALL be 587. A message that names no sender address SHALL use the configured default sender address. A message with neither SHALL fail to send with an error, before any network activity.

#### Scenario: Missing host
- **WHEN** an SMTP sender is constructed without a host
- **THEN** construction fails with a configuration error

#### Scenario: Zero deadline
- **WHEN** an SMTP sender is constructed with a deadline of zero
- **THEN** construction fails with a configuration error

#### Scenario: Message overrides the default sender address
- **WHEN** a sender configured with default sender address `no-reply@example.com` sends a message whose sender address is `support@example.com`
- **THEN** the delivered message's sender is `support@example.com`

#### Scenario: No sender address anywhere
- **WHEN** a sender with no default sender address sends a message that names none
- **THEN** sending fails with an error
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
- log delivery failures and recover from a panic in the wrapped sender without stopping the worker;
- after closing, refuse new messages with a closed error;
- on close, deliver messages already queued, waiting no longer than the closing context allows.

The defaults SHALL be 2 workers, a queue of 256 messages and a 30-second send timeout, each replaceable by an option. Construction SHALL fail with a configuration error for an absent wrapped sender, or a worker count, queue size or send timeout of zero or less.

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
- **WHEN** three messages are queued and the sender is closed with a context that allows 10 seconds
- **THEN** close returns after all three are delivered
- **AND** a later send returns the closed error

#### Scenario: Wrapped sender panics
- **WHEN** the wrapped sender panics while delivering one message and a second message is then queued
- **THEN** the second message is delivered

#### Scenario: Consumer sizing
- **WHEN** a queued sender is configured with 8 workers
- **THEN** up to 8 deliveries run at the same time

#### Scenario: Zero workers
- **WHEN** a queued sender is constructed with zero workers
- **THEN** construction fails with a configuration error

### Requirement: Send logs carry no message body and no recipient
Logs written by the built-in senders SHALL NOT contain the message body, the recipient address, or the text of a delivery failure, which a mail server's reply routinely quotes the recipient in. A failure record SHALL name the stage that failed and the error's type, as the diagnostic-redaction capability requires.

#### Scenario: Failed delivery of a sign-in link
- **WHEN** delivery of a message whose body contains a sign-in link fails
- **THEN** no written log record contains the link

#### Scenario: Recipient rejected
- **WHEN** an SMTP server rejects the recipient with `550 5.1.1 <alice@example.com>: Recipient address rejected`
- **THEN** no written log record contains `alice@example.com`

### Requirement: Delivery failures are reported by default
The built-in senders SHALL write their failure records to the application's own default logger unless the consumer supplies another. A dropped queued message, a failed delivery and a recovered panic SHALL all be reported this way.

A dropped message is a sign-in link that never arrives, and the caller has already been told the send succeeded, so a default that discarded these records would make the failure invisible at both ends. A consumer who wants them silenced SHALL be able to supply a discarding logger explicitly.

#### Scenario: A dropped message is reported without configuration
- **WHEN** a queued sender with no logger configured drops a message because its queue is full
- **THEN** a record of the drop is written to the default logger

#### Scenario: Silence is available but must be asked for
- **WHEN** a consumer supplies a discarding logger
- **THEN** no record is written
