# Spec Delta

## MODIFIED Requirements

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
