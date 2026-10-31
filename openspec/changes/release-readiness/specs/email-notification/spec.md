# Spec Delta

## MODIFIED Requirements

### Requirement: A queued sender returns without waiting for delivery
The library SHALL provide a sender that wraps any other sender, queues each message for a bounded pool of workers, and returns as soon as the message is queued. It SHALL declare itself non-blocking to components that ask. It SHALL:
- keep the caller's context values but not its cancellation, and bound each delivery by its own send timeout;
- when the queue is full, drop the message, log an error and return a queue-full error, never waiting for space;
- log delivery failures, recover from a panic in the wrapped sender, and replace a worker whose wrapped sender ends its goroutine, so the pool never shrinks below its configured size;
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

#### Scenario: Consumer sizing
- **WHEN** a queued sender is configured with 8 workers
- **THEN** up to 8 deliveries run at the same time

#### Scenario: Zero workers
- **WHEN** a queued sender is constructed with zero workers
- **THEN** construction fails with a configuration error
