## MODIFIED Requirements

### Requirement: Delivery failures are reported by default
The built-in senders SHALL write their failure records to the consumer's logger when one is configured. Otherwise they SHALL write them to the logger of the chain that handled the request which queued or sent the message, when that chain was configured with a logger, and otherwise to the application's own default logger as it stands when the record is written. A dropped queued message, a failed delivery, a recovered panic and a delivery whose goroutine ended SHALL all be reported this way.

A dropped message is a sign-in link that never arrives, and the caller has already been told the send succeeded, so a default that discarded these records would make the failure invisible at both ends. A consumer who wants them silenced SHALL be able to supply a discarding logger explicitly. A nil logger SHALL fail the sender's construction.

#### Scenario: A dropped message is reported without configuration
- **WHEN** a queued sender with no logger configured drops a message because its queue is full, outside any chain
- **THEN** a record of the drop is written to the default logger

#### Scenario: An ended goroutine is reported without configuration
- **WHEN** a queued sender with no logger configured wraps a sender that ends its goroutine while delivering, outside any chain
- **THEN** a record of the lost delivery is written to the default logger

#### Scenario: The queuing request's chain receives the record
- **WHEN** a queued sender with no logger configured drops a message queued during a request handled by a chain configured with the consumer's logger
- **THEN** the record of the drop is written to the chain's logger and not to the default logger

#### Scenario: Silence is available but must be asked for
- **WHEN** a consumer supplies a discarding logger
- **THEN** no record is written
