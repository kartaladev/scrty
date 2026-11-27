## ADDED Requirements

### Requirement: A consumer's bus may refuse an envelope when it is raised
When a consumer's bus implements the optional check, the chain SHALL ask it before queueing an envelope and SHALL return its error, so that a signal the bus can never carry is refused to the caller.

#### Scenario: A bus that refuses
- **WHEN** a consumer's bus refuses an `app.*` signal through its check
- **THEN** `PublishSignal` returns that error, and nothing is queued or counted as dropped

#### Scenario: An end report
- **WHEN** a bus refuses an end report's envelope through its check
- **THEN** the end's outcome is unchanged, and the heartbeat ends the streams

#### Scenario: A bus with no check
- **WHEN** a consumer's bus does not implement the check
- **THEN** the chain queues as before
