# Spec Delta

## RENAMED Requirements

- FROM: `### Requirement: Start is idempotent and construction starts nothing`
- TO: `### Requirement: Start launches the background work once, and construction starts nothing`

- FROM: `### Requirement: Stop leaves no goroutine behind`
- TO: `### Requirement: Shutdown leaves no goroutine behind`

## MODIFIED Requirements

### Requirement: Start launches the background work once, and construction starts nothing
Construction SHALL start no goroutine. Starting SHALL launch the rotation, reload and housekeeping background work. That work SHALL carry the values of the context given to start, but SHALL NOT end when that context is cancelled: only shutdown ends it. Starting a manager whose work is running SHALL fail with an already-started error and launch nothing. Starting a manager that has been shut down SHALL fail with an already-shut-down error and launch nothing.

#### Scenario: Constructed but not started
- **WHEN** a key manager is constructed and not started
- **THEN** no goroutine started by the key manager is running

#### Scenario: Double start
- **WHEN** a key manager is started twice and then shut down
- **THEN** the second start fails with the already-started error
- **AND** no goroutine started by the key manager remains after shutdown returns

#### Scenario: Cancelled start context
- **WHEN** a key manager is started with a context that is then cancelled, and its rotation interval passes
- **THEN** the rotation still runs

#### Scenario: Start after shutdown
- **WHEN** a key manager is shut down and then started
- **THEN** start fails with the already-shut-down error and launches no goroutine

### Requirement: Shutdown leaves no goroutine behind
Shutdown SHALL end the background work and SHALL be terminal. It SHALL wait for the work to end, including any in-flight key generation or store write, but no longer than the context given to it allows. It SHALL return no error once the work has ended, and that context's error if the context is done first. A later shutdown SHALL wait again under its own context. Shutting down a manager that was never started SHALL return at once. Shutdown SHALL end the background work only: a shut-down manager SHALL keep serving its current signers and verification keys, and SHALL rotate, reload and clean up no more. Concurrent start and shutdown SHALL be free of data races and SHALL leave no goroutine behind.

#### Scenario: Clean shutdown
- **WHEN** a key manager is started, its loops run several times, and it is shut down
- **THEN** shutdown returns no error and no goroutine started by the key manager is running

#### Scenario: Stop during rotation
- **WHEN** shutdown is called while a rotation is generating and storing a key
- **THEN** shutdown returns only after that store write has completed
- **AND** no store write happens after shutdown returns

#### Scenario: Consumer bounds the shutdown
- **WHEN** shutdown is called with a context that expires while a store write is still in flight
- **THEN** shutdown returns that context's error
- **AND** a later shutdown with a sufficient context returns no error once the write has completed

#### Scenario: Shutdown twice
- **WHEN** a started key manager is shut down twice
- **THEN** both calls return no error and no goroutine remains

#### Scenario: Keys served after shutdown
- **WHEN** a started key manager is shut down, and a token is then issued and verified with its keys
- **THEN** issuing and verifying succeed with the keys held at shutdown
- **AND** no rotation happens however much time passes

#### Scenario: Concurrent start and stop
- **WHEN** start and shutdown are called concurrently under the race detector
- **THEN** no data race is reported and no goroutine started by the key manager remains

#### Scenario: Stop before start
- **WHEN** a key manager that was never started is shut down and then started
- **THEN** shutdown returns at once, and start fails with the already-shut-down error and launches no goroutine
