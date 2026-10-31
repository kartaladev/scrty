# Spec Delta

## MODIFIED Requirements

### Requirement: The scheduled sweeper starts and stops cleanly
Starting the scheduled sweeper twice SHALL fail with an already-started error. Starting it after shutdown SHALL fail with an already-shut-down error. Scheduled runs SHALL carry the values of the context given to start, but SHALL NOT be cancelled when that context is: only shutdown ends them. Shutdown SHALL stop scheduling, cancel the context of any run in progress, and wait for it to return, but no longer than the context given to shutdown allows, returning an error wrapping that context's error if it is done first. The wait SHALL also be bounded by the sweeper's stop timeout, which defaults to 10 seconds and is replaceable by an option; a purge that outlasts it SHALL make shutdown return an error saying so. The sweeper SHALL be shut down once, and every shutdown call, concurrent or later, SHALL return that one shutdown's result once it is known. Shutdown SHALL be idempotent and SHALL release every goroutine the sweeper owns, whether or not it was started. A start that fails partway SHALL leave the sweeper shut down, not partially scheduled.

#### Scenario: Built and never started
- **WHEN** a sweeper is built and then shut down without being started
- **THEN** no goroutine owned by the sweeper remains

#### Scenario: Shutdown stops runs
- **WHEN** a started sweeper is shut down and several intervals pass
- **THEN** no task runs after shutdown returned

#### Scenario: Restart refused
- **WHEN** a sweeper that was shut down is started again
- **THEN** start fails with the already-shut-down error

#### Scenario: Cancelled start context
- **WHEN** a sweeper is started with a request context that is then cancelled, and a task's interval passes
- **THEN** the task still runs, and its purge receives a context that is not cancelled

#### Scenario: Shutdown cancels a running purge
- **WHEN** a started sweeper is shut down while a task's purge is running
- **THEN** that purge's context is cancelled, and shutdown returns after the purge returns

#### Scenario: Consumer bounds the shutdown
- **WHEN** a started sweeper is shut down with a context that expires while a purge ignores its cancellation and keeps running
- **THEN** shutdown returns an error wrapping that context's error

#### Scenario: Purge outlasts the stop timeout
- **WHEN** a started sweeper with a 1-second stop timeout is shut down while a purge ignores its cancellation for longer than that, and is then shut down again
- **THEN** both calls return the error saying a running purge outlasted the stop timeout
