## Purpose

Bounds the growth of expiring security state by deleting it through the purge operations of the components that own it, with failures isolated per task. It works the same whether it runs manually or on a schedule, and it can never free rate-limit or lockout quota.

## ADDED Requirements

### Requirement: Expired security state is deleted through its owners
The system SHALL provide an expiry task for each of the following, and each task SHALL delete only what its owning component's purge operation deems deletable:
- expired sessions;
- magic-link tokens that are past both their expiry and their issuance window;
- one-time tokens of any other single purpose, on the same rule;
- login attempts older than the lockout window;
- idle keys held by the in-memory rate limiter;
- expired OIDC flows;
- spent or expired OIDC handoffs;
- expired one-time state the library keeps on its own behalf: passkey ceremony challenges, MFA challenges, and account-recovery issued codes and hold tokens, each through the component that owns it.

API keys, OIDC links, MFA enrolments, passkey credentials (pending or active), account-recovery records, signing keys and identity records SHALL NOT be deleted by any expiry task. Each built-in task SHALL carry a stable default name that is used in logs, results and lock keys, and SHALL leave its scheduling interval unset.

#### Scenario: Expired and live sessions
- **WHEN** two expired sessions and one valid session exist and the session task runs
- **THEN** the two expired sessions are deleted
- **AND** the valid session remains

#### Scenario: Separate purposes stay separate
- **WHEN** one-time tokens of purposes `magic-link` and `email-change` are both past expiry and their windows, and only the `email-change` task runs
- **THEN** only the `email-change` tokens are deleted

#### Scenario: Durable records untouched
- **WHEN** every expiry task runs against stores holding an API key past its optional expiry, an OIDC link, an MFA enrolment and a signing key
- **THEN** none of them is deleted

#### Scenario: Unauthenticated ceremony state is swept
- **WHEN** strangers made passwordless passkey begins whose challenges have expired and passed their issuance window, and the passkey component's tasks run
- **THEN** those challenges are deleted
- **AND** a challenge issued within its window is kept

#### Scenario: Only enabled components contribute tasks
- **WHEN** a chain enables MFA with the TOTP method and does not enable account recovery
- **THEN** the chain's expiry tasks include the TOTP challenge task and no recovery task

#### Scenario: Consumer task for their own state
- **WHEN** a consumer adds a task with their own name and purge operation for a table they own
- **THEN** the runner runs it with the same isolation and reporting as the built-in tasks

#### Scenario: Consumer renames a built-in task
- **WHEN** a consumer schedules two in-memory rate limiters and renames one task `ratelimit:apikey`
- **THEN** both tasks run and are reported under their own names

### Requirement: A sweep never frees rate-limit or lockout quota
No expiry task and no runner or scheduler setting SHALL accept a retention window or cutoff. Each built-in task SHALL derive its cutoff from the owning component's own configured window. Running any task SHALL NOT change a count that a rate limiter, an issuance limit or an account lockout uses for a decision. When the owning component's store cannot purge, the task SHALL fail with a purge-unsupported error that is recognisable in the same way for every task, and SHALL NOT report zero removed.

#### Scenario: Expired token still counted for issuance
- **WHEN** with a 15-minute token lifetime and a 1-hour issuance window, a magic-link token for subject `carol` was issued 30 minutes ago, and the magic-link task runs
- **THEN** the token is not deleted
- **AND** the issued count for `carol` is the same before and after the run

#### Scenario: Recent login failures survive
- **WHEN** with a 15-minute lockout window, failures for `ada` were recorded 5 and 20 minutes ago, and the login-attempt task runs
- **THEN** only the 20-minute-old failure is deleted
- **AND** the failure count for `ada` within the window is unchanged

#### Scenario: Consumer-configured window is respected
- **WHEN** a consumer configures the lockout window as 1 hour, a failure for `ada` was recorded 30 minutes ago, and the login-attempt task runs
- **THEN** the failure is not deleted

#### Scenario: Store without purge support
- **WHEN** the lockout policy uses a consumer's attempt store that cannot purge, and the login-attempt task runs
- **THEN** the task's result carries the purge-unsupported error, matched by the same check as for any other task
- **AND** the result is not reported as a successful run that removed zero

### Requirement: One task's failure does not affect other tasks
A task that returns an error or panics SHALL have that failure recorded in its result and logged. The remaining tasks in the same run SHALL still run, and the process SHALL NOT crash. A recovered panic SHALL be reported as a task-panicked error that includes the panic value.

#### Scenario: Failing task among healthy ones
- **WHEN** a run has tasks `a`, `b` and `c`, and `b` returns a database error
- **THEN** `a` and `c` run and report their removed counts
- **AND** `b`'s result carries the database error

#### Scenario: Panicking task
- **WHEN** task `b` panics with the value `nil store`
- **THEN** `b`'s result carries the task-panicked error with `nil store` in its message
- **AND** `c` still runs

### Requirement: Runs honour cancellation and deadlines
A run SHALL check its context before each task. When the context is done, no further task SHALL start, and every task not reached SHALL be reported as skipped with the context's error. By default a task run SHALL have no deadline beyond the caller's context. A consumer SHALL be able to bound each task run with a timeout. A run SHALL NOT leave any goroutine running after it returns.

#### Scenario: Cancelled between tasks
- **WHEN** the caller's context is cancelled while task `a` is running in a run of `a`, `b` and `c`
- **THEN** after `a` returns, `b` and `c` are reported as skipped with the cancellation error

#### Scenario: Consumer run timeout
- **WHEN** a consumer configures a run timeout of 30 seconds
- **THEN** each task's purge receives a context whose deadline is at most 30 seconds after that task started

#### Scenario: No goroutine left behind
- **WHEN** a run completes, including runs with failing, panicking and cancelled tasks
- **THEN** no goroutine started by the run is still running

### Requirement: Sweeps can run manually
The runner SHALL run every task once, in the order they were given, and SHALL run a single task by name. A manual run of all tasks SHALL return a report with one result per task, together with an error combining every task failure, so that a caller can exit non-zero. Running an unknown task name SHALL fail with an unknown-task error. A task that is already running in the same runner SHALL be skipped with a task-busy result, not queued.

#### Scenario: Consumer's own scheduler
- **WHEN** a consumer's scheduled job calls a manual run of all tasks and one task fails
- **THEN** the report holds a result for every task and the returned error matches that task's failure

#### Scenario: Unknown task
- **WHEN** a manual run is requested for the task name `nope`
- **THEN** it fails with the unknown-task error and no task runs

#### Scenario: Overlapping runs of one task
- **WHEN** the session task is running and a second run of the session task is requested in the same runner
- **THEN** the second request returns a skipped result with the task-busy error
- **AND** the first run is unaffected

### Requirement: Sweeps can run on a schedule
The scheduled sweeper SHALL run each task on the task's own interval, or on the sweeper's default interval when the task has none. The sweeper SHALL have no default interval of its own, and a task left with no interval SHALL fail construction. By default the first run of each task SHALL wait one interval, and an option SHALL make each task run once at start. A tick that arrives while the same task is still running SHALL be skipped, not queued. An optional distributed lock SHALL be consulted with a key derived from the task name before each run. Without a lock, every process SHALL sweep independently.

#### Scenario: Consumer default interval
- **WHEN** the sweeper is built with a default interval of 10 minutes, it starts, and 10 minutes pass
- **THEN** each task without its own interval has run once

#### Scenario: Task interval
- **WHEN** the `login-attempts` task has a 1-minute interval, the sweeper's default is 10 minutes, and 3 minutes pass
- **THEN** the `login-attempts` task has run three times and every other task has not run

#### Scenario: No interval anywhere
- **WHEN** a sweeper is built with no default interval over a task with no interval
- **THEN** construction fails with the no-interval error naming the task

#### Scenario: No boot-time sweep by default
- **WHEN** the sweeper starts with default options
- **THEN** no task runs before the first interval has passed

#### Scenario: Consumer asks for a boot-time sweep
- **WHEN** the sweeper starts with run-at-start enabled
- **THEN** every task runs once at start

#### Scenario: Slow run skips ticks
- **WHEN** a task's run takes longer than two of its intervals and then completes
- **THEN** exactly one run of that task has happened, with no queued runs firing back to back afterwards

#### Scenario: Distributed lock consulted
- **WHEN** the sweeper is configured with a distributed lock and the session task's interval passes
- **THEN** the lock is requested with a key naming the session task before the task runs

### Requirement: Each run is reported
Each task run SHALL produce a result carrying the task name, the number removed, whether it was skipped, its error, and its elapsed time measured with the runner's clock. By default a successful run SHALL be logged at debug level with its count, and a failed run at error level. A consumer-supplied observer SHALL receive every result, synchronously and after the log record, for manual and scheduled runs alike.

#### Scenario: Observer sees counts
- **WHEN** a consumer registers an observer and the session task removes 3 records
- **THEN** the observer receives a result named `sessions` with 3 removed and no error

#### Scenario: Default logging
- **WHEN** no observer is registered and a task fails
- **THEN** an error-level log record names the task and the error

### Requirement: Wiring mistakes fail at construction
Construction of the runner SHALL fail with a configuration error when any of the following holds:
- there are no tasks;
- a task has an empty name, no purge operation or a negative interval;
- two tasks share a name;
- the run timeout is negative.

#### Scenario: Empty runner
- **WHEN** a runner is built with no tasks
- **THEN** construction fails, because a runner with no tasks would appear to work while reclaiming nothing

#### Scenario: Duplicate names
- **WHEN** a runner is built with two tasks named `sessions`
- **THEN** construction fails naming `sessions`

#### Scenario: Missing purge operation
- **WHEN** a runner is built with a task named `audit` that has no purge operation
- **THEN** construction fails naming `audit`

### Requirement: The scheduled sweeper starts and stops cleanly
Starting the scheduled sweeper twice SHALL fail with an already-started error. Starting it after shutdown SHALL fail with an already-shut-down error. Shutdown SHALL be idempotent and SHALL release every goroutine the sweeper owns, whether or not it was started. A start that fails partway SHALL leave the sweeper shut down, not partially scheduled.

#### Scenario: Built and never started
- **WHEN** a sweeper is built and then shut down without being started
- **THEN** no goroutine owned by the sweeper remains

#### Scenario: Shutdown stops runs
- **WHEN** a started sweeper is shut down and several intervals pass
- **THEN** no task runs after shutdown returned

#### Scenario: Restart refused
- **WHEN** a sweeper that was shut down is started again
- **THEN** start fails with the already-shut-down error
