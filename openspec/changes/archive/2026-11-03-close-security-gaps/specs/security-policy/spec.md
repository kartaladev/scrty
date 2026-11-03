## ADDED Requirements

### Requirement: A failure recorded without a time is recorded at the policy's clock
When a failed attempt is recorded through the lockout policy's attempts view with the zero time, the view SHALL record it at the policy's current time, with or without a failure-streak limit, so that it counts in the window as any other failure does and a lock it causes is reported. A caller that forgets the time SHALL never leave an identifier unlocked that the same failures recorded with the time would lock. A failure recorded with a time SHALL be recorded at that time, unchanged.

#### Scenario: Zero-time failures lock
- **WHEN** a lockout policy with a threshold of 3 and no failure-streak limit records three failures for `ada` through its attempts view, each with the zero time
- **THEN** pre-authentication for `ada` is denied as locked

#### Scenario: Lock reported on the failure that locks
- **WHEN** a security-event sink watches, `ada` has three failures recorded two hours ago under a 15-minute window and a 48-hour retention, and three more failures are recorded with the zero time
- **THEN** the lock events are reported once, on the third zero-time failure, carrying the policy's current time

#### Scenario: Under a failure-streak limit
- **WHEN** the same three zero-time failures are recorded under a failure-streak limit
- **THEN** pre-authentication for `ada` is denied as locked, as without the limit

#### Scenario: A given time is kept
- **WHEN** a failure is recorded with a time ten minutes ago
- **THEN** it is counted at that time, not at the policy's current time
