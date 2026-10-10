## MODIFIED Requirements

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

#### Scenario: A hold survives every sweep
- **WHEN** with a cap configured and the default 30-day retention, `ada` became held 90 days ago, and the login-attempt task runs
- **THEN** `ada` is still held

#### Scenario: A recent consecutive count survives
- **WHEN** with a cap configured and the default 30-day retention, `ada` has a consecutive count of ten with its newest failure 29 days ago, and the login-attempt task runs
- **THEN** the consecutive count for `ada` is still ten

#### Scenario: An inactive consecutive count is deleted
- **WHEN** with a cap configured and the default 30-day retention, `ada` has a consecutive count of ten with its newest failure 31 days ago, and the login-attempt task runs
- **THEN** the count for `ada` is deleted, and the next failure for `ada` starts a count of one, as it would have without the sweep
