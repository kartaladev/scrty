## MODIFIED Requirements

### Requirement: Accounts lock after repeated failures
The account lockout policy SHALL run in the pre-authentication phase.
- It SHALL deny with an account-locked reason while the submitted identifier owes a wait or has reached the ceiling, as the escalating-wait and ceiling requirements state, counting failures recorded strictly within the window before now.
- Failures SHALL be recorded, and cleared after a successful authentication, through the attempt store.
- If the attempt store fails, the policy SHALL deny with a reason wrapping the store's error.
- The defaults SHALL be a threshold of 5, a window of 24 hours, a first wait of 30 seconds, a longest wait of 1 hour, a ceiling of 100 and an in-memory attempt store, each replaceable by an option.
- Construction SHALL fail with a configuration error for a threshold, window or first wait of zero or less, a longest wait shorter than the first, or a ceiling not above the threshold.

#### Scenario: At the threshold
- **WHEN** five failures for `ada` were recorded in the last 24 hours, the newest 10 seconds ago
- **THEN** pre-authentication for `ada` is denied as locked

#### Scenario: Reset on success
- **WHEN** four failures for `ada` were recorded, then cleared after a successful authentication, and one more failure is recorded
- **THEN** pre-authentication for `ada` is allowed

#### Scenario: Store failure
- **WHEN** the attempt store returns an error while counting
- **THEN** pre-authentication is denied with a reason wrapping that error

#### Scenario: Consumer threshold
- **WHEN** the policy is configured with a threshold of 3, and three failures for `ada` were recorded in the window, the newest 10 seconds ago
- **THEN** pre-authentication for `ada` is denied as locked

#### Scenario: Zero window
- **WHEN** a lockout policy is constructed with a zero window
- **THEN** construction fails with a configuration error

#### Scenario: Ceiling not above the threshold
- **WHEN** a lockout policy is constructed with a threshold of 5 and a ceiling of 5
- **THEN** construction fails with a configuration error

## ADDED Requirements

### Requirement: A locked account waits, and the wait escalates
By default, once an identifier has at least the threshold number of failures in the window, the policy SHALL deny it while its newest failure is more recent than the wait it owes. The wait SHALL be the first wait doubled once for each failure beyond the threshold, and SHALL NOT exceed the longest wait. Once the wait has passed, the next attempt SHALL be allowed.

#### Scenario: First wait
- **WHEN** five failures for `ada` were recorded, the newest 29 seconds ago
- **THEN** pre-authentication for `ada` is denied as locked

#### Scenario: First wait served
- **WHEN** five failures for `ada` were recorded, the newest 31 seconds ago
- **THEN** pre-authentication for `ada` is allowed

#### Scenario: Doubled wait
- **WHEN** seven failures for `ada` were recorded, the newest 100 seconds ago
- **THEN** pre-authentication for `ada` is denied as locked, because the wait owed is 120 seconds

#### Scenario: Longest wait
- **WHEN** twenty failures for `ada` were recorded in the last 24 hours, the newest 61 minutes ago
- **THEN** pre-authentication for `ada` is allowed

### Requirement: An account at the ceiling is refused until its failures age out
By default, an identifier with at least the ceiling number of failures in the window SHALL be denied with an account-locked reason however long ago its newest failure was, until enough failures leave the window or a successful authentication clears them.

#### Scenario: One hundred failures
- **WHEN** one hundred failures for `ada` were recorded in the last 24 hours, the newest 2 hours ago
- **THEN** pre-authentication for `ada` is denied as locked

#### Scenario: Consumer ceiling
- **WHEN** the policy is configured with a ceiling of 20, and twenty failures for `ada` were recorded in the window, the newest 2 hours ago
- **THEN** pre-authentication for `ada` is denied as locked

### Requirement: A fixed lock is available as an option
A consumer SHALL be able to choose a fixed lock in place of the escalating wait, with its own threshold and window: an identifier with at least that threshold of failures in that window SHALL be denied however long ago its newest failure was. Configuring the fixed lock together with any threshold, window, wait or ceiling option SHALL be a configuration error.

#### Scenario: Fixed lock
- **WHEN** the policy is configured with a fixed lock of 5 failures in 15 minutes, and five failures for `ada` were recorded, the newest 10 minutes ago
- **THEN** pre-authentication for `ada` is denied as locked

#### Scenario: Fixed lock with a wait option
- **WHEN** the policy is configured with a fixed lock and a first wait
- **THEN** construction fails with a configuration error

### Requirement: An account-locked refusal states the wait it owes
An account-locked reason SHALL be identifiable as the account-locked refusal, and SHALL carry the wait the identifier owes when that is known: the full escalated wait, which is an upper bound on what remains. At the ceiling and under a fixed lock it SHALL carry no wait.

#### Scenario: Wait carried
- **WHEN** pre-authentication for `ada` is denied with seven failures recorded
- **THEN** the reason is the account-locked refusal and carries a wait of 120 seconds

#### Scenario: Ceiling carries none
- **WHEN** pre-authentication for `ada` is denied at the ceiling
- **THEN** the reason is the account-locked refusal and carries no wait
