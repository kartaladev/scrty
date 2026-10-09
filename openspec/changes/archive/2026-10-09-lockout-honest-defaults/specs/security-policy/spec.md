## MODIFIED Requirements

### Requirement: An account at the ceiling is refused until its failures age out
By default, an identifier with at least the ceiling number of failures in the window SHALL be denied with an account-locked reason however long ago its newest failure was, until enough failures leave the window or a successful authentication clears them. The ceiling SHALL count only failures in the window. The documentation SHALL state that the ceiling limits failures per window, not consecutive failures in total, and that it does not disable the authenticator until it is bound again.

#### Scenario: One hundred failures
- **WHEN** one hundred failures for `ada` were recorded in the last 24 hours, the newest 2 hours ago
- **THEN** pre-authentication for `ada` is denied as locked

#### Scenario: Consumer ceiling
- **WHEN** the policy is configured with a ceiling of 20, and twenty failures for `ada` were recorded in the window, the newest 2 hours ago
- **THEN** pre-authentication for `ada` is denied as locked

#### Scenario: Failures outside the window do not count toward the ceiling
- **WHEN** twenty-four failures for `ada` were recorded on each of the last five days, none cleared, and the newest 2 hours ago
- **THEN** pre-authentication for `ada` is allowed, although more than one hundred failures were recorded in total

### Requirement: An account-locked refusal states the wait it owes
An account-locked reason SHALL be identifiable as the account-locked refusal, and SHALL carry the wait the identifier owes when that is known: the full escalated wait, which is an upper bound on what remains. At the ceiling and under a sliding lock it SHALL carry no wait.

#### Scenario: Wait carried
- **WHEN** pre-authentication for `ada` is denied with seven failures recorded
- **THEN** the reason is the account-locked refusal and carries a wait of 120 seconds

#### Scenario: Ceiling carries none
- **WHEN** pre-authentication for `ada` is denied at the ceiling
- **THEN** the reason is the account-locked refusal and carries no wait

#### Scenario: Sliding lock carries none
- **WHEN** pre-authentication for `ada` is denied under a sliding lock
- **THEN** the reason is the account-locked refusal and carries no wait

## ADDED Requirements

### Requirement: A sliding lock is available as an option
A consumer SHALL be able to choose a sliding lock in place of the escalating wait, with its own threshold and window: an identifier SHALL be denied while at least that threshold of failures falls in that window, whenever its newest failure was. Combining it with any threshold, window, wait or ceiling option SHALL be a configuration error. The documentation SHALL state that it limits the failure rate and holds no lock of fixed duration.

#### Scenario: Sliding lock
- **WHEN** the policy is configured with a sliding lock of 5 failures in 15 minutes, and five failures for `ada` were recorded, the newest 10 minutes ago
- **THEN** pre-authentication for `ada` is denied as locked

#### Scenario: Sliding lock lifts when the oldest failure leaves the window
- **WHEN** the policy is configured with a sliding lock of 5 failures in 15 minutes, and five failures for `ada` were recorded 15 minutes 1 second, 14, 10, 5 and 1 minute ago
- **THEN** pre-authentication for `ada` is allowed

#### Scenario: Sliding lock with a wait option
- **WHEN** the policy is configured with a sliding lock and a first wait
- **THEN** construction fails with a configuration error

### Requirement: A lock of fixed duration is an escalating wait that does not escalate
When the first and longest waits are equal, an identifier with at least the threshold of failures in the window SHALL be denied for exactly that wait after its newest failure, and allowed from the instant the wait has passed. Each further failure while the count stays at or above the threshold SHALL lock it again for the same wait. The documentation SHALL present this as the way to configure a lock of fixed duration.

#### Scenario: Locked for the whole duration
- **WHEN** the policy is configured with a first and longest wait of 15 minutes, and five failures for `ada` were recorded, the newest 14 minutes 59 seconds ago
- **THEN** pre-authentication for `ada` is denied as locked, and the reason carries a wait of 15 minutes

#### Scenario: Allowed when the duration has passed
- **WHEN** the policy is configured with a first and longest wait of 15 minutes, and five failures for `ada` were recorded, the newest exactly 15 minutes ago
- **THEN** pre-authentication for `ada` is allowed

#### Scenario: A further failure locks again for the full duration
- **WHEN** the policy is configured with a first and longest wait of 15 minutes, and six failures for `ada` were recorded in the window, the newest 14 minutes ago
- **THEN** pre-authentication for `ada` is denied as locked, and the reason carries a wait of 15 minutes

### Requirement: Lockout transitions can be observed
By default, the lockout policy SHALL report nothing. A consumer SHALL be able to supply an observer, told of every recorded failure that leaves its identifier locked (owing a wait, at the ceiling, or under the sliding lock) and of every clearing of an identifier that had failures in the window. Each report SHALL carry the identifier as submitted, the kind, the failure count and the time. The observer SHALL NOT be able to change any decision or error.

#### Scenario: No observer by default
- **WHEN** a policy built with no observer records a fifth failure for `ada`
- **THEN** the failure is recorded and nothing else is reported

#### Scenario: Threshold reached
- **WHEN** the consumer supplies an observer, and four failures then a fifth for `ada` are recorded within the window
- **THEN** the observer is told nothing for the first four, and is told that `ada` is locked with five failures at the time of the fifth

#### Scenario: Each further locking failure is reported
- **WHEN** the consumer supplies an observer, `ada` has five failures in the window, and a sixth is recorded
- **THEN** the observer is told that `ada` is locked with six failures

#### Scenario: Ceiling reached
- **WHEN** the consumer supplies an observer, and a hundredth failure for `ada` is recorded within the window
- **THEN** the observer is told that `ada` is at the ceiling with one hundred failures

#### Scenario: Cleared
- **WHEN** the consumer supplies an observer, `ada` has three failures in the window, and its failures are cleared
- **THEN** the observer is told that `ada` was cleared

#### Scenario: Clearing nothing is not reported
- **WHEN** the consumer supplies an observer, `ada` has no failures in the window, and its failures are cleared
- **THEN** the observer is told nothing

#### Scenario: Unknown and known identifiers are reported alike
- **WHEN** the consumer supplies an observer, and five failures are recorded for `ada`, which has an account, and five for `nobody`, which does not
- **THEN** the observer is told that each is locked, in the same form

## REMOVED Requirements

### Requirement: A fixed lock is available as an option
**Reason**: The option never held a lock of fixed duration: it refuses while the threshold of failures falls in the window, and lifts as soon as the oldest leaves it. It is replaced by the sliding lock, which is the same behaviour under a name that says what it does. A lock of fixed duration is the escalating wait with equal first and longest waits.
**Migration**: Use the sliding lock option with the same threshold and window. For a lock of fixed duration, set the first and longest waits to that duration instead.
