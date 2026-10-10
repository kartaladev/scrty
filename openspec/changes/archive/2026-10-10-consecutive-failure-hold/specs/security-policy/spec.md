## ADDED Requirements

### Requirement: An opt-in cap holds an identifier after consecutive failures
By default the lockout policy SHALL have no cap. A consumer SHALL be able to set a cap. Once the failures recorded for an identifier since it was last cleared reach the cap, whatever their age, the identifier SHALL be held: every pre-authentication for it SHALL be denied as locked, however long ago its newest failure was. A named constant SHALL give NIST's limit of 100. The documentation SHALL state that a cap above 100 is outside that limit.

#### Scenario: No cap by default
- **WHEN** a policy with default options has recorded twenty failures for `ada` on each of the last five days, none cleared, the newest 2 hours ago
- **THEN** pre-authentication for `ada` is allowed

#### Scenario: Cap reached across days
- **WHEN** the policy is configured with a cap of 100, and twenty failures for `ada` were recorded on each of five days, none cleared, the newest 3 days ago
- **THEN** pre-authentication for `ada` is denied as locked

#### Scenario: Consumer cap
- **WHEN** the policy is configured with a cap of 20, and twenty failures for `ada` were recorded over two days, none cleared
- **THEN** pre-authentication for `ada` is denied as locked

#### Scenario: Below the cap
- **WHEN** the policy is configured with a cap of 100, and ninety-nine failures for `ada` were recorded over five days, none cleared, the newest 2 days ago
- **THEN** pre-authentication for `ada` is allowed

#### Scenario: Unknown identifiers are held alike
- **WHEN** the policy is configured with a cap of 20, and twenty failures are recorded for `ada`, which has an account, and twenty for `nobody`, which does not
- **THEN** pre-authentication for each is denied with the same refusal

### Requirement: A hold is lifted only by clearing the identifier
A hold SHALL NOT lift with time. It SHALL lift only when the identifier's failures are cleared through its attempt store: by a password change through the chain, or by the policy's reset, which the documentation SHALL present as the unlock for an administrator. A held identifier SHALL be denied before its password is checked, so a correct password SHALL NOT lift a hold. Clearing SHALL remove the hold, the consecutive count and the failures in the window together.

#### Scenario: A hold outlives every window
- **WHEN** the policy is configured with a cap of 100, `ada` was held 90 days ago, and nothing has cleared it
- **THEN** pre-authentication for `ada` is denied as locked

#### Scenario: The correct password does not lift a hold
- **WHEN** `ada` is held, and pre-authentication runs for a login presenting `ada`'s correct password
- **THEN** it is denied as locked, and `ada` is still held

#### Scenario: Reset unlocks
- **WHEN** `ada` is held and also has one hundred failures in the window, and the policy's reset is called for `ada`
- **THEN** pre-authentication for `ada` is allowed

### Requirement: A count below the cap expires after inactivity
A consecutive count whose newest failure is older than the retention period SHALL no longer be counted, and the next failure SHALL start a new count. The retention SHALL be 30 days by default, replaceable by an option. A hold SHALL never expire this way.

#### Scenario: Inactive count restarts
- **WHEN** the policy is configured with a cap of 100, ninety-nine failures for `ada` were recorded, the newest 31 days ago, and one more is recorded now
- **THEN** pre-authentication for `ada` is allowed, and the consecutive count for `ada` is one

#### Scenario: Consumer retention
- **WHEN** the policy is configured with a cap of 100 and a retention of 7 days, ninety-nine failures for `ada` were recorded, the newest 8 days ago, and one more is recorded now
- **THEN** pre-authentication for `ada` is allowed

#### Scenario: A hold does not expire
- **WHEN** the policy is configured with a cap of 100, and `ada` became held 31 days ago
- **THEN** pre-authentication for `ada` is denied as locked

### Requirement: A held refusal is identifiable as a hold
A refusal of a held identifier SHALL be the account-locked refusal, SHALL carry no wait, and SHALL also be identifiable as a hold, so a consumer can tell the user to reset their password. When the record of held identifiers cannot be read, pre-authentication SHALL be denied with a reason wrapping the store's error.

#### Scenario: Held refusal
- **WHEN** pre-authentication for a held `ada` is denied
- **THEN** the reason is the account-locked refusal, is identifiable as a hold, and carries no wait

#### Scenario: A windowed lock is not a hold
- **WHEN** the policy is configured with a cap of 100, and pre-authentication for `ada` is denied with seven failures in the window and none before
- **THEN** the reason is the account-locked refusal and is not identifiable as a hold

#### Scenario: Unreadable hold
- **WHEN** the policy is configured with a cap, and the store fails while reading whether `ada` is held
- **THEN** pre-authentication for `ada` is denied with a reason wrapping that error

### Requirement: Concurrent failures cannot pass the cap without a hold
The consecutive count SHALL be advanced by one atomic write per failure. However many failures for one identifier are recorded at once, none SHALL be lost, and the identifier SHALL become held exactly once, by the failure that reaches the cap.

#### Scenario: Burst across the cap
- **WHEN** the policy is configured with a cap of 100, `ada` has ninety failures, and twenty failures for `ada` are recorded concurrently
- **THEN** the consecutive count for `ada` is one hundred and ten, `ada` is held, and the hold was set once

### Requirement: A cap is refused unless its wiring can enforce it
Construction SHALL fail with a configuration error, naming the option, when:
- a cap is set and the attempt store cannot keep consecutive counts and holds;
- the cap is not above the threshold;
- a retention is zero or less, given without a cap, or shorter than the lockout window.

#### Scenario: Store without consecutive counts
- **WHEN** a policy is configured with a cap and an attempt store that keeps no consecutive counts
- **THEN** construction fails with a configuration error naming the cap option

#### Scenario: Retention without a cap
- **WHEN** a policy is configured with a retention and no cap
- **THEN** construction fails with a configuration error

#### Scenario: Cap at the threshold
- **WHEN** a policy is configured with a threshold of 5 and a cap of 5
- **THEN** construction fails with a configuration error

## MODIFIED Requirements

### Requirement: Lockout transitions can be observed
By default, the lockout policy SHALL report nothing. A consumer SHALL be able to supply an observer, told of every recorded failure that leaves its identifier locked (owing a wait, at the ceiling, or under the sliding lock), of the failure that makes an identifier held, of every clearing of an identifier that had failures in the window, and of every clearing that lifts a hold. Each report SHALL carry the identifier as submitted, the kind, the failure count and the time. The observer SHALL NOT be able to change any decision or error.

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

#### Scenario: Held
- **WHEN** the consumer supplies an observer, the policy is configured with a cap of 20, and the twentieth consecutive failure for `ada` is recorded
- **THEN** the observer is told that `ada` is held with twenty failures, once

#### Scenario: Hold lifted
- **WHEN** the consumer supplies an observer, `ada` is held, and its failures are cleared
- **THEN** the observer is told that the hold on `ada` was lifted

### Requirement: Purging attempts cannot disarm lockout
The lockout policy SHALL purge stale attempts using a cutoff derived only from its own window, so that no caller can supply a different one. Only attempts recorded strictly before now minus the window SHALL be removed. When a cap is configured, the purge SHALL also remove consecutive counts whose newest failure is strictly before now minus the retention, and SHALL never remove a hold. When the configured attempt store cannot purge, the purge SHALL fail with a purge-unsupported error rather than report zero removed. An attempt store SHALL refuse a zero cutoff and delete nothing.

#### Scenario: Recent attempts survive a purge
- **WHEN** failures for `ada` were recorded 5 and 20 minutes ago with a 15-minute window, and the policy purges through a store that can purge
- **THEN** only the 20-minute-old failure is removed

#### Scenario: Default in-memory store
- **WHEN** a policy using the default in-memory attempt store purges
- **THEN** the purge-unsupported error is returned

#### Scenario: Zero cutoff
- **WHEN** an attempt store that can purge is asked to delete attempts before the zero time
- **THEN** it refuses and deletes nothing

#### Scenario: Inactive counts are purged, holds are kept
- **WHEN** the policy is configured with a cap of 100 and the default retention, `ada` has a count of ten with its newest failure 31 days ago, `bob` became held 31 days ago, and the policy purges through a store that can purge
- **THEN** the count for `ada` is removed, and `bob` is still held
