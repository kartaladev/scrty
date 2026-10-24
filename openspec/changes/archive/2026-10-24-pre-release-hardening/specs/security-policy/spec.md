# Spec Delta

## ADDED Requirements

### Requirement: The default attempt store stays bounded
The default in-memory attempt store SHALL forget failures older than the longest retention its owning policy needs, sweeping as it is written to, and SHALL hold at most 100,000 identifiers by default, replaceable by an option. Identifiers longer than 256 bytes SHALL be held by a digest. A hold SHALL never be forgotten before it lifts.

#### Scenario: Old failures are forgotten
- **WHEN** 50,000 distinct usernames each fail once, and the policy's window then passes with no further failures
- **THEN** the store holds none of them after its next write

#### Scenario: Consumer capacity
- **WHEN** the consumer sets the default store's capacity to 1,000,000
- **THEN** the store holds up to 1,000,000 identifiers

### Requirement: A full default attempt store fails closed
When the default attempt store is full after a sweep, recording a failure for a new identifier SHALL fail, and the lockout policy SHALL deny that login as it denies on any store error, so a full store never lets a guess through uncounted.

#### Scenario: Store full of live failures
- **WHEN** the store holds 100,000 identifiers with failures inside the window and a login for a new username fails
- **THEN** that login is denied and the store still holds 100,000 identifiers

### Requirement: An evaluation without a time or an input is denied
The policy engine SHALL deny an evaluation whose input is nil, and every policy that compares the evaluation time with a deadline SHALL deny an evaluation whose time is the zero time, so that a caller that forgets the time never lets an expired session, an old password or a closed enrolment path through.

#### Scenario: Nil input
- **WHEN** a phase is evaluated with a nil input
- **THEN** the outcome is deny and no policy panics

#### Scenario: Idle session with no evaluation time
- **WHEN** the idle-timeout policy evaluates a session idle for 48 hours with the evaluation time left at its zero value
- **THEN** the outcome is deny

#### Scenario: Old password with no evaluation time
- **WHEN** the password-age policy evaluates a year-old password with the evaluation time left at its zero value
- **THEN** the outcome is deny

## MODIFIED Requirements

### Requirement: Purging attempts cannot disarm lockout
The lockout policy SHALL purge stale attempts using a cutoff derived only from its own window, so that no caller can supply a different one. Only attempts recorded strictly before now minus the window SHALL be removed. When a cap is configured, the purge SHALL also remove consecutive counts whose newest failure is strictly before now minus the retention, and SHALL never remove a hold. When the configured attempt store cannot purge, the purge SHALL fail with a purge-unsupported error rather than report zero removed. The default in-memory attempt store SHALL be able to purge. An attempt store SHALL refuse a zero cutoff and delete nothing.

#### Scenario: Recent attempts survive a purge
- **WHEN** failures for `ada` were recorded 5 and 20 minutes ago with a 15-minute window, and the policy purges through a store that can purge
- **THEN** only the 20-minute-old failure is removed

#### Scenario: Default in-memory store
- **WHEN** a policy using the default in-memory attempt store purges, with failures for `ada` recorded 5 and 20 minutes ago and a 15-minute window
- **THEN** only the 20-minute-old failure is removed

#### Scenario: Consumer store that cannot purge
- **WHEN** a policy using a consumer's attempt store that cannot purge purges
- **THEN** the purge-unsupported error is returned

#### Scenario: Zero cutoff
- **WHEN** an attempt store that can purge is asked to delete attempts before the zero time
- **THEN** it refuses and deletes nothing

#### Scenario: Inactive counts are purged, holds are kept
- **WHEN** the policy is configured with a cap of 100 and the default retention, `ada` has a count of ten with its newest failure 31 days ago, `bob` became held 31 days ago, and the policy purges through a store that can purge
- **THEN** the count for `ada` is removed, and `bob` is still held
