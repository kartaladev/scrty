# Spec Delta

## ADDED Requirements

### Requirement: A completed recovery says what it removed
A completed recovery SHALL report to its caller the authenticators it removed, the same list its notice names, so that a caller can tell others what changed. A recovery that is held SHALL report none until it finishes. A recovery that fails SHALL report none, even if it had already removed some.

#### Scenario: Default reset
- **WHEN** a recovery completes under the default reset, and the user proved one method and holds two others
- **THEN** the result names the two others, and not the method proved

#### Scenario: A consumer's policy
- **WHEN** a recovery completes under a consumer's policy that removes one authenticator
- **THEN** the result names that one

#### Scenario: A policy that keeps everything
- **WHEN** a recovery completes under a consumer's policy that removes nothing
- **THEN** the result names nothing

#### Scenario: Held, then finished
- **WHEN** a recovery is held, and later finished
- **THEN** the held result names nothing, and the finished result names what was removed

#### Scenario: A failure partway
- **WHEN** a recovery removes one kind of authenticator, and removing the next fails
- **THEN** the recovery fails and reports nothing, and what was removed stays removed
