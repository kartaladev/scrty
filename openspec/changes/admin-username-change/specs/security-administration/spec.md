# Spec Delta

## ADDED Requirements

### Requirement: An update may change the username under the rules of creation
An update SHALL change the username when the caller names one, under the version check every update makes. A username SHALL be refused with the invalid-input error as creation refuses one. It SHALL be refused with the already-exists error for the username when another user holds it, deleted or not, compared exactly, or when it equals another live user's email ignoring case. The user's own username and email SHALL NOT count as a clash.

#### Scenario: Rename
- **WHEN** an administrator updates `ada` at her current version with the username `ada.lovelace`
- **THEN** she loads as `ada.lovelace`, her version has increased, and the username `ada` names no live user

#### Scenario: Username held by a deleted user
- **WHEN** user `bob` was soft-deleted and `ada` is renamed to `bob`
- **THEN** the call fails with the already-exists error for the username and nothing is written

#### Scenario: Username equal to another user's email
- **WHEN** user `carol` has email `carol@example.com` and `ada` is renamed to `CAROL@example.com`
- **THEN** the call fails with the already-exists error for the username and nothing is written

#### Scenario: Only the case changes
- **WHEN** `ada` is renamed to `Ada`
- **THEN** the update succeeds and the username is stored as `Ada`

#### Scenario: Stale rename
- **WHEN** an administrator deactivates `ada` after another caller read her, and that caller then renames her at the version it read
- **THEN** the rename fails with the stale-update error, and `ada` stays inactive with her username unchanged

#### Scenario: Surrounding white space
- **WHEN** `ada` is renamed to ` ada.lovelace`
- **THEN** the call fails with the invalid-input error and the store is not called

### Requirement: A username and an email change in one write
An update that names both the username and the email SHALL apply both or neither, in one write under one version check. The email's verification SHALL follow the rules of an email update. A user MAY take a username equal to the email set in the same update. Concurrent writes that would leave two live users with a clashing username and email SHALL NOT both succeed.

#### Scenario: Username follows a new email
- **WHEN** `ada@example.com`, whose username is her email, is updated with username and email `ada@lovelace.dev`
- **THEN** both are stored, the new email is unverified, and the version has increased once

#### Scenario: One field clashes
- **WHEN** an update names a free username and an email another live user holds
- **THEN** the call fails with the already-exists error for the email, and neither the username nor the email changes

#### Scenario: Racing rename
- **WHEN** one caller renames `ada` to `x@example.com` while another sets the email `x@example.com` on a different user
- **THEN** at most one of the two writes succeeds

### Requirement: A rename is reported as an update
A committed rename SHALL emit one user-updated event naming the actor, the target and the field `username` among the changed fields, never the old or the new username. An audit port, when configured, SHALL receive the records before and after the rename. A refused rename SHALL emit nothing.

#### Scenario: Rename event
- **WHEN** an administrator renames `ada` to `ada.lovelace` and changes her email in the same update
- **THEN** one user-updated event names the fields `username` and `email`, and contains neither username nor the address

#### Scenario: Refused rename
- **WHEN** a rename fails with the already-exists error
- **THEN** no event is emitted and the error text contains neither username

### Requirement: Import is unchanged by renames
Import SHALL keep matching users by identifier and writing the given username, with the rules it has today. A rename through an update SHALL NOT change how a later import of the same identifier behaves.

#### Scenario: Import after a rename
- **WHEN** `ada` is renamed through an update to `ada.lovelace` and her identifier is then imported with the username `ada.lovelace` and otherwise equal values
- **THEN** the import reports unchanged and emits no event
