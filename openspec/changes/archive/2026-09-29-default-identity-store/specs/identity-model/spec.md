## RENAMED Requirements

- FROM: `### Requirement: The library ships no implementation of an identity port`
- TO: `### Requirement: The identity package ships no implementation of an identity port`

## MODIFIED Requirements

### Requirement: Provisioning is create-only and the collision is enforced by the write
A user provisioner SHALL create a user from a required username and optional display name, email, role names, organization, already-hashed password and password-changed time. It SHALL return the created details, which SHALL be active.
- A taken username SHALL return a "user exists" error that callers can identify, and SHALL leave the existing user unchanged.
- The collision SHALL be decided by the write itself, so concurrent requests for one username create exactly one user.
- The first role name SHALL be the primary role, and each occurrence of a name SHALL create its own grant.
- The password hash SHALL be stored exactly as given.
- The password-changed time SHALL be stored only when the caller names it, and SHALL be zero otherwise.
- The email SHALL NOT be used to look up or match a user.
- An empty username SHALL be refused.
- Error messages SHALL NOT include the username.

#### Scenario: Username taken
- **WHEN** a conforming provisioner is asked to create `alice` while `alice` exists
- **THEN** it returns an error identifiable as "user exists"
- **AND** the existing `alice` is unchanged

#### Scenario: Concurrent creation
- **WHEN** two requests to create `bob` reach a conforming provisioner at the same time
- **THEN** exactly one succeeds
- **AND** the other returns an error identifiable as "user exists"

#### Scenario: Roles and hash
- **WHEN** `carol` is created with roles `editor`, `viewer` and a password hash `H`
- **THEN** her details hold `editor` as primary and `viewer` as not primary, with password exactly `H`

#### Scenario: Error does not reveal the username
- **WHEN** creating `dave@example.com` fails because the username is taken
- **THEN** the error message does not contain `dave@example.com`

#### Scenario: Password-changed time named at creation
- **WHEN** `erin` is created naming a password hash and a password-changed time `T`
- **THEN** her details hold password-changed time `T`

### Requirement: Updating amends only named fields of an existing user
A user provisioner SHALL amend an existing user by username, writing only the fields the caller named, whatever values they hold. Every other stored field SHALL be left unchanged. Updating an unknown username SHALL return a "user not found" error and SHALL NOT create a user. A successful update SHALL return the complete stored record. The password-changed time SHALL be written only when the caller names it, like any other field. Naming the password without naming the time SHALL leave the stored time unchanged, so a password mirrored from an identity provider on every login never moves it, and a local change records itself by naming both. Naming the zero time SHALL clear it. The identity model SHALL offer one option that names both the password and the password-changed time, for a local change, distinct from the option that names the password alone. The library's own federated-login paths SHALL name the password alone. Concurrent updates of the same user SHALL be serialized, so the final state equals the last writer's result.

#### Scenario: Unnamed field untouched
- **WHEN** a user with organization `acme` and password `H1` is updated naming only the password `H2`
- **THEN** the user's password is `H2` and the organization is still `acme`

#### Scenario: Unknown user
- **WHEN** a conforming provisioner updates `nobody`
- **THEN** it returns an error identifiable as "user not found"
- **AND** no user `nobody` exists afterwards

#### Scenario: Complete record returned
- **WHEN** a user with roles and an organization is updated naming only the display name
- **THEN** the returned details include the user's roles and organization as stored

#### Scenario: Password-changed time preserved
- **WHEN** a user whose password-changed time is 2030-01-01 is updated naming a new password and not the time
- **THEN** the stored password-changed time is still 2030-01-01

#### Scenario: Local change names the time
- **WHEN** a user whose password-changed time is 2030-01-01 is updated with the local-change option, naming a new password and the time 2031-06-01
- **THEN** the stored and returned password-changed time is 2031-06-01

#### Scenario: Federated login never names the time
- **WHEN** a federated login mirrors a changed password onto a linked user, or provisions a user just in time with a password
- **THEN** the provisioner call names the password and does not name the password-changed time

### Requirement: MFA requirement is looked up by user reference and lives with the user
The MFA requirement lookup SHALL report, for a user reference, whether that user is required to use a second factor. The requirement SHALL be recorded with the user, not with any MFA enrolment, so removing an enrolment does not change it. The requirement SHALL NOT be part of the user details produced at authentication. A lookup failure SHALL be returned as an error, not as "not required". A user reference that names no stored user, including one the implementation cannot parse, SHALL be answered with a "user not found" error and SHALL NOT be answered as "not required".

#### Scenario: Enrolment removed
- **WHEN** a user marked as requiring MFA loses their MFA enrolment
- **THEN** the lookup still reports the user as required

#### Scenario: Lookup failure
- **WHEN** a conforming lookup cannot reach its backend
- **THEN** it returns an error and no answer

#### Scenario: Unknown user
- **WHEN** a conforming lookup is asked about a user reference that names no stored user
- **THEN** it returns an error identifiable as "user not found"
- **AND** it does not report the user as not required

#### Scenario: Stored user with no requirement recorded
- **WHEN** a conforming lookup is asked about a stored user whose requirement was never set
- **THEN** it reports the user as not required, with no error

### Requirement: The identity package ships no implementation of an identity port
The identity model SHALL define the user loader, role loader, user provisioner and MFA requirement lookup as contracts only. The `identity` package SHALL NOT ship an implementation of any of them, in memory or otherwise, and SHALL provide the configuration error value that a component returns when a port it needs was not supplied, naming that port. An in-memory provisioner that also loads users SHALL be available to tests only. Implementations the library offers outside the `identity` package, such as the optional default identity store, SHALL be opt-in: a component SHALL use one only when the consumer supplies it, and SHALL never fall back to one when a port was not supplied.

Whether a particular component refuses to be constructed without a port is that component's own requirement; the `authentication` capability states it.

#### Scenario: No bundled implementation
- **WHEN** the `identity` package's public surface is inspected
- **THEN** it exposes no in-memory or empty implementation of any identity port

#### Scenario: The missing-port error names the port
- **WHEN** the configuration error for an unsupplied user loader is produced
- **THEN** it names the user loader
- **AND** it is identifiable as a missing-port error

#### Scenario: No fallback to the default identity store
- **WHEN** a component that needs a user loader is constructed without one, in a program that also links the default identity store
- **THEN** construction fails with the missing-port error naming the user loader
