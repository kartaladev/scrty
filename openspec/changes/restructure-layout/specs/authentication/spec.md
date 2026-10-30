# Spec Delta

## MODIFIED Requirements

### Requirement: Password authentication does not reveal why it failed
The username-and-password provider SHALL return the same uniform failure, with no distinguishing error, in all of these cases:
- an unknown username;
- a wrong password;
- a correct password for an inactive account.

A failure to load the user other than "not found", and other than the caller's own context ending, SHALL NOT be returned as the uniform failure. It SHALL be returned as a distinct unavailable error, which is not identifiable as the uniform failure, so that a caller can tell an outage of the user store from a refused credential and never counts the outage against the account. The provider SHALL spend the same password work on a load failure as on an unknown username, so the outcome's timing does not change.

The account's active state SHALL be checked only after the password has been verified. A user-load failure other than "not found" SHALL be logged at error level. Constructing the provider without a user loader SHALL fail with a configuration error.

#### Scenario: Unknown user
- **WHEN** a username that does not exist is presented
- **THEN** the uniform authentication failure is returned

#### Scenario: Wrong password
- **WHEN** an existing, active username is presented with a wrong password
- **THEN** the uniform authentication failure is returned

#### Scenario: Inactive account
- **WHEN** an inactive account's username is presented with its correct password
- **THEN** the uniform authentication failure is returned, indistinguishable from the scenarios above

#### Scenario: User store unavailable
- **WHEN** the user loader returns a connection error
- **THEN** the unavailable error is returned, and it is not identifiable as the uniform authentication failure
- **AND** the provider has spent the same password work as for an unknown username
- **AND** an error-level record naming the connection error is logged

#### Scenario: The caller hangs up during the load
- **WHEN** the request's context is cancelled and the user loader fails with that cancellation
- **THEN** the uniform authentication failure is returned, not the unavailable error
