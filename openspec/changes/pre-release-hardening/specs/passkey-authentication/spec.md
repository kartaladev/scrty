# Spec Delta

## ADDED Requirements

### Requirement: Passkey limits are decided by the write
The per-user passkey limit SHALL be decided by one atomic bounded insert, so that registration finishes for one user that race SHALL NOT together store more passkeys than the limit. The per-user registration-challenge limit SHALL likewise be decided by one atomic bounded issue, so begins that race SHALL NOT together issue more challenges than the limit.

#### Scenario: Concurrent finishes at the limit
- **WHEN** the passkey limit is 1, `u-1` holds no passkey, and four registration finishes for `u-1` run concurrently
- **THEN** exactly one stores a passkey and the others are refused with the passkey-limit refusal

#### Scenario: Concurrent registration begins
- **WHEN** 20 registration begins for `u-1` run concurrently and none were issued in the window before
- **THEN** no more challenges are issued than the registration-challenge limit allows

### Requirement: A backed-up state without backup eligibility is refused
Registration and assertion SHALL be refused with the authentication-failed refusal when the authenticator data reports the backup state as set while backup eligibility is not set, as WebAuthn Level 3 requires, whatever verifier the consumer supplies.

#### Scenario: Registration reporting backed up but not eligible
- **WHEN** `u-1` finishes a registration whose authenticator data has the backup-state flag set and the backup-eligible flag clear
- **THEN** the finish is refused with the authentication-failed refusal and nothing is stored

#### Scenario: Assertion reporting backed up but not eligible
- **WHEN** a passwordless finish presents an assertion whose authenticator data has the backup-state flag set and the backup-eligible flag clear
- **THEN** the login is refused with the authentication-failed refusal

### Requirement: The relying party identifier is a valid DNS name
Construction SHALL fail with a configuration error when the relying party identifier is not a lowercase DNS name: each label 1 to 63 characters of lowercase ASCII letters, digits and hyphens, not starting or ending with a hyphen, and the whole at most 253 characters. `localhost` SHALL be accepted.

#### Scenario: Uppercase identifier
- **WHEN** the relying party identifier is configured as `Example.com`
- **THEN** construction fails with a configuration error

#### Scenario: Label with a leading hyphen
- **WHEN** the relying party identifier is configured as `-login.example.com`
- **THEN** construction fails with a configuration error

#### Scenario: Valid identifier
- **WHEN** the relying party identifier is configured as `login.example.com`
- **THEN** construction succeeds

### Requirement: A user lookup with no result is refused, not dereferenced
When the user loader returns no user and no error, a registration begin SHALL be refused, and the default display-name resolver SHALL return an error, rather than panic. A credential list containing an empty entry SHALL be refused as a store failure rather than panic.

#### Scenario: Loader returns no user
- **WHEN** a session of `u-1` begins a registration and the user loader returns no user and no error
- **THEN** the begin is refused and no challenge is issued
