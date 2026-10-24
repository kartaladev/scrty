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
When the user loader returns no user and no error, a registration begin SHALL be refused, and the default display-name resolver SHALL return an error, rather than panic. A credential list containing an empty entry SHALL treat that entry as missing rather than panic.

#### Scenario: Loader returns no user
- **WHEN** a session of `u-1` begins a registration and the user loader returns no user and no error
- **THEN** the begin is refused and no challenge is issued

## MODIFIED Requirements

### Requirement: A first passkey waits for saved recovery codes when the user has no other way back in
When saved recovery codes are wired to registration, finish SHALL ask the account-recovery capability's other-way-back-in check about the session's user before storing the credential. A failed check SHALL refuse the finish, and nothing SHALL be stored. When the check reports no way back:
- the credential SHALL be stored in the pending state, awaiting saved codes;
- a new set of saved codes SHALL be generated for the user, replacing any set they held, only after the credential is stored, so a finish refused by the passkey limit replaces no codes;
- the codes SHALL be returned in the finish response, once, with `Cache-Control: no-store`.

The credential SHALL become active only when the user posts one of those codes to the registration confirm endpoint. That endpoint SHALL:
- read the code from the `code` form field;
- check the code with the saved-code check, which spends nothing and is throttled per user;
- clear the pending reason by one conditional write on the user's credential awaiting codes.

A wrong code SHALL leave the credential pending. The registration confirm endpoint SHALL accept only the session's own user's credential. A new registration finish for a user who holds a credential awaiting codes, created before this finish's registration challenge was issued, SHALL delete that credential before storing the new one, and that credential SHALL NOT count against the passkey limit. A credential awaiting codes created at or after that instant belongs to a concurrent registration and SHALL be kept. If generating the codes fails after the credential is stored, the finish SHALL fail and SHALL remove the credential it stored. A user who already has another way back in SHALL register without this step.

A consumer SHALL be able to choose the optional mode instead. Finish then SHALL store the credential active at once, and SHALL report in its response that recovery is not set up, for the consumer's interface to prompt. The documentation SHALL state that the optional mode allows accounts that only the operator can recover.

#### Scenario: Passwordless user's first passkey
- **WHEN** `u-1` has no password, no MFA enrolment, no saved codes and no counted linked identity, and finishes a registration
- **THEN** the response carries ten saved codes and the credential is pending
- **AND** `u-1` cannot log in with that passkey

#### Scenario: Confirming with a saved code
- **WHEN** `u-1` then posts one of those codes to the registration confirm endpoint
- **THEN** the credential is active and `u-1` can log in with it
- **AND** that code is still unspent

#### Scenario: Wrong code
- **WHEN** `u-1` posts a code that is not in the set
- **THEN** the credential stays pending

#### Scenario: Abandoned registration is replaced
- **WHEN** `u-1` holds a credential awaiting codes from an earlier registration, and begins and finishes a new one, with a passkey limit of 1
- **THEN** the earlier credential no longer exists, and the new one is pending with a new set of codes

#### Scenario: User with a way back
- **WHEN** `u-1` holds three unspent saved codes and finishes a registration
- **THEN** the credential is active at once and no codes are returned

#### Scenario: Consumer chooses the optional mode
- **WHEN** the optional mode is chosen and `u-1`, with no other way back in, finishes a registration
- **THEN** the credential is active at once and the response reports that recovery is not set up

#### Scenario: Check failure
- **WHEN** the way-back check fails because the saved-code store is unavailable
- **THEN** the finish is refused and nothing is stored

#### Scenario: A concurrent registration's credential is kept
- **WHEN** `u-1` begins two registrations, finishes the first, then finishes the second, with a passkey limit of 1
- **THEN** the first credential is kept and its codes confirm it, and the second finish is refused at the limit and replaces no codes
