# Spec Delta

## ADDED Requirements

### Requirement: The verify and begin endpoints serve only a session that owes a second factor
The second-factor verify and begin endpoints SHALL refuse a session that owes no second-factor challenge, a full session included, with the no-MFA-challenge-pending error. The refusal SHALL come after the session and caller refusals and before the method, the throttle or the body is read. It SHALL count nothing, issue nothing and leave the session and its handle unchanged. Re-proving a signed-in session belongs to the re-authentication capability.

#### Scenario: A full session posts a code
- **WHEN** a session whose second factor is satisfied posts a valid code to `/mfa/verify/totp`
- **THEN** it is refused with the no-MFA-challenge-pending error, the code is not checked, nothing is counted and the handle is unchanged

#### Scenario: A full session begins a challenge
- **WHEN** a session whose second factor is satisfied posts to `/mfa/begin/passkey`
- **THEN** it is refused with the no-MFA-challenge-pending error and no challenge is issued

#### Scenario: A session that never owed a second factor
- **WHEN** a session of a user enrolled on TOTP after it signed in, which owes no challenge, posts a valid code to `/mfa/verify/totp`
- **THEN** it is refused with the no-MFA-challenge-pending error and its authentication time is unchanged

#### Scenario: No session still comes first
- **WHEN** a request without a session posts to `/mfa/verify/totp`
- **THEN** it is refused as authentication required

#### Scenario: A pending session is still served
- **WHEN** a session with the MFA challenge pending posts a valid code to `/mfa/verify/totp`
- **THEN** the challenge is resolved and the session rotated

### Requirement: Concurrent verifications of one pending session yield one success
When one session pending a second factor posts two valid verifications at once to one server, exactly one SHALL resolve the challenge and rotate the session, and the other SHALL be refused with the renewal-conflict error, leaving the winner's session and credential in place.

#### Scenario: Two valid codes at once
- **WHEN** one pending session posts two valid codes to `/mfa/verify/totp` at once
- **THEN** one succeeds and the other is refused with the renewal-conflict error
- **AND** the winner's credential authenticates the next request


### Requirement: Passkey management on an MFA chain needs re-authentication
Because the verify and begin endpoints serve only a session that owes a second factor, a full session can meet its second factor only by re-authenticating. A chain with the MFA slot and passkeys SHALL therefore fail construction with a configuration error naming the re-authentication option when re-authentication is not enabled, so no wiring leaves a user unable to reach the state passkey registration and removal require.

#### Scenario: MFA and passkeys without re-authentication
- **WHEN** a chain enables the MFA slot and passkeys and does not enable re-authentication
- **THEN** construction fails with a configuration error naming the re-authentication option

#### Scenario: With re-authentication
- **WHEN** the same chain also enables re-authentication, and a session of a user enrolled on TOTP after signing in, which owes no challenge, re-proves with a valid code at `/reauth/verify/totp`
- **THEN** its second factor is recorded as satisfied and passkey registration begin is served

#### Scenario: MFA without passkeys
- **WHEN** a chain enables the MFA slot and not passkeys, without re-authentication
- **THEN** construction succeeds
