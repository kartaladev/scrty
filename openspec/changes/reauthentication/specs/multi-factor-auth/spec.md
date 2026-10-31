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
