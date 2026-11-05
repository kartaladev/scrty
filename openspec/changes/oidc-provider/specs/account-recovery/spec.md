# Spec Delta

## ADDED Requirements

### Requirement: A recovery verifies an MFA proof before revoking grants
An MFA proof's check is also its spend, so a recovery completing at once SHALL verify it before its first grant revocation. A refused MFA code SHALL revoke nothing, and a failure of that revocation SHALL leave only that code spent.

#### Scenario: A wrong MFA code
- **WHEN** a recovery presents a valid saved code and a wrong MFA code
- **THEN** the recovery is refused, `u-1`'s grants are not revoked, and the saved code is not spent

#### Scenario: Grant store down after an MFA code is accepted
- **WHEN** a recovery's MFA code is accepted, and revoking `u-1`'s grants fails
- **THEN** the recovery fails as a dependency failure, the saved or issued code is not spent, and the same code with the next MFA code succeeds

### Requirement: A recovery that cannot revoke grants spends nothing, or says so
A recovery SHALL revoke the user's provider grants after its proofs pass every check and before any is spent, and a failure there SHALL be a dependency failure with nothing spent. It SHALL revoke them again after the sessions end. If only that second revocation fails, the recovery SHALL complete, its result SHALL say the grants were not revoked, and the failure SHALL be logged and reported as a security event. A held recovery SHALL take both steps at its finish.

#### Scenario: Grant store down before the proofs are spent
- **WHEN** a recovery's proofs pass their checks, and revoking `u-1`'s grants fails
- **THEN** the recovery fails as a dependency failure, and the same proofs succeed when presented again

#### Scenario: Grant store fails after the proofs are spent
- **WHEN** the first revocation of `u-1`'s grants succeeds, the proofs are spent, and the second revocation fails
- **THEN** the recovery session is stored, the result says the grants were not revoked, and a `scrty_grant_revoke_failed` event names `u-1`

#### Scenario: A held recovery
- **WHEN** a recovery is held, and revoking `u-1`'s grants would fail
- **THEN** starting the hold revokes nothing, and a failure of the first revocation at its finish leaves the finish able to be retried

### Requirement: A completed recovery revokes the user's provider grants by default
When the OpenID Provider is in use, completing an account recovery SHALL revoke every provider grant of the recovered user, those holding `offline_access` included, together with ending the user's other sessions. A consumer MAY keep the grants on recovery.

#### Scenario: Recovery ends application access
- **WHEN** a recovery completes for user `u-1`, who holds an offline grant for `billing-ios`
- **THEN** `billing-ios`'s refresh token for `u-1` is refused with `invalid_grant`

#### Scenario: Consumer keeps grants
- **WHEN** the consumer keeps grants on recovery, and a recovery completes for `u-1`
- **THEN** `u-1`'s grants holding `offline_access` keep working, as a grant without it ends with its sign-in

#### Scenario: No provider
- **WHEN** the OpenID Provider is not in use and a recovery completes
- **THEN** the recovery completes as before
