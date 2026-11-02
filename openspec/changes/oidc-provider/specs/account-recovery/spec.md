# Spec Delta

## ADDED Requirements

### Requirement: A completed recovery revokes the user's provider grants by default
When the OpenID Provider is in use, completing an account recovery SHALL revoke every provider grant of the recovered user, those holding `offline_access` included, together with ending the user's other sessions. A consumer MAY keep the grants on recovery. A failure to revoke the grants SHALL be returned as a dependency failure, never swallowed.

#### Scenario: Recovery ends application access
- **WHEN** a recovery completes for user `u-1`, who holds an offline grant for `billing-ios`
- **THEN** `billing-ios`'s refresh token for `u-1` is refused with `invalid_grant`

#### Scenario: Consumer keeps grants
- **WHEN** the consumer keeps grants on recovery, and a recovery completes for `u-1`
- **THEN** `u-1`'s grants keep working

#### Scenario: No provider
- **WHEN** the OpenID Provider is not in use and a recovery completes
- **THEN** the recovery completes as before
