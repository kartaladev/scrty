# Spec Delta

## ADDED Requirements

### Requirement: An operator MFA reset revokes the user's provider grants by default
When the OpenID Provider is in use, an operator reset of a user's MFA enrolment SHALL revoke every provider grant of that user after the removals, together with ending the user's sessions. A consumer MAY keep the grants on an MFA reset. A failure to revoke the grants SHALL be returned after the removals, as the reset's other later failures are.

#### Scenario: Reset ends application access
- **WHEN** an operator resets the MFA enrolment of user `u-1`, who holds grants for two clients
- **THEN** both clients' refresh tokens for `u-1` are refused with `invalid_grant`

#### Scenario: Consumer keeps grants
- **WHEN** the consumer keeps grants on MFA reset, and an operator resets `u-1`'s enrolment
- **THEN** `u-1`'s grants keep working, and `u-1`'s sessions still end
