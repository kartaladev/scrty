# Spec Delta

## ADDED Requirements

### Requirement: Suspending a suspected clone revokes the user's provider grants by default
When the OpenID Provider is in use, suspending a passkey as a suspected clone SHALL revoke every provider grant of the passkey's user, together with ending the user's sessions. A consumer MAY keep the grants on a clone suspension. Removing a passkey by the user's own request SHALL NOT revoke grants.

#### Scenario: Clone suspension ends application access
- **WHEN** a passkey of user `u-1` is suspended as a suspected clone
- **THEN** every refresh token of `u-1` is refused with `invalid_grant`

#### Scenario: Consumer keeps grants
- **WHEN** the consumer keeps grants on clone suspension, and a passkey of `u-1` is suspended
- **THEN** `u-1`'s grants keep working

#### Scenario: User removes a passkey
- **WHEN** user `u-1` removes one of their own passkeys
- **THEN** `u-1`'s grants keep working
