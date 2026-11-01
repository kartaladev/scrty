# Spec Delta

## MODIFIED Requirements

### Requirement: Tokens expire
Each token SHALL expire at its issue time plus the time-to-live. The default time-to-live SHALL be 15 minutes, replaceable by an option. A time-to-live of zero or less SHALL fail construction. A check SHALL fail for a token whose expiry has passed. A consume SHALL fail as invalid for a token whose expiry has passed by the time it is consumed, at the expiry instant included, even when its check succeeded before then, and SHALL leave the token unspent.

#### Scenario: Default expiry
- **WHEN** a token issued at 10:00 with default options is checked at 10:16
- **THEN** the check fails as invalid

#### Scenario: Consumer time-to-live
- **WHEN** the manager is configured with a 24-hour time-to-live, and a token issued at 10:00 is checked at 10:16 the same day
- **THEN** the check succeeds

#### Scenario: A token that expires between its check and its consume
- **WHEN** a token issued at 10:00 with default options is checked at 10:14:59 and consumed at 10:15:00
- **THEN** the consume fails as invalid, and the token is unspent, so a later check fails as expired rather than as consumed
