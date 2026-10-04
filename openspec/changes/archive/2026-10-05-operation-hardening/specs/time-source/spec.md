## MODIFIED Requirements

### Requirement: Every component reads time from one replaceable time source
Every component in the core module and its driver adapters that offers a time-source option SHALL
read the current time from that single source. When no time source is configured, the component
SHALL use the system clock. Every time the component records, and every time check
it makes, SHALL come from that source. A default dependency that the component builds for itself
and that keeps time, such as a manager's default store, SHALL read the same source.

#### Scenario: System clock by default
- **WHEN** a one-time token store is constructed with no time-source option and issues a token with a 5-minute lifetime
- **THEN** the token's expiry is 5 minutes after the system time at issue

#### Scenario: Consumer time source
- **WHEN** a consumer configures a one-time token store with a time source reading 2030-01-01T12:00:00Z, issues a token with a 5-minute lifetime, and advances the source to 12:06
- **THEN** the token's expiry is 2030-01-01T12:05:00Z
- **AND** redeeming the token is refused as expired, with no real waiting

#### Scenario: A manager's default store follows the manager's time source
- **WHEN** a one-time token manager is built with a consumer time source and no store, issues a token, and the source advances past the token's expiry and the manager's issuance window
- **THEN** purging the manager's expired tokens removes that token, with no real waiting
