# Spec Delta

## ADDED Requirements

### Requirement: The clock-skew leeway is bounded
Construction SHALL fail with a configuration error when the clock-skew leeway is longer than 5 minutes, because a longer leeway accepts tokens expired by that much.

#### Scenario: Leeway of an hour
- **WHEN** the OIDC manager is configured with a one-hour clock-skew leeway
- **THEN** construction fails with a configuration error

#### Scenario: Consumer leeway within the bound
- **WHEN** the OIDC manager is configured with a 2-minute clock-skew leeway
- **THEN** construction succeeds and tokens are judged with that leeway

## MODIFIED Requirements

### Requirement: The post-login destination is allowlisted
The destination requested when a login starts SHALL be recorded untrusted, and SHALL be used only when it exactly matches an entry of the redirect allowlist. Otherwise the destination SHALL be `/`. A requested destination longer than 2048 bytes SHALL NOT be recorded, and the login SHALL proceed as if none was requested, because no allowlist entry can be that long. The allowlist SHALL be empty by default. Each entry, and each origin the consumer declares, SHALL be validated at construction by the rules of the `outbound-http-confinement` capability's requirement that browser redirect targets are host-relative or declared; an invalid entry or origin SHALL fail construction. An allowlist entry longer than 2048 bytes SHALL fail construction. The destination SHALL be checked again against the allowlist when it is used. The OIDC allowlist SHALL be configured separately from any other flow's.

#### Scenario: Unlisted destination
- **WHEN** a login starts with destination `https://evil.example/` and completes
- **THEN** the redirect goes to `/` with the handoff code

#### Scenario: Scheme-relative entry
- **WHEN** the allowlist contains `//evil.example/app`
- **THEN** construction fails with a configuration error

#### Scenario: Consumer declares an origin
- **WHEN** the consumer declares origin `https://app.example` and allowlists `https://app.example/welcome`, and a login starts with that destination
- **THEN** the redirect goes to `https://app.example/welcome` with the handoff code

#### Scenario: Absolute entry on an undeclared origin
- **WHEN** the allowlist contains `https://partner.example/landing` and no origin is declared
- **THEN** construction fails with a configuration error

#### Scenario: Over-long destination
- **WHEN** a login starts with a destination of 1 MiB
- **THEN** the flow records no destination, and the completed login redirects to `/`
