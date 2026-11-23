# Spec Delta

## ADDED Requirements

### Requirement: With email login, lockout counts against the resolved account
When login by email is on, an identifier that resolves to a user SHALL be locked, counted, held and cleared under that user's username, before the pre-authentication phase runs, so the username and the email share one budget and one hold. An identifier that resolves to no user SHALL be counted under the identifier as presented.

#### Scenario: Shared budget
- **WHEN** login by email is on with a threshold of 5, three failures were made with `ada` and two with `ada@example.com`, her verified email
- **THEN** pre-authentication for `ada@example.com` is denied as locked, and so is pre-authentication for `ada`

#### Scenario: Held account through its email
- **WHEN** `ada` is held by the failure-streak cap and her verified email is presented
- **THEN** pre-authentication is refused as held, and no password is compared

#### Scenario: Unknown identifier
- **WHEN** login by email is on and `nobody@example.com` fails five times
- **THEN** the failures are counted under `nobody@example.com`

### Requirement: Resolving an identifier for lockout loads the user once
With login by email on, the user found while resolving the identifier for lockout SHALL be the user the provider authenticates, without a second load, so a user changed between the two cannot be locked under one name and authenticated under another.

#### Scenario: One load
- **WHEN** login by email is on and `ada@example.com` is presented
- **THEN** the username lookup and the email lookup are each made at most once for the attempt
