# Spec Delta

## ADDED Requirements

### Requirement: Login by email is off by default
The username-and-password provider SHALL load users by username only, unless the consumer turns on login by email. Turning it on with a user loader that cannot load by email SHALL fail construction with a configuration error.

#### Scenario: Default
- **WHEN** a provider built without login by email is presented `ada@example.com`, the verified email of user `ada`, with her correct password
- **THEN** the uniform authentication failure is returned

#### Scenario: Loader cannot load by email
- **WHEN** a provider is built with login by email over a loader that does not implement the email loader
- **THEN** construction fails with a configuration error

### Requirement: An identifier resolves by username first, then by verified email
With login by email on, the provider SHALL load the presented identifier as a username and, only when that is not found, as an email through the email loader. A user found either way SHALL be authenticated exactly as a user found by username. An identifier found as neither SHALL get the uniform failure.

#### Scenario: Email login
- **WHEN** login by email is on and `ADA@example.com`, `ada`'s verified email, is presented with her correct password
- **THEN** authentication succeeds and the principal is `ada`

#### Scenario: Unverified email
- **WHEN** login by email is on and `ada`'s unverified email is presented with her correct password
- **THEN** the uniform authentication failure is returned

### Requirement: An identifier that names two users is refused
With login by email on, when the presented identifier is found as one user's username and, ignoring case, as a different live user's verified email, the provider SHALL return the uniform failure without verifying the password, SHALL spend the same password work as for an unknown user, and SHALL report the conflict as an event.

#### Scenario: Conflicting data
- **WHEN** a consumer's store holds user `x@example.com` and another user whose verified email is `x@example.com`, and `x@example.com` is presented
- **THEN** the uniform failure is returned and an identifier-conflict event is emitted

### Requirement: Email login reveals nothing an unknown username would not
With login by email on, an unknown identifier, an unverified email and a load failure SHALL produce the same outcomes and spend the same password work as the username-only provider does for an unknown username and a load failure. The email lookup SHALL be made only when the username lookup reports not found.

#### Scenario: Unknown email
- **WHEN** login by email is on and `nobody@example.com` is presented
- **THEN** the uniform failure is returned after the same password work as for an unknown username

#### Scenario: Email store unavailable
- **WHEN** the username lookup reports not found and the email lookup fails with a connection error
- **THEN** the unavailable error is returned, as for a username lookup outage
