# Spec Delta

## ADDED Requirements

### Requirement: A typed-nil credential is refused, not dereferenced
A provider SHALL treat presented credentials that are a nil pointer of a kind it handles as unsupported credentials, both when authenticating and when spending a decoy verification, and SHALL NOT panic.

#### Scenario: Typed-nil username and password
- **WHEN** the password provider is given a nil username-and-password credential
- **THEN** it returns the unsupported-credentials error and does not panic

## MODIFIED Requirements

### Requirement: An unknown user costs the same password work as a known one
When loading the user fails, or the loaded user has no usable password hash, the password provider SHALL still perform exactly one full password verification against a reference hash that the configured password encoder produced at construction, and SHALL discard that verification's result, so a match against the reference never admits anyone. A stored hash is not usable when it is empty, or when the encoder reports that it does not recognise the hash. An encoder that cannot report recognition SHALL be treated as recognising every non-empty hash. Construction SHALL fail if the reference hash cannot be produced. When no encoder is configured, the default password encoder SHALL be used.

#### Scenario: Default encoder
- **WHEN** a provider built without an encoder receives an unknown username
- **THEN** the default encoder performs one full verification before the failure is returned

#### Scenario: Consumer-supplied encoder
- **WHEN** a provider is built with a consumer's password encoder and receives an unknown username
- **THEN** that encoder performs one full verification against a hash it produced itself

#### Scenario: Reference hash cannot be produced
- **WHEN** the configured encoder fails to produce a hash at construction
- **THEN** construction fails with that error

#### Scenario: Known user without a password
- **WHEN** a provider receives the username of a user created by federated login, who has no password hash
- **THEN** one full verification is performed against the reference hash before the failure is returned, so the refusal costs the same as for an unknown user

#### Scenario: Stored hash the encoder does not recognise
- **WHEN** a provider built with the default encoder receives the username of a user whose stored hash is in a format that encoder does not recognise
- **THEN** one full verification is performed against the reference hash and the authentication fails

#### Scenario: Reference password presented
- **WHEN** the password presented for a user without a usable hash happens to match the reference hash
- **THEN** the authentication still fails

### Requirement: No eligible provider is reported as such
When every provider skips the presented credentials, the manager SHALL return a no-eligible-provider error. A provider that returns the no-eligible-provider error, such as a nested manager whose providers all skipped, SHALL be treated as having skipped, and the manager SHALL try its next provider.

#### Scenario: Unsupported credentials
- **WHEN** credentials of a kind no configured provider handles are presented
- **THEN** the no-eligible-provider error is returned

#### Scenario: Nested manager skips
- **WHEN** a manager is built from a nested manager holding only a password provider, followed by a bearer-token provider, and a bearer token is presented
- **THEN** the bearer-token provider authenticates it
