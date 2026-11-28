# Spec Delta

## MODIFIED Requirements

### Requirement: An unknown user costs the same password work as a known one
When loading the user fails, or the loaded user has no usable password hash, the password provider SHALL still perform exactly one full password verification against a reference hash that the configured password encoder produced at construction, and SHALL discard that verification's result, so a match against the reference never admits anyone. A stored hash is not usable when it is empty, or when the encoder reports that it does not recognise the hash. Every encoder SHALL report whether it recognises a stored hash. Construction SHALL fail if the reference hash cannot be produced. When no encoder is configured, the default password encoder SHALL be used.

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

#### Scenario: Consumer encoder that does not recognise a hash
- **WHEN** a provider is built with a consumer's encoder that reports it does not recognise a user's stored hash
- **THEN** one full verification is performed against the reference hash and the authentication fails

#### Scenario: Reference password presented
- **WHEN** the password presented for a user without a usable hash happens to match the reference hash
- **THEN** the authentication still fails
