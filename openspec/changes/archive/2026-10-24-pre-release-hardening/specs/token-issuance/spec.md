# Spec Delta

## ADDED Requirements

### Requirement: A verification key that is a nil pointer is an outage, not a panic
When the consumer's key source returns a key whose value is a nil pointer, verification SHALL fail with the error it returns for a key set that cannot be used, and SHALL NOT panic.

#### Scenario: Typed-nil RSA key
- **WHEN** a consumer key source returns an RS256 key whose public key is a nil RSA public key pointer, and a token is verified
- **THEN** verification returns an error and does not panic

## MODIFIED Requirements

### Requirement: Issuing requires a key and a valid lifetime
Constructing a generator with a lifetime shorter than one second, or not a whole number of seconds, SHALL fail, because expiry is recorded in whole seconds. Constructing a generator whose lifetime is longer than the key source's key lifetime minus its rotation interval SHALL fail with a configuration error, when the key source reports both. Issuing when no key is current for the configured algorithm SHALL return an error and SHALL NOT produce a token.

#### Scenario: Non-positive lifetime
- **WHEN** a generator is constructed with a lifetime of zero
- **THEN** construction fails

#### Scenario: Sub-second lifetime
- **WHEN** a generator is constructed with a 500-millisecond lifetime
- **THEN** construction fails

#### Scenario: Lifetime outlives the key
- **WHEN** a generator with a 24-hour token lifetime is constructed over a key source with a 24-hour key lifetime and a 1-hour rotation interval
- **THEN** construction fails with a configuration error

#### Scenario: No key for the algorithm
- **WHEN** a generator configured for EdDSA issues a token over a key source holding only RS256 keys
- **THEN** issuing returns an error and no token
