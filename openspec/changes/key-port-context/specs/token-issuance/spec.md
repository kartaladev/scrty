# Spec Delta

## MODIFIED Requirements

### Requirement: Issuing requires a key and a valid lifetime
Constructing a generator with a lifetime shorter than one second, or not a whole number of seconds, SHALL fail, because expiry is recorded in whole seconds. Constructing a generator whose lifetime is longer than the key source's key lifetime minus its rotation interval SHALL fail with a configuration error, when the key source reports both. Issuing when no key is current for the configured algorithm SHALL return an error and SHALL NOT produce a token.

Issuing SHALL pass its context to the key source. When the key source cannot answer, issuing SHALL return an error that wraps the source's error behind fixed text, SHALL NOT report it as a missing key, and SHALL NOT produce a token.

#### Scenario: Non-positive lifetime
- **WHEN** a generator is constructed with a lifetime of zero
- **THEN** construction fails

#### Scenario: Lifetime outlives the key
- **WHEN** a generator with a 24-hour token lifetime is constructed over a key source with a 24-hour key lifetime and a 1-hour rotation interval
- **THEN** construction fails with a configuration error

#### Scenario: No key for the algorithm
- **WHEN** a generator configured for EdDSA issues a token over a key source holding only RS256 keys
- **THEN** issuing returns an error and no token

#### Scenario: Sub-second lifetime
- **WHEN** a generator is constructed with a 500-millisecond lifetime
- **THEN** construction fails

#### Scenario: Key source outage
- **WHEN** a generator issues a token over a consumer key source that fails with an outage error when asked for a signing key
- **THEN** issuing returns an error that wraps the outage error and does not match the no-key error
- **AND** no token is produced
