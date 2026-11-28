# Spec Delta

## MODIFIED Requirements

### Requirement: An encoder can report that a stored hash needs upgrading
Every encoder, a consumer's own included, SHALL report, for a stored hash, whether it needs upgrading to the encoder's current output. For each built-in encoder: a hash of the encoder's own algorithm produced with weaker parameters, or a hash of any other algorithm, needs upgrading; a hash produced with the current parameters, or stronger ones, does not. The report SHALL derive no key.

#### Scenario: Raised Argon2id memory
- **WHEN** an Argon2id encoder at 128 MiB is asked about a stored Argon2id hash at 64 MiB
- **THEN** it reports that the hash needs upgrading

#### Scenario: Current parameters
- **WHEN** the same encoder is asked about a hash it produced itself
- **THEN** it reports that no upgrade is needed

#### Scenario: Stronger parameters
- **WHEN** an Argon2id encoder at 64 MiB is asked about a stored Argon2id hash at 128 MiB
- **THEN** it reports that no upgrade is needed

#### Scenario: Another algorithm
- **WHEN** an Argon2id encoder is asked about a stored bcrypt hash
- **THEN** it reports that the hash needs upgrading

#### Scenario: Unparseable hash
- **WHEN** an encoder is asked about a value that is no hash it can parse
- **THEN** it reports that no upgrade is needed, so a login never re-encodes a password whose stored value it could not have verified
