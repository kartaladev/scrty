# Spec Delta

## ADDED Requirements

### Requirement: A stored hash cannot demand unbounded work
Matching SHALL report no match, without deriving a key, for a stored hash whose parameters exceed the record ceilings:
- Argon2id: 1 GiB of memory, 16 iterations, 16 threads, a 64-byte salt, a 64-byte derived key;
- bcrypt: a cost of 16;
- scrypt: p of 16, and a working memory of `(N + p) × 128 × r` bytes above 1 GiB.

The ceilings are a stated limit with no override, because a stored hash is data the library must not let consume the process.

#### Scenario: scrypt parallelism beyond the ceiling
- **WHEN** a password is matched against a stored scrypt hash with N 32768, r 8 and p 1073741823
- **THEN** no match is reported, quickly, and no key is derived

#### Scenario: bcrypt cost beyond the ceiling
- **WHEN** a password is matched against a stored bcrypt hash of cost 20
- **THEN** no match is reported without running bcrypt

#### Scenario: Argon2id threads beyond the ceiling
- **WHEN** a password is matched against a stored Argon2id hash recording 64 threads
- **THEN** no match is reported

### Requirement: An encoder cannot be built to produce hashes it would refuse
Constructing an encoder with any parameter above its record ceiling SHALL fail with a configuration error that names the parameter.

#### Scenario: scrypt parallelism above the ceiling
- **WHEN** a scrypt encoder is constructed with p 32
- **THEN** construction fails with an error naming p

#### Scenario: bcrypt cost above the ceiling
- **WHEN** a bcrypt encoder is constructed with cost 17
- **THEN** construction fails with an error naming cost

#### Scenario: At the ceiling
- **WHEN** an Argon2id encoder is constructed with 1 GiB of memory and 16 iterations
- **THEN** construction succeeds, and a password it encodes matches

## MODIFIED Requirements

### Requirement: bcrypt never matches by truncation
The bcrypt encoder SHALL refuse to encode a password longer than 72 bytes, with a "password too long" error that callers can identify. Matching a password longer than 72 bytes SHALL report no match, even when its first 72 bytes equal the stored password. The bcrypt encoder SHALL also refuse to encode a password containing a NUL byte, with an error that callers can identify, and matching a password containing a NUL byte SHALL report no match, because bcrypt's key schedule makes a password and its NUL-joined repetition the same credential.

#### Scenario: Exactly 72 bytes
- **WHEN** a 72-byte password is encoded with bcrypt
- **THEN** encoding succeeds and the password matches

#### Scenario: 73 bytes refused
- **WHEN** a 73-byte password is encoded with bcrypt
- **THEN** encoding fails with an error identifiable as "password too long"

#### Scenario: Shared 72-byte prefix
- **WHEN** a 73-byte password whose first 72 bytes equal a stored 72-byte password is matched against that password's bcrypt hash
- **THEN** no match is reported

#### Scenario: NUL-joined repetition
- **WHEN** `hunter2\x00hunter2` is matched against the bcrypt hash of `hunter2`
- **THEN** no match is reported

#### Scenario: NUL refused on encoding
- **WHEN** a password containing a NUL byte is encoded with bcrypt
- **THEN** encoding fails with an identifiable error
