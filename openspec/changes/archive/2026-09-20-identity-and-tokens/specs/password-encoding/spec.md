## Purpose

Hashes and verifies passwords with a safe default algorithm and replaceable parameters above a stated floor. Verification costs the same whether or not a password matches, so a caller can make a login for an unknown user take as long as a wrong password.

## ADDED Requirements

### Requirement: Argon2id is the default encoding
With no configuration, the default password encoder SHALL use Argon2id with 64 MiB of memory, 1 iteration, 4 threads, a 16-byte random salt and a 32-byte derived key. The encoded result SHALL name the algorithm and carry the memory, iterations, threads, salt and derived key needed to verify it.

#### Scenario: Default encoding
- **WHEN** a password is encoded by the default encoder
- **THEN** the result begins with `argon2id$65536$1$4$`
- **AND** it matches the same password

#### Scenario: Salted
- **WHEN** the same password is encoded twice
- **THEN** the two results differ and both match the password

### Requirement: bcrypt and scrypt are available
The library SHALL provide a bcrypt encoder, with a default cost of 10, and a scrypt encoder, with defaults N = 32768, r = 8, p = 1, a 16-byte random salt and a 32-byte derived key. Each SHALL match passwords it encoded, and a consumer SHALL be able to choose either in place of Argon2id. The scrypt encoded result SHALL name the algorithm and carry N, r, p, the salt and the derived key.

#### Scenario: scrypt round trip
- **WHEN** a password is encoded by the scrypt encoder with no options
- **THEN** the result begins with `scrypt$32768$8$1$`
- **AND** it matches the same password

#### Scenario: Consumer chooses bcrypt
- **WHEN** a consumer configures the bcrypt encoder with cost 12 and encodes a password
- **THEN** the result is a bcrypt hash at cost 12 that matches the password

### Requirement: Matching reads parameters from the stored hash
Matching SHALL derive the key using the parameters recorded in the stored hash, not the encoder's current parameters. It SHALL compare derived keys in constant time. A wrong password, a stored hash that cannot be parsed, and a stored hash of another algorithm SHALL each report no match.

#### Scenario: Older parameters
- **WHEN** an Argon2id encoder configured with 128 MiB of memory matches a password against a hash that encoder's algorithm produced with 64 MiB
- **THEN** it reports a match for the correct password

#### Scenario: Wrong password
- **WHEN** `hunter3` is matched against the encoding of `hunter2`
- **THEN** no match is reported

#### Scenario: Malformed or foreign hash
- **WHEN** a password is matched by the Argon2id encoder against `argon2id$65536$1$4$!!!$AAAA`, and against a scrypt hash
- **THEN** no match is reported in either case

### Requirement: Parameters are replaceable above a stated floor
Every encoding parameter SHALL be configurable. Constructing an encoder below the floor SHALL fail with a "weak parameters" error that names the parameter. The floors SHALL be:
- Argon2id: either at least 46 MiB of memory with at least 1 iteration, or at least 19 MiB of memory with at least 2 iterations; at least 1 thread; a salt of at least 16 bytes; a derived key of at least 32 bytes;
- bcrypt: a cost of at least 10;
- scrypt: N of at least 32768, r of at least 8, and p of at least 1.

#### Scenario: Weak Argon2id memory
- **WHEN** an Argon2id encoder is constructed with 19 MiB of memory and 1 iteration
- **THEN** construction fails with a "weak parameters" error naming memory and iterations

#### Scenario: Weak bcrypt cost
- **WHEN** a bcrypt encoder is constructed with cost 8
- **THEN** construction fails with a "weak parameters" error naming cost

#### Scenario: Consumer raises parameters
- **WHEN** a consumer constructs an Argon2id encoder with 128 MiB of memory and 3 iterations
- **THEN** new encodings begin with `argon2id$131072$3$`

### Requirement: bcrypt never matches by truncation
The bcrypt encoder SHALL refuse to encode a password longer than 72 bytes, with a "password too long" error that callers can identify. Matching a password longer than 72 bytes SHALL report no match, even when its first 72 bytes equal the stored password.

#### Scenario: Exactly 72 bytes
- **WHEN** a 72-byte password is encoded with bcrypt
- **THEN** encoding succeeds and the password matches

#### Scenario: 73 bytes refused
- **WHEN** a 73-byte password is encoded with bcrypt
- **THEN** encoding fails with an error identifiable as "password too long"

#### Scenario: Shared 72-byte prefix
- **WHEN** a 73-byte password whose first 72 bytes equal a stored 72-byte password is matched against that password's bcrypt hash
- **THEN** no match is reported

### Requirement: A mismatch costs the same work as a match
Matching against a hash SHALL perform the full key derivation its parameters specify, whether or not the password matches. A hash that the encoder produces when a caller is constructed SHALL therefore serve as a decoy: matching any presented password against it SHALL cost the same work as matching against a stored hash produced with the same algorithm and parameters.

The Argon2id and scrypt encoders SHALL additionally perform that derivation whatever the presented password's length. The bcrypt encoder is exempt from the length rule, and SHALL refuse an input longer than 72 bytes before deriving anything, because deriving would match by truncation; the cost of that refusal reveals only the length of the password the caller supplied.

#### Scenario: Decoy for an unknown user
- **WHEN** a decoy hash is encoded at construction, and matching a wrong password against it and matching a wrong password against a stored hash with the same parameters are each benchmarked
- **THEN** their median durations differ by less than 10 percent

#### Scenario: bcrypt refuses an over-length password rather than deriving
- **WHEN** a password longer than 72 bytes is matched against a bcrypt hash
- **THEN** it is refused without a derivation, and the refusal is not treated as a match

#### Scenario: Decoy follows consumer parameters
- **WHEN** a consumer configures Argon2id with 128 MiB of memory and a decoy hash is encoded with that encoder
- **THEN** matching against the decoy performs a derivation using 128 MiB of memory

### Requirement: Password bytes are hashed exactly as given
Encoders SHALL hash the password exactly as given, without trimming, case folding or Unicode normalization.

#### Scenario: Different normalization forms
- **WHEN** a password containing `é` as one code point is encoded, and the same text with `e` followed by a combining acute accent is matched against it
- **THEN** no match is reported

### Requirement: Salt failures are reported
When a salt cannot be read from the secure random source, encoding SHALL return an error wrapping the cause and SHALL NOT return an encoded hash.

#### Scenario: Random source fails
- **WHEN** the random source fails while a password is encoded
- **THEN** encoding returns an error wrapping that failure and no hash
