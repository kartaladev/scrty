# password-encoding Specification

## Purpose

Hashes and verifies passwords with a safe default algorithm and replaceable parameters above a stated floor. Verification costs the same whether or not a password matches, so a caller can make a login for an unknown user take as long as a wrong password.

## Requirements

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

### Requirement: Password reuse is not checked unless the consumer enables it
By default the library SHALL NOT check a new password against earlier ones, and SHALL NOT record password history. Reuse checking SHALL be enabled only by the consumer constructing a reuse guard with a password-history port, an encoder and a depth N, and calling it from their own password-change code. No other library component, including the identity provisioner's update and the password-change resolve endpoint, SHALL check or record history on its own.

#### Scenario: Off by default
- **WHEN** no reuse guard is constructed, and a user changes their password from `hunter2` to `hunter2` through the consumer's change function
- **THEN** the change succeeds
- **AND** no history is read or written

#### Scenario: Provisioner update records nothing
- **WHEN** a reuse guard exists, and a user's password hash is written through the identity provisioner's update (as a provider-mirrored password is on every federated login)
- **THEN** no history entry is recorded and no reuse check runs

### Requirement: The reuse guard refuses the current password and the N−1 before it
A reuse guard of depth N SHALL refuse a candidate password that matches the user's current hash, taken from the user record the caller passes, or one of that user's N−1 most recent retired hashes. The same record SHALL key both the history and the write, so a change can never check one user's history and write another user's password. The refusal SHALL be the password-reused error. A candidate matching none of them SHALL be accepted. An absent current hash SHALL match nothing and SHALL NOT be an error.

#### Scenario: Depth 3
- **WHEN** a guard of depth 3 is used, and a user whose provisioned password was `p1` changes it through the guard to `p2`, then `p3`, then `p4`
- **THEN** changing to `p4`, to `p3` or to `p2` is refused with the password-reused error
- **AND** changing to `p1` succeeds

#### Scenario: Depth 1 refuses only the current password
- **WHEN** a guard of depth 1 is used, and a user whose current password is `p2` and whose previous password was `p1` changes their password
- **THEN** changing to `p2` is refused with the password-reused error
- **AND** changing to `p1` succeeds

#### Scenario: User with no local password yet
- **WHEN** a guard is asked to check a candidate for a user with no current hash and no history
- **THEN** the candidate is accepted

### Requirement: Reuse is detected by verifying the candidate against each stored hash
The reuse guard SHALL detect reuse by verifying the candidate against each stored hash with an encoder's matching, reading the algorithm and parameters from the stored hash. It SHALL NOT encode the candidate and compare bytes. By default the guard SHALL match with its own encoder and with the library's Argon2id, bcrypt and scrypt encoders, so a hash any built-in encoder wrote, under any parameters, still matches. The consumer SHALL be able to replace the additional matchers. The guard's own encoder SHALL always be included.

#### Scenario: Older parameters still match
- **WHEN** a guard whose encoder is Argon2id at 128 MiB checks `p1` for a user whose history holds `p1` encoded by Argon2id at 64 MiB
- **THEN** the candidate is refused with the password-reused error

#### Scenario: Retired algorithm still matches
- **WHEN** a guard whose encoder is Argon2id, with no matchers configured, checks `p1` for a user whose history holds a bcrypt hash of `p1` at cost 12
- **THEN** the candidate is refused with the password-reused error

#### Scenario: Consumer matcher for their own algorithm
- **WHEN** a consumer configures the guard with an extra matcher for an algorithm of their own, and checks `p1` for a user whose history holds that algorithm's hash of `p1`
- **THEN** the candidate is refused with the password-reused error

### Requirement: A successful change retires the old hash and bounds history to N−1
When the reuse guard changes a password, it SHALL run these steps in order, stopping at the first failure:
1. read the user's recent history;
2. check for reuse;
3. retire the current hash, keeping only the newest N−1 retired hashes;
4. encode the candidate with its encoder;
5. hand the user record, the new hash and the change time to the consumer's write.

Retiring a hash identical, byte for byte, to the user's newest retired hash SHALL add no entry. A depth of 1 SHALL keep no retired hashes. History for one user SHALL NOT affect another.

#### Scenario: Record after success, and pruning
- **WHEN** a guard of depth 3 is used, and a user changes from `p1` to `p2`, `p3`, `p4` and `p5` in turn
- **THEN** the user's history holds exactly the hashes of `p4` and `p3`, newest first
- **AND** the stored password is the hash the guard handed to the write for `p5`

#### Scenario: Retry after a failed write does not double-count
- **WHEN** a guard of depth 3 is used, a user with current password `p2` and history `p1` changes to `p3`, the consumer's write fails, and the change is retried and succeeds
- **THEN** the history holds exactly `p2` and `p1`

#### Scenario: Another user's history is not consulted
- **WHEN** user `a` has history holding `p1`, and user `b` changes their password to `p1` through a guard
- **THEN** user `b`'s change succeeds

### Requirement: A change through the reuse guard records when it happened
The reuse guard SHALL hand the consumer's write the time of the change, read from the guard's clock, whose default is the system clock and which the consumer SHALL be able to replace. The library SHALL provide a ready-made write over any user provisioner that updates the user's password and password-changed time together, so a consumer of such a provisioner records the time with no code of their own. A write that ignores the time SHALL leave the stored time unchanged, and the documentation of the write SHALL say that this exempts the user from password-age policy.

#### Scenario: Ready-made write records the time
- **WHEN** a guard with a fixed clock at 2031-06-01 changes a user's password through the ready-made provisioner write
- **THEN** the provisioner is updated naming the new hash and the password-changed time 2031-06-01, and nothing else

#### Scenario: Consumer write receives the time
- **WHEN** a consumer's own write is used with a guard whose clock is replaced with one returning `T`
- **THEN** the write receives the user record, the new hash and `T`

#### Scenario: Write that ignores the time
- **WHEN** a consumer's write stores only the hash and ignores the time
- **THEN** the change succeeds and the stored password-changed time is unchanged

### Requirement: The reuse guard fails closed
The reuse guard SHALL refuse a change it cannot check or record. A failure reading history SHALL refuse the change with the history-unavailable error, and SHALL NOT call the consumer's write. A failure retiring the current hash SHALL refuse the change with the history-unavailable error, and SHALL NOT call the consumer's write, so the stored password is unchanged. The history-unavailable error SHALL carry fixed library text, with the port's error reachable by identity and type. An error from the consumer's write SHALL be returned unchanged.

#### Scenario: Lookup failure refuses
- **WHEN** the history port fails to read, and a user changes to a password never used before
- **THEN** the change is refused with the history-unavailable error
- **AND** the consumer's write is not called

#### Scenario: Record failure refuses before the password changes
- **WHEN** the history port reads successfully but fails to retire the current hash
- **THEN** the change is refused with the history-unavailable error
- **AND** the consumer's write is not called and the stored password is unchanged

#### Scenario: Atomic with the default identity store
- **WHEN** the consumer runs a change inside one transaction, with a write that updates the password through the default identity store, and then rolls the transaction back
- **THEN** neither the new password nor the retired history entry is stored

### Requirement: Reuse refusals and history failures carry no credential
The password-reused and history-unavailable errors SHALL NOT contain the candidate password, any stored hash, or the user reference in their text. The reuse guard SHALL write no log record, and SHALL NOT keep the candidate after the change returns.

#### Scenario: Reuse refusal text
- **WHEN** a change to `Tr0ub4dor&3` is refused as reused for user `u-123`
- **THEN** the error text contains neither `Tr0ub4dor&3`, nor any part of a stored hash, nor `u-123`

#### Scenario: Port failure quoting a hash
- **WHEN** the history port fails with an error whose text quotes a stored hash
- **THEN** the returned error's text does not contain that hash
- **AND** the port's error is reachable by identity

### Requirement: Reuse guard wiring mistakes fail at construction
Constructing a reuse guard SHALL fail with a configuration error naming the mistake when it is given no history port (including a typed-nil one), no encoder, a depth of zero or less, an absent matcher, or an absent clock. Building the ready-made provisioner write SHALL fail with a configuration error when it is given no provisioner (including a typed-nil one). A check or change given no user record, or a change given no write, SHALL fail with a configuration error and SHALL read and write nothing. The ready-made provisioner write, called directly with no user record, SHALL fail the same way and SHALL write nothing. The depth SHALL have no default and SHALL be required. No such mistake SHALL surface first at a change.

#### Scenario: Depth zero
- **WHEN** a reuse guard is constructed with depth 0, or with depth −1
- **THEN** construction fails with a configuration error and no guard is returned

#### Scenario: Missing port
- **WHEN** a reuse guard is constructed with a depth of 5 and no history port
- **THEN** construction fails with a configuration error naming the history port

#### Scenario: Consumer's own history port
- **WHEN** a consumer constructs a reuse guard over their own history implementation, over their own table, with depth 5
- **THEN** construction succeeds, and a reused password is refused using the consumer's history
