## ADDED Requirements

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
