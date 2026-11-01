# Spec Delta

## MODIFIED Requirements

### Requirement: The cipher is replaceable
A consumer SHALL be able to supply their own cipher, such as one backed by a key management service, in place of the default. Stores SHALL use it for every seal and open, and the consumer's cipher errors SHALL propagate as store errors and fail closed.

Every seal and open SHALL carry the context of the store operation it serves, and the default cipher SHALL pass that context to its keyring. Neither the default cipher nor the default keyring performs input or output, and both SHALL answer whatever state the context is in. A cipher SHALL be able to mark a failure to reach its keys with the unavailable error. The adapter that lets a cipher seal sessions SHALL report that error as the session cipher-unavailable error, and SHALL pass context errors through unchanged.

#### Scenario: Consumer cipher used
- **WHEN** a durable session store is constructed with a consumer cipher, and a session with a provider ID token is saved and loaded
- **THEN** the consumer cipher is called once to seal and once to open, with additional data identifying that session

#### Scenario: Consumer cipher fails
- **WHEN** the consumer cipher returns an error while sealing an MFA secret
- **THEN** the enrolment returns an error wrapping it
- **AND** no enrolment is stored

#### Scenario: The cipher receives the store's context
- **WHEN** an MFA enrolment is stored and read through a consumer cipher that records its context, under a context carrying a value
- **THEN** the seal and the open each carry that value

#### Scenario: The default cipher answers under a cancelled context
- **WHEN** the default cipher seals a value and opens it again under a context that is already cancelled
- **THEN** both succeed, and the value opens to the original plaintext

#### Scenario: A marked outage reaches sessions as unavailable
- **WHEN** a session is loaded through the session adapter over a consumer cipher whose open fails with an error that wraps the unavailable error
- **THEN** the error matches the session cipher-unavailable error
- **AND** it does not match the session-unreadable error

### Requirement: A value that cannot be opened fails closed
When a stored sealed value cannot be opened (wrong key, missing key, altered bytes, wrong binding, or a value that is not a sealed value), the store SHALL return an error. It SHALL NOT report the secret as absent, the emailed code as not issued, the user as not enrolled, or the record as not found. An emailed enrolment code whose expiry has passed is the one exception: it can no longer be charged or redeemed, so the store SHALL NOT open it, and SHALL read it back as no code while still reporting its expiry, which records that it was issued. Such a code therefore never fails a read, whatever key it was sealed under. A missing key SHALL be distinguishable from other open failures. A failure to reach the keys that the cipher marks with the unavailable error, and a failure caused by the context of the read ending, SHALL each be distinguishable from a value that does not open and from a missing key. Loading signing keys SHALL fail as a whole when any stored key cannot be opened. A secret SHALL be treated as absent only when nothing is stored.

#### Scenario: MFA secret unreadable
- **WHEN** a user's enrolment exists but its secret cannot be opened
- **THEN** reading the enrolment returns an error
- **AND** the read does not report the user as not enrolled

#### Scenario: Emailed code unreadable
- **WHEN** a user's enrolment holds an emailed code that cannot be opened
- **THEN** reading the enrolment returns an error
- **AND** the read does not report the enrolment as holding no emailed code

#### Scenario: One signing key unreadable
- **WHEN** three signing keys are stored and one of them cannot be opened
- **THEN** loading all signing keys returns an error and returns no keys

#### Scenario: Session with unreadable ID token
- **WHEN** a session exists whose provider ID token cannot be opened
- **THEN** loading the session returns an unreadable-session error that is distinguishable from "session not found"

#### Scenario: Missing key is distinguishable
- **WHEN** a value sealed under key `2026-03` is read through a keyring that no longer contains `2026-03`
- **THEN** the error reports an unknown key id, distinguishable from a failure caused by altered bytes

#### Scenario: An outage is distinguishable
- **WHEN** an MFA enrolment is read through a consumer cipher whose open fails with an error that wraps the unavailable error
- **THEN** reading the enrolment returns an error that matches the unavailable error
- **AND** it matches neither the decryption-failed nor the unknown-key-id error

#### Scenario: No stored secret
- **WHEN** a session created without a provider ID token is loaded
- **THEN** the session loads with no ID token and no error

### Requirement: Retired-key values are re-sealed on read without disturbing concurrent writes
By default, when a signing-key or MFA enrolment store reads a signing key's private material or an MFA secret that opened under a key other than the active key, it SHALL re-seal the value under the active key. The re-seal SHALL change the stored value only if the record still holds the value that was read. A failed re-seal SHALL NOT fail the read, including one that fails because the cipher cannot reach its keys or the context of the read has ended. The re-seal SHALL carry the context of the read it follows. Re-sealing SHALL NOT happen during a read inside a transaction the caller attached. Session stores SHALL NOT re-seal on read. The emailed enrolment code SHALL NOT be re-sealed on read: it is accepted for at most ten minutes, and once expired it is not opened at all, so a key that sealed it is needed only for those ten minutes. Removing a key within ten minutes of its last use to seal a code fails a read of that user's enrolment until the code expires. A consumer SHALL be able to turn re-sealing on read off.

#### Scenario: Re-sealed under the active key
- **WHEN** an enrolment sealed under retired key `k1` is read, outside a caller transaction, through a keyring whose active key is `k2`
- **THEN** the read returns the secret
- **AND** a later read through a keyring containing only `k2` also returns the secret

#### Scenario: Concurrent re-enrolment is kept
- **WHEN** an unconfirmed enrolment sealed under a retired key is read, and a new pending enrolment with a new secret replaces it before the re-seal is written
- **THEN** the stored secret is the new secret

#### Scenario: A re-seal that cannot reach the keys does not fail the read
- **WHEN** an enrolment sealed under a retired key is read, and the cipher opens it but fails with the unavailable error when asked for its active key or asked to seal
- **THEN** the read returns the secret
- **AND** the stored value is unchanged

#### Scenario: Abandoned code after its key is removed
- **WHEN** a device is proven with an emailed code at 10:00 under key `k1`, the code is never redeemed, and at 11:00 the enrolment is read through a keyring that no longer holds `k1`
- **THEN** the read succeeds with no emailed code and with the code's expiry of 10:10
- **AND** the user can begin again

#### Scenario: Expired code is not opened
- **WHEN** an enrolment holds an emailed code whose ciphertext was altered and whose expiry has passed
- **THEN** the read succeeds with no emailed code and with the code's expiry

#### Scenario: Emailed code is not rewritten on read
- **WHEN** an enrolment whose emailed code is sealed under retired key `k1` is read through a keyring whose active key is `k2`
- **THEN** the read returns the emailed code
- **AND** the stored emailed code is unchanged and still opens only with `k1`

#### Scenario: Sessions are not rewritten on read
- **WHEN** a session whose ID token is sealed under a retired key is loaded and then deleted
- **THEN** the session remains deleted
- **AND** the load did not rewrite the stored ID token

#### Scenario: Inside a caller's transaction
- **WHEN** an enrolment sealed under a retired key is read inside a transaction the caller attached
- **THEN** the stored value is not rewritten by that read

#### Scenario: Re-seal turned off
- **WHEN** a store configured not to re-seal on read reads a value sealed under retired key `k1`
- **THEN** the stored value is unchanged and still opens only with `k1`
