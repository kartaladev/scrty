# secrets-at-rest Specification

## Purpose

Keeps the long-lived secrets in security state (signing-key private material, MFA secrets and the provider ID token retained on sessions) unusable to anyone who holds only a database dump or write access to a table. Reads fail closed when a value cannot be opened, and the cipher is replaceable by the consumer.

## Requirements

### Requirement: Long-lived secrets are stored sealed
Durable stores SHALL seal signing-key private material, MFA secrets, the emailed MFA enrolment code and the provider ID token retained on sessions before writing them. The stored value, after undoing any text encoding, SHALL neither equal nor contain the plaintext. Sealing the same plaintext twice SHALL produce different stored values. Single-use OIDC flow values, handoff ID tokens and secrets stored only as one-way digests SHALL NOT be sealed.

The emailed enrolment code is short-lived, but it is sealed rather than digested: a six-digit code's plain digest is reversed by trying every value.

#### Scenario: Signing key column
- **WHEN** a signing key whose private material contains `PKCS8-SENTINEL` is stored and its column is read directly
- **THEN** the column's bytes do not contain `PKCS8-SENTINEL`
- **AND** loading the key through the store returns the original private material

#### Scenario: Encoded MFA secret column
- **WHEN** a user enrols with MFA secret `TOTP-SENTINEL`, and the stored column is read directly and decoded from its text encoding
- **THEN** neither the stored text nor the decoded bytes equal or contain `TOTP-SENTINEL`

#### Scenario: Emailed code column
- **WHEN** a device proof stores emailed code `042917`, and the stored column is read directly and decoded from its text encoding
- **THEN** neither the stored text nor the decoded bytes equal or contain `042917`
- **AND** reading the enrolment through the store returns `042917`

#### Scenario: Randomised sealing
- **WHEN** two users enrol with the same MFA secret
- **THEN** the two stored values differ

### Requirement: A sealed value is bound to its row
A sealed value SHALL open only for the record it was sealed for: an MFA secret for its user reference, an emailed enrolment code for its user reference and enrolment generation, a session ID token for its session identifier, and a signing key's private material for its key id, each within its own table. The emailed code's binding SHALL differ from the MFA secret's, so neither opens in the other's column. Opening a value that was copied to another record or another column, moved to another table, or whose record now names a different user, generation or key id SHALL fail. Opening a value whose stored bytes were altered SHALL fail.

#### Scenario: Secret copied to another user's row
- **WHEN** the sealed MFA secret of user `victim` is copied, out of band, into the enrolment of user `attacker`
- **THEN** reading `attacker`'s enrolment returns an error

#### Scenario: Enrolment reassigned to another user
- **WHEN** the user reference on `attacker`'s enrolment is changed, out of band, to `victim`
- **THEN** reading `victim`'s enrolment returns an error

#### Scenario: Value moved between tables
- **WHEN** a sealed session ID token is copied, out of band, into an MFA enrolment's secret
- **THEN** reading that enrolment returns an error

#### Scenario: Emailed code copied into the secret column
- **WHEN** the sealed emailed code of user `alice` is copied, out of band, into `alice`'s secret column
- **THEN** reading `alice`'s enrolment returns an error

#### Scenario: Emailed code copied to another user's row
- **WHEN** the sealed emailed code of user `victim` is copied, out of band, into the emailed-code column of user `attacker`
- **THEN** reading `attacker`'s enrolment returns an error

#### Scenario: Emailed code carried into a new generation
- **WHEN** the sealed emailed code issued on generation G1 is copied, out of band, back onto the same user's enrolment after it moved to generation G2
- **THEN** reading the enrolment returns an error

#### Scenario: Tampered byte
- **WHEN** a byte in the ciphertext of a stored sealed value is changed
- **THEN** reading the record returns an error

### Requirement: A value that cannot be opened fails closed
When a stored sealed value cannot be opened (wrong key, missing key, altered bytes, wrong binding, or a value that is not a sealed value), the store SHALL return an error. It SHALL NOT report the secret as absent, the emailed code as not issued, the user as not enrolled, or the record as not found. An emailed enrolment code whose expiry has passed is the one exception: it can no longer be charged or redeemed, so the store SHALL NOT open it, and SHALL read it back as no code while still reporting its expiry, which records that it was issued. Such a code therefore never fails a read, whatever key it was sealed under. A missing key SHALL be distinguishable from other open failures. Loading signing keys SHALL fail as a whole when any stored key cannot be opened. A secret SHALL be treated as absent only when nothing is stored.

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

#### Scenario: No stored secret
- **WHEN** a session created without a provider ID token is loaded
- **THEN** the session loads with no ID token and no error

### Requirement: A durable store holding sealed secrets cannot be built without a cipher
Constructing a durable signing-key, MFA enrolment or session store SHALL fail with a configuration error when no cipher is supplied. No configuration SHALL store those secrets unsealed.

#### Scenario: Cipher missing
- **WHEN** a durable MFA enrolment store is constructed without a cipher
- **THEN** construction returns a configuration error and no store

### Requirement: The default cipher uses a keyring with one named active key
The default cipher SHALL use AES-256-GCM with a keyring. The keyring SHALL have exactly one active key, which seals and opens, and zero or more retired keys, which only open. The active key and the retired keys SHALL be named separately, never distinguished by position. Creating a keyring SHALL fail with a configuration error when:
- no active key or more than one active key is given;
- a key is not exactly 32 bytes;
- a key id is empty or duplicated;
- a key id falls outside letters, digits, `.`, `_` and `-`, or is longer than 64 characters.

#### Scenario: Two active keys
- **WHEN** a keyring is created with two active keys
- **THEN** creation returns a configuration error

#### Scenario: Wrong key length
- **WHEN** a keyring is created with an active key of 16 bytes
- **THEN** creation returns a configuration error

#### Scenario: Retired key only opens
- **WHEN** a keyring has active key `k2` and retired key `k1`, and a new secret is stored
- **THEN** the new secret is sealed under `k2`
- **AND** a secret previously sealed under `k1` still opens

### Requirement: Retired-key values are re-sealed on read without disturbing concurrent writes
By default, when a signing-key or MFA enrolment store reads a signing key's private material or an MFA secret that opened under a key other than the active key, it SHALL re-seal the value under the active key. The re-seal SHALL change the stored value only if the record still holds the value that was read. A failed re-seal SHALL NOT fail the read. Re-sealing SHALL NOT happen during a read inside a transaction the caller attached. Session stores SHALL NOT re-seal on read. The emailed enrolment code SHALL NOT be re-sealed on read: it is accepted for at most ten minutes, and once expired it is not opened at all, so a key that sealed it is needed only for those ten minutes. Removing a key within ten minutes of its last use to seal a code fails a read of that user's enrolment until the code expires. A consumer SHALL be able to turn re-sealing on read off.

#### Scenario: Re-sealed under the active key
- **WHEN** an enrolment sealed under retired key `k1` is read, outside a caller transaction, through a keyring whose active key is `k2`
- **THEN** the read returns the secret
- **AND** a later read through a keyring containing only `k2` also returns the secret

#### Scenario: Concurrent re-enrolment is kept
- **WHEN** an unconfirmed enrolment sealed under a retired key is read, and a new pending enrolment with a new secret replaces it before the re-seal is written
- **THEN** the stored secret is the new secret

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

### Requirement: The cipher is replaceable
A consumer SHALL be able to supply their own cipher, such as one backed by a key management service, in place of the default. Stores SHALL use it for every seal and open, and the consumer's cipher errors SHALL propagate as store errors and fail closed.

#### Scenario: Consumer cipher used
- **WHEN** a durable session store is constructed with a consumer cipher, and a session with a provider ID token is saved and loaded
- **THEN** the consumer cipher is called once to seal and once to open, with additional data identifying that session

#### Scenario: Consumer cipher fails
- **WHEN** the consumer cipher returns an error while sealing an MFA secret
- **THEN** the enrolment returns an error wrapping it
- **AND** no enrolment is stored
