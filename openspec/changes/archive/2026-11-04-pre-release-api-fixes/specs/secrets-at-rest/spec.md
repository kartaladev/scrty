# Spec Delta

## MODIFIED Requirements

### Requirement: Retired-key values are re-sealed on read without disturbing concurrent writes
By default, when a signing-key or MFA enrolment store reads a signing key's private material or an MFA secret that opened under a key other than the active key, it SHALL re-seal the value under the active key. The re-seal SHALL change the stored value only if the record still holds the value that was read, so a record deleted before the re-seal is written stays deleted. A failed re-seal SHALL NOT fail the read, including one that fails because the cipher cannot reach its keys or the context of the read has ended. The re-seal SHALL carry the context of the read it follows. Re-sealing SHALL NOT happen during a read inside a transaction the caller attached. Session stores SHALL NOT re-seal on read. The emailed enrolment code SHALL NOT be re-sealed on read: it is accepted for at most ten minutes, and once expired it is not opened at all, so a key that sealed it is needed only for those ten minutes. Removing a key within ten minutes of its last use to seal a code fails a read of that user's enrolment until the code expires. A consumer SHALL be able to turn re-sealing on read off.

#### Scenario: Re-sealed under the active key
- **WHEN** an enrolment sealed under retired key `k1` is read, outside a caller transaction, through a keyring whose active key is `k2`
- **THEN** the read returns the secret
- **AND** a later read through a keyring containing only `k2` also returns the secret

#### Scenario: Concurrent re-enrolment is kept
- **WHEN** an unconfirmed enrolment sealed under a retired key is read, and a new pending enrolment with a new secret replaces it before the re-seal is written
- **THEN** the stored secret is the new secret

#### Scenario: A deleted signing key stays deleted
- **WHEN** a signing key sealed under a retired key is read, and it is deleted before the re-seal is written
- **THEN** the key is not stored again

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
