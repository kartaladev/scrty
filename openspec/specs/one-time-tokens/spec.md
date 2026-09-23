# one-time-tokens Specification

## Purpose

Issues short-lived, single-use credentials bound to a subject and a purpose, such as a magic link. They are stored only as hashes, spent exactly once, and can be checked without being spent, so a caller can refuse a redemption without costing the holder their credential.

## Requirements

### Requirement: Tokens are unguessable and bound to a purpose and subject
A one-time token manager SHALL serve exactly one purpose, and construction without a purpose SHALL fail with a configuration error. Issuing a token SHALL require a non-empty subject, which the library SHALL store and return unchanged without interpreting it. Each issued token SHALL consist of a record identifier and a secret of 32 bytes from the operating system's cryptographically secure random source. If the random source fails, issuance SHALL return an error and store nothing.

#### Scenario: Issued token
- **WHEN** a token is issued for subject `ada@example.com`
- **THEN** the caller receives a token containing a record identifier and a secret that decodes to 32 bytes

#### Scenario: Empty subject
- **WHEN** a token is issued with an empty subject
- **THEN** issuance fails and nothing is stored

#### Scenario: Missing purpose
- **WHEN** a manager is constructed with an empty purpose
- **THEN** construction fails with a configuration error

### Requirement: Secrets are hashed at rest
The token store SHALL receive only a hash of the token secret and, when present, a hash of the binding value. It SHALL never receive either in clear. Neither a stored record nor any record returned by the manager SHALL contain the secret.

#### Scenario: Store contents
- **WHEN** a token is issued and the stored record is inspected
- **THEN** it holds the SHA-256 hash of the secret
- **AND** the secret appears nowhere in the record

### Requirement: Tokens expire
Each token SHALL expire at its issue time plus the time-to-live. The default time-to-live SHALL be 15 minutes, replaceable by an option. A time-to-live of zero or less SHALL fail construction. A check SHALL fail for a token whose expiry has passed.

#### Scenario: Default expiry
- **WHEN** a token issued at 10:00 with default options is checked at 10:16
- **THEN** the check fails as invalid

#### Scenario: Consumer time-to-live
- **WHEN** the manager is configured with a 24-hour time-to-live, and a token issued at 10:00 is checked at 10:16 the same day
- **THEN** the check succeeds

### Requirement: Checking is uniform and has no side effects
Checking a token SHALL succeed only when all of the following hold:
- the token is well formed;
- its record exists and belongs to this manager's purpose;
- it has not been consumed;
- it has not expired;
- the secret matches;
- when the token was issued with a binding, the presented binding matches.

Secret and binding comparisons SHALL take constant time. Every failed condition, and any store failure during the check, SHALL return the same invalid-token error. A check SHALL write nothing, whether it succeeds or fails.

#### Scenario: Wrong secret and unknown record look alike
- **WHEN** one token is checked with a wrong secret and another with an unknown record identifier
- **THEN** both return the same invalid-token error

#### Scenario: Wrong purpose
- **WHEN** a token issued by the manager for purpose `magic-link` is checked by the manager for purpose `email-code` sharing the same store
- **THEN** the check returns the invalid-token error

#### Scenario: Check writes nothing
- **WHEN** a valid token is checked three times
- **THEN** each check succeeds
- **AND** the store receives no write

### Requirement: Binding is optional
When a token is issued with a binding value, redemption SHALL require the same value. A token issued without one SHALL ignore any presented binding.

#### Scenario: Bound token from another device
- **WHEN** a token issued with binding `nonce-a` is checked with binding `nonce-b`
- **THEN** the check returns the invalid-token error

#### Scenario: Unbound token
- **WHEN** a token issued without a binding is checked with any binding value
- **THEN** the binding does not affect the outcome

### Requirement: Consumption is atomic and follows a successful check
Consuming SHALL be possible only for a token that has passed a check. It SHALL mark the token consumed in one indivisible store operation that succeeds only if the token is still unconsumed. Of any number of callers consuming the same token, concurrently or one after another, at most one SHALL succeed, and every other SHALL receive the invalid-token error. An unknown token and an already-consumed token SHALL be indistinguishable to the consumer of the store.

#### Scenario: Racing redemptions
- **WHEN** 32 goroutines check the same valid token, all succeed, and then all consume it
- **THEN** exactly one consumption succeeds
- **AND** 31 receive the invalid-token error

#### Scenario: Second consumption keeps the first time
- **WHEN** a consumed token is consumed again
- **THEN** the invalid-token error is returned
- **AND** the recorded consumption time is unchanged

### Requirement: A refusal between check and consume does not spend the token
A caller SHALL be able to run its own refusal checks after a successful check and before consumption. A refusal or lookup failure at that point SHALL leave the token redeemable until it expires. The manager SHALL provide a single redemption operation that checks, runs the caller's refusal checks in order and then consumes. A refusal check's error SHALL be returned unchanged, and the token SHALL NOT be consumed. When marking the token consumed fails, redemption SHALL return the invalid-token error and no subject, and the failure SHALL be logged at error level.

#### Scenario: Policy refusal keeps the link
- **WHEN** a valid token is redeemed with a refusal check that denies because the user must enrol in MFA, and the same token is later redeemed with no refusal
- **THEN** the first redemption returns the enrolment error unchanged
- **AND** the second redemption succeeds

#### Scenario: Consumption failure is not a success
- **WHEN** a token passes its check and refusal checks, but the store fails while marking it consumed
- **THEN** redemption returns the invalid-token error and no subject

### Requirement: Issuance can be counted per subject over the manager's own window
The manager SHALL report how many tokens were issued for a subject, under its purpose, within its issuance window before now. Callers SHALL NOT be able to supply a different window. The issuance window SHALL default to one hour, be replaceable by an option, and fail construction when zero or less.

#### Scenario: Default window
- **WHEN** tokens for `ada@example.com` were issued 10 and 70 minutes ago
- **THEN** the issued count for `ada@example.com` is 1

#### Scenario: Other subjects and purposes are excluded
- **WHEN** a token for `bob@example.com`, and a token for `ada@example.com` under another purpose, were issued 5 minutes ago
- **THEN** neither is included in the count for `ada@example.com`

### Requirement: Purging cannot free issuance quota or break live tokens
The manager's purge SHALL remove only tokens of its own purpose that both:
- have expired;
- were issued strictly before now minus its issuance window.

A token store SHALL refuse a purge with a zero cutoff and delete nothing. When the configured store cannot purge, the manager's purge SHALL fail with a purge-unsupported error rather than report zero removed.

#### Scenario: Expired but still counted
- **WHEN** a token issued 30 minutes ago with a 15-minute time-to-live and a 1-hour issuance window is purged
- **THEN** it is not removed
- **AND** the issued count still includes it

#### Scenario: Unexpired long-lived token
- **WHEN** a token issued 2 hours ago with a 24-hour time-to-live is purged
- **THEN** it is not removed

#### Scenario: Consumer store without purge support
- **WHEN** the manager is configured with a consumer's store that cannot purge, and it purges
- **THEN** the purge-unsupported error is returned

#### Scenario: Zero cutoff
- **WHEN** a store is asked to purge before the zero time
- **THEN** it refuses and deletes nothing

### Requirement: The in-memory store isolates stored records
When no store is configured, the manager SHALL use an in-memory store. That store SHALL hold its own copies of hashes and records, so mutating a slice passed in or returned cannot change stored state. It SHALL preserve an absent binding hash as absent, and it SHALL implement purging. Any implementation of the token store contract SHALL be usable in its place.

#### Scenario: Returned hash is a copy
- **WHEN** a caller overwrites the bytes of a hash returned by the in-memory store and the record is read again
- **THEN** the stored hash is unchanged
