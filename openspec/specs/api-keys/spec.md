# api-keys Specification

## Purpose

Gives machine clients (services, jobs and integrations) a credential they present on every request without a session. It is shown once, stored only as a digest, recognisable by its prefix, bound to a service principal with scopes, and revocable.

## Requirements

### Requirement: A key's secret is shown only at issuance
Issuing a key SHALL return the presented key once, together with the key's record. Neither the record, any record read back from the store, nor any listing of a principal's keys SHALL contain the secret. Each key SHALL carry a secret of 32 bytes read from the operating system's cryptographically secure random source. If the random source fails, issuance SHALL return an error and store nothing.

#### Scenario: Issued key
- **WHEN** a key is issued for service principal `svc-billing`
- **THEN** the caller receives the presented key and a record naming `svc-billing`
- **AND** the record does not contain the secret

#### Scenario: Listing does not reveal secrets
- **WHEN** the keys of `svc-billing` are listed
- **THEN** no listed record contains a secret

#### Scenario: Random source failure
- **WHEN** the random source fails during issuance
- **THEN** issuance returns an error
- **AND** the store receives no write

### Requirement: Keys are recognisable by their prefix
A presented key SHALL consist of the configured prefix, an underscore, the key's record identifier, a dot and the secret. The default prefix SHALL be `sk`. A consumer SHALL be able to set another prefix of 1 to 16 lowercase ASCII letters or digits. Any other prefix SHALL fail construction with a configuration error. Verification SHALL reject a key whose prefix differs, or whose shape is wrong, without consulting the store.

#### Scenario: Default prefix
- **WHEN** a key is issued with default options
- **THEN** the presented key starts with `sk_`

#### Scenario: Consumer prefix
- **WHEN** the manager is configured with prefix `acme` and a key is issued
- **THEN** the presented key starts with `acme_`

#### Scenario: Wrong prefix
- **WHEN** a key issued with prefix `sk` is verified by a manager configured with prefix `acme`
- **THEN** verification fails with the verification-failed error
- **AND** the store is not consulted

#### Scenario: Invalid prefix
- **WHEN** a manager is constructed with prefix `Bad-Prefix`
- **THEN** construction fails with a configuration error

### Requirement: Secrets are stored only as digests
The key store SHALL receive only a one-way digest of the secret, never the secret. Verification SHALL compare the digest of the presented secret with the stored digest in constant time. The default digest SHALL be SHA-256. A consumer SHALL be able to replace it, and every issuance and verification SHALL then use the replacement.

#### Scenario: Store contents
- **WHEN** a key is issued and the stored record is inspected
- **THEN** it holds the SHA-256 digest of the secret
- **AND** the secret appears nowhere in the record

#### Scenario: Consumer digest
- **WHEN** the manager is configured with a consumer's digest function, and a key is issued and then verified
- **THEN** the stored digest is that function's output for the secret
- **AND** verification succeeds

### Requirement: Keys are bound to a service principal
Issuing a key SHALL require a non-empty principal reference, and SHALL accept a principal name, a list of scopes and a lifetime. The library SHALL store and return the reference, name and scopes unchanged without interpreting them. A successfully verified key SHALL yield a principal of the service kind with that reference, that name and exactly those scopes. The authentication SHALL carry the key's record identifier and the `api-key` first-factor kind.

#### Scenario: Principal from a verified key
- **WHEN** a key issued for `svc-billing` named `nightly export` with scopes `invoices:read` and `invoices:export` is verified
- **THEN** the principal is a service principal with reference `svc-billing` and name `nightly export`
- **AND** its scopes are exactly `invoices:read` and `invoices:export`
- **AND** the authentication records the `api-key` first factor

#### Scenario: Empty principal
- **WHEN** a key is issued with an empty principal reference
- **THEN** issuance fails and nothing is stored

### Requirement: A key expires when issued with a lifetime
A key issued with a positive lifetime SHALL expire at its issue time plus that lifetime, and SHALL be accepted only while now is not after its expiry. A key issued with a lifetime of zero or less SHALL never expire, and this SHALL be documented on the issuance operation.

#### Scenario: Expired key
- **WHEN** a key is issued with a lifetime of 7 days and verified 8 days later
- **THEN** verification fails with the verification-failed error

#### Scenario: Non-expiring key
- **WHEN** a key is issued with a lifetime of zero and verified 5 years later
- **THEN** verification succeeds

### Requirement: Verification failures are uniform
Verification SHALL fail with the same verification-failed error for:
- a malformed key or a wrong prefix;
- an unknown key identifier or a wrong secret;
- an expired key or a revoked key;
- a store failure.

No error or log record SHALL contain the presented key.

#### Scenario: Revoked and unknown look alike
- **WHEN** a revoked key and a key with an unknown identifier are verified
- **THEN** both fail with the same verification-failed error

#### Scenario: Store outage
- **WHEN** the store returns a connection error during verification
- **THEN** verification fails with the verification-failed error

### Requirement: Revocation takes effect immediately
Revoking a key SHALL make every later verification of it fail. Revoking an unknown key SHALL return a key-not-found error.

#### Scenario: Revoked key refused
- **WHEN** a key is verified successfully, revoked, and verified again
- **THEN** the second verification fails with the verification-failed error

#### Scenario: Unknown key
- **WHEN** a key identifier that was never issued is revoked
- **THEN** the key-not-found error is returned

### Requirement: Keys can be rotated
Rotating a key SHALL issue a new key for the same principal reference, name and scopes, with the lifetime the caller gives, and then revoke the old key. The new key SHALL be returned only when both steps succeed. Rotating an unknown key SHALL fail and issue nothing. The two steps SHALL be atomic when rotation runs inside a store transaction the caller attached, and SHALL otherwise be documented as two separate writes.

#### Scenario: Rotation
- **WHEN** a key is rotated
- **THEN** the new key verifies with the same principal and scopes
- **AND** the old key fails with the verification-failed error

#### Scenario: Revoke fails inside a transaction
- **WHEN** a key is rotated inside an attached transaction, revoking the old key fails, and the transaction is rolled back
- **THEN** no new key exists
- **AND** the old key still verifies

### Requirement: Last use is recorded without affecting verification
A successful verification SHALL record the key's last-use time. A failure to record SHALL NOT fail verification.

#### Scenario: Recorded
- **WHEN** a key is verified at 10:00
- **THEN** its record reports a last-use time of 10:00

#### Scenario: Recording failure
- **WHEN** the store fails to record last use
- **THEN** verification still succeeds

### Requirement: Requests authenticate with a key in the Authorization header
The API key interceptor SHALL read a key only from the `Authorization` header, after the literal scheme prefix `ApiKey ` by default. A consumer SHALL be able to configure another scheme prefix. A request without that prefix SHALL pass through unauthenticated, without consulting the limiter. A request with the prefix SHALL be authenticated or refused, and a refused request SHALL NOT reach later handlers.

#### Scenario: No key
- **WHEN** a request carries no `Authorization` header
- **THEN** it passes through unauthenticated
- **AND** the limiter is not consulted

#### Scenario: Key in the query string
- **WHEN** a request carries a valid key only in the query parameter `api_key`
- **THEN** it passes through unauthenticated

#### Scenario: Consumer scheme
- **WHEN** the interceptor is configured with scheme prefix `Service ` and a request carries `Authorization: Service <valid key>`
- **THEN** the request is authenticated as the key's service principal

### Requirement: Key authentication is stateless
A request authenticated by key SHALL create no session. After a successful verification, the interceptor SHALL evaluate the stateless-authentication policy phase with the `api-key` first factor. A deny SHALL refuse the request with the policy's reason, and the principal SHALL NOT reach later handlers.

#### Scenario: No session created
- **WHEN** a request is authenticated by a valid key
- **THEN** no session is created

#### Scenario: Consumer policy refuses a key
- **WHEN** a consumer policy in the stateless-authentication phase denies requests outside office hours, and a valid key is presented outside office hours
- **THEN** the request is refused with that policy's reason

### Requirement: Failed key verifications are throttled per source
The interceptor SHALL check the request's source with a source guard before verifying, and SHALL record a failure for that source when verification fails. A throttled or unattributable source SHALL be refused with the same error as a key that fails verification, without verifying. A refusal by the stateless-authentication phase of a key that verified SHALL NOT be recorded. The default limit SHALL be 20 failures per source per minute, from a limiter used by no other flow. A consumer SHALL be able to replace the limiter, and a nil limiter SHALL fail construction with a configuration error.

#### Scenario: Guessing from one source
- **WHEN** one source presents 20 invalid keys within a minute and then presents a valid key
- **THEN** the valid key is refused with the verification-failed error without verification

#### Scenario: Policy refusal does not count
- **WHEN** a source presents a valid key that a stateless policy denies 25 times within a minute, and then a valid key that is allowed
- **THEN** the allowed key authenticates

#### Scenario: Consumer limiter
- **WHEN** the interceptor is configured with a consumer's shared limiter
- **THEN** every check and failure for key attempts goes to that limiter

#### Scenario: Nil limiter
- **WHEN** the interceptor is configured with a limiter interface holding a nil pointer
- **THEN** construction fails with a configuration error

### Requirement: The in-memory key store is the default and isolates records
When no store is configured, the manager SHALL use an in-memory store that holds its own copies of records, so mutating scopes or digests passed in or returned cannot change stored state. A lookup, revocation or last-use update for an unknown key SHALL return the key-not-found error. Any implementation of the key store contract SHALL be usable in its place.

#### Scenario: Returned scopes are a copy
- **WHEN** a caller overwrites the scopes of a record returned by the in-memory store and the record is read again
- **THEN** the stored scopes are unchanged

#### Scenario: Consumer store
- **WHEN** the manager is configured with a consumer's store
- **THEN** every issue, verify, revoke, rotate and list operation is served by that store

### Requirement: Key throttle refusal logs are sampled
Throttle refusal records written by the interceptor SHALL be written through the source guard's log sampler with a reporter, and SHALL contain no presented key or secret.

#### Scenario: Throttled scanner
- **WHEN** one throttled source presents 300 keys within one minute
- **THEN** one throttle record is written for that source in that minute
- **AND** no written record contains any presented key
