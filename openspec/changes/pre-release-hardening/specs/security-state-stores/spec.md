# Spec Delta

## ADDED Requirements

### Requirement: Store guarantees hold at the database's weaker default isolations
Every transaction a durable store opens for itself, and every statement it runs outside a transaction, SHALL run at READ COMMITTED whatever the database's or role's default isolation is.

#### Scenario: Repeatable-read database default
- **WHEN** the database's default isolation is REPEATABLE READ and 16 failed logins for one username are recorded concurrently
- **THEN** every failure is counted and none is reported as a database failure

#### Scenario: Overlapping recovery-code replacements under a repeatable-read default
- **WHEN** the database's default isolation is REPEATABLE READ and two replacements of `u-1`'s saved-code set overlap
- **THEN** only the later set's codes exist afterwards, and no code of the earlier set matches

#### Scenario: Concurrent provisioning under a repeatable-read default
- **WHEN** the database's default isolation is REPEATABLE READ and 8 provisions of the same username run concurrently
- **THEN** exactly one succeeds and the other 7 report that the user exists

### Requirement: An operation that needs READ COMMITTED refuses a caller's stronger transaction
An operation whose guarantee depends on READ COMMITTED SHALL refuse to run inside a caller's transaction at a stronger isolation, with an error that names the isolation found, rather than silently weakening the guarantee. Operations whose guarantees hold at any isolation SHALL join a caller's transaction at any isolation.

#### Scenario: Caller's repeatable-read transaction
- **WHEN** a caller attaches a REPEATABLE READ transaction and replaces `u-1`'s saved-code set inside it
- **THEN** the replacement is refused with an error naming the isolation level, and the caller's transaction is left usable

### Requirement: A bounded insert is decided under a per-subject lock
The one-time token store and the passkey credential store SHALL offer an insert bounded by a limit: it SHALL count the subject's matching records within the window and insert only while the count is below the limit, as one atomic operation serialised per subject and purpose, and SHALL report whether it inserted. Of any number of concurrent bounded inserts for one subject, the number that succeed SHALL NOT take the count past the limit. A refused insert SHALL write nothing.

#### Scenario: Concurrent bounded inserts
- **WHEN** 20 bounded inserts for one subject and purpose run concurrently with a limit of 5 and no existing records
- **THEN** exactly 5 report inserted and 5 records exist

#### Scenario: Different subjects do not contend
- **WHEN** bounded inserts for `u-1` and `u-2` run concurrently, each with a limit of 1
- **THEN** both insert

#### Scenario: Limit already reached
- **WHEN** a subject already holds 5 records within the window and a bounded insert with a limit of 5 is made
- **THEN** it reports not inserted and no record is written

### Requirement: Deleting a user's sessions ends in a bounded number of passes
Deleting every session of a user, every session of an external session, or every session of a user from an external issuer SHALL finish within a bounded number of passes even while sessions for that user are being created concurrently. When the bound is reached, it SHALL return an identifiable error saying the deletion did not settle, and SHALL NOT loop until its context ends.

#### Scenario: Concurrent logins during a revoke-all
- **WHEN** sessions for `u-1` are created in a tight loop while every session of `u-1` is deleted
- **THEN** the deletion returns, either having settled or with the did-not-settle error, well before its context deadline

## MODIFIED Requirements

### Requirement: MFA enrolment confirmation is recorded once
An MFA enrolment SHALL start unconfirmed. Confirming it SHALL record the confirmation time and the confirming time step only if the enrolment is still unconfirmed and is still on the enrolment generation the caller names, and SHALL report whether this call confirmed it. A caller naming no generation SHALL confirm nothing. Confirming SHALL clear any emailed enrolment code outstanding on the enrolment, and SHALL NOT lower the recorded time step: where a device proof already recorded a later step, that step SHALL be kept. Storing a new pending enrolment SHALL replace an unconfirmed enrolment's secret, clear its accepted time step, start a new enrolment generation, and clear its device proof, its emailed code, that code's expiry and its attempt count. It SHALL be refused with the already-enrolled outcome when the user's enrolment is confirmed, leaving that enrolment unchanged. The check and the write SHALL be a single conditional write.

#### Scenario: First confirmation
- **WHEN** a new enrolment on generation G1 is confirmed at time T naming G1
- **THEN** the confirmation succeeds and the enrolment reads as confirmed at T

#### Scenario: Second confirmation
- **WHEN** a confirmed enrolment is confirmed again at time T2
- **THEN** the second confirmation is refused
- **AND** the recorded confirmation time is unchanged

#### Scenario: Confirmation naming a replaced generation
- **WHEN** a pending enrolment on generation G1 is replaced by one on G2, and a confirmation naming G1 is made
- **THEN** the confirmation is refused and the enrolment reads as unconfirmed on G2

#### Scenario: Pending enrolment replaced
- **WHEN** an unconfirmed enrolment exists and a new pending enrolment with a new secret is stored for the same user
- **THEN** the enrolment reads as unconfirmed with the new secret and no accepted time step

#### Scenario: Confirmed enrolment not replaced
- **WHEN** a confirmed enrolment exists and a new pending enrolment is stored for the same user
- **THEN** the store refuses it with the already-enrolled outcome
- **AND** the enrolment still reads as confirmed with its original secret

#### Scenario: A new pending enrolment starts a new generation
- **WHEN** a pending enrolment on generation G1 has its device proven with an emailed code, and a new pending enrolment on generation G2 is stored for the same user
- **THEN** the enrolment reads with generation G2, no device-proof time, no emailed code, no code expiry and no charged attempts

#### Scenario: Confirmation keeps a later device-proof step
- **WHEN** a pending enrolment's device is proven at step 1001 and the enrolment is then confirmed with step 1000
- **THEN** the confirmation succeeds and the recorded step is 1001
- **AND** the enrolment reads with no emailed code

### Requirement: A TOTP time step is accepted at most once, in increasing order
Recording an accepted TOTP time step for an enrolment SHALL succeed only when the enrolment is confirmed, is still on the enrolment generation the caller names, and the step is greater than the last accepted step. A caller naming no generation SHALL record nothing. The check and the update SHALL be a single conditional write. Concurrent attempts to record the same step SHALL result in exactly one success. A refused attempt SHALL leave the last accepted step unchanged.

#### Scenario: Replayed step
- **WHEN** step 1000 is accepted and step 1000 is recorded again
- **THEN** the second attempt is refused

#### Scenario: Older step after a newer one
- **WHEN** step 1001 is accepted and step 1000 is then recorded
- **THEN** the attempt is refused and the last accepted step remains 1001

#### Scenario: Unconfirmed enrolment
- **WHEN** a step is recorded for an enrolment that has not been confirmed
- **THEN** the attempt is refused

#### Scenario: Concurrent verifications of one step
- **WHEN** 8 callers record step 1002 for the same enrolment at the same time
- **THEN** exactly one succeeds

#### Scenario: Step for a removed generation
- **WHEN** a code was checked against the secret of generation G1, the enrolment is reset and re-enrolled as G2 and confirmed, and the step is then recorded naming G1
- **THEN** the attempt is refused
