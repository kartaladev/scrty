# Spec Delta

## MODIFIED Requirements

### Requirement: MFA enrolment confirmation is recorded once
An MFA enrolment SHALL start unconfirmed. Confirming it SHALL record the confirmation time and the confirming time step only if the enrolment is still unconfirmed, is still on the enrolment generation the caller names, and has no device proof recorded, and SHALL report whether this call confirmed it. A caller naming no generation SHALL confirm nothing. A refused confirmation SHALL change nothing: the device proof, the emailed code, its expiry, its attempt count and the recorded time step all stay as they were. Storing a new pending enrolment SHALL replace an unconfirmed enrolment's secret, clear its accepted time step, start a new enrolment generation, and clear its device proof, its emailed code, that code's expiry and its attempt count. It SHALL be refused with the already-enrolled outcome when the user's enrolment is confirmed, leaving that enrolment unchanged. The check and the write SHALL be a single conditional write.

#### Scenario: First confirmation
- **WHEN** a new enrolment on generation G1 is confirmed at time T naming G1
- **THEN** the confirmation succeeds and the enrolment reads as confirmed at T

#### Scenario: Second confirmation
- **WHEN** a confirmed enrolment is confirmed again at time T2
- **THEN** the second confirmation is refused
- **AND** the recorded confirmation time is unchanged

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
- **WHEN** a pending enrolment's device is proven at step 1001 with an emailed code, and the enrolment is then confirmed with step 1000 naming its generation
- **THEN** the confirmation is refused
- **AND** the enrolment reads as unconfirmed with step 1001, its device-proof time and its emailed code

#### Scenario: Confirmation refused after a device proof with no emailed code
- **WHEN** a pending enrolment's device is proven with no emailed code, and the enrolment is then confirmed naming its generation
- **THEN** the confirmation is refused and the enrolment reads as unconfirmed with its device-proof time

#### Scenario: Confirmation refused when the emailed code has expired or run out of attempts
- **WHEN** a proven enrolment has an emailed code past its expiry with five attempts charged, and the enrolment is confirmed naming its generation at a later time
- **THEN** the confirmation is refused
- **AND** the enrolment reads as unconfirmed with the same device-proof time, step, emailed code, expiry and attempt count

#### Scenario: Confirmation naming a replaced generation
- **WHEN** a pending enrolment on generation G1 is replaced by one on G2, and a confirmation naming G1 is made
- **THEN** the confirmation is refused and the enrolment reads as unconfirmed on G2

### Requirement: Enrolment device proof, completion and emailed-code attempts are decided by the write
Every durable MFA enrolment store SHALL implement the enrolment path's device-proof operations. Each operation SHALL be a single conditional write whose conditions are all checked by that write, SHALL report whether it changed the enrolment, and SHALL change nothing when it reports no change:
- **device proof** SHALL record the time step, the device-proof time, the emailed code and its expiry only where the user's enrolment is pending on the given generation, its device is not yet proven, and the step is later than the recorded step;
- **completion** SHALL mark the enrolment confirmed and clear its emailed code only where the enrolment is on the given generation, its device is proven and it is not yet confirmed;
- **charging an emailed-code attempt** SHALL increment the attempt count and report the count after the write only where the enrolment is pending on the given generation, its device is proven, its emailed code is outstanding and unexpired at the given time, and fewer than five attempts have been charged. A code is expired from its expiry instant onward: a charge at exactly that instant is refused.

An absent generation SHALL match no enrolment. Within one generation, the code's expiry SHALL be cleared only by storing a new pending enrolment, and the emailed code only by completion or a new pending enrolment; neither SHALL be cleared when the code expires or runs out of attempts. Of any number of concurrent completions of one generation, exactly one SHALL succeed, and of any number of concurrent charges against one code, at most five SHALL succeed.

#### Scenario: Device proof on a stale generation
- **WHEN** a pending enrolment is on generation G2 and a device proof names generation G1
- **THEN** the proof is refused and the enrolment reads with no device-proof time

#### Scenario: Device proven twice
- **WHEN** a pending enrolment's device is proven at step 1000 and a second proof on the same generation names step 1001
- **THEN** the second proof is refused and the recorded step remains 1000

#### Scenario: Device proof on a confirmed enrolment
- **WHEN** an enrolment on generation G1 is confirmed, and a device proof then names G1
- **THEN** the proof is refused and the enrolment reads as confirmed with no device-proof time, no emailed code, and its step and confirmation time unchanged

#### Scenario: A newer begin invalidates an earlier proof
- **WHEN** a device is proven on generation G1, a new pending enrolment on generation G2 is stored for the same user, and completion then names G1
- **THEN** the completion is refused
- **AND** the enrolment reads as unconfirmed

#### Scenario: Completion before device proof
- **WHEN** a pending enrolment on generation G1 whose device is not proven is completed on G1
- **THEN** the completion is refused and the enrolment reads as unconfirmed

#### Scenario: Concurrent completions of one generation
- **WHEN** 8 callers complete the same proven enrolment on its generation at the same time
- **THEN** exactly one succeeds

#### Scenario: Concurrent charges against one code
- **WHEN** 20 callers charge an attempt against the same outstanding emailed code at the same time
- **THEN** exactly five succeed
- **AND** the enrolment reads with five charged attempts and its emailed code still stored

#### Scenario: Expired code is not charged
- **WHEN** an emailed code whose expiry is 10:10 is charged at 10:11
- **THEN** the charge is refused and the attempt count is unchanged
- **AND** the enrolment still reads with its emailed code and its expiry

#### Scenario: Code charged at its expiry instant
- **WHEN** an emailed code whose expiry is 10:10 is charged at exactly 10:10
- **THEN** the charge is refused and the attempt count is unchanged

### Requirement: Passkey credentials are unique, and their state changes are decided by the write
A passkey credential store SHALL keep, per credential, a library identifier and the user reference. It SHALL also keep:
- the credential ID and public key, as bytes;
- the signature counter;
- the backup-eligible and backup-state flags;
- the transports;
- the authenticator model identifier;
- the attestation format and statement, when recorded;
- the name;
- the creation and last-use times;
- the state: active, pending or suspended;
- the pending reasons;
- for a credential awaiting its emailed code, the sealed code, its expiry and the attempts charged.

It SHALL:
- **insert** a credential, refusing one whose credential ID is already stored, whatever its user, with a duplicate outcome decided by the write;
- **find** a credential by credential ID, and by library identifier within a user;
- **list** a user's credentials, and **count** them;
- **record an assertion** by one conditional write that sets the counter, the backup-state flag and the last-use time only where the credential is active and the stored counter is lower than the new one, or both are zero. It SHALL report whether this call recorded it;
- **suspend** a credential, and **clear one pending reason**, each by one conditional write on its current state, reporting whether this call changed it. Clearing the last pending reason SHALL make the credential active;
- **charge an emailed-code attempt** by one conditional write that succeeds only while the code is outstanding, unexpired and has fewer than five attempts charged;
- **rename** and **delete** a credential within a user;
- **delete every credential of a user**, returning how many were removed.

A refused write SHALL change nothing. The emailed code SHALL be sealed at rest with the store's cipher, which durable stores SHALL require at construction. A read that cannot open a sealed code SHALL be an error, never a missing code. The in-memory store SHALL be the default, SHALL hold its own copies of byte values, and any implementation of the contract SHALL be usable in its place.

#### Scenario: Duplicate credential ID
- **WHEN** a credential with ID C is stored for `u-1`, and another with ID C is inserted for `u-2`
- **THEN** the second insert is refused as a duplicate and `u-1`'s credential is unchanged

#### Scenario: Concurrent counter recordings
- **WHEN** 8 callers record counter 43 on the same credential whose stored counter is 42, at the same time
- **THEN** exactly one recording succeeds

#### Scenario: Counter going backwards is not recorded
- **WHEN** a recording of counter 41 is made on a credential whose stored counter is 42
- **THEN** it is refused and the stored counter is still 42

#### Scenario: Zero counters are recorded
- **WHEN** a recording of counter 0 is made on a credential whose stored counter is 0
- **THEN** it succeeds and the last-use time is updated

#### Scenario: Suspended credential is not recorded
- **WHEN** a recording is made on a suspended credential
- **THEN** it is refused and nothing changes

#### Scenario: Attempts bounded under concurrency
- **WHEN** 20 attempts are charged at the same time on a credential awaiting its emailed code
- **THEN** exactly five are charged

#### Scenario: Last reason cleared activates
- **WHEN** a credential pending on both its emailed code and saved codes has the emailed-code reason cleared and then the saved-code reason cleared
- **THEN** it is pending after the first clearing and active after the second
