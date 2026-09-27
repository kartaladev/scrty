## MODIFIED Requirements

### Requirement: MFA enrolment confirmation is recorded once
An MFA enrolment SHALL start unconfirmed. Confirming it SHALL record the confirmation time and the confirming time step only if the enrolment is still unconfirmed, and SHALL report whether this call confirmed it. Confirming SHALL clear any emailed enrolment code outstanding on the enrolment, and SHALL NOT lower the recorded time step: where a device proof already recorded a later step, that step SHALL be kept. Storing a new pending enrolment SHALL replace an unconfirmed enrolment's secret, clear its accepted time step, start a new enrolment generation, and clear its device proof, its emailed code, that code's expiry and its attempt count. It SHALL be refused with the already-enrolled outcome when the user's enrolment is confirmed, leaving that enrolment unchanged. The check and the write SHALL be a single conditional write.

#### Scenario: First confirmation
- **WHEN** a new enrolment is confirmed at time T
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
- **WHEN** a pending enrolment's device is proven at step 1001 and the enrolment is then confirmed with step 1000
- **THEN** the confirmation succeeds and the recorded step is 1001
- **AND** the enrolment reads with no emailed code

## ADDED Requirements

### Requirement: Enrolment device proof, completion and emailed-code attempts are decided by the write
Every durable MFA enrolment store SHALL implement the enrolment path's device-proof operations. Each operation SHALL be a single conditional write whose conditions are all checked by that write, SHALL report whether it changed the enrolment, and SHALL change nothing when it reports no change:
- **device proof** SHALL record the time step, the device-proof time, the emailed code and its expiry only where the user's enrolment is pending on the given generation, its device is not yet proven, and the step is later than the recorded step;
- **completion** SHALL mark the enrolment confirmed and clear its emailed code only where the enrolment is on the given generation, its device is proven and it is not yet confirmed;
- **charging an emailed-code attempt** SHALL increment the attempt count and report the count after the write only where the enrolment is pending on the given generation, its device is proven, its emailed code is outstanding and unexpired at the given time, and fewer than five attempts have been charged. A code is expired from its expiry instant onward: a charge at exactly that instant is refused.

An absent generation SHALL match no enrolment. Within one generation, the code's expiry SHALL be cleared only by storing a new pending enrolment, and the emailed code only by completion, confirmation or a new pending enrolment; neither SHALL be cleared when the code expires or runs out of attempts. Of any number of concurrent completions of one generation, exactly one SHALL succeed, and of any number of concurrent charges against one code, at most five SHALL succeed.

#### Scenario: Device proof on a stale generation
- **WHEN** a pending enrolment is on generation G2 and a device proof names generation G1
- **THEN** the proof is refused and the enrolment reads with no device-proof time

#### Scenario: Device proven twice
- **WHEN** a pending enrolment's device is proven at step 1000 and a second proof on the same generation names step 1001
- **THEN** the second proof is refused and the recorded step remains 1000

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

### Requirement: Enrolment-path session state survives a durable store
Durable session stores SHALL store and return unchanged a session's enrolment-pending second-factor state, its enrolment-origin marker and its enrolment generation. The stored second-factor state SHALL keep the ordinal of every existing state, so a state stored before the enrolment-pending state was added reads back as the same state. A session without the marker SHALL read back with no marker and no generation.

#### Scenario: Enrolment-only session round trip
- **WHEN** a session in the enrolment-pending state, with enrolment-origin marker 21:00 and enrolment generation G1, is saved and loaded
- **THEN** it loads in the enrolment-pending state with marker 21:00 and generation G1

#### Scenario: Backends share the enrolment fields
- **WHEN** such a session is saved through the store of one supported backend
- **THEN** a store of a different supported backend, connected to the same database, loads it with the same state, marker and generation

#### Scenario: Unmarked session
- **WHEN** a session that was never marked enrolment-pending is saved and loaded
- **THEN** it loads with no enrolment-origin marker and no enrolment generation

#### Scenario: Marker cleared on upgrade
- **WHEN** an enrolment-only session is restored to a full session, saved and loaded
- **THEN** it loads with no enrolment-origin marker and no enrolment generation
