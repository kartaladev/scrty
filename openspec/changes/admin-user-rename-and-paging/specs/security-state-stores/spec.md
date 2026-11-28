# Spec Delta

## MODIFIED Requirements

### Requirement: Enrolment device proof, completion and emailed-code attempts are decided by the write
Every MFA enrolment store SHALL implement the enrolment path's device-proof operations. Each operation SHALL be a single conditional write whose conditions are all checked by that write, SHALL report whether it changed the enrolment, and SHALL change nothing when it reports no change:
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
