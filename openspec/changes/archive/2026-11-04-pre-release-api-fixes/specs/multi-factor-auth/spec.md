# Spec Delta

## MODIFIED Requirements

### Requirement: Device proof and completion are separate, generation-bound writes
An enrolment SHALL carry a generation, which every begin replaces. Proving the device and completing the enrolment SHALL each be one conditional store write, decided by the write rather than by a preceding read:
- **proving the device** SHALL record the code's time step, the device-proof time and the emailed code only where the generation matches, the enrolment is pending, the device is not yet proven and the step is later than the recorded one;
- **completing** SHALL mark the enrolment confirmed only where the generation matches, the device is proven and the enrolment is not yet confirmed.

Beginning again SHALL clear the device proof and the emailed code. Every enrolment store SHALL pass these cases in the store conformance suite. The single-call confirmation this capability already defines SHALL remain for consumers who enrol out of band, and SHALL confirm only an enrolment whose device is not proven, decided by its own write rather than by a preceding read. When a device proof lands after the single-call confirmation has read the enrolment, the confirmation SHALL fail with the invalid-code error and SHALL change nothing.

#### Scenario: A newer begin invalidates an earlier proof
- **WHEN** `u-1` proves a device in session B, a second session A for `u-1` then begins again, and session B completes with the emailed code it received
- **THEN** completion fails and `u-1` is not enrolled
- **AND** the secret provisioned in session A is not confirmed

#### Scenario: Concurrent completions
- **WHEN** two completions of the same generation run concurrently
- **THEN** exactly one reports success

#### Scenario: Completion before proof
- **WHEN** completion is attempted for a generation whose device is not proven
- **THEN** it fails and the enrolment stays pending

#### Scenario: Device proof lands during a single-call confirmation
- **WHEN** a single-call confirmation has read a pending enrolment and checked a valid code, and before its write a device proof of the same generation issues an emailed code
- **THEN** the confirmation fails with the invalid-code error
- **AND** the enrolment stays pending with its emailed code outstanding
- **AND** redeeming that emailed code completes the enrolment

#### Scenario: Device proof lands during a confirmation with email confirmation off
- **WHEN** a single-call confirmation has read a pending enrolment and checked a valid code, and before its write a device proof of the same generation is recorded with no emailed code
- **THEN** the confirmation fails with the invalid-code error and changes nothing
- **AND** the enrolment path can still complete that proof

#### Scenario: Device proof lands after a single-call confirmation
- **WHEN** a single-call confirmation confirms an enrolment, and a device proof of the same generation then reaches its write
- **THEN** the proof fails with the invalid-code error, and no emailed code is stored or sent
- **AND** the enrolment stays confirmed, with its confirmation time and step unchanged

#### Scenario: A new begin clears the proof the confirmation would have met
- **WHEN** a device is proven with an emailed code, a new begin replaces the enrolment, and a single-call confirmation then presents a valid code for the new secret
- **THEN** the enrolment is confirmed, since the single-call confirmation carries no mailbox proof of its own, and must not be reachable from a session the enrolment path confines

#### Scenario: Out-of-band enrolment with no device proof
- **WHEN** a consumer enrolling out of band confirms a pending enrolment whose device was never proven, with a valid code
- **THEN** the enrolment is confirmed
