## ADDED Requirements

### Requirement: TOTP verification charges each attempt before comparing it
Every TOTP verification of a confirmed enrolment SHALL first charge one attempt against that enrolment, as one conditional store write, and SHALL compare the code only if the charge succeeds. Every presented code, well formed or not, SHALL be charged. At most 5 attempts SHALL be charged per enrolment within a 15-minute window, whatever the number of concurrent requests or replicas. The charge SHALL be made by the TOTP method itself, so it binds every caller of the method.

#### Scenario: Concurrent guesses are bounded
- **WHEN** twenty wrong codes for `u-1` are presented at the same moment, followed by a valid code within the same 15 minutes
- **THEN** no more than five of them are compared against the secret
- **AND** the valid code is refused

#### Scenario: Charge refused
- **WHEN** five attempts have been charged against `u-1`'s enrolment within the window and another code is presented
- **THEN** it is refused with the throttled error without being compared

#### Scenario: Malformed code is charged
- **WHEN** a code of the wrong length is presented for `u-1`
- **THEN** one attempt is charged against `u-1`'s enrolment

#### Scenario: A new window
- **WHEN** five attempts were charged against `u-1`'s enrolment in a window that began at 12:00, and a valid code is presented at 12:16
- **THEN** it is charged in a new window and accepted

#### Scenario: A recovery's TOTP proof is charged
- **WHEN** a recovery presents a TOTP code as its second-factor proof
- **THEN** one attempt is charged against the user's enrolment before the code is compared

#### Scenario: No confirmed enrolment
- **WHEN** a code is presented for a user whose enrolment is pending or absent
- **THEN** it is refused as an invalid code and no attempt is charged

### Requirement: A successful TOTP verification gives its charge back
A verification whose code matches and whose time step is accepted SHALL give back the attempt it charged, within the window it was charged in, so a successful verification spends nothing. A charge SHALL NOT be given back once its window has ended. A failure to give the charge back SHALL be logged and SHALL NOT turn the success into a refusal. Giving the charge back SHALL NOT be abandoned because the caller went away.

#### Scenario: Successes spend nothing
- **WHEN** `u-1` verifies valid codes at seven successive time steps within 15 minutes
- **THEN** all seven are accepted

#### Scenario: Replayed step is not given back
- **WHEN** a valid code whose time step was already accepted is presented again
- **THEN** it is refused as an invalid code and its charge is kept

#### Scenario: Give-back fails
- **WHEN** a valid code is accepted and the store fails to give its charge back
- **THEN** the verification succeeds and the failure is logged

### Requirement: The TOTP attempt limit and window are replaceable
A consumer SHALL be able to replace the attempt limit and the window by an option on the TOTP method. A limit of zero or less, or a window of zero or less, SHALL fail construction with a configuration error. The charge SHALL NOT be switchable off, and the option's documentation SHALL state that a larger limit admits that many compares per window however many requests arrive at once.

#### Scenario: Consumer limit
- **WHEN** the attempt limit is set to 3 per 10 minutes and four codes are presented for `u-1` at the same moment
- **THEN** no more than three of them are compared

#### Scenario: Limit of zero
- **WHEN** the TOTP method is constructed with an attempt limit of 0
- **THEN** construction fails with a configuration error

### Requirement: A refused charge is not counted as a failed verification
A verification refused because its charge was refused SHALL NOT be recorded as a failed verification against the user's rate limit, since no code was compared. A store failure while charging SHALL be returned as an error, never as an invalid code or a throttled refusal, and SHALL refuse the verification.

#### Scenario: Refused charge leaves the limiter alone
- **WHEN** the verify endpoint receives a code for `u-1` whose charge is refused
- **THEN** the throttled error is returned and no failure is recorded on the limiter for `u-1`

#### Scenario: Store failure while charging
- **WHEN** the enrolment store fails while charging an attempt for `u-1`
- **THEN** the verification is refused with an error that is neither an invalid code nor the throttled error
