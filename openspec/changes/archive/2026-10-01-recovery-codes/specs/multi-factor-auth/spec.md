# Spec Delta

## ADDED Requirements

### Requirement: A recovery-pending session enrols a new second factor through the enrolment path
When the enrolment path is enabled, its begin, confirm and emailed-code endpoints SHALL serve a session in the recovery-pending state exactly as they serve an enrolment-only session, on that session's own user, with the same refusals, limits and notification. Confirming the enrolment SHALL move the session to the MFA pending state, keeping its confinement marker and its recovery time. The MFA verify endpoint SHALL then resolve the challenge, restore the session's deadlines and rotate it, as for a session that entered through the enrolment path. The enrolment path SHALL NOT be the only way such a session is served: the recovery gate decides which endpoints it reaches.

#### Scenario: Enrol after recovery
- **WHEN** a recovery-pending session created at 09:00 begins a TOTP enrolment, proves the device, completes it with the emailed code, and posts a fresh valid code to `/mfa/verify/totp` at 09:09, with a 12-hour absolute timeout
- **THEN** the rotated session reports a satisfied second factor, an absolute deadline of 21:00 and a recovery time of 09:00

#### Scenario: Confirmation alone is not enough
- **WHEN** a recovery-pending session has just confirmed its enrolment and requests `/invoices`
- **THEN** an MFA challenge error is returned

### Requirement: MFA enrolments take part in the authenticator reset of a recovery
The library SHALL provide an authenticator kind for the recovery reset port over a set of MFA methods. It SHALL list, as the authenticators a user holds, the methods the user is enrolled on, and SHALL remove an enrolment through that method's enrolment remover. A method that cannot remove its enrolments SHALL fail construction with a configuration error. A failed enrolment lookup SHALL be returned as an error, never as holding nothing. An MFA method used as a proof in a recovery SHALL count as proven, so the default reset keeps it.

#### Scenario: Listing
- **WHEN** TOTP and `email-code` are configured and `u-1` is enrolled on TOTP only
- **THEN** the kind lists TOTP as held by `u-1`

#### Scenario: Method without a remover
- **WHEN** the kind is constructed over a consumer's method that cannot remove enrolments
- **THEN** construction fails with a configuration error

#### Scenario: Lookup failure
- **WHEN** the TOTP enrolment lookup fails while `u-1`'s authenticators are listed
- **THEN** the listing returns an error
