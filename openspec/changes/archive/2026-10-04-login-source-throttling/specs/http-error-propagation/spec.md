## MODIFIED Requirements

### Requirement: One public table maps refusals to a status
The library SHALL provide a public status-only mapping from an error to an HTTP status code. Every library default response and helper SHALL use it, and it SHALL recognise wrapped and joined errors:

| Refusal | Status |
|---|---|
| authentication required (this capability's, and the authorization capability's own), authentication failed (including a refused account recovery and a refused passkey ceremony), session idle, throttled source, throttled saved-code presentation | 401 |
| challenge of kind password change, challenge of kind second-factor enrolment, challenge of kind account recovery | 403 |
| challenge of any other kind | 401 |
| invalid second-factor code, throttled second-factor verification or enrolment, throttled passkey registration begin | 401 |
| access denied, refused by policy without a reason (the security-policy capability's own error), second factor required or unsatisfiable, second-factor enrolment required, second factor on the same channel as the first, already enrolled, MFA method not usable by the session's user, no MFA challenge pending, request refused during a recovery cool-down, reauthentication required for a saved-code regeneration, reauthentication required for a passkey registration or removal, passkey suspected to be a clone, passkey suspended, passkey still pending, passkey refused by the attestation policy, passkey limit reached | 403 |
| malformed login, malformed recovery, invalid federated logout token | 400 |
| unknown identity provider named in a federated login or logout path, unknown MFA method named in a second-factor path, passkey not found | 404 |
| request too large | 413 |
| new password matches a recent password (the password-encoding capability's password-reused error) | 422 |
| account locked, too many sessions | 429 |
| held recovery presented before its hold ends | 409 |
| any other error | 500 |

A failure to read or record password history is a dependency failure, not a refusal of the caller's input, and SHALL map to 500 like any other unrecognised error.

Federated login refusals that are authentication failures (an invalid flow, an invalid ID token, an unlinked identity, a refused provisioning, an invalid handoff code) SHALL be identifiable as the authentication-failed refusal and SHALL therefore map to 401 without rows of their own. An invalid, expired or voided emailed enrolment code, an absent, unknown, expired, spent or mismatched pending MFA challenge, and an invalid, expired or voided emailed passkey confirmation code, SHALL be identifiable as the invalid second-factor code refusal.

#### Scenario: Wrapped sentinel
- **WHEN** an error wraps the access-denied refusal with extra context
- **THEN** the mapping returns 403

#### Scenario: Joined verification failure
- **WHEN** an error joins the authentication failure refusal with a token-parsing cause
- **THEN** the mapping returns 401

#### Scenario: Second-factor challenge
- **WHEN** the error is a challenge of kind second factor
- **THEN** the mapping returns 401

#### Scenario: Password-change challenge
- **WHEN** the error is a challenge of kind password change
- **THEN** the mapping returns 403

#### Scenario: Enrolment challenge
- **WHEN** the error is a challenge of kind second-factor enrolment
- **THEN** the mapping returns 403

#### Scenario: Invalid second-factor code
- **WHEN** the error is the invalid second-factor code refusal returned by the verify endpoint
- **THEN** the mapping returns 401

#### Scenario: Spent pending challenge
- **WHEN** the error is the refusal of a pending MFA challenge that was already spent
- **THEN** the mapping returns 401

#### Scenario: Expired emailed code
- **WHEN** the error is the refusal of an expired emailed enrolment code
- **THEN** the mapping returns 401

#### Scenario: Throttled enrolment
- **WHEN** the error is the throttled refusal of an enrolment begin
- **THEN** the mapping returns 401

#### Scenario: Already enrolled
- **WHEN** the error is the already-enrolled refusal
- **THEN** the mapping returns 403

#### Scenario: Unknown MFA method
- **WHEN** the error is the unknown-MFA-method refusal of a verify path
- **THEN** the mapping returns 404

#### Scenario: MFA method not usable
- **WHEN** the error is the refusal of an MFA method the session's user is not enrolled on
- **THEN** the mapping returns 403

#### Scenario: No MFA challenge pending
- **WHEN** the error is the refusal of the method-listing endpoint for a fully authenticated session
- **THEN** the mapping returns 403

#### Scenario: Unrecognised error
- **WHEN** the error is a database connection failure that wraps no refusal
- **THEN** the mapping returns 500

#### Scenario: Either identity matches a wrapped core refusal
- **WHEN** an unauthenticated request matches a rule requiring authentication
- **THEN** the refusal matches both this capability's authentication-required error and the authorization capability's own, and maps to 401

#### Scenario: Unknown identity provider
- **WHEN** the error is the unknown-provider refusal of a federated login path
- **THEN** the mapping returns 404

#### Scenario: Invalid logout token
- **WHEN** the error is the invalid-logout-token refusal
- **THEN** the mapping returns 400

#### Scenario: Federated authentication failure
- **WHEN** the error is the invalid-handoff refusal
- **THEN** the mapping returns 401

#### Scenario: Consumer refines the mapping
- **WHEN** the consumer's error handler maps its own error type to 409 and falls back to the library mapping for everything else
- **THEN** the consumer's error returns 409 and a library refusal keeps its library status

#### Scenario: Reused password
- **WHEN** a consumer's password-change function returns the password-reused error, wrapped with extra context
- **THEN** the mapping returns 422

#### Scenario: Password history unavailable
- **WHEN** the error is the history-unavailable error wrapping a database connection failure
- **THEN** the mapping returns 500

#### Scenario: Recovery challenge
- **WHEN** the error is a challenge of kind account recovery
- **THEN** the mapping returns 403

#### Scenario: Refused recovery
- **WHEN** the error is the recovery-refused refusal
- **THEN** the mapping returns 401

#### Scenario: Malformed recovery
- **WHEN** the error is the malformed-recovery refusal
- **THEN** the mapping returns 400

#### Scenario: Recovery not yet completable
- **WHEN** the error is the refusal of a held recovery presented before its hold ends
- **THEN** the mapping returns 409

#### Scenario: Cool-down
- **WHEN** the error is the cool-down refusal
- **THEN** the mapping returns 403

#### Scenario: Reauthentication required
- **WHEN** the error is the reauthentication-required refusal of a saved-code regeneration
- **THEN** the mapping returns 403

#### Scenario: Suspected clone
- **WHEN** the error is the clone-suspected refusal of a passkey assertion
- **THEN** the mapping returns 403

#### Scenario: Pending passkey
- **WHEN** the error is the pending-passkey refusal
- **THEN** the mapping returns 403

#### Scenario: Attestation refused
- **WHEN** the error is the attestation-refused refusal of a passkey registration
- **THEN** the mapping returns 403

#### Scenario: Passkey not found
- **WHEN** the error is the passkey-not-found refusal of a removal
- **THEN** the mapping returns 404

#### Scenario: Refused passkey ceremony
- **WHEN** the error is the refusal of a passwordless finish whose signature does not verify
- **THEN** the mapping returns 401

#### Scenario: Disclosed account lock
- **WHEN** the error is the account-locked refusal alone
- **THEN** the mapping returns 429

#### Scenario: Concealed account lock
- **WHEN** the error joins the authentication failure refusal with the account-locked refusal
- **THEN** the mapping returns 401
