# Spec Delta

## MODIFIED Requirements

### Requirement: Refusal errors are a stable public contract
The library SHALL expose distinguishable public refusal errors for at least these cases:
- authentication required;
- malformed login;
- request too large;
- an unknown MFA method named in a second-factor path;
- an MFA method the session's user may not use;
- a request to the MFA method-listing endpoint from a session that owes no MFA challenge;
- a refused account recovery, whatever the cause: an unknown user, a disabled user, a wrong or spent proof, or an unknown, spent or cancelled completion token;
- a malformed recovery: the wrong number or kinds of proofs, a proof kind that is not enabled, or a reported loss the user does not hold;
- a held recovery presented for completion before its hold ends;
- a request refused during a recovery cool-down;
- a saved-code regeneration from a session whose latest authentication is outside the freshness window;
- a passkey assertion refused as a suspected clone;
- a passkey assertion from a suspended credential;
- a passkey assertion from a credential that is still pending;
- a passkey registration refused by the attestation policy;
- a passkey registration beyond the user's passkey limit;
- a passkey registration or removal from a session below the account's assurance or outside the freshness window;
- a passkey identifier that names no passkey of the session's user.

A refused recovery SHALL be identifiable as the authentication-failed refusal, so it reads to the client like a failed login. A refused passkey ceremony (an invalid, spent or mismatched challenge, a missing ceremony cookie, an unknown credential, a user-handle mismatch or a signature that does not verify) SHALL be identifiable as the authentication-failed refusal without a sentinel of its own. As a second factor it SHALL be the invalid second-factor code refusal.

A refusal a core already names SHALL be reported as that core's own error rather than restated under a second name. In particular, a policy that denies without giving a reason SHALL be reported as the security-policy capability's reasonless-deny error, because the policy engine already substitutes it: a second sentinel for the same condition would be unreachable, and a consumer matching one identity would miss the other. Where this capability's own refusal and a core's name the same condition, the chain SHALL wrap the core's with its own so that either identity matches.

It SHALL also expose one challenge error type, whose kinds include account recovery, and SHALL map the refusal errors that the authentication, authorization, session, security-policy, second-factor and passkey cores define. A challenge error SHALL carry its challenge kind, the pending session when one exists, and the access token issued with it when one was issued. A challenge error of the second-factor kind SHALL also carry the session user's usable MFA methods, each with its name, its channel and whether it has a begin step, computed by the one function the security policies use to decide usability; when that computation fails, the request SHALL be refused with the failure instead of the challenge, and SHALL NEVER carry an empty or partial list. No refusal error's text SHALL contain an access token, a session handle, a submitted credential, a method name, a challenge, a credential ID or a user handle. A refusal caused by a consumer-supplied dependency SHALL carry fixed library text, with the dependency's error reachable by identity and type, as the diagnostic-redaction capability requires; this SHALL NOT change the status it maps to.

#### Scenario: Challenge error contents
- **WHEN** form login is challenged for a second factor
- **THEN** the challenge error carries the second-factor kind, the pending session and the token

#### Scenario: Challenge carries the usable methods
- **WHEN** TOTP and a challenge method named `passkey` are configured, `u-1` is enrolled on both, and `u-1`'s password login is challenged for a second factor
- **THEN** the challenge error lists `totp` on the authenticator-app channel without a begin step, then `passkey` with a begin step

#### Scenario: Challenge omits methods the user cannot use
- **WHEN** `u-1` is enrolled on TOTP only and a session of `u-1` with the challenge pending requests `/invoices`
- **THEN** the challenge error lists `totp` only

#### Scenario: A failed lookup never yields an empty list
- **WHEN** a session with the challenge pending requests `/invoices` and a method's enrolment lookup fails
- **THEN** the request is refused with that failure and no challenge error is returned

#### Scenario: Challenge text carries no secret
- **WHEN** a challenge error carrying a token is converted to text
- **THEN** the text names the challenge kind and contains neither the token, the session handle nor any method name

#### Scenario: Challenge raised on a later request
- **WHEN** the password-change gate refuses a session
- **THEN** the challenge error carries the session and no token

#### Scenario: Dependency text stays out of the refusal
- **WHEN** a login is refused because the attempt store failed with an error quoting `alice@example.com`
- **THEN** the refusal's text does not contain `alice@example.com`, and it still maps to the status it mapped to before

#### Scenario: Recovery refusal reveals no cause
- **WHEN** one recovery is refused for an unknown username and another for a wrong saved code
- **THEN** both errors are the same recovery-refused refusal, and neither's text contains a username or a code

#### Scenario: Passkey refusal reveals no credential
- **WHEN** one passwordless finish is refused for an unknown credential and another for a bad signature
- **THEN** both errors are the authentication-failed refusal, and neither's text contains a credential ID or a challenge

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
| account locked | 423 |
| too many sessions | 429 |
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
