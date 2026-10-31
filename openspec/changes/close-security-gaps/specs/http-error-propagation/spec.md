## ADDED Requirements

### Requirement: Hardening refusals join the public contract and the status table
The library SHALL expose distinguishable public refusal errors for these cases, and the public status mapping SHALL map them as follows, recognising wrapped and joined errors:

| Refusal | Status |
|---|---|
| a cross-site request refused by CSRF protection | 403 |
| a request whose resolved host is not an allowed host | 400 |
| a missing or invalid DPoP proof, a bound token presented without a matching proof, or a DPoP proof without a required server nonce | 401 |
| a certificate-bound token presented without its certificate | 401 |
| a request refused by the automation-challenge verifier | 403 |
| a new password refused by the password policy (too short, too long, common, context word, breached or reused) | 422 |
| a session handle that names no session of the requesting user | 404 |

The password-reused refusal SHALL be identifiable both as itself and as the password-policy refusal, and SHALL keep mapping to 422. A DPoP refusal SHALL be answered by the default responder with a `WWW-Authenticate: DPoP` challenge as the `sender-constrained-tokens` capability defines. A failure of the DPoP replay store, the password-history port or the breach lookup with failures refusing is a dependency failure, not a refusal of the caller's input, and SHALL map to 500. No refusal's text SHALL contain a proof, a token, a certificate, a CSRF token, a candidate password or a session handle.

#### Scenario: CSRF refusal
- **WHEN** an error wraps the cross-site-request refusal
- **THEN** the mapping returns 403

#### Scenario: Invalid proof
- **WHEN** an error wraps the invalid-DPoP-proof refusal
- **THEN** the mapping returns 401

#### Scenario: Breached password
- **WHEN** a password change is refused by the policy as breached
- **THEN** the mapping returns 422

#### Scenario: Host not allowed
- **WHEN** an error is the host-not-allowed refusal
- **THEN** the mapping returns 400
