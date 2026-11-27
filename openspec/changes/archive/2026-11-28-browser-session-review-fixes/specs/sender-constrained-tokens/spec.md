## ADDED Requirements

### Requirement: A cookie chain refuses to continue a key-bound session
On a chain with the cookie session, second-factor verification, re-authentication and renewal SHALL refuse a session bound to a sender key as unauthenticated, without reading a proof or a certificate, spending nothing and storing nothing, since that chain judges no proof. A session such a chain creates is never bound, so only a session a consumer's own authenticator published can reach this refusal.

#### Scenario: Bound session at second-factor verification on a cookie chain
- **WHEN** a consumer's authenticator publishes a session bound to a DPoP key on a cookie chain, and the request then verifies a second-factor code for it
- **THEN** verification is refused as authentication required, the code is not spent, and the session is not rotated

#### Scenario: Bound session at renewal on a cookie chain
- **WHEN** a request on a cookie chain asks to renew a session bound to a DPoP key
- **THEN** the renewal is refused as authentication required, and the session is not rotated

#### Scenario: Unbound session unchanged
- **WHEN** a cookie chain verifies a second factor, re-authenticates or renews an unbound session, with or without a DPoP header
- **THEN** it proceeds as before, reading no proof
