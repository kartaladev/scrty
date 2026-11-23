## MODIFIED Requirements

### Requirement: The provider reports its security outcomes as events
When a sink is configured, the provider SHALL emit an event for each of these outcomes:
- a grant created;
- consent given, denied or revoked;
- a refused client authentication;
- a replayed authorization code;
- a refresh token reused after its grace window;
- a grant revoked, with its cause;
- a failed back-channel logout delivery;
- a device authorization issued, claimed, approved, denied or exchanged;
- a replayed device code;
- a user-code entry refused by the throttle.

Each event SHALL name the client and the user when known. It SHALL NOT carry a code, handle, token, assertion or secret.

#### Scenario: Refresh-token reuse
- **WHEN** a refresh token is reused after its grace window
- **THEN** one event reports the reuse with the client and user, and one reports the grant revoked for reuse, and neither carries the token

#### Scenario: Reuse of a grant already revoked
- **WHEN** a refresh token is reused after its grace window, on a grant something else has already revoked
- **THEN** one event reports the reuse, and no second revocation is reported

#### Scenario: No sink
- **WHEN** no sink is configured and a code is replayed
- **THEN** no event is emitted, and the replay is still refused and still revokes the grant

#### Scenario: A replayed device code
- **WHEN** a client presents a device code it already exchanged
- **THEN** one event reports the device-code replay with the client and user, and one reports the grant revoked, and neither carries the device code or user code
