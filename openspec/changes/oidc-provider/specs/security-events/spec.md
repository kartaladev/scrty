# Spec Delta

## ADDED Requirements

### Requirement: The provider reports its security outcomes as events
When a sink is configured, the provider SHALL emit an event for each of these outcomes:
- a grant created;
- consent given, denied or revoked;
- a refused client authentication;
- a replayed authorization code;
- a refresh token reused after its grace window;
- a grant revoked, with its cause;
- a failed back-channel logout delivery.

Each event SHALL name the client and the user when known. It SHALL NOT carry a code, handle, token, assertion or secret.

#### Scenario: Refresh-token reuse
- **WHEN** a refresh token is reused after its grace window
- **THEN** one event reports the reuse with the client and user, and one reports the grant revoked for reuse, and neither carries the token

#### Scenario: No sink
- **WHEN** no sink is configured and a code is replayed
- **THEN** no event is emitted, and the replay is still refused and still revokes the grant
