# Spec Delta

## ADDED Requirements

### Requirement: Adapter recency guards match the core recency guard
The gin and fiber guards SHALL offer the recency guard with the same default window, the same guards-wide and per-route windows, the same time-source and authentication-time options, and the same construction and wiring failures as the core guards, and SHALL produce the same outcome for the same request. Their refusals SHALL reach the consumer as every other adapter guard refusal does.

#### Scenario: gin stale session
- **WHEN** a gin route under the default recency guard is called by a session that authenticated 16 minutes ago
- **THEN** the route handler is not called, the reauthentication-required refusal reaches gin's error channel, and the default response is 403

#### Scenario: fiber stale session
- **WHEN** a fiber route under the default recency guard is called by a session that authenticated 16 minutes ago
- **THEN** the route handler is not called, and fiber's error handler receives the reauthentication-required refusal carrying the 15-minute window

#### Scenario: Fresh session on every adapter
- **WHEN** a session that authenticated 5 minutes ago calls the same recency-guarded route on net/http, gin and fiber
- **THEN** the route is called on all three

#### Scenario: Per-route window on gin
- **WHEN** a gin route is guarded with a 5-minute window and a session that authenticated 6 minutes ago calls it
- **THEN** it is refused with the reauthentication-required refusal carrying the 5-minute window

#### Scenario: fiber guards with an absent time source
- **WHEN** fiber guards are built with a nil time source
- **THEN** construction fails with a configuration error

#### Scenario: gin per-route window of zero
- **WHEN** a gin route's recency guard is built with a window of zero
- **THEN** building it fails at wiring with a message naming the window
