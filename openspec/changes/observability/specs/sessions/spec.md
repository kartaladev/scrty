# Spec Delta

## ADDED Requirements

### Requirement: The session manager reports to a telemetry observer
When given a telemetry observer, the session manager SHALL report session creation, strict rotation and renewal as operations, with the session's user. It SHALL report the events `session_created` on creation, `session_renewed` on a renewal, and `authn_token_reuse` when it detects reuse. The existing reuse observer SHALL keep receiving its reports unchanged.

#### Scenario: Renewal reported
- **WHEN** a session is renewed on a manager given an observer
- **THEN** the observer sees the `session.renew` operation end in success, and the event `session_renewed` with the session's user

#### Scenario: Reuse reported to both
- **WHEN** a manager has both a reuse observer and a telemetry observer, and a superseded session is presented after its window
- **THEN** the reuse observer receives its report as before, and the telemetry observer receives `authn_token_reuse`

#### Scenario: No session identifier handed out
- **WHEN** any session operation is reported
- **THEN** nothing the telemetry observer receives contains a session identifier
