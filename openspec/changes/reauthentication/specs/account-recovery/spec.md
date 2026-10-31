# Spec Delta

## MODIFIED Requirements

### Requirement: Regenerating codes needs a recent authentication and notifies the user
The endpoint that regenerates a user's set SHALL answer POST requests on its path, `/recovery/codes` by default, and SHALL be answered only for a full session: one with no pending challenge of any kind. It SHALL refuse with a reauthentication-required error unless the session's latest authentication is within the freshness window. The latest authentication is the session's authentication time, as the `sessions` capability records it: the sign-in, a satisfied second factor or a re-authentication, whichever is latest. The window SHALL be 15 minutes by default, replaceable by an option, and a window of zero or less SHALL fail construction. On success it SHALL return the new codes once, through a replaceable responder, and SHALL notify the user at their contact address. The notice SHALL name the time and SHALL contain no code. The notice SHALL NOT be sent through a sender that delivers synchronously, unless the consumer explicitly accepts synchronous delivery. A GET on the same path SHALL answer any full session with the remaining count and whether it is low, and SHALL NOT return a code.

#### Scenario: Fresh session regenerates
- **WHEN** a session created at 09:00 posts to `/recovery/codes` at 09:10
- **THEN** a new set is returned once, the previous set is void, and a notice is queued to the user

#### Scenario: Stale session
- **WHEN** a session created at 09:00, whose second factor was never satisfied since, posts to `/recovery/codes` at 09:20
- **THEN** it is refused with the reauthentication-required error and the set is unchanged

#### Scenario: Consumer window
- **WHEN** the freshness window is configured as 2 hours and a session created at 09:00 posts at 10:30
- **THEN** a new set is returned

#### Scenario: Count without codes
- **WHEN** a full session sends GET `/recovery/codes`
- **THEN** the response carries the remaining count and the low flag, and no code

#### Scenario: Pending session refused
- **WHEN** a session with an MFA challenge pending posts to `/recovery/codes`
- **THEN** it is refused by the gate enforcing that challenge, and no set is generated

#### Scenario: Fresh after a re-authentication
- **WHEN** a session created at 09:00 re-authenticates at 09:30 and posts to `/recovery/codes` at 09:40
- **THEN** a new set is returned
