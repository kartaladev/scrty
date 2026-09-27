## ADDED Requirements

### Requirement: A reused password at the resolve endpoint leaves the change owed
When the consumer's password-change function refuses a new password with the password-reused error, the resolve endpoint SHALL refuse the request with that error, SHALL NOT clear the pending password-change marker, and SHALL keep gating the session. The library SHALL NOT read the new password from the request itself. The reuse check runs only where the consumer's function calls the reuse guard.

#### Scenario: Reused password keeps the challenge pending
- **WHEN** a session with a pending password-change challenge posts to the consumer's resolve endpoint, and the consumer's function refuses the new password as reused through the reuse guard
- **THEN** the request is refused with the password-reused error, mapped to 422
- **AND** the next request on that session is still refused with a password-change challenge error

#### Scenario: Endpoint without a reuse guard
- **WHEN** the consumer's resolve function changes the password without calling a reuse guard, and the caller submits their current password as the new one
- **THEN** the change succeeds and the marker is cleared, because reuse checking is off unless the consumer enables it
