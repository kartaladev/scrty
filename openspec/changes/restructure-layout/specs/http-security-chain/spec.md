# Spec Delta

## ADDED Requirements

### Requirement: An unavailable user store is not a failed login
When form login or Basic authentication receives the authentication capability's unavailable error, it SHALL refuse with that error, and SHALL NOT record, count or clear any failure for the username or the request's source. A Basic refusal for this reason SHALL NOT carry a `WWW-Authenticate` challenge, because no credential was refused.

#### Scenario: Outage during form login
- **WHEN** the user store returns a connection error while a form login for `ada` is authenticated
- **THEN** the request is refused with the unavailable error and answered 503
- **AND** no failure is recorded for `ada` and none is counted against the source

#### Scenario: Outage during Basic authentication
- **WHEN** the user store returns a connection error while a Basic request for `ada` is authenticated
- **THEN** the request is refused with the unavailable error, answered 503, and carries no `WWW-Authenticate` header
- **AND** no failure is recorded for `ada` and none is counted against the source

#### Scenario: An outage never holds an account
- **WHEN** a lockout policy holds an identifier after three consecutive failures, the user store is down for three Basic requests for `ada`, and the store then recovers
- **THEN** a Basic request with `ada`'s correct password succeeds

### Requirement: A client that leaves during the user load is charged to its source only
When form login or Basic authentication receives the uniform failure for a load the request's own context ended, it SHALL refuse it as a failed login and SHALL count it against the request's source, recorded on a context whose cancellation is stripped, but SHALL NOT record a failure for the username, because no password was compared. A login whose password was compared and refused SHALL be recorded for the username even when the client leaves afterwards.

#### Scenario: A client hangs up during the load
- **WHEN** a form login for `ada` is authenticated, the request's context is cancelled, and the user loader fails with that cancellation
- **THEN** the request is refused as a failed login
- **AND** one failure is counted against the source and none is recorded for `ada`

#### Scenario: A slow store behind client timeouts never holds an account
- **WHEN** a lockout policy holds an identifier after three consecutive failures, and three Basic requests with `ada`'s correct password each time out while the user store is slow to load
- **THEN** once the store answers in time, a Basic request with `ada`'s correct password succeeds
