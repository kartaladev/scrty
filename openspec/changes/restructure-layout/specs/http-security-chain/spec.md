# Spec Delta

## ADDED Requirements

### Requirement: An unavailable user store is not a failed login
When form login or Basic authentication receives the authentication capability's unavailable error, it SHALL refuse with that error and answer exactly as it answers a wrong password, including Basic's `WWW-Authenticate` challenge, so that an outage reveals nothing about an account's existence or lock state. It SHALL count the refusal against the request's source, and SHALL NOT record or clear any failure for the username, because no password was compared.

#### Scenario: Outage during form login
- **WHEN** the user store returns a connection error while a form login for `ada` is authenticated
- **THEN** the request is refused with the unavailable error and answered as a wrong password is
- **AND** one failure is counted against the source and none is recorded for `ada`

#### Scenario: Outage during Basic authentication
- **WHEN** the user store returns a connection error while a Basic request for `ada` is authenticated
- **THEN** the request is refused with the unavailable error, answered 401, and carries the same `WWW-Authenticate` challenge as a wrong password
- **AND** one failure is counted against the source and none is recorded for `ada`

#### Scenario: An outage never holds an account
- **WHEN** a lockout policy holds an identifier after three consecutive failures, the user store is down for three Basic requests for `ada`, and the store then recovers
- **THEN** a Basic request with `ada`'s correct password succeeds

#### Scenario: A held account answers an outage as a free one does
- **WHEN** the user store is down, `bob` is held by the lockout policy with locks concealed, and `ada` is not
- **THEN** a form login for `bob` and one for `ada` receive the same status and headers

#### Scenario: Outages are charged to the source
- **WHEN** the user store fails for every load, and more password logins arrive from one source than its limit allows in the window
- **THEN** the source guard refuses the requests beyond the limit, and no password work is spent on them

### Requirement: A client that leaves during the user load is charged to its source only
When form login or Basic authentication receives the uniform failure for a load the request's own context ended, it SHALL refuse it as a failed login and SHALL count it against the request's source, recorded on a context whose cancellation is stripped, but SHALL NOT record a failure for the username, because no password was compared. A login whose password was compared and refused SHALL be recorded for the username even when the client leaves afterwards.

#### Scenario: A client hangs up during the load
- **WHEN** a form login for `ada` is authenticated, the request's context is cancelled, and the user loader fails with that cancellation
- **THEN** the request is refused as a failed login
- **AND** one failure is counted against the source and none is recorded for `ada`

#### Scenario: A slow store behind client timeouts never holds an account
- **WHEN** a lockout policy holds an identifier after three consecutive failures, and three Basic requests with `ada`'s correct password each time out while the user store is slow to load
- **THEN** once the store answers in time, a Basic request with `ada`'s correct password succeeds
