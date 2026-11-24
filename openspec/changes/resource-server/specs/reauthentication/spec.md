## MODIFIED Requirements

### Requirement: The authentication time comes from the session unless the consumer supplies it
By default the guard SHALL judge the request's session's authentication time. For a caller a resource server authenticated, it SHALL judge the authentication time its access token carries, and SHALL refuse one whose token carries none. A request with a principal but no session and no access token, as from an API key, HTTP Basic or a consumer's own first factor, SHALL be refused with the reauthentication-required error. A consumer SHALL be able to replace how the time is found; a replacement reporting none SHALL refuse, and an absent one SHALL fail construction.

#### Scenario: API key caller
- **WHEN** a caller authenticated by an API key calls a recency-guarded route
- **THEN** it is refused with the reauthentication-required error

#### Scenario: Fresh access token
- **WHEN** a caller whose access token records an authentication time of 09:00 calls a route under the default window at 09:10
- **THEN** the route is called

#### Scenario: Stale access token
- **WHEN** the same caller calls the route at 09:16
- **THEN** it is refused with the reauthentication-required error

#### Scenario: Access token without an authentication time
- **WHEN** a caller whose access token carries no authentication time calls a recency-guarded route
- **THEN** it is refused with the reauthentication-required error

#### Scenario: Consumer authentication time
- **WHEN** guards are built with a consumer source that reports 09:00 for the caller, and the caller calls a route under the default window at 09:10
- **THEN** the route is called

#### Scenario: Consumer source reports none
- **WHEN** the consumer source reports no authentication time for the caller
- **THEN** the request is refused with the reauthentication-required error

#### Scenario: Absent consumer source
- **WHEN** guards are built with a nil authentication-time source
- **THEN** construction fails with a configuration error naming the option

### Requirement: The reauthentication-required refusal names the window it needed
The recency guard's refusal SHALL be distinguishable from every other refusal and SHALL carry the window the route required, so a consumer's error handler can tell the client how recent an authentication it must present. With no error handler the response SHALL be the refusal's status with no body: 403 for a session caller, and for an access-token caller 401 with the insufficient-user-authentication challenge, whose refusal also carries the window.

#### Scenario: Window on the refusal
- **WHEN** a stale session is refused by a route guarded with a 5-minute window
- **THEN** the refusal is identifiable as the reauthentication-required error and reports a window of 5 minutes

#### Scenario: Default response
- **WHEN** guards are built with no error handler and a stale session is refused
- **THEN** the response is 403 with no body

#### Scenario: Consumer error handler
- **WHEN** guards are built with an error handler and a stale session is refused
- **THEN** the handler receives the refusal with its window, and the route is not called

#### Scenario: Default response for an access token
- **WHEN** guards are built with no error handler and a stale access token is refused by a route guarded with a 5-minute window
- **THEN** the response is 401 with `WWW-Authenticate: Bearer error="insufficient_user_authentication", max_age=300` and no body
