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
