## ADDED Requirements

### Requirement: Session-only endpoints refuse an access-token caller
On a path a resource server covers, every endpoint and operation of the chain that acts on the caller's sign-in session SHALL refuse a caller that resource server authenticated, with the authentication-required error, before changing anything, and no option SHALL relax this. That covers password change, passkeys, second factors, saved codes, re-authentication, session renewal and management, the provider's resume and consent, the active-role switch, and logout.

#### Scenario: Password change with an access token
- **WHEN** a client holding a valid access token for the user posts a password change
- **THEN** the request is refused with the authentication-required error, and the password is unchanged

#### Scenario: Every session-only endpoint
- **WHEN** a valid access token is presented to each of: password change, passkey registration and removal, second-factor enrolment, method listing and verification, saved-code regeneration, re-authentication, session renewal, session listing and ending, the provider's resume and consent endpoints, and the active-role switch
- **THEN** each refuses it with the authentication-required error and changes nothing

#### Scenario: Session-signal stream keeps its own answer
- **WHEN** a valid access token is presented to the session-signal stream, which this requirement does not cover
- **THEN** it is refused as the settled session-signals capability answers a request without a sign-in, and no stream opens

#### Scenario: Session caller unchanged
- **WHEN** the same user posts a password change with a session token
- **THEN** the change is judged as before

### Requirement: Per-endpoint guards judge an access-token caller like any other
Per-endpoint guards SHALL judge a caller a resource server authenticated by the same principal they judge for any caller: its subject, its roles and privileges as the source's caller strategy resolved them, and the token's scopes. No guard SHALL refuse such a caller only because it has no session, except as the recency guard's own rules state.

#### Scenario: Scope requirement at a guard
- **WHEN** a route guarded by a requirement for any of `orders:read` is called with an access token granted `orders:read`
- **THEN** the route is called

#### Scenario: Privilege guard
- **WHEN** a route guarded by "any of read on sales/order" is called with a provider access token whose user's active role grants it
- **THEN** the route is called

## MODIFIED Requirements

### Requirement: Logout ends the session
When enabled, logout SHALL answer POST requests on its path, by default `/sign-out`. It SHALL refuse with the authentication-required error a request with no authentication result, and, on a path a resource server covers, a request authenticated by an access token, which it cannot end: such a client ends its access through token revocation and the provider's end-session endpoint. Off every covered path, the resource server's off-prefix refusal applies first. When the request carries a session, logout SHALL delete it, and a session that is already gone SHALL NOT be an error. A stateless authenticated request SHALL be answered without deleting anything. Logout SHALL NOT call the handler. The consumer SHALL be able to change the path.

Logout SHALL accept an optional end-session step. When one is configured and the deleted session records an identity provider, logout SHALL call it after the delete, with the deleted session and the request's optional `state` form value. When the step returns a URL, logout SHALL answer 200 with a JSON body carrying it as `end_session_url` and with `Cache-Control: no-store`. Otherwise logout SHALL answer 200 with an empty body. A failure of the step SHALL be logged and SHALL NOT fail the logout, because the session has already been deleted. With no step configured, logout SHALL behave exactly as it does without federated login.

#### Scenario: Logout
- **WHEN** an authenticated request posts to the logout path
- **THEN** its session is deleted, the response is 200 with an empty body, and a later request with the same token is refused

#### Scenario: Session already deleted
- **WHEN** two logout requests for the same session race and the second finds the session gone
- **THEN** the second is also answered 200

#### Scenario: Anonymous logout
- **WHEN** a request with no authentication posts to the logout path
- **THEN** it is refused with the authentication-required error

#### Scenario: Consumer path
- **WHEN** the consumer sets the logout path to `/session/end`
- **THEN** logout answers there and a POST to `/sign-out` passes through

#### Scenario: Federated session with an end-session step
- **WHEN** an end-session step is configured and a session that records provider `corp` is logged out, and the step returns `https://idp.example/logout?id_token_hint=...`
- **THEN** the session is deleted before the step is called
- **AND** the response is 200 with `end_session_url` equal to that URL and `Cache-Control: no-store`

#### Scenario: Password session with an end-session step
- **WHEN** an end-session step is configured and a session established by a password is logged out
- **THEN** the step is not called and the response is 200 with an empty body

#### Scenario: End-session step fails
- **WHEN** an end-session step is configured and returns an error for a federated session
- **THEN** the session is deleted, the error is logged, and the response is 200 with an empty body

#### Scenario: Access-token caller
- **WHEN** a client holding only an access token posts to the logout path
- **THEN** it is refused with the authentication-required error, and no session or grant is ended
