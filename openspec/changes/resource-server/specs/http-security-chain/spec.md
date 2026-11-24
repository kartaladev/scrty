## ADDED Requirements

### Requirement: Session-only endpoints refuse an access-token caller
The chain's endpoints that act on the caller's sign-in session SHALL refuse a caller a resource server authenticated, with the authentication-required error, before changing anything: password change, passkey registration and management, second-factor enrolment and verification, re-authentication, session renewal, session management, and logout. No option SHALL make them accept such a caller.

#### Scenario: Password change with an access token
- **WHEN** a client holding a valid access token for the user posts a password change
- **THEN** the request is refused with the authentication-required error, and the password is unchanged

#### Scenario: Logout with an access token
- **WHEN** a client holding only an access token posts to the logout endpoint
- **THEN** the request is refused with the authentication-required error, and no session or grant is ended

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
