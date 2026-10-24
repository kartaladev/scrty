# Spec Delta

## ADDED Requirements

### Requirement: A resolved session authenticates only its own, active user
Signed bearer tokens, session references and the renewal endpoint, including a late renewal, SHALL refuse with the authentication-required error when the reloaded user's identifier differs from the user reference the session records, or when the reloaded user is not active. A refused session SHALL NOT be revoked by the refusal; it authenticates again if its user is re-enabled before it expires.

#### Scenario: Username reassigned to another user
- **WHEN** a signed bearer token names user `u-1`'s session, and the username in the token now belongs to user `u-2`
- **THEN** the request is refused with the authentication-required error and the handler does not run

#### Scenario: Disabled user's live session
- **WHEN** a request carries a valid credential for a live session whose user has been disabled
- **THEN** it is refused with the authentication-required error

#### Scenario: Disabled user renews
- **WHEN** a disabled user's session posts to the renewal endpoint, inside or after the session's grace window
- **THEN** it is refused with the authentication-required error and no successor is created

#### Scenario: Re-enabled user
- **WHEN** a disabled user is re-enabled while their session is still live
- **THEN** that session authenticates again

### Requirement: Credential-bearing responses are never cached
Every default responder that returns a credential, a challenge document or a session SHALL set `Cache-Control: no-store`. That covers form login, magic-link redemption, MFA begin and verify, passkey login, renewal, handoff redemption and recovery. A consumer responder SHALL own its own headers.

#### Scenario: Default form login response
- **WHEN** a form login succeeds with the default responder
- **THEN** the response carries `Cache-Control: no-store`

#### Scenario: MFA begin response
- **WHEN** an MFA begin succeeds with the default responder
- **THEN** the response carries `Cache-Control: no-store`

#### Scenario: Consumer responder
- **WHEN** the consumer replaces the form login responder
- **THEN** the library adds no cache header to the consumer's response

### Requirement: An ownership guard without a checker or extractor fails at wiring
Building an ownership guard with a nil ownership checker or a nil identifier extractor SHALL panic at wiring time with a message naming the missing dependency, and SHALL NOT produce a guard that panics on a request.

#### Scenario: Nil checker
- **WHEN** the consumer builds an ownership guard with a nil checker
- **THEN** building it panics with a message naming the checker, before any request is served

#### Scenario: Nil extractor
- **WHEN** the consumer builds a resource guard with a nil identifier extractor
- **THEN** building it panics with a message naming the extractor

## MODIFIED Requirements

### Requirement: The cool-down guard runs after authentication
When the recovery cool-down is enabled, the chain SHALL register its guard after bearer authentication, so it sees the session's user. It SHALL act only on the requests the consumer marked, each marked by method and path. A request SHALL match a marked route when its method is the marked method, treating `HEAD` as `GET`, and its path equals the marked path ignoring ASCII letter case and any trailing slashes (a marked or requested `/` stays `/`), so that no framework's lenient routing can reach a marked route by a path the guard does not match. Matching SHALL be this broad only for the cool-down, whose matches refuse; every path the chain exempts from a gate or answers itself SHALL stay an exact match. It SHALL let requests without a session through for later interceptors to decide.

#### Scenario: Unauthenticated marked request
- **WHEN** a request without a session posts to a marked route
- **THEN** the cool-down guard does not refuse it, and authorization decides

#### Scenario: Letter case and trailing slash
- **WHEN** `POST /account/email` is marked and a recovered session inside its cool-down posts to `/Account/Email`, `/account/email/` or `/account/email//`
- **THEN** the request is refused as it would be on `/account/email`

#### Scenario: HEAD on a marked GET route
- **WHEN** `GET /account/export` is marked and a recovered session inside its cool-down sends `HEAD /account/export`
- **THEN** the request is refused

#### Scenario: Gate exemptions stay exact
- **WHEN** a session pending a second factor sends `POST /MFA/verify/totp` to a chain whose verify prefix is `/mfa/verify`
- **THEN** the MFA gate does not exempt it, and refuses it
