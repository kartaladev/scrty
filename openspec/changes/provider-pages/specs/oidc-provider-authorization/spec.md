# Spec Delta

## MODIFIED Requirements

### Requirement: A pending request is resumed with the sign-in that completes it
The resume endpoint SHALL accept a handle together with a sign-in credential in the `Authorization` header and the flow cookie. On a chain whose sign-ins are cookie sessions, it SHALL accept the request's cookie sign-in in place of the `Authorization` header. It SHALL refuse the resume as an unknown handle when the handle is unknown, expired past the grace window, already spent for its stage, or not bound to the flow cookie sent. It SHALL refuse the sign-in as unauthenticated when the credential does not authenticate.

#### Scenario: Resume from another browser
- **WHEN** a resume presents a valid handle and a valid sign-in, but not the flow cookie set for that handle
- **THEN** the resume is refused as an unknown handle, and no code is issued

#### Scenario: Handle resumed twice
- **WHEN** a handle's login stage is resumed successfully, and the same stage is resumed again
- **THEN** the second resume is refused as an unknown handle

#### Scenario: Login finished in another browser
- **WHEN** a user starts a request in one browser, opens a magic link in another, and that browser's page resumes the handle
- **THEN** the resume is refused as an unknown handle, and the user must start again from the relying party

#### Scenario: No sign-in credential
- **WHEN** a resume presents a valid handle and flow cookie but no `Authorization` header
- **THEN** it is refused as unauthenticated

#### Scenario: Cookie sign-in on a cookie chain
- **WHEN** on a chain whose sign-ins are cookie sessions, a resume presents a valid handle, its flow cookie and a valid session cookie, and no `Authorization` header
- **THEN** the login stage is resumed with that sign-in

### Requirement: The sign-in credential is never read from the query
The resume endpoint SHALL never accept the sign-in credential from a query parameter. It SHALL accept the provider's browser session in its place only at the consent stage (`oidc-provider-authorization`, "A browser session"), and the chain's cookie sign-in in its place at either stage on a chain whose sign-ins are cookie sessions.

#### Scenario: Credential in the query
- **WHEN** a resume carries a sign-in credential as a query parameter, and no `Authorization` header
- **THEN** it is refused as unauthenticated

#### Scenario: Session identifier in the query on a cookie chain
- **WHEN** on a cookie chain, a resume carries a session identifier as a query parameter and no session cookie
- **THEN** it is refused as unauthenticated

### Requirement: The resume answers with where the browser goes next
A successful resume SHALL answer 200 with a JSON object holding `redirect_to`:
- the consumer's consent URL with the handle, when consent is needed;
- otherwise, the client's redirect URI with the authorization response.

It SHALL NOT answer with a redirect status, except on a chain whose sign-ins are cookie sessions, where a form post or a request preferring HTML SHALL be answered `303 See Other` to the same location. The response SHALL carry `Cache-Control: no-store`.

#### Scenario: Consent needed
- **WHEN** a resume succeeds and the client requires consent for the requested scopes
- **THEN** the response is 200 with `redirect_to` set to the consent URL carrying the handle

#### Scenario: No consent needed
- **WHEN** a resume succeeds and no consent is needed
- **THEN** the response is 200 with `redirect_to` set to the redirect URI carrying `code`, `state` and `iss`

#### Scenario: Form post on a cookie chain
- **WHEN** on a cookie chain, the consent page posts a form granting `openid profile`
- **THEN** the response is `303` to the redirect URI carrying `code`, `state` and `iss`, with `Cache-Control: no-store`

### Requirement: The login page can cancel a parked request
The chain SHALL serve a cancel endpoint, at `/authorize/cancel` under the provider prefix by default, taking a POST with the handle and the flow cookie and no sign-in. It SHALL end the login-stage request with `access_denied` and answer 200 with `redirect_to` as a resume does, with `Cache-Control: no-store`, or, on a chain whose sign-ins are cookie sessions, `303` to that location for a form post or a request preferring HTML. It SHALL follow the resume endpoint's TLS, origin, body and throttle rules.

#### Scenario: User gives up on the login page
- **WHEN** the login page POSTs the cancel endpoint with a live handle and its flow cookie
- **THEN** the response is 200 with `redirect_to` set to the client's redirect URI carrying `error=access_denied`, `state` and `iss`

#### Scenario: Unknown handle charged
- **WHEN** the cancel endpoint receives an unknown handle
- **THEN** it is refused as an unknown handle and the handle is charged to the source, as at the resume endpoint

#### Scenario: Consumer moves the endpoint
- **WHEN** the consumer sets the cancel endpoint's path to `/login/give-up`
- **THEN** the cancel is served there and not at the default path

#### Scenario: Form cancel on a cookie chain
- **WHEN** on a cookie chain, the login page posts a cancel form with a live handle and its flow cookie
- **THEN** the response is `303` to the client's redirect URI carrying `error=access_denied`, `state` and `iss`

## ADDED Requirements

### Requirement: Page-facing provider endpoints accept a form body on a cookie chain
On a chain whose sign-ins are cookie sessions, the resume and cancel endpoints SHALL accept an `application/x-www-form-urlencoded` body as well as JSON, with the same fields: `req` for the handle, `scopes` repeated once per granted scope, and `deny`. A form whose fields cannot be read SHALL be refused as malformed, as a malformed JSON body is. Other chains SHALL keep accepting JSON only.

#### Scenario: Form consent
- **WHEN** on a cookie chain, the consent page posts `req=<handle>&scopes=openid&scopes=profile`
- **THEN** the consent stage is resumed granting `openid` and `profile`

#### Scenario: Form on a token chain
- **WHEN** on a chain without the cookie session, a form body is posted to the resume endpoint
- **THEN** it is refused as malformed
