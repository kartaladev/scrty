# Spec Delta

## MODIFIED Requirements

### Requirement: The code exchange authenticates the client and hides provider detail
After completing the flow, the library SHALL exchange the authorization code at the provider's token endpoint. The exchange SHALL carry the flow's PKCE verifier and the configured redirect URL. It SHALL authenticate the client with the client id and secret in the request body by default, or with HTTP Basic client credentials when the provider is configured for that method. The request SHALL be sent through the confined client's form POST, so the rule that no request body is replayed to another origin covers it. A provider error response, a malformed response or a response without an ID token SHALL fail the login as a provider failure. The provider's response body SHALL be logged at most in bounded form and SHALL never be returned to the caller. The provider's refresh token SHALL be discarded. The provider's access token SHALL be kept only in memory, for the callback that received it, and offered only as the upstream access of the requirement that upstream access reaches only a broker that asks for it; the library SHALL keep no reference to it once that callback returns.

#### Scenario: Default client authentication
- **WHEN** a code is exchanged for provider `corp` with no client authentication method configured
- **THEN** the token request carries `client_id` and `client_secret` as form fields and no authorization header
- **AND** it carries the code verifier

#### Scenario: Consumer selects HTTP Basic
- **WHEN** provider `corp` is configured for HTTP Basic client authentication
- **THEN** the token request carries the client id and secret in an HTTP Basic authorization header and no `client_secret` form field

#### Scenario: Provider rejects the code
- **WHEN** the token endpoint answers `invalid_grant` with a description
- **THEN** the login fails as a provider failure
- **AND** the description does not appear in the response to the browser

#### Scenario: Access token outlives no callback
- **WHEN** a callback receives a token response carrying an access token and a refresh token, and completes
- **THEN** neither token is stored in the flow, handoff or session records, nor carried in the callback result

### Requirement: The callback conveys the login by a short-lived single-use code
After the ID token is verified and the external identity resolves to an internal user, the callback SHALL NOT create a session and SHALL issue a handoff code, except under the requirement that a federated sign-in started from the provider's login page completes on the server. It SHALL issue the handoff code and redirect the browser to the post-login destination, with the code as a query parameter. The code SHALL:
- be drawn from a cryptographically secure source with at least 256 bits of secret entropy;
- be stored only as a digest of its secret;
- carry the user reference of the resolved user, the provider name, the verified issuer, the provider session id (which may be empty), the raw ID token, and the `amr` values (in order, without duplicates) and `acr` the verified ID token asserted, each of which may be empty;
- expire 60 seconds after issue.

The handoff store SHALL refuse to delete expired codes with a zero cutoff time. The expiry SHALL NOT be configurable: the code travels in a URL and a refused code stays live until it expires, so widening the window is a security decision, and the documentation SHALL say so. The redirect SHALL carry `Referrer-Policy: no-referrer` and `Cache-Control: no-store`, and SHALL clear the flow cookie. The code, the ID token and the claims SHALL never be written to a log by the library. The documentation SHALL state that a code travels in a URL and can be recorded by browser history and intermediaries until it expires or is spent.

#### Scenario: Successful callback
- **WHEN** a callback completes the flow, verifies the ID token and resolves user `u-1`
- **THEN** the browser is redirected to the destination with a `handoff` query parameter
- **AND** the response carries `Referrer-Policy: no-referrer` and `Cache-Control: no-store`
- **AND** no session exists yet for `u-1`

#### Scenario: Asserted assurance travels with the code
- **WHEN** a callback verifies an ID token asserting `amr` `["pwd","mfa","mfa"]` and `acr` `urn:corp:loa:2` and issues a code
- **THEN** the stored record carries `amr` `["pwd","mfa"]` and `acr` `urn:corp:loa:2`

#### Scenario: Digest at rest
- **WHEN** a handoff code is issued and its stored record is read
- **THEN** the record does not contain the code's secret

#### Scenario: Zero purge cutoff for handoff codes
- **WHEN** expired handoff codes are deleted with a zero cutoff time
- **THEN** an error is returned and every unexpired code remains redeemable

#### Scenario: Expired at the deadline
- **WHEN** a code issued at 10:00:00 is redeemed at 10:01:00
- **THEN** redemption is refused with the invalid-handoff outcome

### Requirement: The post-login destination is allowlisted
The destination requested when a login starts SHALL be recorded untrusted, and SHALL be used only when it exactly matches an entry of the redirect allowlist. Otherwise the destination SHALL be `/`. A requested destination longer than 2048 bytes SHALL NOT be recorded, and the login SHALL proceed as if none was requested, because no allowlist entry can be that long. The allowlist SHALL be empty by default. Each entry, and each origin the consumer declares, SHALL be validated at construction by the rules of the `outbound-http-confinement` capability's requirement that browser redirect targets are host-relative or declared; an invalid entry or origin SHALL fail construction. An allowlist entry longer than 2048 bytes SHALL fail construction. The destination SHALL be checked again against the allowlist when it is used. The OIDC allowlist SHALL be configured separately from any other flow's. The one exception is server-side completion of a federated provider sign-in: with it enabled, a destination that is the provider's login URL carrying only a parked request's handle SHALL be used without an allowlist entry, under the requirement that logins not tied to a parked request keep their conveyance.

#### Scenario: Unlisted destination
- **WHEN** a login starts with destination `https://evil.example/` and completes
- **THEN** the redirect goes to `/` with the handoff code

#### Scenario: Scheme-relative entry
- **WHEN** the allowlist contains `//evil.example/app`
- **THEN** construction fails with a configuration error

#### Scenario: Consumer declares an origin
- **WHEN** the consumer declares origin `https://app.example` and allowlists `https://app.example/welcome`, and a login starts with that destination
- **THEN** the redirect goes to `https://app.example/welcome` with the handoff code

#### Scenario: Absolute entry on an undeclared origin
- **WHEN** the allowlist contains `https://partner.example/landing` and no origin is declared
- **THEN** construction fails with a configuration error

#### Scenario: Over-long destination
- **WHEN** a login starts with a destination of 1 MiB
- **THEN** the flow records no destination, and the completed login redirects to `/`

#### Scenario: Provider login page with completion enabled
- **WHEN** server-side completion is enabled, the allowlist is empty, and a login starts with destination `<login URL>?req=h-1`
- **THEN** that destination is honoured by completion or by its handoff fallback, and is never replaced by `/`, including in the answer to the handoff code's redemption

## ADDED Requirements

### Requirement: Upstream access reaches only a broker that asks for it
The callback SHALL offer the upstream access, holding the provider's access token, to a broker that declares it accepts upstream access, and SHALL call any other broker exactly as before. The upstream access SHALL print, format and log as a fixed redacted text under every verb, also when it is a field of a consumer's struct, exported or not. The library SHALL never write the access token to a log, an event, an error, a record or a response.

#### Scenario: Broker that does not ask
- **WHEN** the consumer's broker does not declare that it accepts upstream access
- **THEN** it is called with the verified identity alone, as without this change

#### Scenario: Broker that asks
- **WHEN** the consumer's broker declares that it accepts upstream access and a callback succeeds
- **THEN** the broker receives the verified identity and upstream access holding the token response's access token

#### Scenario: Redacted when printed
- **WHEN** upstream access is formatted with `%v`, `%+v` or `%#v`, logged as an attribute, or printed as an exported or unexported field of a consumer's struct
- **THEN** the output does not contain the access token

#### Scenario: Token response without an access token
- **WHEN** the token response carries an ID token and no access token
- **THEN** the login proceeds, and the upstream access reports that no access token is available

### Requirement: UserInfo is fetched through the confined client and bound to the ID token's subject
The upstream access SHALL fetch the provider's UserInfo by a GET carrying the access token as a bearer credential, through the confined client and its response size bound. It SHALL return the JSON object's members unchanged. It SHALL fail with a UserInfo failure when no endpoint is known, no access token is held, or the answer is not 200, not a JSON object, or has no `sub` or another `sub` than the ID token's.

#### Scenario: UserInfo returned
- **WHEN** UserInfo answers 200 with `{"sub":"s-1","email":"a@corp.example","password":"…"}` and the ID token's subject is `s-1`
- **THEN** the fetch returns those members unchanged

#### Scenario: Subject mismatch
- **WHEN** UserInfo answers with `sub` `s-2` and the ID token's subject is `s-1`
- **THEN** the fetch fails with the UserInfo failure and returns no members

#### Scenario: Provider refuses the token
- **WHEN** UserInfo answers 401
- **THEN** the fetch fails with the UserInfo failure, and neither the error nor any log record holds the access token or the response body

#### Scenario: Oversized answer
- **WHEN** UserInfo answers with a body larger than the confined client's response bound
- **THEN** the fetch fails with the UserInfo failure

#### Scenario: Signed UserInfo
- **WHEN** UserInfo answers 200 with content type `application/jwt`
- **THEN** the fetch fails with the UserInfo failure

### Requirement: A provider's UserInfo endpoint is discovered or pinned
A provider's UserInfo endpoint SHALL be its discovery document's `userinfo_endpoint`, under the discovery rules that confine every other endpoint. A consumer SHALL be able to pin it per provider instead. A pinned endpoint SHALL be validated at construction as other pinned endpoints are. Neither discovery nor validation SHALL require a UserInfo endpoint.

#### Scenario: Discovered endpoint
- **WHEN** provider `corp`'s discovery document names `userinfo_endpoint` `https://corp.example/userinfo`
- **THEN** UserInfo is fetched from `https://corp.example/userinfo`

#### Scenario: Consumer pins the endpoint
- **WHEN** provider `corp` pins its UserInfo endpoint to `https://corp.example/me`
- **THEN** UserInfo is fetched from `https://corp.example/me`

#### Scenario: Pinned endpoint with a refused scheme
- **WHEN** provider `corp` pins its UserInfo endpoint to an `http` URL the confined client does not allow
- **THEN** construction fails with a configuration error

#### Scenario: No endpoint anywhere
- **WHEN** provider `corp` has no discovered or pinned UserInfo endpoint and a broker fetches UserInfo
- **THEN** the fetch fails with the UserInfo failure, and logins that do not fetch it are unaffected

### Requirement: A federated sign-in started from the provider's login page completes on the server
A consumer SHALL be able to enable server-side completion when the chain also serves the OpenID Provider. It is off by default. A login whose destination is the provider's login URL carrying only a parked request's handle SHALL then be completed by the callback with the same checks and steps a handoff redemption followed by a resume performs, in that order, as the next requirements state. It SHALL return no session credential to the browser.

#### Scenario: Default keeps the handoff
- **WHEN** completion is not enabled and a login started with destination `<login URL>?req=<handle>` succeeds
- **THEN** the browser is redirected with a handoff code, as without this change

#### Scenario: Sign-in completed with no page script
- **WHEN** completion is enabled, a login started from the provider's login page with handle `h-1` succeeds, and the policy owes nothing
- **THEN** a session recording the OIDC first factor, provider, issuer, provider session and asserted assurance is created
- **AND** the browser receives the provider's browser-session cookie and a 303 to the client's redirect URI with an authorization code, `state` and `iss`
- **AND** the response carries `Cache-Control: no-store` and `Referrer-Policy: no-referrer`, and no handoff code and no session credential

#### Scenario: Consent needed
- **WHEN** completion is enabled and the resumed request needs consent
- **THEN** the browser is redirected with 303 to the consent URL carrying the handle

### Requirement: Completion checks the parked request before it changes anything
Before it loads the user or creates a session, completion SHALL check that the parked request exists, has not expired and is bound to the browser's flow cookie. A request that fails the check SHALL be answered with the provider's unknown-handle outcome, charged to the request's source, with no session, no event of a successful login and no change to the user's held recoveries.

#### Scenario: Parked request expired
- **WHEN** completion is enabled and the handle `h-1` expired before the callback
- **THEN** the callback fails with the provider's unknown-handle outcome, no session is created, and the source is charged

#### Scenario: Handle of another browser
- **WHEN** completion is enabled and the browser's flow cookie does not bind handle `h-1`
- **THEN** the callback fails with the provider's unknown-handle outcome and no session is created

### Requirement: Completion builds the session as a redemption does
Completion SHALL load the user through the configured user loader and refuse a missing, disabled or mismatched user as a redemption does. It SHALL run the post-authentication policy on the stored details, including the password-change time, and the asserted assurance. When nothing is owed it SHALL create the session through the login completion step, with the external session and assurance in its creating write, after cancelling the user's held recoveries.

#### Scenario: Stored roles, not the broker's
- **WHEN** the broker's principal carries role `admin` and the user's stored roles are `viewer`
- **THEN** the session created by completion holds `viewer` only

#### Scenario: Password age judged from the stored time
- **WHEN** the user's stored password-change time makes the policy require a password change
- **THEN** completion does not resume the request and falls back to the handoff

#### Scenario: Held recovery cancelled
- **WHEN** the user has a held account recovery and completion signs them in
- **THEN** the held recovery is cancelled before the session is stored

#### Scenario: Policy denies
- **WHEN** completion is enabled and the post-authentication policy denies the user
- **THEN** the callback fails with the policy's reason and no session is created

### Requirement: Completion resumes only a fully authenticated session
Before it resumes, completion SHALL judge the new session under the chain's per-request policy as the resume endpoint judges a sign-in, and SHALL build the provider sign-in with the chain's sign-in assurance mapping. After the resume it SHALL confirm the sign-in as the resume endpoint does. A per-request refusal, a resume that fails or answers without a code, and a failed confirmation SHALL each end the session just stored and issue no redirect to the client.

#### Scenario: Per-request policy refuses
- **WHEN** a consumer per-request policy refuses the new session
- **THEN** the callback fails with that refusal, the session is ended, and no code is issued

#### Scenario: Consumer assurance mapping
- **WHEN** the consumer replaced the sign-in assurance mapping
- **THEN** the provider sign-in carries the values that mapping returns

#### Scenario: Resume answers login required
- **WHEN** the parked request carries an `id_token_hint` naming another subject and the resume answers `login_required`
- **THEN** the session just stored is ended and the browser receives the client's error response

#### Scenario: Confirmation fails
- **WHEN** the sign-in ends between the resume and its confirmation
- **THEN** the callback fails with the re-authentication outcome and no redirect to the client is sent

#### Scenario: Ending the session fails
- **WHEN** completion must end the session it stored and the end fails
- **THEN** an error record is logged and the original refusal is returned unchanged

### Requirement: An owed step falls back to the handoff to the login page
When server-side completion is enabled and the sign-in still owes a step (a second factor, an enrolment, a recovery or a password change), the callback SHALL create no session. It SHALL instead convey the login by a handoff code to the provider's login URL, keeping the handle, so the page can finish the step and resume as it does today.

#### Scenario: Second factor owed
- **WHEN** completion is enabled, the user must use a second factor, and the provider asserted no `amr` that meets it
- **THEN** the browser is redirected to `<login URL>?req=<handle>` with a `handoff` query parameter, and no session exists yet

#### Scenario: Provider assurance meets the requirement
- **WHEN** completion is enabled, the user must use a second factor, and the provider's asserted `amr` meets it
- **THEN** the sign-in completes on the server with no handoff

### Requirement: Logins not tied to a parked request keep their conveyance
With server-side completion enabled, a login whose destination is not the provider's login URL carrying only one handle SHALL be conveyed by the handoff code to the allowlisted destination, exactly as without completion. The login URL SHALL be recognised by exact scheme, host, port and path, and the handle by being the only query parameter.

#### Scenario: Ordinary destination
- **WHEN** completion is enabled and a login started with destination `/welcome` succeeds
- **THEN** the browser is redirected to `/welcome` with a handoff code

#### Scenario: Extra parameter
- **WHEN** completion is enabled and a login started with destination `<login URL>?req=h-1&x=1`
- **THEN** the login is conveyed by a handoff code to the allowlisted destination or `/`

#### Scenario: Look-alike path
- **WHEN** completion is enabled and a login started with destination `<login URL>/?req=h-1` or with the path percent-encoded
- **THEN** the login is conveyed by a handoff code to the allowlisted destination or `/`

### Requirement: Server-side completion wiring mistakes fail at construction
Assembling a chain SHALL fail with a configuration error when server-side completion is enabled and the chain does not serve the OpenID Provider; a callback success handler or a custom handoff redeemer is set; no handoff manager or user loader is configured; OIDC login's session manager is not the provider's; a provider's callback URL is off the issuer's origin, where the provider's cookies are not sent; or the provider's login URL carries its own query.

#### Scenario: Completion without the provider
- **WHEN** completion is enabled on a chain that does not serve the OpenID Provider
- **THEN** assembling the chain fails with a configuration error

#### Scenario: Completion beside a callback success handler
- **WHEN** completion is enabled and a callback success handler is supplied
- **THEN** assembling the chain fails with a configuration error

#### Scenario: Completion beside a custom redeemer
- **WHEN** completion is enabled and a handoff redeemer replaces the default
- **THEN** assembling the chain fails with a configuration error

#### Scenario: Completion without the handoff
- **WHEN** completion is enabled and no handoff manager is configured
- **THEN** assembling the chain fails with a configuration error

#### Scenario: Callback on another origin
- **WHEN** completion is enabled and provider `corp`'s redirect URL is on a host other than the issuer's
- **THEN** assembling the chain fails with a configuration error naming `corp`

#### Scenario: Login URL with its own query
- **WHEN** completion is enabled and the provider's login URL is `https://id.example/login?tenant=a`
- **THEN** assembling the chain fails with a configuration error


### Requirement: A user loader without completion is a wiring mistake
Assembling a chain SHALL fail with a configuration error when OIDC login is given a user loader while server-side completion is off, because nothing would use it.

#### Scenario: User loader without completion
- **WHEN** OIDC login is given a user loader and completion is not enabled
- **THEN** assembling the chain fails with a configuration error
