# Spec Delta

## Purpose

Defines the provider's authorization endpoint for the authorization code flow: how a request is validated, parked under a handle while the consumer's own pages sign the user in and ask for consent, resumed, and answered with a single-use authorization code.

## ADDED Requirements

### Requirement: The authorization endpoint serves the code flow only
The authorization endpoint SHALL accept requests by GET and by form POST. It SHALL support `response_type=code` with the query response mode only. Any other response type SHALL be answered with `unsupported_response_type`, and the implicit and hybrid flows SHALL NOT be available by any option. A parameter given more than once SHALL make the request invalid. Unknown parameters SHALL be ignored.

#### Scenario: Code request accepted
- **WHEN** a valid request for `response_type=code` arrives by GET
- **THEN** it proceeds to the login stage

#### Scenario: Implicit flow refused
- **WHEN** a request for a registered client and redirect URI asks for `response_type=id_token token`
- **THEN** the browser is redirected to the redirect URI with `error=unsupported_response_type`

#### Scenario: Repeated parameter
- **WHEN** a request carries `scope` twice
- **THEN** it is answered with `invalid_request`

### Requirement: An invalid client or redirect URI is never redirected to
The provider SHALL validate the `client_id` and the `redirect_uri` before anything else. When the client is unknown, the redirect URI is missing or does not match one the client registered, the provider SHALL NOT redirect the browser. It SHALL report the failure as a chain error, a bare 400 by default, which the consumer's error handler may render.

#### Scenario: Unregistered redirect URI
- **WHEN** a request for a known client names a redirect URI the client did not register
- **THEN** the response is 400, it carries no `Location` header, and nothing is parked

#### Scenario: Unknown client
- **WHEN** a request names an unknown `client_id` and any redirect URI
- **THEN** the response is 400 and the browser is not redirected

#### Scenario: Consumer renders the error page
- **WHEN** the consumer's error handler renders an HTML page for chain errors, and a request names an unregistered redirect URI
- **THEN** the consumer's page is shown, and the browser is still not redirected

### Requirement: Errors after validation are redirected with state and issuer
Once the client and redirect URI are valid, every other error SHALL be answered by a 303 redirect to that redirect URI, carrying `error`, the request's `state` unchanged when one was sent, and `iss` set to the provider's issuer. By default the response SHALL NOT carry `error_description`.

#### Scenario: Missing scope
- **WHEN** a request with a valid client and redirect URI has no `scope`
- **THEN** the browser is redirected with `error=invalid_request`, the request's `state` and `iss`, and the status is 303

### Requirement: PKCE with S256 is required for every client
Every authorization request SHALL carry a `code_challenge` with `code_challenge_method=S256`, for public and confidential clients alike. A request with no challenge, with the `plain` method, or with any other method SHALL be answered with `invalid_request`. A challenge SHALL be 43 to 128 characters from the unreserved set.

#### Scenario: Missing challenge from a confidential client
- **WHEN** a confidential client sends a request without `code_challenge`
- **THEN** it is answered with `invalid_request`

#### Scenario: Plain method
- **WHEN** a request sends `code_challenge_method=plain`
- **THEN** it is answered with `invalid_request`

### Requirement: Scopes are limited to what the client may ask for
The provider SHALL treat a request whose scope includes `openid` as an OpenID Connect request, which receives an ID token. A request without `openid` SHALL be a plain OAuth request that receives no ID token. Each client SHALL have a set of allowed scopes. A requested scope outside it SHALL be answered with `invalid_scope`.

#### Scenario: Scope not allowed
- **WHEN** a client allowed `openid profile` asks for `openid admin`
- **THEN** the browser is redirected with `error=invalid_scope`

#### Scenario: Plain OAuth request
- **WHEN** a client asks for `api.read` without `openid`
- **THEN** the flow completes without an ID token

### Requirement: Requested resources are limited to what the client may ask for
A request MAY carry one or more `resource` parameters. Each SHALL be an absolute URI without a fragment, and SHALL be one the client is allowed. Otherwise the request SHALL be answered with `invalid_target`.

#### Scenario: Resource not allowed
- **WHEN** a client allowed `https://api.example.com` asks for `resource=https://other.example.com`
- **THEN** the browser is redirected with `error=invalid_target`

### Requirement: Request objects are not supported
The provider SHALL answer a request carrying `request` with `request_not_supported`, and one carrying `request_uri` with `request_uri_not_supported`. It SHALL NOT fetch a request URI.

#### Scenario: Request URI given
- **WHEN** a request carries `request_uri=https://rp.example.com/req/1`
- **THEN** the browser is redirected with `error=request_uri_not_supported`, and no outbound request is made

### Requirement: Every authorization response carries the issuer
Every authorization response sent to a redirect URI, success or error, SHALL carry `iss` equal to the provider's issuer identifier. The `state` sent with the request SHALL be returned unchanged, and omitted when none was sent.

#### Scenario: Success response
- **WHEN** an authorization request completes
- **THEN** the redirect carries `code`, the request's `state`, and `iss`

### Requirement: Every redirect the provider sends is a 303
The authorization endpoint, the resume endpoint's navigation target, and every other provider redirect SHALL use status 303, and never 307 or 308.

#### Scenario: Form POST request
- **WHEN** an authorization request arrives by form POST and is parked
- **THEN** the browser is sent to the login page with status 303

### Requirement: A valid request is parked under a handle bound to the browser
A valid request SHALL be stored as a pending request under a new handle. The handle SHALL carry at least 128 bits from a cryptographically secure source, and SHALL be stored only as a digest. The provider SHALL set a flow cookie bound to the handle, `HttpOnly`, `Secure` and `SameSite=Lax`. It SHALL then redirect the browser to the consumer's login URL with the handle as a query parameter. A pending request SHALL expire 10 minutes after it was created.

#### Scenario: Request parked
- **WHEN** a valid request arrives
- **THEN** the browser is redirected with 303 to the login URL with the handle, the response sets the flow cookie, and the handle is not stored in clear

#### Scenario: Handle expired
- **WHEN** a resume presents a handle 11 minutes after its request was parked
- **THEN** the resume is refused as an unknown handle

#### Scenario: Consumer shortens the lifetime
- **WHEN** the consumer sets the pending-request lifetime to 5 minutes, and a resume presents a handle after 6 minutes
- **THEN** the resume is refused as an unknown handle

### Requirement: The pending-request lifetime is bounded
A pending-request lifetime set by the consumer SHALL be positive and at most 30 minutes. Any other value SHALL fail construction.

#### Scenario: Lifetime too long
- **WHEN** the consumer sets the pending-request lifetime to 2 hours
- **THEN** construction fails with a configuration error

### Requirement: The login and consent URLs are required
Building the provider SHALL fail with a configuration error when the consumer gives no login URL or no consent URL. Both SHALL be absolute URIs on the provider's own site.

#### Scenario: Consent URL missing
- **WHEN** the provider is built with a login URL and no consent URL
- **THEN** construction fails with a configuration error naming the consent URL

### Requirement: The consumer's pages can read a pending request without its secrets
The provider SHALL let the consumer's pages read a pending request by its handle, with the flow cookie present. The view SHALL hold the client's identifier and name, the requested and already-granted scopes, `prompt`, `max_age`, `login_hint`, `ui_locales` and the stage. It SHALL NOT hold the PKCE challenge, the nonce, the state or the redirect URI.

#### Scenario: Login page reads the request
- **WHEN** the login page reads a pending request by its handle
- **THEN** it receives the client's name and the scopes, and no challenge, nonce or state

#### Scenario: Read without the flow cookie
- **WHEN** a request without the flow cookie reads a pending request by its handle
- **THEN** it is refused as an unknown handle

### Requirement: A pending request is resumed with the sign-in that completes it
The resume endpoint SHALL accept a handle together with a sign-in credential in the `Authorization` header and the flow cookie. It SHALL refuse the resume as an unknown handle when the handle is unknown, expired, already spent for its stage, or not bound to the flow cookie sent. It SHALL refuse the sign-in as unauthenticated when the credential does not authenticate. It SHALL never accept the sign-in credential from a cookie or a query parameter.

#### Scenario: Resume from another browser
- **WHEN** a resume presents a valid handle and a valid sign-in, but not the flow cookie set for that handle
- **THEN** the resume is refused as an unknown handle, and no code is issued

#### Scenario: Handle resumed twice
- **WHEN** a handle's login stage is resumed successfully, and the same stage is resumed again
- **THEN** the second resume is refused as an unknown handle

#### Scenario: No sign-in credential
- **WHEN** a resume presents a valid handle and flow cookie but no `Authorization` header
- **THEN** it is refused as unauthenticated

### Requirement: Only a complete sign-in can resume a request
The resume SHALL be refused unless the sign-in passes the chain's per-request policy as a fully authenticated session. A session that still owes a second factor, is pending recovery, is limited to MFA enrolment, or must change its password SHALL be refused with the same refusal the chain gives that state elsewhere. The handle SHALL stay unspent, so the page can finish that step and resume again.

#### Scenario: Second factor owed
- **WHEN** a resume presents a session that has passed the first factor and owes a second
- **THEN** it is refused with the second-factor challenge, and the handle can still be resumed

### Requirement: Freshness requests are met by the sign-in's authentication time
The provider SHALL compare `prompt=login` and `max_age` with the time the user last actually authenticated in the presented sign-in, never with the time of the resume or of a renewal. For `prompt=login`, the user SHALL have authenticated after the request was parked. For `max_age`, no more than `max_age` seconds before the resume. `max_age=0` SHALL behave as `prompt=login`. A failed condition SHALL answer that re-authentication is needed, and SHALL leave the handle unspent.

#### Scenario: Sign-in too old
- **WHEN** a request carries `max_age=300` and the presented sign-in authenticated 20 minutes earlier
- **THEN** the resume answers that re-authentication is needed, and no code is issued

#### Scenario: Renewed sign-in is not fresh
- **WHEN** a request carries `prompt=login`, and the presented sign-in was renewed after the request was parked but authenticated before it
- **THEN** the resume answers that re-authentication is needed

#### Scenario: Re-authenticated after parking
- **WHEN** a request carries `prompt=login`, and the user re-authenticates after it was parked
- **THEN** the resume proceeds

### Requirement: Silent authentication answers that login is required
A request with `prompt=none` SHALL be answered with a redirect carrying `error=login_required`. It SHALL NOT show the login or consent page. A request combining `none` with another `prompt` value SHALL be answered with `invalid_request`.

#### Scenario: Silent request
- **WHEN** a request carries `prompt=none`
- **THEN** the browser is redirected to the redirect URI with `error=login_required`, `state` and `iss`

#### Scenario: Contradictory prompt
- **WHEN** a request carries `prompt=none login`
- **THEN** it is answered with `invalid_request`

### Requirement: An ID token hint must name the user who signs in
When a request carries `id_token_hint`, the provider SHALL accept it only if it is an ID token this provider issued, judged by its signature and issuer, with its expiry ignored. Otherwise the request SHALL be answered with `invalid_request`. When the user of the resumed sign-in is not the hint's subject, the resume SHALL answer with a redirect carrying `error=login_required`.

#### Scenario: Another user signs in
- **WHEN** a request carries a valid hint for user `u-1`, and the resume presents a sign-in of user `u-2`
- **THEN** the browser is redirected with `error=login_required`

### Requirement: The resume answers with where the browser goes next
A successful resume SHALL answer 200 with a JSON object holding `redirect_to`:
- the consumer's consent URL with the handle, when consent is needed;
- otherwise, the client's redirect URI with the authorization response.

It SHALL NOT answer with a redirect status. The response SHALL carry `Cache-Control: no-store`.

#### Scenario: Consent needed
- **WHEN** a resume succeeds and the client requires consent for the requested scopes
- **THEN** the response is 200 with `redirect_to` set to the consent URL carrying the handle

#### Scenario: No consent needed
- **WHEN** a resume succeeds and no consent is needed
- **THEN** the response is 200 with `redirect_to` set to the redirect URI carrying `code`, `state` and `iss`

### Requirement: Authorization codes are single-use, short-lived and bound
An authorization code SHALL:
- carry at least 128 bits from a cryptographically secure source, and be stored only as a digest;
- expire 60 seconds after issue by default;
- be bound to the client, the redirect URI, the PKCE challenge, the nonce, the granted scopes and resources, the sign-in it came from and its authentication facts, and any key the request bound it to.

A consumer MAY set the code lifetime to any value up to 10 minutes. A longer value SHALL fail construction.

#### Scenario: Code expires
- **WHEN** a code is exchanged 61 seconds after issue, under the default
- **THEN** the exchange is refused with `invalid_grant`

#### Scenario: Consumer lengthens the lifetime
- **WHEN** the consumer sets the code lifetime to 5 minutes, and a code is exchanged after 2 minutes
- **THEN** the exchange proceeds

#### Scenario: Lifetime above the bound
- **WHEN** the consumer sets the code lifetime to 15 minutes
- **THEN** construction fails with a configuration error

### Requirement: The authorization endpoint is throttled per source
Requests to the authorization and resume endpoints SHALL pass through the chain's per-source throttling. An unknown handle at the resume endpoint SHALL be charged to the source.

#### Scenario: Guessing handles
- **WHEN** one source presents unknown handles past the throttle's limit
- **THEN** its further resumes are refused by the throttle before the handle is looked up

### Requirement: Login hints and locales are passed to the consumer's page
`login_hint`, `ui_locales` and `prompt=select_account` SHALL be kept on the pending request and shown to the consumer's pages. The provider SHALL NOT act on them itself.

#### Scenario: Login hint
- **WHEN** a request carries `login_hint=ada@example.com`
- **THEN** the pending request's view holds that hint, and no account is looked up by it
