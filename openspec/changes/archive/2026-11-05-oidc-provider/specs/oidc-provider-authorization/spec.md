# Spec Delta

## Purpose

Defines the provider's authorization endpoint for the authorization code flow: how a request is validated, parked under a handle while the consumer's own pages sign the user in and ask for consent, resumed, and answered with a single-use authorization code.

## ADDED Requirements

### Requirement: The authorization endpoint serves the code flow only
The authorization endpoint SHALL accept requests by GET and by form POST. It SHALL support `response_type=code` with the query response mode only. Any other response type SHALL be answered with `unsupported_response_type`, and the implicit and hybrid flows SHALL NOT be available by any option.

#### Scenario: Code request accepted
- **WHEN** a valid request for `response_type=code` arrives by GET
- **THEN** it proceeds to the login stage

#### Scenario: Implicit flow refused
- **WHEN** a request for a registered client and redirect URI asks for `response_type=id_token token`
- **THEN** the browser is redirected to the redirect URI with `error=unsupported_response_type`

### Requirement: Authorization parameters are read as the standards require
A parameter given more than once SHALL make the request invalid, and a parameter sent without a value SHALL be treated as omitted. Unknown parameters SHALL be ignored. A `response_mode` other than `query`, and a missing `response_type`, SHALL be answered with `invalid_request`. A malformed `max_age` SHALL be answered with `invalid_request`. `display`, and `prompt` values the provider does not define, SHALL be ignored and SHALL NOT cause an error.

#### Scenario: Repeated parameter
- **WHEN** a request carries `scope` twice
- **THEN** it is answered with `invalid_request`

#### Scenario: Parameter without a value
- **WHEN** a request carries `state=` with no value
- **THEN** it is treated as sent without `state`, and the response carries none

#### Scenario: Other response mode
- **WHEN** a request for a registered client and redirect URI carries `response_mode=form_post`
- **THEN** the browser is redirected to the redirect URI with `error=invalid_request`

#### Scenario: Missing response type
- **WHEN** a request for a registered client and redirect URI carries no `response_type`
- **THEN** the browser is redirected to the redirect URI with `error=invalid_request`

#### Scenario: Malformed max_age
- **WHEN** a request carries `max_age=-1`
- **THEN** the browser is redirected to the redirect URI with `error=invalid_request`

#### Scenario: Display and unknown prompt value
- **WHEN** a request carries `display=popup` and `prompt=create`
- **THEN** it proceeds, and neither value causes an error

### Requirement: The authorization endpoint requires TLS
The endpoint SHALL refuse a request not made over TLS, as the chain reports the connection, unless the provider was built with the loopback issuer.

#### Scenario: Plain http request
- **WHEN** a request reaches the endpoint over plain http, and the provider was not built with the loopback issuer
- **THEN** it is refused, and nothing is parked

### Requirement: An invalid client or redirect URI is never redirected to
The provider SHALL validate the `client_id` and the `redirect_uri` before anything else. When the client is unknown, when `client_id` or `redirect_uri` is given more than once, or when the redirect URI is missing or does not match one the client registered, the provider SHALL NOT redirect the browser. It SHALL report the failure as a chain error, a bare 400 by default, which the consumer's error handler may render.

#### Scenario: Unregistered redirect URI
- **WHEN** a request for a known client names a redirect URI the client did not register
- **THEN** the response is 400, it carries no `Location` header, and nothing is parked

#### Scenario: Unknown client
- **WHEN** a request names an unknown `client_id` and any redirect URI
- **THEN** the response is 400 and the browser is not redirected

#### Scenario: Repeated redirect URI
- **WHEN** a request carries `redirect_uri` twice, one of them registered
- **THEN** the response is 400, and the browser is not redirected

#### Scenario: Consumer renders the error page
- **WHEN** the consumer's error handler renders an HTML page for chain errors, and a request names an unregistered redirect URI
- **THEN** the consumer's page is shown, and the browser is still not redirected

### Requirement: Errors after validation are redirected with state and issuer
Once the client and redirect URI are valid, every other error SHALL be answered by a 303 redirect to that redirect URI, carrying `error`, the request's `state` unchanged when one was sent, and `iss` set to the provider's issuer. By default the response SHALL NOT carry `error_description`.

#### Scenario: Missing scope
- **WHEN** a request with a valid client and redirect URI has no `scope`
- **THEN** the browser is redirected with `error=invalid_request`, the request's `state` and `iss`, and the status is 303

#### Scenario: Redirect URI holding a query
- **WHEN** a client registered `https://rp.example.com/cb?tenant=a`, and a request for that URI fails validation
- **THEN** the redirect keeps `tenant=a` and adds `error`, `state` and `iss`

### Requirement: PKCE with S256 is required by default
By default, every authorization request SHALL carry a `code_challenge` with `code_challenge_method=S256`, for public and confidential clients alike. A request with no challenge SHALL be answered with `invalid_request`. The `plain` method and any other method SHALL be answered with `invalid_request` for every client. A challenge SHALL be 43 to 128 characters from the unreserved set.

#### Scenario: Missing challenge from a confidential client
- **WHEN** a confidential client under the default sends a request without `code_challenge`
- **THEN** it is answered with `invalid_request`

#### Scenario: Plain method
- **WHEN** a request sends `code_challenge_method=plain`
- **THEN** it is answered with `invalid_request`

### Requirement: A consumer can let a confidential client rely on the nonce
A consumer MAY register a confidential client as PKCE-or-nonce. A request from that client SHALL then carry a challenge or a `nonce`, and a request carrying neither SHALL be answered with `invalid_request`. Registering a public client as PKCE-or-nonce SHALL fail construction.

#### Scenario: Consumer lets a confidential client rely on the nonce
- **WHEN** a confidential client registered as PKCE-or-nonce sends a request with a `nonce` and no challenge
- **THEN** the request proceeds, and the ID token carries that `nonce`

#### Scenario: PKCE-or-nonce with neither
- **WHEN** a confidential client registered as PKCE-or-nonce sends a request with neither a challenge nor a `nonce`
- **THEN** it is answered with `invalid_request`

#### Scenario: PKCE-or-nonce on a public client
- **WHEN** a public client is registered as PKCE-or-nonce
- **THEN** construction fails with a configuration error naming the client

### Requirement: Scopes are limited to what the client may ask for
The provider SHALL treat a request whose scope includes `openid` as an OpenID Connect request, which receives an ID token. A request without `openid` SHALL be a plain OAuth request that receives no ID token. Each client SHALL have a set of allowed scopes. A requested scope outside it SHALL be answered with `invalid_scope`. `offline_access` from a client not registered for the refresh grant SHALL be dropped from the request, and SHALL NOT be asked for at consent.

#### Scenario: Scope not allowed
- **WHEN** a client allowed `openid profile` asks for `openid admin`
- **THEN** the browser is redirected with `error=invalid_scope`

#### Scenario: Plain OAuth request
- **WHEN** a client asks for `api.read` without `openid`
- **THEN** the flow completes without an ID token

#### Scenario: Offline access without the refresh grant
- **WHEN** a client registered only for `authorization_code` asks for `openid offline_access`
- **THEN** the request proceeds as one for `openid`

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
A valid request SHALL be stored as a pending request under a new handle. The handle SHALL carry at least 128 bits from a cryptographically secure source, and SHALL be stored only as a digest. The provider SHALL bind the request to a flow cookie, `HttpOnly`, `Secure` and `SameSite=Lax`, whose name carries the `__Host-` prefix. The provider SHALL then redirect the browser to the consumer's login URL with the handle as a query parameter, with `Cache-Control: no-store`.

#### Scenario: Request parked
- **WHEN** a valid request arrives
- **THEN** the browser is redirected with 303 to the login URL with the handle, the response sets the flow cookie, and the handle is not stored in clear

### Requirement: A pending request expires
A pending request SHALL expire 10 minutes after it was created.

#### Scenario: Handle expired
- **WHEN** a resume presents a handle 11 minutes after its request was parked
- **THEN** the resume is refused as an unknown handle

#### Scenario: Consumer shortens the lifetime
- **WHEN** the consumer sets the pending-request lifetime to 5 minutes, and a resume presents a handle after 6 minutes
- **THEN** the resume is refused as an unknown handle

### Requirement: One flow cookie serves a browser's parallel requests
A browser already holding a valid flow cookie SHALL keep it, so that requests parked in several tabs of one browser can each be resumed. With the loopback issuer, the name SHALL carry no prefix and the cookie SHALL not be `Secure`.

#### Scenario: Two tabs in one browser
- **WHEN** one browser starts two authorization requests in two tabs, and completes the login page in the first tab after the second was parked
- **THEN** the first tab's resume succeeds, and so does the second's

### Requirement: A form POST with no flow cookie cannot replace the browser's cookie
A browser does not send a `SameSite=Lax` cookie on a cross-site POST, so a form POST to the authorization or end-session endpoint with no flow cookie SHALL NOT mint one. It SHALL be answered with 303 to the same endpoint, carrying the same parameters in the query, with `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, no `Set-Cookie`, nothing parked and nothing charged to the source's throttle. A form POST that presents a flow cookie SHALL be answered directly.

#### Scenario: Cross-site POST to the end-session endpoint
- **WHEN** a page on another site submits an empty form POST to the end-session endpoint, in a browser with a request parked in another tab
- **THEN** the response is 303 to the end-session endpoint with no `Set-Cookie`, and the parked request can still be resumed

#### Scenario: Cross-site POST with a browser session
- **WHEN** a relying party on another site sends an authorization request by form POST, in a browser with a browser session, and consent is not needed
- **THEN** the redirected GET is answered from the browser session with a code

#### Scenario: Same-site POST holding the cookie
- **WHEN** a form POST to the authorization endpoint presents a valid flow cookie
- **THEN** it is answered directly, with no redirect to the endpoint itself

### Requirement: The strings a request carries are bounded
Each string a request carries SHALL be bounded, and a request past a bound SHALL be answered with `invalid_request` and nothing parked. By default `state`, `nonce`, `login_hint` and each `resource` SHALL be at most 2048 bytes, `scope` at most 4096 bytes and `id_token_hint` at most 8192 bytes, each replaceable by the consumer.

#### Scenario: Oversized state
- **WHEN** a request for a registered client and redirect URI carries a `state` of 1 MiB
- **THEN** the browser is redirected with `error=invalid_request`, without that `state`, and nothing is parked

### Requirement: The pending-request lifetime is bounded
A pending-request lifetime set by the consumer SHALL be positive and at most 30 minutes. Any other value SHALL fail construction.

#### Scenario: Lifetime too long
- **WHEN** the consumer sets the pending-request lifetime to 2 hours
- **THEN** construction fails with a configuration error

### Requirement: The login and consent URLs are required
Building the provider SHALL fail with a configuration error when the consumer gives no login URL or no consent URL. Both SHALL be absolute URIs on the issuer's origin: the same scheme, host and port. A URI on another origin SHALL fail construction, because the flow cookie is not sent to it.

#### Scenario: Consent URL missing
- **WHEN** the provider is built with a login URL and no consent URL
- **THEN** construction fails with a configuration error naming the consent URL

#### Scenario: Login page on a sibling host
- **WHEN** the issuer is `https://id.example.com` and the login URL is `https://login.example.com/`
- **THEN** construction fails with a configuration error naming the login URL

### Requirement: The consumer's pages can read a pending request without its secrets
The provider SHALL let the consumer's pages read a pending request by its handle, with the flow cookie present. The view SHALL hold the client's identifier and name, the requested and already-granted scopes, `prompt`, `max_age`, `login_hint`, `ui_locales`, `claims_locales`, `acr_values` and the stage. It SHALL NOT hold the PKCE challenge, the nonce, the state or the redirect URI.

#### Scenario: Login page reads the request
- **WHEN** the login page reads a pending request by its handle
- **THEN** it receives the client's name and the scopes, and no challenge, nonce or state

#### Scenario: Read without the flow cookie
- **WHEN** a request without the flow cookie reads a pending request by its handle
- **THEN** it is refused as an unknown handle

### Requirement: A pending request is resumed with the sign-in that completes it
The resume endpoint SHALL accept a handle together with a sign-in credential in the `Authorization` header and the flow cookie. It SHALL refuse the resume as an unknown handle when the handle is unknown, expired, already spent for its stage, or not bound to the flow cookie sent. It SHALL refuse the sign-in as unauthenticated when the credential does not authenticate.

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

### Requirement: The sign-in credential is never read from the query
The resume endpoint SHALL never accept the sign-in credential from a query parameter, and SHALL accept the provider's browser session in its place only at the consent stage (`oidc-provider-authorization`, "A browser session").

#### Scenario: Credential in the query
- **WHEN** a resume carries a sign-in credential as a query parameter, and no `Authorization` header
- **THEN** it is refused as unauthenticated

### Requirement: Only a complete sign-in can resume a request
The resume SHALL be refused unless the sign-in passes the chain's per-request policy as a fully authenticated session. A session that still owes a second factor, is pending recovery, is limited to MFA enrolment, or must change its password SHALL be refused with the same refusal the chain gives that state elsewhere. The handle SHALL stay unspent, so the page can finish that step and resume again.

#### Scenario: Second factor owed
- **WHEN** a resume presents a session that has passed the first factor and owes a second
- **THEN** it is refused with the second-factor challenge, and the handle can still be resumed

#### Scenario: Bound sign-in without its proof
- **WHEN** a resume presents a DPoP-bound sign-in credential with no proof
- **THEN** it is refused as the chain refuses that credential elsewhere, and the handle can still be resumed

### Requirement: Only a sign-in of a known user can resume a request
A session only a late renewal may recover SHALL be refused. A request authenticated by anything but a sign-in, such as an API key or Basic credentials, SHALL be refused as unauthenticated. A sign-in whose principal has no user identifier SHALL fail as a server-side failure matching `token.ErrNoSubject`, and no code SHALL be issued.

#### Scenario: API key offered as a sign-in
- **WHEN** a resume presents a valid handle and flow cookie, and authenticates with an API key
- **THEN** it is refused as unauthenticated, and the handle can still be resumed

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

### Requirement: A login leaves a browser session
After a login stage resumes, the provider SHALL hold a browser session for that sign-in: a cookie with a new 256-bit secret, `HttpOnly`, `Secure`, `SameSite=Lax` and carrying the `__Host-` prefix, with only the secret's digest stored. The record SHALL hold the user, the sign-in's family and its authentication facts. A newer resume SHALL replace it, with a new secret.

#### Scenario: Login resumed
- **WHEN** a login stage resumes
- **THEN** the response sets the browser-session cookie, and its secret is not stored in clear

#### Scenario: Newer resume replaces the session
- **WHEN** a browser holding a browser session resumes another login
- **THEN** the cookie carries a new secret, and the old secret no longer loads

### Requirement: A browser session lives no longer than its sign-in
A browser session SHALL expire at the sign-in's absolute deadline, and after the sign-in manager's idle timeout without use. It SHALL end when the sign-in ends (`http-security-chain`).

#### Scenario: Sign-in ended
- **WHEN** the user logged out of the sign-in the browser session came from, and an authorization then starts in that browser
- **THEN** the login page is shown

#### Scenario: Idle browser session
- **WHEN** a browser session is not used for longer than the sign-in manager's idle timeout, and an authorization then starts
- **THEN** the login page is shown

### Requirement: A code answered from a browser session does not outlive its sign-in
A code answered from a browser session SHALL make no tokens once that sign-in has ended, even when the request overlapped the end, unless the end spares it because it holds `offline_access` for a client that does not end its grants with the sign-in. A code SHALL NOT be released when the browser session could not be looked at after the code was written.

#### Scenario: A request overlapping the end
- **WHEN** a sign-in's end is in progress, and a silent authorization or a consent answered from its browser session writes a code the end does not spare
- **THEN** either the request is refused or the code is answered with `invalid_grant` at the token endpoint

#### Scenario: Browser session store failing
- **WHEN** the browser session cannot be looked at after a silent authorization wrote its code, for a reason other than the session being gone
- **THEN** no code leaves, and the failure is answered as a dependency failure

### Requirement: A browser session skips the login stage
An authorization request whose browser holds a valid browser session SHALL skip the login stage, unless `prompt` includes `login` or `select_account`, or `max_age` is not met. The user SHALL be checked as a refresh checks one, and a missing or disabled user SHALL count as no session. When consent is not needed, the browser SHALL be redirected with 303 and the code.

#### Scenario: Second relying party in one browser
- **WHEN** a user signed in through one client's authorization, and a second client with no consent needed starts an authorization in that browser
- **THEN** the browser is redirected with 303 to the second client with a code, and no login page is shown

#### Scenario: Authentication time carried over
- **WHEN** a code is issued through a browser session
- **THEN** the ID token's `auth_time`, `amr`, `acr` and `sid` are those of the original sign-in

#### Scenario: Prompt login with a browser session
- **WHEN** a request carries `prompt=login`, and the browser holds a valid browser session
- **THEN** the login page is shown, and a code is issued only after the user authenticates again

#### Scenario: Disabled user
- **WHEN** the browser holds a valid browser session for a user since disabled
- **THEN** the login page is shown, and no code is issued from that session

### Requirement: The consent stage can rest on the browser session
When consent is needed, the browser SHALL go to the consent URL, and the consent stage SHALL accept the browser session in place of the `Authorization` header, for that session's user.

#### Scenario: Consent answered through the browser session
- **WHEN** consent is needed, and the consent page posts its answer with the handle and flow cookie and no `Authorization` header
- **THEN** the answer is accepted for the browser session's user

### Requirement: A consumer can turn browser sessions off
A consumer MAY turn browser sessions off. Every authorization request SHALL then show the login page, and `prompt=none` SHALL always be answered with `login_required`, and the documentation SHALL state that this fails the Basic OP plan.

#### Scenario: Consumer turns browser sessions off
- **WHEN** the consumer turns browser sessions off, and a request carries `prompt=none` after an earlier successful login
- **THEN** the browser is redirected with `error=login_required`

### Requirement: Silent authentication answers from the browser session
A request with `prompt=none` SHALL NOT show the login or consent page. With no valid browser session it SHALL be answered with a redirect carrying `error=login_required`. With one, it SHALL issue a code when consent is not needed, and otherwise SHALL be answered with `error=consent_required`. A failed `max_age` SHALL be answered with `error=login_required`. A request combining `none` with another `prompt` value SHALL be answered with `invalid_request`.

#### Scenario: Silent request, not signed in
- **WHEN** a request carries `prompt=none`, and the browser holds no browser session
- **THEN** the browser is redirected to the redirect URI with `error=login_required`, `state` and `iss`

#### Scenario: Silent request, signed in
- **WHEN** a request carries `prompt=none`, the browser holds a valid browser session, and consent is not needed
- **THEN** the browser is redirected to the redirect URI with `code`, `state` and `iss`

#### Scenario: Silent request, consent needed
- **WHEN** a request carries `prompt=none`, the browser holds a valid browser session, and consent is needed
- **THEN** the browser is redirected with `error=consent_required`

#### Scenario: Contradictory prompt
- **WHEN** a request carries `prompt=none login`
- **THEN** it is answered with `invalid_request`

### Requirement: An ID token hint must name the user who signs in
When a request carries `id_token_hint`, the provider SHALL accept it only if it is an ID token this provider issued, judged by its type, signature and issuer, with its expiry ignored. A hint that fails those checks under a key the provider still publishes SHALL be answered with `invalid_request`. When the user of the browser session or the resumed sign-in is not the hint's subject, the provider SHALL answer with a redirect carrying `error=login_required`.

#### Scenario: Another user signs in
- **WHEN** a request carries a valid hint for user `u-1`, and the resume presents a sign-in of user `u-2`
- **THEN** the browser is redirected with `error=login_required`

#### Scenario: Silent request with a matching hint
- **WHEN** a request carries `prompt=none` and a hint for the browser session's user, and consent is not needed
- **THEN** a code is issued, and the ID token carries the same `sub`

#### Scenario: Keys unavailable while judging a hint
- **WHEN** a request with a valid client and redirect URI carries a hint, and the verification keys cannot be read
- **THEN** the browser is redirected to the redirect URI with `error=server_error` and the request's `state`, and nothing is parked

#### Scenario: Access token offered as a hint
- **WHEN** a request carries an access token this provider issued as `id_token_hint`
- **THEN** it is answered with `invalid_request`

### Requirement: A hint signed by a retired key counts as none
A hint signed by a key the provider no longer publishes cannot be judged, and SHALL count as no hint, except that with `prompt=none` it SHALL be answered with `login_required`.

#### Scenario: Hint signed by a retired key
- **WHEN** a request without `prompt=none` carries an ID token whose signing key is no longer published
- **THEN** the request proceeds as one with no hint

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

#### Scenario: Sign-in ends while a code is outstanding
- **WHEN** a code without `offline_access` is issued, the user logs out of its sign-in, and the code is then exchanged
- **THEN** the exchange is refused with `invalid_grant`

#### Scenario: User's grants revoked while a code is outstanding
- **WHEN** a code holding `offline_access` is issued, a recovery then completes for its user, and the code is then exchanged
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
`login_hint`, `ui_locales`, `claims_locales`, `acr_values` and `prompt=select_account` SHALL be kept on the pending request and shown to the consumer's pages. The provider SHALL NOT act on them itself, and SHALL NOT answer an error because it cannot satisfy them.

#### Scenario: Login hint
- **WHEN** a request carries `login_hint=ada@example.com`
- **THEN** the pending request's view holds that hint, and no account is looked up by it

#### Scenario: Requested assurance not met
- **WHEN** a request carries `acr_values=urn:example:high`, and the sign-in does not meet it
- **THEN** the request still succeeds, and the view shows the requested values so the consumer's page may ask for more

### Requirement: A request carries only text a durable store can hold
A request parameter holding a NUL byte or invalid UTF-8 SHALL be refused as `invalid_request`, with nothing parked and without echoing the value, once the client and redirect URI are valid. An unknown parameter is ignored and never stored.

#### Scenario: NUL in the state
- **WHEN** a request from a valid client and redirect URI has a `state` holding a NUL byte
- **THEN** it is answered with a redirect carrying `invalid_request`, and nothing is parked

### Requirement: Only a client registered for the code grant reaches the flow
A client registered without the `authorization_code` grant SHALL be answered with a redirect carrying `unauthorized_client`, with nothing parked, once its redirect URI is valid.

#### Scenario: Refresh-only client
- **WHEN** a client registered only for `refresh_token` sends an authorization request with a valid redirect URI
- **THEN** it is answered with a redirect carrying `unauthorized_client`, `state` and `iss`

### Requirement: A resume judges the client as it is now
Every resume SHALL judge the parked request against the client as read at that moment. If the parked redirect URI is no longer registered, the client lost the code grant, `openid` was parked and may no longer be asked for, or no scope is left, the resume SHALL be refused as an unknown handle, with no redirect. A scope or resource the client may no longer use, and `offline_access` for a client that lost the refresh grant, SHALL be left out, and the request SHALL carry on.

#### Scenario: Redirect URI removed after parking
- **WHEN** a client stops registering a redirect URI, and a request parked with it resumes
- **THEN** the resume is refused as an unknown handle, and the browser is not sent to that URI

#### Scenario: Scope withdrawn after parking
- **WHEN** a client may no longer ask for `profile`, and a request parked with `openid profile` resumes
- **THEN** the code is issued for `openid` alone

### Requirement: An authentication time in the future is not fresh
A sign-in whose authentication time is more than 60 seconds ahead of the provider's clock SHALL be refused as needing re-authentication, whatever the request's `prompt` or `max_age`. Within 60 seconds it SHALL count as now.

#### Scenario: A year ahead
- **WHEN** a sign-in authenticated a year ahead of the provider's clock resumes a request with `max_age=300`
- **THEN** the resume asks for re-authentication

