# Spec Delta

## Purpose

Defines the provider's token endpoint and the grants behind it: exchanging an authorization code, refreshing, what ID and access tokens carry, how long grants live, what revokes them, and the revocation and introspection endpoints.

## ADDED Requirements

### Requirement: The token endpoint accepts two grant types by form POST
The token endpoint SHALL accept only POST requests with a form-encoded body, and SHALL support the `authorization_code` and `refresh_token` grant types. Any other grant type SHALL be answered with `unsupported_grant_type`, and no option SHALL enable the password grant. A client SHALL use only the grant types it is registered for, `authorization_code` by default, or be answered with `unauthorized_client`. A repeated parameter SHALL make the request invalid.

#### Scenario: Password grant
- **WHEN** a client sends `grant_type=password`
- **THEN** the response is 400 with `{"error":"unsupported_grant_type"}`

#### Scenario: Refresh not registered
- **WHEN** a client registered only for `authorization_code` sends `grant_type=refresh_token`
- **THEN** the response is 400 with `{"error":"unauthorized_client"}`

#### Scenario: GET request
- **WHEN** a client sends a token request by GET
- **THEN** the request is refused and no token is issued

### Requirement: Every token request authenticates the client first
The token endpoint SHALL authenticate the client by its registered method (`oidc-provider-clients`) before it reads the grant. A failure SHALL be answered with `invalid_client`, and the grant SHALL be left as it was: a code SHALL stay unspent, and a refresh token SHALL not be rotated.

#### Scenario: Wrong secret with a valid code
- **WHEN** a client sends a valid code with a wrong secret
- **THEN** the response is `invalid_client`, and the same code can still be exchanged with the right secret

### Requirement: A code is exchanged only by its client, with its redirect URI and verifier
A code exchange SHALL succeed only when:
- the code is known, unexpired and unspent;
- it was issued to the authenticated client;
- the request's `redirect_uri` equals the one the code was issued for;
- the SHA-256 of `code_verifier`, base64url-encoded, equals the code's challenge.

Any failure SHALL be answered with `invalid_grant`. A failure before the code's single use SHALL leave it unspent, except that a code presented by another client SHALL count as used.

#### Scenario: Wrong verifier
- **WHEN** a client exchanges its code with a `code_verifier` that does not match
- **THEN** the response is `invalid_grant`

#### Scenario: Missing verifier
- **WHEN** a client exchanges its code without `code_verifier`
- **THEN** the response is `invalid_grant`

#### Scenario: Different redirect URI
- **WHEN** a client exchanges its code with a `redirect_uri` other than the one in the authorization request
- **THEN** the response is `invalid_grant`

#### Scenario: Another client's code
- **WHEN** client `b` exchanges a code issued to client `a`
- **THEN** the response is `invalid_grant`, and the code can no longer be exchanged by `a`

### Requirement: A code is used once, and its replay revokes what it issued
A code SHALL be exchanged at most once, also under concurrent requests. A code presented again after its exchange SHALL be answered with `invalid_grant`, and SHALL revoke the grant the first exchange created, with its refresh tokens and opaque access tokens. When the replay arrives while the first exchange is still being completed, the grant SHALL still end revoked, and no refresh token from it SHALL work afterwards.

#### Scenario: Concurrent exchanges
- **WHEN** two exchanges of one code arrive at once
- **THEN** exactly one receives tokens, and the other receives `invalid_grant`

#### Scenario: Replay after exchange
- **WHEN** a code is exchanged, and the same code is presented again
- **THEN** the second request receives `invalid_grant`, and the refresh token from the first exchange is refused with `invalid_grant`

#### Scenario: Replay racing the first exchange
- **WHEN** a replay of a code arrives after the first exchange has spent the code, and before the first exchange has stored its grant
- **THEN** once both requests finish, the grant is revoked, and the refresh token the first exchange returned is refused

### Requirement: Token responses are JSON and never cached
A successful token response SHALL be 200 with a JSON body holding `access_token`, `token_type`, `expires_in` and `scope`. It SHALL add `id_token` when the grant's scopes include `openid`, and `refresh_token` when the client is registered for the refresh grant. Every token endpoint response, success or error, SHALL carry `Cache-Control: no-store`.

#### Scenario: OpenID code exchange
- **WHEN** a client registered for both grants exchanges a code granted `openid profile`
- **THEN** the response holds an access token, `token_type`, `expires_in`, `scope` `openid profile`, an ID token and a refresh token, with `Cache-Control: no-store`

#### Scenario: No refresh grant
- **WHEN** a client registered only for `authorization_code` exchanges a code
- **THEN** the response holds no `refresh_token`

### Requirement: An ID token states who authenticated, when and how
An ID token SHALL be a signed JWT with header `typ` `JWT`, carrying:
- `iss`; `sub`, the user's stable identifier; `aud` and `azp`, the client's identifier;
- `iat`, and `exp` 5 minutes later by default, replaceable per client;
- `auth_time`, when the user last actually authenticated in the sign-in the code came from;
- `nonce` as sent in the request, when sent; `amr` and `acr` of that sign-in, when known;
- `sid`, identifying that sign-in, stable across its renewals.

#### Scenario: Claims after a password and TOTP sign-in
- **WHEN** a user signs in with a password and a TOTP code, and the client exchanges its code from a request carrying `nonce=n-1`
- **THEN** the ID token carries `nonce` `n-1`, `amr` naming both factors, `aud` and `azp` the client, and `auth_time` the time of that sign-in

#### Scenario: Authentication time is not the exchange time
- **WHEN** the user signed in at 10:00, and the code is exchanged at 10:04
- **THEN** the ID token's `auth_time` is 10:00

### Requirement: ID tokens are signed with the client's algorithm
An ID token SHALL be signed with the client's registered algorithm, RS256 by default, and never with `none`.

#### Scenario: Default algorithm
- **WHEN** a client registered without an algorithm receives an ID token
- **THEN** its header carries `alg` `RS256`

#### Scenario: Client asks for ES256
- **WHEN** a client is registered for ES256 ID tokens and the key manager holds an ES256 key
- **THEN** its ID tokens are signed with ES256

### Requirement: Access tokens are JWTs for a named audience
By default an access token SHALL be a signed JWT with header `typ` `at+jwt`, carrying `iss`, `sub`, `aud`, `client_id`, `scope`, `iat`, `jti`, and `exp` 5 minutes after `iat`. It SHALL carry `auth_time`, `acr` and `amr` from the grant when known, and a confirmation claim when bound. Its audience SHALL be the `resource` values of the request when given, otherwise the client's default audience, otherwise the issuer. A consumer MAY set the lifetime per client.

#### Scenario: Default audience
- **WHEN** a client whose default audience is `https://api.example.com` exchanges a code without `resource`
- **THEN** the access token's `aud` is `https://api.example.com`

#### Scenario: Resource requested
- **WHEN** a client allowed `https://orders.example.com` sends `resource=https://orders.example.com` at the token endpoint
- **THEN** the access token's `aud` is `https://orders.example.com`

#### Scenario: Resource not allowed at the token endpoint
- **WHEN** a client sends a `resource` it is not allowed
- **THEN** the response is 400 with `{"error":"invalid_target"}`

#### Scenario: No audience configured
- **WHEN** a client with no default audience and no allowed resources exchanges a code
- **THEN** the access token's `aud` is the issuer, and it is accepted only at the provider's own endpoints

#### Scenario: Consumer lengthens the lifetime
- **WHEN** the consumer sets a client's access token lifetime to 15 minutes
- **THEN** that client's access tokens expire 15 minutes after issue

### Requirement: Opaque access tokens are available per client
A consumer MAY register a client for opaque access tokens. They SHALL carry at least 128 bits from a cryptographically secure source, SHALL be stored only as digests, SHALL be verified by looking them up, and SHALL stop working as soon as their grant is revoked. Their format SHALL differ from refresh tokens and from every sign-in credential.

#### Scenario: Revoked at once
- **WHEN** a client registered for opaque access tokens has its grant revoked
- **THEN** its unexpired access token is refused at UserInfo and reported inactive by introspection

### Requirement: Refresh tokens rotate on every use
A refresh token SHALL carry at least 128 bits from a cryptographically secure source, SHALL be stored only as a digest, and SHALL have a format no sign-in path of the chain accepts. A successful refresh SHALL return a new refresh token and supersede the one presented. The superseded token SHALL be accepted again only within a grace window, 30 seconds by default, for a client retrying a lost response.

#### Scenario: Rotation
- **WHEN** a client refreshes with token `r1`
- **THEN** the response carries a new refresh token `r2`

#### Scenario: Retry within the grace window
- **WHEN** a client refreshes with `r1`, loses the response, and presents `r1` again 10 seconds later
- **THEN** it receives tokens, and the grant is not revoked

#### Scenario: Consumer widens the grace window
- **WHEN** the consumer sets a client's grace window to 2 minutes, and `r1` is presented again 90 seconds after its rotation
- **THEN** it receives tokens

#### Scenario: Refresh token offered as a sign-in
- **WHEN** a refresh token is presented to the chain as a session-reference bearer or a session renewal
- **THEN** it is refused as an unknown credential

### Requirement: Refresh-token reuse revokes the whole grant
A superseded refresh token presented after its grace window SHALL be answered with `invalid_grant`, and SHALL revoke the whole grant: every refresh token of it, including the newest, and its opaque access tokens. No option SHALL weaken this. A grace window above 5 minutes SHALL fail construction.

#### Scenario: Stolen token reused
- **WHEN** an attacker presents `r1` after the client already rotated it to `r2` and the grace window ended
- **THEN** the attacker receives `invalid_grant`, and the client's next refresh with `r2` receives `invalid_grant` too

#### Scenario: Grace window too wide
- **WHEN** the consumer sets a grace window of 10 minutes
- **THEN** construction fails with a configuration error

### Requirement: A refresh stays within its grant
A refresh SHALL succeed only when the refresh token's grant exists, is not revoked or expired, and was issued to the authenticated client, and its user still exists and is enabled. Otherwise it SHALL be answered with `invalid_grant`, and a missing or disabled user SHALL also revoke the grant. A refresh MAY narrow `scope` to a subset of the grant's. A scope outside it SHALL be answered with `invalid_scope`.

#### Scenario: Another client's refresh token
- **WHEN** client `b` presents a refresh token issued to client `a`
- **THEN** the response is `invalid_grant`, and `a`'s token keeps working

#### Scenario: Disabled user
- **WHEN** a client refreshes for a user the identity store reports as disabled
- **THEN** the response is `invalid_grant`, and the grant is revoked

#### Scenario: Narrowed scope
- **WHEN** a grant holds `openid profile email`, and a refresh asks for `scope=openid profile`
- **THEN** the new access token carries `openid profile`

#### Scenario: Widened scope
- **WHEN** a grant holds `openid profile`, and a refresh asks for `scope=openid admin`
- **THEN** the response is `invalid_scope`

### Requirement: Refreshed tokens keep the grant's authentication facts
Tokens issued by a refresh SHALL carry the grant's `auth_time`, `acr` and `amr`, and an ID token issued by a refresh SHALL carry no `nonce`.

#### Scenario: ID token on refresh
- **WHEN** a grant holding `openid` is refreshed
- **THEN** the new ID token has the original `auth_time`, the same `sub` and `aud`, and no `nonce`

### Requirement: Grants expire on idle and absolute deadlines
A grant SHALL expire when it has not been refreshed for its idle timeout, 30 days by default, and at its absolute lifetime, 90 days after it was created by default. A grant without `offline_access` SHALL also expire no later than the absolute deadline of the sign-in it came from. Rotation SHALL extend neither deadline beyond these. A consumer MAY set both per client. An idle timeout longer than the absolute lifetime SHALL fail construction.

#### Scenario: Idle grant
- **WHEN** a grant is not refreshed for 31 days, under the defaults
- **THEN** its refresh token is refused with `invalid_grant`

#### Scenario: Absolute lifetime reached
- **WHEN** a grant refreshed every day reaches 90 days, under the defaults
- **THEN** its refresh token is refused with `invalid_grant`

#### Scenario: Online grant capped by its sign-in
- **WHEN** a grant without `offline_access` comes from a sign-in whose absolute deadline is 12 hours away
- **THEN** the grant's refresh token is refused after those 12 hours

#### Scenario: Consumer shortens the absolute lifetime
- **WHEN** the consumer sets a client's absolute grant lifetime to 7 days
- **THEN** that client's grants end after 7 days

#### Scenario: Idle longer than absolute
- **WHEN** the consumer sets an idle timeout of 60 days and an absolute lifetime of 30 days
- **THEN** construction fails with a configuration error

### Requirement: Rotation can be turned off only for sender-constrained confidential clients
A consumer MAY turn rotation off for a confidential client that is required to use sender-constrained tokens. Its refresh token SHALL then be returned unchanged by each refresh, and still SHALL be bound to the client's authentication. Turning rotation off for a public client, or for a client not required to use sender-constrained tokens, SHALL fail construction.

#### Scenario: Rotation off for a public client
- **WHEN** the consumer turns rotation off for a public client
- **THEN** construction fails with a configuration error

#### Scenario: Rotation off for a constrained confidential client
- **WHEN** rotation is off for a confidential client required to use DPoP, and it refreshes
- **THEN** the response carries no new refresh token, and the same refresh token works again

### Requirement: Logout ends the grants of the sign-in without offline access
When a sign-in ends by logout, by revocation of its session family, or by a back-channel logout from an upstream provider, the provider SHALL revoke the grants created from that sign-in that do not hold `offline_access`. Grants holding `offline_access` SHALL survive. A consumer MAY register a client so that all its grants end with their sign-in, `offline_access` included.

#### Scenario: Logout with an online grant
- **WHEN** a user logs out of the sign-in a grant without `offline_access` came from
- **THEN** that grant's refresh token is refused with `invalid_grant`

#### Scenario: Logout with an offline grant
- **WHEN** a user logs out of the sign-in a grant holding `offline_access` came from
- **THEN** that grant's refresh token keeps working

#### Scenario: Consumer ties offline grants to the sign-in
- **WHEN** a client is registered to end its grants with the sign-in, and the user logs out
- **THEN** that client's grant holding `offline_access` is revoked too

### Requirement: Security events revoke the user's grants by default
The provider SHALL revoke every grant of a user when any of these happens to the user:
- an account recovery completes;
- an operator resets the user's MFA enrolment;
- a passkey is suspended as a suspected clone.

A consumer MAY keep grants for each of these events separately. A password change SHALL keep grants by default, and a consumer MAY make it revoke them.

#### Scenario: Recovery completed
- **WHEN** an account recovery completes for user `u-1`
- **THEN** every refresh token of `u-1`, offline grants included, is refused with `invalid_grant`

#### Scenario: Consumer keeps grants on MFA reset
- **WHEN** the consumer keeps grants on MFA reset, and an operator resets `u-1`'s MFA
- **THEN** `u-1`'s grants keep working

#### Scenario: Password change by default
- **WHEN** user `u-1` changes their password, under the default
- **THEN** `u-1`'s grants keep working

#### Scenario: Consumer revokes on password change
- **WHEN** the consumer makes a password change revoke grants, and `u-1` changes their password
- **THEN** every grant of `u-1` is revoked

### Requirement: Sender-constrained grants require the bound key
A grant bound to a key SHALL be refreshed only with proof of that key. A refresh without it SHALL be answered as the binding's own refusal, and SHALL NOT rotate the token. A public client's grant SHALL be bound when its first token request carried a DPoP proof. A confidential client's refresh token SHALL be bound to its client authentication and not to a DPoP key.

#### Scenario: Refresh without the bound key
- **WHEN** a public client's grant is bound to DPoP key `k1`, and a refresh arrives with a proof from `k2`
- **THEN** the refresh is refused, and the presented refresh token still works with a proof from `k1`

### Requirement: The revocation endpoint ends tokens for their client
The revocation endpoint SHALL accept a form POST with `token` and an optional `token_type_hint`, which only orders the lookup, from an authenticated client. Revoking a refresh token SHALL revoke its whole grant, and revoking an opaque access token SHALL revoke that token. A JWT access token, an unknown token or an expired token SHALL be answered 200 with nothing revoked. A token issued to another client SHALL be answered with `invalid_grant`, revoking nothing.

#### Scenario: Refresh token revoked
- **WHEN** a client revokes its refresh token
- **THEN** the response is 200, and every refresh token of that grant is refused afterwards

#### Scenario: Unknown token
- **WHEN** a client revokes a value that is no token
- **THEN** the response is 200

#### Scenario: Another client's token
- **WHEN** client `b` revokes a refresh token issued to client `a`
- **THEN** the response is 400 with `{"error":"invalid_grant"}`, and `a`'s token keeps working

### Requirement: The introspection endpoint answers only for tokens a client may see
The introspection endpoint SHALL accept a form POST with `token` and an optional `token_type_hint`, from an authenticated client. It SHALL answer `{"active": false}` alone for an unknown, expired or revoked token, and for a token the client may not see. A client SHALL see a token issued to it, and an access token whose audience includes its registered resource identifier. Responses SHALL carry `Cache-Control: no-store`.

#### Scenario: Another client's token
- **WHEN** client `b`, which is not in the token's audience, introspects client `a`'s access token
- **THEN** the answer is `{"active": false}`

#### Scenario: Resource server introspects
- **WHEN** a client registered with resource identifier `https://api.example.com` introspects an access token whose audience is `https://api.example.com`
- **THEN** the answer holds `active` true

#### Scenario: Unauthenticated introspection
- **WHEN** a request to the introspection endpoint carries no client authentication
- **THEN** it is refused with `invalid_client`

### Requirement: An active introspection answer describes the token
For an active token the introspection answer SHALL hold `active`, `scope`, `client_id`, `sub`, `exp`, `iat`, `iss`, `aud`, `token_type`, and the confirmation claim when bound.

#### Scenario: Active opaque token
- **WHEN** the client that holds an opaque access token introspects it
- **THEN** the answer holds `active` true with its `sub`, `scope`, `client_id` and `exp`

### Requirement: Grant records are durable through the store adapters
Authorization codes, grants, refresh-token lineages, opaque access tokens, consent and pending requests SHALL each be kept in a store with an in-memory default and durable SQL adapters. No store SHALL hold a code, handle, refresh token, opaque access token or client secret in clear.

#### Scenario: Restart with a durable store
- **WHEN** the provider uses durable stores and is restarted between issuing a refresh token and its use
- **THEN** the refresh succeeds

### Requirement: Provider secrets never reach logs or error text
No code, handle, refresh token, access token, ID token, client secret or client assertion SHALL appear in a log line, an error's text or a security event.

#### Scenario: Refused refresh logged
- **WHEN** a refresh is refused and the refusal is logged
- **THEN** the log holds the client and the reason, and not the refresh token
