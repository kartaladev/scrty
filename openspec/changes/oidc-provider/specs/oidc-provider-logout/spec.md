# Spec Delta

## Purpose

Defines how a relying party asks the provider to log the user out, and how the provider tells relying parties, over the back channel, that a sign-in they hold tokens from has ended.

## ADDED Requirements

### Requirement: The end-session endpoint ends the sign-in an ID token hint names
The end-session endpoint SHALL accept GET and form POST with `id_token_hint`, `client_id`, `post_logout_redirect_uri`, `state` and `ui_locales`. A valid hint SHALL be an ID token this provider issued, judged by signature and issuer, expiry ignored, whose audience equals `client_id` when given. With a valid hint, the provider SHALL end the sign-in its `sid` names, as a logout does. With an invalid one, it SHALL end nothing and refuse the request as a chain error, without a redirect.

#### Scenario: Logout with a hint
- **WHEN** a relying party sends the browser to the end-session endpoint with a valid ID token hint
- **THEN** the sign-in its `sid` names ends, and the grants without `offline_access` from that sign-in are revoked

#### Scenario: Expired hint
- **WHEN** the hint is an expired ID token this provider issued
- **THEN** the sign-in it names ends

#### Scenario: Forged hint
- **WHEN** the hint's signature does not verify
- **THEN** the response is 400, nothing ends, and the browser is not redirected

#### Scenario: Client does not match the hint
- **WHEN** `client_id` is `billing-web` and the hint's audience is `crm-web`
- **THEN** the response is 400 and nothing ends

### Requirement: Without a hint, nothing is ended
A request without `id_token_hint` SHALL end no sign-in. The provider SHALL send the browser to the consumer's logged-out page, where the consumer may log the user out of its own session by the chain's logout endpoint.

#### Scenario: No hint
- **WHEN** a request to the end-session endpoint carries no `id_token_hint`
- **THEN** no sign-in ends, and the browser is redirected with 303 to the consumer's logged-out page

### Requirement: The browser returns only to a registered post-logout redirect URI
After the end-session endpoint, the provider SHALL redirect the browser with 303 to `post_logout_redirect_uri`, with `state` added when given, only when that URI exactly matches one registered by the client the hint or `client_id` identifies. Otherwise it SHALL redirect to the consumer's logged-out page, which SHALL be required at construction when logout is enabled.

#### Scenario: Registered URI
- **WHEN** a valid hint and a registered `post_logout_redirect_uri` with `state=s-1` are sent
- **THEN** the browser is redirected with 303 to that URI with `state=s-1`

#### Scenario: Unregistered URI
- **WHEN** a valid hint and an unregistered `post_logout_redirect_uri` are sent
- **THEN** the sign-in ends, and the browser is redirected to the consumer's logged-out page, never to the unregistered URI

#### Scenario: Logged-out page missing
- **WHEN** logout is enabled without a logged-out page URL
- **THEN** construction fails with a configuration error

### Requirement: Relying parties are told when a sign-in ends
When a sign-in ends for any reason the provider learns of (`http-security-chain`), it SHALL send a logout token to the back-channel logout URI of every client that holds a grant created from that sign-in and registered such a URI. Delivery SHALL be a form POST of `logout_token`, through the confined outbound client, with a timeout. It SHALL NOT delay the response to the user. A client SHALL be notified at most once for one ended sign-in.

#### Scenario: Two clients notified
- **WHEN** a sign-in from which `billing-web` and `crm-web` both hold grants ends by the chain's logout, and both registered back-channel logout URIs
- **THEN** each receives one logout token

#### Scenario: Client without a grant from that sign-in
- **WHEN** a sign-in ends, and `hr-web` holds grants only from another sign-in of the same user
- **THEN** `hr-web` receives no logout token

#### Scenario: Slow relying party
- **WHEN** a relying party's back-channel logout URI does not answer
- **THEN** the user's logout completes without waiting for it

### Requirement: Logout tokens follow the back-channel logout format
A logout token SHALL be a signed JWT with header `typ` `logout+jwt`. It SHALL carry `iss`, `aud` the client's identifier, `iat`, `exp` no more than 2 minutes after `iat`, a unique `jti`, the `events` member with the back-channel logout event, `sub`, and `sid` of the ended sign-in. It SHALL NOT carry `nonce`. It SHALL be signed with the client's ID token algorithm.

#### Scenario: Token contents
- **WHEN** a logout token is sent for a sign-in of user `u-1`
- **THEN** it carries `sub` `u-1`, the sign-in's `sid`, the logout event, and no `nonce`

### Requirement: Failed deliveries are reported, and delivery is replaceable
A delivery that fails or times out SHALL be logged and reported as a security event, without the token. By default it SHALL NOT be retried. A consumer MAY supply its own delivery, such as a queue that retries. A failed delivery SHALL NOT undo the logout.

#### Scenario: Relying party answers 500
- **WHEN** a relying party answers a logout token with 500
- **THEN** the failure is logged and reported as an event, and the sign-in stays ended

#### Scenario: Consumer delivers through a queue
- **WHEN** the consumer supplies a delivery that enqueues logout tokens
- **THEN** the provider hands each token to it instead of posting it

### Requirement: Back-channel logout URIs are registered like redirect URIs
A client MAY register one back-channel logout URI. It SHALL be an absolute `https` URI without a fragment. A client MAY require `sid` in its logout tokens, and the provider SHALL always send it.

#### Scenario: Plain http URI
- **WHEN** a client registers `http://rp.example.com/logout` as its back-channel logout URI
- **THEN** construction fails with a configuration error
