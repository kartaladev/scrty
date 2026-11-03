# Spec Delta

## Purpose

Defines how a relying party asks the provider to log the user out, and how the provider tells relying parties, over the back channel, that a sign-in they hold tokens from has ended.

## ADDED Requirements

### Requirement: The end-session endpoint ends the browser's sign-in without asking only on a matching hint
The end-session endpoint SHALL accept GET and form POST with `id_token_hint`, `logout_hint`, `client_id`, `post_logout_redirect_uri`, `state` and `ui_locales`. A valid hint SHALL be an ID token this provider issued, judged by its type, signature and issuer, expiry ignored, whose audience equals `client_id` when given. When a valid hint's `sid` names the sign-in of the browser's session, the provider SHALL end that sign-in as a logout does, without asking.

#### Scenario: Logout with a matching hint
- **WHEN** a relying party sends the browser to the end-session endpoint with a valid hint naming the browser session's sign-in
- **THEN** that sign-in ends, and the grants without `offline_access` from it are revoked

#### Scenario: Expired hint
- **WHEN** a matching hint is an expired ID token this provider issued
- **THEN** that sign-in ends

### Requirement: A consumer can always ask
A consumer MAY require the question on every request, and the provider SHALL then ask it.

#### Scenario: Consumer always asks
- **WHEN** the consumer requires the question, and a matching hint arrives
- **THEN** the browser goes to the logout page with a handle, and nothing has ended

### Requirement: Any other end-session request asks the user first
With no hint, with a hint signed by a key the provider no longer publishes, or with a valid hint not naming the browser session's sign-in, the provider SHALL end nothing yet. It SHALL park the request under a handle bound to the flow cookie and redirect the browser with 303 to the consumer's logout page, with that handle. The page SHALL ask the user, and SHALL answer through the logout confirmation endpoint with the handle and flow cookie.

#### Scenario: No hint
- **WHEN** a request to the end-session endpoint carries no `id_token_hint`
- **THEN** no sign-in has ended, and the browser is redirected with 303 to the logout page with a handle

#### Scenario: Hint signed by a retired key
- **WHEN** a hint's signing key is no longer published
- **THEN** the request is treated as one with no hint

### Requirement: A confirmation ends only the browser's sign-in
A confirmation SHALL end the sign-in of the browser's session. A browser with no session SHALL end nothing, except that when the consumer turned browser sessions off, a confirmation SHALL end the sign-in a valid hint names. The answer SHALL be 200 with a JSON object holding `redirect_to`, and `Cache-Control: no-store`. A refusal by the user SHALL end nothing.

It SHALL NOT be an error for a relying party to ask for a logout when no sign-in is live.

#### Scenario: User confirms
- **WHEN** the logout page confirms that handle, and the browser holds a session
- **THEN** that sign-in ends, and `redirect_to` is the consumer's logged-out page

#### Scenario: Hint for another sign-in
- **WHEN** a valid hint names a sign-in other than the browser session's, and the user confirms
- **THEN** the browser session's sign-in ends, and the sign-in the hint names does not

#### Scenario: Holder of a hint in another browser
- **WHEN** someone holding a user's ID token sends it from a browser with no session, and confirms
- **THEN** no sign-in ends

#### Scenario: Nothing to end
- **WHEN** a valid hint names a sign-in that has already ended, and the browser holds no session
- **THEN** the response is not an error, and the browser goes to the logout page

### Requirement: A hint that fails its checks is refused
A hint that fails the checks under a key the provider still publishes, or whose audience does not equal `client_id`, SHALL end nothing, and SHALL be refused as a chain error, a bare 400 by default, without a redirect.

#### Scenario: Forged hint
- **WHEN** the hint's signature does not verify under a published key
- **THEN** the response is 400, nothing ends, and the browser is not redirected

#### Scenario: Client does not match the hint
- **WHEN** `client_id` is `billing-web` and the hint's audience is `crm-web`
- **THEN** the response is 400 and nothing ends

#### Scenario: Access token offered as a hint
- **WHEN** the hint is an access token this provider issued
- **THEN** the response is 400 and nothing ends

### Requirement: The browser returns only to a registered post-logout redirect URI
After the logout, the provider SHALL send the browser to `post_logout_redirect_uri`, with `state` added when given, only when a valid hint was given and that URI exactly matches one registered by the client the hint identifies. In every other case it SHALL send the browser to the consumer's logged-out page. The logged-out page and the logout page SHALL be required at construction when logout is enabled, and SHALL be on the issuer's origin.

#### Scenario: Registered URI
- **WHEN** a valid matching hint and a registered `post_logout_redirect_uri` with `state=s-1` are sent
- **THEN** the browser is redirected with 303 to that URI with `state=s-1`

#### Scenario: Registered URI without state
- **WHEN** a valid matching hint and a registered `post_logout_redirect_uri` are sent with no `state`
- **THEN** the browser is redirected with 303 to that URI, with no `state`

#### Scenario: Unregistered URI
- **WHEN** a valid matching hint and an unregistered `post_logout_redirect_uri` are sent
- **THEN** the sign-in ends, and the browser is redirected to the consumer's logged-out page, never to the unregistered URI

#### Scenario: Query added to a registered URI
- **WHEN** a valid matching hint is sent with a registered `post_logout_redirect_uri` plus an added query
- **THEN** the browser is redirected to the consumer's logged-out page

#### Scenario: Registered URI with no hint
- **WHEN** a request names a `client_id` and its registered `post_logout_redirect_uri`, with no hint, and the user confirms
- **THEN** the browser goes to the consumer's logged-out page, never to that URI

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

### Requirement: Logout delivery follows no redirect
Delivery SHALL follow no redirect, and SHALL treat 200 and 204 as success.

#### Scenario: Relying party redirects
- **WHEN** a relying party's back-channel logout URI answers 302
- **THEN** the redirect is not followed, and the delivery is reported as failed

#### Scenario: Answer 204
- **WHEN** a relying party answers 204
- **THEN** the delivery counts as a success

### Requirement: Logout delivery is bounded and outlives its request
Deliveries SHALL run on a bounded pool that survives a delivery ending its goroutine, with a bounded queue. A delivery dropped because the queue is full, or still queued when the provider shuts down past its context, SHALL be reported as failed. Delivery SHALL keep the caller's context values and not its cancellation.

#### Scenario: Queue full
- **WHEN** a logout token is handed to delivery while the queue is full
- **THEN** the logout completes, and the dropped delivery is logged and reported as an event

#### Scenario: User hangs up during logout
- **WHEN** the request that ended a sign-in is cancelled as its delivery starts
- **THEN** the delivery still runs

### Requirement: Logout tokens follow the back-channel logout format
A logout token SHALL be a signed JWT with header `typ` `logout+jwt`. It SHALL carry `iss`, `aud` the client's identifier, `iat`, `exp` no more than 2 minutes after `iat`, a unique `jti`, `events`, `sub`, and `sid` of the ended sign-in, equal to the `sid` of the ID tokens from it. The `events` member SHALL hold exactly `http://schemas.openid.net/event/backchannel-logout` with an empty object. It SHALL NOT carry `nonce`. It SHALL be signed with the client's ID token algorithm.

#### Scenario: Token contents
- **WHEN** a logout token is sent for a sign-in of user `u-1`
- **THEN** it carries `sub` `u-1`, the sign-in's `sid`, the logout event, and no `nonce`

### Requirement: Failed deliveries are reported, and delivery is replaceable
A delivery that fails or times out SHALL be logged and reported as a security event, without the token. By default it SHALL NOT be retried, since a logout token is retransmitted only for a recoverable failure. A consumer MAY supply its own delivery, such as a queue that retries. A failed delivery SHALL NOT undo the logout.

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
