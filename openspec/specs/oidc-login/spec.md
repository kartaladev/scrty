# oidc-login Specification

## Purpose

Lets a user log in through an external OpenID Connect provider and leaves the application holding an ordinary internal session. It covers the provider registry, discovery and key caching, the authorization code flow with PKCE, state and nonce, ID token verification, and the single-use handoff code that carries a completed login from the browser callback to the application.

## Requirements

### Requirement: Provider configuration is validated at construction
The library SHALL accept a registry of named providers and SHALL validate it when constructed, before any request. Construction SHALL fail with a configuration error when:
- two providers share a name, or a name is empty or not usable as a single URL path segment;
- the issuer, client id or redirect URL is missing;
- the issuer, the redirect URL, the end-session endpoint or any pinned endpoint is not an absolute URL with a host name;
- the issuer carries a query or a fragment, or the redirect URL carries a fragment;
- the requested scopes are configured but do not include `openid`;
- the scheme of any of those URLs is not one the confined client in use allows, which with that capability's defaults means anything other than `https`;
- only some of the authorization, token and key-set endpoints are pinned;
- the accepted signature algorithms include `none`, or include a symmetric algorithm the provider was not explicitly configured to use, or include a symmetric algorithm while the client secret, which is its key, is empty.

Provider configuration SHALL be treated as trusted operator input. The only constraints on where outbound requests go SHALL be the scheme and host checks above: loopback, link-local and private-network hosts SHALL be accepted, and this SHALL be documented as a limit.

Every outbound request SHALL go through a confined client of the `outbound-http-confinement` capability, by default one built with that capability's defaults. A consumer SHALL be able to supply their own confined client, for example to trust a test certificate authority or to allow `http` for a development provider; the scheme checks above and the guarantees of that capability then apply as the supplied client configures them. The scheme check SHALL be made when the provider registry is combined with the client, so a scheme the client does not allow still fails construction, not the first login.

#### Scenario: Partial endpoint pin
- **WHEN** a provider pins its token endpoint but not its authorization or key-set endpoint
- **THEN** construction fails with a configuration error naming the provider

#### Scenario: Plain-text issuer with the default client
- **WHEN** a provider's issuer is `http://idp.example` and the consumer supplies no outbound client
- **THEN** construction fails with a configuration error naming the provider

#### Scenario: Internal development provider
- **WHEN** a provider's issuer is `https://localhost:8443/realms/dev`
- **THEN** construction succeeds

#### Scenario: Consumer supplies the outbound client
- **WHEN** a consumer supplies a confined client that allows `http` and a provider's issuer is `http://localhost:8080/realms/dev`
- **THEN** construction succeeds, and discovery and the code exchange for that provider are sent through the supplied client

#### Scenario: Algorithm none
- **WHEN** a provider is configured to accept the algorithms `RS256` and `none`
- **THEN** construction fails with a configuration error

### Requirement: Discovery is lazy by default and confined to the issuer
When a provider pins none of its endpoints, the library SHALL fetch the provider's discovery document on first use, not at construction. The document's issuer SHALL equal the configured issuer exactly. Every endpoint the document names SHALL use a scheme the confined client allows and share the issuer's origin, as the `outbound-http-confinement` capability's origin comparison decides, or the document SHALL be refused. A provider that pins all three endpoints SHALL never be sent a discovery request. A consumer SHALL be able to request eager discovery at start-up, which fetches every provider's metadata and key set and returns an error naming the first provider that could not be fetched.

#### Scenario: No network at construction
- **WHEN** a registry of providers without pinned endpoints is constructed while every provider is unreachable
- **THEN** construction succeeds and no request is made

#### Scenario: Issuer mismatch
- **WHEN** a provider configured with issuer `https://idp.example` serves a discovery document whose issuer is `https://evil.example`
- **THEN** the document is refused and the login fails as a provider failure

#### Scenario: Discovered endpoint on another origin
- **WHEN** a discovery document names a key-set URL on `https://keys.other.example`
- **THEN** the document is refused and no request is sent to `keys.other.example`

#### Scenario: Consumer requests eager discovery
- **WHEN** the consumer requests eager discovery at start-up and one provider is unreachable
- **THEN** the request returns an error naming that provider

### Requirement: Provider metadata is cached, coalesced and backed off
The library SHALL cache each provider's discovery document and key set for a TTL of 15 minutes by default, replaceable by an option. A request that finds a fresh cache entry SHALL make no network call. Concurrent requests that miss the same entry for the same provider SHALL share one outbound fetch. A cancelled caller SHALL stop waiting without failing the shared fetch for the other callers. After a failed fetch, later callers for the same provider and resource SHALL receive the recorded failure without a network call until a backoff window elapses. The window SHALL start at 1 second, double per consecutive failure, be capped at 30 seconds, and reset on a success. Both backoff bounds SHALL be replaceable. A non-positive TTL, a non-positive base or a cap below the base SHALL fail construction.

#### Scenario: Burst of cache misses
- **WHEN** 8 requests needing the same provider's key set arrive concurrently with an empty cache
- **THEN** exactly one key-set fetch is sent
- **AND** all 8 requests receive its result

#### Scenario: Failing provider is not hammered
- **WHEN** a key-set fetch fails and 20 further requests for that provider arrive within one second
- **THEN** no further fetch is sent
- **AND** each of the 20 requests fails as a provider failure

#### Scenario: Leader cancels
- **WHEN** the caller that started a shared fetch cancels its context while another caller waits on the same fetch
- **THEN** the waiting caller receives the fetched key set

#### Scenario: Consumer TTL
- **WHEN** the TTL is configured as 1 hour and a key set fetched at 10:00 is needed at 10:30
- **THEN** no fetch is sent

### Requirement: Expired provider metadata is never served by default
A cached discovery document or key set older than the TTL SHALL NOT be used when its refetch fails, by default; the request SHALL fail as a provider failure. A consumer SHALL be able to configure a stale window, after which an entry at least as old as the TTL and no older than the TTL plus the window SHALL be served when its refetch fails, with a warning logged for every such use naming the provider and the entry's age. A stale key set SHALL NOT be served to a caller whose token names a key id the stale set does not contain. A fresh entry SHALL never be served in place of a failed unknown-key-id refetch. A negative window SHALL fail construction.

#### Scenario: Default refuses expired keys during an outage
- **WHEN** a provider's key set is older than the TTL and its refetch fails
- **THEN** the login fails as a provider failure

#### Scenario: Consumer stale window
- **WHEN** a stale window of 10 minutes is configured, the provider's key set is 20 minutes old with a 15-minute TTL, its refetch fails, and a token names a key id in that set
- **THEN** the token is verified against the stale set
- **AND** a warning naming the provider is logged

#### Scenario: Stale set lacks the key
- **WHEN** a stale window is configured, the key set is inside it, its refetch fails, and a token names a key id absent from the set
- **THEN** the login fails as a provider failure, not as an invalid token

### Requirement: Provider metadata is fetched on demand, with no background work
Provider metadata and key sets SHALL be fetched only on behalf of a request or an explicit eager-discovery call. The library SHALL run no background refresh and SHALL leave no goroutine running between requests, so OIDC login needs no start or stop step. The documentation SHALL state that the first request after an entry expires waits for one fetch, bounded by the outbound client's timeout.

#### Scenario: No goroutine between requests
- **WHEN** a key set is fetched for a burst of concurrent requests, some of whose callers cancel, and every request has returned
- **THEN** no goroutine started by the library remains running

#### Scenario: Expired entry is refetched on demand
- **WHEN** a key set fetched at 10:00 with a 15-minute TTL is needed at 10:20
- **THEN** exactly one key-set fetch is sent for that request

### Requirement: An unknown key id refetches at most once per cooldown per provider
When a token names a key id absent from a fresh cached key set, the library SHALL refetch the provider's key set once before refusing the token. Further unknown key ids for the same provider within a cooldown of 30 seconds after that refetch SHALL be refused from the cache without a network call. The cooldown SHALL be tracked per provider, never globally. Callers arriving while the refetch is in flight SHALL share its result. A refusal inside the cooldown SHALL be reported as an invalid token, not as a provider failure, and SHALL NOT open or widen a failure backoff window. The cooldown SHALL be replaceable, and a non-positive cooldown SHALL fail construction.

#### Scenario: Key rotation is picked up
- **WHEN** a provider rotates its signing key and a token signed with the new key id arrives while the old key set is cached
- **THEN** the key set is refetched once and the token verifies

#### Scenario: Random key ids cost one fetch
- **WHEN** 100 tokens for provider `a`, each naming a different random key id, arrive within 10 seconds while provider `a`'s key set is cached
- **THEN** at most one key-set fetch is sent to provider `a`
- **AND** every token is refused as invalid, not as a provider failure

#### Scenario: Cooldown is per provider
- **WHEN** provider `a` is inside its cooldown and a token for provider `b` names a key id missing from `b`'s cached key set
- **THEN** provider `b`'s key set is refetched

#### Scenario: Consumer cooldown
- **WHEN** the cooldown is configured as zero
- **THEN** construction fails with a configuration error

### Requirement: Authorization always uses PKCE, state and nonce
Starting a login for a registered provider SHALL generate a fresh state, a fresh nonce and a fresh PKCE code verifier from a cryptographically secure source, each carrying at least 256 bits of entropy. The redirect to the provider SHALL carry the client id, the configured redirect URL, the requested scopes (`openid`, `profile` and `email` by default, replaceable per provider), the state, the nonce and an S256 code challenge. The verifier SHALL never be sent to the authorization endpoint, and the `plain` challenge method SHALL never be used. The flow SHALL be stored with an expiry of 10 minutes by default, replaceable by an option. The browser SHALL receive only an opaque flow handle, in a cookie that is `HttpOnly`, `Secure`, `SameSite=Lax` and scoped to the callback path, and whose lifetime is the flow's remaining lifetime rounded up to whole seconds, and at least one second. The redirect SHALL carry `Referrer-Policy: no-referrer`. A request for an unregistered provider SHALL be answered as not found without creating a flow.

#### Scenario: Authorization redirect
- **WHEN** a browser starts a login for provider `corp`
- **THEN** it is redirected to `corp`'s authorization endpoint with `response_type=code`, `code_challenge_method=S256`, a state, a nonce and a code challenge
- **AND** it receives a flow cookie that is `HttpOnly`, `Secure` and `SameSite=Lax`

#### Scenario: Fresh values per attempt
- **WHEN** the same browser starts two logins for `corp`
- **THEN** the two redirects carry different states, nonces and code challenges

#### Scenario: Unknown provider
- **WHEN** a browser starts a login for provider `nope`, which is not registered
- **THEN** the response is not found and no flow is stored

#### Scenario: Consumer scopes
- **WHEN** provider `corp` is configured with scopes `openid` and `groups`
- **THEN** the authorization redirect requests exactly `openid groups`

### Requirement: A flow is completed only by a caller who knows its provider and state
A flow store SHALL provide an operation that completes a flow given its handle, provider and state. Existence, the provider binding, the state binding, not having been completed, and not having expired SHALL be decided in one indivisible operation. At most one completion of a flow SHALL ever succeed. A completion that fails any condition SHALL leave the flow exactly as it was. An unknown handle, a wrong provider, a wrong or empty state, an expired flow and a completed flow SHALL all be refused with the same outcome. State comparisons made in process memory SHALL take constant time. The flow store SHALL provide deletion of expired flows. Deleting expired flows with a zero cutoff time SHALL be refused with an error and SHALL delete nothing. The in-memory flow store SHALL be the default. It SHALL remove expired flows without a background goroutine, and SHALL refuse new flows with an error once it holds its configured maximum of unexpired flows, 100,000 by default. Any implementation of the flow store contract SHALL be usable in its place.

#### Scenario: Forged callback does not spend the victim's flow
- **WHEN** a victim's browser carries a live flow cookie and is sent to the callback with an attacker's code and state `attacker`
- **THEN** the callback is refused as an authentication failure
- **AND** the victim's genuine callback with the real state still completes

#### Scenario: Racing callbacks
- **WHEN** 8 callbacks present the same handle, provider and correct state at the same time
- **THEN** exactly one completes the flow
- **AND** the other 7 are refused with the same outcome as an unknown handle

#### Scenario: Wrong provider
- **WHEN** a flow started for provider `a` is completed through the callback path of provider `b`
- **THEN** the completion is refused
- **AND** the flow remains completable through provider `a`

#### Scenario: Zero purge cutoff
- **WHEN** expired flows are deleted with a zero cutoff time
- **THEN** an error is returned and every flow remains completable

#### Scenario: Consumer flow store
- **WHEN** the login is configured with a consumer's flow store
- **THEN** every flow is begun and completed through that store

### Requirement: A provider error redirect cannot cancel someone else's login
When the callback receives an authorization error from the provider instead of a code, the library SHALL end the flow only when the echoed state completes it, as for a code. Only then SHALL it clear the flow cookie. A callback carrying an error and a state that does not complete the flow SHALL change nothing and SHALL leave the cookie in place. The provider's error text SHALL be logged only after the flow has been completed, and SHALL never be returned to the caller. Either way the response SHALL be an authentication failure.

#### Scenario: Forged error link
- **WHEN** a victim with a live flow cookie follows a link to the callback carrying `error=access_denied` and no valid state
- **THEN** the response is an authentication failure
- **AND** no cookie-clearing header is sent
- **AND** the victim's genuine callback still completes

#### Scenario: Genuine denial at the provider
- **WHEN** the provider redirects back with `error=access_denied` and the flow's real state
- **THEN** the flow is ended and the flow cookie is cleared

### Requirement: The code exchange authenticates the client and hides provider detail
After completing the flow, the library SHALL exchange the authorization code at the provider's token endpoint. The exchange SHALL carry the flow's PKCE verifier and the configured redirect URL. It SHALL authenticate the client with the client id and secret in the request body by default, or with HTTP Basic client credentials when the provider is configured for that method. The request SHALL be sent through the confined client's form POST, so the rule that no request body is replayed to another origin covers it. A provider error response, a malformed response or a response without an ID token SHALL fail the login as a provider failure. The provider's response body SHALL be logged at most in bounded form and SHALL never be returned to the caller. The provider's access and refresh tokens SHALL be discarded.

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

### Requirement: ID tokens are verified strictly
An ID token SHALL be accepted only when all of the following hold:
- it is a signed token whose algorithm is in the provider's accepted set (`RS256` by default, replaceable per provider) and never `none`;
- for an asymmetric algorithm, it names a key id and its signature verifies against that key in the provider's key set; for a symmetric algorithm the provider explicitly accepts, its signature verifies against the client secret;
- when it carries an authorized party, that party is a string equal to the client id;
- its issuer equals the configured issuer exactly;
- its audience contains the client id, and when it names more than one audience, its authorized party equals the client id;
- it carries an expiry that has not passed, and its issued-at and not-before times are acceptable, each within a clock leeway of 60 seconds by default, replaceable by an option;
- its nonce equals the flow's nonce;
- its subject is present and non-empty.

Every verification failure SHALL be reported as one invalid-token outcome, with the specific cause available only to logs. A key set that could not be retrieved SHALL be reported as a provider failure, not as an invalid token.

#### Scenario: Wrong audience
- **WHEN** an otherwise valid ID token's audience is `other-client`
- **THEN** the login fails with the invalid-token outcome

#### Scenario: Nonce replay
- **WHEN** an ID token carrying a valid signature and the nonce of an earlier flow is returned for a new flow
- **THEN** the login fails with the invalid-token outcome

#### Scenario: Missing expiry
- **WHEN** an otherwise valid ID token carries no expiry
- **THEN** the login fails with the invalid-token outcome

#### Scenario: Multiple audiences without authorized party
- **WHEN** an ID token's audience is `client-a` and `client-b` and it names no authorized party
- **THEN** the login fails with the invalid-token outcome

#### Scenario: Consumer algorithm set
- **WHEN** provider `corp` is configured to accept only `ES256` and returns a token signed with `RS256`
- **THEN** the login fails with the invalid-token outcome

### Requirement: The callback conveys the login by a short-lived single-use code
After the ID token is verified and the external identity resolves to an internal user, the callback SHALL NOT create a session. It SHALL issue a handoff code and redirect the browser to the post-login destination, with the code as a query parameter. The code SHALL:
- be drawn from a cryptographically secure source with at least 256 bits of secret entropy;
- be stored only as a digest of its secret;
- carry the user reference of the resolved user, the provider name, the verified issuer, the provider session id (which may be empty) and the raw ID token;
- expire 60 seconds after issue.

The handoff store SHALL refuse to delete expired codes with a zero cutoff time. The expiry SHALL NOT be configurable: the code travels in a URL and a refused code stays live until it expires, so widening the window is a security decision, and the documentation SHALL say so. The redirect SHALL carry `Referrer-Policy: no-referrer` and `Cache-Control: no-store`, and SHALL clear the flow cookie. The code, the ID token and the claims SHALL never be written to a log by the library. The documentation SHALL state that a code travels in a URL and can be recorded by browser history and intermediaries until it expires or is spent.

#### Scenario: Successful callback
- **WHEN** a callback completes the flow, verifies the ID token and resolves user `u-1`
- **THEN** the browser is redirected to the destination with a `handoff` query parameter
- **AND** the response carries `Referrer-Policy: no-referrer` and `Cache-Control: no-store`
- **AND** no session exists yet for `u-1`

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
The destination requested when a login starts SHALL be recorded untrusted, and SHALL be used only when it exactly matches an entry of the redirect allowlist. Otherwise the destination SHALL be `/`. The allowlist SHALL be empty by default. Each entry, and each origin the consumer declares, SHALL be validated at construction by the rules of the `outbound-http-confinement` capability's requirement that browser redirect targets are host-relative or declared; an invalid entry or origin SHALL fail construction. The destination SHALL be checked again against the allowlist when it is used. The OIDC allowlist SHALL be configured separately from any other flow's.

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

### Requirement: A consumer can replace the callback's conveyance
A consumer SHALL be able to supply a callback success handler. When one is supplied, it SHALL be called after the flow is completed, the ID token is verified and the identity is resolved, with the resolved principal, the provider session details and the validated destination. No handoff code SHALL then be issued. Everything before that point SHALL still be performed by the library.

#### Scenario: Consumer conveys the login itself
- **WHEN** a callback success handler is configured and a callback succeeds for user `u-1`
- **THEN** the handler receives the principal for `u-1` and the verified issuer
- **AND** no handoff code is stored

### Requirement: Handoff redemption is check-then-consume
The handoff redemption endpoint SHALL accept the code only in the body of a POST request, and SHALL ignore a code in the query string. Redemption SHALL proceed in this order:
1. validate the code: it is well formed, its record exists, its secret matches in constant time, and it has not expired;
2. resolve the account by the recorded user reference through the user loader, and refuse it unless the loaded details carry exactly that reference and the user is enabled;
3. run the refusal checks, including the post-authentication policy evaluation from the `security-policy` capability;
4. consume the code in one atomic operation, last.

An already-consumed record MAY be rejected before step 2, but that rejection SHALL NOT be what guarantees single use; only the atomic consume SHALL decide. A refusal or failure at step 2 or 3 SHALL leave the code redeemable until it expires. Refusal checks SHALL be documented as required to be side-effect free, because racing redemptions of one code can each run them. The login completion step SHALL reuse the post-authentication decision made at step 3, rather than evaluating the post-authentication policies again after the code is consumed, so a policy lookup failure never spends the code.

#### Scenario: Racing redemptions
- **WHEN** 8 requests redeem the same valid code at the same time
- **THEN** exactly one creates a session
- **AND** the other 7 receive the invalid-handoff outcome

#### Scenario: Code in the query string
- **WHEN** a POST to the redemption endpoint carries the code only in its query string
- **THEN** redemption is refused with the invalid-handoff outcome

#### Scenario: A policy lookup failure does not spend the code
- **WHEN** a consumer's classification removes the OIDC exemption, the second-factor challenge policy's enrolment lookup fails while a valid code is redeemed, and the code is redeemed again after the lookup recovers
- **THEN** the first redemption is refused and creates no session
- **AND** the second redemption completes

### Requirement: Handoff redemption failures reveal nothing about the cause
Redemption SHALL fail with the same invalid-handoff outcome for:
- an unknown, malformed, wrong-secret, expired or already-consumed code;
- an account that is missing, disabled, or whose loaded reference differs from the recorded one;
- a failure of the handoff store or the user loader, including a failure of the consume.

Policy denials and consumer check errors SHALL be the only redemption errors that are not the invalid-handoff outcome. The cause SHALL be available only to logs, at error level for a store or loader failure. No error or log record SHALL contain the code.

#### Scenario: Disabled user and wrong secret look alike
- **WHEN** a code for a disabled user and a code with a wrong secret are redeemed
- **THEN** both fail with the same invalid-handoff outcome

#### Scenario: Transient loader failure keeps the code
- **WHEN** a valid code is redeemed while the user loader is failing, and the same code is redeemed again after the loader recovers and before the code expires
- **THEN** the first redemption fails with the invalid-handoff outcome, creates no session and logs the failure at error level
- **AND** the second redemption succeeds

#### Scenario: Reference mismatch
- **WHEN** a code recorded for user reference `u-1` is redeemed and the loader returns details for `u-2`
- **THEN** redemption fails with the invalid-handoff outcome
- **AND** the code is not consumed

#### Scenario: Consume fails
- **WHEN** a valid code passes every check but the store fails while consuming it
- **THEN** redemption fails with the invalid-handoff outcome
- **AND** no session is created and no access token is issued

### Requirement: Policy decisions at redemption cannot be lost
When the post-authentication policy evaluation denies a redemption, redemption SHALL refuse without consuming the code. It SHALL return the policy's reason, or a policy-denied error when the policy gave no reason. A deny SHALL never result in a session. When the evaluation challenges, the code SHALL be consumed and a session SHALL be created pending that challenge, as the `sessions` and `security-policy` capabilities define. When the redemption operation is replaced by a consumer implementation, the endpoint SHALL refuse with the policy-denied error, and create no session, whenever the implementation reports success but:
- the policy evaluation never ran; or
- the evaluation denied; or
- the implementation returns a user other than the one the evaluation decided on: a different user reference, or a password-change time not equal to the one the evaluation saw.

#### Scenario: Deny with no reason
- **WHEN** a consumer policy denies a redemption without giving a reason
- **THEN** redemption fails with the policy-denied error
- **AND** no session is created
- **AND** the same code redeems successfully once the policy allows, before it expires

#### Scenario: Challenge redeems
- **WHEN** a consumer's first-factor classification removes the OIDC exemption and the user is enrolled in MFA
- **THEN** the code is consumed and a session is created pending the MFA challenge
- **AND** the response is the challenge outcome

#### Scenario: Implementation skips the checks
- **WHEN** a consumer redemption implementation returns success without running the refusal checks
- **THEN** the endpoint refuses with the policy-denied error and creates no session

#### Scenario: Implementation discards a deny
- **WHEN** a consumer redemption implementation runs the refusal checks, receives a deny, ignores it and returns success
- **THEN** the endpoint refuses with the policy-denied error and creates no session

#### Scenario: Implementation returns another user
- **WHEN** a consumer redemption implementation runs the refusal checks for user `u-1` and returns success for user `u-2`
- **THEN** the endpoint refuses with the policy-denied error and creates no session

#### Scenario: Implementation returns the same user reloaded
- **WHEN** a consumer redemption implementation runs the refusal checks for `u-1` and returns success for `u-1` reloaded, with the same password-change instant in another time zone
- **THEN** the redemption completes as the evaluation decided

### Requirement: Refused redemptions count against the per-source limit by default
The redemption endpoint SHALL check the request's source with a per-source guard from the `rate-limiting` capability, through the chain's source throttle step, before redeeming. A throttled or unattributable source SHALL be refused with the invalid-handoff outcome without redeeming, and the refusal SHALL NOT spend the code. The guard SHALL use a limiter dedicated to handoff redemption unless the consumer shares one on purpose.

By default, the endpoint SHALL record a failure for the source whenever redemption fails, including a policy denial or consumer check refusal of a valid code, and including a store or loader failure. A consumer SHALL be able to choose not to record policy denials and consumer check refusals. Every other redemption failure SHALL still be recorded.

The default limit SHALL be 10 failures per source in 5 minutes, replaceable by options. A consumer SHALL be able to replace the limiter. A nil limiter SHALL fail construction with a configuration error.

#### Scenario: Replaying a denied code
- **WHEN** a code is denied by policy 10 times from `203.0.113.7` within 5 minutes and redeemed an 11th time from that source
- **THEN** the 11th request is refused with the invalid-handoff outcome without redeeming
- **AND** the code is not consumed

#### Scenario: Consumer opts out of counting refusals
- **WHEN** counting refusals of valid codes is turned off and a code is denied by policy 10 times from one source within 5 minutes
- **THEN** an 11th redemption from that source is evaluated, not throttled

#### Scenario: Guessing still counts
- **WHEN** counting refusals of valid codes is turned off and 10 wrong codes are presented from one source within 5 minutes
- **THEN** an 11th redemption from that source is refused with the invalid-handoff outcome without redeeming

### Requirement: A successful redemption establishes a federated session
A redemption that consumes the code SHALL complete the login through the login completion step of the `http-security-chain` capability, as every other first factor does. The session SHALL record the OIDC first-factor kind, together with the provider name, verified issuer, provider session id and ID token carried by the code, all in the write that creates the session. The session SHALL be created for the principal built from the resolved account's stored details, so that it holds only the user's stored roles. An access token SHALL then be issued through the `token-issuance` capability. The response SHALL be the JSON body form login answers with, plus the destination re-validated against the redirect allowlist as `next`, with `Cache-Control: no-store` and `Referrer-Policy: no-referrer`. A consumer who needs a different response replaces the conveyance with a callback success handler.

#### Scenario: Session carries the federation fields
- **WHEN** a code issued for user `u-1`, issuer `https://idp.example` and provider session `sid-9` is redeemed
- **THEN** the created session records the OIDC first factor, issuer `https://idp.example` and provider session `sid-9`

#### Scenario: Response body
- **WHEN** a code is redeemed with destination `/welcome`, which is allowlisted
- **THEN** the response body carries `access_token`, `valid_until` and `next` equal to `/welcome`, in the same form a form login's body carries its token
- **AND** the response carries `Cache-Control: no-store`

### Requirement: OIDC logins are exempt from local MFA by default, as a stated limit
By default, a login established through OIDC SHALL be classified as exempt from the local MFA challenge and MFA requirement, per the first-factor classification of the `identity-model` and `security-policy` capabilities. The library SHALL NOT read the provider's authentication method or assurance claims to decide this. This exemption SHALL be documented as a limit: the application trusts the provider's own authentication strength entirely. A consumer SHALL be able to remove the exemption through that classification, after which OIDC logins are evaluated by the MFA policies like any other login. Removing it SHALL require the second-factor challenge to be wired, as the chain already requires of any policy that can raise one.

With the exemption removed, a required user with no usable enrolment SHALL enter the MFA enrolment path only when the consumer has also added OIDC to that path's allowlist, as the `security-policy` capability defines; OIDC is off it by default.

#### Scenario: Default exemption
- **WHEN** a user required to use MFA logs in through OIDC with the default classification
- **THEN** the redemption creates a session without an MFA challenge

#### Scenario: Consumer removes the exemption
- **WHEN** the consumer's classification makes OIDC non-exempt and a user required to use MFA with no enrolment redeems a code
- **THEN** redemption is refused with the enrolment-required reason
- **AND** the code is not consumed

#### Scenario: Consumer removes the exemption and admits OIDC to the enrolment path
- **WHEN** the consumer's classification makes OIDC non-exempt, the enrolment path is on with OIDC on its allowlist, and a user required to use MFA with no enrolment redeems a code
- **THEN** the code is consumed and a session is created in the enrolment-pending state
- **AND** the response is the enrolment challenge outcome

### Requirement: Endpoints fail in a way that separates bad input from outages
An invalid flow, a provider error redirect, an invalid ID token, an unlinked identity, a refused provisioning and an invalid handoff SHALL be reported as authentication failures, each identifiable both as its own error and as the authentication-failed refusal of the `http-error-propagation` capability. A provider that cannot be reached, a failed key-set retrieval, and a store or loader outage in the callback SHALL be reported as errors that are not authentication failures, so that they map to a server-error status. A handoff redemption outage is the exception: it is the invalid-handoff outcome, as the redemption requirements state. A request to an OIDC path for an unregistered provider SHALL be refused with an unknown-provider error, which maps to not found. Refusal log records SHALL be sampled through the `log-sampling` capability with a reporter configured, and SHALL NOT contain codes, secrets, tokens or claim values.

#### Scenario: Provider outage is not a bad login
- **WHEN** a callback's code exchange fails because the token endpoint is unreachable
- **THEN** the error is not an authentication failure

#### Scenario: Unlinked identity
- **WHEN** a callback verifies an ID token for an identity with no link while just-in-time provisioning is off
- **THEN** the error is an authentication failure and maps to 401

#### Scenario: Unknown provider path
- **WHEN** a browser requests the authorize path for provider `nope`, which is not registered
- **THEN** the error is the unknown-provider error and maps to 404

#### Scenario: Every adapter answers alike
- **WHEN** the same authorize, callback, redemption and back-channel requests are sent through the `net/http` chain and through each framework adapter
- **THEN** every adapter produces the same status, headers and body

### Requirement: OIDC wiring mistakes fail at construction
Constructing OIDC login SHALL fail with a configuration error when:
- no provider is registered;
- two of the authorize, callback, redemption and back-channel logout paths collide;
- any duration option is zero or negative, except the clock-skew leeway, for which zero means no leeway and only a negative value fails;
- just-in-time provisioning or role derivation is configured for a provider name that is not registered.

#### Scenario: Colliding paths
- **WHEN** the redemption path is configured equal to the callback path
- **THEN** construction fails with a configuration error

#### Scenario: Option for an unknown provider
- **WHEN** just-in-time provisioning is enabled for provider `corpp` while only `corp` is registered
- **THEN** construction fails with a configuration error naming `corpp`

### Requirement: OIDC components flush their refusal logs
The OIDC login manager, the handoff manager and the identity broker SHALL each expose a flush that reports every pending suppressed count of their refusal-log samplers to the configured reporter. Flushing the login manager SHALL also flush the broker it was given, when that broker can flush. A flush SHALL write nothing else and SHALL leave the component usable.

#### Scenario: Handoff redemption flood flushed at shutdown
- **WHEN** the handoff manager has suppressed 30 refusal records in the current window and is flushed
- **THEN** its reporter receives the pending count of 30

#### Scenario: Manager flushes its broker
- **WHEN** a login manager built with a broker that has suppressed provisioning refusals is flushed
- **THEN** the broker's reporter receives its pending count
