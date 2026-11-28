# Spec Delta

## Purpose

Lets an app that signs browsers in with a session cookie call its downstream APIs as the signed-in
user, with a token for each API that never reaches the browser, and keeps the session cookie from
ever reaching an API.

## ADDED Requirements

### Requirement: Outbound tokens are off until enabled
A chain SHALL hand out no outbound token and offer no outbound transport unless the consumer enables outbound tokens. Enabling them SHALL name each downstream API by its resource identifier, which is the audience of the tokens for it.

#### Scenario: Default chain
- **WHEN** a cookie chain that does not enable outbound tokens serves a cookie-authenticated request, and a handler asks for an outbound token
- **THEN** it receives the no-outbound-token error and no token is minted or loaded

#### Scenario: Consumer enables outbound tokens
- **WHEN** a cookie chain enables outbound tokens for the API `https://orders.example`, and a handler on a cookie-authenticated request asks for that API's token
- **THEN** it receives a token whose audience is `https://orders.example`

### Requirement: Each API is served by exactly one token source
Each configured API SHALL name exactly one source of tokens: minted by the chain, the access token of a named identity provider, or a token source the consumer supplies. The consumer source SHALL replace the library's minting and refresh entirely for that API.

#### Scenario: Consumer source
- **WHEN** an API is configured with a consumer token source that returns `tok-1`, and a handler asks for that API's token
- **THEN** it receives `tok-1`, and the chain mints nothing and loads no provider token

#### Scenario: Consumer source fails
- **WHEN** the consumer token source returns an error, or returns an empty token
- **THEN** the handler receives a dependency error, identifiable as such and not as the no-outbound-token error, and nothing is sent

### Requirement: Only a cookie-authenticated request gets an outbound token
An outbound token SHALL be returned only for a request the session cookie authenticated, whose session owes no second-factor or enrolment challenge. Any other request SHALL receive the no-outbound-token error, and no token SHALL be minted, loaded or refreshed for it.

#### Scenario: Request authenticated by another method
- **WHEN** a handler asks for an outbound token on a request authenticated by an API key, a session reference or a resource-server source
- **THEN** it receives the no-outbound-token error

#### Scenario: Anonymous request
- **WHEN** a handler asks for an outbound token on a request with no authenticated session
- **THEN** it receives the no-outbound-token error

#### Scenario: Challenge still owed
- **WHEN** a handler asks for an outbound token on a cookie-authenticated request whose session still owes a second factor
- **THEN** it receives the no-outbound-token error

### Requirement: An outbound token never reaches a response
The library SHALL NOT write an outbound token, minted or provider, into a response header, body or cookie.

#### Scenario: Handler obtains a token
- **WHEN** a handler obtains an outbound token on a cookie-authenticated request and writes a response of its own
- **THEN** no header, cookie or body that the library writes carries the token

### Requirement: A minted token is a typed access token for one API
A minted token SHALL be a signed JWT with header `typ` `at+jwt`, and claims `iss` the chain's issuer, `sub` the session's user reference, `aud` exactly the API's resource identifier, `client_id`, `iat`, `exp`, and a `jti` drawn fresh from a cryptographic random source. `client_id` SHALL default to the chain's issuer and SHALL be replaceable by an option.

#### Scenario: Default claims
- **WHEN** a token for `https://orders.example` is minted at 10:00:00 for a session of user `u-1`, on a chain with issuer `https://app.example` and default settings
- **THEN** its header has `typ` `at+jwt`, and its claims have `iss` `https://app.example`, `sub` `u-1`, `aud` `https://orders.example`, `client_id` `https://app.example`, `iat` 10:00:00 and `exp` 10:05:00

#### Scenario: Consumer sets the client identifier
- **WHEN** the consumer configures the client identifier `bff-web` and a token is minted
- **THEN** its `client_id` claim is `bff-web`

#### Scenario: Verified by a resource server
- **WHEN** a minted token is sent to a resource server whose remote-issuer source names the chain's issuer and key set, covers `https://orders.example` and opts out of binding
- **THEN** the token is accepted and its subject is `u-1`

### Requirement: A minted token never carries the session identifier
A minted token's `jti` SHALL differ from the identifier of the session it was minted for, and SHALL differ between any two minted tokens. A minted token SHALL NOT authenticate any request as a session on any chain.

#### Scenario: Identifier is not the session's
- **WHEN** a token is minted for a session whose identifier is `S`
- **THEN** its `jti` is not `S` and does not contain `S`

#### Scenario: Presented as a signed bearer token
- **WHEN** a minted token is presented under `Bearer` to a chain with signed bearer tokens that share the same signing keys
- **THEN** it is refused as an invalid token and no session is loaded

#### Scenario: Two tokens for one session
- **WHEN** two tokens are minted for the same session and API
- **THEN** their `jti` values differ

### Requirement: A minted token's lifetime is short and bounded by the session
A minted token's lifetime SHALL default to 5 minutes and SHALL NOT exceed 5 minutes. Its expiry SHALL be the earlier of its issue time plus the lifetime and the session's absolute deadline.

#### Scenario: Session ends sooner
- **WHEN** a token is minted at 20:58:00 for a session whose absolute deadline is 21:00:00
- **THEN** its `exp` is 21:00:00

#### Scenario: Consumer shortens the lifetime
- **WHEN** the consumer configures a lifetime of 2 minutes and a token is minted at 10:00:00
- **THEN** its `exp` is 10:02:00

### Requirement: A minted token is never stored and is renewed by minting again
A minted token SHALL NOT be written to the session or to any store. Within one request, asking again for the same API SHALL return the same token while more than one minute of it remains, and a new token otherwise. A later request SHALL mint its own token.

#### Scenario: Same request asks twice
- **WHEN** a handler asks twice for the token of one API within one request, the second time 10 seconds after the first
- **THEN** both answers are the same token

#### Scenario: Under one minute left
- **WHEN** within one request the held token for an API has less than one minute left and the handler asks again
- **THEN** a new token is minted with a new `jti`

#### Scenario: Nothing persisted
- **WHEN** a token is minted and the request completes
- **THEN** the session record and every store are unchanged by the minting

### Requirement: A minting failure is a dependency failure
When the key source cannot provide a signing key, the handler SHALL receive a dependency error that keeps the cause reachable, identifiable as neither the no-outbound-token error nor an authentication refusal, and the session SHALL be left unchanged.

#### Scenario: Key source down
- **WHEN** the key source fails while a token is being minted
- **THEN** the handler receives a dependency error whose cause is the key source's error, and the session is neither ended nor modified

#### Scenario: Request context ends
- **WHEN** the request's context is cancelled while a token is being minted
- **THEN** the handler receives an error matching the context's error

### Requirement: A provider API gets the access token of the provider the session signed in through
For an API served by a named provider, the token SHALL be the provider access token kept on the session. A session not signed in through that provider, or holding no access token for it, SHALL get the provider-token-unavailable error, distinct from the no-outbound-token error and from a dependency failure.

#### Scenario: Federated session
- **WHEN** a session signed in through provider `corp`, which kept access token `at-1` valid for 30 more minutes, asks for the token of an API served by `corp`
- **THEN** it receives `at-1`

#### Scenario: Local sign-in
- **WHEN** a session signed in with a password asks for the token of an API served by `corp`
- **THEN** it receives the provider-token-unavailable error

#### Scenario: Another provider
- **WHEN** a session signed in through `partner` asks for the token of an API served by `corp`
- **THEN** it receives the provider-token-unavailable error

### Requirement: A provider token near expiry is refreshed with the provider's refresh token
When less than one minute of the kept access token remains, the library SHALL refresh it at the provider's token endpoint with the kept refresh token, authenticating the client as the code exchange does, through the confined client, and SHALL return the new access token.

#### Scenario: Refresh near expiry
- **WHEN** the kept access token expires in 40 seconds and the session asks for the API's token
- **THEN** a refresh-token request is sent to `corp`'s token endpoint with the kept refresh token, and the handler receives the new access token

#### Scenario: Provider rotates the refresh token
- **WHEN** the refresh response carries a new refresh token
- **THEN** the session keeps the new refresh token and the old one is no longer kept

#### Scenario: Provider keeps the refresh token
- **WHEN** the refresh response carries no refresh token
- **THEN** the session keeps the refresh token it had

#### Scenario: Response without an expiry
- **WHEN** a token response carries no `expires_in`, received at 10:00:00, with default settings
- **THEN** the access token is treated as expiring at 10:05:00

#### Scenario: Consumer sets the fallback expiry
- **WHEN** the consumer configures a fallback lifetime of 15 minutes and a token response without `expires_in` is received at 10:00:00
- **THEN** the access token is treated as expiring at 10:15:00

### Requirement: Refreshes of one session are coalesced and saved conditionally
Concurrent refreshes for one session within one process SHALL send one refresh request. The result SHALL be saved by a single write conditional on the session still holding the refresh token that was read. A caller whose write loses SHALL reload the session and use the token it then holds.

#### Scenario: Concurrent requests in one process
- **WHEN** ten requests of one session ask for the API's token at once and the kept access token is about to expire
- **THEN** one refresh request is sent, and all ten receive the same new access token

#### Scenario: Another replica refreshed first
- **WHEN** a refresh's conditional save fails because another replica already replaced the refresh token
- **THEN** the session is reloaded and the handler receives the access token the other replica saved

#### Scenario: Session deleted during the refresh
- **WHEN** the session is deleted while its refresh is in flight
- **THEN** the save changes nothing, no session is re-created, and the handler receives the no-outbound-token error

#### Scenario: Session rotated during the refresh
- **WHEN** the session is rotated while its refresh is in flight, so the save reports it superseded
- **THEN** the new tokens are saved to its newest successor under the same condition, and the handler receives the new access token

#### Scenario: Superseded identifier near expiry
- **WHEN** a request presents a superseded identifier inside its grace window, and that session's kept access token has less than one minute left
- **THEN** no refresh request is sent and the handler receives the provider-token-unavailable error

#### Scenario: One waiter's request is cancelled
- **WHEN** one of several requests waiting on the same refresh is cancelled
- **THEN** that request receives an error matching its context's error, and the others receive the refreshed token

### Requirement: A rejected refresh clears the provider tokens and keeps the session
When the provider rejects the refresh token as an invalid grant, the library SHALL clear the provider tokens from the session by a conditional write and return the provider-token-unavailable error. The session SHALL remain signed in.

#### Scenario: Refresh token revoked at the provider
- **WHEN** the provider answers the refresh with `invalid_grant`
- **THEN** the handler receives the provider-token-unavailable error, the session no longer holds provider tokens, and the next cookie-authenticated request on that session still succeeds

#### Scenario: No refresh token kept
- **WHEN** the provider issued no refresh token at sign-in and the kept access token has expired
- **THEN** the handler receives the provider-token-unavailable error and no refresh is attempted

### Requirement: A provider outage during refresh is a dependency failure
A refresh that fails by transport error, timeout, a 5xx answer or a malformed response SHALL give the handler a dependency error, SHALL leave the kept tokens unchanged, and SHALL NOT end the session.

#### Scenario: Token endpoint answers 503
- **WHEN** the provider's token endpoint answers 503 to a refresh
- **THEN** the handler receives a dependency error and the session still holds its refresh token

### Requirement: The outbound transport sends only to configured APIs
The library SHALL offer an HTTP transport built from the configured APIs, each of which names one or more base URLs. The transport SHALL refuse, before sending, a request whose URL is under no configured API's base URL, where a base URL's path prefix matches whole segments.

#### Scenario: Unconfigured destination
- **WHEN** a request to `https://evil.example/x` is sent through the transport
- **THEN** it is refused before any connection is made, and no token is minted or loaded

#### Scenario: Prefix is not a segment boundary
- **WHEN** an API's base URL is `https://api.example/orders` and a request goes to `https://api.example/orders-admin/1`
- **THEN** it is refused before sending

### Requirement: The outbound transport attaches the API's token and removes cookies
For a request under a configured API's base URL, the transport SHALL set `Authorization` to `Bearer` and that API's token, replacing any value present, SHALL remove every `Cookie` header, and SHALL refuse the request without sending it when no token can be obtained, returning that error.

#### Scenario: Cookie and stale authorization present
- **WHEN** a request to `https://orders.example/v1` carries a `Cookie` header and `Authorization: Bearer old`
- **THEN** the request sent carries no `Cookie` header and `Authorization: Bearer` with the API's current token

#### Scenario: No token for this request
- **WHEN** the transport is used on a request context that was not cookie-authenticated
- **THEN** nothing is sent and the caller receives the no-outbound-token error

### Requirement: The outbound transport follows the confined client's rules
The transport SHALL send only over `https` by default, SHALL NOT follow a redirect to another origin, SHALL never send the token to an origin other than the request's, and SHALL bound each request in time and response size as the confined client does.

#### Scenario: Cross-origin redirect
- **WHEN** a configured API answers with a redirect to `https://other.example/`
- **THEN** the redirect is not followed and no request carrying the token reaches `other.example`

#### Scenario: Consumer allows plain HTTP
- **WHEN** the consumer allows `http` on the outbound client and an API's base URL is `http://orders.internal`
- **THEN** requests to it are sent

#### Scenario: Plain HTTP by default
- **WHEN** an API's base URL uses `http` and the consumer has not allowed `http`
- **THEN** building the chain fails with a configuration error

### Requirement: Outbound-token wiring mistakes fail at construction
Building a chain with outbound tokens SHALL fail with a configuration error naming the setting when: the chain has no cookie session; a resource identifier is empty, not absolute or has a fragment; two APIs share one; base URLs of two APIs overlap; an API has no source or several; a minted lifetime is under 1 second, not whole seconds or over 5 minutes; a provider API names an unconfigured provider.

#### Scenario: No cookie session
- **WHEN** outbound tokens are enabled on a chain that uses signed bearer tokens and no cookie session
- **THEN** construction fails with a configuration error

#### Scenario: Relative resource identifier
- **WHEN** an API is named `orders`
- **THEN** construction fails with a configuration error

#### Scenario: Lifetime too long
- **WHEN** a minted API is configured with a 10-minute lifetime
- **THEN** construction fails with a configuration error naming the 5-minute maximum

#### Scenario: Overlapping base URLs
- **WHEN** one API has base URL `https://api.example/` and another `https://api.example/orders`
- **THEN** construction fails with a configuration error

### Requirement: Provider tokens are kept only for a provider an API uses
Building a chain SHALL fail with a configuration error when a provider is configured to keep tokens for forwarding and no configured API is served by it, and when an API is served by a provider not configured to keep tokens.

#### Scenario: Kept but unused
- **WHEN** provider `corp` is configured to keep tokens and no API names `corp`
- **THEN** construction fails with a configuration error

#### Scenario: Used but not kept
- **WHEN** an API is served by `corp` and `corp` is not configured to keep tokens
- **THEN** construction fails with a configuration error

### Requirement: Outbound tokens never reach logs or errors
Minted tokens, provider access tokens and refresh tokens SHALL print, format and log as a fixed redacted text under every verb, and SHALL NOT appear in any error, event or log the library writes. A provider's error description from a refresh SHALL be logged only in bounded form and SHALL NOT be returned to the handler.

#### Scenario: Token printed
- **WHEN** a value holding an outbound token is formatted with `%v`, `%+v` or `%#v` or logged as an attribute
- **THEN** the output does not contain the token

#### Scenario: Refresh refused with a description
- **WHEN** a refresh is refused with an `error_description` containing `DESC-SENTINEL`
- **THEN** the handler's error text does not contain `DESC-SENTINEL`
