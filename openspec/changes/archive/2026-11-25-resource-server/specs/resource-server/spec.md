## Purpose

Lets a chain act as an OAuth resource server: accept access tokens, from the chain's own provider or from
other issuers, on the API routes it protects, and publish the caller they name.

## ADDED Requirements

### Requirement: A resource server accepts access tokens for its own resource identifier
The chain SHALL offer a resource-server mode, built with a resource identifier and at least one token source. It SHALL accept on the routes it covers an access token that a source verifies and whose audience names the identifier, and SHALL publish the caller it names. The identifier and each alias SHALL be an absolute URI with no fragment.

#### Scenario: Provider token accepted
- **WHEN** a resource server for `urn:example:orders:api` with the chain's provider as source receives a valid, bound access token whose audience is `urn:example:orders:api`
- **THEN** the route is called with that token's user as the caller

#### Scenario: No session needed
- **WHEN** the same request is made on a chain whose session store holds no session for the user
- **THEN** the route is still called

#### Scenario: Identifier that is no URI
- **WHEN** a resource server is built with the identifier `orders api`
- **THEN** construction fails with a configuration error naming the identifier

### Requirement: Several resource servers on one chain are scoped by path prefix
A chain MAY enable several resource servers, each covering the paths under its own prefixes. A resource server with no prefix SHALL cover every path, and SHALL be allowed only when it is the chain's only one. Prefixes of two resource servers SHALL NOT overlap; one that is a prefix of another counts as overlapping.

#### Scenario: Two APIs in one binary
- **WHEN** resource servers for `urn:orders` under `/orders/` and `urn:billing` under `/billing/` are enabled, and a token for `urn:billing` is sent to `/orders/1`
- **THEN** it is refused as an invalid token, and a token for `urn:orders` on the same route is accepted

#### Scenario: Overlapping prefixes
- **WHEN** resource servers are built under `/api/` and `/api/billing/`
- **THEN** construction fails with a configuration error naming both prefixes

#### Scenario: Unscoped beside another
- **WHEN** a resource server with no prefix and one under `/billing/` are enabled on one chain
- **THEN** construction fails with a configuration error

### Requirement: A prefix covers whole segments of the absolute path
A prefix SHALL begin and end with `/`, SHALL be absolute rather than relative to the chain's base path, and SHALL be matched against the request's canonical path whole segment by whole segment.

#### Scenario: Segment boundary
- **WHEN** a resource server covers `/api/orders/` and a token is sent to `/api/orders-v2/1`
- **THEN** that path is not covered by it

#### Scenario: Prefix without a trailing slash
- **WHEN** a resource server is built with the prefix `/api`
- **THEN** construction fails with a configuration error naming the prefix

### Requirement: A token is judged by the resource server that covers its path
The chain SHALL first choose the resource server whose prefixes cover the request's path, and then, within it, the source the token belongs to. Each resource server SHALL hold its own sources, so that two resource servers MAY trust the same issuer or the same provider.

#### Scenario: Two APIs trusting one issuer
- **WHEN** resource servers under `/orders/` and `/billing/` both trust the same remote issuer, and that issuer's token for `urn:orders` is sent to `/billing/1`
- **THEN** it is refused as an invalid token, and the same token is accepted at `/orders/1`

### Requirement: An access token on a path no resource server covers is refused
A token presented on a path no resource server covers SHALL be refused as an invalid token, before any later mode or endpoint judges it, when it is the provider's own token, an `at+jwt`, a JWT from a source's issuer, or an opaque token with a configured introspection prefix; any other token SHALL pass on. The refusal SHALL be under `DPoP` when the token came under `DPoP`, `Bearer` otherwise. The provider's token-reading endpoints run earlier and judge their tokens as before.

#### Scenario: Token outside every prefix
- **WHEN** the only resource server covers `/api/`, and a provider access token is sent to `/admin/report`
- **THEN** the request is refused as an invalid token

#### Scenario: Unprefixed opaque token off every prefix
- **WHEN** a chain's only resource server covers `/api/` with an introspection source given the prefix `kc_`, and an opaque token without that prefix is sent to `/internal/x`
- **THEN** it passes to the chain's next credential mode

#### Scenario: The provider's own endpoints
- **WHEN** the same token is sent to the provider's UserInfo endpoint
- **THEN** UserInfo judges it, as before

### Requirement: Access tokens are recognised by shape and routed to one source
Within the resource server that covers the path, a token SHALL be recognised as an access token when it is the provider's opaque access token, a JWT typed `at+jwt` (without regard to case, an `application/` prefix ignored), a JWT whose issuer is one of that resource server's sources, or an opaque token an introspection source claims, and SHALL be routed to the one source that matches. A session token and a session reference SHALL never be offered to a source.

#### Scenario: Session token beside a resource server
- **WHEN** a chain runs signed bearer tokens and a resource server, and a valid session token is sent
- **THEN** the signed bearer authenticates it, and no source is consulted

#### Scenario: Type compared without regard to case
- **WHEN** a provider JWT access token typed `application/AT+JWT` is sent to a covered route
- **THEN** it is routed to the provider source and accepted

### Requirement: A token is bounded in size before it is read
The whole token SHALL be bounded in size before any part of it is decoded for routing or verification, and a token over the bound SHALL be refused as an invalid token. The bound SHALL be no smaller than the largest token the chain's own provider can issue, so that a token UserInfo accepts is never refused for its size.

#### Scenario: Oversized token
- **WHEN** a token of 64 KiB whose header claims `at+jwt` is sent
- **THEN** it is refused as an invalid token without its payload being decoded

### Requirement: A recognised access token that is refused is not handed on
A token a resource server recognised and refused SHALL be refused, and SHALL never be handed to another credential mode of the chain.

#### Scenario: Refused provider token not retried
- **WHEN** an expired provider access token is sent on a chain that also runs signed bearer tokens
- **THEN** it is refused as an invalid token, and the signed bearer never judges it

#### Scenario: Unknown issuer
- **WHEN** a JWT typed `at+jwt` from an issuer no source names is sent to a covered route
- **THEN** it is refused as an invalid token

### Requirement: The audience must name the resource
A token SHALL be accepted only when its audience contains the resource identifier, one of its aliases, or the audience configured for the source that verified it. Aliases SHALL apply to every source of the resource server; a source's audience SHALL apply to that source alone and MAY be any non-empty text other than that source's issuer. A token whose audience is only an issuer SHALL be refused.

#### Scenario: Issuer-only audience
- **WHEN** a provider access token whose audience is only the issuer is sent to a resource server for `urn:example:orders:api`
- **THEN** it is refused as an invalid token

#### Scenario: Renamed API
- **WHEN** a resource server for `urn:orders` with the alias `https://orders.old.example` receives a valid token whose audience is `https://orders.old.example`
- **THEN** the token is accepted

#### Scenario: An issuer's own spelling
- **WHEN** a remote-issuer source is configured with the audience `orders-api`, and that issuer's token names only `orders-api`
- **THEN** the token is accepted, and a token from another source naming only `orders-api` is refused

#### Scenario: Source audience equal to its issuer
- **WHEN** a remote-issuer source for `https://sso.example` is configured with the audience `https://sso.example`
- **THEN** construction fails with a configuration error

### Requirement: Access tokens must be explicitly typed by default
By default a JWT access token SHALL be accepted only when typed `at+jwt`. A source MAY opt in to tokens typed `JWT`, but only together with a named claim and the value it must hold, so that an ID token of the same issuer stays refused.

#### Scenario: Untyped token by default
- **WHEN** a remote issuer's access token typed `JWT` is sent to a source with default settings
- **THEN** it is refused as an invalid token

#### Scenario: Opted in with a telling claim
- **WHEN** the source opts in to tokens typed `JWT` whose claim `typ` is `Bearer`, and an access token with that claim is sent
- **THEN** it is accepted, and that issuer's ID token, whose `typ` claim is `ID`, is refused

#### Scenario: Opt-in without a claim
- **WHEN** a source opts in to tokens typed `JWT` naming no claim
- **THEN** construction fails with a configuration error

### Requirement: An external JWT access token carries the claims the profile requires
A remote-issuer source SHALL refuse a JWT access token that lacks `iss`, `exp`, `aud`, `sub`, `iat` or `client_id`, has an empty `sub`, has an `iat` or `nbf` later than now plus the larger of the source's clock skew and 60 seconds, or, when typed `at+jwt`, lacks `jti`. A source opted in to tokens typed `JWT` MAY take the client from `azp` when `client_id` is absent.

#### Scenario: Missing subject
- **WHEN** a verified `at+jwt` from a remote issuer has no `sub`
- **THEN** it is refused as an invalid token

#### Scenario: Client named in azp
- **WHEN** a source that accepts tokens typed `JWT` verifies one naming its client in `azp` only
- **THEN** the token is accepted, and its client is that value, while an `at+jwt` naming its client in `azp` only is refused

#### Scenario: Issuer clock slightly ahead
- **WHEN** a token's `iat` is 30 seconds ahead and the source's clock skew is zero
- **THEN** it is accepted

#### Scenario: Issued in the future
- **WHEN** a token's `iat` is two minutes ahead and the source's clock skew is zero
- **THEN** it is refused as an invalid token

#### Scenario: Consumer allows clock skew
- **WHEN** the same source is configured with a three-minute clock skew
- **THEN** the token is accepted

### Requirement: Access tokens must be bound by default
Every source SHALL by default refuse an access token that is not bound to a key or certificate. A bound token SHALL be accepted only with a valid proof of possession for its key, or over a connection with its certificate. A source MAY opt out and accept unbound tokens; the opt-out SHALL apply to that source alone, and SHALL be a configuration error on a chain that requires DPoP.

#### Scenario: Unbound token refused
- **WHEN** a source with default settings verifies a valid token that carries no confirmation
- **THEN** it is refused as an invalid token

#### Scenario: Consumer opts out for one source
- **WHEN** a remote-issuer source opts out, and its valid unbound token is sent under `Bearer`
- **THEN** the token is accepted, and an unbound token of the provider source on the same resource server is still refused

#### Scenario: Confirmation the chain cannot check
- **WHEN** a token's confirmation names only a method the chain does not support, from a source that accepts unbound tokens
- **THEN** it is refused as an invalid token, never treated as unbound

#### Scenario: Unbound token under the DPoP scheme
- **WHEN** an unbound token from a source that opted out is presented under the `DPoP` scheme
- **THEN** it is refused with the invalid-DPoP-proof refusal

#### Scenario: Opt-out on a chain that requires DPoP
- **WHEN** a source opts out of binding on a chain whose DPoP is required
- **THEN** construction fails with a configuration error naming both settings

### Requirement: Binding failures are answered as the sender-constrained-token rules define
A resource server SHALL answer a failed binding with the refusals the sender-constrained-tokens capability defines: the invalid-DPoP-proof refusal for a bound token under `Bearer`, without a proof, or with a failing proof; the nonce-required refusal, with a fresh nonce, for a missing required nonce; the certificate-binding refusal for a missing certificate. One replay store SHALL serve the resource server and the provider's endpoints.

#### Scenario: Bound token under Bearer
- **WHEN** a token bound to a DPoP key is sent under `Bearer` with no proof
- **THEN** it is refused with the invalid-DPoP-proof refusal, and no caller is published

#### Scenario: Server nonce required
- **WHEN** the chain's DPoP requires server nonces, and a bound token arrives with a proof carrying no nonce
- **THEN** it is refused with the nonce-required refusal, and the response carries a fresh `DPoP-Nonce`

#### Scenario: Certificate-bound token without its certificate
- **WHEN** a token bound to a certificate is sent over a connection presenting another certificate
- **THEN** it is refused with the certificate-binding refusal

### Requirement: The provider source checks the grant on every request
A provider source SHALL verify each token with the provider, so that a token whose grant has been revoked, has expired, or names another client or user is refused on the next request after that, whether the token is a JWT or opaque.

#### Scenario: Grant revoked
- **WHEN** a provider access token is accepted, its grant is then revoked, and the same token is sent again before it expires
- **THEN** the second request is refused as an invalid token

#### Scenario: Opaque token
- **WHEN** the provider issues opaque access tokens and one is sent to a covered route
- **THEN** it is verified through the provider's store and accepted

### Requirement: A remote issuer's tokens are verified against its published keys
A remote-issuer source SHALL verify a JWT against the key set its issuer publishes, pinned to that issuer, and SHALL refuse a token signed with no algorithm, a symmetric algorithm, an algorithm outside the source's list, or a key the set does not hold. It SHALL ignore `jku`, `jwk` and `x5u` headers and keys not meant for signing. The key set SHALL be cached and refetched at most once per cooldown for an unknown key identifier.

#### Scenario: Keys rotated
- **WHEN** the issuer starts signing with a new key, and the first token under it arrives
- **THEN** the key set is refetched once and the token is accepted

#### Scenario: Unknown key flood
- **WHEN** many tokens naming unknown key identifiers arrive within the cooldown
- **THEN** at most one refetch is made, and the tokens are refused as invalid

#### Scenario: Unsigned token
- **WHEN** a token with algorithm `none` claiming the issuer is sent
- **THEN** it is refused as an invalid token

#### Scenario: Token without a key identifier
- **WHEN** a token carries no `kid` and the issuer's set holds two signing keys
- **THEN** it is refused as an invalid token, and with one signing key in the set it is verified against that key

#### Scenario: Consumer narrows the algorithms
- **WHEN** a source accepts only `ES256` and a valid token signed with `RS256` arrives
- **THEN** it is refused as an invalid token

#### Scenario: Embedded key ignored
- **WHEN** a token carries a `jwk` header holding the key that signed it, and the issuer's key set does not hold that key
- **THEN** it is refused as an invalid token

### Requirement: A remote issuer's key set is found only where the issuer says
A remote-issuer source SHALL find the key set from the issuer's metadata, and SHALL refuse metadata whose `issuer` is not the configured issuer. A discovered key-set URL SHALL be on the issuer's own origin. A consumer MAY instead give the key-set URL explicitly, which SHALL be https and MAY be on another origin. Every fetch SHALL go through the library's confined outbound client, which the consumer MAY replace.

#### Scenario: Discovered key set on another origin
- **WHEN** the issuer's metadata names a key-set URL on another origin
- **THEN** no key set is fetched from it, and the request fails as a dependency failure

#### Scenario: Consumer supplies the outbound client
- **WHEN** a source is given an outbound client that routes through a proxy
- **THEN** every metadata and key-set fetch goes through that client

#### Scenario: Consumer pins the key set
- **WHEN** a source for `https://accounts.example` is given the key-set URL `https://keys.example/certs`
- **THEN** keys are fetched from that URL and no metadata is read

#### Scenario: Metadata for another issuer
- **WHEN** the metadata fetched for `https://sso.example` states the issuer `https://evil.example`
- **THEN** no key set is fetched, and the request fails as a dependency failure

### Requirement: A verified JWT is valid until it expires unless the source introspects it
By default a JWT a remote-issuer source verifies SHALL be accepted until its expiry, whatever happens at the issuer meanwhile. A source MAY opt in to introspecting every JWT it verifies, and SHALL then refuse one the introspection endpoint reports inactive.

#### Scenario: Default
- **WHEN** an issuer revokes a JWT that has not expired, and it is sent to a source with default settings
- **THEN** it is accepted

#### Scenario: Consumer opts in to introspection
- **WHEN** the same source introspects every JWT, and the endpoint reports that token inactive
- **THEN** it is refused as an invalid token

### Requirement: An introspection source accepts only an active access token for its resource
An introspection source SHALL be built with the issuer it trusts and SHALL send each token it claims to the configured RFC 7662 endpoint, authenticated as the configured client. It SHALL accept a token only when reported active, with a token type absent or naming an access token, an issuer absent or equal to its own, an audience naming the resource, a subject, and a future expiry. By default it SHALL cache no answer.

#### Scenario: Inactive token
- **WHEN** the endpoint reports a token inactive
- **THEN** it is refused as an invalid token

#### Scenario: A refresh token reported active
- **WHEN** the endpoint reports a token active with the token type `refresh_token`
- **THEN** it is refused as an invalid token

#### Scenario: Another issuer in the answer
- **WHEN** an endpoint built for `https://sso.example` reports a token active with the issuer `https://other.example`
- **THEN** it is refused as an invalid token

#### Scenario: No audience in the answer
- **WHEN** the endpoint reports a token active with no audience
- **THEN** it is refused as an invalid token

### Requirement: Introspection answers are cached only within bounds
A consumer MAY enable a cache of introspection answers, bounded in time and in entries, held per source, keyed by a digest of the token and never the token itself. An answer SHALL never be kept beyond its token's expiry or the configured bound, and an answer with no expiry SHALL NOT be cached. Concurrent requests carrying one token SHALL share one introspection call.

#### Scenario: Cache bounded by expiry
- **WHEN** a 60-second cache is enabled and a token expiring in 10 seconds is reported active
- **THEN** the answer is not reused after the token's expiry

#### Scenario: Concurrent requests
- **WHEN** ten requests carrying the same uncached token arrive together
- **THEN** one introspection call is made

### Requirement: The chain provider's own tokens are never sent to an introspection endpoint
A token in a format the chain's own provider issues (its opaque access tokens and refresh tokens) SHALL never be sent to an introspection source. On a path whose resource server has no provider source, such a token SHALL be refused as an invalid token.

#### Scenario: Provider refresh token at a partner API
- **WHEN** a chain runs a provider issuing opaque tokens and a resource server under `/partner/` whose only source is an introspection source, and the provider's refresh token is sent to `/partner/x`
- **THEN** it is refused as an invalid token, and the partner's endpoint receives nothing

### Requirement: Other credentials are never sent to an introspection endpoint
When the chain runs any other credential mode that reads the `Bearer` scheme, such as session-reference bearers or API keys under that scheme, an introspection source SHALL claim opaque tokens only by a prefix it is given. Building such a chain with an introspection source and no prefix SHALL fail with a configuration error.

#### Scenario: Missing prefix
- **WHEN** a chain enables session-reference bearers and an introspection source without a prefix
- **THEN** construction fails with a configuration error naming both

#### Scenario: API keys under the Bearer scheme
- **WHEN** a chain reads API keys under the `Bearer` scheme and enables an introspection source without a prefix
- **THEN** construction fails with a configuration error naming both

#### Scenario: Prefix given
- **WHEN** the source is given the prefix `kc_`, and a session reference is sent
- **THEN** the session-reference bearer judges it, and the endpoint receives nothing

### Requirement: Refused access tokens are throttled per source
A resource server SHALL count verification refusals (signature, type, audience, claims, expiry, an inactive or unknown token) per client address and source, through the chain's limiter factory under the namespace `resource-server` with its IPv6 aggregate, and refuse a throttled address as an invalid token before any verification or call. Binding, nonce, assurance and dependency failures SHALL NOT count. The limiter SHALL be replaceable.

#### Scenario: Flood of invalid opaque tokens
- **WHEN** one address sends invalid opaque tokens to an introspection source past the limit
- **THEN** further requests are refused as invalid tokens, answered 401, and no introspection call is made for them

#### Scenario: Nonce challenges do not count
- **WHEN** a client behind one address is answered with a server-nonce challenge on every first request
- **THEN** those answers are not counted, and the client is never throttled for them

#### Scenario: Consumer replaces the limiter
- **WHEN** a consumer gives the resource server a limiter allowing 1000 refusals a minute
- **THEN** that limiter decides, and the chain's default does not

### Requirement: A source's caller strategy decides who the caller is
Each source SHALL resolve the caller by one strategy: claims only (subject and scopes from the token, no roles); a claims mapper (a consumer function given the verified claims); local user (provider source only, the subject's user loaded each request); or linked user (other sources only, the user found through the identity links). A loaded user SHALL exist and be active, with its current roles. The provider source SHALL default to local user, the others to claims only.

#### Scenario: Role removed
- **WHEN** a provider token was issued while its user held `admin`, the role is then removed, and the token is sent again
- **THEN** the caller does not hold `admin`

#### Scenario: Claims only by default
- **WHEN** a remote-issuer token from `https://sso.example` with subject `42` and scope `orders:read` is accepted by a source with default settings
- **THEN** the caller carries scope `orders:read` and no role, and its identifier is not `42`

#### Scenario: Consumer mapper
- **WHEN** the source is given a mapper that turns the claim `groups: [ops]` into the role `operator`
- **THEN** the caller holds `operator`

#### Scenario: Local user inactive
- **WHEN** a local-user source loads a user who is inactive
- **THEN** the request is refused as an invalid token

### Requirement: A claims mapper's caller is a local user unless declared external
A claims mapper SHALL be built with a provider name and SHALL return, with its caller, whether that caller is external. A caller not declared external SHALL be treated as a local user and judged by the MFA requirement policy through the federated-assurance mode from the token's evidence, under that provider name; one declared external SHALL name no local user.

#### Scenario: Mapper names a local administrator
- **WHEN** a mapper turns an external token into local user `u-7`, and `u-7` is required to use MFA while the token asserts `amr` `["pwd"]`
- **THEN** the request is refused with the insufficient-user-authentication refusal

#### Scenario: Mapper declares an external caller
- **WHEN** a mapper returns a service principal declared external
- **THEN** the MFA requirement is not looked up for it

### Requirement: A source's issuer is an https URL without a query or fragment
A remote-issuer or introspection source's issuer SHALL be an absolute https URL with no query and no fragment, so that it is one issuer identifier and its qualified caller identifiers cannot collide. Any other issuer SHALL fail construction.

#### Scenario: Issuer with a fragment
- **WHEN** a remote-issuer source is built for `https://sso.example#x`
- **THEN** construction fails with a configuration error naming the issuer

### Requirement: A claims-only caller never carries a local user's identifier
A claims-only caller's identifier SHALL be its issuer and subject together, so that it never equals a local user's identifier or another issuer's subject.

#### Scenario: Qualified identifier
- **WHEN** two issuers each send a token with subject `42` to sources with default settings
- **THEN** the two callers have different identifiers, neither of them `42`

### Requirement: An external token's subject is never a local user identifier
For a remote-issuer or introspection source, the linked-user strategy SHALL find the user only by the identity link keyed by the source's provider name, the token's issuer and its subject, and SHALL refuse an unlinked subject. No strategy of those sources SHALL load a local user by the token's subject.

#### Scenario: Subject equal to a local user identifier
- **WHEN** a remote issuer's token has the subject `42`, local user `42` exists, and the source uses the linked-user strategy with no link for that subject
- **THEN** the request is refused as an invalid token, and local user `42` is never loaded

#### Scenario: Linked subject
- **WHEN** the same subject is linked for that source's provider and issuer to user `u-7`
- **THEN** the caller is `u-7` with its current roles

### Requirement: Scopes come from the token in either of its usual forms
A source SHALL read the token's scopes from `scope`, a space-separated string, or, when `scope` is absent, from `scp`, as a string or an array. The published scopes SHALL be the token's, whatever the caller strategy returned.

#### Scenario: scp as an array
- **WHEN** a token carries `scp: ["orders:read", "orders:write"]` and no `scope`
- **THEN** the caller carries both scopes

#### Scenario: Mapper cannot widen scopes
- **WHEN** a mapper returns a principal carrying the scope `admin:all` for a token granted `orders:read`
- **THEN** the caller carries `orders:read` only

### Requirement: The accepted token is published for the request
For an accepted token the chain SHALL publish a caller whose principal carries the token's scopes and whose first factor is `access-token` for the provider source and `external-access-token` for the other sources, and SHALL expose the token's issuer, subject, client, audience, scopes, issue and expiry times, authentication time, authentication context and methods to the request's handlers, with the token's claims for the remote-issuer and introspection sources. Each read SHALL return a copy.

#### Scenario: Handler reads the token
- **WHEN** a handler behind a resource server reads the accepted token
- **THEN** it finds the client `web-app` and the scopes the token was granted

#### Scenario: Factor kinds
- **WHEN** a provider token and a remote issuer's token are each accepted
- **THEN** the first callers' factor is `access-token` and the second's `external-access-token`

#### Scenario: Copy on read
- **WHEN** a handler changes the scopes of the token it read and reads it again
- **THEN** the second read shows the original scopes

### Requirement: Failures of a source's dependencies are not refusals
A provider store, key set, metadata, introspection endpoint, user loader, link store, claims mapper, MFA requirement lookup, federated-assurance source or refusal limiter that fails SHALL fail the request as a dependency failure, never counted against the throttle, not refuse the token, and SHALL NOT be retried within the request. A request whose own context ends during verification SHALL fail with that context's error.

#### Scenario: Key set unreachable
- **WHEN** a remote issuer's key set cannot be fetched and no cached set holds the token's key
- **THEN** the request fails as a dependency failure, answered 500 by default, and is not answered as an invalid token

#### Scenario: Introspection endpoint down
- **WHEN** the introspection endpoint answers 503
- **THEN** the request fails as a dependency failure

#### Scenario: Caller hangs up
- **WHEN** the request's context is cancelled while a key set is fetched
- **THEN** the request fails with the context's error, and no error-level record is written

### Requirement: Resource-server wiring mistakes fail at construction
Building a chain SHALL fail with a configuration error naming the mistake when a resource server has: no source, or a nil source; an identifier or alias that is not an absolute URI, or equals the provider's issuer; a duplicate alias; an invalid prefix; two sources for one issuer; binding required with neither DPoP nor certificate binding, or a binding opt-out on a chain that requires DPoP; or when the chain's session token type would be recognised as an access token.

#### Scenario: Identifier equal to the issuer
- **WHEN** a resource server's identifier is the chain provider's issuer
- **THEN** construction fails with a configuration error

#### Scenario: Binding with nothing to check it
- **WHEN** a resource server with default binding is enabled on a chain without DPoP or certificate binding
- **THEN** construction fails with a configuration error naming the binding

#### Scenario: Two sources for one issuer in one resource server
- **WHEN** one resource server is given two remote-issuer sources naming the same issuer
- **THEN** construction fails with a configuration error

#### Scenario: Session token type that looks like an access token
- **WHEN** the chain's session token generator declares the type `AT+JWT` and a resource server is enabled
- **THEN** construction fails with a configuration error naming the type

### Requirement: Source wiring mistakes fail at construction
Building a chain SHALL fail with a configuration error naming the mistake when a source has: an empty audience or one equal to its issuer; an issuer equal to the identifier or an alias; a provider not the chain's; two caller strategies; a nil mapper, user loader or link store; a mapper on the provider source; local user on another source; a clock skew above five minutes; no algorithm or a symmetric one; a non-positive cache bound; a nil refusal limiter; or a plain-http introspection endpoint.

#### Scenario: Mapper on the provider source
- **WHEN** a provider source is given a claims mapper
- **THEN** construction fails with a configuration error

#### Scenario: Local user on a remote issuer
- **WHEN** a remote-issuer source is given the local-user strategy
- **THEN** construction fails with a configuration error naming the linked-user strategy

#### Scenario: Plain-http introspection endpoint
- **WHEN** an introspection source is built with `http://idp.example/introspect`
- **THEN** construction fails with a configuration error

### Requirement: Tokens never reach logs or errors
No log record, error text or event produced while judging an access token SHALL contain the token, a key, a client secret or an introspection response body.

#### Scenario: Refused token logged
- **WHEN** a token is refused and the refusal is logged at debug level
- **THEN** the record names a fixed reason and not the token
