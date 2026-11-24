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

### Requirement: An access token on a path no resource server covers is refused
An access token the chain recognises, presented on a path no resource server covers and that no endpoint of the chain answers itself, SHALL be refused as an invalid token and SHALL NOT be offered to any other credential mode.

#### Scenario: Token outside every prefix
- **WHEN** the only resource server covers `/api/`, and a provider access token is sent to `/admin/report`
- **THEN** the request is refused as an invalid token

#### Scenario: The provider's own endpoints
- **WHEN** the same token is sent to the provider's UserInfo endpoint
- **THEN** UserInfo judges it, as before

### Requirement: Access tokens are recognised by shape and routed to one source
A resource server SHALL recognise a token as an access token when it is the provider's opaque access token, a JWT typed `at+jwt` (without regard to case, an `application/` prefix ignored), a JWT whose issuer is a configured source's, or an opaque token an introspection source claims, and SHALL route it to the one source that matches. A session token and a session reference SHALL never be offered to a source.

#### Scenario: Session token beside a resource server
- **WHEN** a chain runs signed bearer tokens and a resource server, and a valid session token is sent
- **THEN** the signed bearer authenticates it, and no source is consulted

### Requirement: A recognised access token that is refused is not handed on
A token a resource server recognised and refused SHALL be refused as an invalid token, and SHALL never be handed to another credential mode of the chain.

#### Scenario: Refused provider token not retried
- **WHEN** an expired provider access token is sent on that chain
- **THEN** it is refused as an invalid token, and the signed bearer never judges it

#### Scenario: Unknown issuer
- **WHEN** a JWT typed `at+jwt` from an issuer no source names is sent to a covered route
- **THEN** it is refused as an invalid token

### Requirement: The audience must name the resource
A token SHALL be accepted only when its audience contains the resource identifier, one of its aliases, or the audience configured for the source that verified it. Aliases SHALL apply to every source; a source's audience SHALL apply to that source alone and MAY be any non-empty text. A token whose audience is only the provider's issuer SHALL be refused.

#### Scenario: Issuer-only audience
- **WHEN** a provider access token whose audience is only the issuer is sent to a resource server for `urn:example:orders:api`
- **THEN** it is refused as an invalid token

#### Scenario: Renamed API
- **WHEN** a resource server for `urn:orders` with the alias `https://orders.old.example` receives a valid token whose audience is `https://orders.old.example`
- **THEN** the token is accepted

#### Scenario: An issuer's own spelling
- **WHEN** a remote-issuer source is configured with the audience `orders-api`, and that issuer's token names only `orders-api`
- **THEN** the token is accepted, and a token from another source naming only `orders-api` is refused

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

### Requirement: Access tokens must be bound by default
Every source SHALL by default refuse an access token that is not bound to a key or certificate. A bound token SHALL be accepted only with a valid proof of possession for its key, or over a connection with its certificate. A source MAY opt out and accept unbound tokens; the opt-out SHALL apply to that source alone.

#### Scenario: Unbound token refused
- **WHEN** a source with default settings verifies a valid token that carries no confirmation
- **THEN** it is refused as an invalid token

#### Scenario: Consumer opts out for one source
- **WHEN** a remote-issuer source opts out, and its valid unbound token is sent under `Bearer`
- **THEN** the token is accepted, and an unbound token of the provider source on the same resource server is still refused

#### Scenario: Bound token without a proof
- **WHEN** a token bound to a DPoP key is sent under `Bearer` with no proof
- **THEN** it is refused, and no caller is published

### Requirement: The provider source checks the grant on every request
A provider source SHALL verify each token with the provider, so that a token whose grant has been revoked, has expired, or names another client or user is refused on the next request after that, whether the token is a JWT or opaque.

#### Scenario: Grant revoked
- **WHEN** a provider access token is accepted, its grant is then revoked, and the same token is sent again before it expires
- **THEN** the second request is refused as an invalid token

#### Scenario: Opaque token
- **WHEN** the provider issues opaque access tokens and one is sent to a covered route
- **THEN** it is verified through the provider's store and accepted

### Requirement: A remote issuer's tokens are verified against its published keys
A remote-issuer source SHALL verify a JWT against the key set its issuer publishes, pinned to that issuer, and SHALL refuse a token signed with no algorithm, with a symmetric algorithm, or by a key the set does not hold. It SHALL cache the key set, refetch it at most once per cooldown for an unknown key identifier, and fetch only from the issuer's own origin.

#### Scenario: Keys rotated
- **WHEN** the issuer starts signing with a new key, and the first token under it arrives
- **THEN** the key set is refetched once and the token is accepted

#### Scenario: Unknown key flood
- **WHEN** many tokens naming unknown key identifiers arrive within the cooldown
- **THEN** at most one refetch is made, and the tokens are refused as invalid

#### Scenario: Unsigned token
- **WHEN** a token with algorithm `none` claiming the issuer is sent
- **THEN** it is refused as an invalid token

### Requirement: A verified JWT is valid until it expires unless the source introspects it
By default a JWT a remote-issuer source verifies SHALL be accepted until its expiry, whatever happens at the issuer meanwhile. A source MAY opt in to introspecting every JWT it verifies, and SHALL then refuse one the introspection endpoint reports inactive.

#### Scenario: Default
- **WHEN** an issuer revokes a JWT that has not expired, and it is sent to a source with default settings
- **THEN** it is accepted

#### Scenario: Consumer opts in to introspection
- **WHEN** the same source introspects every JWT, and the endpoint reports that token inactive
- **THEN** it is refused as an invalid token

### Requirement: An introspection source asks the issuer about each token
An introspection source SHALL send each token it claims to the configured RFC 7662 endpoint, authenticated as the configured client, and SHALL accept it only when reported active. By default it SHALL cache no answer. A consumer MAY enable a cache, which SHALL never keep an answer beyond its token's expiry or the configured bound.

#### Scenario: Inactive token
- **WHEN** the endpoint reports a token inactive
- **THEN** it is refused as an invalid token

#### Scenario: Cache bounded by expiry
- **WHEN** a 60-second cache is enabled and a token expiring in 10 seconds is reported active
- **THEN** the answer is not reused after the token's expiry

### Requirement: Session references are never sent to an introspection endpoint
An introspection source SHALL claim opaque tokens only by a prefix it is given, when the chain also runs session-reference bearers. Building a chain that runs session-reference bearers and an introspection source without a prefix SHALL fail with a configuration error.

#### Scenario: Missing prefix
- **WHEN** a chain enables session-reference bearers and an introspection source without a prefix
- **THEN** construction fails with a configuration error naming both

#### Scenario: Prefix given
- **WHEN** the source is given the prefix `kc_`, and a session reference is sent
- **THEN** the session-reference bearer judges it, and the endpoint receives nothing

### Requirement: A source's caller strategy decides who the caller is
Each source SHALL resolve the caller by one strategy:
- **claims only**: subject and scopes from the token, no roles;
- **claims mapper**: a consumer function given the verified claims returns the caller;
- **local user**: the subject's user is loaded each request and must exist and be active, and its current roles are used.

The provider source SHALL default to local user; remote-issuer and introspection sources SHALL default to claims only.

#### Scenario: Role removed
- **WHEN** a provider token was issued while its user held `admin`, the role is then removed, and the token is sent again
- **THEN** the caller does not hold `admin`

#### Scenario: Claims only by default
- **WHEN** a remote-issuer token with scope `orders:read` is accepted by a source with default settings
- **THEN** the caller carries scope `orders:read` and no role

#### Scenario: Consumer mapper
- **WHEN** the source is given a mapper that turns the claim `groups: [ops]` into the role `operator`
- **THEN** the caller holds `operator`

#### Scenario: Local user inactive
- **WHEN** a local-user source loads a user who is inactive
- **THEN** the request is refused as authentication required

### Requirement: The accepted token is published for the request
For an accepted token the chain SHALL publish a caller whose principal carries the token's scopes and whose first factor is `access-token`, and SHALL expose the token's issuer, subject, client, audience, scopes, issue and expiry times, authentication time and claims to the request's handlers. Each read SHALL return a copy.

#### Scenario: Handler reads the token
- **WHEN** a handler behind a resource server reads the accepted token
- **THEN** it finds the client `web-app` and the scopes the token was granted

#### Scenario: Copy on read
- **WHEN** a handler changes the scopes of the token it read and reads it again
- **THEN** the second read shows the original scopes

### Requirement: Failures of a source's dependencies are not refusals
A provider store, key set, or introspection endpoint that cannot answer SHALL fail the request as a dependency failure, not refuse the token, and SHALL NOT be retried within the request. A request whose own context ends during verification SHALL fail with that context's error.

#### Scenario: Key set unreachable
- **WHEN** a remote issuer's key set cannot be fetched and no cached set holds the token's key
- **THEN** the request fails as a dependency failure, answered 500 by default, and is not answered as an invalid token

#### Scenario: Introspection endpoint down
- **WHEN** the introspection endpoint answers 503
- **THEN** the request fails as a dependency failure

### Requirement: Resource-server wiring mistakes fail at construction
Building a chain SHALL fail with a configuration error naming the mistake when a resource server has no source, a nil source, an identifier equal to the provider's issuer, a duplicate alias, two sources for one issuer, a source requiring binding on a chain with neither DPoP nor certificate binding, a nil mapper or user loader, a non-positive cache bound, or an introspection endpoint that is not https.

#### Scenario: Identifier equal to the issuer
- **WHEN** a resource server's identifier is the chain provider's issuer
- **THEN** construction fails with a configuration error

#### Scenario: Binding with nothing to check it
- **WHEN** a resource server with default binding is enabled on a chain without DPoP or certificate binding
- **THEN** construction fails with a configuration error naming the binding

#### Scenario: Two sources for one issuer
- **WHEN** two remote-issuer sources name the same issuer
- **THEN** construction fails with a configuration error

### Requirement: Tokens never reach logs or errors
No log record, error text or event produced while judging an access token SHALL contain the token, a key, a client secret or an introspection response body.

#### Scenario: Refused token logged
- **WHEN** a token is refused and the refusal is logged at debug level
- **THEN** the record names a fixed reason and not the token
