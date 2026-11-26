## ADDED Requirements

### Requirement: A provider source can trust a provider another chain serves
A provider source SHALL be able to trust a provider that the chain does not run, so that one binary can serve the provider on a cookie chain and its API on a token chain. When the chain runs a provider, a provider source SHALL trust only that provider. Every check the provider source makes on a token SHALL be the same whichever chain serves the provider.

#### Scenario: Provider on the cookie chain, API on the token chain
- **WHEN** one binary runs the provider on a cookie chain and, under `/api`, a token chain whose resource server trusts that provider through a provider source, and a client sends a bound access token the provider issued for the resource to `/api/orders`
- **THEN** the token is verified by the provider, and the caller is the local user it names

#### Scenario: Grant revoked, token checked on the other chain
- **WHEN** such a token is accepted on the token chain, its grant is then revoked through the provider, and the same token is sent again before it expires
- **THEN** the second request is refused as an invalid token

#### Scenario: Another provider than the chain's
- **WHEN** a chain runs one provider and its resource server's provider source is given a different provider
- **THEN** construction fails with a configuration error

### Requirement: Rules naming the chain's provider apply to a trusted provider
Every rule that names the chain's provider SHALL also apply to the provider a provider source on the chain trusts: the size bound, the identifier and issuer checks, and the routing of the provider's own token formats.

#### Scenario: Remote-issuer source naming the trusted provider's issuer
- **WHEN** a resource server on a chain without a provider has a provider source and a remote-issuer source naming that provider's issuer
- **THEN** construction fails with a configuration error

#### Scenario: Large provider token on the other chain
- **WHEN** the provider can issue access tokens larger than the resource server's default bound, and one is sent to the token chain
- **THEN** it is not refused for its size

## MODIFIED Requirements

### Requirement: A token is bounded in size before it is read
The whole token SHALL be bounded in size before any part of it is decoded for routing or verification, and a token over the bound SHALL be refused as an invalid token. The bound SHALL be no smaller than the largest token the chain's own provider, or a provider a provider source on the chain trusts, can issue, so that a token UserInfo accepts is never refused for its size.

#### Scenario: Oversized token
- **WHEN** a token of 64 KiB whose header claims `at+jwt` is sent
- **THEN** it is refused as an invalid token without its payload being decoded

### Requirement: The chain provider's own tokens are never sent to an introspection endpoint
A token in a format the chain's own provider, or a provider a provider source on the chain trusts, issues (its opaque access tokens and refresh tokens) SHALL never be sent to an introspection source. On a path whose resource server has no provider source, such a token SHALL be refused as an invalid token.

#### Scenario: Provider refresh token at a partner API
- **WHEN** a chain runs a provider issuing opaque tokens and a resource server under `/partner/` whose only source is an introspection source, and the provider's refresh token is sent to `/partner/x`
- **THEN** it is refused as an invalid token, and the partner's endpoint receives nothing

### Requirement: Resource-server wiring mistakes fail at construction
Building a chain SHALL fail with a configuration error naming the mistake when a resource server has: no source, or a nil source; an identifier or alias that is not an absolute URI, or equals the issuer of the chain's provider or of a provider a provider source trusts; a duplicate alias; an invalid prefix; two sources for one issuer; binding required with neither DPoP nor certificate binding, or a binding opt-out on a chain that requires DPoP; or when the chain's session token type would be recognised as an access token.

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
Building a chain SHALL fail with a configuration error naming the mistake when a source has: an empty audience or one equal to its issuer; an issuer equal to the identifier or an alias; a nil provider, a provider other than the chain's when the chain runs one, a second provider source in one resource server, or a provider whose token binding the chain cannot check; two caller strategies; a nil mapper, user loader or link store; a mapper on the provider source; local user on another source; a clock skew above five minutes; no algorithm or a symmetric one; a non-positive cache bound; a nil refusal limiter; or a plain-http introspection endpoint.

#### Scenario: Mapper on the provider source
- **WHEN** a provider source is given a claims mapper
- **THEN** construction fails with a configuration error

#### Scenario: Local user on a remote issuer
- **WHEN** a remote-issuer source is given the local-user strategy
- **THEN** construction fails with a configuration error naming the linked-user strategy

#### Scenario: Two provider sources in one resource server
- **WHEN** a resource server on a chain without a provider is given two provider sources naming different providers
- **THEN** construction fails with a configuration error

#### Scenario: Binding the token chain cannot check
- **WHEN** a provider binds its access tokens to DPoP and a chain that enables only certificate binding trusts it through a provider source
- **THEN** construction fails with a configuration error naming the binding

#### Scenario: Plain-http introspection endpoint
- **WHEN** an introspection source is built with `http://idp.example/introspect`
- **THEN** construction fails with a configuration error
