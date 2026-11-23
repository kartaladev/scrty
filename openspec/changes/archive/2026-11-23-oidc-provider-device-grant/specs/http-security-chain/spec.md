## MODIFIED Requirements

### Requirement: The OpenID Provider's endpoints plug into the chain
When enabled, the provider SHALL answer on the chain under a prefix, `/oauth2` by default, with these paths:
- authorization `/authorize` and resume `/authorize/resume`;
- token `/token`, UserInfo `/userinfo`, revocation `/revoke`, introspection `/introspect`;
- end-session `/logout`, its confirmation `/logout/confirm`, and the user's consents `/consents`;
- when the provider has enabled the device grant, device authorization `/device-authorization` and code entry `/device`.

A request on any other path SHALL pass through.

#### Scenario: Other path
- **WHEN** the provider is enabled and a request arrives for `/api/orders`
- **THEN** it passes through to the next interceptor

#### Scenario: Device endpoints with the grant enabled
- **WHEN** the provider has enabled the device grant, with default paths
- **THEN** the chain answers device authorization at `/oauth2/device-authorization` and code entry at `/oauth2/device`, and lists both among its endpoints

#### Scenario: Device endpoints without the grant
- **WHEN** the provider has not enabled the device grant
- **THEN** a request for `/oauth2/device-authorization` passes through, and neither path is listed among the chain's endpoints

## ADDED Requirements

### Requirement: Failed client authentications at the device authorization endpoint are throttled per source
The device authorization endpoint SHALL charge failed client authentications to the source, under the token endpoint's default of 10 failures per source in 15 minutes, in its own limiter namespace. A throttled source SHALL be refused as `invalid_client` without the client being authenticated. A consumer MAY replace the limiter.

#### Scenario: The eleventh failure
- **WHEN** one source fails client authentication at the device authorization endpoint 10 times within 15 minutes, then sends a valid request
- **THEN** the request is refused as `invalid_client`

#### Scenario: Throttles are separate per endpoint
- **WHEN** a source has exhausted the device authorization endpoint's budget
- **THEN** its requests to the token endpoint are judged by the token endpoint's own budget

### Requirement: The code-entry endpoint passes the source to the provider's throttle
The code-entry endpoint SHALL hand the provider the request's source as the chain resolves it, trusted proxies included, so that the provider's throttle on failed user-code entries counts per real source.

#### Scenario: Behind a trusted proxy
- **WHEN** code entries arrive through a trusted proxy carrying different client addresses
- **THEN** each address is throttled on its own

#### Scenario: The chain's IPv6 source prefix applies to code entry
- **WHEN** the chain is configured to key IPv6 sources by a /48 prefix, and failed entries arrive from two addresses in one /48
- **THEN** the provider's entry throttle counts them as one source

### Requirement: The chain shares its limiter factory with the provider's entry throttle
When the consumer configured a rate-limiter factory on the chain and gave the provider no entry limiter of its own, the chain SHALL hand the provider that factory under the namespace `oidc-device-entry`, together with the way the chain keys sources. The provider SHALL accept a later hand-over of the same factory, namespace and source keying, and SHALL refuse a different one as a configuration error, so the counts are never split.

#### Scenario: Two chains over one provider share a durable factory
- **WHEN** two chains over one provider are built with the same durable rate-limiter factory
- **THEN** both are built, and entries through either are counted together

#### Scenario: Two chains with different factories
- **WHEN** a second chain over the same provider is built with a different rate-limiter factory
- **THEN** building it fails with a configuration error

#### Scenario: The consumer's own entry limiter
- **WHEN** the consumer gave the provider its own entry limiter
- **THEN** the chain's factory is never asked for one
