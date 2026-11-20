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
