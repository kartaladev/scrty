# Spec Delta

## ADDED Requirements

### Requirement: The provider's endpoints follow the CORS rules of the protocol
When CORS is enabled with the provider, the CORS layer SHALL answer for the provider's token, UserInfo, revocation and introspection endpoints, and for the metadata documents, as for any other route, under the consumer's allowlist. It SHALL never add CORS headers to the authorization endpoint, the resume endpoint, the end-session endpoint or its confirmation, whatever the allowlist says.

#### Scenario: Browser client calls the token endpoint
- **WHEN** an allowed origin sends a preflight for the token endpoint
- **THEN** the preflight is allowed

#### Scenario: Cross-origin call to the resume endpoint
- **WHEN** an allowed origin sends a cross-origin request to the resume endpoint
- **THEN** the response carries no CORS headers

#### Scenario: Cross-origin call to the authorization endpoint
- **WHEN** an allowed origin sends a cross-origin request to the authorization endpoint
- **THEN** the response carries no CORS headers

### Requirement: Browser clients can use DPoP at the provider's endpoints
On the endpoints the CORS layer answers for, it SHALL by default allow the `Authorization` and `DPoP` request headers, and SHALL expose `DPoP-Nonce` and `WWW-Authenticate`. A consumer who turns off the layer's automatic headers states these itself. It SHALL never allow credentials there, whatever the consumer's policy says. The provider's consent-management endpoint is an application route, and SHALL follow the consumer's policy unchanged.

#### Scenario: Browser client uses DPoP
- **WHEN** an allowed origin sends a preflight for the token endpoint asking for the `DPoP` header
- **THEN** the preflight allows it, and the response exposes `DPoP-Nonce`

#### Scenario: Consumer turns off the automatic headers
- **WHEN** a consumer turns off the layer's automatic headers, and its policy allows credentials
- **THEN** the token endpoint no longer gains the `DPoP` header, and credentials are still not allowed there
