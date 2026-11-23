## MODIFIED Requirements

### Requirement: The provider's endpoints follow the CORS rules of the protocol
When CORS is enabled with the provider, the CORS layer SHALL answer for the provider's token, UserInfo, revocation and introspection endpoints, and for the metadata documents, as for any other route, under the consumer's allowlist. It SHALL never add CORS headers to the authorization endpoint, the resume endpoint, the end-session endpoint or its confirmation, the device authorization endpoint or the code-entry endpoint, whatever the allowlist says.

#### Scenario: Browser client calls the token endpoint
- **WHEN** an allowed origin sends a preflight for the token endpoint
- **THEN** the preflight is allowed

#### Scenario: Cross-origin call to the resume endpoint
- **WHEN** an allowed origin sends a cross-origin request to the resume endpoint
- **THEN** the response carries no CORS headers

#### Scenario: Cross-origin call to the authorization endpoint
- **WHEN** an allowed origin sends a cross-origin request to the authorization endpoint
- **THEN** the response carries no CORS headers

#### Scenario: Cross-origin call to the device endpoints
- **WHEN** an allowed origin sends a cross-origin request to the device authorization endpoint or the code-entry endpoint
- **THEN** the response carries no CORS headers
