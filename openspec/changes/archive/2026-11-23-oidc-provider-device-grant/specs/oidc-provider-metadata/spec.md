## MODIFIED Requirements

### Requirement: The configuration states the supported features exactly
The configuration SHALL carry:
- `response_types_supported` `["code"]`, `response_modes_supported` `["query"]`, `grant_types_supported` `["authorization_code","refresh_token"]`, with `urn:ietf:params:oauth:grant-type:device_code` added when the provider has enabled the device grant, `subject_types_supported` `["public"]`;
- `id_token_signing_alg_values_supported` naming every algorithm the keys can produce, RS256 among them;
- `scopes_supported`, `claims_supported`, `token_endpoint_auth_methods_supported`, `code_challenge_methods_supported` `["S256"]`.

#### Scenario: Features listed
- **WHEN** a relying party fetches the configuration of a provider with defaults
- **THEN** `response_types_supported` is `["code"]`, `request_uri_parameter_supported` is false, and `id_token_signing_alg_values_supported` includes `RS256`

#### Scenario: Device grant enabled
- **WHEN** a relying party fetches the configuration of a provider that has enabled the device grant
- **THEN** `grant_types_supported` is `["authorization_code","refresh_token","urn:ietf:params:oauth:grant-type:device_code"]`

## ADDED Requirements

### Requirement: Metadata names the device authorization endpoint when the grant is enabled
Both metadata documents SHALL carry `device_authorization_endpoint`, the device authorization endpoint's URL at the path in use, when the provider has enabled the device grant, and SHALL NOT carry it otherwise. The code-entry endpoint SHALL NOT appear in either document.

#### Scenario: Enabled
- **WHEN** a relying party fetches the authorization server metadata of a provider that has enabled the device grant, with an issuer without a path and default paths
- **THEN** `device_authorization_endpoint` is the issuer followed by `/oauth2/device-authorization`

#### Scenario: Not enabled
- **WHEN** a relying party fetches the configuration of a provider without the device grant
- **THEN** it carries no `device_authorization_endpoint`
