# oidc-provider-metadata Specification

## Purpose
Defines the metadata the provider publishes so relying parties can discover its endpoints, keys and supported features: the OpenID Provider configuration document and the OAuth authorization server metadata document.

## Requirements

### Requirement: The issuer is an https URL without query or fragment
The provider SHALL be built with an issuer identifier that is an `https` URL with no query and no fragment. Any other value SHALL fail construction. A consumer MAY allow an `http` issuer for loopback hosts only, for local testing, and the option SHALL say it is not for production, and that the OpenID Foundation's Config OP plan refuses it.

#### Scenario: Issuer with a query
- **WHEN** the provider is built with issuer `https://id.example.com?x=1`
- **THEN** construction fails with a configuration error

#### Scenario: Loopback issuer for tests
- **WHEN** the consumer allows a loopback issuer and builds the provider with `http://127.0.0.1:8080`
- **THEN** the provider is built

### Requirement: The OpenID configuration document is published at its well-known path
The provider SHALL serve its configuration as JSON at the issuer's path followed by `/.well-known/openid-configuration`. The document's `issuer` SHALL equal the issuer identifier exactly. It SHALL list the URLs of the authorization, token, UserInfo, revocation, introspection and end-session endpoints and `jwks_uri`, each starting with the issuer's scheme and host.

#### Scenario: Discovery fetched
- **WHEN** a relying party fetches `https://id.example.com/.well-known/openid-configuration`
- **THEN** the response is 200 JSON whose `issuer` is `https://id.example.com` and whose `code_challenge_methods_supported` is `["S256"]`

#### Scenario: Issuer with a path
- **WHEN** the issuer is `https://example.com/id`
- **THEN** the configuration is served at `https://example.com/id/.well-known/openid-configuration`

### Requirement: The configuration states the supported features exactly
The configuration SHALL carry:
- `response_types_supported` `["code"]`, `response_modes_supported` `["query"]`, `grant_types_supported` `["authorization_code","refresh_token"]`, `subject_types_supported` `["public"]`;
- `id_token_signing_alg_values_supported` naming every algorithm the keys can produce, RS256 among them;
- `scopes_supported`, `claims_supported`, `token_endpoint_auth_methods_supported`, `code_challenge_methods_supported` `["S256"]`.

#### Scenario: Features listed
- **WHEN** a relying party fetches the configuration of a provider with defaults
- **THEN** `response_types_supported` is `["code"]`, `request_uri_parameter_supported` is false, and `id_token_signing_alg_values_supported` includes `RS256`

### Requirement: The configuration names its logout and client authentication details
`end_session_endpoint` SHALL be listed when logout is enabled, and `revocation_endpoint_auth_methods_supported` and `introspection_endpoint_auth_methods_supported` always, the latter without `none`. `token_endpoint_auth_signing_alg_values_supported`, and the revocation and introspection equivalents, SHALL name the assertion algorithms accepted, never `none`, when `private_key_jwt` is listed there. `offline_access` SHALL be in `scopes_supported` when any client may ask for it.

#### Scenario: Assertion algorithms listed
- **WHEN** a client may use `private_key_jwt`, and the provider accepts RS256 and ES256 assertions
- **THEN** `token_endpoint_auth_signing_alg_values_supported` is `["RS256","ES256"]`, without `none`

### Requirement: The configuration states what the provider refuses and how it logs out
The configuration SHALL carry `authorization_response_iss_parameter_supported` true; `request_parameter_supported`, `request_uri_parameter_supported` and `claims_parameter_supported` false; and `backchannel_logout_supported` and `backchannel_logout_session_supported` true.

#### Scenario: Request objects declared unsupported
- **WHEN** a relying party reads the configuration
- **THEN** `request_parameter_supported` and `request_uri_parameter_supported` are false, and `authorization_response_iss_parameter_supported` is true

### Requirement: The authorization server metadata is published at its well-known path
The provider SHALL also serve OAuth authorization server metadata, with the same content and `issuer`, at `/.well-known/oauth-authorization-server` followed by the issuer's path.

#### Scenario: Issuer with a path
- **WHEN** the issuer is `https://example.com/id`
- **THEN** the metadata is served at `https://example.com/.well-known/oauth-authorization-server/id`

### Requirement: Metadata names the sender-constraining features that are enabled
When DPoP is enabled, the metadata SHALL carry `dpop_signing_alg_values_supported` with the accepted proof algorithms. When certificate binding is enabled, it SHALL carry `tls_client_certificate_bound_access_tokens` true. When neither is enabled, neither member SHALL appear.

#### Scenario: DPoP enabled
- **WHEN** DPoP is enabled with ES256 proofs
- **THEN** the metadata carries `dpop_signing_alg_values_supported` `["ES256"]`

### Requirement: Metadata is derived from the configuration, and the consumer may add to it
The metadata SHALL be built from the provider's configuration, so it never advertises a feature the provider does not serve. A consumer MAY add members, such as `service_documentation` or `ui_locales_supported`. A consumer member that would replace one the provider sets SHALL fail construction.

#### Scenario: Consumer adds documentation
- **WHEN** the consumer adds `service_documentation`
- **THEN** the published metadata carries it

#### Scenario: Consumer overrides an endpoint
- **WHEN** the consumer adds a `token_endpoint` member
- **THEN** construction fails with a configuration error

### Requirement: Metadata documents are cacheable and public
The metadata documents SHALL be served to anyone, without authentication. They SHALL carry a `Cache-Control` header that allows caching for a bounded time, 1 hour by default, replaceable by the consumer. `jwks_uri` SHALL name the chain's JWKS endpoint, which keeps its own behaviour, so the provider requires that endpoint to be enabled.

#### Scenario: JWKS endpoint not enabled
- **WHEN** the provider is enabled on a chain without the JWKS endpoint
- **THEN** construction fails with a configuration error naming the JWKS endpoint

#### Scenario: Key rotated
- **WHEN** the signing key rotates while ID tokens signed by the previous key are unexpired
- **THEN** the JWKS endpoint still publishes the previous public key

#### Scenario: Consumer shortens the cache
- **WHEN** the consumer sets the metadata cache lifetime to 5 minutes
- **THEN** the documents carry `Cache-Control` with a maximum age of 300 seconds
