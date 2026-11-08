# Spec Delta

## ADDED Requirements

### Requirement: A base path does not move the metadata documents
The OpenID configuration and the authorization server metadata SHALL be served where their standards place them from the issuer, whatever base path the chain has. The authorization server metadata SHALL therefore always be served at the host root, outside any base path, and the documentation SHALL say that a proxy in front of the chain must route it.

#### Scenario: Documents placed by the issuer
- **WHEN** the chain has the base path `/auth` and the issuer is `https://id.example.com/auth`
- **THEN** the OpenID configuration answers at `/auth/.well-known/openid-configuration` and the authorization server metadata at `/.well-known/oauth-authorization-server/auth`

#### Scenario: Endpoint URLs follow the base path
- **WHEN** the chain has the base path `/auth` and the issuer is `https://id.example.com/auth`
- **THEN** every endpoint URL either document names, `jwks_uri` included, starts with `https://id.example.com/auth/`
