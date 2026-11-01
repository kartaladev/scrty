# Spec Delta

## ADDED Requirements

### Requirement: A provider's redirect URL must reach the callback path
Assembling a chain with OIDC login SHALL fail with a configuration error when a registered provider's redirect URL has a path that does not end with the chain's callback path, after the base path is applied, followed by that provider's name. The error SHALL name the provider, its redirect path and the expected callback path. The consumer SHALL be able to waive this check, for a proxy that rewrites paths beyond removing a prefix.

#### Scenario: Matching redirect URL
- **WHEN** provider `corp` is registered with the redirect URL `https://app.example.com/login/oauth2/callback/corp` and the chain has no base path
- **THEN** the chain is assembled

#### Scenario: Base path not reflected in the redirect URL
- **WHEN** provider `corp` keeps the redirect URL `https://app.example.com/login/oauth2/callback/corp` and the chain has the base path `/auth`
- **THEN** assembly fails with a configuration error naming `corp`, the path `/login/oauth2/callback/corp` and the expected `/auth/login/oauth2/callback/corp`

#### Scenario: Callback path moved without the redirect URL
- **WHEN** the consumer sets the callback path to `/sso/callback/` and provider `corp` keeps a redirect URL ending in `/login/oauth2/callback/corp`
- **THEN** assembly fails with a configuration error naming `corp`

#### Scenario: Proxy that removes a prefix
- **WHEN** provider `corp` is registered with the redirect URL `https://example.com/public/login/oauth2/callback/corp`, a proxy removes `/public` before requests reach the chain, and the chain has no base path
- **THEN** the chain is assembled, because the redirect path ends with `/login/oauth2/callback/corp`

#### Scenario: Consumer waives the check
- **WHEN** the consumer waives the redirect path check and provider `corp` is registered with the redirect URL `https://example.com/cb?p=corp`
- **THEN** the chain is assembled
