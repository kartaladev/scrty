# Spec Delta

## ADDED Requirements

### Requirement: A provider's redirect URL must reach the callback path
Assembling a chain with OIDC login SHALL fail with a configuration error when a registered provider's redirect URL has a path that, decoded, does not end with the chain's callback path, after the base path is applied, followed by that provider's name. The error SHALL name the provider, its redirect path and the expected callback path. The consumer SHALL be able to waive this check, for a proxy that rewrites paths beyond removing a prefix.

#### Scenario: Matching redirect URL
- **WHEN** provider `corp` is registered with the redirect URL `https://app.example.com/sso/callback/corp` and the chain has no base path
- **THEN** the chain is assembled

#### Scenario: Base path not reflected in the redirect URL
- **WHEN** provider `corp` keeps the redirect URL `https://app.example.com/sso/callback/corp` and the chain has the base path `/auth`
- **THEN** assembly fails with a configuration error naming `corp`, the path `/sso/callback/corp` and the expected `/auth/sso/callback/corp`

#### Scenario: Callback path moved without the redirect URL
- **WHEN** the consumer sets the callback path to `/federation/callback/` and provider `corp` keeps a redirect URL ending in `/sso/callback/corp`
- **THEN** assembly fails with a configuration error naming `corp`

#### Scenario: Proxy that removes a prefix
- **WHEN** provider `corp` is registered with the redirect URL `https://example.com/public/sso/callback/corp`, a proxy removes `/public` before requests reach the chain, and the chain has no base path
- **THEN** the chain is assembled, because the redirect path ends with `/sso/callback/corp`

#### Scenario: Percent-encoded redirect path
- **WHEN** provider `corp` is registered with the redirect URL `https://app.example.com/sso/callback/%63orp` and the chain has no base path
- **THEN** the chain is assembled, because the decoded path ends with `/sso/callback/corp`

#### Scenario: Consumer waives the check
- **WHEN** the consumer waives the redirect path check and provider `corp` is registered with the redirect URL `https://example.com/cb?p=corp`
- **THEN** the chain is assembled

## MODIFIED Requirements

### Requirement: OIDC wiring mistakes fail at construction
Constructing OIDC login SHALL fail with a configuration error when:
- no provider is registered;
- any duration option is zero or negative, except the clock-skew leeway, for which zero means no leeway and only a negative value fails;
- just-in-time provisioning or role derivation is configured for a provider name that is not registered;
- an assurance configuration is given for a provider name that is not registered, contains an empty value in any of its sets, requests an `acr` value that contains whitespace, or names a match mode the library does not define.

Assembling a chain with OIDC login SHALL fail with a configuration error when one of the authorize, callback, redemption and back-channel logout paths collides with another of them or with another endpoint the chain answers, as the chain-wide collision requirement of `http-security-chain` judges.

Assembling a chain with OIDC login SHALL fail with a configuration error when an MFA policy that decides federated logins on provider assurance has no source of assurance wired to it.

#### Scenario: Colliding paths
- **WHEN** the redemption path is configured equal to the callback path
- **THEN** chain assembly fails with a configuration error naming both paths

#### Scenario: Option for an unknown provider
- **WHEN** just-in-time provisioning is enabled for provider `corpp` while only `corp` is registered
- **THEN** construction fails with a configuration error naming `corpp`

#### Scenario: Assurance for an unknown provider
- **WHEN** an assurance configuration is given for provider `corpp` while only `corp` is registered
- **THEN** construction fails with a configuration error naming `corpp`

#### Scenario: Empty accepted value
- **WHEN** provider `corp` is configured to accept the `amr` values `mfa` and the empty string
- **THEN** construction fails with a configuration error

#### Scenario: Requested acr value with whitespace
- **WHEN** provider `corp` is configured to request the `acr` value `urn:corp:loa 2`
- **THEN** construction fails with a configuration error, because `acr_values` separates values by spaces and the value would be sent as two

#### Scenario: Requirement policy without an assurance source
- **WHEN** a chain enables OIDC login and registers the MFA requirement policy in the default mode without wiring an assurance source to it
- **THEN** chain assembly fails with a configuration error
