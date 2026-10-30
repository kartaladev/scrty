# Spec Delta

## RENAMED Requirements

- FROM: `### Requirement: Issuer is enforced exactly when configured`
- TO: `### Requirement: Issuer is enforced unless explicitly waived`
- FROM: `### Requirement: Audience is enforced when configured`
- TO: `### Requirement: Audience is enforced unless explicitly waived`

## MODIFIED Requirements

### Requirement: Issuer is enforced unless explicitly waived
A verifier SHALL enforce an issuer unless the consumer waives the check explicitly. Construction SHALL fail with a configuration error when the verifier is given neither a non-blank issuer nor an explicit waiver of the issuer check. When a verifier is configured with an issuer, verification SHALL reject a token whose issuer is absent or different. Only a verifier whose issuer check was explicitly waived SHALL NOT check the issuer.

#### Scenario: Configured and matching
- **WHEN** a verifier configured with issuer `https://auth.example` verifies a token with that issuer
- **THEN** verification succeeds

#### Scenario: Configured and different
- **WHEN** a verifier configured with issuer `https://auth.example` verifies a token with `iss` `https://evil.example`
- **THEN** it is rejected as invalid

#### Scenario: Configured and absent
- **WHEN** a verifier configured with issuer `https://auth.example` verifies a token without `iss`
- **THEN** it is rejected as invalid

#### Scenario: Not configured
- **WHEN** a verifier is constructed with a key source and an audience, but with no issuer and no waiver of the issuer check
- **THEN** construction fails with a configuration error

#### Scenario: Explicitly waived
- **WHEN** a verifier whose issuer check was explicitly waived verifies a token with `iss` `https://other.example`
- **THEN** the issuer does not cause rejection

### Requirement: Audience is enforced unless explicitly waived
A verifier SHALL enforce an audience unless the consumer waives the check explicitly. Construction SHALL fail with a configuration error when the verifier is given neither a non-blank audience nor an explicit waiver of the audience check. When a verifier is configured with an audience, verification SHALL reject a token whose audience is absent or does not contain it. Only a verifier whose audience check was explicitly waived SHALL NOT check the audience.

#### Scenario: Audience missing
- **WHEN** a verifier configured with audience `api` verifies a token without `aud`
- **THEN** it is rejected as invalid

#### Scenario: Wrong audience
- **WHEN** a verifier configured with audience `api` verifies a token with `aud` `admin`
- **THEN** it is rejected as invalid

#### Scenario: A token minted for another service
- **WHEN** two services share a key source, and a verifier configured with audience `service-b` verifies a token minted with `aud` `service-a`
- **THEN** it is rejected as invalid

#### Scenario: Not configured
- **WHEN** a verifier is constructed with a key source and an issuer, but with no audience and no waiver of the audience check
- **THEN** construction fails with a configuration error

#### Scenario: Explicitly waived
- **WHEN** a verifier whose audience check was explicitly waived verifies a token with `aud` `api`
- **THEN** the audience does not cause rejection

## ADDED Requirements

### Requirement: A generator requires an issuer and an audience, or an explicit waiver
A generator verifies the tokens it issues, so it SHALL follow the verifier's rule. Its construction SHALL fail with a configuration error unless each of the issuer and the audience is either configured with a non-blank value or explicitly waived, but not both. A configured claim SHALL go into every token it issues and SHALL be checked when it verifies. A waived claim SHALL be neither issued nor checked.

#### Scenario: Generator with neither issuer nor waiver
- **WHEN** a generator is constructed with a key source and an audience, but with no issuer and no waiver of the issuer
- **THEN** construction fails with a configuration error

#### Scenario: Two services sharing a key source
- **WHEN** generators for `service-a` and `service-b` share a key source, each configured with its own audience, and `service-b`'s generator verifies a token `service-a`'s generator issued
- **THEN** it is rejected as invalid

#### Scenario: An empty value is not a configuration
- **WHEN** a generator or a verifier is constructed with an empty issuer or an empty audience, or one made only of white space
- **THEN** construction fails with a configuration error that names the waiver

#### Scenario: Waived on purpose
- **WHEN** a generator that waived both claims issues a token and then verifies it
- **THEN** the token carries no issuer and no audience, and verification succeeds
