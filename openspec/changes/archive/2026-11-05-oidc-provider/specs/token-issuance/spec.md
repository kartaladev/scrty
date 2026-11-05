# Spec Delta

## ADDED Requirements

### Requirement: Every issued token declares its type
Every token the library issues SHALL carry a `typ` header naming its kind:
- a first-party token: `scrty+jwt`;
- an OAuth access token: `at+jwt`;
- an ID token: `JWT`;
- a logout token: `logout+jwt`.

A consumer MAY replace the first-party token's type with another value that is not one of the other three.

#### Scenario: First-party token
- **WHEN** a generator with default settings issues a token
- **THEN** its header carries `typ` `scrty+jwt`

#### Scenario: Consumer names the type
- **WHEN** the consumer sets the first-party type to `app+jwt`
- **THEN** issued first-party tokens carry `typ` `app+jwt`

#### Scenario: Type reserved for another kind
- **WHEN** the consumer sets the first-party type to `at+jwt`
- **THEN** construction fails with a configuration error

### Requirement: A verifier accepts only the token type it is for
A verifier SHALL accept a token only when its `typ` header equals the type the verifier is for, compared without regard to case and with an `application/` prefix ignored. By default that SHALL be the first-party type. A token with another type, or with none, SHALL be refused as an invalid token, matching the uniform authentication failure. No option SHALL make a verifier accept any type.

#### Scenario: Access token at a first-party verifier
- **WHEN** an access token with `typ` `at+jwt`, signed by the same keys, with the same issuer and audience, is verified by a default verifier
- **THEN** verification fails with the uniform authentication failure

#### Scenario: ID token at a first-party verifier
- **WHEN** an ID token is presented to the chain's signed-bearer mode
- **THEN** it is refused as unauthenticated

#### Scenario: Missing type
- **WHEN** a token without a `typ` header is verified by a default verifier
- **THEN** verification fails with the uniform authentication failure

#### Scenario: Consumer verifies access tokens
- **WHEN** a verifier is configured for `at+jwt` and verifies an access token whose header carries `typ` `application/at+jwt`
- **THEN** verification succeeds

### Requirement: A token can be issued with a declared type and further claims
The library SHALL provide an issuer, built from a key source, an algorithm and an issuer identifier, separate from the first-party `Generator` so that `Generator`'s interface and subject modes are unchanged. It SHALL issue a token of a declared type for a subject named by the caller, with further claims, such as `client_id`, `scope`, `nonce`, `auth_time`, `acr`, `amr`, `azp`, `sid`, `gid` and `events`, and with an audience of one or more values for that token alone.

#### Scenario: Access token claims
- **WHEN** a token of type `at+jwt` is issued with `client_id` `billing-web`, `scope` `openid profile` and audience `https://api.example.com`
- **THEN** the token carries those claims and that audience, with the generator's `iss` and its own `iat`, `exp` and `jti`

### Requirement: Further claims cannot replace the token's own
Further claims SHALL NOT replace `iss`, `sub`, `iat`, `exp` or `jti`. A request that tries SHALL fail with a configuration error, and no token SHALL be issued.

#### Scenario: Further claim replaces the issuer
- **WHEN** a token is requested with a further claim `iss`
- **THEN** issuing fails with a configuration error, and no token is returned

### Requirement: An issued token names a subject and respects the key cap
A token's lifetime SHALL NOT exceed the cap the key source reports, as for a generator. An empty subject SHALL fail with `ErrNoSubject`.

#### Scenario: Empty subject
- **WHEN** a token is requested for an empty subject
- **THEN** issuing fails matching `ErrNoSubject`, and no token is returned

#### Scenario: Lifetime past the key cap
- **WHEN** an issuer over a key source that reports a 23-hour window is asked for a token of 24 hours
- **THEN** issuing fails with a configuration error
