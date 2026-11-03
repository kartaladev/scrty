# Spec Delta

## ADDED Requirements

### Requirement: The provider counts as a verifier of bound credentials
When the OpenID Provider is enabled, it SHALL count as a feature that verifies bound credentials, because it checks bindings at its token endpoint and at UserInfo. A chain that runs the provider and neither bearer mode SHALL be able to enable DPoP.

#### Scenario: Provider-only chain with DPoP
- **WHEN** DPoP is enabled on a chain whose only feature that verifies bound credentials is the provider
- **THEN** the chain is built

### Requirement: The provider's token endpoint binds the tokens it issues
With DPoP enabled, a token request carrying a valid proof without `ath` SHALL receive access tokens carrying `cnf.jkt` for the proof's key, with `token_type` `DPoP`. A public client's grant SHALL be bound to that key. A confidential client's refresh tokens SHALL NOT be. The proof SHALL be verified before the code is spent or the refresh token rotated, so a refused proof leaves both as they were.

#### Scenario: Public client binds at the code exchange
- **WHEN** a public client exchanges its code with a valid proof from key `k1`
- **THEN** the access token carries `cnf.jkt` of `k1`, `token_type` is `DPoP`, and a later refresh with a proof from `k2` is refused

#### Scenario: Bad proof at the token endpoint
- **WHEN** a code exchange carries a proof whose `htu` is another URL
- **THEN** the request is refused with `invalid_dpop_proof`, and the code can still be exchanged

#### Scenario: Confidential client refreshes with a new key
- **WHEN** a confidential client's access tokens were bound to `k1`, and it refreshes with a proof from `k2`
- **THEN** the refresh succeeds, and the new access token carries `cnf.jkt` of `k2`

### Requirement: The provider's token endpoint binds to a client certificate
With certificate binding enabled, a token request with a client certificate and no DPoP proof SHALL receive access tokens carrying `cnf.x5t#S256` of that certificate.

#### Scenario: Certificate-bound access token
- **WHEN** a client exchanges its code over a connection presenting certificate `C`, without a proof
- **THEN** the access token carries `cnf.x5t#S256` of `C`

### Requirement: A code can be bound to a key at the authorization request
An authorization request MAY carry `dpop_jkt`. The code SHALL then be exchanged only with a proof whose key thumbprint equals it. A missing or different proof SHALL be answered with `invalid_grant`.

#### Scenario: Exchange with another key
- **WHEN** an authorization request carried `dpop_jkt` of `k1`, and the code is exchanged with a proof from `k2`
- **THEN** the response is `invalid_grant`

### Requirement: A client can be required to use sender-constrained tokens
A consumer MAY register a client as requiring bound tokens. A token request from that client without a valid proof, or without a certificate when certificate binding is its method, SHALL be refused. Requiring DPoP for a client while DPoP is not enabled SHALL fail construction.

#### Scenario: Required client without a proof
- **WHEN** a client required to use DPoP exchanges its code without a proof
- **THEN** the request is refused with `invalid_dpop_proof`, and the code can still be exchanged
