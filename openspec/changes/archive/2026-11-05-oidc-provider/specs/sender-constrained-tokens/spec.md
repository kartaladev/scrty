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

#### Scenario: Public client's first proof at a refresh
- **WHEN** a public client whose code exchange carried no proof refreshes with a valid proof
- **THEN** the request is refused with `invalid_dpop_proof`, and the refresh token is not rotated

#### Scenario: Bad proof at the token endpoint
- **WHEN** a code exchange carries a proof whose `htu` is another URL
- **THEN** the request is refused with `invalid_dpop_proof`, and the code can still be exchanged

#### Scenario: Proof and certificate together
- **WHEN** a token request carries a valid proof over a connection presenting a client certificate
- **THEN** the access token carries `cnf.jkt` alone, and `token_type` is `DPoP`

#### Scenario: Refresh keeps its token type
- **WHEN** a public client refreshes a bound grant with a proof from its key
- **THEN** the new access token carries `cnf.jkt`, and `token_type` is `DPoP`

#### Scenario: Confidential client refreshes without a proof
- **WHEN** a confidential client not required to use DPoP refreshes without a proof, after earlier tokens were bound
- **THEN** the refresh succeeds, and `token_type` is `Bearer`

#### Scenario: Proof while DPoP is off
- **WHEN** a token request carries a `DPoP` header on a chain without DPoP
- **THEN** the header is ignored, and `token_type` is `Bearer`

#### Scenario: Confidential client refreshes with a new key
- **WHEN** a confidential client's access tokens were bound to `k1`, and it refreshes with a proof from `k2`
- **THEN** the refresh succeeds, and the new access token carries `cnf.jkt` of `k2`

### Requirement: The provider's token endpoint binds to a client certificate
With certificate binding enabled, a token request with a client certificate and no DPoP proof SHALL receive access tokens carrying `cnf.x5t#S256` of that certificate. A public client's grant SHALL be bound to that certificate, and a refresh SHALL present it.

#### Scenario: Certificate-bound access token
- **WHEN** a client exchanges its code over a connection presenting certificate `C`, without a proof
- **THEN** the access token carries `cnf.x5t#S256` of `C`

#### Scenario: Public client refreshes without its certificate
- **WHEN** a public client exchanged its code presenting certificate `C`, and refreshes presenting none
- **THEN** the request is refused, and the refresh token is not rotated

### Requirement: A code can be bound to a key at the authorization request
An authorization request MAY carry `dpop_jkt`. The code SHALL then be exchanged only with a proof whose key thumbprint equals it. A missing or different proof SHALL be answered with `invalid_grant`. A request carrying `dpop_jkt` while DPoP is not enabled SHALL be answered with `invalid_request`, because the client would otherwise hold an unbound code it believes is bound.

#### Scenario: dpop_jkt while DPoP is off
- **WHEN** an authorization request carries `dpop_jkt` on a chain without DPoP
- **THEN** the browser is redirected to the redirect URI with `error=invalid_request`

#### Scenario: Exchange with another key
- **WHEN** an authorization request carried `dpop_jkt` of `k1`, and the code is exchanged with a proof from `k2`
- **THEN** the response is `invalid_grant`

### Requirement: A client can be required to use sender-constrained tokens
A consumer MAY register a client as requiring bound tokens. A token request from that client without a valid proof, or without a certificate when certificate binding is its method, SHALL be refused, also when refreshing. Requiring DPoP for a client while DPoP is not enabled SHALL fail construction.

#### Scenario: Required client without a proof
- **WHEN** a client required to use DPoP exchanges its code without a proof
- **THEN** the request is refused with `invalid_dpop_proof`, and the code can still be exchanged

### Requirement: The token endpoint asks for a server nonce in the protocol's form
When server nonces are enabled, a token request whose proof has no acceptable nonce SHALL be answered 400 with `{"error":"use_dpop_nonce"}`, a `DPoP-Nonce` header and `Cache-Control: no-store`. The code SHALL stay unspent and the refresh token unrotated. UserInfo SHALL keep the resource-server form, 401 with `WWW-Authenticate: DPoP error="use_dpop_nonce"`.

#### Scenario: Nonce needed at the token endpoint
- **WHEN** nonces are enabled, and a code exchange carries a proof with no nonce
- **THEN** the response is 400 with `{"error":"use_dpop_nonce"}` and a `DPoP-Nonce` header, and the same code can be exchanged with a proof carrying that nonce

#### Scenario: Nonce needed at UserInfo
- **WHEN** nonces are enabled, and a UserInfo request carries a proof with no nonce
- **THEN** the response is 401 with `WWW-Authenticate: DPoP error="use_dpop_nonce"` and a `DPoP-Nonce` header
