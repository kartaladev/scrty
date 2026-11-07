# Spec Delta

## MODIFIED Requirements

### Requirement: Every issuing endpoint binds the token when the request carries a proof
When a request to an endpoint that issues a credential carries a valid proof, with `ath` matching the access token the request presents (the credential the chain's bearer authenticated) or without `ath` when it presents none, the issued access token SHALL carry `cnf.jkt`, the base64url JWK SHA-256 thumbprint of the proof's key, and the session SHALL be built with the binding before its credential is issued. The endpoints that bind are login completion, passkey login, magic-link redemption, OIDC handoff redemption, recovery completion and re-authentication. Second-factor verification and session renewal continue a sign-in already created, so they carry its binding and add none. Every issuing endpoint, those two included, SHALL verify a proof it is given before anything is spent. The issued result SHALL tell the consumer's responder that the token type is `DPoP`, so it can answer `token_type` accordingly.

The proof SHALL be verified in the endpoint's checks, before anything is spent or stored: a refused proof SHALL leave a magic link, a handoff code, a pending challenge's attempts and recovery proofs unspent, and SHALL be charged as the endpoint charges a malformed request, not as a failed credential.

A binding SHALL be set when a sign-in is created and SHALL carry over to every successor through rotation and renewal. Renewal SHALL NOT add, change or remove a binding. Re-authentication of an unbound session MAY bind its successor to the proof's key; re-authentication of a bound session SHALL keep the binding.

#### Scenario: Proof beside a presented token at a continuing endpoint
- **WHEN** an unbound session presented as `Authorization: Bearer <token>` renews, verifies a second factor or re-authenticates with a proof whose `ath` is the hash of `<token>`
- **THEN** the proof is accepted

#### Scenario: Proof without ath beside a presented token
- **WHEN** an unbound session presented as `Authorization: Bearer <token>` renews, verifies a second factor or re-authenticates with an otherwise valid proof that carries no `ath`
- **THEN** the request is refused with the invalid-DPoP-proof error, and nothing is rotated or issued

#### Scenario: Second factor carries the sign-in's binding
- **WHEN** a sign-in created without a proof completes its second factor with a request carrying a valid proof whose `ath` matches the access token the request presents (or no `ath`, when it presents none)
- **THEN** the issued token carries no `cnf` and the session stays unbound, because the binding is set when the sign-in is created

#### Scenario: Bound login
- **WHEN** a client posts its credentials to `/sign-in/password` with a valid proof
- **THEN** the issued token carries `cnf.jkt` equal to the thumbprint of the proof's key, and the responder is told the token type is `DPoP`

#### Scenario: Unbound login
- **WHEN** DPoP is enabled and a client posts its credentials to `/sign-in/password` without a proof
- **THEN** the issued token carries no `cnf`, and the responder is told the token type is `Bearer`

#### Scenario: Bad proof leaves the magic link unspent
- **WHEN** a magic link is redeemed with a proof whose signature does not verify
- **THEN** the redemption is refused with the invalid-DPoP-proof error, the link is not consumed, and no session is stored

#### Scenario: Bad proof at login is not a failed password
- **WHEN** a client posts the right credentials to `/sign-in/password` with a proof whose `htu` is wrong
- **THEN** the login is refused with the invalid-DPoP-proof error, and no lockout failure is recorded for the username

#### Scenario: Re-proof keeps the binding
- **WHEN** a bound session re-authenticates and is rotated
- **THEN** the successor's token is bound to the same key

#### Scenario: Renewal does not bind
- **WHEN** an unbound session is renewed with a valid proof
- **THEN** the successor is unbound

#### Scenario: Re-authentication binds an unbound session
- **WHEN** an unbound session re-authenticates with a valid proof
- **THEN** the successor and its token are bound to the proof's key

#### Scenario: Binding never outlives the family
- **WHEN** a bound session's family has ended and the client presents a valid proof from the bound key at renewal
- **THEN** the renewal fails as expired and nothing is stored

