## Purpose

Binds the tokens scrty issues to a key the legitimate client holds, a DPoP key or a TLS client certificate, so a copied token cannot be used from anywhere else, and verifies that binding on every request.

## ADDED Requirements

### Requirement: DPoP is accepted whenever bearer authentication is enabled
A chain with signed-bearer or session-reference authentication enabled SHALL accept the `DPoP` authorization scheme, matched without regard to case, together with exactly one `DPoP` request header carrying a proof. Plain `Bearer` tokens SHALL still be accepted unless the consumer requires DPoP or the token is bound. The consumer SHALL be able to switch DPoP off, after which the `DPoP` scheme is refused like any unknown scheme.

#### Scenario: Unbound bearer client keeps working
- **WHEN** DPoP is not required and a client presents an unbound token as `Authorization: Bearer`
- **THEN** it is authenticated as before

#### Scenario: Two proof headers
- **WHEN** a request carries two `DPoP` headers
- **THEN** it is refused with the invalid-DPoP-proof error

### Requirement: A DPoP proof is verified in full before the token is accepted
A proof SHALL be accepted only when all of the following hold:
- it is a JWS with `typ` `dpop+jwt`, an asymmetric `alg` from the accepted set (ES256 by default, replaceable), and a public `jwk` with no private part;
- its signature verifies with that key;
- `htm` equals the request method, and `htu` equals the request's public URL without query or fragment, built from the scheme and host the chain resolved;
- `iat` is no older than the proof lifetime (60 seconds by default, replaceable) and not later than the current time by more than the proof lifetime;
- its `jti` has not been seen within the proof lifetime;
- when a token is presented, `ath` equals the base64url SHA-256 of that token;
- when nonces are enabled, `nonce` is a nonce the server issued and has not expired.

Any failure SHALL refuse the request with the invalid-DPoP-proof error. The consumer SHALL be able to give the public base URL explicitly instead of the resolved one.

#### Scenario: Proof for another URL
- **WHEN** a proof signed for `GET https://app.example.com/api/orders` is presented on `GET https://app.example.com/api/payments`
- **THEN** the request is refused with the invalid-DPoP-proof error

#### Scenario: Replayed proof
- **WHEN** a proof that was accepted 10 seconds earlier is presented again
- **THEN** the request is refused with the invalid-DPoP-proof error

#### Scenario: Behind a trusted proxy
- **WHEN** a trusted proxy forwards scheme `https` and host `app.example.com`, the app receives `GET http://10.20.1.5:8080/api/orders`, and the proof's `htu` is `https://app.example.com/api/orders`
- **THEN** the `htu` check passes

### Requirement: Every issuing endpoint binds the token when the request carries a proof
When a request to an endpoint that issues a credential carries a valid proof without `ath`, the issued access token SHALL carry `cnf.jkt`, the base64url JWK SHA-256 thumbprint of the proof's key, and the session SHALL record the binding. The endpoints are login completion, second-factor verification, passkey login, magic-link redemption, OIDC handoff redemption, recovery completion, re-authentication and session renewal. A session's binding SHALL carry over to every successor through rotation and renewal.

#### Scenario: Bound login
- **WHEN** a client posts its credentials to `/login` with a valid proof
- **THEN** the issued token carries `cnf.jkt` equal to the thumbprint of the proof's key

#### Scenario: Re-proof keeps the binding
- **WHEN** a bound session re-authenticates and is rotated
- **THEN** the successor's token is bound to the same key

### Requirement: A bound token is accepted only with a proof from its key
A token or session carrying a DPoP binding SHALL be refused when it is presented as `Bearer`, when no proof accompanies it, or when the proof's key thumbprint differs from the binding. Renewal of a bound session SHALL require a proof from the bound key.

#### Scenario: Stolen token replayed as Bearer
- **WHEN** a token bound to key K is presented as `Authorization: Bearer` with no proof
- **THEN** the request is refused with the invalid-DPoP-proof error

#### Scenario: Stolen token with the thief's own key
- **WHEN** a token bound to key K is presented with a valid proof signed by another key
- **THEN** the request is refused with the invalid-DPoP-proof error

### Requirement: The consumer can require DPoP
When the consumer requires DPoP, an unbound token SHALL be refused, and every issuing endpoint SHALL refuse a request that carries no valid proof.

#### Scenario: Required
- **WHEN** DPoP is required and a client signs in without a proof
- **THEN** the login is refused with the invalid-DPoP-proof error and no token is issued

### Requirement: Replay protection is replaceable and fails closed
Seen `jti` values SHALL be kept in an in-memory store by default, for the proof lifetime, and the consumer SHALL be able to supply a shared store. A store that cannot record or check a `jti` SHALL refuse the request.

#### Scenario: Store failure
- **WHEN** the replay store returns an error while checking a proof
- **THEN** the request is refused, and the error maps to 500 like any other dependency failure

### Requirement: Server nonces are opt-in
By default the server SHALL issue no DPoP nonces. When the consumer enables them, a proof without a current server nonce SHALL be refused with 401, `WWW-Authenticate: DPoP error="use_dpop_nonce"` and a fresh `DPoP-Nonce` header; responses SHALL carry a fresh `DPoP-Nonce` when the current one is about to expire.

#### Scenario: Nonce required
- **WHEN** nonces are enabled and a proof carries no nonce
- **THEN** the response is 401 with `error="use_dpop_nonce"` and a `DPoP-Nonce` header

### Requirement: DPoP refusals tell the client which scheme to use
A refusal for a missing or invalid proof SHALL carry `WWW-Authenticate: DPoP` with an `error` parameter, `invalid_dpop_proof` or `use_dpop_nonce`, and the accepted algorithms, and SHALL carry no detail about which check failed.

#### Scenario: Invalid signature
- **WHEN** a proof's signature does not verify
- **THEN** the response is 401 with `WWW-Authenticate: DPoP error="invalid_dpop_proof", algs="ES256"`

### Requirement: Tokens can be bound to a TLS client certificate
When a request to an issuing endpoint arrives with a TLS client certificate, and the consumer has enabled certificate binding, the issued token SHALL carry `cnf.x5t#S256`, the base64url SHA-256 of the certificate's DER encoding, and the session SHALL record it. A token or session bound to a certificate SHALL be accepted only on a request presenting that same certificate. The certificate SHALL come from the TLS connection, or, behind a trusted proxy, from a forwarded-certificate header the consumer names, read only from a trusted peer.

#### Scenario: Certificate-bound service call
- **WHEN** certificate binding is enabled, a service signs in over mutual TLS with certificate C, and later presents its token over a connection with certificate C
- **THEN** the request is authenticated

#### Scenario: Token without its certificate
- **WHEN** a token bound to certificate C is presented over a connection with no client certificate
- **THEN** the request is refused with the certificate-binding error

#### Scenario: Forwarded certificate from an untrusted peer
- **WHEN** a request from a peer that is not a trusted proxy carries the named forwarded-certificate header
- **THEN** the header is ignored and the request has no client certificate
