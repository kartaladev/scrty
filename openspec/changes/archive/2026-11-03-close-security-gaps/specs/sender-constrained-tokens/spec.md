## Purpose

Binds the tokens scrty issues to a key the legitimate client holds, a DPoP key or a TLS client certificate, so a copied token cannot be used from anywhere else, and verifies that binding on every request.

## ADDED Requirements

### Requirement: DPoP is one chain-wide feature, off until enabled
DPoP SHALL be enabled once for the whole chain, and then SHALL apply to both bearer modes, signed tokens and session references, and to every issuing endpoint. Without it, the `DPoP` authorization scheme SHALL be passed through as any unknown scheme, and no endpoint SHALL bind a token. Enabling DPoP SHALL fail construction unless the chain has at least one enabled feature that verifies bound credentials. The signed-bearer and session-reference modes are such features. A consumer's own handler SHALL NOT count as one. Enabling DPoP more than once SHALL fail construction. Enabling DPoP SHALL also fail construction unless the host the `htu` check is judged against is declared, by an explicit public base URL or by a trusted-proxy forwarded-host allowlist, because otherwise it would be the request's `Host` header, which the client chooses; the error SHALL name both declarations.

#### Scenario: Not enabled
- **WHEN** DPoP is not enabled and a request carries `Authorization: DPoP <token>` with a proof
- **THEN** no bearer interceptor authenticates it, and a protected route refuses it as unauthenticated

#### Scenario: Enabled with nothing that verifies a binding
- **WHEN** DPoP is enabled on a chain with neither bearer mode, and no other feature that verifies bound credentials
- **THEN** building the chain fails with a configuration error naming DPoP

#### Scenario: Host not declared
- **WHEN** DPoP is enabled with a bearer mode, no public base URL and no trusted-proxy forwarded-host allowlist
- **THEN** building the chain fails with a configuration error naming the public base URL and the forwarded-host allowlist

#### Scenario: Host off the allowlist
- **WHEN** DPoP is enabled with no public base URL and a trusted-proxy forwarded-host allowlist naming `app.example.com`, and a request that carries no allowlisted forwarded host arrives with `Host: evil.example` and a proof whose `htu` is `http://evil.example/api/orders`
- **THEN** the proof is refused as invalid and the handler does not run

#### Scenario: Proof for an undeclared host
- **WHEN** DPoP is enabled with the public base URL `https://app.example.com`, and a proof whose `htu` is `https://evil.example/api/orders` is sent with `Host: evil.example`
- **THEN** the request is refused with the invalid-DPoP-proof error

#### Scenario: Enabled with one bearer mode
- **WHEN** DPoP is enabled, with a public base URL, on a chain with only the session-reference mode
- **THEN** the chain is built

### Requirement: DPoP is accepted beside Bearer once enabled
With DPoP enabled, both bearer modes SHALL accept the `DPoP` authorization scheme, matched without regard to case, together with exactly one `DPoP` request header carrying a proof. Plain `Bearer` tokens SHALL still be accepted unless the consumer requires DPoP or the token is bound. A `DPoP` header longer than a bound, 8 KiB by default, SHALL be refused without being parsed.

#### Scenario: Unbound bearer client keeps working
- **WHEN** DPoP is not required and a client presents an unbound token as `Authorization: Bearer`
- **THEN** it is authenticated as before

#### Scenario: Two proof headers
- **WHEN** a request carries two `DPoP` headers
- **THEN** it is refused with the invalid-DPoP-proof error

#### Scenario: DPoP scheme without a proof
- **WHEN** a request carries `Authorization: DPoP <token>` and no `DPoP` header
- **THEN** it is refused with the invalid-DPoP-proof error

#### Scenario: Oversized proof
- **WHEN** a request carries a `DPoP` header of 64 KiB
- **THEN** it is refused with the invalid-DPoP-proof error, and no signature is verified

#### Scenario: Session-reference mode
- **WHEN** DPoP is enabled with session-reference authentication and a client presents its session reference as `Authorization: DPoP <reference>` with a valid proof whose `ath` hashes the reference
- **THEN** the request is authenticated

### Requirement: A DPoP proof is verified in full before the token is accepted
A proof SHALL be accepted only when all of the following hold, checked in this order:
1. it is a compact JWS with `typ` `dpop+jwt`, an asymmetric `alg` from the accepted set (ES256 by default, replaceable, never `none` or a MAC), and a public `jwk` with no private part whose key type fits the `alg`;
2. its signature verifies with that key;
3. `htm` equals the request method, and `htu` equals the request's public URL, both compared after normalising scheme and host case and dropping a default port, and ignoring the query and fragment of both, the public URL built from the scheme and host the chain resolved;
4. `iat` is no older than the proof lifetime (60 seconds by default, replaceable) and not later than the current time by more than the proof lifetime, judged by the chain's time source;
5. when a token is presented, `ath` equals the base64url SHA-256 of that token, and when none is, `ath` is absent;
6. when nonces are enabled, `nonce` is a nonce the server issued and has not expired;
7. its `jti`, at most 256 bytes, has not been seen within the proof lifetime; it SHALL then be recorded.

The `jti` SHALL be recorded only for a proof that passed every other check, so a refused proof consumes nothing. Any failure SHALL refuse the request with the invalid-DPoP-proof error. The consumer SHALL be able to give the public base URL explicitly instead of the resolved one.

#### Scenario: Proof for another URL
- **WHEN** a proof signed for `GET https://app.example.com/api/orders` is presented on `GET https://app.example.com/api/payments`
- **THEN** the request is refused with the invalid-DPoP-proof error

#### Scenario: Proof for another method
- **WHEN** a proof signed for `GET` is presented on a `POST` to the same URL
- **THEN** the request is refused with the invalid-DPoP-proof error

#### Scenario: Default port and query
- **WHEN** a proof's `htu` is `https://APP.example.com:443/api/orders` and the request is `GET https://app.example.com/api/orders?page=2`
- **THEN** the `htu` check passes

#### Scenario: Replayed proof
- **WHEN** a proof that was accepted 10 seconds earlier is presented again
- **THEN** the request is refused with the invalid-DPoP-proof error

#### Scenario: Refused proof does not consume its jti
- **WHEN** a proof is refused for a wrong `htm`, and a correct proof with the same `jti` is presented next
- **THEN** the second proof is not refused as a replay

#### Scenario: Private key in the proof
- **WHEN** a proof's `jwk` carries the private parameter `d`
- **THEN** the request is refused with the invalid-DPoP-proof error

#### Scenario: Symmetric or unsigned proof
- **WHEN** proofs with `alg` `none` and `HS256` are presented
- **THEN** both are refused with the invalid-DPoP-proof error

#### Scenario: Proof from the future
- **WHEN** a proof's `iat` is 5 minutes after the chain's current time
- **THEN** the request is refused with the invalid-DPoP-proof error

#### Scenario: Proof for another token
- **WHEN** a proof whose `ath` hashes token A accompanies token B
- **THEN** the request is refused with the invalid-DPoP-proof error

#### Scenario: Behind a trusted proxy
- **WHEN** a trusted proxy whose forwarded-host allowlist names `app.example.com` forwards scheme `https` and host `app.example.com`, the app receives `GET http://10.20.1.5:8080/api/orders`, and the proof's `htu` is `https://app.example.com/api/orders`
- **THEN** the `htu` check passes

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
- **WHEN** a client posts its credentials to `/login` with a valid proof
- **THEN** the issued token carries `cnf.jkt` equal to the thumbprint of the proof's key, and the responder is told the token type is `DPoP`

#### Scenario: Unbound login
- **WHEN** DPoP is enabled and a client posts its credentials to `/login` without a proof
- **THEN** the issued token carries no `cnf`, and the responder is told the token type is `Bearer`

#### Scenario: Bad proof leaves the magic link unspent
- **WHEN** a magic link is redeemed with a proof whose signature does not verify
- **THEN** the redemption is refused with the invalid-DPoP-proof error, the link is not consumed, and no session is stored

#### Scenario: Bad proof at login is not a failed password
- **WHEN** a client posts the right credentials to `/login` with a proof whose `htu` is wrong
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

### Requirement: A bound token is accepted only with a proof from its key
A token or session carrying a DPoP binding SHALL be refused when it is presented as `Bearer`, when no proof accompanies it, or when the proof's key thumbprint differs from the binding. In session-reference mode the binding SHALL be read from the session. Renewal and re-authentication of a bound session SHALL require a proof from the bound key.

#### Scenario: Stolen token replayed as Bearer
- **WHEN** a token bound to key K is presented as `Authorization: Bearer` with no proof
- **THEN** the request is refused with the invalid-DPoP-proof error

#### Scenario: Stolen token with the thief's own key
- **WHEN** a token bound to key K is presented with a valid proof signed by another key
- **THEN** the request is refused with the invalid-DPoP-proof error

#### Scenario: Renewal with another key
- **WHEN** a session bound to key K is renewed with a valid proof from another key
- **THEN** the renewal is refused with the invalid-DPoP-proof error, and nothing is rotated

#### Scenario: Bound session reference as Bearer
- **WHEN** session-reference mode is on and the reference of a session bound to K is presented as `Bearer`
- **THEN** the request is refused with the invalid-DPoP-proof error

### Requirement: The consumer can require DPoP
When the consumer requires DPoP, an unbound token SHALL be refused, and every issuing endpoint SHALL refuse a request that carries no valid proof, before any account is looked up and without recording a failed credential.

#### Scenario: Required
- **WHEN** DPoP is required and a client signs in without a proof
- **THEN** the login is refused with the invalid-DPoP-proof error, no token is issued, and no account is looked up

#### Scenario: Required refuses unbound tokens
- **WHEN** DPoP is required and a token issued before it was required, with no `cnf`, is presented as `Bearer`
- **THEN** the request is refused with the invalid-DPoP-proof error

### Requirement: Replay protection is replaceable and fails closed
Seen `jti` values SHALL be kept in an in-memory store by default, for as long as a proof could still be accepted (its issue time plus twice the proof lifetime, covering the allowed clock skew), keyed by a digest of the `jti` and the proof's key thumbprint, and the consumer SHALL be able to supply a shared store. Recording a `jti` SHALL be one atomic insert-if-absent. A store that cannot record or check a `jti` SHALL fail the request as a dependency failure, with fixed library text, not charged to any throttle. When the request's own context ends while the store answers, the request SHALL fail with an error matching the context's error, and SHALL NOT be logged as a dependency failure.

#### Scenario: Store failure
- **WHEN** the replay store returns an error while checking a proof
- **THEN** the request fails, and the error maps to 500 like any other dependency failure

#### Scenario: Concurrent replay
- **WHEN** the same valid proof is presented by two requests at the same instant
- **THEN** exactly one is accepted

#### Scenario: Client leaves during the replay check
- **WHEN** a request's context is cancelled and the replay store fails with that cancellation
- **THEN** the request fails with an error matching the cancellation, and nothing is recorded at ERROR

### Requirement: Server nonces are opt-in
By default the server SHALL issue no DPoP nonces. When the consumer enables them, a proof without a nonce the server still accepts SHALL be refused with 401, `WWW-Authenticate: DPoP error="use_dpop_nonce"`, and the replica's current `DPoP-Nonce`. Responses to an accepted proof SHALL carry the next `DPoP-Nonce` when the presented one is past half its lifetime; a proof refused for any other reason SHALL NOT be given a new nonce. Every response that carries `DPoP-Nonce` SHALL also carry `Cache-Control: no-store`. A replica SHALL hand the same current nonce to every client until half its lifetime has passed, so the rate of sealing does not depend on traffic. Nonces SHALL be verifiable by every replica that shares the nonce key, without a shared store.

#### Scenario: Nonce required
- **WHEN** nonces are enabled and a proof carries no nonce
- **THEN** the response is 401 with `error="use_dpop_nonce"` and a `DPoP-Nonce` header

#### Scenario: Expired nonce
- **WHEN** nonces are enabled and a proof carries a nonce the server issued long enough ago to have expired
- **THEN** the response is 401 with `error="use_dpop_nonce"`, a `DPoP-Nonce` header carrying a nonce the server accepts, and `Cache-Control: no-store`

#### Scenario: Refused replay gets no new nonce
- **WHEN** nonces are enabled and a proof whose nonce is past half its lifetime is sent a second time
- **THEN** the replay is refused with the invalid-DPoP-proof error, carries no `DPoP-Nonce`, and nothing is sealed for it

#### Scenario: One nonce per replica
- **WHEN** nonces are enabled and many clients ask for one within half a nonce lifetime
- **THEN** every client is handed the same nonce, and the replica seals once

### Requirement: DPoP refusals tell the client which scheme to use
A refusal for a missing or invalid proof SHALL carry `WWW-Authenticate: DPoP` with an `error` parameter, `invalid_dpop_proof` or `use_dpop_nonce`, and the accepted algorithms, and SHALL carry no detail about which check failed. When DPoP is not required, a refusal for a missing token SHALL carry both the `DPoP` and the `Bearer` challenge.

#### Scenario: Invalid signature
- **WHEN** a proof's signature does not verify
- **THEN** the response is 401 with `WWW-Authenticate: DPoP error="invalid_dpop_proof", algs="ES256"`

#### Scenario: No token at all
- **WHEN** DPoP is enabled but not required, and a request to a protected route carries no `Authorization` header, whether the route is protected by the chain's authorization rules or by a per-route guard
- **THEN** the 401 response carries a `DPoP` challenge and a `Bearer` challenge

### Requirement: Tokens can be bound to a TLS client certificate
Certificate binding SHALL be off until the consumer enables it. Once enabled, when a request to an issuing endpoint arrives with a client certificate, the issued token SHALL carry `cnf.x5t#S256`, the base64url SHA-256 of the certificate's DER encoding, and the session SHALL be built with that binding. A token or session bound to a certificate SHALL be accepted only on a request presenting that same certificate. The certificate SHALL come from the TLS connection or, behind a trusted proxy, from a forwarded-certificate header the consumer names, read only from a trusted peer and decoded as URL-encoded PEM by default or by a decoder the consumer supplies. The library SHALL NOT validate the certificate's chain or validity period; that is the TLS server's or the proxy's job, and the documentation SHALL say so. When a request carries both a valid DPoP proof and a client certificate, the token SHALL be bound to the DPoP key only.

#### Scenario: Certificate-bound service call
- **WHEN** certificate binding is enabled, a service signs in over mutual TLS with certificate C, and later presents its token over a connection with certificate C
- **THEN** the request is authenticated

#### Scenario: Token without its certificate
- **WHEN** a token bound to certificate C is presented over a connection with no client certificate
- **THEN** the request is refused with the certificate-binding error

#### Scenario: Token with another certificate
- **WHEN** a token bound to certificate C is presented over a connection with certificate D
- **THEN** the request is refused with the certificate-binding error

#### Scenario: Forwarded certificate from a trusted proxy
- **WHEN** the consumer names `X-Client-Cert`, and trusted proxy 10.20.0.2 forwards certificate C URL-encoded in it
- **THEN** a token issued on that request is bound to C

#### Scenario: Forwarded certificate from an untrusted peer
- **WHEN** a request from a peer that is not a trusted proxy carries the named forwarded-certificate header
- **THEN** the header is ignored and the request has no client certificate

#### Scenario: Undecodable forwarded certificate
- **WHEN** a trusted proxy forwards a value in the named header that does not decode to a certificate
- **THEN** the request has no client certificate, and a certificate-bound token on it is refused with the certificate-binding error

#### Scenario: Both bindings offered
- **WHEN** certificate binding and DPoP are enabled and a client signs in over mutual TLS with a valid proof
- **THEN** the token carries `cnf.jkt` and no `cnf.x5t#S256`

### Requirement: A token whose confirmation the chain cannot honour is refused
A presented token carrying a `cnf` claim SHALL be accepted only when that claim holds exactly one of `jkt` and `x5t#S256`, well-formed, and the matching feature is enabled. A token whose `cnf` names another member, both members, a malformed value, or a binding whose feature is not enabled SHALL be refused, never accepted as a plain bearer token.

#### Scenario: Unknown confirmation member
- **WHEN** a correctly signed token carries `cnf` `{"jwk": {...}}` only
- **THEN** it is refused, and not accepted as a bearer token

#### Scenario: Feature switched off after issuance
- **WHEN** a token bound with `cnf.x5t#S256` is presented after certificate binding was turned off
- **THEN** it is refused with the certificate-binding error
