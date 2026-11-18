# Spec Delta

## Purpose

Lets an application accept, through its security chain's bearer authentication, the access tokens
its embedded OpenID Provider issues, held to their key and to a live grant and user.

## ADDED Requirements

### Requirement: The provider offers a verifier of its own access tokens for one audience
The provider SHALL offer a token verifier for its access tokens, built for one audience: an absolute URI with no fragment, by the rule the provider applies to a client's resources, that is not the provider's issuer. An empty, relative or fragment-bearing audience, or the issuer, SHALL fail construction with a configuration error.

#### Scenario: URL audience
- **WHEN** the verifier is built for `https://hris.example/api`
- **THEN** it is built

#### Scenario: URN audience
- **WHEN** the verifier is built for `urn:kartala:hris:api`
- **THEN** it is built

#### Scenario: Relative audience
- **WHEN** the verifier is built for `hris-api`
- **THEN** construction fails with a configuration error

#### Scenario: Issuer as audience
- **WHEN** the verifier is built for the provider's issuer identifier
- **THEN** construction fails with a configuration error, because nearly every token the provider issues for `openid` names the issuer

### Requirement: The verifier routes a token by its shape
The verifier SHALL treat as a provider access token one that begins `at.`, or a JWT whose protected header declares `typ` `at+jwt` or `application/at+jwt`, without regard to case. The consumer MAY give it a first-party verifier, to which every other token SHALL go unchanged; without one, every other token SHALL be refused as invalid. Reading the header SHALL decide only the route, read through a bounded size, and grant nothing.

#### Scenario: First-party token routed
- **WHEN** the verifier has a first-party route and verifies a first-party token typed `scrty+jwt`
- **THEN** the first-party verifier's result is returned, and it carries no grant-backed mark

#### Scenario: No first-party route
- **WHEN** the verifier has no first-party route and is given a first-party token
- **THEN** it is refused as invalid

#### Scenario: ID token
- **WHEN** the verifier is given an ID token the provider issued, typed `JWT`, and has a first-party route
- **THEN** the first-party verifier refuses it as invalid, and no grant-backed claims are returned

#### Scenario: Opaque token
- **WHEN** the verifier is given `at.<id>.<secret>`
- **THEN** the provider verifies it

### Requirement: A provider access token is verified with its grant and audience
For a provider access token the verifier SHALL check the signature, issuer, type, expiry or record and grant through the provider, and SHALL refuse as invalid a token that fails any of them, or whose audience does not include the configured audience exactly. A provider that cannot answer SHALL be reported as a dependency failure, not an invalid token.

#### Scenario: Altered signature
- **WHEN** a JWT access token's signature has been altered
- **THEN** it is refused as invalid

#### Scenario: Unknown signing key
- **WHEN** a JWT access token is signed by a key the provider does not hold
- **THEN** it is refused as invalid

#### Scenario: Expired
- **WHEN** a token issued at 08:00 with a 5-minute lifetime is verified at 08:06
- **THEN** it is refused as invalid

#### Scenario: Grant revoked
- **WHEN** the user's grants are revoked, and a token issued from one of them before its expiry is verified
- **THEN** it is refused as invalid

#### Scenario: Grant ended by logout
- **WHEN** the user logs out of the sign-in a grant without `offline_access` came from, and that grant's unexpired token is verified
- **THEN** it is refused as invalid

#### Scenario: Opaque token revoked
- **WHEN** an opaque access token revoked at the revocation endpoint is verified
- **THEN** it is refused as invalid

#### Scenario: Another audience
- **WHEN** the verifier's audience is `https://hris.example/api`, and a token whose audience is `https://payroll.example/api` or only the issuer is verified
- **THEN** it is refused as invalid

#### Scenario: One of several audiences
- **WHEN** a token's audience is the issuer and `https://hris.example/api`
- **THEN** the audience check passes

#### Scenario: Grant store down
- **WHEN** the provider's grant store fails during verification
- **THEN** the failure is not reported as an invalid token

### Requirement: Verified provider tokens are marked grant-backed, and nothing else can be
The claims of a verified provider access token SHALL carry a grant-backed mark holding what the token states, and its subject SHALL be the user's identifier. No code outside the library's own packages SHALL be able to produce claims carrying the mark; a consumer's own verifier SHALL only ever produce unmarked claims.

#### Scenario: Consumer verifier
- **WHEN** a consumer's verifier returns claims it built through the public constructors
- **THEN** they carry no grant-backed mark, and the bearer judges them against a session

### Requirement: The bearer authenticates a grant-backed token without a session
For grant-backed claims the bearer SHALL NOT look up a session. It SHALL judge the key binding, then load the user by the subject, then record any proof, then publish the caller. A user who does not exist, is not active, or whose identifier is not the subject SHALL be refused with the authentication-required error, consuming no proof. A loader failure SHALL be a dependency failure, and a load the caller's context ended SHALL match that context's error.

#### Scenario: Accepted
- **WHEN** an access token bound to key K is sent as `Authorization: DPoP` with a fresh proof signed by K for the request's method and URL
- **THEN** the request is authenticated with no session read

#### Scenario: Deactivated after issue
- **WHEN** a user is deactivated after their unexpired token was issued, and the token is presented with a valid proof
- **THEN** the request is refused with the authentication-required error, 401, and a `DPoP` challenge

#### Scenario: A refused user consumes no proof
- **WHEN** a valid bound token and proof are refused for a deactivated user, and the user is reactivated and the same proof presented again within its lifetime
- **THEN** the second request is authenticated

#### Scenario: Roles are current
- **WHEN** a user's role is removed after their token was issued, and the token is presented
- **THEN** the published principal does not hold that role

#### Scenario: User store down
- **WHEN** the user loader fails with a connection error
- **THEN** the request fails as a dependency failure, not a refusal, and the proof is not recorded

### Requirement: A grant-backed token is held to its key as any bound token is
A grant-backed token whose confirmation names a DPoP key or a certificate SHALL be judged as the bearer judges any bound token: a DPoP-bound token only under `DPoP` with a proof from its key for the request's method and URL, fresh, unreplayed, with an `ath` over the token and a nonce when nonces are on; a certificate-bound token only with that certificate.

#### Scenario: Bearer with no proof
- **WHEN** a DPoP-bound provider token is sent as `Authorization: Bearer` with no proof
- **THEN** the request is refused with the invalid-DPoP-proof error

#### Scenario: No DPoP header
- **WHEN** a bound provider token is sent under `DPoP` with no `DPoP` header
- **THEN** the request is refused with the invalid-DPoP-proof error

#### Scenario: Another key
- **WHEN** the proof is signed by a key other than the one the token is bound to
- **THEN** the request is refused with the invalid-DPoP-proof error

#### Scenario: Another method or URL
- **WHEN** the proof names another HTTP method, or another URL, than the request's
- **THEN** the request is refused with the invalid-DPoP-proof error

#### Scenario: Stale proof
- **WHEN** the proof's `iat` is more than the chain's proof lifetime, 60 seconds by default, from the chain's clock
- **THEN** the request is refused with the invalid-DPoP-proof error

#### Scenario: Replayed proof
- **WHEN** a proof already accepted is presented again with the same token
- **THEN** the request is refused with the invalid-DPoP-proof error

#### Scenario: Wrong ath
- **WHEN** the proof's `ath` is not the hash of the presented token
- **THEN** the request is refused with the invalid-DPoP-proof error

#### Scenario: Certificate-bound
- **WHEN** certificate binding is on and a provider token bound to the request's certificate is presented under `Bearer`
- **THEN** the request is authenticated

### Requirement: The bearer refuses an unbound grant-backed token by default
By default the bearer SHALL refuse a grant-backed token bound to no key, under either scheme, with the invalid-token error, before any user is loaded, whatever the chain's own DPoP requirement. The consumer MAY allow unbound grant-backed tokens; one is then accepted only under `Bearer`, unless the chain requires DPoP. First-party tokens SHALL be unaffected by this default.

#### Scenario: Unbound refused by default
- **WHEN** a provider access token with no `cnf` is presented under `Bearer`
- **THEN** the request is refused with the invalid-token error, challenged under `DPoP`

#### Scenario: Consumer allows unbound
- **WHEN** the consumer allows unbound grant-backed tokens, the chain does not require DPoP, and an unbound provider token is sent under `Bearer`
- **THEN** the request is authenticated

#### Scenario: Chain requirement still wins
- **WHEN** the consumer allows unbound grant-backed tokens but the chain requires DPoP
- **THEN** an unbound provider token under `Bearer` is refused with the invalid-DPoP-proof error

#### Scenario: Unbound first-party token unaffected
- **WHEN** the chain does not require DPoP, and an unbound first-party token for a live session is presented under `Bearer`
- **THEN** the request is authenticated

### Requirement: With the provider's verifier, the token is read from one header and never the query
When the bearer's verifier is the provider's, a request with more than one `Authorization` header, or with an `access_token` query parameter beside a header the bearer claims, SHALL be refused as malformed with 400 and an `invalid_request` challenge, before any token is verified. A token in the query alone SHALL be no token.

#### Scenario: Two Authorization headers
- **WHEN** a request carries two `Authorization` headers
- **THEN** it is refused with 400 and `error="invalid_request"`, and nothing is verified

#### Scenario: Token in the query and the header
- **WHEN** a request carries a token in its header and `access_token=x` in its query
- **THEN** it is refused with 400 and `error="invalid_request"`

### Requirement: The caller and the token are published to the request
On success the bearer SHALL publish the caller as for any authenticated request, with no session. The principal SHALL be the reloaded user carrying exactly the token's granted scopes. What the verified token states (client, scopes, audience, grant, binding, issue and expiry) SHALL be readable from the request's context as a copy a reader cannot change.

#### Scenario: Authorization by scope
- **WHEN** an authorization rule requires scope `employees:read` and the token was granted it
- **THEN** the request is allowed, and a token not granted it is refused with 403

#### Scenario: Handler reads the token
- **WHEN** a handler reads the published token
- **THEN** it reads the token's client ID, scopes and grant, and changing what it read changes nothing another reader sees

#### Scenario: Nothing published on refusal
- **WHEN** a grant-backed token is refused
- **THEN** no caller and no token are published

### Requirement: The stateless policy phase judges a grant-backed caller
After publishing, the bearer SHALL run the policy phase for a stateless authentication with the `access-token` first-factor kind. A denial SHALL be returned as the policy's reason, and a challenge as a challenge error.

#### Scenario: Policy denies
- **WHEN** the consumer's policy denies the caller
- **THEN** the request is refused with the policy's reason and the handler does not run

#### Scenario: MFA requirement does not challenge every call
- **WHEN** the chain's policy requires a second factor of the token's user, and a valid token is presented
- **THEN** the request is authenticated, because the requirement was judged at the sign-in that made the grant

### Requirement: Grant-backed refusals carry a challenge in the scheme the token came in
A refused grant-backed or provider-routed token SHALL be answered with a `WWW-Authenticate` challenge: `invalid_token` for a refused token, `invalid_dpop_proof` or `use_dpop_nonce` for a refused proof, none for a missing caller. It SHALL use `DPoP` when the token came under it, is bound, or binding is required by default, and `Bearer` otherwise, and SHALL name no check.

#### Scenario: Bad token under DPoP
- **WHEN** a provider token with an altered signature is sent under `DPoP`
- **THEN** the response is 401 with `WWW-Authenticate: DPoP error="invalid_token", algs="ES256"`

#### Scenario: Bad proof
- **WHEN** a bound provider token is sent with a proof signed with RS256, which the chain does not accept
- **THEN** the response is 401 with `WWW-Authenticate: DPoP error="invalid_dpop_proof", algs="ES256"`

#### Scenario: Unbound allowed, expired under Bearer
- **WHEN** unbound grant-backed tokens are allowed, DPoP is off, and an expired unbound provider token is sent under `Bearer`
- **THEN** the response is 401 with `WWW-Authenticate: Bearer error="invalid_token"`

#### Scenario: Fiber keeps the challenge
- **WHEN** the chain runs on fiber with the adapter's error handler and refuses a provider token
- **THEN** the fiber response carries the same status and `WWW-Authenticate` header as on net/http

### Requirement: Grant-backed failures never carry the token
No error, log record or event on the grant-backed path SHALL contain the presented token, the proof, or the user's identifier. A refused token SHALL be recorded at debug with the check it failed; a dependency failure SHALL be recorded at error, sampled, with a fixed reason and the error's type.

#### Scenario: Refusal record
- **WHEN** a provider token is refused for an expired grant
- **THEN** the debug record names the refusal and contains neither the token nor the user's identifier
