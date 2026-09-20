# token-issuance Specification

## Purpose

Issues signed JSON Web Tokens for an authenticated principal and verifies them. The key and its algorithm, expiry, issuer and audience are each checked by a fixed, tested rule that no configuration can invert or silently disable.

## Requirements

### Requirement: Issued tokens carry a fixed set of claims
An issued token SHALL be a compact JWS. Its header SHALL carry the signing algorithm, which is RS256 by default and configurable, and the key identifier of the key currently signing for that algorithm. Its claims SHALL carry:
- the token identifier supplied by the caller;
- the configured issuer;
- the principal's username as subject;
- the issue time;
- an expiry equal to the issue time plus the lifetime, which is 15 minutes by default and configurable.

#### Scenario: Default token
- **WHEN** a token with identifier `s-7` is issued at 10:00:00 for a principal with username `alice` by a generator configured with issuer `https://auth.example`
- **THEN** the header has `alg` `RS256` and the `kid` of the current RS256 key
- **AND** the claims have `jti` `s-7`, `iss` `https://auth.example`, `sub` `alice`, `iat` 10:00:00 and `exp` 10:15:00

#### Scenario: Consumer algorithm and lifetime
- **WHEN** a consumer configures ES256 and a 5-minute lifetime and issues a token at 10:00:00
- **THEN** the header has `alg` `ES256`
- **AND** the claims have `exp` 10:05:00

### Requirement: Issued tokens can carry an audience
When a generator is configured with an audience, issued tokens SHALL carry it. A verifier configured with the same audience SHALL accept them. When no audience is configured, issued tokens SHALL carry no audience.

#### Scenario: Audience round trip
- **WHEN** a generator configured with audience `api` issues a token and a verifier configured with audience `api` verifies it
- **THEN** verification succeeds

### Requirement: Issuing requires a key and a valid lifetime
Constructing a generator with a lifetime of zero or less SHALL fail. Constructing a generator whose lifetime is longer than the key source's key lifetime minus its rotation interval SHALL fail with a configuration error, when the key source reports both. Issuing when no key is current for the configured algorithm SHALL return an error and SHALL NOT produce a token.

#### Scenario: Non-positive lifetime
- **WHEN** a generator is constructed with a lifetime of zero
- **THEN** construction fails

#### Scenario: Lifetime outlives the key
- **WHEN** a generator with a 24-hour token lifetime is constructed over a key source with a 24-hour key lifetime and a 1-hour rotation interval
- **THEN** construction fails with a configuration error

#### Scenario: No key for the algorithm
- **WHEN** a generator configured for EdDSA issues a token over a key source holding only RS256 keys
- **THEN** issuing returns an error and no token

### Requirement: A verifier requires a key source
Constructing a verifier without a key source SHALL fail. A generator SHALL also verify tokens, using its own key source, issuer and audience.

#### Scenario: Missing key source
- **WHEN** a verifier is constructed without a key source
- **THEN** construction returns an error

#### Scenario: Generator verifies its own tokens
- **WHEN** a generator issues a token and the same generator verifies it
- **THEN** verification succeeds and reports the subject and token identifier as issued

### Requirement: The key identifier selects the key
Verification SHALL select the verification key by the key identifier in the token header, from the key source's current key set only. A token without a key identifier, and a token whose key identifier is not in the set, SHALL be rejected. A token signed by a key from a different key source SHALL be rejected.

#### Scenario: Token from another key source
- **WHEN** a token issued by a generator over key source A is verified by a verifier over key source B
- **THEN** it is rejected as invalid

#### Scenario: Missing key identifier
- **WHEN** a correctly signed token without `kid` is verified
- **THEN** it is rejected as invalid

### Requirement: The algorithm is pinned by the key and `alg: none` is rejected
Verification SHALL use the algorithm recorded on the selected key. It SHALL reject a token whose header names a different algorithm, and SHALL reject a token whose header algorithm is `none`. No option SHALL enable unsigned tokens.

#### Scenario: Unsigned token
- **WHEN** a token with header `{"alg":"none","typ":"JWT"}`, valid claims and an empty signature is verified
- **THEN** it is rejected as invalid

#### Scenario: Algorithm mismatch
- **WHEN** a token whose header names `HS256` and the `kid` of an RS256 key, signed using that key's public key as an HMAC secret, is verified
- **THEN** it is rejected as invalid

#### Scenario: Tampered payload
- **WHEN** one character of a validly signed token's payload is changed and the token is verified
- **THEN** it is rejected as invalid

### Requirement: Expiry is required and enforced
Verification SHALL reject a token without an expiry, and a token whose expiry has passed. The not-before and issued-at times, when present, SHALL NOT be in the future. No clock skew SHALL be tolerated by default.

#### Scenario: Missing expiry
- **WHEN** a correctly signed token without `exp` is verified
- **THEN** it is rejected as invalid

#### Scenario: Expired
- **WHEN** a token with `exp` 10:15:00 is verified at 10:14:59 and again at 10:15:01
- **THEN** the first verification succeeds
- **AND** the second is rejected as invalid

#### Scenario: Issued in the future
- **WHEN** a token with `iat` 10:01:00 is verified at 10:00:00
- **THEN** it is rejected as invalid

### Requirement: Issuer is enforced exactly when configured
When a verifier is configured with an issuer, verification SHALL reject a token whose issuer is absent or different. When no issuer is configured, verification SHALL NOT check the issuer.

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
- **WHEN** a verifier with no issuer configured verifies a token with `iss` `https://other.example`
- **THEN** the issuer does not cause rejection

### Requirement: Audience is enforced when configured
When a verifier is configured with an audience, verification SHALL reject a token whose audience is absent or does not contain it. When no audience is configured, verification SHALL NOT check the audience.

#### Scenario: Audience missing
- **WHEN** a verifier configured with audience `api` verifies a token without `aud`
- **THEN** it is rejected as invalid

#### Scenario: Wrong audience
- **WHEN** a verifier configured with audience `api` verifies a token with `aud` `admin`
- **THEN** it is rejected as invalid

#### Scenario: Not configured
- **WHEN** a verifier with no audience configured verifies a token with `aud` `api`
- **THEN** the audience does not cause rejection

### Requirement: Verification failures are uniform and keep their cause
Every rejection of a token SHALL return an error identifiable as "token invalid" that wraps the specific cause. A failure to obtain the key set from the key source SHALL be returned as that failure, and SHALL NOT be identifiable as "token invalid".

#### Scenario: Rejection keeps cause
- **WHEN** an expired token is verified
- **THEN** the error is identifiable as "token invalid" and wraps the expiry failure

#### Scenario: Key source failure
- **WHEN** the key source fails to supply its key set during verification
- **THEN** the error is not identifiable as "token invalid"

### Requirement: The clock is injectable
The generator and the verifier SHALL each read the current time from a configurable time source, defaulting to the system clock. Issue times, expiries and every time check SHALL use that source.

#### Scenario: Controlled clock
- **WHEN** generator and verifier share a time source fixed at 2030-01-01T00:00:00Z, a token is issued, and the source advances by 16 minutes before verification
- **THEN** the token's `iat` is 2030-01-01T00:00:00Z
- **AND** verification rejects it as invalid
