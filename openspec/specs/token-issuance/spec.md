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
Constructing a generator with a lifetime shorter than one second, or not a whole number of seconds, SHALL fail, because expiry is recorded in whole seconds. Constructing a generator whose lifetime is longer than the key source's key lifetime minus its rotation interval SHALL fail with a configuration error, when the key source reports both. Issuing when no key is current for the configured algorithm SHALL return an error and SHALL NOT produce a token.

#### Scenario: Non-positive lifetime
- **WHEN** a generator is constructed with a lifetime of zero
- **THEN** construction fails

#### Scenario: Lifetime outlives the key
- **WHEN** a generator with a 24-hour token lifetime is constructed over a key source with a 24-hour key lifetime and a 1-hour rotation interval
- **THEN** construction fails with a configuration error

#### Scenario: No key for the algorithm
- **WHEN** a generator configured for EdDSA issues a token over a key source holding only RS256 keys
- **THEN** issuing returns an error and no token

#### Scenario: Sub-second lifetime
- **WHEN** a generator is constructed with a 500-millisecond lifetime
- **THEN** construction fails

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

### Requirement: A verification key that is a nil pointer is an outage, not a panic
When the consumer's key source returns a key whose value is a nil pointer, verification SHALL fail with the error it returns for a key set that cannot be used, and SHALL NOT panic.

#### Scenario: Typed-nil RSA key
- **WHEN** a consumer key source returns an RS256 key whose public key is a nil RSA public key pointer, and a token is verified
- **THEN** verification returns an error and does not panic

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
