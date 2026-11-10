## MODIFIED Requirements

### Requirement: The algorithm is pinned by the key and `alg: none` is rejected
Verification SHALL use the algorithm recorded on the selected key. It SHALL reject a token whose header names a different algorithm, a token whose header algorithm is `none`, and a token whose header names no algorithm. No option SHALL enable unsigned tokens.

#### Scenario: Unsigned token
- **WHEN** a token with header `{"alg":"none","typ":"JWT"}`, valid claims and an empty signature is verified
- **THEN** it is rejected as invalid

#### Scenario: Algorithm mismatch
- **WHEN** a token whose header names `HS256` and the `kid` of an RS256 key, signed using that key's public key as an HMAC secret, is verified
- **THEN** it is rejected as invalid

#### Scenario: Header without an algorithm
- **WHEN** a token signed with the current RS256 key, whose header carries that key's `kid` and `typ` but no `alg`, is verified
- **THEN** it is rejected as invalid

#### Scenario: Tampered payload
- **WHEN** one character of a validly signed token's payload is changed and the token is verified
- **THEN** it is rejected as invalid
