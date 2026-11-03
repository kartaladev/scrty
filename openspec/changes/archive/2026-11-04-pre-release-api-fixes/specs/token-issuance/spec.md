# Spec Delta

## MODIFIED Requirements

### Requirement: Issued tokens carry a fixed set of claims
An issued token SHALL be a compact JWS. Its header SHALL carry the signing algorithm, which is RS256 by default and configurable, and the key identifier of the key currently signing for that algorithm. Its claims SHALL carry:
- the token identifier supplied by the caller;
- the configured issuer;
- as subject, the principal's user identifier by default, or the principal's username when the generator is configured to use usernames;
- the issue time;
- an expiry equal to the issue time plus the lifetime, which is 15 minutes by default and configurable.

Issuing a token for a principal whose chosen subject is empty SHALL fail with an error identifiable as the no-subject error, and SHALL produce no token. A token generator SHALL report which subject it writes, so that a component it is given to can check agreement at construction; a generator that reports nothing else reports the user identifier, which is the zero value.

#### Scenario: Default token
- **WHEN** a token with identifier `s-7` is issued at 10:00:00 for a principal with user identifier `u-1` and username `alice` by a generator configured with issuer `https://auth.example`
- **THEN** the header has `alg` `RS256` and the `kid` of the current RS256 key
- **AND** the claims have `jti` `s-7`, `iss` `https://auth.example`, `sub` `u-1`, `iat` 10:00:00 and `exp` 10:15:00

#### Scenario: Consumer chooses the username as subject
- **WHEN** a generator configured to use usernames issues a token for a principal with user identifier `u-1` and username `alice`
- **THEN** the claims have `sub` `alice`

#### Scenario: Empty subject
- **WHEN** a token is issued by a default generator for a principal with no user identifier
- **THEN** issuing fails with the no-subject error and no token is returned

#### Scenario: Empty username under the username subject
- **WHEN** a generator configured to use usernames issues a token for a principal with user identifier `u-1` and no username
- **THEN** issuing fails with the no-subject error and no token is returned

#### Scenario: Generator reports its subject mode
- **WHEN** a default generator and one configured to use usernames are asked for their subject mode
- **THEN** the first reports the user identifier, which is the zero value, and the second reports the username

#### Scenario: Consumer algorithm and lifetime
- **WHEN** a consumer configures ES256 and a 5-minute lifetime and issues a token at 10:00:00
- **THEN** the header has `alg` `ES256`
- **AND** the claims have `exp` 10:05:00
