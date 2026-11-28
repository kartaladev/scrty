# Spec Delta

## MODIFIED Requirements

### Requirement: The verifier can ask only for suspicious requests
The verifier SHALL receive whether the request's source has recent failures recorded by the chain's limiters and, at form login and Basic authentication, whether the identifier has failures within the lockout's failure window, so it can answer not needed for ordinary traffic and ask only for suspicious requests. Recovery start, magic-link requests and passwordless begin SHALL report no identifier failures: an owner's sign-in clears an account's failures, so the signal would let a challenge tell a known account from an unknown one on a flow that otherwise answers alike for both. When the source limiter keeps an IPv6 aggregate, the verifier SHALL also receive whether the aggregate holding the request's source has recent failures, reported apart from the source's own, which keeps its meaning; for IPv4, or without an aggregate, it SHALL be reported as none. Every limiter, the library's in memory and durable and a consumer's own alike, SHALL answer whether a key has recent failures. A limiter whose answer fails SHALL be reported to the verifier as having recent failures, so it can ask.

#### Scenario: Clean source
- **WHEN** a source with no recorded failures posts a login, and the verifier answers not needed when there are none
- **THEN** the login proceeds without a challenge

#### Scenario: Suspicious identifier
- **WHEN** a clean source posts a login for a username with recent failures
- **THEN** the verifier is told the identifier has recent failures

#### Scenario: Recovery start keeps the identifier out
- **WHEN** a username has recent failures and a recovery start is posted for it
- **THEN** the verifier is told the identifier has no recent failures

#### Scenario: Fresh address in a failing aggregate
- **WHEN** the source limiter keeps a /56 aggregate, failures were recorded from three /64s inside one /56, and a login is posted from a fourth /64 in it
- **THEN** the verifier is told the source has no recent failures and its aggregate has recent failures

#### Scenario: Aggregate not configured
- **WHEN** the source limiter keeps no aggregate and an IPv6 source posts a login
- **THEN** the verifier is told the aggregate has no recent failures

#### Scenario: Durable limiter
- **WHEN** the chain's source limit is kept by the Redis or SQL limiter and a source with no recorded failures posts a login
- **THEN** the verifier is told the source has no recent failures

#### Scenario: Limiter whose answer fails
- **WHEN** the source limiter's answer to whether a source has recent failures returns an error
- **THEN** the verifier is told the source has recent failures
