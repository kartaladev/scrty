# Spec Delta

## ADDED Requirements

### Requirement: Requiring bound grant-backed tokens does not require proofs at sign-in
The bearer's default refusal of unbound grant-backed tokens SHALL apply only to grant-backed tokens. It SHALL NOT make any issuing endpoint, form login included, require a proof, and SHALL NOT refuse an unbound first-party token; only the chain's own DPoP requirement does either.

#### Scenario: Form login without a proof
- **WHEN** the bearer uses the provider's verifier with its default, the chain does not require DPoP, and form login is posted with no `DPoP` header
- **THEN** the login is judged on its credentials, and the token it issues is unbound

#### Scenario: Issued tokens still bind when a proof is sent
- **WHEN** the same chain receives form login with a valid proof
- **THEN** the token it issues is bound to the proof's key

#### Scenario: One replay store
- **WHEN** a proof accepted with a provider token by the bearer is replayed to the provider's UserInfo endpoint on the same chain within its lifetime
- **THEN** the replay is refused with the invalid-DPoP-proof error
