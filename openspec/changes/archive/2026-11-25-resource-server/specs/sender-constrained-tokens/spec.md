## ADDED Requirements

### Requirement: A resource server counts as a verifier of bound credentials
When a resource server is enabled, it SHALL count as a feature that verifies bound credentials. A chain whose only such feature is a resource server SHALL be able to enable DPoP or certificate binding.

#### Scenario: API-only chain with DPoP
- **WHEN** DPoP is enabled on a chain whose only credential mode is a resource server
- **THEN** the chain is built

### Requirement: Requiring bound access tokens does not require proofs at sign-in
A resource server's default refusal of unbound access tokens SHALL apply only to the access tokens it judges. It SHALL NOT make any issuing endpoint, form login included, require a proof, and SHALL NOT refuse an unbound session token; only the chain's own DPoP requirement does either.

#### Scenario: Form login without a proof
- **WHEN** a chain runs a resource server with its default binding, does not require DPoP, and form login is posted with no `DPoP` header
- **THEN** the login is judged on its credentials, and the token it issues is unbound

#### Scenario: One replay store
- **WHEN** a proof accepted with a provider token by a resource server is replayed to the provider's UserInfo endpoint on the same chain within its lifetime
- **THEN** the replay is refused with the invalid-DPoP-proof error
