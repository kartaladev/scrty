# Spec Delta

## MODIFIED Requirements

### Requirement: Logout wiring mistakes fail at construction
Constructing OIDC logout SHALL fail with a configuration error when:
- the logout scope is not one of the defined scopes;
- the post-logout redirect URL is invalid.

Assembling a chain with OIDC logout SHALL fail with a configuration error when the back-channel logout path collides with another endpoint the chain answers, as the chain-wide collision requirement of `http-security-chain` judges.

#### Scenario: Back-channel path shadows the callback
- **WHEN** the back-channel logout path is configured equal to the callback path
- **THEN** chain assembly fails with a configuration error naming both paths
