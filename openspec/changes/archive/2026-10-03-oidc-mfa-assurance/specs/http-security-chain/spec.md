# Spec Delta

## ADDED Requirements

### Requirement: The login completion step carries federated assurance evidence
The login completion step SHALL accept the asserted `amr` and `acr` of a federated login, hand them to the post-authentication policy phase as library-minted federated assurance evidence, and record them on the session in the write that creates it. Per-request evaluation SHALL hand a federated session's stored assurance to the policies as the same evidence. The step SHALL NOT mark the second factor satisfied on that evidence. Only the library's OIDC redemption SHALL supply the values to the step.

#### Scenario: Evidence reaches policy at login
- **WHEN** an OIDC redemption hands the step a login asserting `amr` `["mfa"]` for a required user enrolled on nothing
- **THEN** the session is created with `amr` `["mfa"]` and second-factor state none, and its token is returned without a challenge

#### Scenario: Evidence reaches policy per request
- **WHEN** a request presents the token of a federated session holding `amr` `["mfa"]`, for a required user, while the provider accepts `mfa`
- **THEN** the request reaches the handler
