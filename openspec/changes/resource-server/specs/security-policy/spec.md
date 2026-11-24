## ADDED Requirements

### Requirement: An external access token meets the MFA requirement on its asserted assurance
For a required user authenticated by an external access token, the MFA requirement policy SHALL decide by the federated-assurance mode from the assurance the token asserts, re-matched on every request. Met assurance SHALL allow. Unmet assurance SHALL be refused in both challenge and refuse mode, because no session can hold a challenge, and the refusal SHALL be answered as a request for a fresher, stronger sign-in at the issuer. Exempt mode SHALL allow.

#### Scenario: Assurance met
- **WHEN** a required user calls an API with an external access token asserting `amr` `["mfa"]`, which the assurance source accepts for that issuer
- **THEN** the request is allowed

#### Scenario: Password-only token in challenge mode
- **WHEN** a required user calls an API with an external access token asserting `amr` `["pwd"]`, and the policy is in the default challenge mode
- **THEN** the request is refused, and no second-factor challenge is raised

#### Scenario: Consumer exempts federated logins
- **WHEN** the policy is in exempt mode and the same token is presented
- **THEN** the request is allowed

#### Scenario: Provider access token
- **WHEN** a required user calls an API with an access token the chain's own provider issued
- **THEN** the MFA requirement policy treats it as exempt, as its sign-in passed the chain's gates

## MODIFIED Requirements

### Requirement: Federated assurance evidence is minted only by the library
The policy input SHALL carry federated assurance as evidence: the provider name, verified issuer, and asserted `amr` and `acr`. Only the library's OIDC redemption, its per-request evaluation of a federated session, and a resource server's verification of an external access token SHALL be able to produce evidence that asserts anything. The evidence type SHALL have no public constructor, and its zero value SHALL assert nothing. The MFA policies SHALL decide assurance only through a configured assurance source, which matches the evidence; without a source, no evidence SHALL be met.

#### Scenario: Zero evidence
- **WHEN** a consumer evaluates the MFA requirement policy directly for a required user enrolled on TOTP, recording the `oidc` first factor and leaving the evidence at its zero value
- **THEN** the outcome is an MFA challenge

#### Scenario: No source wired
- **WHEN** the policy has no assurance source and a required user enrolled on TOTP redeems an OIDC code whose token asserted `amr` `["mfa"]`
- **THEN** the outcome is an MFA challenge

#### Scenario: Evidence from an external access token
- **WHEN** a resource server accepts an external access token from issuer `https://sso.example` asserting `amr` `["mfa"]`
- **THEN** the per-request evaluation receives evidence naming that source's provider, that issuer and that `amr`
