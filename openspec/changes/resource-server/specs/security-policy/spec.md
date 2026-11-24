## ADDED Requirements

### Requirement: An unmet access-token sign-in is answered as insufficient user authentication
When the MFA requirement policy denies an access-token caller with the insufficient-user-authentication reason, the chain SHALL refuse with the insufficient-user-authentication refusal, answered 401 with a `WWW-Authenticate` challenge naming `error="insufficient_user_authentication"`, so that the client obtains a token from a stronger sign-in.

#### Scenario: Password-only external token in challenge mode
- **WHEN** a linked, required user calls an API with an external access token asserting `amr` `["pwd"]`, and the federated-assurance mode is challenge
- **THEN** the response is 401 with `error="insufficient_user_authentication"`, and no second-factor challenge is raised

#### Scenario: Consumer exempts federated logins
- **WHEN** the federated-assurance mode is exempt and the same token is presented
- **THEN** the request is allowed

## MODIFIED Requirements

### Requirement: A required user is challenged or refused, never let through
For a user who is required to use MFA, the MFA requirement policy SHALL decide as follows:
- for a principal that names no local user (an external access token resolved by claims only or a claims mapper), allow, before the requirement is looked up;
- for a `federated` first factor in exempt mode, allow, before the requirement is looked up;
- for an `access-token` or `external-access-token` first factor in the per-request phase, allow when the token's sign-in met the requirement (for `access-token`, its grant records a second factor the library verified; for `external-access-token`, the federated-assurance mode decides, refuse mode and challenge mode alike), and otherwise deny with an insufficient-user-authentication reason, never challenging;
- in the stateless-authentication phase, deny with an MFA-required reason, whatever the user's enrolment;
- in the per-request phase, allow a session whose second factor is already satisfied;
- for a `federated` first factor in the post-authentication or per-request phase, deny when the assurance decision fails, and allow when the assurance is met;
- when no MFA method is configured, deny with an MFA-required reason;
- in the post-authentication phase, allow a login that carries the library's proof that its second factor was met at the first factor;
- for a `federated` first factor in refuse mode, in the post-authentication or per-request phase, deny with an assurance-not-met reason;
- when any configured method's enrolment lookup fails, deny;
- when the user can use no configured method (enrolled on none, or only on methods on the first factor's channel), challenge for enrolment when all of the following hold, and otherwise deny with an enrolment-required reason:
  - the enrolment path is on and has not been closed;
  - the phase is post-authentication or per-request;
  - the first factor's kind is on the path's allowlist;
  - at least one configured method supports the enrolment path and has a channel that differs from the first factor's. The passkey method supports the path when passkey registration serves it;
- in the per-request phase, challenge for MFA;
- in the post-authentication phase, challenge for MFA for a `federated` first factor, and otherwise allow, leaving the login challenge to the second-factor challenge policy;
- evaluated directly in a phase it does not declare, deny with an MFA-required reason.

With the enrolment path on, the policy SHALL declare that it can raise the enrolment challenge, so that the chain can refuse to assemble without its enforcer. In challenge mode the policy SHALL declare that it can raise the MFA challenge. A failed enrolment lookup SHALL deny whether the path is on or off.

In the post-authentication phase a login's plain claim to have satisfied a second factor SHALL NOT be honoured. Only the library's proof that the second factor was met at the first factor, and library-minted federated assurance evidence matched by the assurance source, SHALL be. The documentation SHALL state that the second-factor challenge policy must be registered alongside this one, over the same methods.

#### Scenario: Basic auth for a required user
- **WHEN** a required, enrolled user authenticates with HTTP basic in the stateless-authentication phase
- **THEN** the outcome is deny with the MFA-required reason

#### Scenario: Required and not enrolled
- **WHEN** a required user who is not enrolled logs in by password
- **THEN** the outcome is deny with the enrolment-required reason

#### Scenario: Required and not enrolled, path on
- **WHEN** the enrolment path is on and a required user who is not enrolled logs in by password
- **THEN** the outcome is a challenge of the enrolment kind

#### Scenario: Only method on the first factor's channel
- **WHEN** the enrolment path is on, the only configured method is an email one-time-code method, and a required, unenrolled user logs in by magic link
- **THEN** the outcome is deny with the enrolment-required reason

#### Scenario: Only a method that cannot enrol on another channel
- **WHEN** the enrolment path is on, the configured methods are an email one-time-code method that can enrol and a consumer's authenticator-app method that cannot, and a required, unenrolled user logs in by magic link
- **THEN** the outcome is deny with the enrolment-required reason

#### Scenario: Passkey registration serves the path
- **WHEN** the enrolment path is on, the only configured method is the passkey method, passkey registration serves the path, and a required, unenrolled user logs in by password
- **THEN** the outcome is a challenge of the enrolment kind

#### Scenario: Lookup failure with the path on
- **WHEN** the enrolment path is on and the enrolment lookup fails for a required user logging in by password
- **THEN** the outcome is deny

#### Scenario: Stateless with the path on
- **WHEN** the enrolment path is on and a required, unenrolled user authenticates with HTTP basic
- **THEN** the outcome is deny with the MFA-required reason

#### Scenario: A login claiming a satisfied second factor
- **WHEN** a required user who is not enrolled logs in by password and the login claims a satisfied second factor
- **THEN** the outcome is deny with the enrolment-required reason

#### Scenario: A user-verified passkey login
- **WHEN** a required user holding only passkeys logs in with a passkey and the login carries the library's proof that its second factor was met
- **THEN** the outcome is allow

#### Scenario: Federated login without assurance, enrolled
- **WHEN** a required user enrolled on TOTP logs in through OIDC without accepted assurance, in the post-authentication phase
- **THEN** the outcome is an MFA challenge

#### Scenario: Flagged mid-session
- **WHEN** a user becomes required during a session that has not satisfied a second factor, and the user is enrolled on a usable method
- **THEN** the next per-request evaluation is an MFA challenge

#### Scenario: Flagged mid-session without an enrolment, path on
- **WHEN** the enrolment path is on and a user with no enrolment becomes required during a password session
- **THEN** the next per-request evaluation is a challenge of the enrolment kind

#### Scenario: Undeclared phase
- **WHEN** the policy is evaluated directly in the pre-authentication phase for a required, enrolled user
- **THEN** the outcome is deny with the MFA-required reason

#### Scenario: Provider token without a second factor
- **WHEN** a user becomes required to use MFA after signing in with a password alone, and calls an API with an access token from that grant
- **THEN** the per-request evaluation denies with the insufficient-user-authentication reason, and no challenge is raised

#### Scenario: Provider token with a second factor
- **WHEN** a required user calls an API with an access token whose grant records a TOTP second factor the library verified
- **THEN** the request is allowed

#### Scenario: Claims-only external caller
- **WHEN** MFA is required for all users and an external access token is resolved by claims only
- **THEN** the requirement is not looked up and the request is allowed by this policy

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
