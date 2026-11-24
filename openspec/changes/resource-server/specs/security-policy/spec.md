## ADDED Requirements

### Requirement: An unmet access-token sign-in is answered as insufficient user authentication
When the MFA requirement policy denies an access-token caller with the insufficient-user-authentication reason, the chain SHALL refuse with the insufficient-user-authentication refusal, answered 401 with a `WWW-Authenticate` challenge naming `error="insufficient_user_authentication"`, so that the client obtains a token from a stronger sign-in.

#### Scenario: Password-only external token in challenge mode
- **WHEN** a linked, required user calls an API with an external access token asserting `amr` `["pwd"]`, and the federated-assurance mode is challenge
- **THEN** the response is 401 with `error="insufficient_user_authentication"`, and no second-factor challenge is raised

#### Scenario: Consumer exempts federated logins
- **WHEN** the federated-assurance mode is exempt and the same token is presented
- **THEN** the request is allowed

### Requirement: Access-token assurance is evidence minted only by the library
The policy input SHALL carry an access-token caller's assurance as evidence: whether the caller names a local user, whether the library verified a second factor at the grant's sign-in, and the federated evidence the grant or token recorded. Only a resource server's verification SHALL be able to produce it. The type SHALL have no public constructor, and its zero value SHALL mean a local user, no second factor and no federated evidence.

#### Scenario: Zero value
- **WHEN** a consumer evaluates the MFA requirement policy directly for a required user with the `access-token` first factor and leaves the assurance at its zero value
- **THEN** the outcome is deny with the insufficient-user-authentication reason

### Requirement: A per-request challenge for an access-token caller is refused
When any per-request policy, the library's or a consumer's, challenges a caller a resource server authenticated, the chain SHALL refuse with the insufficient-user-authentication refusal instead, because no session can hold the challenge. A consumer's per-request policy SHALL be able to receive a request with no session.

#### Scenario: Consumer policy challenges an API caller
- **WHEN** a consumer's per-request policy raises a password-change challenge for an access-token caller
- **THEN** the response is 401 with `error="insufficient_user_authentication"`, and nothing is marked on any session

### Requirement: Linked external callers need an assurance source
A chain whose MFA requirement policy is enabled SHALL fail construction when a resource-server source resolves callers to local users (linked users, or a claims mapper that declares local users) and no assurance source judges that source's issuer. A source MAY be given its own assurance source.

#### Scenario: No assurance source
- **WHEN** MFA is required and a remote-issuer source uses linked users, with no assurance source for its issuer
- **THEN** construction fails with a configuration error naming the source

#### Scenario: Source given its own assurance source
- **WHEN** the same source is given an assurance source that accepts `amr` `["mfa"]` from its issuer
- **THEN** the chain is built, and a linked user's token asserting `["mfa"]` meets the requirement

## MODIFIED Requirements

### Requirement: A required user is challenged or refused, never let through
For a user who is required to use MFA, the MFA requirement policy SHALL decide as follows:
- for an access-token caller whose library-minted assurance says it names no local user (claims only, or a claims mapper that did not declare a local user), allow, before the requirement is looked up;
- for a `federated` first factor in exempt mode, allow, before the requirement is looked up;
- for an `access-token` or `external-access-token` first factor in the per-request phase, allow when the token's sign-in met the requirement, and otherwise deny with an insufficient-user-authentication reason, never challenging. For `access-token`, it is met when the grant records that the library verified a second factor at its sign-in, or, for a grant from a federated sign-in, when the federated evidence the grant recorded is met under the federated-assurance mode, re-matched now; for `external-access-token`, the federated-assurance mode decides from the token's evidence, refuse and challenge modes alike;
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

#### Scenario: Provider token from a federated sign-in, assurance tightened
- **WHEN** a user signed in through OIDC whose provider asserted `amr` `["mfa"]`, the provider's accepted assurance is then tightened to `hwk`, and the user calls an API with an access token from that grant
- **THEN** the per-request evaluation denies with the insufficient-user-authentication reason

#### Scenario: Provider token from an exempt federated sign-in
- **WHEN** the federated-assurance mode is exempt and a required user calls an API with an access token from a federated sign-in that asserted no second factor
- **THEN** the request is allowed

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

### Requirement: The enrolment path admits first factors by an allowlist of kinds
The enrolment path SHALL admit a login only when its first-factor kind is on the path's allowlist. By default the allowlist SHALL be password, magic link, account recovery and an unrecorded first factor. A session produced by an account recovery rests on two proofs of different kinds and exists to bind a new authenticator, so it is admitted by default. OIDC SHALL be off it by default. A consumer SHALL be able to replace the allowlist by an option; the option SHALL replace the list, not add to it. Listing the API-key, basic, `access-token` or `external-access-token` first factor SHALL fail construction with a configuration error, because those logins are stateless or exempt and have no session to confine. An empty allowlist SHALL fail construction with a configuration error, because a path that admits nothing would still declare the enrolment challenge and demand an enforcer no login can reach. The allowlist SHALL govern only entry to the path: it SHALL NOT change whether a user is required to use MFA, or which first factors are exempt. The documentation of adding OIDC SHALL state that a stolen provider account usually includes its mailbox, so the emailed code adds no assurance there.

#### Scenario: Password is on the default list
- **WHEN** the path is on and a required, unenrolled user logs in by password
- **THEN** the outcome is a challenge of the enrolment kind

#### Scenario: Recovery is on the default list
- **WHEN** the path is on and a required user left with no usable second factor holds a session produced by an account recovery
- **THEN** the outcome is a challenge of the enrolment kind, not deny

#### Scenario: OIDC is off the default list
- **WHEN** the path is on and a required, unenrolled user logs in through OIDC without accepted assurance
- **THEN** the outcome is deny with the enrolment-required reason

#### Scenario: Consumer admits OIDC
- **WHEN** the path's allowlist is set to password, magic link and OIDC, and a required, unenrolled user logs in through OIDC without accepted assurance
- **THEN** the outcome is a challenge of the enrolment kind

#### Scenario: Consumer removes magic link
- **WHEN** the path's allowlist is set to password only and a required, unenrolled user logs in by magic link
- **THEN** the outcome is deny with the enrolment-required reason

#### Scenario: Ineligible kind listed
- **WHEN** the path's allowlist includes the API-key first factor
- **THEN** construction fails with a configuration error

#### Scenario: Access-token kinds on the allowlist
- **WHEN** the enrolment path's allowlist names `access-token` or `external-access-token`
- **THEN** construction fails with a configuration error, as for `api-key`
