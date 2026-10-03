# Spec Delta

## ADDED Requirements

### Requirement: Federated logins meet the MFA requirement on verified provider assurance
For a required user whose first factor has the `federated` channel, the MFA requirement policy SHALL decide by a federated-assurance mode: challenge (the default), refuse, or exempt. In challenge mode an unmet login SHALL be challenged for the library's own second factor; in refuse mode it SHALL be denied with an assurance-not-met reason; exempt mode SHALL allow every such login. Met assurance SHALL allow in every mode. A consumer SHALL be able to choose the mode by an option.

#### Scenario: Assurance met
- **WHEN** a required user who is enrolled on nothing logs in through OIDC and the provider asserted accepted assurance
- **THEN** the outcome is allow

#### Scenario: Not met, enrolled, default mode
- **WHEN** a required user enrolled on TOTP logs in through OIDC and the provider asserted no accepted assurance
- **THEN** the outcome is an MFA challenge

#### Scenario: Not met, not enrolled, default mode
- **WHEN** MFA is required for all and an unenrolled user logs in through OIDC and the provider asserted no accepted assurance
- **THEN** the outcome is deny with the enrolment-required reason

#### Scenario: Consumer chooses refusal
- **WHEN** the policy is in refuse mode and a required user enrolled on TOTP logs in through OIDC without accepted assurance
- **THEN** the outcome is deny with the assurance-not-met reason

#### Scenario: Consumer chooses exemption
- **WHEN** the policy is in exempt mode and a required, unenrolled user logs in through OIDC without accepted assurance
- **THEN** the outcome is allow
- **AND** no requirement lookup, assurance source or enrolment lookup is consulted

#### Scenario: Consumer exemption rule
- **WHEN** the consumer's exemption rule marks `oidc` exempt and a required, unenrolled user logs in through OIDC without accepted assurance
- **THEN** the outcome is allow, as in exempt mode

#### Scenario: Assurance decision fails
- **WHEN** the assurance source returns an error for a required user's OIDC login
- **THEN** the outcome is deny with that error as its reason

### Requirement: Federated assurance evidence is minted only by the library
The policy input SHALL carry federated assurance as evidence: the provider name, verified issuer, and asserted `amr` and `acr`. Only the library's OIDC redemption and its per-request evaluation of a federated session SHALL be able to produce evidence that asserts anything. The evidence type SHALL have no public constructor, and its zero value SHALL assert nothing. The MFA policies SHALL decide assurance only through a configured assurance source, which matches the evidence; without a source, no evidence SHALL be met.

#### Scenario: Zero evidence
- **WHEN** a consumer evaluates the MFA requirement policy directly for a required user enrolled on TOTP, recording the `oidc` first factor and leaving the evidence at its zero value
- **THEN** the outcome is an MFA challenge

#### Scenario: No source wired
- **WHEN** the policy has no assurance source and a required user enrolled on TOTP redeems an OIDC code whose token asserted `amr` `["mfa"]`
- **THEN** the outcome is an MFA challenge

### Requirement: Federated assurance is re-matched on every request
In the per-request phase, the MFA requirement policy SHALL re-match a federated session's stored assurance against the assurance source's current configuration, and SHALL NOT rely on a decision stored at login. A session whose second factor was satisfied by the library's verification SHALL be allowed whatever its stored assurance.

#### Scenario: Provider configuration tightened
- **WHEN** a required user enrolled on TOTP holds a session from an OIDC login that asserted `amr` `["mfa"]`, and the provider is reconfigured to accept only `hwk`
- **THEN** the next per-request evaluation is an MFA challenge

#### Scenario: Provider removed
- **WHEN** a required user enrolled on TOTP holds a session from provider `corp`, which is no longer registered
- **THEN** the next per-request evaluation is an MFA challenge

#### Scenario: Locally satisfied session
- **WHEN** a required user's federated session, created without accepted assurance, has resolved its MFA challenge through the verify endpoint
- **THEN** the next per-request evaluation is allow

## MODIFIED Requirements

### Requirement: Enrolled users are challenged for a second factor
The second-factor challenge policy SHALL be constructed with the set of configured MFA methods and SHALL run in the post-authentication phase. It SHALL allow:
- exempt first factors;
- logins that have already satisfied a second factor;
- logins that carry the library's proof that their second factor was met at the first factor;
- by default, logins whose first factor has the `federated` channel, without consulting any lookup.

A consumer SHALL be able to choose to challenge federated logins whose provider assurance is not met; that choice SHALL require an assurance source, and its absence SHALL fail construction with a configuration error. With that choice, a federated login with met assurance SHALL be allowed and an unmet one judged like any other login.

For every other login it SHALL:
- deny with a reason wrapping the error when any method's enrolment lookup fails;
- challenge for MFA when the user can use at least one configured method, that is, is enrolled on a method whose channel differs from the first factor's channel;
- apply the same-channel rule when the user is enrolled only on methods whose channel equals the first factor's;
- allow a user who is enrolled on no configured method.

Construction SHALL fail with a configuration error when the set is empty, or contains an absent method or two methods of the same name.

#### Scenario: Enrolled password user
- **WHEN** a password login occurs for a user enrolled on an authenticator-app method
- **THEN** the outcome is an MFA challenge

#### Scenario: Enrolled on the second of two methods
- **WHEN** TOTP and `email-code` are configured and a password login occurs for a user enrolled only on `email-code`
- **THEN** the outcome is an MFA challenge

#### Scenario: OIDC login
- **WHEN** an OIDC login without accepted assurance occurs for an enrolled user
- **THEN** the outcome is allow

#### Scenario: Consumer challenges unmet federated logins
- **WHEN** the policy is configured to challenge unmet federated logins and an OIDC login without accepted assurance occurs for a user enrolled on TOTP
- **THEN** the outcome is an MFA challenge

#### Scenario: Consumer challenges unmet federated logins, assurance met
- **WHEN** the policy is configured to challenge unmet federated logins and an OIDC login asserting accepted assurance occurs for a user enrolled on TOTP
- **THEN** the outcome is allow

#### Scenario: Challenging unmet federated logins without a source
- **WHEN** the policy is configured to challenge unmet federated logins and is given no assurance source
- **THEN** construction fails with a configuration error

#### Scenario: User-verified passkey login
- **WHEN** a passkey login carrying the library's proof that its second factor was met occurs for a user enrolled on TOTP
- **THEN** the outcome is allow

#### Scenario: Passkey login without the proof
- **WHEN** a passkey login without that proof occurs for a user enrolled on TOTP
- **THEN** the outcome is an MFA challenge

#### Scenario: Lookup failure
- **WHEN** the enrolment lookup fails
- **THEN** the outcome is deny with a reason wrapping the failure

#### Scenario: No methods
- **WHEN** the policy is constructed with an empty set of methods
- **THEN** construction fails with a configuration error

### Requirement: A required user is challenged or refused, never let through
For a user who is required to use MFA, the MFA requirement policy SHALL decide as follows:
- for a `federated` first factor in exempt mode, allow, before the requirement is looked up;
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

### Requirement: A second factor met at the first factor is honoured only when the library recorded it
The policy input SHALL carry a proof that a login's second factor was met at its first factor. Only the library's own passkey verification SHALL be able to produce a proof that holds. The proof's type SHALL have no public constructor, and its zero value SHALL prove nothing. Both MFA policies SHALL honour a proof that holds. When deciding whether the first factor met the second, they SHALL ignore every other field or claim except library-minted federated assurance evidence, which they SHALL decide only as the federated-assurance rules state. Federated evidence SHALL NOT be the proof, and SHALL NOT set the met-by-first-factor marker. The proof SHALL NOT be an exemption:
- a login without it is judged like any other login of its kind;
- the exemption rule and its replacement SHALL NOT be consulted for it.

A consumer who wants a separate second factor even after a user-verified passkey login SHALL turn the proof off at the passkey login, so the policies never see one. The documentation of both policies SHALL say where that option lives.

#### Scenario: Proof produced by the library
- **WHEN** the MFA requirement policy evaluates a post-authentication input carrying a proof produced by the library's passkey verification, for a required user enrolled on nothing else
- **THEN** the outcome is allow

#### Scenario: Zero proof
- **WHEN** a consumer evaluates a post-authentication input recording the `passkey` first factor, with the proof left at its zero value, for a required user enrolled on TOTP
- **THEN** the second-factor challenge policy challenges for MFA

#### Scenario: Replaced exemption rule does not see the proof
- **WHEN** the consumer's exemption rule exempts nothing, and a required user logs in with a user-verified passkey
- **THEN** the outcome is still allow, on the proof

#### Scenario: Federated evidence is not the proof
- **WHEN** a required user logs in through OIDC with accepted assurance
- **THEN** the outcome is allow
- **AND** the login carries no proof that its second factor was met at the first factor

### Requirement: The enrolment path admits first factors by an allowlist of kinds
The enrolment path SHALL admit a login only when its first-factor kind is on the path's allowlist. By default the allowlist SHALL be password, magic link, account recovery and an unrecorded first factor. A session produced by an account recovery rests on two proofs of different kinds and exists to bind a new authenticator, so it is admitted by default. OIDC SHALL be off it by default. A consumer SHALL be able to replace the allowlist by an option; the option SHALL replace the list, not add to it. Listing the API-key or basic first factor SHALL fail construction with a configuration error, because those logins are stateless or exempt and have no session to confine. An empty allowlist SHALL fail construction with a configuration error, because a path that admits nothing would still declare the enrolment challenge and demand an enforcer no login can reach. The allowlist SHALL govern only entry to the path: it SHALL NOT change whether a user is required to use MFA, or which first factors are exempt. The documentation of adding OIDC SHALL state that a stolen provider account usually includes its mailbox, so the emailed code adds no assurance there.

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
