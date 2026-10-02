# Spec Delta

## MODIFIED Requirements

### Requirement: Enrolled users are challenged for a second factor
The second-factor challenge policy SHALL be constructed with the set of configured MFA methods and SHALL run in the post-authentication phase. It SHALL allow:
- exempt first factors;
- logins that have already satisfied a second factor;
- logins that carry the library's proof that their second factor was met at the first factor.

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
- **WHEN** an OIDC login occurs for an enrolled user
- **THEN** the outcome is allow

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
- in the stateless-authentication phase, deny with an MFA-required reason, whatever the user's enrolment;
- when no MFA method is configured, deny with an MFA-required reason;
- in the per-request phase, allow a session whose second factor is already satisfied;
- in the post-authentication phase, allow a login that carries the library's proof that its second factor was met at the first factor;
- when any configured method's enrolment lookup fails, deny;
- when the user can use no configured method (enrolled on none, or only on methods on the first factor's channel), challenge for enrolment when all of the following hold, and otherwise deny with an enrolment-required reason:
  - the enrolment path is on and has not been closed;
  - the phase is post-authentication or per-request;
  - the first factor's kind is on the path's allowlist;
  - at least one configured method supports the enrolment path and has a channel that differs from the first factor's. The passkey method supports the path when passkey registration serves it;
- in the per-request phase, challenge for MFA;
- in the post-authentication phase, allow, leaving the login challenge to the second-factor challenge policy;
- evaluated directly in a phase it does not declare, deny with an MFA-required reason.

With the enrolment path on, the policy SHALL declare that it can raise the enrolment challenge, so that the chain can refuse to assemble without its enforcer. A failed enrolment lookup SHALL deny whether the path is on or off.

In the post-authentication phase a login's plain claim to have satisfied a second factor SHALL NOT be honoured. Only the library's proof that the second factor was met at the first factor SHALL be. The documentation SHALL state that the second-factor challenge policy must be registered alongside this one, over the same methods.

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

#### Scenario: Flagged mid-session
- **WHEN** a user becomes required during a session that has not satisfied a second factor, and the user is enrolled on a usable method
- **THEN** the next per-request evaluation is an MFA challenge

#### Scenario: Flagged mid-session without an enrolment, path on
- **WHEN** the enrolment path is on and a user with no enrolment becomes required during a password session
- **THEN** the next per-request evaluation is a challenge of the enrolment kind

#### Scenario: Undeclared phase
- **WHEN** the policy is evaluated directly in the pre-authentication phase for a required, enrolled user
- **THEN** the outcome is deny with the MFA-required reason

## ADDED Requirements

### Requirement: A second factor met at the first factor is honoured only when the library recorded it
The policy input SHALL carry a proof that a login's second factor was met at its first factor. Only the library's own passkey verification SHALL be able to produce a proof that holds. The proof's type SHALL have no public constructor, and its zero value SHALL prove nothing. Both MFA policies SHALL honour a proof that holds, and SHALL ignore every other field or claim when deciding whether the first factor met the second. The proof SHALL NOT be an exemption:
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
