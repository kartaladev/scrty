## ADDED Requirements

### Requirement: The enrolment path admits first factors by an allowlist of kinds
The enrolment path SHALL admit a login only when its first-factor kind is on the path's allowlist. By default the allowlist SHALL be password, magic link and an unrecorded first factor. OIDC SHALL be off it by default. A consumer SHALL be able to replace the allowlist by an option; the option SHALL replace the list, not add to it. Listing the API-key or basic first factor SHALL fail construction with a configuration error, because those logins are stateless or exempt and have no session to confine. An empty allowlist SHALL fail construction with a configuration error, because a path that admits nothing would still declare the enrolment challenge and demand an enforcer no login can reach. The allowlist SHALL govern only entry to the path: it SHALL NOT change whether a user is required to use MFA, or which first factors are exempt. The documentation of adding OIDC SHALL state that a stolen provider account usually includes its mailbox, so the emailed code adds no assurance there.

#### Scenario: Password is on the default list
- **WHEN** the path is on and a required, unenrolled user logs in by password
- **THEN** the outcome is a challenge of the enrolment kind

#### Scenario: OIDC is off the default list
- **WHEN** the path is on, the consumer's classification makes OIDC non-exempt, and a required, unenrolled user logs in through OIDC
- **THEN** the outcome is deny with the enrolment-required reason

#### Scenario: Consumer admits OIDC
- **WHEN** the path's allowlist is set to password, magic link and OIDC, the classification makes OIDC non-exempt, and a required, unenrolled user logs in through OIDC
- **THEN** the outcome is a challenge of the enrolment kind

#### Scenario: Consumer removes magic link
- **WHEN** the path's allowlist is set to password only and a required, unenrolled user logs in by magic link
- **THEN** the outcome is deny with the enrolment-required reason

#### Scenario: Ineligible kind listed
- **WHEN** the path's allowlist includes the API-key first factor
- **THEN** construction fails with a configuration error

## MODIFIED Requirements

### Requirement: A required user is challenged or refused, never let through
For a user who is required to use MFA, the MFA requirement policy SHALL decide as follows:
- in the stateless-authentication phase, deny with an MFA-required reason, whatever the user's enrolment;
- when no MFA method is configured, deny with an MFA-required reason;
- in the per-request phase, allow a session whose second factor is already satisfied;
- when the user has no usable enrolment (not enrolled, or enrolled only on the first factor's channel), challenge for enrolment when all of the following hold, and otherwise deny with an enrolment-required reason:
  - the enrolment path is on and has not been closed;
  - the phase is post-authentication or per-request;
  - the first factor's kind is on the path's allowlist;
  - the MFA method's channel differs from the first factor's;
- in the per-request phase, challenge for MFA;
- in the post-authentication phase, allow, leaving the login challenge to the second-factor challenge policy;
- evaluated directly in a phase it does not declare, deny with an MFA-required reason.

With the enrolment path on, the policy SHALL declare that it can raise the enrolment challenge, so that the chain can refuse to assemble without its enforcer. A failed enrolment lookup SHALL deny whether the path is on or off.

In the post-authentication phase a login's claim to have satisfied a second factor SHALL NOT be honoured. The documentation SHALL state that the second-factor challenge policy must be registered alongside this one.

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
- **WHEN** the enrolment path is on, the MFA method is an email one-time-code method, and a required, unenrolled user logs in by magic link
- **THEN** the outcome is deny with the enrolment-required reason

#### Scenario: Lookup failure with the path on
- **WHEN** the enrolment path is on and the enrolment lookup fails for a required user logging in by password
- **THEN** the outcome is deny

#### Scenario: Stateless with the path on
- **WHEN** the enrolment path is on and a required, unenrolled user authenticates with HTTP basic
- **THEN** the outcome is deny with the MFA-required reason

#### Scenario: A login claiming a satisfied second factor
- **WHEN** a required user who is not enrolled logs in by password and the login claims a satisfied second factor
- **THEN** the outcome is deny with the enrolment-required reason

#### Scenario: Flagged mid-session
- **WHEN** a user becomes required during a session that has not satisfied a second factor, and the user is enrolled on a usable method
- **THEN** the next per-request evaluation is an MFA challenge

#### Scenario: Flagged mid-session without an enrolment, path on
- **WHEN** the enrolment path is on and a user with no enrolment becomes required during a password session
- **THEN** the next per-request evaluation is a challenge of the enrolment kind

#### Scenario: Undeclared phase
- **WHEN** the policy is evaluated directly in the pre-authentication phase for a required, enrolled user
- **THEN** the outcome is deny with the MFA-required reason

### Requirement: Concurrent sessions are capped
The concurrent session policy SHALL run in the post-authentication phase, with a maximum supplied by the consumer. It SHALL deny with a too-many-sessions reason when the user already holds at least that many unexpired sessions. When counting fails, it SHALL deny with a reason wrapping the error. A maximum of zero or less SHALL fail construction.

Sessions in the enrolment-pending state SHALL count like any other unexpired session. The documentation SHALL state this as a limit: a password holder can occupy a required, unenrolled user's slots, each for at most the enrolment lifetime.

#### Scenario: At the cap
- **WHEN** a policy with a maximum of 3 evaluates a login by a user holding 3 unexpired sessions
- **THEN** post-authentication is denied as too many sessions

#### Scenario: Enrolment-only sessions count until they expire
- **WHEN** a policy with a maximum of 1 evaluates a login at 09:10 by a user holding one enrolment-only session that entered the state at 09:00, and again at 09:16, with the default enrolment lifetime
- **THEN** the 09:10 login is denied as too many sessions
- **AND** the 09:16 login is not

#### Scenario: Count failure
- **WHEN** counting sessions returns an error
- **THEN** post-authentication is denied with a reason wrapping that error

#### Scenario: Zero maximum
- **WHEN** a concurrent session policy is constructed with a maximum of 0
- **THEN** construction fails with a configuration error
