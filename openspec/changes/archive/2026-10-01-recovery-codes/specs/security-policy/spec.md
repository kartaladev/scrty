# Spec Delta

## MODIFIED Requirements

### Requirement: The enrolment path admits first factors by an allowlist of kinds
The enrolment path SHALL admit a login only when its first-factor kind is on the path's allowlist. By default the allowlist SHALL be password, magic link, account recovery and an unrecorded first factor. A session produced by an account recovery rests on two proofs of different kinds and exists to bind a new authenticator, so it is admitted by default. OIDC SHALL be off it by default. A consumer SHALL be able to replace the allowlist by an option; the option SHALL replace the list, not add to it. Listing the API-key or basic first factor SHALL fail construction with a configuration error, because those logins are stateless or exempt and have no session to confine. An empty allowlist SHALL fail construction with a configuration error, because a path that admits nothing would still declare the enrolment challenge and demand an enforcer no login can reach. The allowlist SHALL govern only entry to the path: it SHALL NOT change whether a user is required to use MFA, or which first factors are exempt. The documentation of adding OIDC SHALL state that a stolen provider account usually includes its mailbox, so the emailed code adds no assurance there.

#### Scenario: Password is on the default list
- **WHEN** the path is on and a required, unenrolled user logs in by password
- **THEN** the outcome is a challenge of the enrolment kind

#### Scenario: Recovery is on the default list
- **WHEN** the path is on and a required user left with no usable second factor holds a session produced by an account recovery
- **THEN** the outcome is a challenge of the enrolment kind, not deny

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
