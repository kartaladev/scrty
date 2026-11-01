# Spec Delta

## MODIFIED Requirements

### Requirement: Concurrent sessions are capped
The concurrent session policy SHALL run in the post-authentication phase, with a maximum supplied by the consumer. It SHALL deny with a too-many-sessions reason when the user already holds at least that many unexpired sessions. When counting fails, it SHALL deny with a reason wrapping the error. A maximum of zero or less SHALL fail construction. When the input marks the evaluation as the re-authentication of an existing session, that session is already among those counted and no session is added, so the policy SHALL deny only when the user holds more than the maximum.

Sessions in the enrolment-pending state SHALL count like any other unexpired session. The documentation SHALL state this as a limit: a password holder can occupy a required, unenrolled user's slots, each for at most the enrolment lifetime.

#### Scenario: At the cap
- **WHEN** a policy with a maximum of 3 evaluates a login by a user holding 3 unexpired sessions
- **THEN** post-authentication is denied as too many sessions

#### Scenario: A re-authentication at the cap
- **WHEN** a policy with a maximum of 3 evaluates the re-authentication of one of the 3 unexpired sessions a user holds
- **THEN** post-authentication is allowed

#### Scenario: A re-authentication above the cap
- **WHEN** a policy with a maximum of 3 evaluates the re-authentication of a session of a user holding 4 unexpired sessions
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
