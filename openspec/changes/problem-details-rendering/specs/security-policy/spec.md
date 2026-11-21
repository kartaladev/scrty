## MODIFIED Requirements

### Requirement: Policies run only in the phases they declare
The policy engine SHALL evaluate, for a given phase, only the policies that declare that phase, in the order they were registered. The phases SHALL be pre-authentication, post-authentication, per-request, post-handler and stateless authentication. A phase with no declaring policies SHALL evaluate to allow. A consumer policy's deny reason SHALL be returned unchanged when its chain can be walked; when it cannot, the library's fixed error SHALL stand in its place, as the http-error-propagation capability requires, and the outcome SHALL still be a deny.

#### Scenario: Other phases are not evaluated
- **WHEN** a lockout policy declaring pre-authentication and a password-age policy declaring post-authentication are registered, and the pre-authentication phase is evaluated
- **THEN** only the lockout policy runs

#### Scenario: Empty phase
- **WHEN** the stateless-authentication phase is evaluated and no policy declares it
- **THEN** the outcome is allow

#### Scenario: Consumer policy
- **WHEN** a consumer registers a policy of their own that declares per-request and denies requests outside office hours
- **THEN** a per-request evaluation outside office hours returns that denial and its reason unchanged

#### Scenario: Unwalkable deny reason
- **WHEN** a consumer policy denies with a reason whose chain contains itself
- **THEN** the evaluation returns a deny whose reason is the library's fixed error, without hanging
