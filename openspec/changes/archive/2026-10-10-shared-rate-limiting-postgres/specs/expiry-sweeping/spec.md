## MODIFIED Requirements

### Requirement: Expired security state is deleted through its owners
The system SHALL provide an expiry task for each of the following, and each task SHALL delete only what its owning component's purge operation deems deletable:
- expired sessions;
- magic-link tokens that are past both their expiry and their issuance window;
- one-time tokens of any other single purpose, on the same rule;
- login attempts older than the lockout window, and, with a lockout cap, consecutive failure counts inactive past the cap retention, never a hold;
- idle keys held by a rate limiter that can prune: the in-memory limiter, and the PostgreSQL limiter's table across all its namespaces;
- expired OIDC flows;
- spent or expired OIDC handoffs;
- expired one-time state the library keeps on its own behalf: passkey ceremony challenges, MFA challenges, and account-recovery issued codes and hold tokens, each through the component that owns it.

API keys, OIDC links, MFA enrolments, passkey credentials (pending or active), account-recovery records, signing keys and identity records SHALL NOT be deleted by any expiry task. Each built-in task SHALL carry a stable default name that is used in logs, results and lock keys, and SHALL leave its scheduling interval unset.

#### Scenario: Expired and live sessions
- **WHEN** two expired sessions and one valid session exist and the session task runs
- **THEN** the two expired sessions are deleted
- **AND** the valid session remains

#### Scenario: Separate purposes stay separate
- **WHEN** one-time tokens of purposes `magic-link` and `email-change` are both past expiry and their windows, and only the `email-change` task runs
- **THEN** only the `email-change` tokens are deleted

#### Scenario: Durable records untouched
- **WHEN** every expiry task runs against stores holding an API key past its optional expiry, an OIDC link, an MFA enrolment and a signing key
- **THEN** none of them is deleted

#### Scenario: Unauthenticated ceremony state is swept
- **WHEN** strangers made passwordless passkey begins whose challenges have expired and passed their issuance window, and the passkey component's tasks run
- **THEN** those challenges are deleted
- **AND** a challenge issued within its window is kept

#### Scenario: Only enabled components contribute tasks
- **WHEN** a chain enables MFA with the passkey challenge method and does not enable account recovery
- **THEN** the chain's expiry tasks include the passkey challenge task and no recovery task

#### Scenario: A factor with no challenge state contributes no task
- **WHEN** a chain enables MFA with only the TOTP method, which keeps no pending challenge
- **THEN** the chain contributes no MFA challenge task

#### Scenario: Consumer task for their own state
- **WHEN** a consumer adds a task with their own name and purge operation for a table they own
- **THEN** the runner runs it with the same isolation and reporting as the built-in tasks

#### Scenario: Consumer renames a built-in task
- **WHEN** a consumer schedules two in-memory rate limiters and renames one task `ratelimit:apikey`
- **THEN** both tasks run and are reported under their own names

#### Scenario: One task prunes the PostgreSQL limiter table
- **WHEN** a PostgreSQL limiter factory has built limiters for several namespaces, idle keys exist in each, and its rate-limiter task runs
- **THEN** the idle keys of every namespace are removed
- **AND** a key whose newest failure is inside the longest window recorded for it is kept
