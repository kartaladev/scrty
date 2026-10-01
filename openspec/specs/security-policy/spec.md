# security-policy Specification

## Purpose

Applies a deployment's security rules at defined points in a request's life (lockout, idle timeout, password age, concurrent sessions, second factors and the MFA requirement), each returning allow, deny or challenge, and failing closed wherever a rule cannot decide.

## Requirements

### Requirement: Policies run only in the phases they declare
The policy engine SHALL evaluate, for a given phase, only the policies that declare that phase, in the order they were registered. The phases SHALL be pre-authentication, post-authentication, per-request, post-handler and stateless authentication. A phase with no declaring policies SHALL evaluate to allow.

#### Scenario: Other phases are not evaluated
- **WHEN** a lockout policy declaring pre-authentication and a password-age policy declaring post-authentication are registered, and the pre-authentication phase is evaluated
- **THEN** only the lockout policy runs

#### Scenario: Empty phase
- **WHEN** the stateless-authentication phase is evaluated and no policy declares it
- **THEN** the outcome is allow

#### Scenario: Consumer policy
- **WHEN** a consumer registers a policy of their own that declares per-request and denies requests outside office hours
- **THEN** a per-request evaluation outside office hours returns that denial and its reason unchanged

### Requirement: Deny outranks challenge, which outranks allow
Within a phase, the first deny SHALL end evaluation and be returned. A challenge SHALL be held while later policies run, so a later deny still wins. When no policy denies, the first challenge in registration order SHALL be returned, and otherwise allow.

An outcome the engine does not recognise SHALL be treated as a deny. A policy that returned one cannot be shown to have permitted the request, and passing it over would let a policy that meant to refuse be ignored.

#### Scenario: Locked account beats an MFA prompt
- **WHEN** in one phase a policy challenging for MFA is registered before a policy that denies
- **THEN** the deny is returned

#### Scenario: First challenge wins
- **WHEN** a policy challenging for MFA is registered before one challenging for a password change, and neither denies
- **THEN** the MFA challenge is returned

#### Scenario: An unrecognised outcome
- **WHEN** a policy returns an outcome that is neither allow, deny nor challenge
- **THEN** the phase evaluates to deny with the generic policy-denied reason

### Requirement: A deny always carries a reason
When a policy returns a deny without a reason, the engine SHALL substitute a generic policy-denied reason. That way, a caller that refuses a request by returning the reason as its error can never return nothing for a deny. Registering an absent policy SHALL fail with a configuration error.

#### Scenario: Reasonless deny
- **WHEN** a consumer policy in the stateless-authentication phase returns a deny with no reason
- **THEN** the phase evaluates to deny with the generic policy-denied reason

#### Scenario: Absent policy
- **WHEN** an engine is constructed with an absent policy
- **THEN** construction fails with a configuration error

### Requirement: Policies are told which phase they are being asked in
The engine SHALL make the phase it is evaluating available to every policy it evaluates, so that a policy whose decision depends on the phase can tell one from another. The facts the engine reports about the request SHALL reach every policy unchanged, so that each judges the same request against the same instant.

A policy whose decision depends on the phase SHALL fail closed when no phase can be identified, rather than assume one. A consumer SHALL be able to replace how such a policy learns the phase, and a replacement that cannot identify a phase SHALL be treated as none.

#### Scenario: A phase-dependent policy is challenged mid-session
- **WHEN** a user who is required to use MFA, is enrolled on a usable method, and has not satisfied a second factor is evaluated through an engine in the per-request phase
- **THEN** the outcome is an MFA challenge

#### Scenario: The same user after authenticating
- **WHEN** that same user is evaluated through an engine in the post-authentication phase
- **THEN** the outcome is allow, leaving the login challenge to the second-factor challenge policy

#### Scenario: No phase can be identified
- **WHEN** the MFA requirement policy is evaluated directly, outside an engine, with no phase available
- **THEN** the outcome is deny with the MFA-required reason

#### Scenario: Consumer supplies the phase
- **WHEN** a consumer configures the MFA requirement policy with a rule of their own that derives the phase from the request
- **THEN** that rule decides the phase instead of the engine's

### Requirement: Accounts lock after repeated failures
The account lockout policy SHALL run in the pre-authentication phase.
- It SHALL deny with an account-locked reason when the submitted identifier has at least the threshold number of failures recorded strictly within the window before now.
- Failures SHALL be recorded, and cleared after a successful authentication, through the attempt store.
- If the attempt store fails, the policy SHALL deny with a reason wrapping the store's error.
- The defaults SHALL be a threshold of 5, a window of 15 minutes and an in-memory attempt store, each replaceable by an option.
- Construction SHALL fail with a configuration error for a threshold or window of zero or less.

#### Scenario: At the threshold
- **WHEN** five failures for `ada` were recorded in the last 15 minutes
- **THEN** pre-authentication for `ada` is denied as locked

#### Scenario: Reset on success
- **WHEN** four failures for `ada` were recorded, then cleared after a successful authentication, and one more failure is recorded
- **THEN** pre-authentication for `ada` is allowed

#### Scenario: Store failure
- **WHEN** the attempt store returns an error while counting
- **THEN** pre-authentication is denied with a reason wrapping that error

#### Scenario: Consumer threshold
- **WHEN** the policy is configured with a threshold of 3, and three failures for `ada` were recorded in the window
- **THEN** pre-authentication for `ada` is denied as locked

#### Scenario: Zero window
- **WHEN** a lockout policy is constructed with a zero window
- **THEN** construction fails with a configuration error

### Requirement: Purging attempts cannot disarm lockout
The lockout policy SHALL purge stale attempts using a cutoff derived only from its own window, so that no caller can supply a different one. Only attempts recorded strictly before now minus the window SHALL be removed. When the configured attempt store cannot purge, the purge SHALL fail with a purge-unsupported error rather than report zero removed. An attempt store SHALL refuse a zero cutoff and delete nothing.

#### Scenario: Recent attempts survive a purge
- **WHEN** failures for `ada` were recorded 5 and 20 minutes ago with a 15-minute window, and the policy purges through a store that can purge
- **THEN** only the 20-minute-old failure is removed

#### Scenario: Default in-memory store
- **WHEN** a policy using the default in-memory attempt store purges
- **THEN** the purge-unsupported error is returned

#### Scenario: Zero cutoff
- **WHEN** an attempt store that can purge is asked to delete attempts before the zero time
- **THEN** it refuses and deletes nothing

### Requirement: Idle sessions are denied per request
The idle timeout policy SHALL run in the per-request phase. It SHALL deny with a session-idle reason when the time since the session's last access exceeds the idle timeout. A zero last-access time SHALL be allowed, and this SHALL be documented. The policy SHALL also supply the idle and absolute deadlines for a session created at a given time.

The defaults SHALL be an idle timeout of 30 minutes and an absolute timeout of 12 hours, replaceable by options. Construction SHALL fail with a configuration error when either is zero or less.

#### Scenario: Idle too long
- **WHEN** a session last accessed at 09:00 is evaluated at 09:31 with default options
- **THEN** the request is denied as idle

#### Scenario: Consumer idle timeout
- **WHEN** the policy is configured with a 10-minute idle timeout, and a session last accessed at 09:00 is evaluated at 09:11
- **THEN** the request is denied as idle

### Requirement: Old passwords are challenged at login
The password age policy SHALL run in the post-authentication phase. It SHALL challenge for a password change when the time since the password was last changed exceeds the maximum age. The default maximum age SHALL be 90 days, replaceable by an option, and a maximum age of zero or less SHALL fail construction.

By default, an unknown password change time SHALL be allowed. The policy's documentation SHALL state that it enforces nothing for users whose change time is never recorded. A consumer SHALL be able to choose to challenge unknown change times instead.

#### Scenario: Expired password
- **WHEN** a login occurs for a password last changed 91 days ago
- **THEN** the outcome is a password-change challenge

#### Scenario: Unknown change time by default
- **WHEN** a login occurs for a user whose password change time is unknown
- **THEN** the outcome is allow

#### Scenario: Consumer challenges unknown change times
- **WHEN** the policy is configured to challenge unknown change times, and a login occurs for a user whose change time is unknown
- **THEN** the outcome is a password-change challenge

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

### Requirement: The enrolment lookup fails closed
The MFA policies SHALL consult, for each configured method, an enrolment lookup that, for a user, reports enrolled, not enrolled, or an error.
- The lookup SHALL report enrolled only for an enrolment that has been confirmed and whose secret can be read.
- An enrolment that has been started but not confirmed SHALL be reported as not enrolled.
- A store failure, or a stored secret that cannot be read (for example because it cannot be decrypted), SHALL be reported as an error and never as not enrolled.
- The MFA policies SHALL treat a lookup error on any method as a refusal, even when another method reports the user enrolled, so a lost or unreadable enrolment never downgrades a user to single-factor.

#### Scenario: Unreadable secret
- **WHEN** a required user's stored enrolment secret cannot be decrypted, and the user logs in by password
- **THEN** the lookup reports an error
- **AND** the login is denied rather than completed on the first factor

#### Scenario: Unconfirmed enrolment
- **WHEN** a user started enrolment but never confirmed it, and logs in by password
- **THEN** the lookup reports not enrolled

#### Scenario: Store outage
- **WHEN** the enrolment store returns a connection error during a password login for an enrolled user
- **THEN** the second-factor challenge policy denies with a reason wrapping that error

#### Scenario: One method's lookup fails
- **WHEN** a user enrolled on TOTP logs in by password and the lookup of a second configured method fails
- **THEN** the second-factor challenge policy denies with a reason wrapping that failure

### Requirement: Enrolled users are challenged for a second factor
The second-factor challenge policy SHALL be constructed with the set of configured MFA methods and SHALL run in the post-authentication phase. It SHALL allow exempt first factors, and logins that have already satisfied a second factor. For every other login it SHALL:
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

#### Scenario: Lookup failure
- **WHEN** the enrolment lookup fails
- **THEN** the outcome is deny with a reason wrapping the failure

#### Scenario: No methods
- **WHEN** the policy is constructed with an empty set of methods
- **THEN** construction fails with a configuration error

### Requirement: A second factor on the first factor's channel is an explicit decision, refused by default
A user who is not required to use MFA may be enrolled only on methods whose channel equals the login's first-factor channel. For such a login, the second-factor challenge policy SHALL, by default, deny with a same-channel reason and write a sampled warning.

A consumer SHALL be able to choose instead to complete such logins on the first factor. In that case the policy SHALL allow, SHALL NOT mark a second factor as satisfied, and SHALL still write a sampled warning naming the same-channel completion. Neither choice SHALL complete the login without a log record.

A user enrolled on at least one method on a different channel SHALL be challenged, whatever else they are enrolled on. A user who is required to use MFA SHALL be governed by the MFA requirement policy and SHALL NOT be affected by this choice.

#### Scenario: Default refusal
- **WHEN** a magic-link login occurs for a user who is not required to use MFA and is enrolled only on an email one-time-code method
- **THEN** the outcome is deny with the same-channel reason
- **AND** a warning is written through the sampler

#### Scenario: Consumer completes on the first factor
- **WHEN** the policy is configured to complete same-channel logins on the first factor, and the same login occurs
- **THEN** the outcome is allow
- **AND** no second factor is recorded as satisfied
- **AND** a same-channel completion warning is written through the sampler

#### Scenario: Different channel is unaffected
- **WHEN** a password login occurs for a user enrolled only on an email one-time-code method
- **THEN** the outcome is an MFA challenge

#### Scenario: A usable method alongside a same-channel one
- **WHEN** a magic-link login occurs for a user enrolled on an email one-time-code method and on TOTP
- **THEN** the outcome is an MFA challenge

### Requirement: The MFA requirement is looked up per user or applied to all
The MFA requirement policy SHALL decide whether a user must use a second factor, either by the per-user requirement lookup or, when configured to require MFA for all, for every non-exempt user without consulting the lookup. First factors that the identity model marks as exempt from local MFA SHALL be allowed before any lookup. A request with no recorded first factor, or with an unrecognised kind, SHALL be enforced and SHALL NOT be treated as exempt. A consumer SHALL be able to replace the exemption rule.

When the lookup fails, the policy SHALL deny with the failure as its reason. It SHALL NOT allow.

The policy SHALL be constructed with the set of configured MFA methods, which MAY be empty. Construction SHALL fail with a configuration error:
- when there is no lookup and the policy is not configured to require MFA for all;
- when it is configured to require MFA for all but the set of MFA methods is empty;
- when the set contains an absent method or two methods of the same name.

#### Scenario: Flagged user
- **WHEN** the lookup reports that user `u-1` is required, and `u-1` logs in by password
- **THEN** the requirement applies to `u-1`

#### Scenario: Required for all
- **WHEN** the policy is configured to require MFA for all and the lookup would report `u-2` as not required
- **THEN** the requirement applies to `u-2`
- **AND** the lookup is not consulted

#### Scenario: Lookup failure fails closed
- **WHEN** the requirement lookup returns an error for a password login
- **THEN** the outcome is deny with that error as its reason

#### Scenario: No lookup and not required for all
- **WHEN** the policy is constructed without a lookup and without requiring MFA for all
- **THEN** construction fails with a configuration error

#### Scenario: Required for all with no methods
- **WHEN** the policy is configured to require MFA for all with an empty set of methods
- **THEN** construction fails with a configuration error

### Requirement: A required user is challenged or refused, never let through
For a user who is required to use MFA, the MFA requirement policy SHALL decide as follows:
- in the stateless-authentication phase, deny with an MFA-required reason, whatever the user's enrolment;
- when no MFA method is configured, deny with an MFA-required reason;
- in the per-request phase, allow a session whose second factor is already satisfied;
- when any configured method's enrolment lookup fails, deny;
- when the user can use no configured method (enrolled on none, or only on methods on the first factor's channel), challenge for enrolment when all of the following hold, and otherwise deny with an enrolment-required reason:
  - the enrolment path is on and has not been closed;
  - the phase is post-authentication or per-request;
  - the first factor's kind is on the path's allowlist;
  - at least one configured method supports the enrolment path and has a channel that differs from the first factor's;
- in the per-request phase, challenge for MFA;
- in the post-authentication phase, allow, leaving the login challenge to the second-factor challenge policy;
- evaluated directly in a phase it does not declare, deny with an MFA-required reason.

With the enrolment path on, the policy SHALL declare that it can raise the enrolment challenge, so that the chain can refuse to assemble without its enforcer. A failed enrolment lookup SHALL deny whether the path is on or off.

In the post-authentication phase a login's claim to have satisfied a second factor SHALL NOT be honoured. The documentation SHALL state that the second-factor challenge policy must be registered alongside this one, over the same methods.

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

### Requirement: Policy refusal logs are sampled per subsystem
Each policy that logs refusals SHALL write them through its own log sampler, with a reporter that writes a summary record of each suppressed count, and SHALL expose a flush that reports pending counts.

The sampling window SHALL default to one minute and be configurable by an option named for that policy alone. A window of zero or less SHALL log every refusal.

The MFA requirement policy SHALL sample its lookup-failure record under one key shared by all users. A lookup that failed because the request's context had ended SHALL be logged at debug level without sampling.

#### Scenario: Lookup outage
- **WHEN** 1,000 requirement lookups fail within one minute for different users
- **THEN** one lookup-failure error record is written for that minute
- **AND** the reporter receives the 999 suppressed failures when the key ages out or the policy is flushed

#### Scenario: Consumer interval for one policy only
- **WHEN** the MFA requirement policy is configured with a log interval of zero, and the second-factor challenge policy keeps its default
- **THEN** every MFA requirement refusal is logged
- **AND** same-channel warnings are still sampled per minute

#### Scenario: Request ended during lookup
- **WHEN** a requirement lookup fails because the request's context was cancelled
- **THEN** a debug record is written without consulting the sampler
- **AND** the outcome is still deny

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

### Requirement: One function decides which MFA methods a user can use
The library SHALL provide one public function that, given the configured MFA methods, a user and the login's first factor, returns the methods the user can use: those the user is enrolled on whose channel differs from the first factor's channel, in the order the methods were configured. When the enrolment lookup of any method fails, the function SHALL return that error and SHALL NOT return a shorter list. The MFA policies, the verify and begin endpoints, the MFA challenge error's method list and the method-listing endpoint SHALL all decide usability through this function, so none of them can disagree with another. A consumer SHALL be able to call it to build their own listing.

#### Scenario: Usable methods in configuration order
- **WHEN** TOTP and `email-code` are configured in that order, `u-1` is enrolled on both, and `u-1` logged in by password
- **THEN** the function returns TOTP then `email-code`

#### Scenario: A method on the first factor's channel is not usable
- **WHEN** `u-1` is enrolled on TOTP and on `email-code`, and logged in by magic link
- **THEN** the function returns TOTP only

#### Scenario: A failed lookup is an error, not a shorter list
- **WHEN** `u-1` is enrolled on TOTP and the `email-code` enrolment lookup fails
- **THEN** the function returns that error
