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
- It SHALL deny with an account-locked reason while the submitted identifier owes a wait or has reached the ceiling, as the escalating-wait and ceiling requirements state, counting failures recorded strictly within the window before now.
- Failures SHALL be recorded, and cleared after a successful authentication, through the attempt store.
- If the attempt store fails, the policy SHALL deny with a reason wrapping the store's error.
- The defaults SHALL be a threshold of 5, a window of 24 hours, a first wait of 30 seconds, a longest wait of 1 hour, a ceiling of 100 and an in-memory attempt store, each replaceable by an option.
- Construction SHALL fail with a configuration error for a threshold, window or first wait of zero or less, a longest wait shorter than the first, or a ceiling not above the threshold.

#### Scenario: At the threshold
- **WHEN** five failures for `ada` were recorded in the last 24 hours, the newest 10 seconds ago
- **THEN** pre-authentication for `ada` is denied as locked

#### Scenario: Reset on success
- **WHEN** four failures for `ada` were recorded, then cleared after a successful authentication, and one more failure is recorded
- **THEN** pre-authentication for `ada` is allowed

#### Scenario: Store failure
- **WHEN** the attempt store returns an error while counting
- **THEN** pre-authentication is denied with a reason wrapping that error

#### Scenario: Consumer threshold
- **WHEN** the policy is configured with a threshold of 3, and three failures for `ada` were recorded in the window, the newest 10 seconds ago
- **THEN** pre-authentication for `ada` is denied as locked

#### Scenario: Zero window
- **WHEN** a lockout policy is constructed with a zero window
- **THEN** construction fails with a configuration error

#### Scenario: Ceiling not above the threshold
- **WHEN** a lockout policy is constructed with a threshold of 5 and a ceiling of 5
- **THEN** construction fails with a configuration error

### Requirement: Purging attempts cannot disarm lockout
The lockout policy SHALL purge stale attempts using a cutoff derived only from its own window, so that no caller can supply a different one. Only attempts recorded strictly before now minus the window SHALL be removed. When a cap is configured, the purge SHALL also remove consecutive counts whose newest failure is strictly before now minus the retention, and SHALL never remove a hold. When the configured attempt store cannot purge, the purge SHALL fail with a purge-unsupported error rather than report zero removed. An attempt store SHALL refuse a zero cutoff and delete nothing.

#### Scenario: Recent attempts survive a purge
- **WHEN** failures for `ada` were recorded 5 and 20 minutes ago with a 15-minute window, and the policy purges through a store that can purge
- **THEN** only the 20-minute-old failure is removed

#### Scenario: Default in-memory store
- **WHEN** a policy using the default in-memory attempt store purges
- **THEN** the purge-unsupported error is returned

#### Scenario: Zero cutoff
- **WHEN** an attempt store that can purge is asked to delete attempts before the zero time
- **THEN** it refuses and deletes nothing

#### Scenario: Inactive counts are purged, holds are kept
- **WHEN** the policy is configured with a cap of 100 and the default retention, `ada` has a count of ten with its newest failure 31 days ago, `bob` became held 31 days ago, and the policy purges through a store that can purge
- **THEN** the count for `ada` is removed, and `bob` is still held

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

### Requirement: A locked account waits, and the wait escalates
By default, once an identifier has at least the threshold number of failures in the window, the policy SHALL deny it while its newest failure is more recent than the wait it owes. The wait SHALL be the first wait doubled once for each failure beyond the threshold, and SHALL NOT exceed the longest wait. Once the wait has passed, the next attempt SHALL be allowed.

#### Scenario: First wait
- **WHEN** five failures for `ada` were recorded, the newest 29 seconds ago
- **THEN** pre-authentication for `ada` is denied as locked

#### Scenario: First wait served
- **WHEN** five failures for `ada` were recorded, the newest 31 seconds ago
- **THEN** pre-authentication for `ada` is allowed

#### Scenario: Doubled wait
- **WHEN** seven failures for `ada` were recorded, the newest 100 seconds ago
- **THEN** pre-authentication for `ada` is denied as locked, because the wait owed is 120 seconds

#### Scenario: Longest wait
- **WHEN** twenty failures for `ada` were recorded in the last 24 hours, the newest 61 minutes ago
- **THEN** pre-authentication for `ada` is allowed

### Requirement: An account at the ceiling is refused until its failures age out
By default, an identifier with at least the ceiling number of failures in the window SHALL be denied with an account-locked reason however long ago its newest failure was, until enough failures leave the window or a successful authentication clears them. The ceiling SHALL count only failures in the window. The documentation SHALL state that the ceiling limits failures per window, not consecutive failures in total, and that it does not disable the authenticator until it is bound again.

#### Scenario: One hundred failures
- **WHEN** one hundred failures for `ada` were recorded in the last 24 hours, the newest 2 hours ago
- **THEN** pre-authentication for `ada` is denied as locked

#### Scenario: Consumer ceiling
- **WHEN** the policy is configured with a ceiling of 20, and twenty failures for `ada` were recorded in the window, the newest 2 hours ago
- **THEN** pre-authentication for `ada` is denied as locked

#### Scenario: Failures outside the window do not count toward the ceiling
- **WHEN** twenty-four failures for `ada` were recorded on each of the last five days, none cleared, and the newest 2 hours ago
- **THEN** pre-authentication for `ada` is allowed, although more than one hundred failures were recorded in total

### Requirement: A sliding lock is available as an option
A consumer SHALL be able to choose a sliding lock in place of the escalating wait, with its own threshold and window: an identifier SHALL be denied while at least that threshold of failures falls in that window, whenever its newest failure was. Combining it with any threshold, window, wait or ceiling option SHALL be a configuration error. The documentation SHALL state that it limits the failure rate and holds no lock of fixed duration.

#### Scenario: Sliding lock
- **WHEN** the policy is configured with a sliding lock of 5 failures in 15 minutes, and five failures for `ada` were recorded, the newest 10 minutes ago
- **THEN** pre-authentication for `ada` is denied as locked

#### Scenario: Sliding lock lifts when the oldest failure leaves the window
- **WHEN** the policy is configured with a sliding lock of 5 failures in 15 minutes, and five failures for `ada` were recorded 15 minutes 1 second, 14, 10, 5 and 1 minute ago
- **THEN** pre-authentication for `ada` is allowed

#### Scenario: Sliding lock with a wait option
- **WHEN** the policy is configured with a sliding lock and a first wait
- **THEN** construction fails with a configuration error

### Requirement: An account-locked refusal states the wait it owes
An account-locked reason SHALL be identifiable as the account-locked refusal, and SHALL carry the wait the identifier owes when that is known: the full escalated wait, which is an upper bound on what remains. At the ceiling and under a sliding lock it SHALL carry no wait.

#### Scenario: Wait carried
- **WHEN** pre-authentication for `ada` is denied with seven failures recorded
- **THEN** the reason is the account-locked refusal and carries a wait of 120 seconds

#### Scenario: Ceiling carries none
- **WHEN** pre-authentication for `ada` is denied at the ceiling
- **THEN** the reason is the account-locked refusal and carries no wait

#### Scenario: Sliding lock carries none
- **WHEN** pre-authentication for `ada` is denied under a sliding lock
- **THEN** the reason is the account-locked refusal and carries no wait

### Requirement: A lock of fixed duration is an escalating wait that does not escalate
When the first and longest waits are equal, an identifier with at least the threshold of failures in the window SHALL be denied for exactly that wait after its newest failure, and allowed from the instant the wait has passed. Each further failure while the count stays at or above the threshold SHALL lock it again for the same wait. The documentation SHALL present this as the way to configure a lock of fixed duration.

#### Scenario: Locked for the whole duration
- **WHEN** the policy is configured with a first and longest wait of 15 minutes, and five failures for `ada` were recorded, the newest 14 minutes 59 seconds ago
- **THEN** pre-authentication for `ada` is denied as locked, and the reason carries a wait of 15 minutes

#### Scenario: Allowed when the duration has passed
- **WHEN** the policy is configured with a first and longest wait of 15 minutes, and five failures for `ada` were recorded, the newest exactly 15 minutes ago
- **THEN** pre-authentication for `ada` is allowed

#### Scenario: A further failure locks again for the full duration
- **WHEN** the policy is configured with a first and longest wait of 15 minutes, and six failures for `ada` were recorded in the window, the newest 14 minutes ago
- **THEN** pre-authentication for `ada` is denied as locked, and the reason carries a wait of 15 minutes

### Requirement: Lockout transitions can be observed
By default, the lockout policy SHALL report nothing. A consumer SHALL be able to supply an observer, told of every recorded failure that leaves its identifier locked (owing a wait, at the ceiling, or under the sliding lock), of the failure that makes an identifier held, of every clearing of an identifier that had failures in the window, and of every clearing that lifts a hold. Each report SHALL carry the identifier as submitted, the kind, the failure count and the time. The observer SHALL NOT be able to change any decision or error.

#### Scenario: No observer by default
- **WHEN** a policy built with no observer records a fifth failure for `ada`
- **THEN** the failure is recorded and nothing else is reported

#### Scenario: Threshold reached
- **WHEN** the consumer supplies an observer, and four failures then a fifth for `ada` are recorded within the window
- **THEN** the observer is told nothing for the first four, and is told that `ada` is locked with five failures at the time of the fifth

#### Scenario: Each further locking failure is reported
- **WHEN** the consumer supplies an observer, `ada` has five failures in the window, and a sixth is recorded
- **THEN** the observer is told that `ada` is locked with six failures

#### Scenario: Ceiling reached
- **WHEN** the consumer supplies an observer, and a hundredth failure for `ada` is recorded within the window
- **THEN** the observer is told that `ada` is at the ceiling with one hundred failures

#### Scenario: Cleared
- **WHEN** the consumer supplies an observer, `ada` has three failures in the window, and its failures are cleared
- **THEN** the observer is told that `ada` was cleared

#### Scenario: Clearing nothing is not reported
- **WHEN** the consumer supplies an observer, `ada` has no failures in the window, and its failures are cleared
- **THEN** the observer is told nothing

#### Scenario: Unknown and known identifiers are reported alike
- **WHEN** the consumer supplies an observer, and five failures are recorded for `ada`, which has an account, and five for `nobody`, which does not
- **THEN** the observer is told that each is locked, in the same form

#### Scenario: Held
- **WHEN** the consumer supplies an observer, the policy is configured with a cap of 20, and the twentieth consecutive failure for `ada` is recorded
- **THEN** the observer is told that `ada` is held with twenty failures, once

#### Scenario: Hold lifted
- **WHEN** the consumer supplies an observer, `ada` is held, and its failures are cleared
- **THEN** the observer is told that the hold on `ada` was lifted

### Requirement: An opt-in cap holds an identifier after consecutive failures
By default the lockout policy SHALL have no cap. A consumer SHALL be able to set a cap. Once the failures recorded for an identifier since it was last cleared reach the cap, whatever their age, the identifier SHALL be held: every pre-authentication for it SHALL be denied as locked, however long ago its newest failure was. A named constant SHALL give NIST's limit of 100. The documentation SHALL state that a cap above 100 is outside that limit.

#### Scenario: No cap by default
- **WHEN** a policy with default options has recorded twenty failures for `ada` on each of the last five days, none cleared, the newest 2 hours ago
- **THEN** pre-authentication for `ada` is allowed

#### Scenario: Cap reached across days
- **WHEN** the policy is configured with a cap of 100, and twenty failures for `ada` were recorded on each of five days, none cleared, the newest 3 days ago
- **THEN** pre-authentication for `ada` is denied as locked

#### Scenario: Consumer cap
- **WHEN** the policy is configured with a cap of 20, and twenty failures for `ada` were recorded over two days, none cleared
- **THEN** pre-authentication for `ada` is denied as locked

#### Scenario: Below the cap
- **WHEN** the policy is configured with a cap of 100, and ninety-nine failures for `ada` were recorded over five days, none cleared, the newest 2 days ago
- **THEN** pre-authentication for `ada` is allowed

#### Scenario: Unknown identifiers are held alike
- **WHEN** the policy is configured with a cap of 20, and twenty failures are recorded for `ada`, which has an account, and twenty for `nobody`, which does not
- **THEN** pre-authentication for each is denied with the same refusal

### Requirement: A hold is lifted only by clearing the identifier
A hold SHALL NOT lift with time. It SHALL lift only when the identifier's failures are cleared through its attempt store: by a password change through the chain, or by the policy's reset, which the documentation SHALL present as the unlock for an administrator. A held identifier SHALL be denied before its password is checked, so a correct password SHALL NOT lift a hold. Clearing SHALL remove the hold, the consecutive count and the failures in the window together.

#### Scenario: A hold outlives every window
- **WHEN** the policy is configured with a cap of 100, `ada` was held 90 days ago, and nothing has cleared it
- **THEN** pre-authentication for `ada` is denied as locked

#### Scenario: The correct password does not lift a hold
- **WHEN** `ada` is held, and pre-authentication runs for a login presenting `ada`'s correct password
- **THEN** it is denied as locked, and `ada` is still held

#### Scenario: Reset unlocks
- **WHEN** `ada` is held and also has one hundred failures in the window, and the policy's reset is called for `ada`
- **THEN** pre-authentication for `ada` is allowed

### Requirement: A count below the cap expires after inactivity
A consecutive count whose newest failure is older than the retention period SHALL no longer be counted, and the next failure SHALL start a new count. The retention SHALL be 30 days by default, replaceable by an option. A hold SHALL never expire this way.

#### Scenario: Inactive count restarts
- **WHEN** the policy is configured with a cap of 100, ninety-nine failures for `ada` were recorded, the newest 31 days ago, and one more is recorded now
- **THEN** pre-authentication for `ada` is allowed, and the consecutive count for `ada` is one

#### Scenario: Consumer retention
- **WHEN** the policy is configured with a cap of 100 and a retention of 7 days, ninety-nine failures for `ada` were recorded, the newest 8 days ago, and one more is recorded now
- **THEN** pre-authentication for `ada` is allowed

#### Scenario: A hold does not expire
- **WHEN** the policy is configured with a cap of 100, and `ada` became held 31 days ago
- **THEN** pre-authentication for `ada` is denied as locked

### Requirement: A held refusal is identifiable as a hold
A refusal of a held identifier SHALL be the account-locked refusal, SHALL carry no wait, and SHALL also be identifiable as a hold, so a consumer can tell the user to reset their password. When the record of held identifiers cannot be read, pre-authentication SHALL be denied with a reason wrapping the store's error.

#### Scenario: Held refusal
- **WHEN** pre-authentication for a held `ada` is denied
- **THEN** the reason is the account-locked refusal, is identifiable as a hold, and carries no wait

#### Scenario: A windowed lock is not a hold
- **WHEN** the policy is configured with a cap of 100, and pre-authentication for `ada` is denied with seven failures in the window and none before
- **THEN** the reason is the account-locked refusal and is not identifiable as a hold

#### Scenario: Unreadable hold
- **WHEN** the policy is configured with a cap, and the store fails while reading whether `ada` is held
- **THEN** pre-authentication for `ada` is denied with a reason wrapping that error

### Requirement: Concurrent failures cannot pass the cap without a hold
The consecutive count SHALL be advanced by one atomic write per failure. However many failures for one identifier are recorded at once, none SHALL be lost, and the identifier SHALL become held exactly once, by the failure that reaches the cap.

#### Scenario: Burst across the cap
- **WHEN** the policy is configured with a cap of 100, `ada` has ninety failures, and twenty failures for `ada` are recorded concurrently
- **THEN** the consecutive count for `ada` is one hundred and ten, `ada` is held, and the hold was set once

### Requirement: A cap is refused unless its wiring can enforce it
Construction SHALL fail with a configuration error, naming the option, when:
- a cap is set and the attempt store cannot keep consecutive counts and holds;
- the cap is not above the threshold;
- a retention is zero or less, given without a cap, or shorter than the lockout window.

#### Scenario: Store without consecutive counts
- **WHEN** a policy is configured with a cap and an attempt store that keeps no consecutive counts
- **THEN** construction fails with a configuration error naming the cap option

#### Scenario: Retention without a cap
- **WHEN** a policy is configured with a retention and no cap
- **THEN** construction fails with a configuration error

#### Scenario: Cap at the threshold
- **WHEN** a policy is configured with a threshold of 5 and a cap of 5
- **THEN** construction fails with a configuration error
