# Spec Delta

## ADDED Requirements

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

## MODIFIED Requirements

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
