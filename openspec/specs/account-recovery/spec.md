# account-recovery Specification

## Purpose
Lets a user who has lost the authenticators their account depends on get back in with two independent proofs, never one. The recovery is confined until a new authenticator is bound, announced to the user, and never weaker than the authentication it replaces.

## Requirements

### Requirement: Saved recovery codes carry 128 bits and are stored only as hashes
Generating a set of saved recovery codes for a user SHALL produce codes that each carry 128 bits read from the operating system's cryptographically secure random source. Each code SHALL be written as 26 characters of the Crockford base32 alphabet, which omits I, L, O and U, grouped in fours and separated by dashes. The generated length SHALL be pinned by the library's own tests, so no later change can shorten the codes silently. The store SHALL receive only the SHA-256 hash of each code's 16 bytes, and a presented code SHALL be found by that hash among the user's codes. If the random source fails, generation SHALL return an error and store nothing. No code SHALL be written to a log record or an error's text.

#### Scenario: Code shape
- **WHEN** a set is generated
- **THEN** each code is 26 Crockford base32 characters grouped in fours with dashes, and decodes to 16 bytes

#### Scenario: Only hashes at rest
- **WHEN** a set is generated and the stored records are inspected
- **THEN** each holds the SHA-256 hash of a code's 16 bytes
- **AND** no code appears in any stored record

#### Scenario: Random source failure
- **WHEN** the random source fails during generation
- **THEN** generation returns an error and the user's existing set is unchanged

#### Scenario: No codes in logs
- **WHEN** a set is generated and one of its codes is presented wrongly and then correctly
- **THEN** no written log record and no returned error's text contains any code

### Requirement: Presented codes tolerate case, dashes and look-alike characters
A presented saved code SHALL be accepted regardless of letter case and of where dashes appear. The characters `O`, `I` and `L`, in either case, SHALL be read as `0`, `1` and `1`, as Crockford base32 decoding defines. A presented value that holds any other character outside the alphabet, or that does not decode to exactly 16 bytes, SHALL be refused as an invalid code without the store being asked.

#### Scenario: Lower case without dashes
- **WHEN** a generated code is presented in lower case with its dashes removed
- **THEN** it matches that code

#### Scenario: Look-alike characters
- **WHEN** a code containing `0` and `1` is presented with `O` in place of `0` and `l` in place of `1`
- **THEN** it matches that code

#### Scenario: Malformed code
- **WHEN** a value of 25 characters, or one containing `U`, is presented
- **THEN** it is refused as an invalid code and the store receives no lookup

### Requirement: A set holds ten codes by default and is replaced as a whole
A set SHALL hold 10 codes by default. A consumer SHALL be able to replace the count by an option, and construction SHALL fail with a configuration error when the count is zero or less, or above 100. Generating a set SHALL replace the user's previous set in one store operation, so no code of the previous set remains usable afterwards, and a failure SHALL leave the previous set as it was.

#### Scenario: Default count
- **WHEN** a set is generated with default options
- **THEN** it holds 10 codes

#### Scenario: Consumer count
- **WHEN** the count is configured as 16 and a set is generated
- **THEN** it holds 16 codes

#### Scenario: Invalid count
- **WHEN** a manager is constructed with a count of 0
- **THEN** construction fails with a configuration error

#### Scenario: Regeneration voids the old set
- **WHEN** a user's set is regenerated
- **THEN** every code of the previous set is refused, spent or not

### Requirement: A saved code is spent once, and checking it spends nothing
Spending a saved code SHALL be one conditional store write that succeeds only while the code is unspent. Of any number of concurrent spends of one code, at most one SHALL succeed. A spent code SHALL be refused. Checking a code without spending it SHALL write nothing, whether it succeeds or fails. The library SHALL offer a confirmation that a user kept their set: it SHALL succeed for any unspent code of the user and SHALL spend nothing, since it is a check and not a recovery.

#### Scenario: Racing spends
- **WHEN** 16 callers spend the same unspent code at the same time
- **THEN** exactly one succeeds

#### Scenario: Spent code refused
- **WHEN** a code has been spent and is presented again
- **THEN** it is refused as an invalid code

#### Scenario: Confirmation spends nothing
- **WHEN** a user confirms they kept their set with one of its codes, and the user's remaining count is then read
- **THEN** the confirmation succeeds and the remaining count is unchanged

### Requirement: The remaining count is reported, and a low count is flagged
The library SHALL report how many unspent codes a user has. A count at or below the low threshold, 2 by default and replaceable by an option, SHALL be reported as low, in the code listing and in a recovery's result, so the consumer's interface can prompt a regeneration. The library SHALL render nothing itself. A threshold below zero SHALL fail construction.

#### Scenario: Low count
- **WHEN** a user holding 10 codes has spent 8, and their remaining count is read
- **THEN** it reports 2 remaining, flagged as low

#### Scenario: Consumer threshold
- **WHEN** the low threshold is configured as 4 and a user has 4 codes remaining
- **THEN** the count is flagged as low

### Requirement: Saved-code presentations are throttled per user
The library SHALL count failed saved-code presentations per user reference, whether in a recovery or in a confirmation. It SHALL refuse further presentations for a user at the limit with a throttled error, without looking the code up. The default SHALL be 5 failures per 15 minutes. A consumer SHALL be able to replace the limiter. A limiter that cannot decide SHALL cause the presentation to be refused. Recording a failure SHALL NOT be abandoned because the caller went away.

#### Scenario: Guessing codes
- **WHEN** five wrong codes are presented for `u-1` within 15 minutes and then a valid one is presented
- **THEN** the valid one is refused with the throttled error

#### Scenario: A client that hangs up is still charged
- **WHEN** a wrong code is presented and the request's context is already cancelled
- **THEN** the failure is still recorded against that user

#### Scenario: Consumer limiter
- **WHEN** saved-code presentation is configured with a consumer's shared limiter
- **THEN** every check and failure goes to that limiter, keyed by user reference

### Requirement: Regenerating codes needs a recent authentication and notifies the user
The endpoint that regenerates a user's set SHALL answer POST requests on its path, `/recovery/codes` by default, and SHALL be answered only for a full session: one with no pending challenge of any kind. It SHALL refuse with a reauthentication-required error unless the session's latest authentication is within the freshness window. The latest authentication is the later of the session's creation and its second-factor satisfaction. The window SHALL be 15 minutes by default, replaceable by an option, and a window of zero or less SHALL fail construction. On success it SHALL return the new codes once, through a replaceable responder, and SHALL notify the user at their contact address. The notice SHALL name the time and SHALL contain no code. The notice SHALL NOT be sent through a sender that delivers synchronously, unless the consumer explicitly accepts synchronous delivery. A GET on the same path SHALL answer any full session with the remaining count and whether it is low, and SHALL NOT return a code.

#### Scenario: Fresh session regenerates
- **WHEN** a session created at 09:00 posts to `/recovery/codes` at 09:10
- **THEN** a new set is returned once, the previous set is void, and a notice is queued to the user

#### Scenario: Stale session
- **WHEN** a session created at 09:00, whose second factor was never satisfied since, posts to `/recovery/codes` at 09:20
- **THEN** it is refused with the reauthentication-required error and the set is unchanged

#### Scenario: Consumer window
- **WHEN** the freshness window is configured as 2 hours and a session created at 09:00 posts at 10:30
- **THEN** a new set is returned

#### Scenario: Count without codes
- **WHEN** a full session sends GET `/recovery/codes`
- **THEN** the response carries the remaining count and the low flag, and no code

#### Scenario: Pending session refused
- **WHEN** a session with an MFA challenge pending posts to `/recovery/codes`
- **THEN** it is refused by the gate enforcing that challenge, and no set is generated

### Requirement: An issued recovery code is sent by email and is checked before it is consumed
When issued codes are enabled, starting a recovery for a user SHALL issue a one-time token under a recovery purpose of its own, whose subject is the user reference, and SHALL send it to the user's contact address through the configured sender. The contact address SHALL come from a contact resolver, by default the username, replaceable by the consumer. The code's lifetime SHALL be 15 minutes by default, replaceable by an option. Construction SHALL fail with a configuration error when the lifetime is zero or less, or longer than 24 hours. The message SHALL be plain text, SHALL name no product or organisation by default, and SHALL be replaceable through a message builder, while the library still sets the recipient. The issued code SHALL be checked without being spent, and SHALL be consumed only as the last step of a recovery that succeeds.

#### Scenario: Code sent to the contact address
- **WHEN** recovery is started for `u-1`, whose username is `ana@example.com`
- **THEN** a message carrying an issued code is queued to `ana@example.com`

#### Scenario: Consumer contact resolver
- **WHEN** the consumer's contact resolver returns `ana.home@example.com` for `u-1`
- **THEN** the issued code goes to `ana.home@example.com`

#### Scenario: Lifetime beyond 24 hours
- **WHEN** issued codes are configured with a 25-hour lifetime
- **THEN** construction fails with a configuration error

#### Scenario: Expired code
- **WHEN** an issued code sent at 10:00 with the default lifetime is presented at 10:16
- **THEN** it is refused as an invalid proof

### Requirement: Starting a recovery reveals nothing about the account
The start endpoint SHALL match only POST requests to its path, `/recovery/start` by default, and SHALL read the username from a form field or a JSON body. It SHALL answer with the same status and the same empty body in every case:
- a code is sent;
- the username is unknown, or names a disabled user;
- the lookup fails;
- the user's issuance limit is reached;
- the source is throttled;
- the token store or random source fails;
- the sender refuses the message;
- the body is missing or malformed.

Each cause SHALL be logged server-side only, without the username or the contact address. The sender SHALL be one that does not wait for delivery, unless the consumer explicitly accepts synchronous delivery, whose documentation SHALL state that response time then reveals which usernames have accounts. Issuance SHALL be limited per user to 5 codes within the one-time manager's issuance window by default, replaceable by an option, with a limit below 1 failing construction. Every start SHALL be counted per source through a source guard, 10 per hour by default, with a replaceable limiter.

#### Scenario: Known and unknown usernames look alike
- **WHEN** recovery is started for an active user and, separately, for a username with no account
- **THEN** both requests receive the same status and the same empty body

#### Scenario: Issuance limit reached
- **WHEN** five codes were issued for `u-1` within the last hour and recovery is started for `u-1` again
- **THEN** the caller receives the same answer as for an unknown username, and no code is issued

#### Scenario: Synchronous sender
- **WHEN** issued codes are enabled with a sender that delivers synchronously, without accepting synchronous delivery
- **THEN** construction fails with a configuration error

### Requirement: A recovery needs two proofs of different kinds
The completion endpoint SHALL match only POST requests to its path, `/recovery/complete` by default, and SHALL read the username and the proofs from form fields. It SHALL accept exactly two proofs, of different kinds, and at least one of them a recovery code:
- a saved code and an issued code;
- a saved code or an issued code, together with an authenticator the user holds: the user's password, or a code for an MFA method the user is enrolled on.

A request with one proof, with more than two, with two of the same kind, or with no recovery code SHALL be refused as a malformed recovery before any proof is checked. Each proof kind SHALL be enabled separately by the consumer, and a proof of a kind that is not enabled SHALL be refused as a malformed recovery. Only an MFA method whose response is a single form field and which has no begin step SHALL serve as a proof. The documentation SHALL state that a challenge method cannot serve as a proof. A password proof SHALL be subject to the pre-authentication policy phase, which includes lockout, and SHALL be verified by the same password authenticator as form login, recording a failed attempt as login does. An unknown username, a disabled user, and any refused proof, including a password proof refused because the account is locked, SHALL all be refused with the same recovery-refused error, unless the consumer has chosen to disclose locks.

#### Scenario: Saved and issued codes
- **WHEN** `u-1` posts a valid saved code and a valid issued code
- **THEN** the recovery succeeds

#### Scenario: Saved code and password
- **WHEN** `u-1` posts a valid saved code and their correct password
- **THEN** the recovery succeeds

#### Scenario: Issued code and TOTP
- **WHEN** `u-1`, enrolled on TOTP, posts a valid issued code and a valid TOTP code naming the `totp` method
- **THEN** the recovery succeeds

#### Scenario: An emailed code alone
- **WHEN** `u-1` posts only a valid issued code
- **THEN** it is refused as a malformed recovery and nothing is checked or spent

#### Scenario: Password and TOTP without a recovery code
- **WHEN** `u-1` posts their password and a TOTP code
- **THEN** it is refused as a malformed recovery

#### Scenario: Locked account
- **WHEN** `u-1`'s account is locked and they post a valid saved code and their password
- **THEN** the recovery is refused with the recovery-refused error, identifiable as the account-locked refusal by the consumer's error handling, the account's password is not checked, and one decoy verification is spent

#### Scenario: Locked account with locks disclosed
- **WHEN** the chain is configured to disclose locks, `u-1`'s account is locked, and they post a valid saved code and their password
- **THEN** the recovery is refused with the account-locked refusal, answered 429, and no decoy verification is spent

#### Scenario: Unknown and wrong look alike
- **WHEN** one recovery names an unknown username and another names `u-1` with a wrong saved code
- **THEN** both are refused with the same recovery-refused error

### Requirement: Every proof is checked before any is spent
A recovery SHALL proceed in this order:
1. refuse while the source or the user is throttled;
2. resolve the user;
3. check every recovery code without spending it, and verify the password;
4. run the side-effect-free checks: the reported losses and the reset plan, the risk hook, and the consumer's refusal checks;
5. spend, last: first the MFA method proof, whose verification records its time step as it accepts it, then the issued code and the saved code.

A refusal or lookup failure at any step before the last SHALL leave every recovery code redeemable. Of two racing recoveries presenting the same code, at most one SHALL succeed. A failed recovery SHALL be counted per user and per source. A refused recovery that presented a valid recovery code SHALL be counted against the source by default. A consumer SHALL be able to turn that off by an explicit option.

#### Scenario: Wrong password keeps the codes
- **WHEN** `u-1` posts a valid saved code and a wrong password, then posts the same saved code with the correct password
- **THEN** the first is refused and the second succeeds

#### Scenario: Consumer refusal keeps the codes
- **WHEN** a consumer refusal check denies `u-1`'s recovery, and the check later allows it
- **THEN** the first recovery returns the consumer's error unchanged, and the same two codes then succeed

#### Scenario: Racing recoveries
- **WHEN** two recoveries of `u-1` present the same saved and issued codes at the same time
- **THEN** exactly one succeeds

#### Scenario: Refusals count against the source
- **WHEN** a recovery presenting a valid saved code is refused by a consumer refusal check
- **THEN** a failure is recorded against the request's source

#### Scenario: Consumer turns refusal counting off
- **WHEN** refusal counting is turned off and the same recovery is refused
- **THEN** no failure is recorded against the source for it

### Requirement: A recovery spending a saved code replaces the whole set
When a recovery succeeds and one of its proofs was a saved code, the library SHALL replace the user's whole set with a new one and return the new codes once, in the recovery's result. When no saved code was spent, the result SHALL carry the user's remaining count and whether it is low. The recovery notice SHALL say that the saved codes were replaced.

#### Scenario: New set after recovery
- **WHEN** `u-1` recovers with a saved code and an issued code
- **THEN** the result carries a new set of 10 codes, and every code of the old set is refused afterwards

#### Scenario: No saved code spent
- **WHEN** `u-1` recovers with an issued code and their password, and holds 2 saved codes
- **THEN** the result carries no codes and reports 2 remaining, flagged as low

### Requirement: A completed recovery resets the account's authenticators by default
When a recovery completes, the library SHALL remove the user's authenticators through the authenticator-reset port: every kind registered with it lists what the user holds, and removes what it is told to. By default it SHALL remove every authenticator the user holds, except any the user proved possession of in this recovery. The reset plan SHALL be decided before anything is spent. The removals SHALL run when the recovery completes, never when it starts. A consumer SHALL be able to choose instead:
- removing only what the user reported lost, named in the recovery request. A reported authenticator the user does not hold, a request that reports nothing, or a reported authenticator the user proved in the same recovery SHALL refuse the recovery as malformed before anything is spent;
- a policy of their own, given what the user holds, what they reported and what they proved, which returns what to remove.

The documentation of the reported-loss mode SHALL state that it trusts the user's report at the moment they are least sure. The documentation of the custom policy SHALL state that a policy removing nothing leaves possibly compromised authenticators valid, against NIST's invalidation requirement. There SHALL be no built-in mode that keeps every authenticator. A listing failure SHALL refuse the recovery before anything is spent. A removal failure SHALL stop the recovery and be returned: no recovery session SHALL be created and no other session SHALL be revoked, while the proofs stay spent and the removals already done stay done.

#### Scenario: Default reset
- **WHEN** `u-1`, enrolled on TOTP and on a consumer's `email-code` method, recovers with a saved code and an issued code
- **THEN** `u-1` is enrolled on neither method afterwards

#### Scenario: Proven method is kept
- **WHEN** `u-1`, enrolled on TOTP and `email-code`, recovers with a saved code and a TOTP code
- **THEN** `u-1` is still enrolled on TOTP and no longer on `email-code`

#### Scenario: Consumer chooses reported losses
- **WHEN** the reported-loss mode is chosen, and `u-1`, enrolled on TOTP and `email-code`, recovers reporting only `email-code` lost
- **THEN** `u-1` is still enrolled on TOTP and no longer on `email-code`

#### Scenario: Reporting what is not held
- **WHEN** in the reported-loss mode `u-1` reports a method they are not enrolled on
- **THEN** the recovery is refused as malformed and no code is spent

#### Scenario: Reporting nothing
- **WHEN** in the reported-loss mode `u-1` recovers without reporting any authenticator lost
- **THEN** the recovery is refused as malformed and no code is spent

#### Scenario: Consumer policy
- **WHEN** the consumer's policy returns only TOTP for removal
- **THEN** TOTP is removed and every other authenticator stays

#### Scenario: Listing failure
- **WHEN** listing `u-1`'s MFA enrolments fails during a recovery
- **THEN** the recovery is refused and no code is spent

### Requirement: A completed recovery ends other sessions and notifies the user
When a recovery completes, the library SHALL, after the reset, delete every session of the user by default, and SHALL notify the user at their contact address. The notice SHALL name the time of the recovery. It SHALL say whether the saved codes were replaced and which authenticators were removed. It SHALL carry clear instructions for repudiating a recovery the user did not make, including contact details the consumer configures. It SHALL contain no code, token or secret. Recovery SHALL NOT be enabled without those contact details, and construction SHALL fail with a configuration error when they are missing. A consumer SHALL be able to keep other sessions by an explicit option, documented as weakening recovery, and to replace the notice's subject and body through a message builder, while the library still sets the recipient. A notice the sender refuses to queue SHALL be logged and SHALL NOT undo the recovery.

#### Scenario: Other sessions end
- **WHEN** `u-1` holds two sessions and completes a recovery
- **THEN** neither of the earlier session handles loads, and the recovery session does

#### Scenario: Notice
- **WHEN** `u-1`, whose username is `ana@example.com`, completes a recovery
- **THEN** a notice is queued to `ana@example.com` naming the time, the removed authenticators and the repudiation contact details
- **AND** it contains no code

#### Scenario: Missing repudiation contact
- **WHEN** recovery is enabled without repudiation contact details
- **THEN** construction fails with a configuration error

#### Scenario: Consumer keeps sessions
- **WHEN** session revocation is turned off and `u-1` completes a recovery
- **THEN** `u-1`'s earlier sessions still load

### Requirement: A recovery produces a confined session, never a full one
A completed recovery SHALL create a session for the user, recording the `recovery` first factor, in the recovery-pending state with the time it was recovered, and SHALL answer with a credential for it through a replaceable responder. The session SHALL live at most the recovery lifetime, 15 minutes by default, replaceable by an option. Construction SHALL fail when the lifetime is zero or less, or longer than the session manager's absolute timeout. The session SHALL become a full session only by binding a new authenticator, through one of:
- the MFA enrolment path, after which the MFA verify endpoint resolves the challenge;
- passkey registration, after which the MFA verify endpoint resolves the challenge with the new passkey;
- a successful password change at the password-change resolve endpoint.

Recovery SHALL fail construction when none is wired. No option SHALL let a recovery end in a full session on its own.

#### Scenario: Recovery session
- **WHEN** `u-1` completes a recovery at 09:00 with default options
- **THEN** the response carries a credential for a session in the recovery-pending state, recording the `recovery` first factor and a recovery time of 09:00
- **AND** that session is refused at 09:16 as expired, unless it has become full by then

#### Scenario: Passkey is the only binding route
- **WHEN** recovery is enabled on a chain with passkey registration and the passkey method on the MFA slot, and neither the MFA enrolment path nor a password-change resolve endpoint
- **THEN** construction succeeds

#### Scenario: Nothing to bind
- **WHEN** recovery is enabled on a chain with neither the MFA enrolment path, passkey registration nor a password-change resolve endpoint
- **THEN** construction fails with a configuration error

### Requirement: Recovery completes at once by default, with opt-in holds
By default, a recovery whose proofs pass SHALL complete at once. A consumer SHALL be able to add either or both holds:
- **a fixed delay**, of a duration the consumer states, with no default;
- **a risk hook**, a function of the consumer's that is given the user, the source and the proof kinds and returns a hold duration. An error from the hook SHALL refuse the recovery before anything is spent.

The hold SHALL be the longer of the two. When it is above zero, the proofs SHALL be checked and spent at the completion request, and a recovery record SHALL be written pending until the end of the hold. The response SHALL carry a completion token and the instant the recovery becomes completable. The user SHALL be notified at once with a cancel link. The recovery SHALL complete only through the finish endpoint, `/recovery/finish` by default, presenting the completion token after the hold and before the completion window ends, 24 hours after the hold by default. The removals, the revocation, the replacement set and the recovery session SHALL all happen at the finish, never at the start. A delay of zero or less, a completion window of zero or less, or a hold configured without a link base URL for the cancel link, SHALL fail construction.

#### Scenario: Default completes at once
- **WHEN** no hold is configured and `u-1` posts two valid proofs
- **THEN** the response carries a credential for a recovery-pending session

#### Scenario: Fixed delay
- **WHEN** a 72-hour delay is configured and `u-1` posts two valid proofs on Monday at 09:00
- **THEN** the response carries a completion token and the instant Thursday 09:00, no session is created, and a notice with a cancel link is queued
- **AND** `u-1`'s authenticators and sessions are unchanged

#### Scenario: Finish too early
- **WHEN** the completion token is presented on Wednesday
- **THEN** it is refused as not yet completable, and the token stays usable

#### Scenario: Finish after the hold
- **WHEN** the completion token is presented on Thursday at 10:00
- **THEN** the reset and the revocation run, and the response carries a credential for a recovery-pending session

#### Scenario: Risk hook holds a risky recovery
- **WHEN** no fixed delay is configured, and the consumer's risk hook returns 48 hours for a recovery from an unfamiliar source
- **THEN** that recovery is held for 48 hours

#### Scenario: Risk hook allows a familiar recovery
- **WHEN** the risk hook returns zero for a recovery
- **THEN** the recovery completes at once

### Requirement: A held recovery is cancelled by the user
While a recovery is held, the user's existing authenticators and sessions SHALL stay valid. It SHALL be cancelled by:
- the cancel link, redeemed at the cancel endpoint, `/recovery/cancel` by default, with a POST;
- any login of the user that completes a first factor through the chain's login completion step.

Cancellation and completion SHALL each be one conditional write on a pending record, so of a racing cancel and finish at most one SHALL succeed. A cancelled recovery SHALL NOT complete. When a held recovery has spent a saved code, the user's remaining saved set SHALL be voided when the hold starts, and the hold's notice SHALL say that it was, so a cancelled recovery leaves no code of that set usable whichever way it was cancelled. A login that cannot record the cancellation SHALL be refused rather than let the recovery stand.

#### Scenario: Login cancels
- **WHEN** a recovery of `u-1` is held and `u-1` then logs in with their password
- **THEN** the finish is later refused as a recovery-refused error

#### Scenario: Cancel link
- **WHEN** the cancel link is redeemed while the recovery is held
- **THEN** the finish is later refused, and `u-1`'s saved set is void if a saved code was spent

#### Scenario: A hold voids the saved set
- **WHEN** a recovery of `u-1` presenting a saved code is held
- **THEN** no code of `u-1`'s saved set is usable while the hold runs, and the hold's notice says the set was voided

#### Scenario: Racing cancel and finish
- **WHEN** a cancel and a finish of the same held recovery run at the same time after its hold
- **THEN** exactly one of them succeeds

#### Scenario: Cancellation store outage at login
- **WHEN** a recovery of `u-1` is held, and `u-1` logs in while the recovery store fails
- **THEN** the login is refused

### Requirement: An opt-in cool-down refuses sensitive routes after a recovery
A consumer SHALL be able to enable a cool-down: for a duration they state after the user's latest completed recovery, requests the consumer marks as sensitive SHALL be refused with a cool-down error. The latest completed recovery SHALL be read from the user's recovery record, not from the session, so a new login does not end the cool-down. A failed lookup SHALL refuse the request. Unmarked requests SHALL be unaffected. The cool-down SHALL be off by default, and a duration of zero or less or an empty set of marked routes SHALL fail construction.

#### Scenario: Email change during the cool-down
- **WHEN** a 48-hour cool-down marks `POST /account/email`, and `u-1` completed a recovery 3 hours ago, logged out and logged in again
- **THEN** `u-1`'s `POST /account/email` is refused with the cool-down error

#### Scenario: After the cool-down
- **WHEN** the same request is made 49 hours after the recovery
- **THEN** it reaches the handler

#### Scenario: Unmarked route
- **WHEN** `u-1` requests `GET /invoices` during the cool-down
- **THEN** it reaches the handler

### Requirement: The library reports whether a user has another way back in
The library SHALL export a check that reports whether a user has a way back into the account other than saved codes they have yet to generate. It SHALL report yes when any of these holds:
- the user has a password or a usable authenticator, and issued codes are enabled, so it can pair with an issued code. An authenticator is usable when it can authenticate now: an enrolled MFA method, or an active passkey. A pending or suspended passkey is not usable;
- the user holds at least one unspent saved code;
- the user has a linked federated identity whose login would be admitted without a local second factor whatever the provider asserts, as decided by the MFA requirement policy the login itself is evaluated by: the policy is in the exempt federated-assurance mode, the exemption rule marks `oidc` exempt, or the user is not required to use MFA. Provider assurance SHALL NOT be assumed, because it is known only at a login.

Linked identities SHALL be read through a lookup the consumer supplies. With none supplied they SHALL NOT count, and the documentation SHALL say so. Kinds of authenticator added later SHALL feed the check through the authenticator-reset port. A kind that holds authenticators that cannot authenticate SHALL report only its usable ones to the check, while still listing every one it holds for the reset. A failed lookup SHALL return an error and SHALL NOT report no.

#### Scenario: Password with issued codes
- **WHEN** issued codes are enabled and `u-1` has a password and no saved codes
- **THEN** the check reports yes

#### Scenario: Password without issued codes
- **WHEN** issued codes are disabled and `u-1` has a password, no MFA enrolment and no saved codes
- **THEN** the check reports no

#### Scenario: Saved codes held
- **WHEN** `u-1` has no password and holds 3 unspent saved codes
- **THEN** the check reports yes

#### Scenario: Linked provider under the default exemption
- **WHEN** a linked-identity lookup is supplied and reports a linked OIDC identity for `u-1`, who has nothing else, and the MFA requirement policy is in the exempt federated-assurance mode
- **THEN** the check reports yes

#### Scenario: Linked provider, required user, default mode
- **WHEN** a linked-identity lookup is supplied and reports a linked OIDC identity for `u-1`, who is required to use MFA and has nothing else, and the policy is in the default mode
- **THEN** the check reports no

#### Scenario: Linked provider, user not required
- **WHEN** a linked-identity lookup is supplied and reports a linked OIDC identity for `u-1`, who is not required to use MFA and has nothing else
- **THEN** the check reports yes

#### Scenario: Requirement lookup failure
- **WHEN** a linked OIDC identity is reported for `u-1` and the requirement lookup fails during the check
- **THEN** the check returns an error

#### Scenario: Active passkey with issued codes
- **WHEN** issued codes are enabled and `u-1` has no password and one active passkey
- **THEN** the check reports yes

#### Scenario: Only a suspended passkey
- **WHEN** issued codes are enabled and `u-1` has no password and only a suspended passkey
- **THEN** the check reports no

#### Scenario: Lookup failure
- **WHEN** the enrolment lookup fails during the check
- **THEN** the check returns an error

### Requirement: Recovery is off by default, and its wiring mistakes fail at construction
No recovery endpoint SHALL exist until the consumer enables recovery on the chain. Saved codes, issued codes, the password proof and the MFA-method proof SHALL each be enabled separately. Construction SHALL fail with a configuration error when:
- no recovery code kind is enabled;
- only one proof kind is enabled, so no pair of different kinds is possible;
- issued codes are enabled with no sender, or the password proof with no password authenticator, or the MFA-method proof with no method that can serve;
- the reset has no authenticator kind registered;
- any endpoint path is empty, lacks a leading `/`, or equals another recovery path, the login path or the logout path.

#### Scenario: Off by default
- **WHEN** a chain is built without enabling recovery and a POST is sent to `/recovery/complete`
- **THEN** no recovery is attempted by the library

#### Scenario: One proof kind
- **WHEN** recovery is enabled with saved codes only
- **THEN** construction fails with a configuration error

#### Scenario: Path collision
- **WHEN** the start path is set to the logout path
- **THEN** construction fails with a configuration error
