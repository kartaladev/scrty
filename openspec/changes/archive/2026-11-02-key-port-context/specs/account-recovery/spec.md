# Spec Delta

## MODIFIED Requirements

### Requirement: Every proof is checked before any is spent
A recovery SHALL proceed in this order:
1. refuse while the source or the user is throttled;
2. resolve the user;
3. check every recovery code without spending it, and verify the password;
4. run the side-effect-free checks: the reported losses and the reset plan, the risk hook, and the consumer's refusal checks;
5. when the recovery completes at once, build the recovery session and issue its credential;
6. spend, last: first the MFA method proof, whose verification records its time step as it accepts it, then the issued code and the saved code; only then reset the authenticators, end the other sessions, replace the saved codes, store the recovery session and hand out its credential.

A refusal or lookup failure at any step before the last SHALL leave every recovery code redeemable. A failure to issue the credential is a dependency failure, not a refusal: it SHALL spend no proof, remove no authenticator, end no session, replace no code and send no notice, and SHALL NOT be counted against the user or the source. Of two racing recoveries presenting the same code, at most one SHALL succeed. A failed recovery SHALL be counted per user and per source. A refused recovery that presented a valid recovery code SHALL be counted against the source by default. A consumer SHALL be able to turn that off by an explicit option.

#### Scenario: Wrong password keeps the codes
- **WHEN** `u-1` posts a valid saved code and a wrong password, then posts the same saved code with the correct password
- **THEN** the first is refused and the second succeeds

#### Scenario: Consumer refusal keeps the codes
- **WHEN** a consumer refusal check denies `u-1`'s recovery, and the check later allows it
- **THEN** the first recovery returns the consumer's error unchanged, and the same two codes then succeed

#### Scenario: Racing recoveries
- **WHEN** two recoveries of `u-1` present the same saved and issued codes at the same time
- **THEN** exactly one succeeds

#### Scenario: Credential cannot be issued
- **WHEN** `u-1` has a live session, posts a valid saved code and the correct password, and the key source fails when the recovery session's credential is issued
- **THEN** the recovery fails as a dependency failure, not as a refusal, and no notice is queued
- **AND** `u-1`'s live session still loads, the saved code still confirms, and nothing is recorded against `u-1` or the source

#### Scenario: Refusals count against the source
- **WHEN** a recovery presenting a valid saved code is refused by a consumer refusal check
- **THEN** a failure is recorded against the request's source

#### Scenario: Consumer turns refusal counting off
- **WHEN** refusal counting is turned off and the same recovery is refused
- **THEN** no failure is recorded against the source for it

### Requirement: A recovery produces a confined session, never a full one
A completed recovery SHALL create a session for the user, recording the `recovery` first factor, in the recovery-pending state with the time it was recovered, and SHALL answer with a credential for it through a replaceable responder. The credential SHALL be issued before anything is spent, and the session SHALL be stored, in one write already in the recovery-pending state, only after the recovery's other effects have run. The session SHALL live at most the recovery lifetime, 15 minutes by default, replaceable by an option. Construction SHALL fail when the lifetime is zero or less, or longer than the session manager's absolute timeout. The session SHALL become a full session only by binding a new authenticator, through one of:
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

The hold SHALL be the longer of the two. When it is above zero, the proofs SHALL be checked and spent at the completion request, and a recovery record SHALL be written pending until the end of the hold. The response SHALL carry a completion token and the instant the recovery becomes completable. The user SHALL be notified at once with a cancel link. The recovery SHALL complete only through the finish endpoint, `/recovery/finish` by default, presenting the completion token after the hold and before the completion window ends, 24 hours after the hold by default. The removals, the revocation, the replacement set and the recovery session SHALL all happen at the finish, never at the start. At the finish, the recovery session's credential SHALL be issued before the record is completed; a failure to issue it is a dependency failure that SHALL leave the record pending and the completion token usable, and SHALL remove, revoke and replace nothing. A delay of zero or less, a completion window of zero or less, or a hold configured without a link base URL for the cancel link, SHALL fail construction.

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

#### Scenario: Finish while the credential cannot be issued
- **WHEN** the completion token is presented on Thursday at 10:00 while the key source fails when the credential is issued, and presented again at 10:05 after it recovers
- **THEN** the first finish fails as a dependency failure, and `u-1`'s authenticators and sessions are unchanged
- **AND** the second finish completes the recovery

#### Scenario: Risk hook holds a risky recovery
- **WHEN** no fixed delay is configured, and the consumer's risk hook returns 48 hours for a recovery from an unfamiliar source
- **THEN** that recovery is held for 48 hours

#### Scenario: Risk hook allows a familiar recovery
- **WHEN** the risk hook returns zero for a recovery
- **THEN** the recovery completes at once
