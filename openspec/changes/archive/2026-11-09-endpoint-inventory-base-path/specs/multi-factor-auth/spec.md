# Spec Delta

## MODIFIED Requirements

### Requirement: An enrolment-only session reaches only the enrolment endpoints and logout
A request whose session is in the enrolment-pending state SHALL be refused with an enrolment challenge error carrying that session, whatever its method or path, before any interceptor after the enrolment gate runs. These requests are exempt:
- a POST to a begin path, formed from the begin prefix, by default `/mfa/enrol/begin`, and an enrolling method's name;
- a POST to a confirm path, under the confirm prefix, by default `/mfa/enrol/confirm`;
- a POST to an emailed-code path, under the emailed-code prefix, by default `/mfa/enrol/confirm-email`, when email confirmation is on;
- a POST to the passkey registration begin, finish, saved-code confirm and emailed-code confirm paths, when passkey registration serves the enrolment path;
- the logout endpoint, wherever it is placed in the chain relative to the gate.

Each enrolment prefix SHALL be replaceable by an option. There SHALL be no option that lets further routes through. The MFA verify and begin endpoints, the method-listing endpoint, the passkey listing, rename and remove endpoints and the password-change resolve endpoint SHALL be refused like any other route. A session in the enrolment-pending state SHALL always be able to log out, and logging out SHALL end it.

#### Scenario: Protected route
- **WHEN** an enrolment-only session requests `/invoices`
- **THEN** an enrolment challenge error carrying the session is returned
- **AND** the route's handler, the authorizer and any consumer interceptor after the gate do not run

#### Scenario: Verify endpoint is not reachable
- **WHEN** an enrolment-only session posts a code to `/mfa/verify/totp`
- **THEN** an enrolment challenge error is returned and no code is verified

#### Scenario: GET on an enrolment path
- **WHEN** an enrolment-only session sends a GET to `/mfa/enrol/begin/totp`
- **THEN** an enrolment challenge error is returned

#### Scenario: Passkey registration reachable
- **WHEN** passkey registration serves the enrolment path and an enrolment-only session posts to `/passkeys/register/begin`
- **THEN** a registration challenge is issued

#### Scenario: Passkey listing is not reachable
- **WHEN** an enrolment-only session sends a GET to `/passkeys`
- **THEN** an enrolment challenge error is returned

#### Scenario: Logout
- **WHEN** an enrolment-only session posts to the logout endpoint
- **THEN** no enrolment challenge error is returned
- **AND** the session is deleted, and its handle no longer loads

#### Scenario: Consumer path
- **WHEN** the begin prefix is configured as `/account/2fa/start` and an enrolment-only session posts to `/account/2fa/start/totp`
- **THEN** a pending enrolment is begun

### Requirement: A challenge method verifies only against a challenge the library issued
A method MAY declare a begin step. For such a method the library SHALL provide a begin endpoint that matches POST requests to one path per method under a begin prefix, `/mfa/challenge` by default and replaceable by an option. Begin SHALL apply the same session, method and usability refusals as verification, SHALL be refused while the user's verification is throttled, and SHALL then issue a pending challenge: a one-time token of a purpose of the method's own, whose subject is the session's user and which is bound to the session's handle, expiring after 5 minutes by default, replaceable by an option. The token string SHALL be the challenge the method builds its begin data around, and the begin data SHALL be written through a replaceable responder. The pending-challenge store SHALL default to the in-memory one-time store and be replaceable by an option, and the documentation SHALL state that the in-memory store serves a single process.

At verification of a challenge method, after the response is read, the library SHALL take from the response the challenge the client answered, check it against the pending challenges it issued for that session, and spend it, before the method verifies the response. A challenge SHALL be spent by any verification attempt that presents it on the session it was issued to, whether that attempt is accepted or refused. A challenge presented on another session SHALL be refused without being spent, since it matches no challenge issued to that session. A challenge that is absent, unknown, expired, already spent, or bound to another session SHALL be refused as an invalid second-factor code and counted as a failed verification. A challenge SHALL only ever be compared with one the library issued, never accepted from the request alone.

A begin path naming a method that has no begin step SHALL be refused as an unknown MFA method.

Begin SHALL be refused as throttled, issuing nothing, once the user has been issued as many challenges for that method within the pending-challenge store's issuance window as the challenge limit allows: 10 within one hour by default, the limit replaceable by an option, and a limit of zero or less a configuration error. The count and the issue SHALL be one atomic bounded issue, so begins that race SHALL NOT together exceed the limit. The library SHALL remove a method's expired challenges from the store at most once per issuance window, as part of a begin, so the default store does not grow without bound, and SHALL keep doing so after the clock steps backwards; a failed removal SHALL NOT refuse the begin.

#### Scenario: Begin then verify
- **WHEN** a pending session begins a challenge method, and posts a response answering the issued challenge
- **THEN** the method verifies the response and the challenge is resolved

#### Scenario: One try per challenge
- **WHEN** a pending session posts a response answering an issued challenge and the method refuses it, and then posts a second response answering the same challenge
- **THEN** the second attempt is refused as an invalid second-factor code without the method being asked to verify

#### Scenario: Challenge from another session
- **WHEN** session A begins a challenge method, and session B, for the same user, posts a response answering A's challenge
- **THEN** it is refused as an invalid second-factor code

#### Scenario: Expired challenge
- **WHEN** a challenge issued at 12:00 with the default lifetime is answered at 12:06
- **THEN** it is refused as an invalid second-factor code and a failure is counted

#### Scenario: Consumer challenge lifetime
- **WHEN** the challenge lifetime is set to 2 minutes and a challenge issued at 12:00 is answered at 12:03
- **THEN** it is refused as an invalid second-factor code

#### Scenario: Too many challenges
- **WHEN** a pending session of `u-1` begins the same challenge method 10 times within an hour, then begins it once more
- **THEN** the eleventh begin is refused as throttled and no challenge is issued

#### Scenario: Consumer challenge limit
- **WHEN** the challenge limit is set to 3 and `u-1` begins the same method 4 times within an hour
- **THEN** the fourth begin is refused as throttled

#### Scenario: Expired challenges are removed
- **WHEN** with the challenge limit raised to 1000, 200 challenges are issued and left unanswered, more than an hour passes, and another begin is made
- **THEN** the expired challenges are no longer held by the store

#### Scenario: Begin for a method without a begin step
- **WHEN** a pending session posts to the begin path of the TOTP method
- **THEN** it is refused as an unknown MFA method

#### Scenario: Concurrent begins
- **WHEN** the challenge limit is set to 3 and 12 begins of the same method for `u-1` run concurrently
- **THEN** at most 3 challenges are issued

#### Scenario: Removal after the clock steps backwards
- **WHEN** the clock steps back by an hour after a removal, and challenges then expire and more than an issuance window passes before another begin
- **THEN** the expired challenges are removed at that begin

### Requirement: Passkey registration serves the enrolment path when the passkey method is enrolled through it
When the enrolment path is enabled on the chain, passkey registration is enabled, and the passkey MFA method is among the path's enrolling methods, passkey registration SHALL serve the path. The passkey method is among them by default, and a consumer who names the path's methods SHALL name `passkey` to include it. An enrolment-only session SHALL then be able to register a passkey, under the path's email confirmation, confirmation limiter, notification and contact resolver, as the `passkey-authentication` capability defines. When the passkey becomes active, the session SHALL move to the MFA pending state, and the MFA verify endpoint SHALL complete the upgrade as for any enrolment through the path.

Chain assembly SHALL fail with a configuration error when the passkey method is among the path's enrolling methods but passkey registration is not enabled, because the policy would send users to a path that cannot enrol the method.

#### Scenario: Passkey through the path
- **WHEN** MFA is required for all users, the path is on with TOTP and the passkey method, and a user who has never enrolled logs in by password, registers a passkey, confirms the emailed code, and verifies the passkey at `/mfa/verify/passkey`
- **THEN** the session is a full session with a satisfied second factor

#### Scenario: Passkey method without registration
- **WHEN** the path is enabled with the passkey method among its enrolling methods and passkey registration is not enabled on the chain
- **THEN** chain assembly fails with a configuration error

#### Scenario: Consumer names TOTP only
- **WHEN** the path's enrolling methods are named as `totp` only and an enrolment-only session posts to `/passkeys/register/begin`
- **THEN** an enrolment challenge error is returned

### Requirement: The verify and begin endpoints serve only a session that owes a second factor
The second-factor verify and begin endpoints SHALL refuse a session that owes no second-factor challenge, a full session included, with the no-MFA-challenge-pending error. The refusal SHALL come after the session and caller refusals and before the method, the throttle or the body is read. It SHALL count nothing, issue nothing and leave the session and its handle unchanged. Re-proving a signed-in session belongs to the re-authentication capability.

#### Scenario: A full session posts a code
- **WHEN** a session whose second factor is satisfied posts a valid code to `/mfa/verify/totp`
- **THEN** it is refused with the no-MFA-challenge-pending error, the code is not checked, nothing is counted and the handle is unchanged

#### Scenario: A full session begins a challenge
- **WHEN** a session whose second factor is satisfied posts to `/mfa/challenge/passkey`
- **THEN** it is refused with the no-MFA-challenge-pending error and no challenge is issued

#### Scenario: A session that never owed a second factor
- **WHEN** a session of a user enrolled on TOTP after it signed in, which owes no challenge, posts a valid code to `/mfa/verify/totp`
- **THEN** it is refused with the no-MFA-challenge-pending error and its authentication time is unchanged

#### Scenario: No session still comes first
- **WHEN** a request without a session posts to `/mfa/verify/totp`
- **THEN** it is refused as authentication required

#### Scenario: A pending session is still served
- **WHEN** a session with the MFA challenge pending posts a valid code to `/mfa/verify/totp`
- **THEN** the challenge is resolved and the session rotated

### Requirement: Verification judges what the second-factor challenge hid
After a valid code and before the session is rotated, verification SHALL judge the post-authentication phase again with the login's input, marked as having satisfied a second factor. A deny SHALL refuse verification and leave the session pending under the caller's credential. Any other challenge than a second factor SHALL be completed as at login: the session satisfied, rotated and marked, and the challenge error carrying the rotated session and its credential.

#### Scenario: A password change behind the second factor
- **WHEN** the MFA policy is registered before a policy that challenges for a password change, `u-1` signs in with the password and posts a valid code to `/mfa/verify/totp`
- **THEN** verification answers with a challenge error for a password change carrying the rotated session, which has met its second factor and owes the password change

#### Scenario: A deny behind the second factor
- **WHEN** a consumer policy registered after the MFA policy denies `u-1` in the post-authentication phase only once a second factor is satisfied, and `u-1` posts a valid code to `/mfa/verify/totp`
- **THEN** verification is refused with the policy's reason, and the session the caller arrived with still loads and is still pending

#### Scenario: A substituted caller at verification
- **WHEN** a consumer interceptor publishes a principal other than the pending session's user and that session posts a valid code to `/mfa/verify/totp`
- **THEN** verification is refused as authentication required before the phase is judged, and the session is still pending

#### Scenario: A substituted caller at begin
- **WHEN** a consumer interceptor publishes a principal other than the pending session's user and that session posts to `/mfa/challenge/passkey`
- **THEN** it is refused as authentication required, no challenge is issued and nothing is counted

#### Scenario: A federated verification behind the requirement
- **WHEN** the second-factor requirement policy in its challenge mode is registered before a policy that challenges for a password change, and a pending federated session whose provider did not meet the requirement posts a valid code to `/mfa/verify/totp`
- **THEN** verification answers with a challenge error for a password change carrying the rotated session

#### Scenario: Nothing behind the second factor
- **WHEN** no other policy objects and `u-1` posts a valid code to `/mfa/verify/totp`
- **THEN** verification succeeds as before

