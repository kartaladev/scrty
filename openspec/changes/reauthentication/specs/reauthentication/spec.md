# Spec Delta

## Purpose

Lets a consumer require a recent authentication before an important route runs, and lets the user of an already signed-in session prove themselves again without signing out, under a factor policy that never accepts a weaker proof than the user holds.

## ADDED Requirements

### Requirement: A recency guard refuses a session that authenticated too long ago
A recency guard SHALL let its route run only when the request's session authenticated no longer ago than the guard's window. It SHALL refuse otherwise with the reauthentication-required error. The comparison SHALL be inclusive: a session exactly at the window's end is still fresh. Before judging recency, the guard SHALL apply the guards' shared refusals: no principal, then no authorizer.

#### Scenario: Fresh session
- **WHEN** a session authenticated at 09:00 calls a route under the default recency guard at 09:10
- **THEN** the route is called

#### Scenario: Stale session
- **WHEN** the same session calls the route at 09:16
- **THEN** the route is not called and the request is refused with the reauthentication-required error

#### Scenario: At the window's end
- **WHEN** the same session calls the route at exactly 09:15
- **THEN** the route is called

#### Scenario: A renewal does not make a session fresh
- **WHEN** a session authenticated at 09:00 is renewed at 09:10 and calls the guarded route at 09:20
- **THEN** it is refused with the reauthentication-required error

#### Scenario: No principal
- **WHEN** a request without a principal calls the guarded route
- **THEN** it is refused as authentication required, not as reauthentication required

#### Scenario: No authorizer
- **WHEN** guards built with a declared reliance on the chain's authorizer serve a fresh session through a chain with no authorizer
- **THEN** the request is refused with the access-denied error

#### Scenario: Behind a privilege guard
- **WHEN** a route is guarded by "any of delete on projects/project" and then by the recency guard, and a stale session without that privilege calls it
- **THEN** the request is refused with the access-denied error

### Requirement: An absent authentication time is never recent
A session whose authentication time is not recorded SHALL be refused by every recency guard, whatever the window.

#### Scenario: Zero authentication time
- **WHEN** a session with no recorded authentication time calls a route guarded with a 24-hour window
- **THEN** it is refused with the reauthentication-required error

### Requirement: Only an authentication makes a session fresh again
Calling a guarded route, or any other route, SHALL NOT extend the window. Only a sign-in, a second factor satisfied at sign-in, or a re-authentication SHALL move the time a recency guard judges.

#### Scenario: Repeated use does not slide the window
- **WHEN** a session authenticated at 09:00 calls the guarded route at 09:05, 09:10 and 09:14, and calls it again at 09:16
- **THEN** the last call is refused with the reauthentication-required error

#### Scenario: A re-authentication makes it fresh
- **WHEN** a session authenticated at 09:00 re-authenticates at 09:30 and calls the guarded route at 09:40
- **THEN** the route is called

### Requirement: The recency window has a default, a guards-wide override and a per-route override
The window SHALL be 15 minutes by default. A consumer SHALL be able to set another window for all guards built together, and another for one route when its guard is built; a route's own window SHALL take precedence. A guards-wide window of zero or less SHALL fail construction with a configuration error. A per-route window of zero or less SHALL fail at wiring, before any request is served.

#### Scenario: Consumer guards-wide window
- **WHEN** guards are built with a 2-hour window, and a session authenticated at 09:00 calls a recency-guarded route at 10:30
- **THEN** the route is called

#### Scenario: A route's own window wins
- **WHEN** guards are built with the default window and a route is guarded with a 5-minute window, and a session authenticated at 09:00 calls it at 09:06
- **THEN** it is refused with the reauthentication-required error

#### Scenario: Zero guards-wide window
- **WHEN** guards are built with a window of zero
- **THEN** construction fails with a configuration error

#### Scenario: Negative per-route window
- **WHEN** a route's recency guard is built with a negative window
- **THEN** building it fails at wiring with a message naming the window, before any request is served

### Requirement: The recency guard reads time from a replaceable time source
The guards SHALL read the current time from a time source, the system clock by default, replaceable by an option. An absent time source, including a typed-nil one, SHALL fail construction with a configuration error.

#### Scenario: System clock by default
- **WHEN** guards are built with no time source and a session authenticated one minute ago calls a recency-guarded route
- **THEN** the route is called

#### Scenario: Consumer time source
- **WHEN** guards are built with a controlled time source, a session authenticated at the source's 09:00 calls a recency-guarded route, and the source is advanced to 09:16
- **THEN** a second call is refused with the reauthentication-required error, with no real waiting

#### Scenario: Absent time source
- **WHEN** guards are built with a nil or typed-nil time source
- **THEN** construction fails with a configuration error naming the option

### Requirement: The authentication time comes from the session unless the consumer supplies it
By default the guard SHALL judge the request's session's authentication time. A request with a principal but no session, as from an API key, HTTP Basic or a consumer's own first factor, SHALL be refused with the reauthentication-required error. A consumer SHALL be able to replace how the time is found; a replacement reporting none SHALL refuse, and an absent one SHALL fail construction.

#### Scenario: API key caller
- **WHEN** a caller authenticated by an API key calls a recency-guarded route
- **THEN** it is refused with the reauthentication-required error

#### Scenario: Consumer authentication time
- **WHEN** guards are built with a consumer source that reports 09:00 for the caller, and the caller calls a route under the default window at 09:10
- **THEN** the route is called

#### Scenario: Consumer source reports none
- **WHEN** the consumer source reports no authentication time for the caller
- **THEN** the request is refused with the reauthentication-required error

#### Scenario: Absent consumer source
- **WHEN** guards are built with a nil authentication-time source
- **THEN** construction fails with a configuration error naming the option

### Requirement: The reauthentication-required refusal names the window it needed
The recency guard's refusal SHALL be distinguishable from every other refusal and SHALL carry the window the route required, so a consumer's error handler can tell the client how recent an authentication it must present. With no error handler the response SHALL be the refusal's status with no body.

#### Scenario: Window on the refusal
- **WHEN** a stale session is refused by a route guarded with a 5-minute window
- **THEN** the refusal is identifiable as the reauthentication-required error and reports a window of 5 minutes

#### Scenario: Default response
- **WHEN** guards are built with no error handler and a stale session is refused
- **THEN** the response is 403 with no body

#### Scenario: Consumer error handler
- **WHEN** guards are built with an error handler and a stale session is refused
- **THEN** the handler receives the refusal with its window, and the route is not called

### Requirement: Re-proof endpoints exist only when re-authentication is enabled
The chain SHALL offer re-proof endpoints only when the consumer enables re-authentication. They SHALL live under one prefix, `/reauth` by default and replaceable: a method listing answering GET at `<prefix>/methods`, a second-factor begin and verify answering POST at `<prefix>/begin/<method>` and `<prefix>/verify/<method>`, and a password re-proof answering POST at `<prefix>/password`.

#### Scenario: Off by default
- **WHEN** re-authentication is not enabled and a signed-in session posts to `/reauth/password`
- **THEN** the library answers nothing there and the request reaches the application

#### Scenario: Consumer prefix
- **WHEN** re-authentication is enabled with the prefix `/account/confirm`, and a signed-in session posts a valid TOTP code to `/account/confirm/verify/totp`
- **THEN** the session is re-authenticated

#### Scenario: A method segment is required
- **WHEN** re-authentication is enabled and a session posts to `/reauth/verify/` with no method
- **THEN** it is refused as an unknown MFA method

### Requirement: Re-authentication wiring mistakes fail at construction
Enabling re-authentication SHALL fail chain construction with a configuration error when:
- neither the MFA slot nor form login is enabled;
- second-factor-only re-proof is required without the MFA slot;
- the prefix is empty;
- a re-proof path equals or lies under the logout path, the form login path, the MFA verify or begin prefix, or equals the MFA listing path;
- it is enabled twice;
- no credential can be issued for the rotated session.

#### Scenario: Nothing to re-prove with
- **WHEN** re-authentication is enabled on a chain without the MFA slot and without form login
- **THEN** construction fails with a configuration error

#### Scenario: Second factor only without MFA
- **WHEN** second-factor-only re-proof is required on a chain with form login and without the MFA slot
- **THEN** construction fails with a configuration error

#### Scenario: Empty prefix
- **WHEN** re-authentication is enabled with an explicitly empty prefix
- **THEN** construction fails with a configuration error

#### Scenario: Prefix collides with MFA verify
- **WHEN** the re-authentication prefix is set to `/mfa/verify`
- **THEN** construction fails with a configuration error

#### Scenario: Enabled twice
- **WHEN** re-authentication is enabled twice on one chain
- **THEN** construction fails with a configuration error

#### Scenario: No credential to issue
- **WHEN** re-authentication is enabled on a token-bearer chain without a token generator for it
- **THEN** construction fails with a configuration error

### Requirement: Only a full session may re-prove
Every re-proof endpoint SHALL serve only a full session: one with a resolved caller, no pending challenge of any kind, and not confined. A request with no session or no resolved caller SHALL be refused as authentication required. A session owing a challenge SHALL be refused by that challenge's gate before the endpoint. A session that is still fresh SHALL be served.

#### Scenario: No session
- **WHEN** a request without a session posts to `/reauth/password`
- **THEN** it is refused as authentication required

#### Scenario: Pending second factor
- **WHEN** a session with the MFA challenge pending posts to `/reauth/verify/totp`
- **THEN** it is refused with the MFA challenge and nothing is verified

#### Scenario: Pending password change
- **WHEN** a session with a pending password change posts to `/reauth/password`
- **THEN** it is refused with the password-change challenge and the password is not checked

#### Scenario: Enrolment-only session
- **WHEN** an enrolment-only session sends GET `/reauth/methods`
- **THEN** it is refused by the enrolment gate

#### Scenario: Recovery-pending session
- **WHEN** a recovery-pending session posts to `/reauth/password`
- **THEN** it is refused by the recovery gate

#### Scenario: A fresh session re-proves
- **WHEN** a session authenticated one minute ago posts a valid TOTP code to `/reauth/verify/totp`
- **THEN** it is re-authenticated

### Requirement: A user re-proves with the strongest factor they hold, by default
By default a user who holds a usable re-proof second factor SHALL re-prove with one and SHALL NOT re-prove with the password; a user who holds none SHALL re-prove with the password. A usable re-proof second factor is a configured MFA method the user is enrolled on, whatever its channel. A failed enrolment lookup SHALL refuse the request and SHALL NOT fall back to the password.

#### Scenario: A TOTP holder offers a password
- **WHEN** `u-1`, enrolled on TOTP, posts the correct password to `/reauth/password`
- **THEN** it is refused with the re-proof-method-not-usable error before the body is read, the password is not checked and no failure is recorded

#### Scenario: A user without a second factor
- **WHEN** `u-2`, enrolled on no method, posts the correct password to `/reauth/password`
- **THEN** `u-2`'s session is re-authenticated

#### Scenario: MFA not configured
- **WHEN** the chain has form login and no MFA slot, and `u-1` posts the correct password to `/reauth/password`
- **THEN** the session is re-authenticated

#### Scenario: Lookup failure does not downgrade
- **WHEN** the TOTP enrolment lookup fails for `u-1` and `u-1` posts the correct password to `/reauth/password`
- **THEN** the request is refused with the lookup failure and the password is not checked

#### Scenario: A passkey login re-proves with the passkey
- **WHEN** `u-3` signed in with a passkey, the passkey MFA method is configured, and `u-3` re-proves through `/reauth/begin/passkey` and `/reauth/verify/passkey`
- **THEN** `u-3`'s session is re-authenticated, although the passkey shares the first factor's channel

### Requirement: A consumer can require a second factor for every re-proof
A consumer SHALL be able to require a second factor for every re-proof. A user with no usable second factor SHALL then be refused at the password endpoint with the re-proof-method-not-usable error, and SHALL be offered no re-proof method; they become fresh only by signing in again. No option SHALL let a user who holds a usable second factor re-prove with the password.

#### Scenario: Second factor only
- **WHEN** second-factor-only re-proof is required and `u-2`, enrolled on no method, posts the correct password to `/reauth/password`
- **THEN** it is refused with the re-proof-method-not-usable error and the password is not checked

#### Scenario: A fresh sign-in still makes the session fresh
- **WHEN** second-factor-only re-proof is required and `u-2` signs in again
- **THEN** the new session passes a recency guard

### Requirement: The method listing reports how the session's user may re-prove
The listing SHALL answer a full session with what its user may re-prove with under the factor policy: each usable second factor's name, channel and whether it has a begin step, and whether the password is accepted. It SHALL come from the same decision the re-proof endpoints apply. A failed lookup SHALL refuse, never yield an empty list. The default body SHALL be documented JSON, replaceable through a responder.

#### Scenario: A TOTP holder
- **WHEN** `u-1`, enrolled on TOTP only, sends GET `/reauth/methods`
- **THEN** the default body lists `totp` with its channel and no begin step, and reports the password as not accepted

#### Scenario: A user without a second factor
- **WHEN** `u-2`, enrolled on no method, on a chain with form login, sends GET `/reauth/methods`
- **THEN** the default body lists no method and reports the password as accepted

#### Scenario: Nothing to re-prove with
- **WHEN** second-factor-only re-proof is required and `u-2` sends GET `/reauth/methods`
- **THEN** the default body lists no method and reports the password as not accepted

#### Scenario: Lookup failure
- **WHEN** an enrolment lookup fails for the session's user
- **THEN** the request is refused with that failure and no list is written

#### Scenario: Consumer responder
- **WHEN** re-authentication is enabled with a listing responder of the consumer's
- **THEN** the consumer's responder writes the response with the same decision

### Requirement: A second-factor re-proof is verified like a second factor
Verify SHALL refuse, before reading the body and without counting against the throttle, an unknown method in the path, and a method the factor policy does not offer the user. It SHALL then check the user's second-factor verification throttle, read the response with the method's reader, spend a pending re-proof challenge for a challenge method, and verify the response. A wrong response SHALL count against the same per-user throttle as verification at login.

#### Scenario: Valid TOTP code
- **WHEN** `u-1`, enrolled on TOTP, posts a valid code to `/reauth/verify/totp`
- **THEN** the session is re-authenticated

#### Scenario: Unknown method
- **WHEN** a session posts to `/reauth/verify/sms` and no method is named `sms`
- **THEN** it is refused as an unknown MFA method and nothing is counted

#### Scenario: Method the user is not enrolled on
- **WHEN** `u-1`, enrolled on TOTP only, posts to `/reauth/verify/passkey`
- **THEN** it is refused with the re-proof-method-not-usable error and nothing is counted

#### Scenario: Wrong code
- **WHEN** `u-1` posts a wrong TOTP code to `/reauth/verify/totp`
- **THEN** it is refused with the invalid-code error, one failure is counted against `u-1`, and the session is unchanged

#### Scenario: One throttle with the login second factor
- **WHEN** `u-1` has four wrong codes counted at second-factor verification after login, posts a fifth wrong code to `/reauth/verify/totp`, and then a valid one
- **THEN** the valid one is refused with the throttled error

#### Scenario: A code already used
- **WHEN** `u-1` posts to `/reauth/verify/totp` a code whose time step was already accepted for `u-1`
- **THEN** it is refused with the invalid-code error

### Requirement: Re-proof challenges are their own and bound to the session
Begin SHALL apply verify's refusals and throttle check, then issue a re-proof challenge: a one-time token of a purpose of its own per method, whose subject is the user and which is bound to the session, expiring after 5 minutes by default. A login challenge SHALL NOT answer a re-proof, nor the reverse. The lifetime, the issuance limit (10 per user and method within an hour by default) and the store SHALL be replaceable.

#### Scenario: Begin
- **WHEN** `u-3`, holding an active passkey, posts to `/reauth/begin/passkey`
- **THEN** the response carries a challenge document and is marked not to be cached

#### Scenario: A login challenge is refused
- **WHEN** a challenge issued by `/mfa/begin/passkey` is presented to `/reauth/verify/passkey`
- **THEN** it is refused with the invalid-code error and counted

#### Scenario: Another session's challenge
- **WHEN** a re-proof challenge issued to one session of `u-3` is presented by another session of `u-3`
- **THEN** it is refused with the invalid-code error and counted

#### Scenario: Expired challenge
- **WHEN** a re-proof challenge is answered six minutes after it was issued with the default lifetime
- **THEN** it is refused with the invalid-code error

#### Scenario: Issuance limit
- **WHEN** `u-3` begins a passkey re-proof ten times within an hour and begins again
- **THEN** the eleventh begin is refused with the throttled error and no challenge is issued

#### Scenario: Consumer lifetime
- **WHEN** the re-proof challenge lifetime is set to 2 minutes and a challenge is answered after 3 minutes
- **THEN** it is refused with the invalid-code error

#### Scenario: Zero lifetime
- **WHEN** the re-proof challenge lifetime is set to zero
- **THEN** construction fails with a configuration error

### Requirement: A refused authenticator at re-proof keeps its meaning
A passkey re-proof refused as a suspected clone, or from a suspended credential, SHALL return that refusal unchanged and SHALL NOT count as a failed verification. The passkey capability's response to a suspected clone, including ending the user's sessions, SHALL apply as it does at second-factor verification.

#### Scenario: Suspected clone
- **WHEN** a passkey re-proof presents a signature counter that suggests a clone, under the default clone response
- **THEN** it is refused with the suspected-clone error, no failure is counted, and the user's sessions, this one included, are ended

#### Scenario: Suspended passkey
- **WHEN** a passkey re-proof uses a suspended credential
- **THEN** it is refused with the suspended error and no failure is counted

### Requirement: A password re-proof checks the session's own user under the account lockout
The password endpoint SHALL read only the password, from the `password` form field or a JSON body, and SHALL check it for the session's own user, never a username named in the request. It SHALL apply the account lockout before checking, record a wrong password against the user's lockout failures as a login does, and clear them on success. A locked account SHALL be refused as a login refuses one.

#### Scenario: Correct password
- **WHEN** `u-2`, enrolled on no method, posts the correct password
- **THEN** the session is re-authenticated and `u-2`'s lockout failures are cleared

#### Scenario: A username in the request is ignored
- **WHEN** `u-2`'s session posts `username=u-9` with `u-9`'s correct password
- **THEN** it is refused as authentication failed and a failure is recorded against `u-2`

#### Scenario: Wrong password
- **WHEN** `u-2` posts a wrong password
- **THEN** it is refused as authentication failed, a failure is recorded against `u-2`, and the session is unchanged

#### Scenario: Locked account
- **WHEN** `u-2` is locked by the lockout policy and posts the correct password
- **THEN** it is refused as a locked login is refused, and the password is not compared

#### Scenario: A user with no password
- **WHEN** `u-4`, who signed in through a provider and has no password, posts any password
- **THEN** it is refused as authentication failed and the session is unchanged

#### Scenario: Missing password field
- **WHEN** a session posts to `/reauth/password` with no password
- **THEN** it is refused as a malformed request and nothing is recorded

#### Scenario: Oversized body
- **WHEN** a session posts a body larger than the login limit
- **THEN** it is refused as too large and nothing is recorded

#### Scenario: User store unavailable
- **WHEN** the user store cannot answer during a password re-proof
- **THEN** it is refused with the unavailable error and no failure is recorded

### Requirement: A successful re-proof refreshes the authentication time and rotates the session
A successful re-proof SHALL set the authentication time to now from the chain's time source; a second-factor re-proof SHALL also record the second factor as satisfied then. It SHALL rotate the session, so the previous handle stops working, and answer with the rotated session's credential through a replaceable responder, without passing the request on. A failure SHALL change neither the session nor its handle.

#### Scenario: Second-factor re-proof
- **WHEN** a session authenticated at 09:00 re-proves with TOTP at 09:30
- **THEN** the rotated session reports 09:30 as its authentication time and its second-factor-satisfied time
- **AND** the previous handle no longer loads
- **AND** the response carries a credential naming the rotated session, so the next request authenticates

#### Scenario: Password re-proof leaves the second-factor state
- **WHEN** a session of `u-2` with no second factor re-proves with the password at 09:30
- **THEN** the rotated session reports 09:30 as its authentication time and still reports no second factor

#### Scenario: A session that met no second factor yet
- **WHEN** `u-1` enrolled on TOTP from another session after this session signed in, and this session re-proves with TOTP
- **THEN** the rotated session reports a satisfied second factor

#### Scenario: The guard passes afterwards
- **WHEN** a stale session re-proves and calls a recency-guarded route with its new credential
- **THEN** the route is called

#### Scenario: Concurrent re-proofs
- **WHEN** one session sends two valid re-proofs at once
- **THEN** one succeeds and the other is refused with the renewal-conflict error, leaving the winner's session in place

#### Scenario: Controlled chain time source
- **WHEN** the chain has a controlled time source reading 09:30 and a session re-proves
- **THEN** the rotated session reports 09:30 as its authentication time

#### Scenario: Consumer responder
- **WHEN** re-authentication is enabled with a responder of the consumer's that sets a cookie
- **THEN** the consumer's responder receives the rotated session and the library writes no response of its own

### Requirement: Re-proof responses are not cached and re-proof logs carry no secret
Every default re-proof responder SHALL set `Cache-Control: no-store`; a consumer responder SHALL own its headers. Records the re-proof endpoints write SHALL contain no password, code, challenge or authenticator response.

#### Scenario: Default verify response
- **WHEN** a re-proof succeeds with the default responder
- **THEN** the response carries `Cache-Control: no-store`

#### Scenario: Refusal logs
- **WHEN** a password re-proof and a TOTP re-proof are refused for a wrong secret
- **THEN** the records written contain neither the password nor the code
