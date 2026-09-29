# Spec Delta

## ADDED Requirements

### Requirement: Each method declares its response format, read only by the library
Every MFA method SHALL declare how its verification response is carried: either one field of a URL-encoded body, or a whole JSON body, together with the largest body it accepts. The library SHALL read the response with one of two readers of its own and hand the method only the response bytes: for a form-field method, that field's value; for a JSON method, the whole body. A method SHALL NOT read the request. Both readers SHALL:
- read the request body only, never the URL query;
- require the declared content type, URL-encoded for a form field and JSON for a JSON body;
- bound the body at the method's declared limit.

A body over the limit SHALL be refused as too large, and a body that is empty, of another content type, or does not parse SHALL be refused as missing credentials. Neither SHALL be counted against the verification throttle. The built-in TOTP method SHALL declare the `code` form field with a limit of 4 KiB, so a plain HTML form verifies a code. Constructing a component with a method whose declared limit is zero or less or above 1 MiB, or whose form-field name is empty, SHALL fail with a configuration error.

#### Scenario: TOTP from an HTML form
- **WHEN** a session with the MFA challenge pending posts `code=<valid code>` as a URL-encoded body to TOTP's verify path
- **THEN** the challenge is resolved

#### Scenario: JSON method
- **WHEN** a consumer's method declares a JSON body of up to 16 KiB and a pending session posts a 6 KiB JSON document to its verify path
- **THEN** the method receives exactly that document's bytes

#### Scenario: Wrong content type for a JSON method
- **WHEN** the same method is posted a URL-encoded body
- **THEN** it is refused as missing credentials, the method is not called, and no failure is counted

#### Scenario: Body over the declared limit
- **WHEN** a pending session posts a 5 KiB body to TOTP's verify path
- **THEN** it is refused as too large and no failure is counted

#### Scenario: Invalid declared limit
- **WHEN** a component is constructed with a method declaring a limit of 0
- **THEN** construction fails with a configuration error

### Requirement: A challenge method verifies only against a challenge the library issued
A method MAY declare a begin step. For such a method the library SHALL provide a begin endpoint that matches POST requests to one path per method under a begin prefix, `/mfa/begin` by default and replaceable by an option. Begin SHALL apply the same session, method and usability refusals as verification, SHALL be refused while the user's verification is throttled, and SHALL then issue a pending challenge: a one-time token of a purpose of the method's own, whose subject is the session's user and which is bound to the session's handle, expiring after 5 minutes by default, replaceable by an option. The token string SHALL be the challenge the method builds its begin data around, and the begin data SHALL be written through a replaceable responder. The pending-challenge store SHALL default to the in-memory one-time store and be replaceable by an option, and the documentation SHALL state that the in-memory store serves a single process.

At verification of a challenge method, after the response is read, the library SHALL take from the response the challenge the client answered, check it against the pending challenges it issued for that session, and spend it, before the method verifies the response. A challenge SHALL be spent by any verification attempt that presents it, whether that attempt is accepted or refused. A challenge that is absent, unknown, expired, already spent, or bound to another session SHALL be refused as an invalid second-factor code and counted as a failed verification. A challenge SHALL only ever be compared with one the library issued, never accepted from the request alone.

A begin path naming a method that has no begin step SHALL be refused as an unknown MFA method.

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

#### Scenario: Begin for a method without a begin step
- **WHEN** a pending session posts to the begin path of the TOTP method
- **THEN** it is refused as an unknown MFA method

## MODIFIED Requirements

### Requirement: Methods declare a constant, non-empty channel
Every MFA method SHALL report a name and the channel its codes travel over, using a channel value defined by the identity model, and SHALL report the same channel for its whole lifetime. A method's name SHALL be one path segment of lowercase letters, digits and hyphens, starting with a letter or digit. The built-in TOTP method SHALL be named `totp` and report the identity model's `authenticator-app` channel, which is not the channel of any first-factor kind the library names. A component SHALL be constructed with a set of one or more methods, and construction SHALL fail with a configuration error when the set is empty, or when any method in it is absent, has an empty channel or an invalid name, or shares its name with another method in the set. A consumer SHALL be able to supply their own methods alongside or instead of TOTP.

#### Scenario: TOTP channel
- **WHEN** the channel of the built-in TOTP method is requested
- **THEN** it is `authenticator-app`
- **AND** it differs from the channels of `password`, `basic`, `magic-link`, `oidc` and `api-key`

#### Scenario: Consumer email method
- **WHEN** a consumer supplies an email one-time-code method reporting channel `email`
- **THEN** MFA components accept it and report its channel as `email`

#### Scenario: Two methods
- **WHEN** a component is constructed with TOTP and a consumer's method named `email-code`
- **THEN** construction succeeds and both methods are served

#### Scenario: Empty channel
- **WHEN** a component is constructed with a method whose channel is empty
- **THEN** construction fails with a configuration error

#### Scenario: Duplicate names
- **WHEN** a component is constructed with two methods both named `totp`
- **THEN** construction fails with a configuration error

#### Scenario: Empty set
- **WHEN** a component is constructed with no methods
- **THEN** construction fails with a configuration error

### Requirement: Failed verifications are throttled per user
The library SHALL count failed verifications per user reference, across every method: a failure on any method SHALL count toward the same limit. It SHALL refuse further verifications for a user at the limit with a throttled error, without checking the response. The default SHALL be 5 failures per 15 minutes. A successful verification SHALL spend nothing. A consumer SHALL be able to replace the limiter. A limiter that cannot decide SHALL cause the verification to be refused.

Recording a failure SHALL NOT be abandoned because the caller went away: a guess that was made SHALL be charged even if the client disconnects before the answer is written. The context handed to the limiter when recording a failure SHALL therefore carry no cancellation from the request.

#### Scenario: A client that hangs up is still charged
- **WHEN** a wrong code is presented and the request's context is already cancelled
- **THEN** the failure is still recorded against that user

#### Scenario: Guessing codes
- **WHEN** five wrong codes are presented for `u-1` within 15 minutes and then a valid code is presented
- **THEN** the valid code is refused with the throttled error

#### Scenario: Guessing across methods
- **WHEN** `u-1` is enrolled on two methods, presents three wrong responses to one and two to the other within 15 minutes, and then presents a valid response to either
- **THEN** the valid response is refused with the throttled error

#### Scenario: Other users unaffected
- **WHEN** `u-1` is throttled and `u-2` presents a valid code
- **THEN** `u-2`'s verification succeeds

#### Scenario: Consumer limiter
- **WHEN** code verification is configured with a consumer's shared limiter
- **THEN** every check and failure for code verification goes to that limiter, keyed by user reference

#### Scenario: Limiter outage
- **WHEN** the limiter returns an error for `u-1`
- **THEN** the verification is refused

### Requirement: A second factor on the first factor's channel is refused at verification
When a session's recorded first factor has the same channel as the method named in the verify or begin path, the endpoint SHALL refuse with a same-channel error before reading the request body. It SHALL leave the session's MFA challenge pending and record no failed verification. This check has no override. Whether such a login is challenged at all is decided by the security policy's same-channel rule.

#### Scenario: Email code after a magic link
- **WHEN** a session established by magic link, with the MFA challenge pending, posts a code to the verify path of an email one-time-code method
- **THEN** the same-channel error is returned
- **AND** the method is not asked to verify the code
- **AND** the challenge stays pending

#### Scenario: Authenticator code after a magic link
- **WHEN** a session established by magic link, with the MFA challenge pending, posts a valid TOTP code to TOTP's verify path
- **THEN** verification proceeds and succeeds

### Requirement: The verify endpoint resolves the challenge and rotates the session
The verify endpoint SHALL match only POST requests to one path per configured method, formed from a verify prefix and the method's name, the prefix being `/mfa/verify` by default and replaceable by an option. The method to verify against SHALL be read from the path only, never from a header, the URL query or the body. Before the request body is read, the endpoint SHALL refuse, in order:
- a request with no session, or whose session carries no resolved caller, as authentication required — the credential the endpoint issues names a principal, so a session without one cannot be answered;
- a path naming no configured method, as an unknown MFA method;
- a method on the session's first-factor channel, with the same-channel error;
- a method the session's user may not use, as the MFA method not usable, where usable means enrolled and on a channel that differs from the first factor's, as decided by the one function the security policies use; a failed enrolment lookup SHALL propagate as a refusal.

None of these refusals SHALL be counted against the verification throttle. The endpoint SHALL then check the throttle, read the response with the method's declared reader, spend the pending challenge of a challenge method, and have the method verify the response.

The endpoint SHALL be given a token generator at construction, and a chain that enables it without one SHALL fail to assemble: the endpoint's whole purpose on success is to hand back a credential for the rotated session, and it has none to issue without a generator.

On a verified response the endpoint SHALL:
- resolve the session's MFA challenge, which records the second-factor-satisfied time;
- for a session that entered the MFA pending state through the enrolment path, restore its normal deadlines, as the `sessions` capability defines;
- rotate the session handle;
- write the response itself, through a replaceable responder that receives the rotated session;
- answer with a success status without passing the request to later handlers.

Because the endpoint answers the request itself, no later handler runs, so the rotated handle SHALL
reach the caller through that responder or not at all. With no responder supplied the library SHALL
write a credential the caller can use for its next request; a consumer SHALL be able to replace that
whole response, for example to set a cookie instead.

Rotation SHALL NOT strand the caller: a caller that completes its second factor SHALL be able to
make an authenticated request afterwards without signing in again.

However many methods are configured, this endpoint SHALL be the only place that resolves a session's MFA challenge. A session SHALL become a full session through the enrolment path only by this endpoint: a confirmed enrolment alone SHALL NOT satisfy the challenge.

On any failure the challenge SHALL stay pending, the handle SHALL be unchanged, and the error SHALL propagate to the consumer's error handling unchanged.

#### Scenario: Successful verification
- **WHEN** a session with the MFA challenge pending posts a valid code to `/mfa/verify/totp`
- **THEN** the session reports no pending challenge and a second-factor-satisfied time
- **AND** the previous session handle no longer loads
- **AND** the response carries a credential naming the rotated session, so the next request authenticates

#### Scenario: Upgrade from the enrolment path
- **WHEN** a session created at 09:00 entered the enrolment path, confirmed its enrolment at 09:08, and posts a fresh valid code at 09:09 with a 12-hour absolute timeout
- **THEN** the rotated session reports a satisfied second factor and an absolute deadline of 21:00

#### Scenario: Confirmation alone is not a second factor
- **WHEN** a session's enrolment has just been confirmed through the path and it requests `/invoices`
- **THEN** an MFA challenge error is returned

#### Scenario: The caller is not stranded by rotation
- **WHEN** a bearer caller completes its second factor and then requests a protected route with the credential the verify response returned
- **THEN** the request is authenticated and reaches the handler

#### Scenario: Consumer responder
- **WHEN** the endpoint is configured with a responder that sets a session cookie and writes no body
- **THEN** that responder writes the response instead of the library's default
- **AND** it receives the rotated session

#### Scenario: A session with no resolved caller
- **WHEN** a request to a verify path carries a session but no resolved caller
- **THEN** it is refused as authentication required, and no body is read and no failure is recorded

#### Scenario: No token generator
- **WHEN** a chain enables the verify endpoint without a token generator
- **THEN** assembly fails with a configuration error

#### Scenario: Wrong code
- **WHEN** a session with the MFA challenge pending posts a wrong code
- **THEN** the invalid-code error propagates
- **AND** the challenge stays pending and the handle is unchanged

#### Scenario: Unknown method
- **WHEN** a pending session posts to `/mfa/verify/sms`, and no method named `sms` is configured
- **THEN** it is refused as an unknown MFA method, no body is read and no failure is counted

#### Scenario: Method the user is not enrolled on
- **WHEN** TOTP and `email-code` are configured, `u-1` is enrolled only on TOTP, and `u-1`'s pending session posts to `/mfa/verify/email-code`
- **THEN** it is refused as the MFA method not usable, the method is not called, and no failure is counted

#### Scenario: Method named in the query or body is ignored
- **WHEN** a pending session posts a valid TOTP code to `/mfa/verify/totp?method=email-code` with a body field `method=email-code`
- **THEN** TOTP verifies the code and the challenge is resolved

#### Scenario: GET is not verification
- **WHEN** a GET request is made to a verify path
- **THEN** it passes through without verifying anything

#### Scenario: Consumer path
- **WHEN** the verify prefix is configured as `/auth/second-factor` and a pending session posts a valid code to `/auth/second-factor/totp`
- **THEN** the challenge is resolved

#### Scenario: Code in the query string
- **WHEN** a session with the MFA challenge pending posts to TOTP's verify path with a valid code in the query string and an empty body
- **THEN** it is refused as missing credentials
- **AND** the challenge stays pending and no failure is counted

#### Scenario: Code in the query overrides nothing
- **WHEN** a pending session posts a wrong code in the body and a valid code in the query string
- **THEN** the invalid-code error propagates and the challenge stays pending

#### Scenario: Unreadable body
- **WHEN** a pending session posts a valid code as a multipart form to TOTP's verify path
- **THEN** it is refused as missing credentials, the challenge stays pending, and no failure is counted

### Requirement: A session with a pending MFA challenge reaches no protected handler
A request whose session has the MFA challenge pending SHALL be refused with an MFA challenge error carrying that session and the session user's usable methods. The refused request SHALL NOT reach later handlers. These requests are exempt: every verify path, every begin path, the method-listing endpoint when it is enabled, and the logout endpoint, wherever it is placed in the chain relative to the gate. A session with a pending challenge SHALL always be able to log out, and logging out SHALL end that session, pending challenge included.

#### Scenario: Pending session requests a protected route
- **WHEN** a session with the MFA challenge pending requests `/invoices`
- **THEN** an MFA challenge error is returned
- **AND** the route's handler is not called

#### Scenario: Pending session begins a challenge method
- **WHEN** a session with the MFA challenge pending posts to the begin path of a challenge method it is enrolled on
- **THEN** no MFA challenge error is returned and a pending challenge is issued

#### Scenario: Pending session logs out
- **WHEN** a session with the MFA challenge pending posts to the logout endpoint
- **THEN** no MFA challenge error is returned
- **AND** the session is deleted, and its handle no longer loads

#### Scenario: Consumer logout path
- **WHEN** logout is configured with path `/auth/sign-out` and a session with the MFA challenge pending posts there
- **THEN** the session is deleted

### Requirement: The enrolment path is off unless enabled on both the policy and the chain
The enrolment path SHALL be off by default. With it off, a required user with no usable enrolment SHALL be refused exactly as before this capability offered a path. A consumer SHALL turn it on explicitly, on the MFA requirement policy and on the chain. Chain assembly SHALL fail with a configuration error when only one side is configured:
- the policy side is on and nothing registered enforces the enrolment challenge;
- the chain side is on and no registered policy can raise the enrolment challenge.

It SHALL also fail when the chain side is on and no MFA method is enabled, or no enabled method can enrol through the path, or a method the consumer names for the path is not enabled or cannot enrol, or the consumer names an empty list, or an enrolling method's enrolment store cannot record a device proof. An enrolment store that cannot record a device proof SHALL keep serving out-of-band enrolment. The methods that can be enrolled through the path SHALL be, by default, every enabled MFA method that supports the path, and a consumer SHALL be able to narrow them by naming them; no method outside the verify endpoint's methods SHALL be enrolled through the path.

#### Scenario: Default is off
- **WHEN** MFA is required for all users, the path is not enabled, and a user who has never enrolled logs in by password with a correct password
- **THEN** the login is refused with the enrolment-required reason
- **AND** no session is established

#### Scenario: Consumer enables the path
- **WHEN** the consumer enables the path on both the policy and the chain, and the same user logs in by password
- **THEN** the login is refused with an enrolment challenge carrying a session and a token

#### Scenario: Policy side only
- **WHEN** the path is enabled on the MFA requirement policy and the chain has no enrolment interceptor
- **THEN** chain assembly fails with a configuration error naming the enrolment challenge

#### Scenario: Chain side only
- **WHEN** the enrolment interceptor is enabled and no registered policy can raise the enrolment challenge
- **THEN** chain assembly fails with a configuration error

#### Scenario: Method that cannot enrol
- **WHEN** the enrolment interceptor is enabled and no enabled MFA method supports enrolment
- **THEN** chain assembly fails with a configuration error

#### Scenario: Consumer names a method that cannot enrol
- **WHEN** TOTP and a consumer's method that cannot enrol are enabled, and the enrolment interceptor is told to enrol the consumer's method
- **THEN** chain assembly fails with a configuration error

#### Scenario: Store that cannot record a device proof
- **WHEN** the enrolment interceptor is enabled and the TOTP method's enrolment store implements only the single-call confirmation
- **THEN** chain assembly fails with a configuration error
- **AND** the same store still begins and confirms enrolments out of band

### Requirement: An enrolment-only session reaches only the enrolment endpoints and logout
A request whose session is in the enrolment-pending state SHALL be refused with an enrolment challenge error carrying that session, whatever its method or path, before any interceptor after the enrolment gate runs. These requests are exempt:
- a POST to a begin path, formed from the begin prefix, by default `/mfa/enrol/begin`, and an enrolling method's name;
- a POST to a confirm path, under the confirm prefix, by default `/mfa/enrol/confirm`;
- a POST to an emailed-code path, under the emailed-code prefix, by default `/mfa/enrol/confirm-email`, when email confirmation is on;
- the logout endpoint, wherever it is placed in the chain relative to the gate.

Each enrolment prefix SHALL be replaceable by an option. There SHALL be no option that lets further routes through. The MFA verify and begin endpoints, the method-listing endpoint and the password-change resolve endpoint SHALL be refused like any other route. A session in the enrolment-pending state SHALL always be able to log out, and logging out SHALL end it.

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

#### Scenario: Logout
- **WHEN** an enrolment-only session posts to the logout endpoint
- **THEN** no enrolment challenge error is returned
- **AND** the session is deleted, and its handle no longer loads

#### Scenario: Consumer path
- **WHEN** the begin prefix is configured as `/account/2fa/start` and an enrolment-only session posts to `/account/2fa/start/totp`
- **THEN** a pending enrolment is begun

### Requirement: Enrolment endpoints begin and confirm on the session's own user
Every enrolment endpoint SHALL act on the method named in its path, which SHALL be one of the methods that can be enrolled through the path; any other name SHALL be refused as an unknown MFA method. The begin endpoint SHALL begin a pending enrolment on that method for the session's user, and answer with the method's provisioning data. The account label in that data SHALL come from a label resolver over the user's loaded details, by default the username, and SHALL NOT be read from the request. Begin SHALL be refused:
- with the same-channel error, before anything is generated, when the named method's channel equals the session's first-factor channel;
- with the already-enrolled error when the user has a confirmed enrolment on that method, leaving it unchanged.

Beginning again SHALL replace the pending enrolment and start a new generation, recorded on the session. A generation SHALL belong to the method that issued it: a confirmation naming another method SHALL be refused as that method's store refuses an unknown generation.

The confirm endpoint SHALL read a code from the `code` form field and prove the device with it against the pending enrolment of the session's generation on the named method. The endpoints SHALL read no other request field, and SHALL write only to the enrolment and to the session's library-owned second-factor fields. No enrolment endpoint SHALL change a password or an account attribute, or remove an enrolment.

#### Scenario: Begin
- **WHEN** an enrolment-only session for `u-1`, established by password, posts to `/mfa/enrol/begin/totp`
- **THEN** the response carries a TOTP secret and a provisioning URI whose account label is `u-1`'s username
- **AND** `u-1` is reported as not enrolled

#### Scenario: Label from the request is ignored
- **WHEN** the begin request carries a form field `label=attacker@example.com`
- **THEN** the provisioning URI's account label is still the one the label resolver returned

#### Scenario: Consumer label resolver
- **WHEN** the consumer configures a label resolver that returns the user's display email
- **THEN** the provisioning URI's account label is that email

#### Scenario: Same channel at begin
- **WHEN** a session established by magic link begins an enrolment on an email one-time-code method
- **THEN** begin fails with the same-channel error and nothing is stored

#### Scenario: Unknown method at begin
- **WHEN** an enrolment-only session posts to `/mfa/enrol/begin/sms`, and no enrollable method is named `sms`
- **THEN** it is refused as an unknown MFA method and nothing is stored

#### Scenario: Device code confirms the device
- **WHEN** the session posts a valid code for the pending secret to `/mfa/enrol/confirm/totp`, with email confirmation on
- **THEN** the device is proven and the user is still reported as not enrolled

#### Scenario: Wrong device code
- **WHEN** the session posts a wrong code to the confirm path
- **THEN** the invalid-code error propagates and the device is not proven

### Requirement: An operator reset removes the enrolment, ends sessions and notifies
The library SHALL offer an operation that resets a user's second factors. It SHALL be given the enrolment remover of every method to reset, and SHALL remove the user's enrolment on each, in order, then delete every session of the user, then notify the user. Every dependency SHALL be checked before anything is written; an empty list of removers, or an absent remover, SHALL be a configuration error. A removal failure SHALL stop the reset and be returned: the user's sessions SHALL NOT be deleted and no notification SHALL be sent, and removals already done SHALL stay done. Any failure after the removals (deleting sessions, loading the user, resolving the address, sending) SHALL be returned after the removals, never swallowed. The user's MFA requirement SHALL be unchanged. A consumer SHALL be able to turn off session deletion and notification, each by an explicit option. A missing sender while notification is on SHALL be a configuration error, returned before any enrolment is removed. By default the notification SHALL name the time of the reset and carry no code, secret or identifier; a consumer SHALL be able to replace its subject and body by an option, while the library still sets the recipient. The operation SHALL NOT be exposed over HTTP by the library.

#### Scenario: Reset
- **WHEN** `u-1`, who holds two sessions and a confirmed enrolment, is reset
- **THEN** `u-1` is not enrolled, neither session handle loads, and a notification is queued
- **AND** `u-1` is still required to use MFA

#### Scenario: Reset across methods
- **WHEN** `u-1` is enrolled on TOTP and on a consumer's method, and is reset with both methods' removers
- **THEN** `u-1` is enrolled on neither

#### Scenario: A removal fails
- **WHEN** a reset is given two removers and the second fails
- **THEN** the reset returns that error, the first method's enrolment is removed, and `u-1`'s sessions still load

#### Scenario: Session store failure
- **WHEN** deleting `u-1`'s sessions fails during a reset
- **THEN** the reset returns that error
- **AND** the enrolments are already removed

#### Scenario: Consumer message
- **WHEN** a reset is run with a consumer's message builder
- **THEN** the notification carries the consumer's subject and body, addressed to the user's contact address

#### Scenario: Missing sender
- **WHEN** a reset is run with notification on and no sender
- **THEN** it fails with a configuration error
- **AND** the enrolment is still in place

#### Scenario: No removers
- **WHEN** a reset is run with an empty list of removers
- **THEN** it fails with a configuration error and nothing is written

#### Scenario: Consumer keeps sessions
- **WHEN** a reset is run with session deletion turned off
- **THEN** the enrolment is removed and `u-1`'s sessions still load
