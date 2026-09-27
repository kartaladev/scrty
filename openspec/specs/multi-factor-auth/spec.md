# multi-factor-auth Specification

## Purpose

Lets a user prove a second factor after the first, with methods that declare the channel their codes travel over. TOTP is built in. Codes cannot be replayed or guessed without limit, and a lost or unreadable enrolment never lets a user who is required to use MFA through.

## Requirements

### Requirement: Methods declare a constant, non-empty channel
Every MFA method SHALL report a name and the channel its codes travel over, using a channel value defined by the identity model, and SHALL report the same channel for its whole lifetime. The built-in TOTP method SHALL report the identity model's `authenticator-app` channel, which is not the channel of any first-factor kind the library names. Constructing a component with a method whose channel is empty SHALL fail with a configuration error. A consumer SHALL be able to supply their own method.

#### Scenario: TOTP channel
- **WHEN** the channel of the built-in TOTP method is requested
- **THEN** it is `authenticator-app`
- **AND** it differs from the channels of `password`, `basic`, `magic-link`, `oidc` and `api-key`

#### Scenario: Consumer email method
- **WHEN** a consumer supplies an email one-time-code method reporting channel `email`
- **THEN** MFA components accept it and report its channel as `email`

#### Scenario: Empty channel
- **WHEN** a component is constructed with a method whose channel is empty
- **THEN** construction fails with a configuration error

### Requirement: Enrolment answers are definitive or errors
A method SHALL report that a user is not enrolled only when its store definitively holds no enrolment for that user. When the store cannot answer, or holds an enrolment that cannot be read, the method SHALL return an error and SHALL NOT report the user as not enrolled.

#### Scenario: Store outage is not "not enrolled"
- **WHEN** the enrolment store returns a connection error while a user's enrolment is looked up
- **THEN** the lookup returns an error
- **AND** does not report the user as not enrolled

#### Scenario: Unreadable enrolment
- **WHEN** a user's stored enrolment secret cannot be opened
- **THEN** the lookup returns an error
- **AND** does not report the user as not enrolled

### Requirement: The TOTP issuer is required configuration
Constructing the TOTP method SHALL fail with a configuration error when no issuer is given, or when the issuer contains a colon. The library SHALL NOT supply a default issuer. The issuer SHALL appear in every provisioning URI the method produces.

#### Scenario: Missing issuer
- **WHEN** a TOTP method is constructed without an issuer
- **THEN** construction fails with a configuration error naming the issuer

#### Scenario: Consumer issuer
- **WHEN** a TOTP method is constructed with issuer `Example Payroll` and an enrolment is begun
- **THEN** the provisioning URI names the issuer `Example Payroll`

### Requirement: TOTP codes follow RFC 6238
The TOTP method SHALL verify codes as RFC 6238 specifies, with HMAC-SHA-1. It SHALL accept a code for the current time step or for one step on either side. The defaults SHALL be 6 digits and a 30-second step. A consumer SHALL be able to choose 8 digits and another step length. Constructing the method with a digit count other than 6 or 8, or a step of zero or less, SHALL fail with a configuration error. A wrong code SHALL fail with an invalid-code error. Codes SHALL be compared in constant time.

#### Scenario: RFC test vector
- **WHEN** a method configured with 8 digits verifies code `94287082` against the RFC 6238 SHA-1 test secret at Unix time 59
- **THEN** verification succeeds

#### Scenario: Previous step accepted
- **WHEN** a code for the previous 30-second step is presented with default options
- **THEN** verification succeeds

#### Scenario: Two steps old rejected
- **WHEN** a code for two steps ago is presented with default options
- **THEN** verification fails with the invalid-code error

#### Scenario: Consumer digits
- **WHEN** the method is configured with 8 digits and a valid 8-digit code is presented
- **THEN** verification succeeds

#### Scenario: Invalid digit count
- **WHEN** a TOTP method is constructed with 7 digits
- **THEN** construction fails with a configuration error

### Requirement: Each time step is accepted at most once per user
When a code is accepted, the method SHALL record the matched time step for that user in the same store operation that decides acceptance. It SHALL reject, with the invalid-code error, any later code whose matched step is at or before the recorded step. Of concurrent verifications of the same code for the same user, at most one SHALL succeed.

#### Scenario: Replayed code
- **WHEN** a valid code is accepted and the same code is presented again within its step
- **THEN** the second verification fails with the invalid-code error

#### Scenario: Racing verifications
- **WHEN** 16 goroutines verify the same valid code for one user at the same time
- **THEN** exactly one verification succeeds

### Requirement: Enrolment is usable only after confirmation
Beginning a TOTP enrolment for a user SHALL:
- generate a secret of 20 bytes from the operating system's cryptographically secure random source;
- store it as a pending enrolment;
- return the secret in base32 and a provisioning URI naming the issuer and the account label the caller supplies.

The library SHALL NOT derive the account label, and SHALL reject an empty label or one containing a colon. A pending enrolment SHALL NOT count as enrolled and SHALL NOT satisfy a challenge. Confirming SHALL require a valid code for the pending secret, SHALL then make the enrolment confirmed, and SHALL record the code's step. Beginning again while an enrolment is pending SHALL replace the pending secret. If the random source fails, beginning SHALL return an error and store nothing.

#### Scenario: Pending is not enrolled
- **WHEN** an enrolment is begun for `u-1` and not confirmed
- **THEN** `u-1` is reported as not enrolled

#### Scenario: Confirmation
- **WHEN** an enrolment for `u-1` is confirmed with a valid code
- **THEN** `u-1` is reported as enrolled on the TOTP method

#### Scenario: Wrong confirmation code
- **WHEN** an enrolment for `u-1` is confirmed with a wrong code
- **THEN** confirmation fails with the invalid-code error
- **AND** `u-1` is not enrolled

#### Scenario: Random source failure
- **WHEN** the random source fails while an enrolment is begun
- **THEN** beginning returns an error and nothing is stored

### Requirement: A confirmed enrolment is not replaced silently
Beginning an enrolment for a user who already has a confirmed enrolment SHALL fail with an already-enrolled error, and SHALL leave the confirmed enrolment unchanged. Removing an enrolment SHALL be a separate, explicit operation.

#### Scenario: Re-enrolment attempt
- **WHEN** an enrolment is begun for `u-1`, who has a confirmed enrolment
- **THEN** it fails with the already-enrolled error
- **AND** codes from `u-1`'s existing authenticator still verify

### Requirement: A lost enrolment never downgrades a required user
Removing, losing or failing to read a user's enrolment SHALL NOT change whether that user is required to use MFA. The requirement is read from the user, never from the enrolment. After a required user's enrolment is removed, their next login SHALL NOT be completed on the first factor: with the enrolment path off, it SHALL be refused as requiring enrolment; with the path on and the first factor eligible for it, it SHALL enter the enrolment-only state. A failed or unreadable enrolment lookup for a required user SHALL refuse the login.

#### Scenario: Enrolment deleted
- **WHEN** `u-1` is required to use MFA, their enrolment is removed, and they log in by password
- **THEN** the login is refused with the enrolment-required reason
- **AND** no session is established without a second factor

#### Scenario: Enrolment deleted with the path on
- **WHEN** the enrolment path is on, `u-1` is required to use MFA, their enrolment is removed, and they log in by password
- **THEN** the login is refused with an enrolment challenge
- **AND** the session it carries reaches only the enrolment endpoints and logout

#### Scenario: Enrolment store outage
- **WHEN** `u-1` is required to use MFA and the enrolment lookup fails during their password login
- **THEN** the login is refused

### Requirement: Requiring MFA for all locks out unenrolled users
When MFA is required for all users and the enrolment path is off, a user with no usable enrolment SHALL be refused at every non-exempt login, and this capability SHALL offer them no way to enrol through that login. This SHALL be documented as a limit, together with the enrolment path that lifts it. With the path on, such a user whose first factor is eligible SHALL instead enter the enrolment-only state. A user whose first factor is not eligible, or whose only method shares the first factor's channel, SHALL still be refused.

#### Scenario: Unenrolled user under require-for-all
- **WHEN** MFA is required for all users, the path is off, and a user who has never enrolled logs in by password with a correct password
- **THEN** the login is refused with the enrolment-required reason
- **AND** no session is established

#### Scenario: Unenrolled user with the path on
- **WHEN** MFA is required for all users, the path is on, and a user who has never enrolled logs in by password with a correct password
- **THEN** the login is refused with an enrolment challenge carrying a session and a token

### Requirement: Failed verifications are throttled per user
The library SHALL count failed code verifications per user reference. It SHALL refuse further verifications for a user at the limit with a throttled error, without checking the code. The default SHALL be 5 failures per 15 minutes. A successful verification SHALL spend nothing. A consumer SHALL be able to replace the limiter. A limiter that cannot decide SHALL cause the verification to be refused.

Recording a failure SHALL NOT be abandoned because the caller went away: a guess that was made SHALL be charged even if the client disconnects before the answer is written. The context handed to the limiter when recording a failure SHALL therefore carry no cancellation from the request.

#### Scenario: A client that hangs up is still charged
- **WHEN** a wrong code is presented and the request's context is already cancelled
- **THEN** the failure is still recorded against that user

#### Scenario: Guessing codes
- **WHEN** five wrong codes are presented for `u-1` within 15 minutes and then a valid code is presented
- **THEN** the valid code is refused with the throttled error

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
When a session's recorded first factor has the same channel as the method, the verify endpoint SHALL refuse with a same-channel error before reading the presented code. It SHALL leave the session's MFA challenge pending and record no failed verification. This check has no override. Whether such a login is challenged at all is decided by the security policy's same-channel rule.

#### Scenario: Email code after a magic link
- **WHEN** a session established by magic link, with the MFA challenge pending, posts a code to the verify endpoint of an email one-time-code method
- **THEN** the same-channel error is returned
- **AND** the method is not asked to verify the code
- **AND** the challenge stays pending

#### Scenario: Authenticator code after a magic link
- **WHEN** a session established by magic link, with the MFA challenge pending, posts a valid TOTP code
- **THEN** verification proceeds and succeeds

### Requirement: The verify endpoint resolves the challenge and rotates the session
The verify endpoint SHALL match only POST requests to its path, and SHALL read the code from the `code` field of a URL-encoded POST body only, never from the URL query. A body that carries no code, is not a URL-encoded form, or does not parse SHALL be refused as missing credentials before any code is checked, and SHALL NOT be counted against the verification throttle; the endpoint's documentation SHALL state that only a URL-encoded body is read. The default path SHALL be `/mfa/totp`, replaceable by an option. A request with no session SHALL be refused as authentication required, and so SHALL a request whose session carries no resolved caller — the credential the endpoint issues names a principal, so a session without one cannot be answered. Both refusals SHALL happen before the code is read.

The endpoint SHALL be given a token generator at construction, and a chain that enables it without one SHALL fail to assemble: the endpoint's whole purpose on success is to hand back a credential for the rotated session, and it has none to issue without a generator.

On a valid code the endpoint SHALL:
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

A session SHALL become a full session through the enrolment path only by this endpoint: a confirmed enrolment alone SHALL NOT satisfy the challenge.

On any failure the challenge SHALL stay pending, the handle SHALL be unchanged, and the error SHALL propagate to the consumer's error handling unchanged.

#### Scenario: Successful verification
- **WHEN** a session with the MFA challenge pending posts a valid code
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
- **WHEN** a request to the verify path carries a session but no resolved caller
- **THEN** it is refused as authentication required, and no code is read and no failure is recorded

#### Scenario: No token generator
- **WHEN** a chain enables the verify endpoint without a token generator
- **THEN** assembly fails with a configuration error

#### Scenario: Wrong code
- **WHEN** a session with the MFA challenge pending posts a wrong code
- **THEN** the invalid-code error propagates
- **AND** the challenge stays pending and the handle is unchanged

#### Scenario: GET is not verification
- **WHEN** a GET request is made to the verify path
- **THEN** it passes through without verifying anything

#### Scenario: Consumer path
- **WHEN** the endpoint is configured with path `/auth/second-factor` and a pending session posts a valid code there
- **THEN** the challenge is resolved

#### Scenario: Code in the query string
- **WHEN** a session with the MFA challenge pending posts to the verify path with a valid code in the query string and an empty body
- **THEN** it is refused as missing credentials
- **AND** the challenge stays pending and no failure is counted

#### Scenario: Code in the query overrides nothing
- **WHEN** a pending session posts a wrong code in the body and a valid code in the query string
- **THEN** the invalid-code error propagates and the challenge stays pending

#### Scenario: Unreadable body
- **WHEN** a pending session posts a valid code as a multipart form
- **THEN** it is refused as missing credentials, the challenge stays pending, and no failure is counted

### Requirement: A session with a pending MFA challenge reaches no protected handler
A request whose session has the MFA challenge pending SHALL be refused with an MFA challenge error carrying that session. The refused request SHALL NOT reach later handlers. Two requests are exempt: the verify endpoint, and the logout endpoint, wherever it is placed in the chain relative to the gate. A session with a pending challenge SHALL always be able to log out, and logging out SHALL end that session, pending challenge included.

#### Scenario: Pending session requests a protected route
- **WHEN** a session with the MFA challenge pending requests `/invoices`
- **THEN** an MFA challenge error is returned
- **AND** the route's handler is not called

#### Scenario: Pending session logs out
- **WHEN** a session with the MFA challenge pending posts to the logout endpoint
- **THEN** no MFA challenge error is returned
- **AND** the session is deleted, and its handle no longer loads

#### Scenario: Consumer logout path
- **WHEN** logout is configured with path `/auth/sign-out` and a session with the MFA challenge pending posts there
- **THEN** the session is deleted

### Requirement: MFA logs carry no codes or secrets
Records written for MFA verification and enrolment SHALL contain neither a presented code, an emailed code, an enrolment secret, a provisioning URI nor a contact address. Throttle refusals SHALL be written through a log sampler with a reporter, keyed by refusal reason. The window SHALL default to one minute and be configurable by an option that governs only MFA verification logs. Enrolment path refusals SHALL be written through a sampler of their own, with a reporter, whose window defaults to one minute and is configurable by an option that governs only enrolment path logs.

#### Scenario: No codes in logs
- **WHEN** a wrong code `123456` is refused
- **THEN** no written log record contains `123456`

#### Scenario: No enrolment secrets in logs
- **WHEN** an enrolment is begun, its device proven and its emailed code refused once
- **THEN** no written log record contains the secret, the provisioning URI, the emailed code or the contact address

#### Scenario: Throttled guessing
- **WHEN** 200 verifications for one throttled user are refused within one minute
- **THEN** one throttle record is written for that minute

#### Scenario: Consumer interval for enrolment logs only
- **WHEN** the enrolment log interval is set to zero and the verification log interval keeps its default
- **THEN** every enrolment refusal is logged
- **AND** verification throttle refusals are still sampled per minute

### Requirement: The enrolment path is off unless enabled on both the policy and the chain
The enrolment path SHALL be off by default. With it off, a required user with no usable enrolment SHALL be refused exactly as before this capability offered a path. A consumer SHALL turn it on explicitly, on the MFA requirement policy and on the chain. Chain assembly SHALL fail with a configuration error when only one side is configured:
- the policy side is on and nothing registered enforces the enrolment challenge;
- the chain side is on and no registered policy can raise the enrolment challenge.

It SHALL also fail when the chain side is on and the MFA method cannot enrol, its enrolment store cannot record a device proof, or no MFA method is enabled. An enrolment store that cannot record a device proof SHALL keep serving out-of-band enrolment. The enrolling method SHALL be the MFA method the verify endpoint uses; no other method SHALL be enrolled through the path.

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
- **WHEN** the enrolment interceptor is enabled and the MFA method does not support enrolment
- **THEN** chain assembly fails with a configuration error

#### Scenario: Store that cannot record a device proof
- **WHEN** the enrolment interceptor is enabled and the TOTP method's enrolment store implements only the single-call confirmation
- **THEN** chain assembly fails with a configuration error
- **AND** the same store still begins and confirms enrolments out of band

### Requirement: An enrolment-only session reaches only the enrolment endpoints and logout
A request whose session is in the enrolment-pending state SHALL be refused with an enrolment challenge error carrying that session, whatever its method or path, before any interceptor after the enrolment gate runs. Four requests are exempt:
- a POST to the begin path, by default `/mfa/enrol/begin`;
- a POST to the confirm path, by default `/mfa/enrol/confirm`;
- a POST to the emailed-code path, by default `/mfa/enrol/confirm-email`, when email confirmation is on;
- the logout endpoint, wherever it is placed in the chain relative to the gate.

Each enrolment path SHALL be replaceable by an option. There SHALL be no option that lets further routes through. The MFA verify endpoint and the password-change resolve endpoint SHALL be refused like any other route. A session in the enrolment-pending state SHALL always be able to log out, and logging out SHALL end it.

#### Scenario: Protected route
- **WHEN** an enrolment-only session requests `/invoices`
- **THEN** an enrolment challenge error carrying the session is returned
- **AND** the route's handler, the authorizer and any consumer interceptor after the gate do not run

#### Scenario: Verify endpoint is not reachable
- **WHEN** an enrolment-only session posts a code to the MFA verify path
- **THEN** an enrolment challenge error is returned and no code is verified

#### Scenario: GET on an enrolment path
- **WHEN** an enrolment-only session sends a GET to the begin path
- **THEN** an enrolment challenge error is returned

#### Scenario: Logout
- **WHEN** an enrolment-only session posts to the logout endpoint
- **THEN** no enrolment challenge error is returned
- **AND** the session is deleted, and its handle no longer loads

#### Scenario: Consumer path
- **WHEN** the begin path is configured as `/account/2fa/start` and an enrolment-only session posts there
- **THEN** a pending enrolment is begun

### Requirement: Enrolment endpoints begin and confirm on the session's own user
The begin endpoint SHALL begin a pending enrolment on the MFA method for the session's user, and answer with the method's provisioning data. The account label in that data SHALL come from a label resolver over the user's loaded details, by default the username, and SHALL NOT be read from the request. Begin SHALL be refused:
- with the same-channel error, before anything is generated, when the MFA method's channel equals the session's first-factor channel;
- with the already-enrolled error when the user has a confirmed enrolment, leaving it unchanged.

Beginning again SHALL replace the pending enrolment and start a new generation, recorded on the session.

The confirm endpoint SHALL read a code from the `code` form field and prove the device with it against the pending enrolment of the session's generation. The endpoints SHALL read no other request field, and SHALL write only to the enrolment and to the session's library-owned second-factor fields. No enrolment endpoint SHALL change a password or an account attribute, or remove an enrolment.

#### Scenario: Begin
- **WHEN** an enrolment-only session for `u-1`, established by password, posts to the begin path
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

#### Scenario: Device code confirms the device
- **WHEN** the session posts a valid code for the pending secret to the confirm path, with email confirmation on
- **THEN** the device is proven and the user is still reported as not enrolled

#### Scenario: Wrong device code
- **WHEN** the session posts a wrong code to the confirm path
- **THEN** the invalid-code error propagates and the device is not proven

### Requirement: Device proof and completion are separate, generation-bound writes
An enrolment SHALL carry a generation, which every begin replaces. Proving the device and completing the enrolment SHALL each be one conditional store write, decided by the write rather than by a preceding read:
- **proving the device** SHALL record the code's time step, the device-proof time and the emailed code only where the generation matches, the enrolment is pending, the device is not yet proven and the step is later than the recorded one;
- **completing** SHALL mark the enrolment confirmed only where the generation matches, the device is proven and the enrolment is not yet confirmed.

Beginning again SHALL clear the device proof and the emailed code. Every enrolment store SHALL pass these cases in the store conformance suite. The single-call confirmation this capability already defines SHALL remain for consumers who enrol out of band.

#### Scenario: A newer begin invalidates an earlier proof
- **WHEN** `u-1` proves a device in session B, a second session A for `u-1` then begins again, and session B completes with the emailed code it received
- **THEN** completion fails and `u-1` is not enrolled
- **AND** the secret provisioned in session A is not confirmed

#### Scenario: Concurrent completions
- **WHEN** two completions of the same generation run concurrently
- **THEN** exactly one reports success

#### Scenario: Completion before proof
- **WHEN** completion is attempted for a generation whose device is not proven
- **THEN** it fails and the enrolment stays pending

### Requirement: An emailed code proves the mailbox before an enrolment counts, by default
With email confirmation on, which is the default, a proven device SHALL NOT make the enrolment confirmed. Proving the device SHALL generate a 6-digit code from the cryptographically secure random source, keep it on the pending enrolment sealed like the enrolment secret, with an expiry 10 minutes later, and send it to the user's contact address. The emailed-code endpoint SHALL read the code from the `code` form field and SHALL, in order:
1. charge one attempt on the enrolment, as one conditional write that succeeds only while its generation equals the session's, its device is proven, its code has not expired, and fewer than five attempts have been charged;
2. compare the presented code in constant time;
3. complete the enrolment last, as one conditional write.

A refusal SHALL NOT complete the enrolment. Every presented code, well formed or not, SHALL be charged before it is compared, so no more than five codes are ever compared against one emailed code, however many requests arrive at once; the fifth wrong code therefore voids it. If the sender refuses to queue the code, the confirm request SHALL fail, and that proof SHALL NOT be completable. There SHALL be no resend: a lost or expired code is replaced by beginning again. A consumer SHALL be able to turn email confirmation off by an explicit option; the device proof then completes the enrolment at once, on the same generation. The option's documentation SHALL state that without it a password alone binds a second factor, and that after a magic-link login, or a federated one, the emailed code adds no assurance.

#### Scenario: Emailed code completes the enrolment
- **WHEN** a session whose device was proven posts the emailed code to the emailed-code path within 10 minutes
- **THEN** the enrolment is confirmed
- **AND** the session moves to the MFA pending state

#### Scenario: Expired code
- **WHEN** the emailed code is posted 11 minutes after the device was proven
- **THEN** it is refused and the enrolment stays pending

#### Scenario: Fifth wrong code
- **WHEN** five wrong emailed codes are posted, followed by the correct one
- **THEN** the correct one is refused and the enrolment stays pending

#### Scenario: No other way round the emailed code
- **WHEN** a device was proven with email confirmation on, and the enrolment is then completed without the code, or confirmed through the single-call confirm with a valid authenticator code, whether the code is still outstanding, has expired, or has run out of attempts
- **THEN** both are refused and the enrolment stays pending

#### Scenario: Concurrent guesses are bounded
- **WHEN** twenty wrong emailed codes for the same enrolment are posted at the same moment, followed by the correct one
- **THEN** no more than five of them are compared against the code
- **AND** the correct one is refused and the enrolment stays pending

#### Scenario: Code from another session
- **WHEN** a session whose recorded generation is not the enrolment's current generation posts the current emailed code
- **THEN** it is refused and the enrolment is not completed

#### Scenario: Sender refuses to queue
- **WHEN** the sender's queue is full when the device is proven
- **THEN** the confirm request fails
- **AND** no later emailed-code request can complete that proof

#### Scenario: Consumer turns email confirmation off
- **WHEN** email confirmation is turned off and the session posts a valid device code
- **THEN** the enrolment is confirmed and the session moves to the MFA pending state

### Requirement: Binding an authenticator notifies the user, by default
With notification on, which is the default, the library SHALL send the user a plain-text message when an enrolment becomes confirmed through the path, naming the method and the time. The message SHALL contain no code, secret or provisioning URI. The contact address SHALL come from a contact resolver, by default the username, replaceable by the consumer. Delivery SHALL be non-blocking: a sender that delivers synchronously SHALL be refused at construction unless the consumer explicitly accepts synchronous delivery. A notification the sender refuses to queue SHALL be logged, and SHALL NOT undo the confirmation. A missing sender while notification or email confirmation is on SHALL fail construction. A consumer SHALL be able to turn notification off by an explicit option whose documentation states what it gives up.

#### Scenario: Notification on binding
- **WHEN** an enrolment for `u-1`, whose username is `ana@example.com`, becomes confirmed through the path
- **THEN** a message is queued to `ana@example.com` naming the TOTP method and the time
- **AND** it contains neither a code, the secret nor the provisioning URI

#### Scenario: Consumer contact resolver
- **WHEN** the consumer configures a contact resolver returning `ana.work@example.com` for `u-1`
- **THEN** both the emailed code and the notification go to `ana.work@example.com`

#### Scenario: Synchronous sender
- **WHEN** the path is enabled with a synchronous sender and synchronous delivery is not accepted
- **THEN** construction fails with a configuration error

#### Scenario: Consumer turns notification off
- **WHEN** notification is turned off and an enrolment becomes confirmed
- **THEN** no notification is queued

### Requirement: Enrolment begins and failed confirmations are limited per user
The path SHALL limit, per user reference:
- begin calls, recording every call, by default 5 per hour;
- failed device and emailed-code confirmations, by default 5 per 15 minutes.

A user at a limit SHALL be refused with a throttled error without the request being evaluated. The two limiters SHALL be separate from the verification throttle, and each SHALL be replaceable by an option. A limiter that cannot decide SHALL cause the request to be refused. A nil limiter SHALL fail construction. Recording SHALL NOT be abandoned because the caller went away. Documentation SHALL state that the begin limiter counts every call, and that a password holder can exhaust a user's begin budget for an hour.

#### Scenario: Begin limit
- **WHEN** `u-1` begins five times within an hour and then begins again
- **THEN** the sixth begin is refused with the throttled error and nothing is generated

#### Scenario: Confirmation guessing
- **WHEN** five wrong device codes are posted for `u-1` within 15 minutes and then a valid one is posted
- **THEN** the valid one is refused with the throttled error

#### Scenario: Verification unaffected
- **WHEN** `u-1`'s enrolment confirmations are throttled and `u-2`, already enrolled, verifies a valid code
- **THEN** `u-2`'s verification succeeds

#### Scenario: A client that hangs up is still charged
- **WHEN** a wrong device code is posted and the request's context is already cancelled
- **THEN** the failure is still recorded against that user

#### Scenario: Consumer limiter
- **WHEN** the begin limit is configured with a consumer's shared limiter
- **THEN** every begin check and record goes to that limiter, keyed by user reference

#### Scenario: Limiter outage
- **WHEN** the confirmation limiter returns an error for `u-1`
- **THEN** the confirmation is refused

### Requirement: An enrolment-only session lives at most the enrolment lifetime
A session entering the enrolment-pending state SHALL end no later than the enrolment lifetime after it entered, by default 15 minutes, as the `sessions` capability defines. The lifetime SHALL be replaceable by an option. Construction SHALL fail with a configuration error when it is zero or less, or longer than the session manager's absolute timeout.

#### Scenario: Default lifetime
- **WHEN** a session enters the enrolment-pending state at 09:00 with default options and is loaded at 09:16
- **THEN** the expired error is returned

#### Scenario: Consumer lifetime
- **WHEN** the enrolment lifetime is configured as 30 minutes and a session enters the state at 09:00
- **THEN** it still loads at 09:20

#### Scenario: Lifetime longer than the absolute timeout
- **WHEN** the enrolment lifetime is configured longer than the session manager's absolute timeout
- **THEN** construction fails with a configuration error

### Requirement: The path can be closed at a set time
A consumer SHALL be able to set an instant after which the path is closed. After it, the MFA requirement policy SHALL deny a required user with no usable enrolment with the enrolment-required reason, as when the path is off. By default the path SHALL stay open while it is enabled.

#### Scenario: Before the deadline
- **WHEN** the path is closed at 2027-01-01 and an unenrolled required user logs in by password on 2026-12-31
- **THEN** the login is refused with an enrolment challenge

#### Scenario: After the deadline
- **WHEN** the same user logs in by password on 2027-01-02
- **THEN** the login is refused with the enrolment-required reason and no session is established

### Requirement: An operator reset removes the enrolment, ends sessions and notifies
The library SHALL offer an operation that resets a user's enrolment. It SHALL remove the user's enrolment first, then delete every session of the user, then notify the user. Every dependency SHALL be checked before anything is written. Any failure after the removal (deleting sessions, loading the user, resolving the address, sending) SHALL be returned after the removal, never swallowed. The user's MFA requirement SHALL be unchanged. A consumer SHALL be able to turn off session deletion and notification, each by an explicit option. A missing sender while notification is on SHALL be a configuration error, returned before the enrolment is removed. By default the notification SHALL name the time of the reset and carry no code, secret or identifier; a consumer SHALL be able to replace its subject and body by an option, while the library still sets the recipient. The operation SHALL NOT be exposed over HTTP by the library.

#### Scenario: Reset
- **WHEN** `u-1`, who holds two sessions and a confirmed enrolment, is reset
- **THEN** `u-1` is not enrolled, neither session handle loads, and a notification is queued
- **AND** `u-1` is still required to use MFA

#### Scenario: Session store failure
- **WHEN** deleting `u-1`'s sessions fails during a reset
- **THEN** the reset returns that error
- **AND** the enrolment is already removed

#### Scenario: Consumer message
- **WHEN** a reset is run with a consumer's message builder
- **THEN** the notification carries the consumer's subject and body, addressed to the user's contact address

#### Scenario: Missing sender
- **WHEN** a reset is run with notification on and no sender
- **THEN** it fails with a configuration error
- **AND** the enrolment is still in place

#### Scenario: Consumer keeps sessions
- **WHEN** a reset is run with session deletion turned off
- **THEN** the enrolment is removed and `u-1`'s sessions still load
