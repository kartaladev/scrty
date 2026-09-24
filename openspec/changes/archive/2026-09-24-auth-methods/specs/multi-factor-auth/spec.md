## Purpose

Lets a user prove a second factor after the first, with methods that declare the channel their codes travel over. TOTP is built in. Codes cannot be replayed or guessed without limit, and a lost or unreadable enrolment never lets a user who is required to use MFA through.

## ADDED Requirements

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
Removing, losing or failing to read a user's enrolment SHALL NOT change whether that user is required to use MFA. The requirement is read from the user, never from the enrolment. After a required user's enrolment is removed, their next login SHALL be refused as requiring enrolment rather than completed on the first factor. A failed or unreadable enrolment lookup for a required user SHALL refuse the login.

#### Scenario: Enrolment deleted
- **WHEN** `u-1` is required to use MFA, their enrolment is removed, and they log in by password
- **THEN** the login is refused with the enrolment-required reason
- **AND** no session is established without a second factor

#### Scenario: Enrolment store outage
- **WHEN** `u-1` is required to use MFA and the enrolment lookup fails during their password login
- **THEN** the login is refused

### Requirement: Requiring MFA for all locks out unenrolled users
When MFA is required for all users, a user with no usable enrolment SHALL be refused at every non-exempt login, and this capability SHALL offer them no way to enrol through that login. This SHALL be documented as a limit until an enrolment path exists for required users.

#### Scenario: Unenrolled user under require-for-all
- **WHEN** MFA is required for all users and a user who has never enrolled logs in by password with a correct password
- **THEN** the login is refused with the enrolment-required reason
- **AND** no session is established

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
The verify endpoint SHALL match only POST requests to its path, and SHALL read the code from the `code` form field. The default path SHALL be `/mfa/totp`, replaceable by an option. A request with no session SHALL be refused as authentication required, and so SHALL a request whose session carries no resolved caller — the credential the endpoint issues names a principal, so a session without one cannot be answered. Both refusals SHALL happen before the code is read.

The endpoint SHALL be given a token generator at construction, and a chain that enables it without one SHALL fail to assemble: the endpoint's whole purpose on success is to hand back a credential for the rotated session, and it has none to issue without a generator.

On a valid code the endpoint SHALL:
- resolve the session's MFA challenge, which records the second-factor-satisfied time;
- rotate the session handle;
- write the response itself, through a replaceable responder that receives the rotated session;
- answer with a success status without passing the request to later handlers.

Because the endpoint answers the request itself, no later handler runs, so the rotated handle SHALL
reach the caller through that responder or not at all. With no responder supplied the library SHALL
write a credential the caller can use for its next request; a consumer SHALL be able to replace that
whole response, for example to set a cookie instead.

Rotation SHALL NOT strand the caller: a caller that completes its second factor SHALL be able to
make an authenticated request afterwards without signing in again.

On any failure the challenge SHALL stay pending, the handle SHALL be unchanged, and the error SHALL propagate to the consumer's error handling unchanged.

#### Scenario: Successful verification
- **WHEN** a session with the MFA challenge pending posts a valid code
- **THEN** the session reports no pending challenge and a second-factor-satisfied time
- **AND** the previous session handle no longer loads
- **AND** the response carries a credential naming the rotated session, so the next request authenticates

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
Records written for MFA verification and enrolment SHALL contain neither a presented code, an enrolment secret nor a provisioning URI. Throttle refusals SHALL be written through a log sampler with a reporter, keyed by refusal reason. The window SHALL default to one minute and be configurable by an option that governs only MFA verification logs.

#### Scenario: No codes in logs
- **WHEN** a wrong code `123456` is refused
- **THEN** no written log record contains `123456`

#### Scenario: Throttled guessing
- **WHEN** 200 verifications for one throttled user are refused within one minute
- **THEN** one throttle record is written for that minute
