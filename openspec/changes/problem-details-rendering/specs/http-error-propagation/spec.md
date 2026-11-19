# Spec Delta

## ADDED Requirements

### Requirement: A status lookup tells a recognised error from an unknown one
The library SHALL provide a public lookup that returns the status the public mapping gives an error, together with whether the library recognises it. It recognises a refusal the table names, a challenge, and a dependency failure the library reported, whatever status that is. An error it does not recognise SHALL be reported as unrecognised with status 500. For every error, the lookup's status SHALL equal the public mapping's.

#### Scenario: Recognised refusal
- **WHEN** the error wraps the access-denied refusal
- **THEN** the lookup reports 403 and recognised

#### Scenario: Recognised dependency failure
- **WHEN** the error is the automation-challenge verifier's unavailable error wrapping a connection error
- **THEN** the lookup reports 500 and recognised

#### Scenario: Dependency failure reported with fixed text
- **WHEN** a login's session creation fails and the chain returns the store's failure under fixed library text
- **THEN** the lookup reports the status the public mapping gives it, and recognised

#### Scenario: Unknown error
- **WHEN** the error is a consumer handler's own error that wraps nothing the library defines
- **THEN** the lookup reports 500 and unrecognised

#### Scenario: Agreement with the mapping
- **WHEN** every refusal of the status table, every challenge kind and an unknown error are each looked up
- **THEN** each status equals the public mapping's status for the same error

### Requirement: A refusal that carries a credential is never cacheable
Whenever the chain refuses with a challenge error that carries an access token, it SHALL set `Cache-Control: no-store` on the response before the refusal propagates, replacing any `Cache-Control` value already set, so that no renderer sends the credential in a cacheable response. A challenge error that carries no token SHALL leave `Cache-Control` as it was.

#### Scenario: Upstream middleware set a cacheable policy
- **WHEN** a consumer middleware sets `Cache-Control: public, max-age=300` before the chain, and a password login is challenged for a second factor over a bearer-token chain
- **THEN** the response the error handler receives carries `Cache-Control: no-store` only

#### Scenario: Challenge without a token
- **WHEN** a consumer middleware sets `Cache-Control: public, max-age=300` before the chain, and a refusal carries a challenge error with no token
- **THEN** the response keeps `Cache-Control: public, max-age=300`

### Requirement: Classifying an error never hangs, crashes or panics
The status lookup and the problem-details mapper SHALL classify an error with one walk, in `errors.Is` order. The walk SHALL skip a nil-pointer link without calling its methods, stop after 1,000 visited links counting repeats, and recover a panic from a link's `Unwrap`, `Is` or `As` method. A walk that stops for its budget or a panic SHALL give status 500, unrecognised.

#### Scenario: Cyclic chain
- **WHEN** an error's chain contains itself, through `Unwrap() error` or through `Unwrap() []error`
- **THEN** the lookup returns 500 and unrecognised, without hanging or overflowing the stack, and one error record with reason `budget` is logged

#### Scenario: Fan-out chain
- **WHEN** an error is 25 levels of an error joined with itself, with no cycle
- **THEN** the lookup returns 500 and unrecognised promptly, and one error record with reason `budget` is logged

#### Scenario: A link's method panics
- **WHEN** a link in the chain has an `Is` or `As` method that panics
- **THEN** the lookup returns 500 and unrecognised, the panic does not escape, and one error record with reason `panic` is logged

#### Scenario: Typed nil ahead of a refusal
- **WHEN** a nil `*password.RejectedError` is joined ahead of the access-denied refusal
- **THEN** the lookup returns 403 and recognised, without panicking

#### Scenario: Challenge offered through an As method behind a typed nil
- **WHEN** a nil `*ChallengeError` is joined ahead of an error whose own `As` method presents a challenge
- **THEN** the lookup returns that challenge's status

### Requirement: An aborted classification is logged
When classifying an error stops for its budget or for a panic, the library SHALL log one error record for that error. The record SHALL carry the reason (`budget` or `panic`) and SHALL NOT carry the error's text. It SHALL go to the chain's logger where the caller holds one, and otherwise to the process default logger.

#### Scenario: One record per aborted error
- **WHEN** a cyclic error is classified once
- **THEN** exactly one error record with reason `budget` is logged, and it does not contain the error's text

#### Scenario: Consumer chooses the logger
- **WHEN** a chain configured with the consumer's own logger classifies a cyclic error during its error dispatch
- **THEN** the error record is written to the consumer's logger, not to the process default

## MODIFIED Requirements

### Requirement: Refusals propagate as errors, unrendered
Interceptors and guards SHALL report every refusal by returning an error. The library SHALL NOT write a response body for a refusal. The error reaching the consumer's error handling SHALL be the refusal error itself, or an error wrapping it, so the consumer can identify the refusal by error identity or type. The core module SHALL NOT include a problem-details or other body renderer. The one renderer the library offers SHALL be the opt-in integration module the problem-details-rendering capability defines, which the core does not depend on. The one exception SHALL be the OpenID Provider's protocol endpoints: authorization, resume, token, revocation, introspection, UserInfo, end-session and its confirmation. They SHALL answer protocol errors in the form their standards fix, as the `oidc-provider-*` capabilities state. They SHALL report through the chain's error handling only the failures the protocol does not let them answer themselves: an invalid client or redirect URI at the authorization endpoint, a refused `id_token_hint` at the end-session endpoint, and dependency failures.

#### Scenario: Consumer identifies the refusal
- **WHEN** a request is refused because the account is locked
- **THEN** the error reaching the consumer's error handler is identifiable as the account-locked refusal

#### Scenario: No body from the library
- **WHEN** any refusal occurs and the consumer's error handler writes nothing
- **THEN** no bytes written by the library appear in the response body

#### Scenario: Provider token endpoint error
- **WHEN** a token request presents an expired authorization code and no error handler is configured
- **THEN** the response is 400 with the JSON body `{"error":"invalid_grant"}` and `Cache-Control: no-store`

#### Scenario: Unredirectable authorization error
- **WHEN** an authorization request names an unregistered redirect URI and the consumer's error handler renders a page
- **THEN** the consumer's error handler receives the refusal, and the library writes no body of its own

#### Scenario: The core renders nothing with prblm absent
- **WHEN** a consumer's module requires only the core and a request is refused with no error handler configured
- **THEN** the response has an empty body, and `github.com/kartaladev/prblm` is not in the consumer's module graph

### Requirement: Refusal errors are a stable public contract
The library SHALL expose distinguishable public refusal errors for at least these cases:
- authentication required;
- malformed login;
- request too large;
- an unknown MFA method named in a second-factor path;
- an MFA method the session's user may not use;
- a request to the MFA method-listing endpoint from a session that owes no MFA challenge;
- a refused account recovery, whatever the cause: an unknown user, a disabled user, a wrong or spent proof, or an unknown, spent or cancelled completion token;
- a malformed recovery: the wrong number or kinds of proofs, a proof kind that is not enabled, or a reported loss the user does not hold;
- a held recovery presented for completion before its hold ends;
- a request refused during a recovery cool-down;
- a saved-code regeneration from a session whose latest authentication is outside the freshness window;
- a passkey assertion refused as a suspected clone;
- a passkey assertion from a suspended credential;
- a passkey assertion from a credential that is still pending;
- a passkey registration refused by the attestation policy;
- a passkey registration beyond the user's passkey limit;
- a passkey registration or removal from a session below the account's assurance or outside the freshness window;
- a passkey identifier that names no passkey of the session's user;
- a session renewal that lost a concurrent renewal of the same session;
- a session renewal refused because its family has renewed too often;
- a session identifier presented after its supersession window, which SHALL also be identifiable as the session-expired refusal of the session capability;
- a cross-site request refused by CSRF protection, whatever layer refused it: Fetch Metadata, Origin or token;
- a request whose resolved host is not an allowed host;
- a missing or invalid DPoP proof, a bound token presented without a proof from its key, or a proof without a required server nonce, the last also identifiable as its own nonce-required refusal;
- a certificate-bound token presented without its certificate;
- a request refused by the automation-challenge verifier;
- a new password refused by the password policy, which SHALL name the rule that refused it;
- a session handle that names no live sign-in of the requesting user.

The password-reused refusal of the password-policy capability SHALL be identifiable both as itself and as the password-policy refusal.

A refused recovery SHALL be identifiable as the authentication-failed refusal, so it reads to the client like a failed login. A refused passkey ceremony (an invalid, spent or mismatched challenge, a missing ceremony cookie, an unknown credential, a user-handle mismatch or a signature that does not verify) SHALL be identifiable as the authentication-failed refusal without a sentinel of its own. As a second factor it SHALL be the invalid second-factor code refusal.

A refusal a core already names SHALL be reported as that core's own error rather than restated under a second name. In particular, a policy that denies without giving a reason SHALL be reported as the security-policy capability's reasonless-deny error, because the policy engine already substitutes it: a second sentinel for the same condition would be unreachable, and a consumer matching one identity would miss the other. Where this capability's own refusal and a core's name the same condition, the chain SHALL wrap the core's with its own so that either identity matches.

It SHALL also expose one challenge error type, whose kinds include account recovery, and SHALL map the refusal errors that the authentication, authorization, session, security-policy, second-factor and passkey cores define. A challenge error SHALL carry its challenge kind, the pending session when one exists, and the access token issued with it when one was issued, together with that token's type (`Bearer`, or `DPoP` for a session bound to a proof key). It SHALL carry no token type when it carries no token. A challenge error of the second-factor kind SHALL also carry the session user's usable MFA methods, each with its name, its channel and whether it has a begin step, computed by the one function the security policies use to decide usability; when that computation fails, the request SHALL be refused with the failure instead of the challenge, and SHALL NEVER carry an empty or partial list. No refusal error's text SHALL contain an access token, a session handle, a submitted credential, a method name, a challenge, a credential ID, a user handle, a DPoP proof, a certificate, a CSRF token, a candidate password or a forwarded host. A refusal caused by a consumer-supplied dependency SHALL carry fixed library text, with the dependency's error reachable by identity and type, as the diagnostic-redaction capability requires; this SHALL NOT change the status it maps to.

#### Scenario: Challenge error contents
- **WHEN** form login is challenged for a second factor
- **THEN** the challenge error carries the second-factor kind, the pending session, the token and the token type `Bearer`

#### Scenario: Challenge carries the usable methods
- **WHEN** TOTP and a challenge method named `passkey` are configured, `u-1` is enrolled on both, and `u-1`'s password login is challenged for a second factor
- **THEN** the challenge error lists `totp` on the authenticator-app channel without a begin step, then `passkey` with a begin step

#### Scenario: Challenge omits methods the user cannot use
- **WHEN** `u-1` is enrolled on TOTP only and a session of `u-1` with the challenge pending requests `/invoices`
- **THEN** the challenge error lists `totp` only

#### Scenario: A failed lookup never yields an empty list
- **WHEN** a session with the challenge pending requests `/invoices` and a method's enrolment lookup fails
- **THEN** the request is refused with that failure and no challenge error is returned

#### Scenario: Challenge text carries no secret
- **WHEN** a challenge error carrying a token is converted to text
- **THEN** the text names the challenge kind and contains neither the token, the session handle nor any method name

#### Scenario: Challenge raised on a later request
- **WHEN** the password-change gate refuses a session
- **THEN** the challenge error carries the session and no token

#### Scenario: Dependency text stays out of the refusal
- **WHEN** a login is refused because the attempt store failed with an error quoting `alice@example.com`
- **THEN** the refusal's text does not contain `alice@example.com`, and it still maps to the status it mapped to before

#### Scenario: Recovery refusal reveals no cause
- **WHEN** one recovery is refused for an unknown username and another for a wrong saved code
- **THEN** both errors are the same recovery-refused refusal, and neither's text contains a username or a code

#### Scenario: Reuse refusal is distinguishable
- **WHEN** a request presenting a superseded session identifier after its window is refused
- **THEN** the refusal is identifiable as the reused-session refusal, and also as the authentication-required and session-expired refusals
- **AND** its text contains no session identifier

#### Scenario: Recency refusal carries its window
- **WHEN** a recency guard with a 5-minute window refuses a stale session
- **THEN** the refusal is identifiable as the reauthentication-required refusal, reports the 5-minute window, and its text contains no session handle

#### Scenario: Passkey refusal reveals no credential
- **WHEN** one passwordless finish is refused for an unknown credential and another for a bad signature
- **THEN** both errors are the authentication-failed refusal, and neither's text contains a credential ID or a challenge

#### Scenario: Password-policy refusal names its rule
- **WHEN** a password change is refused by the policy because the candidate is breached
- **THEN** the refusal is identifiable as the password-policy refusal, names the breached rule, and its text contains neither the candidate nor the user reference

#### Scenario: Reused password is both refusals
- **WHEN** a password change is refused by the policy's reuse rule
- **THEN** the refusal is identifiable both as the password-reused refusal and as the password-policy refusal

#### Scenario: Host refusal does not echo the host
- **WHEN** a request is refused because a trusted proxy forwarded the host `evil.example`
- **THEN** the refusal's text does not contain `evil.example`

#### Scenario: Challenge on a DPoP-bound login
- **WHEN** a login with a DPoP proof is challenged for a second factor
- **THEN** the challenge error carries the token and the token type `DPoP`
