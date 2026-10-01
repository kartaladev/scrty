# Spec Delta

## ADDED Requirements

### Requirement: Each provider has an assurance configuration with a safe default
Each registered provider SHALL have an assurance configuration made of a set of accepted authentication method references (`amr`), a set of accepted authentication context class references (`acr`), a set of `acr` values to request, and a match mode. A provider with no configuration SHALL accept the `amr` value `mfa` only, accept no `acr`, request none, and match any. A consumer SHALL be able to replace a provider's whole configuration.

#### Scenario: Default accepts only mfa
- **WHEN** provider `corp` has no assurance configuration and a verified ID token asserts `amr` `["pwd","otp"]`
- **THEN** assurance for that login is not met

#### Scenario: Default with mfa asserted
- **WHEN** provider `corp` has no assurance configuration and a verified ID token asserts `amr` `["pwd","mfa"]`
- **THEN** assurance for that login is met

#### Scenario: Consumer accepts an acr
- **WHEN** provider `corp` is configured to accept the `acr` value `urn:corp:loa:2` and no `amr`, and a verified ID token asserts that `acr` and no `amr`
- **THEN** assurance for that login is met

#### Scenario: Values match exactly
- **WHEN** provider `corp` accepts the `amr` value `mfa` and a verified ID token asserts `amr` `["MFA"]`
- **THEN** assurance for that login is not met

#### Scenario: Match all
- **WHEN** provider `corp` accepts the `amr` value `mfa` and the `acr` value `gold` with the match-all mode, and a verified ID token asserts `amr` `["mfa"]` and `acr` `silver`
- **THEN** assurance for that login is not met

#### Scenario: Configured with nothing accepted
- **WHEN** provider `corp` is configured with empty accepted sets and a verified ID token asserts `amr` `["mfa"]`
- **THEN** assurance for that login is not met

### Requirement: Assurance is read only from the verified ID token
Assurance SHALL be decided only from the `amr` and `acr` claims of an ID token that passed every verification check. No value from a UserInfo response, an access token, a request parameter, a consumer broker, or a redemption request SHALL be considered. An absent `amr`, an empty `amr`, an `amr` that is not an array of strings, and an `acr` that is not a non-empty string SHALL each mean nothing was asserted. A malformed claim SHALL NOT make the token invalid; it SHALL write a sampled warning naming the provider and the claim name, never its value.

#### Scenario: No amr claim
- **WHEN** a verified ID token from provider `corp` carries no `amr` claim
- **THEN** the login proceeds with assurance not asserted

#### Scenario: Malformed amr
- **WHEN** a verified ID token from provider `corp` carries `amr` as the string `"mfa"` rather than an array
- **THEN** the login proceeds with assurance not asserted
- **AND** a warning naming `corp` and `amr`, and not containing `mfa`, is written through the sampler

#### Scenario: Value presented at redemption is ignored
- **WHEN** a handoff code issued for a login whose ID token asserted no `amr` is redeemed with a request body that also carries `"amr": ["mfa"]`
- **THEN** the redemption is evaluated with assurance not asserted

### Requirement: Requested acr values are sent but never trusted
When a provider's configuration lists `acr` values to request, the authorization redirect SHALL carry them as the space-separated `acr_values` parameter, in the configured order. With none configured, the redirect SHALL carry no `acr_values` parameter. Requesting an `acr` SHALL NOT itself count as evidence: only the returned ID token's `acr` SHALL be matched.

#### Scenario: Requested values on the redirect
- **WHEN** provider `corp` is configured to request `urn:corp:loa:2` and `urn:corp:loa:3` and a browser starts a login
- **THEN** the authorization redirect carries `acr_values=urn:corp:loa:2 urn:corp:loa:3`

#### Scenario: Provider ignores the request
- **WHEN** provider `corp` requests and accepts `urn:corp:loa:2`, and the returned ID token asserts `acr` `urn:corp:loa:1`
- **THEN** assurance for that login is not met

#### Scenario: Nothing requested by default
- **WHEN** provider `corp` has no assurance configuration and a browser starts a login
- **THEN** the authorization redirect carries no `acr_values` parameter

### Requirement: A consumer can replace the assurance decision
A consumer SHALL be able to supply an assurance evaluator that replaces the matching of asserted values against the provider's configuration. It SHALL receive the user reference, the provider name, the verified issuer and the asserted `amr` and `acr`, never the raw token, and SHALL answer met, not met, or an error. An error SHALL fail closed: the MFA policies SHALL deny with it as the reason. The library SHALL still own claim extraction, so the evaluator SHALL NOT widen the source of assurance.

#### Scenario: Per-user rule
- **WHEN** a consumer evaluator answers not met for administrator `u-1` unless `amr` contains `hwk`, and `u-1` logs in through `corp` with `amr` `["mfa","otp"]`
- **THEN** assurance for that login is not met

#### Scenario: Evaluator failure denies
- **WHEN** the consumer evaluator returns an error during the redemption of a required user's valid code
- **THEN** redemption is refused with that error as the reason
- **AND** the code is not consumed

## MODIFIED Requirements

### Requirement: The callback conveys the login by a short-lived single-use code
After the ID token is verified and the external identity resolves to an internal user, the callback SHALL NOT create a session. It SHALL issue a handoff code and redirect the browser to the post-login destination, with the code as a query parameter. The code SHALL:
- be drawn from a cryptographically secure source with at least 256 bits of secret entropy;
- be stored only as a digest of its secret;
- carry the user reference of the resolved user, the provider name, the verified issuer, the provider session id (which may be empty), the raw ID token, and the `amr` values (in order, without duplicates) and `acr` the verified ID token asserted, each of which may be empty;
- expire 60 seconds after issue.

The handoff store SHALL refuse to delete expired codes with a zero cutoff time. The expiry SHALL NOT be configurable: the code travels in a URL and a refused code stays live until it expires, so widening the window is a security decision, and the documentation SHALL say so. The redirect SHALL carry `Referrer-Policy: no-referrer` and `Cache-Control: no-store`, and SHALL clear the flow cookie. The code, the ID token and the claims SHALL never be written to a log by the library. The documentation SHALL state that a code travels in a URL and can be recorded by browser history and intermediaries until it expires or is spent.

#### Scenario: Successful callback
- **WHEN** a callback completes the flow, verifies the ID token and resolves user `u-1`
- **THEN** the browser is redirected to the destination with a `handoff` query parameter
- **AND** the response carries `Referrer-Policy: no-referrer` and `Cache-Control: no-store`
- **AND** no session exists yet for `u-1`

#### Scenario: Asserted assurance travels with the code
- **WHEN** a callback verifies an ID token asserting `amr` `["pwd","mfa","mfa"]` and `acr` `urn:corp:loa:2` and issues a code
- **THEN** the stored record carries `amr` `["pwd","mfa"]` and `acr` `urn:corp:loa:2`

#### Scenario: Digest at rest
- **WHEN** a handoff code is issued and its stored record is read
- **THEN** the record does not contain the code's secret

#### Scenario: Zero purge cutoff for handoff codes
- **WHEN** expired handoff codes are deleted with a zero cutoff time
- **THEN** an error is returned and every unexpired code remains redeemable

#### Scenario: Expired at the deadline
- **WHEN** a code issued at 10:00:00 is redeemed at 10:01:00
- **THEN** redemption is refused with the invalid-handoff outcome

### Requirement: A consumer can replace the callback's conveyance
A consumer SHALL be able to supply a callback success handler. When one is supplied, it SHALL be called after the flow is completed, the ID token is verified and the identity is resolved, with the resolved principal, the provider session details, the asserted `amr` and `acr`, and the validated destination. No handoff code SHALL then be issued. Everything before that point SHALL still be performed by the library. The documentation SHALL state that a handler which creates a session itself must record the asserted values on it, or the session carries no assurance and required users are challenged or refused.

#### Scenario: Consumer conveys the login itself
- **WHEN** a callback success handler is configured and a callback succeeds for user `u-1`
- **THEN** the handler receives the principal for `u-1` and the verified issuer
- **AND** no handoff code is stored

#### Scenario: Handler receives the asserted assurance
- **WHEN** a callback success handler is configured and the verified ID token asserts `amr` `["mfa"]`
- **THEN** the handler receives `amr` `["mfa"]`

### Requirement: Handoff redemption is check-then-consume
The handoff redemption endpoint SHALL accept the code only in the body of a POST request, and SHALL ignore a code in the query string. Redemption SHALL proceed in this order:
1. validate the code: it is well formed, its record exists, its secret matches in constant time, and it has not expired;
2. resolve the account by the recorded user reference through the user loader, and refuse it unless the loaded details carry exactly that reference and the user is enabled;
3. run the refusal checks, including the post-authentication policy evaluation from the `security-policy` capability, with the assurance the record carries;
4. consume the code in one atomic operation, last.

An already-consumed record MAY be rejected before step 2, but that rejection SHALL NOT be what guarantees single use; only the atomic consume SHALL decide. A refusal or failure at step 2 or 3 SHALL leave the code redeemable until it expires. Refusal checks SHALL be documented as required to be side-effect free, because racing redemptions of one code can each run them. The login completion step SHALL reuse the post-authentication decision made at step 3, rather than evaluating the post-authentication policies again after the code is consumed, so a policy lookup failure never spends the code.

#### Scenario: Racing redemptions
- **WHEN** 8 requests redeem the same valid code at the same time
- **THEN** exactly one creates a session
- **AND** the other 7 receive the invalid-handoff outcome

#### Scenario: Code in the query string
- **WHEN** a POST to the redemption endpoint carries the code only in its query string
- **THEN** redemption is refused with the invalid-handoff outcome

#### Scenario: A policy lookup failure does not spend the code
- **WHEN** a required user's code carries no accepted assurance, the MFA requirement policy's enrolment lookup fails while the code is redeemed, and the code is redeemed again after the lookup recovers
- **THEN** the first redemption is refused and creates no session
- **AND** the second redemption completes

### Requirement: Policy decisions at redemption cannot be lost
When the post-authentication policy evaluation denies a redemption, redemption SHALL refuse without consuming the code. It SHALL return the policy's reason, or a policy-denied error when the policy gave no reason. A deny SHALL never result in a session. When the evaluation challenges, the code SHALL be consumed and a session SHALL be created pending that challenge, as the `sessions` and `security-policy` capabilities define. When the redemption operation is replaced by a consumer implementation, the endpoint SHALL refuse with the policy-denied error, and create no session, whenever the implementation reports success but:
- the policy evaluation never ran; or
- the evaluation denied; or
- the implementation returns a user other than the one the evaluation decided on: a different user reference, or a password-change time not equal to the one the evaluation saw.

#### Scenario: Deny with no reason
- **WHEN** a consumer policy denies a redemption without giving a reason
- **THEN** redemption fails with the policy-denied error
- **AND** no session is created
- **AND** the same code redeems successfully once the policy allows, before it expires

#### Scenario: Challenge redeems
- **WHEN** a code whose ID token asserted no `amr` is redeemed for a user who is required to use MFA and enrolled on TOTP
- **THEN** the code is consumed and a session is created pending the MFA challenge
- **AND** the response is the challenge outcome

#### Scenario: Implementation skips the checks
- **WHEN** a consumer redemption implementation returns success without running the refusal checks
- **THEN** the endpoint refuses with the policy-denied error and creates no session

#### Scenario: Implementation discards a deny
- **WHEN** a consumer redemption implementation runs the refusal checks, receives a deny, ignores it and returns success
- **THEN** the endpoint refuses with the policy-denied error and creates no session

#### Scenario: Implementation returns another user
- **WHEN** a consumer redemption implementation runs the refusal checks for user `u-1` and returns success for user `u-2`
- **THEN** the endpoint refuses with the policy-denied error and creates no session

#### Scenario: Implementation returns the same user reloaded
- **WHEN** a consumer redemption implementation runs the refusal checks for `u-1` and returns success for `u-1` reloaded, with the same password-change instant in another time zone
- **THEN** the redemption completes as the evaluation decided

### Requirement: A successful redemption establishes a federated session
A redemption that consumes the code SHALL complete the login through the login completion step of the `http-security-chain` capability, as every other first factor does. The session SHALL record the OIDC first-factor kind, together with the provider name, verified issuer, provider session id, ID token, and asserted `amr` and `acr` carried by the code, all in the write that creates the session. The session SHALL be created for the principal built from the resolved account's stored details, so that it holds only the user's stored roles. An access token SHALL then be issued through the `token-issuance` capability. The response SHALL be the JSON body form login answers with, plus the destination re-validated against the redirect allowlist as `next`, with `Cache-Control: no-store` and `Referrer-Policy: no-referrer`. A consumer who needs a different response replaces the conveyance with a callback success handler.

#### Scenario: Session carries the federation fields
- **WHEN** a code issued for user `u-1`, issuer `https://idp.example` and provider session `sid-9` is redeemed
- **THEN** the created session records the OIDC first factor, issuer `https://idp.example` and provider session `sid-9`

#### Scenario: Session carries the asserted assurance
- **WHEN** a code carrying `amr` `["mfa"]` and `acr` `urn:corp:loa:2` is redeemed
- **THEN** the created session records `amr` `["mfa"]` and `acr` `urn:corp:loa:2`
- **AND** its second-factor state is not satisfied

#### Scenario: Response body
- **WHEN** a code is redeemed with destination `/welcome`, which is allowlisted
- **THEN** the response body carries `access_token`, `valid_until` and `next` equal to `/welcome`, in the same form a form login's body carries its token
- **AND** the response carries `Cache-Control: no-store`

### Requirement: OIDC wiring mistakes fail at construction
Constructing OIDC login SHALL fail with a configuration error when:
- no provider is registered;
- two of the authorize, callback, redemption and back-channel logout paths collide;
- any duration option is zero or negative, except the clock-skew leeway, for which zero means no leeway and only a negative value fails;
- just-in-time provisioning or role derivation is configured for a provider name that is not registered;
- an assurance configuration is given for a provider name that is not registered, contains an empty value in any of its sets, or names a match mode the library does not define.

Assembling a chain with OIDC login SHALL fail with a configuration error when an MFA policy that decides federated logins on provider assurance has no source of assurance wired to it.

#### Scenario: Colliding paths
- **WHEN** the redemption path is configured equal to the callback path
- **THEN** construction fails with a configuration error

#### Scenario: Option for an unknown provider
- **WHEN** just-in-time provisioning is enabled for provider `corpp` while only `corp` is registered
- **THEN** construction fails with a configuration error naming `corpp`

#### Scenario: Assurance for an unknown provider
- **WHEN** an assurance configuration is given for provider `corpp` while only `corp` is registered
- **THEN** construction fails with a configuration error naming `corpp`

#### Scenario: Empty accepted value
- **WHEN** provider `corp` is configured to accept the `amr` values `mfa` and the empty string
- **THEN** construction fails with a configuration error

#### Scenario: Requirement policy without an assurance source
- **WHEN** a chain enables OIDC login and registers the MFA requirement policy in the default mode without wiring an assurance source to it
- **THEN** chain assembly fails with a configuration error

## REMOVED Requirements

### Requirement: OIDC logins are exempt from local MFA by default, as a stated limit
**Reason**: The exemption let a user who is required to use MFA obtain a session through a provider that authenticated by password only, so the requirement's guarantee did not hold on that path. OIDC logins are now decided on verified provider assurance, as the `security-policy` capability defines for the `federated` channel.
**Migration**: A consumer who wants the previous behaviour selects the exempt federated-assurance mode on the MFA requirement policy, or marks `oidc` exempt through the exemption rule. Required users of providers that assert no accepted assurance enrol in a local second factor, or the consumer admits OIDC to the enrolment path.
