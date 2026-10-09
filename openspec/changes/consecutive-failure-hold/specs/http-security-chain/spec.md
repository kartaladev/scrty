## ADDED Requirements

### Requirement: A capped lockout policy requires its own view at the password logins
When the chain's policies include a lockout policy with a cap, construction SHALL fail with a configuration error when form login or Basic authentication is given any attempt store other than that policy's view, because only the view advances the consecutive count. The error SHALL name the endpoint's attempt-store setting. A lockout policy without a cap SHALL leave any attempt store valid, as before.

#### Scenario: Raw store with a cap
- **WHEN** the chain's lockout policy has a cap, and form login is given the policy's underlying attempt store instead of the policy's view
- **THEN** construction fails with a configuration error naming form login's attempt store

#### Scenario: View with a cap
- **WHEN** the chain's lockout policy has a cap, and form login and Basic authentication are both given the policy's view
- **THEN** construction succeeds

#### Scenario: Raw store without a cap
- **WHEN** the chain's lockout policy has no cap, and Basic authentication is given the underlying attempt store
- **THEN** construction succeeds

### Requirement: A held account is refused like any locked account
Form login and Basic authentication SHALL refuse a held identifier exactly as they refuse any locked one: by default as an authentication failure, with the decoy verification spent and, for Basic, the challenge header; and, when the consumer has chosen to disclose locks, as the account-locked refusal answered 429. In both cases the consumer's error handling SHALL be able to identify the refusal as a hold.

#### Scenario: Held by default
- **WHEN** `ada` is held and a form login for `ada` arrives with the correct password
- **THEN** it is refused with the authentication failure error, answered 401, one decoy verification is spent, and the account's password is not checked
- **AND** the error is identifiable as a hold by the consumer's error handling

#### Scenario: Held, disclosure chosen
- **WHEN** the chain is configured to disclose locks, and a Basic request for a held `ada` arrives
- **THEN** it is answered 429 with the account-locked refusal, identifiable as a hold, and carries no `WWW-Authenticate` header

#### Scenario: Unknown username held alike
- **WHEN** `ada`, which has an account, and `nobody`, which does not, are both held, and a form login arrives for each
- **THEN** both are refused with the same error and status, and each spends one decoy verification

### Requirement: A held account is released by recovery and a password change
A user whose account is held SHALL be able to complete a recovery whose proofs do not include the password, and the password change that completes it at the resolve endpoint SHALL lift the hold, so the user can sign in with the new password.

#### Scenario: Recover, change, sign in
- **WHEN** `ada` is held, completes a recovery with a saved code and an issued code, and resolves a password change on the recovery session
- **THEN** a form login by `ada` with the new password succeeds

#### Scenario: Password proof refused while held
- **WHEN** `ada` is held, and posts a recovery with a saved code and the correct password
- **THEN** the recovery is refused as locked, and the password is not checked

## MODIFIED Requirements

### Requirement: HTTP Basic authentication is stateless
When enabled, Basic authentication SHALL handle requests whose `Authorization` header starts with `Basic `, and SHALL pass other requests through unchanged. It SHALL:
1. refuse a header whose value is not valid base64 or has no `:` separator with the authentication failure error;
2. check the request's source against the password-login guard, and refuse a throttled or unattributable source;
3. evaluate the pre-authentication phase before checking credentials;
4. on a failed authentication, record a failed attempt, set a `WWW-Authenticate` Basic challenge header naming the realm (default `Restricted`), and refuse with the authentication failure error;
5. on success, clear the username's failures through its attempt store, as form login does, logging a failure to clear without changing the outcome; then evaluate the stateless-authentication policy phase, and continue with the principal in the context.

Every refusal answered 401 SHALL carry the `WWW-Authenticate` challenge header. It SHALL NOT create a session or issue a token. A challenge from the stateless-authentication phase SHALL refuse with a challenge error carrying no session and no token. The consumer SHALL be able to set the realm.

#### Scenario: Valid credentials
- **WHEN** a request carries correct Basic credentials
- **THEN** the handler runs with the principal in the context and no session is created

#### Scenario: Invalid credentials
- **WHEN** a request carries an incorrect Basic password
- **THEN** it is refused with the authentication failure error and the response carries a `WWW-Authenticate` header for the realm

#### Scenario: Consumer realm
- **WHEN** the consumer sets the realm to `internal-api` and credentials are refused
- **THEN** the `WWW-Authenticate` header names `internal-api`

#### Scenario: Stateless request needing a second factor
- **WHEN** the stateless-authentication phase requires a second factor for the user
- **THEN** the request is refused with that phase's reason, or with a challenge error carrying no session and no token

#### Scenario: Throttled source still challenged
- **WHEN** a Basic request arrives from a source the password-login guard throttles
- **THEN** it is refused with the throttled error and the response carries a `WWW-Authenticate` header for the realm

#### Scenario: Success clears failures
- **WHEN** `ada` has four failures in the window, and a Basic request with `ada`'s correct password succeeds
- **THEN** `ada` has no failures in the window

#### Scenario: Failure to clear does not refuse
- **WHEN** a Basic request with correct credentials succeeds, and the attempt store fails to clear the username's failures
- **THEN** the handler runs with the principal in the context, and one error record names the failed clearing
