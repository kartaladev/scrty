## MODIFIED Requirements

### Requirement: Form login authenticates, applies policy and opens a session
When enabled, form login SHALL answer POST requests on its login path, by default `/login`. Every other request SHALL pass through untouched. It SHALL:
1. read the username and password from form fields, `username` and `password` by default, or from a JSON object when the form yields neither and the request declares a JSON content type;
2. check the request's source against the password-login guard, and refuse a throttled or unattributable source;
3. evaluate the pre-authentication policy phase before checking credentials, and refuse on a deny;
4. authenticate, recording a failed attempt on an authentication failure and clearing attempts on success, where a failure of that bookkeeping is logged and does not change the outcome;
5. evaluate the post-authentication policy phase, and refuse on a deny;
6. create a session recording the password first factor;
7. when the post-authentication phase challenged, mark the challenge pending and save the session before issuing a token;
8. issue an access token.

A challenge SHALL refuse with a challenge error carrying the kind, the pending session and the token. A success SHALL write the success response and SHALL NOT call the handler. By default the success response is a JSON document carrying the access token, an empty refresh token field and the session's idle expiry. The consumer SHALL be able to replace the success response writer, the login path and the field names.

#### Scenario: Successful login
- **WHEN** a user with no pending challenge posts correct credentials to the login path
- **THEN** a session is created, the response is a JSON document carrying an access token and the session's idle expiry, and the handler is not called

#### Scenario: Wrong password
- **WHEN** a user posts an incorrect password
- **THEN** the request is refused with the authentication failure error and a failed attempt is recorded

#### Scenario: Locked account is not probed
- **WHEN** the pre-authentication phase denies a locked account
- **THEN** the request is refused, its error identifiable as both the authentication failure and the account-locked refusal, and the account's password is never checked

#### Scenario: Login raises a challenge
- **WHEN** the post-authentication phase challenges for a second factor
- **THEN** the session is saved as pending before the token is issued, and the request is refused with a challenge error carrying the second-factor kind, the session and the token

#### Scenario: Consumer success response and field names
- **WHEN** the consumer sets the field names to `email` and `secret` and supplies their own success response writer
- **THEN** a login posting `email` and `secret` succeeds and writes the consumer's response

#### Scenario: Other methods pass through
- **WHEN** a GET request arrives on the login path
- **THEN** form login does not handle it and the request continues

### Requirement: HTTP Basic authentication is stateless
When enabled, Basic authentication SHALL handle requests whose `Authorization` header starts with `Basic `, and SHALL pass other requests through unchanged. It SHALL:
1. refuse a header whose value is not valid base64 or has no `:` separator with the authentication failure error;
2. check the request's source against the password-login guard, and refuse a throttled or unattributable source;
3. evaluate the pre-authentication phase before checking credentials;
4. on a failed authentication, record a failed attempt, set a `WWW-Authenticate` Basic challenge header naming the realm (default `Restricted`), and refuse with the authentication failure error;
5. on success, evaluate the stateless-authentication policy phase, and continue with the principal in the context.

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

## ADDED Requirements

### Requirement: Password login is throttled per source
Form login and Basic authentication SHALL share one source guard for the flow `password-login`, checked before the pre-authentication phase. By default its limiter SHALL come from the chain's limiter factory under namespace `password-login`, with a limit of 50 failures per 15 minutes. Authentication failures and account-locked refusals SHALL count against the source, and successes SHALL NOT. A consumer SHALL be able to give either endpoint its own limiter.

#### Scenario: Spraying one password across accounts
- **WHEN** one source posts a wrong password for 50 different usernames within 15 minutes and then posts for a 51st
- **THEN** the 51st request is refused as throttled, without the pre-authentication phase or the password being evaluated

#### Scenario: Form and Basic share the allowance
- **WHEN** one source fails 30 form logins and then 20 Basic authentications within 15 minutes, and makes one more form login
- **THEN** the form login is refused as throttled

#### Scenario: Successes spend nothing
- **WHEN** one source makes 100 successful form logins and 49 failed ones within 15 minutes, and then makes one more failed login
- **THEN** that request is not throttled

#### Scenario: Locked refusals count
- **WHEN** one source makes 50 form logins for a locked account within 15 minutes and then logs in as another user
- **THEN** that request is refused as throttled

#### Scenario: Consumer limiter
- **WHEN** form login is given its own limiter with a limit of 10
- **THEN** the eleventh failed login from one source within the limiter's window is refused as throttled, and Basic authentication keeps the default limiter

#### Scenario: Factory namespace
- **WHEN** a chain with a consumer's factory enables form login and Basic authentication
- **THEN** the factory is asked once for namespace `password-login`, with a limit of 50 and a window of 15 minutes

#### Scenario: Unattributable source
- **WHEN** a form login arrives with no client address
- **THEN** it is refused as unattributable without the password being evaluated

### Requirement: A locked account's login refusal looks like a wrong password by default
When the pre-authentication phase denies with the account-locked refusal, form login and Basic authentication SHALL, by default, refuse with an error identifiable as both the authentication failure and the account-locked refusal, so the status mapping answers 401. Before refusing they SHALL spend the authenticator's decoy verification on the presented password. Basic SHALL set its challenge header. A consumer SHALL be able to opt in to disclosing the lock, which refuses with the account-locked refusal alone, answered 429, without the decoy and, for Basic, without the challenge header.

#### Scenario: Default response
- **WHEN** a form login for a locked account arrives and the consumer's error handling writes only the mapped status
- **THEN** the response is 401, as for a wrong password

#### Scenario: Equal password work
- **WHEN** a form login for a locked account arrives through an authenticator built on the password provider
- **THEN** one decoy verification is performed and the account's own password hash is not verified

#### Scenario: Disclosure chosen
- **WHEN** the chain is configured to disclose locks and a form login for a locked account arrives
- **THEN** the response is 429 and no decoy verification is performed

#### Scenario: Disclosed Basic lock
- **WHEN** the chain is configured to disclose locks and a Basic request for a locked account arrives
- **THEN** the response is 429 and carries no `WWW-Authenticate` header

#### Scenario: Authenticator without a decoy
- **WHEN** a chain enables form login with an authenticator that offers no decoy verification, or with a manager none of whose providers offers one, and locks are not disclosed
- **THEN** construction writes one warning that lock refusals may be told apart by their timing

### Requirement: Login failures are counted even when the client disconnects
Form login and Basic authentication SHALL record a failed attempt, and the source guard's failure, on a context from which the request's cancellation has been removed.

#### Scenario: Client disconnects after a wrong password
- **WHEN** a form login with a wrong password is refused and the request's context is cancelled before the attempt is recorded
- **THEN** the attempt store receives the failure on a context that is not cancelled
