## ADDED Requirements

### Requirement: A failed brokered login for a parked request returns to the login page
With server-side completion enabled, a federated login whose stored destination is the provider's login URL carrying only a parked request's handle SHALL, when it fails with an answerable failure, redirect the browser with 303 to `<login URL>?req=<handle>&error=<code>`, with `Cache-Control: no-store` and `Referrer-Policy: no-referrer`. The parked request SHALL stay parked.

#### Scenario: Hook refuses at the callback
- **WHEN** completion is enabled, a login started from the login page for handle `h-1`, and the provider's sign-in hook refuses the identity
- **THEN** the browser is redirected with 303 to `<login URL>?req=h-1&error=access_denied`
- **AND** the request for `h-1` can still be resumed

#### Scenario: UserInfo outage at the callback
- **WHEN** completion is enabled, a login for handle `h-1`, and the provider's UserInfo endpoint cannot be reached
- **THEN** the browser is redirected to `<login URL>?req=h-1&error=temporarily_unavailable`

#### Scenario: User cancels at the identity provider
- **WHEN** completion is enabled, a login for handle `h-1`, and the identity provider redirects back with `error=access_denied` and the flow's real state
- **THEN** the flow is ended, the flow cookie is cleared, and the browser is redirected to `<login URL>?req=h-1&error=access_denied`

#### Scenario: Completion refuses an inactive user
- **WHEN** completion is enabled and the user the broker resolved for handle `h-1` is disabled
- **THEN** the browser is redirected to `<login URL>?req=h-1&error=access_denied`, and no session exists

#### Scenario: Ordinary destination unchanged
- **WHEN** completion is enabled and a login started with destination `/welcome` is refused by the hook
- **THEN** the callback fails as without this change, and no redirect is sent

### Requirement: A login that cannot start for a parked request returns to the login page
With server-side completion enabled, a login start whose destination is the provider's login URL carrying only a parked request's handle SHALL, when the provider's metadata cannot be discovered, redirect the browser with 303 to `<login URL>?req=<handle>&error=temporarily_unavailable`, store no flow and set no flow cookie.

#### Scenario: Discovery down at the start
- **WHEN** completion is enabled, the login page starts a login for handle `h-1`, and discovery fails
- **THEN** the browser is redirected to `<login URL>?req=h-1&error=temporarily_unavailable`, and no flow is stored

#### Scenario: Discovery down for an ordinary login
- **WHEN** completion is enabled, a login starts with destination `/welcome`, and discovery fails
- **THEN** the start fails as without this change

### Requirement: The login page's error codes are a closed set that names no account
The `error` a failed login carries back to the login page SHALL be `access_denied` for every refusal, `temporarily_unavailable` for a provider that cannot be reached, and `server_error` for a failing store or user loader. No other parameter SHALL be added. The parameter SHALL be named `error` by default, and a consumer MAY rename it.

#### Scenario: Unlinked and inactive look alike
- **WHEN** one login fails for an unlinked identity and another for a disabled user, both for parked requests
- **THEN** both redirects carry `error=access_denied` and nothing else that differs

#### Scenario: Every refusal is access denied
- **WHEN** parked logins fail by an invalid ID token, a refused provisioning, a hook refusal, an error from the identity provider, and completion's refusal by policy
- **THEN** each redirect carries `error=access_denied`

#### Scenario: Failing user loader
- **WHEN** completion's user loader fails for a parked login
- **THEN** the redirect carries `error=server_error`

#### Scenario: Consumer renames the parameter
- **WHEN** the consumer names the parameter `sso_error`, and a login for handle `h-1` is refused
- **THEN** the browser is redirected to `<login URL>?req=h-1&sso_error=access_denied`

### Requirement: Returning to the login page passes the parked-request checks first
Before redirecting back to the login page, the library SHALL refuse over plain HTTP, throttle and check the parked request as completion does: live or within its grace window, bound to the browser's flow cookie, and at its login stage. A request that fails the check SHALL get the failure's answer as without this change. A request expired within its grace window SHALL be answered at the client's redirect URI.

#### Scenario: Handle of another browser
- **WHEN** completion is enabled, a login for handle `h-1` fails, and the browser's flow cookie does not bind `h-1`
- **THEN** the callback fails as without this change, and no redirect to the login page is sent

#### Scenario: Request expired during the login
- **WHEN** a login for handle `h-1` fails after the request expired, within the grace window
- **THEN** the browser is redirected to the client's redirect URI with `error=access_denied`, `state` and `iss`

### Requirement: Failures outside the closed set keep their answer
A failure that maps to no code of the closed set SHALL be answered as it is without this change, with no redirect. This applies to an invalid or unknown state, a failure whose cause cannot be read, a request whose caller has gone, and a refusal by completion's own checks of the transport, the throttle or the handle. Ending the parked request SHALL NOT replace the login's original error.

#### Scenario: Unknown state
- **WHEN** a callback arrives with a state that completes no flow
- **THEN** it fails as an invalid state, as without this change

#### Scenario: Unreadable broker error
- **WHEN** completion is enabled and a broker's error for a parked login cannot be walked
- **THEN** the callback fails as without this change, and no redirect is sent

### Requirement: A consumer can answer the client instead of the login page
A consumer MAY choose that a failed brokered login for a parked request ends the request and answers the client instead. The failure's code SHALL then end the parked request, and the browser SHALL be redirected with 303 to the client's redirect URI with that `error`, `state` and `iss`. Choosing it without server-side completion SHALL fail construction.

#### Scenario: Straight to the client
- **WHEN** the consumer chose to answer the client, and the hook refuses a login for handle `h-1` parked with `state=s-1`
- **THEN** the browser is redirected with 303 to the client's redirect URI with `error=access_denied`, `state=s-1` and `iss`, and `h-1` is spent

#### Scenario: Ending fails
- **WHEN** the consumer chose to answer the client, and the parked request cannot be ended because its store fails
- **THEN** the callback fails with the login's original error, and an error record is logged

#### Scenario: Chosen without completion
- **WHEN** the consumer chooses to answer the client without enabling completion
- **THEN** construction fails with a configuration error

### Requirement: Events and logs of a returned login are as before
A failed login answered by a redirect SHALL emit the same events as without this change, once. A callback refused beside an outage, whether or not its login is parked, SHALL emit one login-failure event, as a refusal does. The library SHALL log one sampled record naming the code for each redirect, and SHALL NOT log the handle, the state or the redirect target.

#### Scenario: One login-failure event
- **WHEN** a parked login is refused by the hook and redirected to the login page
- **THEN** exactly one login-failure event is emitted

#### Scenario: Refusal beside an outage
- **WHEN** a broker's error is both an unlinked identity and a UserInfo failure
- **THEN** the login is answered as a refusal, a parked one with `access_denied`, and exactly one login-failure event is emitted

## MODIFIED Requirements

### Requirement: A provider error redirect cannot cancel someone else's login
When the callback receives an authorization error from the provider instead of a code, the library SHALL end the flow only when the echoed state completes it, as for a code. Only then SHALL it clear the flow cookie. A callback carrying an error and a state that does not complete the flow SHALL change nothing and SHALL leave the cookie in place. The provider's error text SHALL be logged only after the flow has been completed, and SHALL never be returned to the caller. The response SHALL be an authentication failure, unless the completed flow belongs to a parked request, which is answered as a refused login for it.

#### Scenario: Forged error link
- **WHEN** a victim with a live flow cookie follows a link to the callback carrying `error=access_denied` and no valid state
- **THEN** the response is an authentication failure
- **AND** no cookie-clearing header is sent
- **AND** the victim's genuine callback still completes

#### Scenario: Genuine denial at the provider
- **WHEN** the provider redirects back with `error=access_denied` and the flow's real state
- **THEN** the flow is ended and the flow cookie is cleared

### Requirement: Completion checks the parked request before it changes anything
Before it loads the user or creates a session, completion SHALL check that the parked request exists, has not expired and is bound to the browser's flow cookie. A request that fails the check SHALL be answered with the provider's unknown-handle outcome, charged to the request's source, with no session, no event of a successful login and no change to the user's held recoveries. A request expired within its grace window SHALL instead be answered at the client's redirect URI, with no session either.

#### Scenario: Parked request expired
- **WHEN** completion is enabled and the handle `h-1` expired before the callback, past its grace window
- **THEN** the callback fails with the provider's unknown-handle outcome, no session is created, and the source is charged

#### Scenario: Parked request expired within the grace window
- **WHEN** completion is enabled and the handle `h-1` expired 2 minutes before the callback
- **THEN** the browser is redirected to the client's redirect URI with `error=access_denied`, and no session is created

#### Scenario: Handle of another browser
- **WHEN** completion is enabled and the browser's flow cookie does not bind handle `h-1`
- **THEN** the callback fails with the provider's unknown-handle outcome and no session is created

### Requirement: Completion builds the session as a redemption does
Completion SHALL load the user through the configured user loader and refuse a missing, disabled or mismatched user as a redemption does. It SHALL run the post-authentication policy on the stored details, including the password-change time, and the asserted assurance. When nothing is owed it SHALL create the session through the login completion step, with the external session and assurance in its creating write, after cancelling the user's held recoveries.

#### Scenario: Stored roles, not the broker's
- **WHEN** the broker's principal carries role `admin` and the user's stored roles are `viewer`
- **THEN** the session created by completion holds `viewer` only

#### Scenario: Password age judged from the stored time
- **WHEN** the user's stored password-change time makes the policy require a password change
- **THEN** completion does not resume the request and falls back to the handoff

#### Scenario: Held recovery cancelled
- **WHEN** the user has a held account recovery and completion signs them in
- **THEN** the held recovery is cancelled before the session is stored

#### Scenario: Policy denies
- **WHEN** completion is enabled and the post-authentication policy denies the user for handle `h-1`
- **THEN** no session is created and the browser is redirected to `<login URL>?req=h-1&error=access_denied`

### Requirement: Completion resumes only a fully authenticated session
Before it resumes, completion SHALL judge the new session under the chain's per-request policy as the resume endpoint judges a sign-in, and SHALL build the provider sign-in with the chain's sign-in assurance mapping. After the resume it SHALL confirm the sign-in as the resume endpoint does. A per-request refusal, a resume that fails or answers without a code, and a failed confirmation SHALL each end the session just stored and issue no code to the client.

#### Scenario: Per-request policy refuses
- **WHEN** a consumer per-request policy refuses the new session for handle `h-1`
- **THEN** the session is ended, no code is issued, and the browser is redirected to `<login URL>?req=h-1&error=access_denied`

#### Scenario: Consumer assurance mapping
- **WHEN** the consumer replaced the sign-in assurance mapping
- **THEN** the provider sign-in carries the values that mapping returns

#### Scenario: Resume answers login required
- **WHEN** the parked request carries an `id_token_hint` naming another subject and the resume answers `login_required`
- **THEN** the session just stored is ended and the browser receives the client's error response

#### Scenario: Confirmation fails
- **WHEN** the sign-in ends between the resume and its confirmation
- **THEN** the callback fails with the re-authentication outcome and no redirect to the client is sent

#### Scenario: Ending the session fails
- **WHEN** completion must end the session it stored and the end fails
- **THEN** an error record is logged and the original refusal is returned unchanged
