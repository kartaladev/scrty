# Spec Delta

## MODIFIED Requirements

### Requirement: The login page's error codes are a closed set that names no account
The `error` a failed login carries back to the login page SHALL be `access_denied` for every refusal, `temporarily_unavailable` for a provider that cannot be reached, and `server_error` for a failing store or user loader and for any other failure after the flow is spent that maps to neither of the other codes. No other parameter SHALL be added. The parameter SHALL be named `error` by default, and a consumer MAY rename it.

#### Scenario: Unlinked and inactive look alike
- **WHEN** one login fails for an unlinked identity and another for a disabled user, both for parked requests
- **THEN** both redirects carry `error=access_denied` and nothing else that differs

#### Scenario: Every refusal is access denied
- **WHEN** parked logins fail by an invalid ID token, a refused provisioning, a hook refusal, an error from the identity provider, and completion's refusal by policy
- **THEN** each redirect carries `error=access_denied`

#### Scenario: Failing user loader
- **WHEN** completion's user loader fails for a parked login
- **THEN** the redirect carries `error=server_error`

#### Scenario: Sign-in hook's apply step fails
- **WHEN** completion is enabled, a login started from the login page for handle `h-1`, and the provider's sign-in hook decides a user whose apply step returns an error
- **THEN** the browser is redirected with 303 to `<login URL>?req=h-1&error=server_error`
- **AND** the request for `h-1` can still be resumed

#### Scenario: Sign-in hook fails without refusing
- **WHEN** completion is enabled, a login for handle `h-1`, and the provider's sign-in hook returns an error that is neither a refusal nor an outage
- **THEN** the browser is redirected to `<login URL>?req=h-1&error=server_error`

#### Scenario: Unclassified failure answered at the client
- **WHEN** the consumer chose to answer the client, and the sign-in hook's apply step fails for a login for handle `h-1` parked with `state=s-1`
- **THEN** the browser is redirected with 303 to the client's redirect URI with `error=server_error`, `state=s-1` and `iss`, and `h-1` is spent

#### Scenario: Consumer renames the parameter
- **WHEN** the consumer names the parameter `sso_error`, and a login for handle `h-1` is refused
- **THEN** the browser is redirected to `<login URL>?req=h-1&sso_error=access_denied`

### Requirement: Failures outside the closed set keep their answer
A failure that maps to no code of the closed set SHALL be answered as it is without this change, with no redirect. This applies only to an invalid or unknown state, a failure that leaves the flow unspent, a failure whose cause cannot be read, a request whose caller has gone, and a refusal by completion's own checks of the transport, the throttle or the handle. Every other failure after the flow is spent maps to `server_error`. Ending the parked request SHALL NOT replace the login's original error.

#### Scenario: Unknown state
- **WHEN** a callback arrives with a state that completes no flow
- **THEN** it fails as an invalid state, as without this change

#### Scenario: Unreadable broker error
- **WHEN** completion is enabled and a broker's error for a parked login cannot be walked
- **THEN** the callback fails as without this change, and no redirect is sent

#### Scenario: Flow left unspent
- **WHEN** completion is enabled and the flow store fails before the flow for a parked login is spent
- **THEN** the callback fails as without this change, the flow cookie is kept, and no redirect is sent

#### Scenario: Caller gone
- **WHEN** completion is enabled and the caller's context ends while the broker resolves a parked login
- **THEN** the callback fails as without this change, and no redirect is sent

#### Scenario: Ordinary destination unchanged
- **WHEN** completion is enabled and a login started with destination `/welcome` fails in the sign-in hook's apply step
- **THEN** the callback fails as without this change, and no redirect is sent
