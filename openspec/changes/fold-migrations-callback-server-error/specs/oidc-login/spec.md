# Spec Delta

## ADDED Requirements

### Requirement: A failure answered with server_error is logged with its cause
When a callback failure is answered with `server_error`, at the login page or at the client, the library SHALL write one error-level record that names the failure's reason and the Go type of its cause. It SHALL NOT log the cause's text, the handle, the state or the redirect target.

#### Scenario: Failing apply step logged
- **WHEN** completion is enabled and the sign-in hook's apply step fails for a parked login
- **THEN** one error-level record names the cause's type, and it holds no handle, state, redirect target or error text

#### Scenario: Refusal not logged at error level
- **WHEN** a parked login is refused by the hook and answered with `access_denied`
- **THEN** no error-level record is written for it

## MODIFIED Requirements

### Requirement: The login page's error codes are a closed set that names no account
The `error` a failed login carries back to the login page SHALL be `access_denied` for every refusal, `temporarily_unavailable` for a provider that cannot be reached, and `server_error` for a failing store or user loader and for every other broker or store failure after the flow is spent that maps to neither of the other codes and is not one of the failures that keep their answer. No other parameter SHALL be added. The parameter SHALL be named `error` by default, and a consumer MAY rename it.

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
A failure that maps to no code of the closed set SHALL be answered as it is without this change, with no redirect. This applies to an invalid or unknown state, a failure that leaves the flow unspent, an unknown provider, a re-authentication refusal, a failure whose cause cannot be read, a request whose caller has gone, and a refusal by completion's own checks of the transport, the throttle or the handle. A failure that maps to a code SHALL still pass the parked-request checks before any redirect, and ending the parked request SHALL NOT replace the login's original error.

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

#### Scenario: Re-authentication refusal
- **WHEN** completion is enabled and a parked login's callback fails with the re-authentication refusal
- **THEN** the callback fails as without this change, and no redirect is sent

#### Scenario: Unknown provider after the flow is spent
- **WHEN** completion is enabled and a consumer-supplied manager returns the unknown-provider error, without marking the flow unspent, for a parked login
- **THEN** the callback fails as without this change, and no redirect is sent

#### Scenario: Ordinary destination unchanged
- **WHEN** completion is enabled and a login started with destination `/welcome` fails in the sign-in hook's apply step
- **THEN** the callback fails as without this change, and no redirect is sent
