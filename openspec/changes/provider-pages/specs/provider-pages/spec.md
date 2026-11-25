# Spec Delta

## Purpose

Gives a chain that runs the OpenID Provider scrty-served login, consent, logout confirmation and
device code-entry pages, enabled and overridden like every other page in the page set.

## ADDED Requirements

### Requirement: Provider pages are served when the page set runs on a provider chain
When a page set is enabled on a chain that runs the OpenID Provider, the provider's login, consent, logout confirmation and device code-entry pages SHALL be served, each switchable off and replaceable like any other page. On a chain without the provider they SHALL NOT be served.

#### Scenario: Provider chain
- **WHEN** the default page set is enabled on a chain running the provider with the device flow on
- **THEN** the login, consent, logout confirmation and code-entry pages are all served

#### Scenario: Consent page replaced
- **WHEN** the consumer serves the consent page with its own handler
- **THEN** the provider sends the browser to the consumer's handler, and every other provider page is the page set's

### Requirement: The provider's page URLs agree with the page set
The page set SHALL supply the provider's login and consent URLs. Building the chain SHALL fail with a configuration error when the provider's login or consent URL does not name the page set's page at its path under the chain's base path on the issuer's origin, unless that page is switched off or replaced.

#### Scenario: Supplied URLs
- **WHEN** the provider is built with the URLs the page set supplies for the issuer `https://id.example.com`
- **THEN** the chain builds, and a parked request redirects to the page set's login page

#### Scenario: Disagreeing URL
- **WHEN** the provider's login URL is `https://id.example.com/login` and the page set's login page is at `/sign-in`
- **THEN** construction fails with a configuration error naming both

### Requirement: The provider login page shows who is asking
The provider login page SHALL read the pending request by its handle and show the client's name, prefill the identifier field from `login_hint`, offer the sign-in methods the chain answers, and offer a cancel button. A handle the provider does not know for this browser SHALL show the provider error page.

#### Scenario: Request read
- **WHEN** a browser lands on the login page with a live handle and `login_hint=ada@example.com`
- **THEN** the page names the client and prefills `ada@example.com`

#### Scenario: Cancel
- **WHEN** the user cancels
- **THEN** the browser is redirected to the client's redirect URI with `error=access_denied`, `state` and `iss`

#### Scenario: Unknown handle
- **WHEN** a browser opens the login page with a handle not bound to its flow cookie
- **THEN** the provider error page is shown, and nothing is resumed

### Requirement: Signing in on the provider login page continues the request
After a sign-in from the provider login page, the browser SHALL reach the continuation, which SHALL resume the parked request with the request's cookie sign-in and redirect the browser on when the navigation came from the same origin. Otherwise it SHALL show a single button that posts the resume.

#### Scenario: Same-origin continuation
- **WHEN** a user signs in on the provider login page and the browser follows the sign-in's redirect
- **THEN** the request is resumed, and the browser is redirected to the consent page or to the client with a code

#### Scenario: Cross-site navigation to the continuation
- **WHEN** another site navigates a signed-in browser to the continuation with a handle
- **THEN** nothing is resumed, and the page shows a continue button

### Requirement: The consent page asks for each scope
The consent page SHALL name the client and list each requested scope with its description from the message bundle, the scope's name when there is none, show `offline_access` apart, and let the user grant optional scopes individually. `openid`, when requested, SHALL always be granted with any grant. Allow and deny SHALL answer through the resume endpoint.

#### Scenario: Partial grant
- **WHEN** a client asks for `openid profile email offline_access` and the user unticks `email` and `offline_access`
- **THEN** the code is bound to `openid profile`

#### Scenario: Deny
- **WHEN** the user denies
- **THEN** the browser is redirected to the client with `error=access_denied`, and no consent is recorded

#### Scenario: Unknown scope
- **WHEN** a client asks for `inventory.read`, which no message describes
- **THEN** the page lists `inventory.read` by name

### Requirement: The logout confirmation page asks before ending the sign-in
The logout confirmation page SHALL name the client that asked, when known, and offer to sign out or to stay signed in, each answering through the logout confirmation endpoint.

#### Scenario: Sign out
- **WHEN** the user chooses to sign out
- **THEN** the browser's sign-in ends, and the browser is redirected to where the provider says

#### Scenario: Stay
- **WHEN** the user chooses to stay signed in
- **THEN** nothing ends

### Requirement: The code-entry page takes a user code and shows the outcome
The code-entry page SHALL take a user code as a form post to the provider's code-entry endpoint, prefill a code given in the query, and show the outcome when it carries `result` of `approved`, `denied` or `expired`, and the provider's uniform refusal message for any refused code.

#### Scenario: Prefilled code
- **WHEN** a device shows a verification URI carrying `user_code=WDJB-MJHT` and the user opens it
- **THEN** the page shows the code prefilled

#### Scenario: Outcome
- **WHEN** the browser lands on the page with `result=approved`
- **THEN** the page says the device is approved and the user may return to it

#### Scenario: Refused code
- **WHEN** an unknown, expired or already used code is entered
- **THEN** the page shows one message for all of them

### Requirement: The provider error page shows nothing the provider knows
A refused authorization request that cannot be redirected back to the client SHALL be shown as the provider error page with the refusal's status, a message from the bundle, and no client identifier, redirect URI or provider error text.

#### Scenario: Unregistered redirect URI
- **WHEN** a browser sends an authorization request naming an unregistered redirect URI
- **THEN** the provider error page is shown with status `400`, and no redirect URI appears on it
