## MODIFIED Requirements

### Requirement: The provider's protocol endpoints are exempt from the cross-site check
When CSRF protection is enabled with the provider, the chain SHALL exempt exactly these from it, because relying parties reach them cross-site by design, and none takes a state-changing decision from a cookie alone:
- the authorization endpoint;
- the token, revocation and introspection endpoints;
- the device authorization endpoint, when the device grant is enabled;
- the end-session endpoint. Each exempt endpoint SHALL keep every other protection the chain applies.

#### Scenario: Relying party posts an authorization request
- **WHEN** a relying party's page posts an authorization request cross-site
- **THEN** CSRF protection does not refuse it

#### Scenario: A device posts a device authorization request
- **WHEN** CSRF protection is enabled and a client posts a device authorization request with no `Origin` and no `Sec-Fetch-Site`
- **THEN** CSRF protection does not refuse it

## ADDED Requirements

### Requirement: The code-entry endpoint stays protected
The code-entry endpoint's form POST SHALL stay subject to CSRF protection, because a cross-site post could make a victim's browser claim an attacker's user code.

#### Scenario: A cross-site post of a user code
- **WHEN** CSRF protection is enabled and another site's page posts a user code to the code-entry endpoint
- **THEN** CSRF protection refuses it, and no code is claimed

### Requirement: A GET at code entry claims only on the browser's own navigation
A GET carrying a user code SHALL claim it only when the browser reports the navigation as its own: `Sec-Fetch-Site` of `same-origin` or `none`, or no `Sec-Fetch-Site` at all. Any other GET carrying a user code SHALL claim nothing, and SHALL be redirected with 303 to the consumer's code-entry page with the code prefilled, so the user submits it there. A configuration in which that redirect could loop SHALL fail construction.

#### Scenario: A link from another site carries a user code
- **WHEN** a signed-in user follows a link from another site to the code-entry endpoint with a valid user code (`Sec-Fetch-Site: cross-site`)
- **THEN** nothing is claimed, and the browser is redirected with 303 to the consumer's code-entry page with the code prefilled

#### Scenario: The user's own navigation carries a user code
- **WHEN** a GET with a valid user code arrives with `Sec-Fetch-Site` of `none` or `same-origin`
- **THEN** the code is claimed as usual

#### Scenario: A link from a sibling site carries a user code
- **WHEN** a GET with a valid user code arrives with `Sec-Fetch-Site: same-site`
- **THEN** nothing is claimed, and the browser is redirected with 303 to the consumer's code-entry page with the code prefilled
