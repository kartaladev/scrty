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
