# Spec Delta

## ADDED Requirements

### Requirement: The provider's protocol endpoints are exempt from the cross-site check
When CSRF protection is enabled with the provider, the chain SHALL exempt exactly these from it, because relying parties reach them cross-site by design, and none takes a state-changing decision from a cookie alone:
- the authorization endpoint;
- the token, revocation and introspection endpoints;
- the end-session endpoint. Each exempt endpoint SHALL keep every other protection the chain applies.

#### Scenario: Relying party posts an authorization request
- **WHEN** a relying party's page posts an authorization request cross-site
- **THEN** CSRF protection does not refuse it

### Requirement: Provider endpoints that may rest on a cookie stay protected
The resume endpoint, the logout confirmation and the user's consent endpoints SHALL stay protected. The consent stage and the logout confirmation, which may rest on the provider's browser session, SHALL therefore never be reachable cross-site.

#### Scenario: Cross-site consent answer
- **WHEN** a cross-site page posts a consent answer to the resume endpoint, with the victim's handle
- **THEN** CSRF protection refuses it

#### Scenario: Cross-site logout confirmation
- **WHEN** a cross-site page posts to the logout confirmation
- **THEN** CSRF protection refuses it

#### Scenario: Cross-site consent revocation
- **WHEN** a cross-site page posts to the user's consent revocation endpoint
- **THEN** CSRF protection refuses it
