# Spec Delta

## ADDED Requirements

### Requirement: The provider's protocol endpoints are exempt from the cross-site check
When CSRF protection is enabled with the provider, the chain SHALL exempt exactly these from it, because relying parties reach them cross-site by design and none of them authenticates by a cookie:
- the authorization endpoint;
- the token, revocation and introspection endpoints;
- the end-session endpoint.

The resume endpoint and the user's consent endpoints SHALL stay protected. Each exempt endpoint SHALL keep every other protection the chain applies.

#### Scenario: Relying party posts an authorization request
- **WHEN** a relying party's page posts an authorization request cross-site
- **THEN** CSRF protection does not refuse it

#### Scenario: Cross-site consent revocation
- **WHEN** a cross-site page posts to the user's consent revocation endpoint
- **THEN** CSRF protection refuses it
