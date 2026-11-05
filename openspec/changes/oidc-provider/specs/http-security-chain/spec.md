# Spec Delta

## ADDED Requirements

### Requirement: The OpenID Provider's endpoints plug into the chain
When enabled, the provider SHALL answer on the chain under a prefix, `/oauth2` by default, with these paths:
- authorization `/authorize` and resume `/authorize/resume`;
- token `/token`, UserInfo `/userinfo`, revocation `/revoke`, introspection `/introspect`;
- end-session `/logout`, its confirmation `/logout/confirm`, and the user's consents `/consents`.

A request on any other path SHALL pass through.

#### Scenario: Other path
- **WHEN** the provider is enabled and a request arrives for `/api/orders`
- **THEN** it passes through to the next interceptor

### Requirement: The provider's paths are replaceable and published as used
The provider SHALL answer the two metadata documents at their well-known paths. The consumer SHALL be able to change the prefix and each endpoint path. Endpoint URLs in the metadata SHALL follow the paths in use.

#### Scenario: Default paths
- **WHEN** the provider is enabled with defaults and issuer `https://id.example.com`
- **THEN** the metadata's `token_endpoint` is `https://id.example.com/oauth2/token`, and a POST there reaches the token endpoint

#### Scenario: Consumer prefix
- **WHEN** the consumer sets the prefix to `/op`
- **THEN** the token endpoint answers at `/op/token`, the metadata names it, and a POST to `/oauth2/token` passes through

### Requirement: Provider wiring mistakes fail at construction
Building a chain with the provider SHALL fail with a configuration error naming the provider when:
- neither bearer mode is enabled, because the resume needs a sign-in credential;
- the JWKS endpoint is not enabled;
- the provider is enabled more than once;
- a session manager the chain is wired with does not report sign-in ends to the provider (`sessions`), because grants would then outlive a logout;
- two of its paths collide with each other or with another endpoint of the chain.

#### Scenario: No bearer mode
- **WHEN** the provider is enabled on a chain with form login and no bearer mode
- **THEN** construction fails with a configuration error naming the provider

#### Scenario: Session manager not reporting to the provider
- **WHEN** the provider is enabled on a chain whose session manager was built without the provider as an end observer
- **THEN** construction fails with a configuration error naming the provider

#### Scenario: Path collision
- **WHEN** the consumer sets the provider's end-session path to the chain's logout path
- **THEN** construction fails with a configuration error

### Requirement: A provider path is one that can be published as served
Building a chain SHALL fail with a configuration error naming the option when a provider path or prefix holds a character that would need escaping in a URL path, because it could then not be published and compared as served.

#### Scenario: A space in the prefix
- **WHEN** the consumer sets the provider's prefix to `/o p`
- **THEN** construction fails with a configuration error naming the option

### Requirement: The provider and the chain must agree
Building a chain with the provider SHALL fail with a configuration error naming the provider when:
- the JWKS endpoint publishes a different signing-key manager from the one the provider signs with;
- the provider accepts assertions naming a token endpoint other than its public URL;
- a client the provider can list requires a binding the chain does not verify;
- the provider and the chain disagree on whether DPoP is on.

#### Scenario: A consumer's own registry
- **WHEN** a client in a consumer's own registry requires a binding the chain does not verify
- **THEN** the chain builds, as such a registry cannot be listed, and the client is refused at the token endpoint

#### Scenario: Keys that differ
- **WHEN** the provider signs with one `*signingkey.Keys`, and the JWKS endpoint publishes another
- **THEN** construction fails with a configuration error naming the provider

#### Scenario: A wrapped key source
- **WHEN** the consumer wraps the signing-key manager the JWKS endpoint publishes, and gives the wrapper to the provider
- **THEN** the chain builds

### Requirement: The provider requires the protections its pages rest on
The provider also requires two protections its pages rest on. CSRF protection SHALL be enabled while browser sessions are on, because the consent stage and the logout confirmation then rest on a cookie. Security headers SHALL be enabled, unless the consumer states that its login and consent pages carry `frame-ancestors` themselves. Otherwise construction SHALL fail with a configuration error naming the provider.

#### Scenario: Browser sessions without CSRF protection
- **WHEN** the provider is enabled with its default browser sessions on a chain without CSRF protection
- **THEN** construction fails with a configuration error naming the provider

#### Scenario: Security headers that allow framing
- **WHEN** the provider is enabled with security headers whose document policy has no `frame-ancestors`, is report-only, or allows `*`, a scheme, a wildcard host or a plain `http` origin
- **THEN** construction fails with a configuration error naming the provider

#### Scenario: A named origin may frame the pages
- **WHEN** the document policy's `frame-ancestors` holds only `'self'` and `https://ext.example.org:8000`
- **THEN** the chain builds

#### Scenario: Security headers missing
- **WHEN** the provider is enabled on a chain without security headers, and the consumer has not stated that its pages carry `frame-ancestors`
- **THEN** construction fails with a configuration error naming the provider

#### Scenario: Consumer states its pages protect themselves
- **WHEN** the consumer states that its pages carry `frame-ancestors`, on a chain without security headers
- **THEN** the chain is built

### Requirement: Chain logout ends the sign-in's provider grants first
When the provider is in use, logout SHALL end the sign-in through the provider before it deletes the sessions. Grants without `offline_access` created from that sign-in SHALL be revoked, and the relying parties holding them SHALL be told. A failure to revoke the grants SHALL fail the logout as a dependency failure, and SHALL leave the session in place, so the logout can be retried. A failure to notify a relying party SHALL NOT fail the logout.

#### Scenario: Logout revokes an online grant
- **WHEN** a user logs out of the sign-in `billing-web`'s grant without `offline_access` came from
- **THEN** the logout answers 200, and that grant's refresh token is refused with `invalid_grant`

#### Scenario: Grant store outage at logout
- **WHEN** the grant store fails while a user logs out
- **THEN** the logout answers 500, the session still loads, and a retried logout succeeds once the store recovers

### Requirement: Every explicit end of a sign-in reaches the provider
When the provider is in use, each of these SHALL end the affected sign-ins through the provider, as a logout does:
- revocation of a session family because a superseded identifier was presented after its window;
- ending one sign-in by its handle, and ending a user's other sessions;
- ending other sessions when a passkey is removed;
- deleting a user's sessions through the session manager.

A sign-in that merely expires SHALL NOT be reported.

#### Scenario: Stolen session reused
- **WHEN** a session's superseded identifier is presented after its window, and a grant without `offline_access` came from that sign-in
- **THEN** the family is revoked, and the grant's refresh token is refused with `invalid_grant`

#### Scenario: Other sessions ended
- **WHEN** a user ends their other sessions, and `billing-web` holds a grant without `offline_access` from one of them
- **THEN** that grant's refresh token is refused, and `billing-web` receives a logout token

### Requirement: A failed grant revocation never undoes a sign-in's end
When ending a sign-in through the provider fails on one of the paths that report it, other than the chain's logout, the failure SHALL be logged and reported as a security event, and SHALL NOT undo or delay the end of the sessions.

#### Scenario: Grant store outage during family revocation
- **WHEN** the grant store fails while a family is revoked for reuse
- **THEN** the family is still revoked, and the failure is logged and reported as an event

#### Scenario: Sign-in expires
- **WHEN** a sign-in reaches its idle deadline
- **THEN** no logout token is sent, and its grants end by their own deadlines (`oidc-provider-tokens`)

### Requirement: A password change keeps provider grants unless the consumer chooses otherwise
By default a password change through the chain SHALL NOT revoke the user's provider grants. A consumer MAY configure the password change to revoke every grant of the user. A failure to revoke them SHALL then fail the change as a dependency failure, before the new password is written.

#### Scenario: Default
- **WHEN** a user resolves a required password change, under the default
- **THEN** the user's grants keep working

#### Scenario: Consumer revokes on password change
- **WHEN** the consumer configures the change to revoke grants, and a user resolves a required password change
- **THEN** every grant of that user is refused afterwards

### Requirement: Ending one's other sessions can also revoke application access
When the provider is in use, the user's request to end their other sessions SHALL accept a choice to also revoke application access, off by default. When chosen, every provider grant of the user SHALL be revoked, `offline_access` included. The presenting sign-in SHALL be kept, as without the choice.

#### Scenario: Revoke application access chosen
- **WHEN** a user ends their other sessions and chooses to revoke application access
- **THEN** their other sessions end, and every refresh token issued for them is refused

#### Scenario: Not chosen
- **WHEN** a user ends their other sessions without the choice
- **THEN** their grants holding `offline_access` keep working, and grants without it from the ended sign-ins are revoked
