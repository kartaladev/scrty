# Spec Delta

## ADDED Requirements

### Requirement: The OpenID Provider's endpoints plug into the chain
When enabled, the provider SHALL answer on the chain under a prefix, `/oauth2` by default, with these paths:
- authorization `/authorize` and resume `/authorize/resume`;
- token `/token`, UserInfo `/userinfo`, revocation `/revoke`, introspection `/introspect`;
- end-session `/logout`, and the user's consents `/consents`.

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
- two of its paths collide with each other or with another endpoint of the chain.

#### Scenario: No bearer mode
- **WHEN** the provider is enabled on a chain with form login and no bearer mode
- **THEN** construction fails with a configuration error naming the provider

#### Scenario: Path collision
- **WHEN** the consumer sets the provider's end-session path to the chain's logout path
- **THEN** construction fails with a configuration error

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
- ending a user's other sessions;
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
