## ADDED Requirements

### Requirement: An invalid access token is a public refusal mapped to 401
The library SHALL expose a public invalid-token refusal for an access token a resource server refuses: one that does not verify, has expired, has ended at its issuer, names another audience, is of the wrong type, is unbound where binding is required, or is presented where no resource server covers. It SHALL also be identifiable as the uniform authentication failure, and the status mapping SHALL answer it 401. Only a resource server's refusal SHALL be it.

#### Scenario: Status and identity
- **WHEN** the invalid-token refusal is mapped to a status
- **THEN** the status is 401, and the error is identifiable both as the invalid-token refusal and as the authentication failure

#### Scenario: Session tokens unchanged
- **WHEN** signed bearer tokens refuse a session token their verifier rejects
- **THEN** the refusal is the authentication failure, not identifiable as the invalid-token refusal, and carries no `invalid_token` challenge

### Requirement: An invalid-token refusal carries an invalid_token challenge
The chain SHALL answer the invalid-token refusal with a `WWW-Authenticate` challenge naming `error="invalid_token"`: under the `DPoP` scheme with the accepted algorithms when the token came under DPoP or the source requires binding, and under `Bearer` otherwise. The challenge SHALL be set whether or not the chain enables DPoP, SHALL name no check, and a consumer's error handler SHALL be able to replace or remove it.

#### Scenario: Under DPoP
- **WHEN** a resource server refuses a token presented under `DPoP` on a chain accepting ES256
- **THEN** the response carries `WWW-Authenticate: DPoP error="invalid_token", algs="ES256"`

#### Scenario: Under Bearer without DPoP
- **WHEN** the chain does not enable DPoP, a source accepts unbound tokens, and an expired token from it is presented under `Bearer`
- **THEN** the response carries `WWW-Authenticate: Bearer error="invalid_token"`

#### Scenario: Consumer handler edits it
- **WHEN** a consumer's error handler removes the `WWW-Authenticate` header for an invalid-token refusal
- **THEN** the response carries no challenge

### Requirement: A missing scope is answered with an insufficient_scope challenge
When a chain rule or a guard refuses an access-token caller because a scope requirement is not met, the response SHALL be 403 with a `WWW-Authenticate` challenge naming `error="insufficient_scope"` and a `scope` parameter listing the scopes the requirement names, under the scheme the token came under. A refusal of any other caller, or for any other reason, SHALL be answered as before.

#### Scenario: Chain rule
- **WHEN** a chain rule requires any of `orders:write` and an access-token caller holding `orders:read` calls the route under `DPoP`
- **THEN** the response is 403 with `WWW-Authenticate: DPoP error="insufficient_scope", scope="orders:write"`

#### Scenario: Guard
- **WHEN** a guard requires all of `orders:read orders:export` and an access-token caller holding `orders:read` calls the route under `Bearer`
- **THEN** the response is 403 with `WWW-Authenticate: Bearer error="insufficient_scope", scope="orders:read orders:export"`

#### Scenario: API key caller
- **WHEN** an API-key caller lacking a scope is refused by the same rule
- **THEN** the response is 403 with no challenge, as before

### Requirement: A stale access token is answered with an insufficient_user_authentication challenge
When a recency guard refuses an access-token caller, the response SHALL be 401 with a `WWW-Authenticate` challenge naming `error="insufficient_user_authentication"` and a `max_age` parameter holding the guard's window in whole seconds, under the scheme the token came under, so that the client can obtain a token from a fresher sign-in. A session caller's recency refusal SHALL be answered as before.

#### Scenario: Stale token
- **WHEN** a route guarded with a 5-minute window is called with an access token whose authentication time is 20 minutes old, under `DPoP`
- **THEN** the response is 401 with `WWW-Authenticate: DPoP error="insufficient_user_authentication", max_age=300`

#### Scenario: Stale session unchanged
- **WHEN** a stale session calls the same route
- **THEN** the response is 403 with no body, as before

### Requirement: An inactive-account refusal is a public error, disclosed only by choice
The library SHALL expose a public inactive-account refusal. By default it SHALL reach the chain only beneath the uniform authentication failure, answered 401 with nothing in the status, headers or timing to tell it from a wrong password. With inactive-account disclosure enabled, a password login for an inactive account SHALL be refused with the inactive-account refusal alone, which the status mapping SHALL answer 403.

#### Scenario: Default is concealed
- **WHEN** an inactive account signs in by form login with its correct password on a chain with default options
- **THEN** the response is 401, as for a wrong password
- **AND** a consumer's error handler finds the inactive-account refusal beneath the error

#### Scenario: Disclosed
- **WHEN** inactive-account disclosure is enabled and an inactive account signs in with its correct password
- **THEN** the response is 403, and the error is the inactive-account refusal, not identifiable as the uniform authentication failure

#### Scenario: Disclosure needs the password
- **WHEN** inactive-account disclosure is enabled and an inactive account is presented with a wrong password
- **THEN** the response is 401, the uniform authentication failure, and nothing identifies the account as inactive
