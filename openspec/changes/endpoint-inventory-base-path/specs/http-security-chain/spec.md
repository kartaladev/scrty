# Spec Delta

## ADDED Requirements

### Requirement: Built-in endpoints answer under an optional base path
The chain SHALL answer every built-in endpoint at the base path joined with that endpoint's own path, the key set endpoint included. By default there SHALL be no base path, and every endpoint SHALL answer at exactly the path it answers without one. A path the consumer sets for a single endpoint SHALL be relative to the base path. The base path SHALL take effect wherever its option stands among the chain's options.

#### Scenario: No base path
- **WHEN** a chain enables form login and the key set without a base path
- **THEN** login answers at `/login` and the key set at `/.well-known/jwks.json`

#### Scenario: Base path moves the defaults
- **WHEN** a chain enables form login, MFA and the key set with the base path `/auth`
- **THEN** login answers at `/auth/login`, second-factor verification at `/auth/mfa/verify/{method}`, and the key set at `/auth/.well-known/jwks.json`
- **AND** a request to `/login` or `/.well-known/jwks.json` passes through to the handler

#### Scenario: Consumer path within the base
- **WHEN** a chain has the base path `/auth` and the consumer sets the login path to `/signin`
- **THEN** login answers at `/auth/signin` and not at `/signin`

#### Scenario: Option order does not matter
- **WHEN** the base path option is given after the options that enable form login and re-authentication
- **THEN** both answer under the base path, exactly as when it is given first

#### Scenario: Every adapter answers the same paths
- **WHEN** one configuration with the base path `/auth` is served through net/http, gin and fiber
- **THEN** each answers login at `/auth/login` and passes `/login` through

### Requirement: An unusable base path fails at construction
Building a chain SHALL fail with a configuration error naming the base path option when the base path is empty, is the root `/`, does not start with `/`, or is not in clean form (for example it contains `//`, `.` or `..` segments). A single trailing slash SHALL be dropped, so `/auth/` and `/auth` are the same base path.

#### Scenario: Root base path
- **WHEN** the base path is `/`
- **THEN** construction fails with a configuration error naming the base path option

#### Scenario: Relative base path
- **WHEN** the base path is `auth`
- **THEN** construction fails with a configuration error

#### Scenario: Unclean base path
- **WHEN** the base path is `/auth/../admin`
- **THEN** construction fails with a configuration error

#### Scenario: Trailing slash
- **WHEN** the base path is `/auth/`
- **THEN** login answers at `/auth/login`

### Requirement: The base path covers only the endpoints the chain answers
The base path SHALL NOT change the consumer's authorization rules, the paths any consumer interceptor matches, or links that point at pages the consumer serves, such as the page an emailed sign-in link opens. The base path SHALL be compared with the request path the chain receives.

#### Scenario: Authorization rules keep the consumer's paths
- **WHEN** a chain has the base path `/auth` and an authorization rule allowing `GET /projects/{id}`
- **THEN** a request to `GET /projects/42` is judged by that rule, and the rule never matches `/auth/projects/42`

#### Scenario: Emailed sign-in link unchanged
- **WHEN** a chain with the base path `/auth` enables magic-link sign-in whose link points at the consumer's confirm page `/login/magic/confirm`
- **THEN** the emailed link still points at `/login/magic/confirm`
- **AND** the endpoint that redeems the link answers at `/auth/login/magic/consume`

#### Scenario: Prefix stripped before the chain
- **WHEN** a proxy strips `/auth` before requests reach a chain that has no base path
- **THEN** a request the proxy received at `/auth/login` reaches the chain as `/login` and is answered by login

### Requirement: The chain lists the endpoints it answers
A built chain SHALL list every built-in endpoint it answers. Each entry SHALL give the methods, the path after the base path is applied (a segment the endpoint reads written as `{name}`), how it matches (exactly, the path followed by one segment, or the path and everything beneath it), a stable operation identifier, the option that enabled it, and the session state it requires. Endpoints not enabled and consumer interceptors SHALL NOT be listed.

#### Scenario: Enabled endpoints listed
- **WHEN** a chain with the base path `/auth` enables form login and MFA with TOTP
- **THEN** the list contains login at `POST /auth/login` with the operation identifier `scrty.login`, and second-factor verification at `POST /auth/mfa/verify/{method}`
- **AND** it contains no logout, passkey or recovery entry

#### Scenario: Consumer interceptor not listed
- **WHEN** a consumer registers their own interceptor that answers `/status`
- **THEN** the list contains no entry for `/status`

#### Scenario: The list cannot change the chain
- **WHEN** a caller modifies the list it was given
- **THEN** a later request is answered as before, and a fresh list is unchanged

#### Scenario: Operation identifiers are stable
- **WHEN** the same configuration is built with and without a base path
- **THEN** each endpoint carries the same operation identifier in both lists

### Requirement: Colliding endpoint paths fail at construction
Building a chain SHALL fail with a configuration error when, after the base path is applied, some request path would be answered by two enabled built-in endpoints, unless both belong to the same option and answer different methods. An exact path equal to another endpoint's prefix, with or without its trailing slash, SHALL also collide. The error SHALL name both options and both paths.

#### Scenario: Two features on one path
- **WHEN** form login and magic-link requests are both set to answer `/signin`
- **THEN** construction fails with a configuration error naming both options and `/signin`

#### Scenario: Path under another endpoint's prefix
- **WHEN** the re-authentication prefix is set so that its password path lies under the MFA verify prefix
- **THEN** construction fails with a configuration error naming both options

#### Scenario: One option, two methods on one path
- **WHEN** account recovery is enabled with issued codes, whose count and regeneration answer GET and POST on one path
- **THEN** the chain is built

#### Scenario: Collisions judged after the base path
- **WHEN** the base path is `/auth` and the consumer sets the logout path to `/login`
- **THEN** construction fails, because both endpoints would answer `/auth/login`
