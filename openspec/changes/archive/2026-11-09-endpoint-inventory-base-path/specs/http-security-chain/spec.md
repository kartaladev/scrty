# Spec Delta

## ADDED Requirements

### Requirement: Built-in endpoints answer under an optional base path
The chain SHALL answer every built-in endpoint at the base path followed by that endpoint's own path, the key set and the provider's endpoints included. By default there SHALL be no base path, and every endpoint SHALL answer at exactly the path it answers without one. A path the consumer sets for a single endpoint SHALL be relative to the base path. The base path SHALL take effect wherever its option stands among the chain's options.

#### Scenario: No base path
- **WHEN** a chain enables form login and the key set without a base path
- **THEN** password sign-in answers at `/sign-in/password` and the key set at `/.well-known/jwks.json`

#### Scenario: Base path moves the defaults
- **WHEN** a chain enables form login, MFA, the key set, the session signal stream and the provider with issuer `https://id.example.com/auth` with the base path `/auth`
- **THEN** password sign-in answers at `/auth/sign-in/password`, second-factor verification at `/auth/mfa/verify/{method}`, the key set at `/auth/.well-known/jwks.json`, the signal stream at `/auth/session/signals` and the token endpoint at `/auth/oauth2/token`
- **AND** a request to `/sign-in/password` or `/.well-known/jwks.json` passes through to the handler

#### Scenario: Consumer path within the base
- **WHEN** a chain has the base path `/auth` and the consumer sets the password sign-in path to `/signin`
- **THEN** password sign-in answers at `/auth/signin` and not at `/signin`

#### Scenario: Provider endpoint path within the base
- **WHEN** a chain has the base path `/auth`, enables the provider with issuer `https://id.example.com/auth`, and the consumer sets the provider's token endpoint path to `/tokens`
- **THEN** the token endpoint answers at `/auth/tokens`

#### Scenario: Option order does not matter
- **WHEN** the base path option is given after the options that enable form login, re-authentication and the provider with issuer `https://id.example.com/auth`
- **THEN** each answers under the base path, exactly as when it is given first

#### Scenario: Given twice
- **WHEN** the base path option is given twice, first `/a` and then `/b`
- **THEN** every built-in endpoint answers under `/b`

#### Scenario: Every adapter answers the same paths
- **WHEN** one configuration with the base path `/auth` is served through net/http, gin and fiber
- **THEN** each answers password sign-in at `/auth/sign-in/password` and passes `/sign-in/password` through

### Requirement: Built-in endpoints have documented default paths
Without a base path, each built-in endpoint SHALL answer at a documented default path, grouped by what it does: signing in under `/sign-in`, signing out at `/sign-out`, federated sign-in under `/sso`, the provider under `/oauth2`, the caller's session under `/session` and their sessions under `/sessions`. The scenarios list the defaults; passkey paths are those `passkey-authentication` documents.

#### Scenario: Signing in and out
- **WHEN** form login, magic-link sign-in and logout are enabled with default paths
- **THEN** password sign-in answers at `/sign-in/password`, a link is requested at `/sign-in/magic-link` and redeemed at `/sign-in/magic-link/redeem`, and logout answers at `/sign-out`
- **AND** the emailed link points at the confirm page `/sign-in/magic-link/confirm` by default

#### Scenario: Federated sign-in
- **WHEN** OIDC login with redemption and back-channel logout is enabled with default paths and provider `corp`
- **THEN** sign-in with `corp` starts at `/sso/login/corp`, its callback answers at `/sso/callback/corp`, redemption at `/sso/handoff` and back-channel logout at `/sso/backchannel-logout/corp`

#### Scenario: Second factor and re-authentication
- **WHEN** MFA with the method listing and re-authentication are enabled with default paths
- **THEN** a challenge for method `email-code` begins at `/mfa/challenge/email-code` and is verified at `/mfa/verify/email-code`, the methods are listed at `/mfa/methods`, and re-authentication begins at `/reauth/challenge/email-code`, verifies at `/reauth/verify/email-code`, lists at `/reauth/methods` and re-proves a password at `/reauth/password`

#### Scenario: Session endpoints
- **WHEN** session renewal, the signal stream and session management are enabled with default paths
- **THEN** renewal answers at `/session/renewal`, the stream at `/session/signals`, and the user's sessions at `/sessions` and `/sessions/{handle}`

### Requirement: Every endpoint path has one shape
Building a chain SHALL fail with a configuration error naming the option when the base path or any built-in endpoint path is empty, does not start with `/`, is the root `/`, is not in clean form once one trailing slash is set aside, or contains a character other than letters, digits, `-`, `.`, `_`, `~` and `/`.

#### Scenario: Relative endpoint path
- **WHEN** the consumer sets the password sign-in path to `signin`
- **THEN** construction fails with a configuration error naming the option that set it

#### Scenario: Root endpoint path
- **WHEN** the consumer sets the key set path to `/`
- **THEN** construction fails with a configuration error

#### Scenario: Dot segments
- **WHEN** the consumer sets a provider endpoint path to `/oauth2/../token`
- **THEN** construction fails with a configuration error

#### Scenario: A character that needs escaping
- **WHEN** the consumer sets the signal stream path to `/session/sig nals`
- **THEN** construction fails with a configuration error

#### Scenario: Trailing slash of a prefix
- **WHEN** the consumer sets the OIDC callback prefix to `/federation/callback/`
- **THEN** the chain is built and the callback for provider `corp` answers at `/federation/callback/corp`

### Requirement: An unusable base path fails at construction
A base path SHALL follow the endpoint path shape, and a single trailing slash SHALL be dropped, so `/auth/` and `/auth` are the same base path. Building a chain SHALL fail with a configuration error naming the base path option when it follows no shape rule, or when the chain answers no built-in endpoint, since the base path would then move nothing.

#### Scenario: Root base path
- **WHEN** the base path is `/`
- **THEN** construction fails with a configuration error naming the base path option

#### Scenario: Relative base path
- **WHEN** the base path is `auth`
- **THEN** construction fails with a configuration error

#### Scenario: Unclean base path
- **WHEN** the base path is `/auth/../admin`
- **THEN** construction fails with a configuration error

#### Scenario: Base path that needs escaping
- **WHEN** the base path is `/auth%20x`
- **THEN** construction fails with a configuration error

#### Scenario: Trailing slash
- **WHEN** the base path is `/auth/`
- **THEN** password sign-in answers at `/auth/sign-in/password`

#### Scenario: Nothing to move
- **WHEN** the base path `/auth` is set on a chain that enables only bearer authentication and authorization
- **THEN** construction fails with a configuration error naming the base path option

### Requirement: A path that repeats the base path fails at construction
Building a chain SHALL fail with a configuration error naming the option and the path that would result when a base path is set and a built-in endpoint path the consumer sets is the base path or lies under it, judged on whole segments, because every such path would answer with the base path repeated.

#### Scenario: Path left absolute
- **WHEN** the base path is `/auth` and the consumer sets the password sign-in path to `/auth/sign-in/password`
- **THEN** construction fails with a configuration error naming the option and `/auth/auth/sign-in/password`

#### Scenario: Shared prefix is not a repeat
- **WHEN** the base path is `/api` and the consumer sets the key set path to `/api-keys`
- **THEN** the key set answers at `/api/api-keys`

### Requirement: The base path covers only the endpoints the chain answers
The base path SHALL NOT change the consumer's authorization rules, routes the consumer gives the chain, the paths any consumer interceptor matches, or pages the consumer serves: the page an emailed sign-in link opens, the recovery cancel page, the provider's login, consent and logout pages, and redirect destinations. The base path SHALL be compared with the request path the chain receives.

#### Scenario: Authorization rules keep the consumer's paths
- **WHEN** a chain has the base path `/auth` and an authorization rule allowing `GET /projects/{id}`
- **THEN** a request to `GET /projects/42` is judged by that rule, and the rule never matches `/auth/projects/42`

#### Scenario: Emailed sign-in link unchanged
- **WHEN** a chain with the base path `/auth` enables magic-link sign-in whose link points at the consumer's confirm page `/sign-in/magic-link/confirm`
- **THEN** the emailed link still points at `/sign-in/magic-link/confirm`
- **AND** the endpoint that redeems the link answers at `/auth/sign-in/magic-link/redeem`

#### Scenario: Provider pages unchanged
- **WHEN** a chain with the base path `/auth` enables the provider with issuer `https://id.example.com/auth` and the login page `https://id.example.com/signin`
- **THEN** an authorization request that needs a sign-in is sent to `https://id.example.com/signin`

#### Scenario: Prefix stripped before the chain
- **WHEN** a proxy strips `/auth` before requests reach a chain that has no base path
- **THEN** a request the proxy received at `/auth/sign-in/password` reaches the chain as `/sign-in/password` and is answered by password sign-in

### Requirement: Values derived from an endpoint path follow it
Everything the chain derives from a built-in endpoint's path SHALL use the path after the base path is applied: the exemptions one endpoint's gate grants another endpoint, the scope of every cookie an endpoint sets, cross-site and cross-origin exemptions, the URLs the provider publishes or redirects to, and which requests record session activity.

#### Scenario: A pending session can still sign out
- **WHEN** a chain with the base path `/auth` enables MFA and logout, and a session owing a second factor posts to `/auth/sign-out`
- **THEN** logout answers it and the session ends

#### Scenario: Flow cookie scoped to the moved callback
- **WHEN** a chain with the base path `/auth` starts an OIDC sign-in
- **THEN** the flow cookie's path is `/auth/sso/callback/`

#### Scenario: Binding cookie scoped to the moved redemption
- **WHEN** a chain with the base path `/auth` answers a magic-link request
- **THEN** the binding cookie's path is `/auth/sign-in/magic-link/redeem`

#### Scenario: Back-channel exemption follows the move
- **WHEN** a chain with the base path `/auth` and cross-site protection receives a cross-site back-channel logout POST at `/auth/sso/backchannel-logout/corp`
- **THEN** it reaches back-channel logout rather than being refused as cross-site

#### Scenario: The moved stream records no activity
- **WHEN** a chain with the base path `/auth` serves a session's GET to `/auth/session/signals`
- **THEN** the session's last activity is unchanged

### Requirement: A consumer route naming a moved endpoint fails at construction
When a base path is set, building a chain SHALL fail with a configuration error naming the route and the endpoint when a route the consumer gives the chain as a path, such as a recovery cool-down route or a cross-site exemption, would match, as that route's own matcher compares paths, a request to a built-in endpoint's path as written before the base path is applied. The consumer SHALL be able to waive this check.

#### Scenario: Cool-down route left behind
- **WHEN** the base path is `/auth`, re-authentication is enabled, and a recovery cool-down route names `POST /reauth/password`
- **THEN** construction fails with a configuration error naming the route and `/auth/reauth/password`

#### Scenario: Route differing only in case
- **WHEN** the base path is `/auth`, re-authentication is enabled, and a recovery cool-down route names `POST /Reauth/Password/`
- **THEN** construction fails with a configuration error naming the route and `/auth/reauth/password`

#### Scenario: Route written with the base
- **WHEN** the same cool-down route names `POST /auth/reauth/password`
- **THEN** the chain is built and the cool-down applies to re-authentication's password path

#### Scenario: Consumer waives the check
- **WHEN** the consumer waives the check and a cross-site exemption names `/sign-in/password`, a route the consumer serves itself
- **THEN** the chain is built

#### Scenario: Waiver without a base path
- **WHEN** the consumer waives the check and sets no base path
- **THEN** construction fails with a configuration error naming the waiver, because without a base path there is no check to waive

### Requirement: The chain lists the endpoints it answers
A built chain SHALL list every operation of every built-in endpoint it answers. Each entry SHALL give its methods, its path with any segment it reads written as `{name}`, how it matches, what it does with other methods, a stable operation identifier, the option that placed it, and what the request must carry. Endpoints not enabled and consumer interceptors SHALL NOT be listed.

#### Scenario: Enabled endpoints listed
- **WHEN** a chain with the base path `/auth` enables form login and MFA with TOTP
- **THEN** the list contains password sign-in at `POST /auth/sign-in/password` with the operation identifier `scrty.sign-in.password`, and second-factor verification at `POST /auth/mfa/verify/{method}`
- **AND** it contains no sign-out, passkey or recovery entry

#### Scenario: Discovery documents listed where they are served
- **WHEN** a chain with the base path `/auth` enables the provider with issuer `https://id.example.com/auth`
- **THEN** the list contains the OpenID configuration at `GET /auth/.well-known/openid-configuration` and the authorization server metadata at `GET /.well-known/oauth-authorization-server/auth`

#### Scenario: One entry per operation
- **WHEN** account recovery is enabled with issued codes
- **THEN** the list holds two entries on the codes path, `GET` with `scrty.recovery.codes.count` and `POST` with `scrty.recovery.codes.regenerate`

#### Scenario: Consumer interceptor not listed
- **WHEN** a consumer registers their own interceptor that answers `/status`
- **THEN** the list contains no entry for `/status`

#### Scenario: The list cannot change the chain
- **WHEN** a caller modifies the list it was given, including an entry's methods
- **THEN** a later request is answered as before, and a fresh list is unchanged

#### Scenario: Operation identifiers are stable
- **WHEN** the same configuration is built with and without a base path
- **THEN** each endpoint carries the same operation identifier in both lists

#### Scenario: An operation is listed once
- **WHEN** a chain enables the key set twice, at `/.well-known/jwks.json` and at `/keys`
- **THEN** construction fails with a configuration error naming `scrty.key-set` and both settings

#### Scenario: Every entry is answered
- **WHEN** a chain enables every built-in endpoint and a request is sent to each listed method and path
- **THEN** each request is answered by the endpoint the entry names and never reaches the handler

### Requirement: Colliding endpoint paths fail at construction
Building a chain SHALL fail with a configuration error when two built-in operations would answer one resolved request path. Operations of one feature that declare a shared path are exempt if their methods differ or one matches the path and the other the path plus one segment. An exact path equal to another operation's prefix, with or without a trailing slash, SHALL collide unless the two declare that they share the path. The error SHALL name both settings, both paths and what would break.

#### Scenario: Two features on one path
- **WHEN** password sign-in and magic-link requests are both set to answer `/signin`
- **THEN** construction fails with a configuration error naming both options and `/signin`

#### Scenario: Path under another endpoint's prefix
- **WHEN** the re-authentication prefix is set so that its paths lie under the MFA verify prefix
- **THEN** construction fails with a configuration error naming both options

#### Scenario: Within one feature
- **WHEN** the MFA challenge and verify prefixes are both set to `/mfa/step`
- **THEN** construction fails with a configuration error naming both settings

#### Scenario: A built-in endpoint and a provider endpoint
- **WHEN** the password sign-in path is set to `/oauth2/token` on a chain that enables the provider
- **THEN** construction fails with a configuration error naming form login and the provider

#### Scenario: Declared sharing
- **WHEN** account recovery is enabled with issued codes, whose count and regeneration answer GET and POST on one path
- **THEN** the chain is built

#### Scenario: Default session management builds
- **WHEN** session management is enabled with defaults, answering DELETE on `/sessions` and on `/sessions/{handle}`
- **THEN** the chain is built

#### Scenario: Default consents build
- **WHEN** the provider is enabled with defaults, answering GET on `/oauth2/consents` and DELETE on `/oauth2/consents/{client}`
- **THEN** the chain is built

#### Scenario: Undeclared sharing
- **WHEN** the provider's end-session confirmation and consents paths are both set to `/oauth2/me`
- **THEN** construction fails with a configuration error, although the two answer different methods

#### Scenario: The error says what would break
- **WHEN** the logout path is set under the MFA verify prefix
- **THEN** construction fails with a configuration error saying that a session owing a second factor could not sign out

#### Scenario: Collisions judged after the base path
- **WHEN** the base path is `/auth`, the provider is enabled with issuer `https://id.example.com/auth`, and the consumer sets the key set path to `/.well-known/openid-configuration`
- **THEN** construction fails, because the key set would answer `/auth/.well-known/openid-configuration`, where the issuer places the OpenID configuration

### Requirement: Under a base path the provider's issuer must cover it
When a base path is set and the provider is enabled, building a chain SHALL fail with a configuration error naming the issuer and the base path unless the OpenID configuration would be served at or under the base path and every URL the provider publishes names a path it serves: the issuer's path is the base path or lies under it, and every provider path and the key set lie under the issuer's path. The consumer SHALL be able to waive this check.

#### Scenario: Issuer without the base path
- **WHEN** the base path is `/auth` and the provider's issuer is `https://id.example.com`
- **THEN** construction fails with a configuration error naming the issuer and `/auth`

#### Scenario: Issuer at the base path
- **WHEN** the base path is `/auth` and the issuer is `https://id.example.com/auth`
- **THEN** the chain is built and the OpenID configuration answers at `/auth/.well-known/openid-configuration`

#### Scenario: Issuer with a trailing slash
- **WHEN** the base path is `/auth` and the issuer is `https://id.example.com/auth/`
- **THEN** the chain is built

#### Scenario: Issuer deeper than the endpoints
- **WHEN** the base path is `/auth`, the issuer is `https://id.example.com/auth/op` and the provider keeps its default paths
- **THEN** construction fails, because the token endpoint at `/auth/oauth2/token` is not under the issuer's path

#### Scenario: An endpoint override outside the issuer's path
- **WHEN** the base path is `/auth`, the issuer is `https://id.example.com/auth/op`, the provider prefix is `/op/oauth2` and the key set path is `/op/keys`, and the authorization endpoint path is set to `/login`
- **THEN** construction fails, because `/auth/login` is not under the issuer's path

#### Scenario: Consumer waives the check
- **WHEN** the consumer waives the check, the base path is `/auth` and the issuer is `https://id.example.com`
- **THEN** the chain is built, the OpenID configuration answers at `/.well-known/openid-configuration`, and the metadata's `token_endpoint` is `https://id.example.com/auth/oauth2/token`

#### Scenario: Waiver without a base path
- **WHEN** the consumer waives the check, enables the provider and sets no base path
- **THEN** construction fails with a configuration error naming the waiver, because without a base path there is no check to waive

### Requirement: The provider's issuer path uses only endpoint-path characters
When the provider is enabled, building a chain SHALL fail with a configuration error naming the issuer unless every character of the issuer's path is one an endpoint path may use: letters, digits, `.`, `_`, `~`, `-` and `/`. A percent-escape SHALL be refused, whether or not it encodes one of those characters, and whether or not a base path is set, so the path the issuer checks read and the path discovery is served on are always the same string.

#### Scenario: Percent-encoded issuer path
- **WHEN** the base path is `/auth` and the provider's issuer is `https://id.example.com/au%74h`
- **THEN** construction fails with a configuration error naming the issuer

#### Scenario: Percent-encoded issuer path without a base path
- **WHEN** no base path is set and the provider's issuer is `https://id.example.com/t%65nant`
- **THEN** construction fails with a configuration error naming the issuer

#### Scenario: Plain issuer path
- **WHEN** no base path is set, the provider's issuer is `https://id.example.com/tenant-1` and its prefix is `/tenant-1/oauth2`
- **THEN** the chain is built and the OpenID configuration answers at `/tenant-1/.well-known/openid-configuration`

## MODIFIED Requirements

### Requirement: Form login authenticates, applies policy and opens a session
When enabled, form login SHALL answer POST requests on its login path, by default `/sign-in/password`. Every other request SHALL pass through untouched. It SHALL:
1. read the username and password from form fields, `username` and `password` by default, or from a JSON object when the form yields neither and the request declares a JSON content type;
2. check the request's source against the password-login guard, and refuse a throttled or unattributable source;
3. evaluate the pre-authentication policy phase before checking credentials, and refuse on a deny;
4. authenticate, recording a failed attempt on an authentication failure and clearing attempts on success, where a failure of that bookkeeping is logged and does not change the outcome;
5. evaluate the post-authentication policy phase, and refuse on a deny;
6. build a session recording the password first factor;
7. when the post-authentication phase challenged, mark the challenge pending on that session;
8. issue an access token for the session;
9. store the session, with any pending challenge, in one write, and only then hand out the token.

A failure to issue the token SHALL store no session, and SHALL fail the request as a dependency failure, not as a refusal. A challenge SHALL refuse with a challenge error carrying the kind, the pending session and the token. A success SHALL write the success response and SHALL NOT call the handler. By default the success response is a JSON document carrying the access token, an empty refresh token field and the session's idle expiry. The consumer SHALL be able to replace the success response writer, the login path and the field names.

#### Scenario: Successful login
- **WHEN** a user with no pending challenge posts correct credentials to the login path
- **THEN** a session is created, the response is a JSON document carrying an access token and the session's idle expiry, and the handler is not called

#### Scenario: Wrong password
- **WHEN** a user posts an incorrect password
- **THEN** the request is refused with the authentication failure error and a failed attempt is recorded

#### Scenario: Locked account is not probed
- **WHEN** the pre-authentication phase denies a locked account
- **THEN** the request is refused, its error identifiable as both the authentication failure and the account-locked refusal, and the account's password is never checked

#### Scenario: Login raises a challenge
- **WHEN** the post-authentication phase challenges for a second factor
- **THEN** the session is stored as pending before the token is handed out, and the request is refused with a challenge error carrying the second-factor kind, the session and the token

#### Scenario: Token cannot be issued
- **WHEN** a user posts correct credentials and the key source fails when the token is issued
- **THEN** the request fails with an error that matches neither the authentication failure error nor the authentication-required error
- **AND** no session is stored

#### Scenario: Consumer success response and field names
- **WHEN** the consumer sets the field names to `email` and `secret` and supplies their own success response writer
- **THEN** a login posting `email` and `secret` succeeds and writes the consumer's response

#### Scenario: Other methods pass through
- **WHEN** a GET request arrives on the login path
- **THEN** form login does not handle it and the request continues

### Requirement: Logout ends the session
When enabled, logout SHALL answer POST requests on its path, by default `/sign-out`. It SHALL refuse a request with no authentication result with the authentication-required error. When the request carries a session, logout SHALL delete it, and a session that is already gone SHALL NOT be an error. A stateless authenticated request SHALL be answered without deleting anything. Logout SHALL NOT call the handler. The consumer SHALL be able to change the path.

Logout SHALL accept an optional end-session step. When one is configured and the deleted session records an identity provider, logout SHALL call it after the delete, with the deleted session and the request's optional `state` form value. When the step returns a URL, logout SHALL answer 200 with a JSON body carrying it as `end_session_url` and with `Cache-Control: no-store`. Otherwise logout SHALL answer 200 with an empty body. A failure of the step SHALL be logged and SHALL NOT fail the logout, because the session has already been deleted. With no step configured, logout SHALL behave exactly as it does without federated login.

#### Scenario: Logout
- **WHEN** an authenticated request posts to the logout path
- **THEN** its session is deleted, the response is 200 with an empty body, and a later request with the same token is refused

#### Scenario: Session already deleted
- **WHEN** two logout requests for the same session race and the second finds the session gone
- **THEN** the second is also answered 200

#### Scenario: Anonymous logout
- **WHEN** a request with no authentication posts to the logout path
- **THEN** it is refused with the authentication-required error

#### Scenario: Consumer path
- **WHEN** the consumer sets the logout path to `/session/end`
- **THEN** logout answers there and a POST to `/sign-out` passes through

#### Scenario: Federated session with an end-session step
- **WHEN** an end-session step is configured and a session that records provider `corp` is logged out, and the step returns `https://idp.example/logout?id_token_hint=...`
- **THEN** the session is deleted before the step is called
- **AND** the response is 200 with `end_session_url` equal to that URL and `Cache-Control: no-store`

#### Scenario: Password session with an end-session step
- **WHEN** an end-session step is configured and a session established by a password is logged out
- **THEN** the step is not called and the response is 200 with an empty body

#### Scenario: End-session step fails
- **WHEN** an end-session step is configured and returns an error for a federated session
- **THEN** the session is deleted, the error is logged, and the response is 200 with an empty body

### Requirement: A recovery-pending session reaches only the binding endpoints and logout
When recovery is enabled, a request whose session is in the recovery-pending state SHALL be refused with a challenge error of the account-recovery kind carrying that session. The refusal SHALL come before the password-change gate, the enrolment gate, the MFA challenge gate and any interceptor after them run, whatever the request's method or path. These requests are exempt:
- a POST under an MFA enrolment prefix, when the enrolment path is enabled;
- a POST to the passkey registration begin, finish, saved-code confirm and emailed-code confirm paths, when passkey registration is enabled and the passkey MFA method is on the MFA slot, so a registered passkey can resolve the challenge the binding raises;
- a POST to the password-change resolve endpoint, when one is registered;
- the logout endpoint, wherever it is placed in the chain relative to the gate.

There SHALL be no option that lets further routes through. A capability that adds another way to bind an authenticator SHALL add its endpoint to this list in its own change. A recovery-pending session SHALL always be able to log out, and logging out SHALL end it.

The per-request policy phase SHALL still be evaluated for a recovery-pending session, and a deny SHALL refuse the request. A challenge it raises SHALL NOT be marked on the session: marking one would take the session out of the recovery-pending state without a binding.

#### Scenario: Protected route
- **WHEN** a recovery-pending session requests `/invoices`
- **THEN** it is refused with an account-recovery challenge error carrying the session, and the handler does not run

#### Scenario: Enrolment reachable
- **WHEN** the enrolment path is enabled and a recovery-pending session posts to `/mfa/enrol/begin/totp`
- **THEN** a pending enrolment is begun

#### Scenario: Passkey registration reachable
- **WHEN** passkey registration is enabled and a recovery-pending session posts to `/passkeys/register/begin`
- **THEN** a registration challenge is issued

#### Scenario: Passkey registration without the passkey method
- **WHEN** passkey registration is enabled, the passkey MFA method is not on the MFA slot, and a recovery-pending session posts to `/passkeys/register/begin`
- **THEN** it is refused with an account-recovery challenge error, and no registration challenge is issued

#### Scenario: Passkey listing not reachable
- **WHEN** a recovery-pending session sends a GET to `/passkeys`
- **THEN** it is refused with an account-recovery challenge error

#### Scenario: Verify path is not reachable
- **WHEN** a recovery-pending session posts a code to `/mfa/verify/totp`
- **THEN** it is refused with an account-recovery challenge error and no code is verified

#### Scenario: Password change reachable
- **WHEN** the consumer registered `POST /account/password` as the resolve endpoint and a recovery-pending session posts there
- **THEN** the consumer's function runs

#### Scenario: Logout
- **WHEN** a recovery-pending session posts to the logout endpoint
- **THEN** the session is deleted, and its handle no longer loads

#### Scenario: Per-request challenge not marked
- **WHEN** a recovery-pending session of a user required to use MFA, whose enrolments were removed by the recovery, requests `/invoices`
- **THEN** the request is refused with an account-recovery challenge error
- **AND** the session is still in the recovery-pending state

### Requirement: Passkey endpoints plug into the chain
Enabling passkeys on the chain SHALL register the endpoints the `passkey-authentication` capability defines. The registration, saved-code confirm, emailed-code confirm, listing, rename and remove endpoints SHALL run after bearer authentication. The recovery gate, the enrolment gate and the MFA challenge gate SHALL decide, as their own requirements state, which sessions reach them. The passwordless begin and finish endpoints, when enabled, SHALL run as a first factor at a named slot of their own, after the one-time link slot and before Basic authentication. They SHALL complete the login through the login completion step, and their begin SHALL be guarded by the chain's source throttle step under the flow `passkey-login`. Flushing the chain's refusal logs SHALL flush the passkey samplers too. The passkey MFA method SHALL be served by the MFA slot like any other challenge method, with no endpoint of its own.

#### Scenario: Passwordless login reaches login completion
- **WHEN** a passwordless finish authenticates `u-1` and the policy requires a password change
- **THEN** the request is refused with a password-change challenge error carrying a pending session, exactly as form login would refuse it

#### Scenario: Unattributable source at passwordless begin
- **WHEN** a passwordless begin is posted from client address `0.0.0.0`
- **THEN** it is refused with the authentication failure error and no challenge is issued

#### Scenario: Registration needs bearer
- **WHEN** a request without a bearer credential posts to `/passkeys/register/begin`
- **THEN** it is refused as authentication required

### Requirement: The public key set is served
When enabled, the chain SHALL answer GET requests on the key set path, by default `/.well-known/jwks.json`, under the base path when one is set. It SHALL respond 200 with a JSON content type and the current public verification keys as a JSON Web Key Set, and SHALL NOT call the handler. The response SHALL never contain private key material. The key set SHALL be obtained with the request's context. A failure to obtain the key set SHALL propagate as a dependency failure, with fixed library text that keeps the cause reachable. The consumer SHALL be able to change the path.

#### Scenario: Key set served
- **WHEN** a client requests the key set path
- **THEN** the response is 200 with a JSON Web Key Set of the current public keys and no private members

#### Scenario: The key set is obtained with the request's context
- **WHEN** a client requests the key set path under a request context carrying a value
- **THEN** the key set provider is asked with a context carrying that value

#### Scenario: Key set outage
- **WHEN** a client requests the key set path and the key set cannot be obtained
- **THEN** the request fails with an error from which the cause is reachable, which the default status mapping answers with 500

#### Scenario: Consumer path
- **WHEN** the consumer sets the path to `/keys`
- **THEN** the key set is served at `/keys` and `/.well-known/jwks.json` passes through

#### Scenario: Under a base path
- **WHEN** the base path is `/auth` and the provider is enabled with issuer `https://id.example.com/auth`
- **THEN** the key set is served at `/auth/.well-known/jwks.json` and the metadata's `jwks_uri` is `https://id.example.com/auth/.well-known/jwks.json`

### Requirement: An opt-in endpoint lists the methods a pending session can use
The chain SHALL offer an endpoint that lists the MFA methods the session's user can use. It SHALL be off by default, and SHALL exist only when the consumer enables it on the MFA slot. It SHALL answer GET requests to its path, `/mfa/methods` by default, and SHALL NOT read the URL query. It SHALL answer only a session whose MFA challenge is pending:
- a request with no session SHALL be refused as authentication required;
- a session that owes no MFA challenge, including a fully authenticated one, SHALL be refused as no MFA challenge pending;
- an enrolment-only session SHALL be refused by the enrolment gate like any other route.

The list SHALL come from the one function the security policies use to decide usability, so it can never disagree with the MFA challenge or the policies. A failed lookup SHALL be a refusal, never an empty list. By default the endpoint SHALL answer with a documented JSON body naming each method's name, channel and whether it has a begin step; a consumer SHALL be able to replace the response through a responder. The endpoint's path and responder SHALL be settable only inside the option that enables it, and an explicitly given empty path or absent responder SHALL be refused rather than read as the default. Chain assembly SHALL fail with a configuration error when the endpoint's path collides with another endpoint the chain answers, as the chain-wide collision requirement judges.

#### Scenario: Off by default
- **WHEN** the MFA slot is enabled without the listing option and a pending session sends GET `/mfa/methods`
- **THEN** no listing is produced by the library

#### Scenario: Pending session lists its methods
- **WHEN** the listing is enabled, TOTP and `email-code` are configured, `u-1` is enrolled on TOTP only, and `u-1`'s pending session sends GET `/mfa/methods`
- **THEN** the response is the default JSON body listing `totp` only

#### Scenario: A full session is refused
- **WHEN** the listing is enabled and a session whose second factor is satisfied sends GET `/mfa/methods`
- **THEN** it is refused as no MFA challenge pending

#### Scenario: No session
- **WHEN** the listing is enabled and a request without a session sends GET `/mfa/methods`
- **THEN** it is refused as authentication required

#### Scenario: Lookup failure
- **WHEN** the listing is enabled and a method's enrolment lookup fails for a pending session
- **THEN** the request is refused with that failure and no list is written

#### Scenario: Consumer path and responder
- **WHEN** the listing is enabled with path `/account/mfa/methods` and a responder that writes its own document, and a pending session sends GET there
- **THEN** the consumer's responder writes the response with the same list

#### Scenario: Explicit empty path
- **WHEN** the listing is enabled with an explicitly empty path
- **THEN** construction fails with a configuration error

#### Scenario: Path collides with a verify path
- **WHEN** the listing path is set to the MFA verify prefix `/mfa/verify`
- **THEN** chain assembly fails with a configuration error naming the listing and the MFA verify prefix

#### Scenario: Listing beside the verify endpoints
- **WHEN** the listing path is set to `/mfa/verify/totp`, under the MFA verify prefix
- **THEN** the chain is built: the listing answers GET there and verification answers POST, so no request reaches both

### Requirement: The provider's paths are replaceable and published as used
The provider SHALL answer the two metadata documents at the paths their standards derive from the issuer, which a base path does not change. The consumer SHALL be able to change the prefix and each endpoint path; both SHALL be relative to the chain's base path when one is set. Endpoint URLs in the metadata, `jwks_uri` included, SHALL follow the paths in use.

#### Scenario: Default paths
- **WHEN** the provider is enabled with defaults and issuer `https://id.example.com`
- **THEN** the metadata's `token_endpoint` is `https://id.example.com/oauth2/token`, and a POST there reaches the token endpoint

#### Scenario: Consumer prefix
- **WHEN** the consumer sets the prefix to `/op`
- **THEN** the token endpoint answers at `/op/token`, the metadata names it, and a POST to `/oauth2/token` passes through

#### Scenario: Under a base path
- **WHEN** the base path is `/auth` and the provider is enabled with issuer `https://id.example.com/auth`
- **THEN** the token endpoint answers at `/auth/oauth2/token`, the metadata's `token_endpoint` is `https://id.example.com/auth/oauth2/token`, and the OpenID configuration answers at `/auth/.well-known/openid-configuration`

#### Scenario: Endpoint path within the base
- **WHEN** the base path is `/auth`, the issuer is `https://id.example.com/auth`, and the consumer sets the token endpoint path to `/tokens`
- **THEN** the token endpoint answers at `/auth/tokens` and the metadata names that path

### Requirement: Provider wiring mistakes fail at construction
Building a chain with the provider SHALL fail with a configuration error naming the provider when:
- neither bearer mode is enabled, because the resume needs a sign-in credential;
- the JWKS endpoint is not enabled;
- the provider is enabled more than once;
- a session manager the chain is wired with does not report sign-in ends to the provider (`sessions`), because grants would then outlive a logout;
- one of its paths collides with another of its paths or with another endpoint of the chain, as the chain-wide collision requirement judges;
- a base path is set and the issuer does not cover it, as the issuer requirement states, unless the consumer waived that check.

#### Scenario: No bearer mode
- **WHEN** the provider is enabled on a chain with form login and no bearer mode
- **THEN** construction fails with a configuration error naming the provider

#### Scenario: Session manager not reporting to the provider
- **WHEN** the provider is enabled on a chain whose session manager was built without the provider as an end observer
- **THEN** construction fails with a configuration error naming the provider

#### Scenario: Path collision
- **WHEN** the consumer sets the provider's end-session path to the chain's sign-out path
- **THEN** construction fails with a configuration error naming the provider and logout

#### Scenario: Issuer outside the base path
- **WHEN** the base path is `/auth` and the issuer is `https://id.example.com`
- **THEN** construction fails with a configuration error naming the provider
