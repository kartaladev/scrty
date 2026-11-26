# Spec Delta

## Purpose

Lets a browser stay signed in through an `HttpOnly` session cookie, so that no credential is ever
readable by JavaScript, with the same session rules as every other sign-in.

## ADDED Requirements

### Requirement: The cookie session is off until enabled
A chain SHALL authenticate requests by a session cookie only when the consumer enables the cookie session. Without it, the chain SHALL neither read nor set the session cookie, and every existing behaviour SHALL stay as it is.

#### Scenario: Not enabled
- **WHEN** a chain is built without the cookie session and a request carries a cookie named `__Host-scrty-session`
- **THEN** the cookie is ignored, and the request is judged exactly as before

#### Scenario: Enabled
- **WHEN** a chain is built with the cookie session and a valid session cookie
- **THEN** the request is authenticated as that session's user

### Requirement: A session cookie is judged by the same rules as a session reference
A request carrying the session cookie SHALL be judged exactly as a session reference presented in the `Authorization` header is judged: the shape check before any lookup, the load by digest, the refusal of a missing or expired session, reuse detection, the user reload, the per-request policy, the throttling of refused references, and the split between a refusal and a dependency failure.

#### Scenario: Unknown cookie value
- **WHEN** a request carries a well-formed session cookie that names no session
- **THEN** it is refused with the authentication-required error, and the refusal counts against the request's source

#### Scenario: Malformed cookie value
- **WHEN** a request carries a session cookie that is not a well-formed session identifier
- **THEN** it is refused with the authentication-required error before any store lookup

#### Scenario: Two session cookies
- **WHEN** a request carries two cookies with the session cookie's name
- **THEN** it is refused with the authentication-required error before any store lookup

#### Scenario: Superseded identifier after its window
- **WHEN** a request presents, in the cookie, an identifier superseded by a rotation whose grace window has ended
- **THEN** it is refused with an error identifiable as both the authentication-required error and the reused-session error, and the session's family is revoked

#### Scenario: Disabled user
- **WHEN** a request carries the cookie of a session whose user has since been disabled
- **THEN** it is refused with the authentication-required error

#### Scenario: Session store outage
- **WHEN** the session store fails while a request's cookie is loaded
- **THEN** the request fails as a dependency failure, not as a refusal

### Requirement: The cookie session requires CSRF protection
Building a chain with the cookie session SHALL fail with a configuration error when CSRF protection is not enabled and the consumer has not opted out of it explicitly. An unsafe request authenticated by the cookie SHALL carry the sign-in's CSRF token.

#### Scenario: No CSRF protection
- **WHEN** a chain enables the cookie session without CSRF protection and without the explicit opt-out
- **THEN** construction fails with a configuration error

#### Scenario: Unsafe request without a token
- **WHEN** a same-origin POST is authenticated by the session cookie and carries no CSRF token
- **THEN** it is refused as a cross-site request

### Requirement: A cookie chain hands out no credential in a response body
A chain with the cookie session SHALL deliver every credential it issues as the session cookie, and SHALL NOT write a credential to a response body or header other than `Set-Cookie`. This SHALL hold for form login, magic link, federated sign-in, passwordless passkey login, second-factor verification, re-authentication, recovery completion and session renewal.

#### Scenario: Form login
- **WHEN** a user signs in with a password on a cookie chain
- **THEN** the response sets the session cookie, and its body carries no session identifier or token

#### Scenario: Second-factor verification
- **WHEN** a challenged user verifies a second factor on a cookie chain
- **THEN** the response sets the cookie to the rotated session's identifier, and its body carries no credential

#### Scenario: Challenge raised at login
- **WHEN** a password login on a cookie chain is challenged for a second factor
- **THEN** the response sets the cookie of the pending session, and the challenge refusal carries no credential

### Requirement: A chain delivers either cookies or tokens
Building a chain SHALL fail with a configuration error when it enables the cookie session together with the session-reference bearer or the signed-token bearer.

#### Scenario: Cookie and session bearer together
- **WHEN** a chain enables the cookie session and the session-reference bearer
- **THEN** construction fails with a configuration error naming both

#### Scenario: Two chains for two audiences
- **WHEN** a consumer builds a cookie chain at the default paths and a signed-token chain under the base path `/api`
- **THEN** both chains build, browsers receive cookies from the first, and native clients receive tokens from the second

### Requirement: A credential delivery port cannot hand a token to a cookie request
The consumer SHALL be able to replace how a cookie chain delivers a new session's credential. A replacement that returns a credential for a request the cookie authenticated SHALL be refused with an issuing failure, and nothing SHALL be written to the response.

#### Scenario: Consumer delivery
- **WHEN** the consumer replaces delivery with one that sets the cookie and also records an audit entry
- **THEN** sign-ins set the cookie, and the consumer's audit entry is recorded

#### Scenario: Delivery that leaks a token
- **WHEN** the consumer's delivery returns a credential for a renewal the cookie authenticated
- **THEN** the renewal fails as an issuing failure, and the response carries no credential

### Requirement: A request carrying both the cookie and an Authorization header is refused
On a cookie chain, a request that carries the session cookie and an `Authorization` header SHALL be refused with the authentication-required error before either credential is loaded. A request that carries the session cookie after another authenticator has already established its caller SHALL be refused the same way, before the cookie is read. The OpenID Provider's own endpoints that authenticate by their own credential are exempt.

#### Scenario: Both credentials
- **WHEN** a request carries a valid session cookie and `Authorization: Bearer` with any value
- **THEN** it is refused with the authentication-required error, and no session is loaded

#### Scenario: Header only
- **WHEN** a request on a cookie chain carries only an `Authorization` header that a resource server covering its path accepts
- **THEN** the resource server judges it as before

#### Scenario: Cookie beside a consumer credential
- **WHEN** a consumer authenticator ordered before the cookie session establishes a caller from its own header, and the request also carries a session cookie
- **THEN** it is refused with the authentication-required error, and the cookie is not read

#### Scenario: Provider endpoint
- **WHEN** a chain runs the OpenID Provider and the cookie session, and a request to the provider's userinfo endpoint carries an access token and the session cookie
- **THEN** the provider judges the access token, and the guard does not refuse it

### Requirement: A browser sign-in answers by what the request prefers
On a cookie chain, the default answer of every issuing endpoint SHALL be a `303 See Other` to the resolved destination for a form post or a request that prefers HTML, and a `200` JSON document carrying the session's idle expiry and no credential for a JSON request. Each endpoint's responder SHALL stay replaceable.

#### Scenario: HTML form post
- **WHEN** a browser posts the sign-in form with `next=/orders`
- **THEN** the response is `303` to `/orders` and sets the session cookie

#### Scenario: JSON request
- **WHEN** a script posts the sign-in as JSON
- **THEN** the response is `200` with a JSON body holding the idle expiry and no credential, and it sets the session cookie

#### Scenario: Consumer responder
- **WHEN** the consumer replaces the login responder with one that answers `204`
- **THEN** a successful sign-in sets the cookie and answers `204`

### Requirement: A sign-in destination stays on the same origin unless allowlisted
The destination of a browser sign-in SHALL be the requested `next` only when it is a relative path beginning with a single `/`, or a target the consumer allowlisted exactly. Any other value, a missing one included, SHALL resolve to `/`.

#### Scenario: Off-site destination
- **WHEN** a browser signs in with `next=https://evil.example/` or `next=//evil.example/`
- **THEN** the response is `303` to `/`

#### Scenario: Allowlisted absolute destination
- **WHEN** the consumer allowlists `https://app.example.com/home` and a browser signs in with that `next`
- **THEN** the response is `303` to `https://app.example.com/home`

### Requirement: Federated sign-in completes in the callback on a cookie chain
On a cookie chain, a successful federated callback SHALL create the session in its creating write with the federated first factor and the asserted federated fields, set the session cookie, and redirect to the allowlisted destination. No handoff code SHALL be issued, and a handoff manager given alongside SHALL fail construction.

#### Scenario: Callback
- **WHEN** a user returns from provider `corp` with a valid authorization response on a cookie chain
- **THEN** the response sets the session cookie and redirects to the allowlisted destination, and no handoff code appears in the URL

#### Scenario: Consumer callback success
- **WHEN** the consumer supplies its own callback success on a cookie chain
- **THEN** the consumer's function writes the response, as it does on any chain

### Requirement: The session cookie has safe attributes by default
The session cookie SHALL be named `__Host-scrty-session` and SHALL be set with `Path=/`, `Secure`, `HttpOnly` and `SameSite=Lax`, with no `Domain` and no `Max-Age` or `Expires`, unless the consumer overrides them within the limits the next requirement states.

#### Scenario: Default cookie
- **WHEN** a user signs in on a cookie chain with default options
- **THEN** the response sets `__Host-scrty-session=<id>; Path=/; Secure; HttpOnly; SameSite=Lax`, with no `Domain`, `Max-Age` or `Expires`

#### Scenario: Strict same-site
- **WHEN** the consumer sets the same-site mode to strict
- **THEN** the cookie is set with `SameSite=Strict`

### Requirement: Cookie overrides that break a guarantee fail at construction
Building a cookie chain SHALL fail with a configuration error when the cookie name is empty or not a valid cookie name, when a `__Host-` name is given a `Domain`, when a `Domain` is given with a name that lacks the `__Secure-` prefix, or when the same-site mode is `None`. `HttpOnly` and `Secure` SHALL have no override.

#### Scenario: Domain with a __Host- name
- **WHEN** the consumer keeps the default name and sets the domain `example.com`
- **THEN** construction fails with a configuration error

#### Scenario: Shared domain with a __Secure- name
- **WHEN** the consumer names the cookie `__Secure-scrty-session` and sets the domain `example.com`
- **THEN** the chain builds, and the cookie is set with `Domain=example.com`

#### Scenario: Same-site None
- **WHEN** the consumer sets the same-site mode to none
- **THEN** construction fails with a configuration error

### Requirement: A sign-in can choose a persistent cookie
The consumer SHALL be able to decide, at each sign-in, that its cookie persists. A persistent cookie SHALL carry a `Max-Age` equal to the seconds left until the session's absolute deadline, rounded up and at least one. The choice SHALL follow the sign-in through every rotation. By default no cookie persists.

#### Scenario: Remember me
- **WHEN** the consumer's decision returns true for a sign-in whose session ends absolutely in 12 hours
- **THEN** the cookie is set with `Max-Age=43200`

#### Scenario: Persistence survives rotation
- **WHEN** a sign-in that chose a persistent cookie verifies a second factor
- **THEN** the rotated session's cookie is set with a `Max-Age` following its absolute deadline

#### Scenario: Default
- **WHEN** no persistence decision is configured
- **THEN** every session cookie is set without `Max-Age` or `Expires`

### Requirement: The server's deadlines stay authoritative over the cookie
A session cookie SHALL authenticate only a session that is live by the server's idle and absolute deadlines, whatever the cookie's own lifetime.

#### Scenario: Persistent cookie after the idle deadline
- **WHEN** a persistent cookie is presented after its session's idle deadline has passed
- **THEN** the request is refused with the authentication-required error, and the cookie is expired

### Requirement: Privilege changes rotate the cookie session
On a cookie chain, the session identifier SHALL change, and the cookie SHALL be re-set, when a second factor is verified, when the user re-authenticates, when the active role is switched, and when the password is changed. The previous identifier SHALL stay valid only for the in-flight window or grace window of that rotation. The sign-in's CSRF token SHALL stay valid across these rotations.

#### Scenario: Role switch
- **WHEN** `ada` switches her active role to `audit` on a cookie chain
- **THEN** the response re-sets the cookie with a new identifier, and her CSRF token is still accepted

#### Scenario: Password change
- **WHEN** a user changes their password at the resolve endpoint on a cookie chain
- **THEN** the response re-sets the cookie with a new identifier

#### Scenario: Old identifier presented late
- **WHEN** the identifier replaced at the role switch is presented after its window has ended
- **THEN** it is refused as reuse, and the sign-in's family is revoked

#### Scenario: Logout during a role switch
- **WHEN** a logout ends the sign-in while a role switch on it is in progress, before the switch's rotation is stored
- **THEN** the switch fails with the authentication-required error, its response does not re-set the cookie, and no session of the sign-in is stored

### Requirement: The added rotations can be turned off by name, and the existing ones cannot
The consumer SHALL be able to turn off the rotation at the active-role switch, at the password change, or both, each named explicitly. The rotations at sign-in, second-factor verification and re-authentication SHALL have no off switch.

#### Scenario: Role-switch rotation off
- **WHEN** the consumer turns off rotation at the role switch, and `ada` switches her role
- **THEN** her session keeps its identifier, and the cookie is not re-set

#### Scenario: No switch for second-factor rotation
- **WHEN** the consumer tries to turn off rotation at second-factor verification
- **THEN** no such option exists, and verification still rotates the identifier

### Requirement: Logout expires the cookie
A successful logout on a cookie chain SHALL expire the session cookie with the same name, path, domain and security attributes it was set with.

#### Scenario: Logout
- **WHEN** a signed-in user logs out on a cookie chain
- **THEN** the response sets `__Host-scrty-session=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax`

#### Scenario: Logout fails on a provider store outage
- **WHEN** the provider's store fails while a logout on a cookie chain ends the sign-in's grants
- **THEN** the logout fails as a dependency failure, the session stays, and the cookie is not expired

### Requirement: A refused cookie is expired, an unreadable store keeps it
When the session cookie is refused because its session is missing, expired, unreadable or reused, the response SHALL expire the cookie. When the session cannot be loaded because a store failed, or the request is refused before its session is judged (its source is over its allowance, the source limiter cannot answer, or an unsafe request fails CSRF protection), the response SHALL leave the cookie in place.

#### Scenario: Expired session
- **WHEN** a request carries the cookie of an expired session
- **THEN** it is refused with the authentication-required error, and the response expires the cookie

#### Scenario: Store outage
- **WHEN** the session store fails while a request's cookie is loaded
- **THEN** the request fails as a dependency failure, and the response does not touch the cookie

#### Scenario: Source over its allowance
- **WHEN** a request carries a valid session cookie from a source that is over its allowance of refused references
- **THEN** it is refused with the authentication-required error, and the response does not touch the cookie

#### Scenario: Cross-site request
- **WHEN** an unsafe request carries a valid session cookie and no valid CSRF token
- **THEN** it is refused as a cross-site request, the response does not touch the cookie, and nothing is counted against the source

### Requirement: The OpenID Provider resumes a cookie sign-in
A chain SHALL be able to run the OpenID Provider with the cookie session. On such a chain, the provider's resume endpoint SHALL take as its sign-in the session the cookie session authenticated, under the same checks a sign-in presented in the `Authorization` header passes, and SHALL NOT take a session that another authenticator published.

#### Scenario: Resume with the cookie
- **WHEN** a user signed in on a cookie chain that runs the provider posts the resume of a pending authorization request with the session cookie and the sign-in's CSRF token
- **THEN** the authorization request resumes with that sign-in

#### Scenario: Resume with the cookie and an Authorization header
- **WHEN** the same resume also carries an `Authorization` header
- **THEN** it is refused with the authentication-required error, and no session is loaded

### Requirement: Ending a cookie sign-in ends the provider's browser sessions of it
When the chain also runs the OpenID Provider, every explicit end of a cookie sign-in, by logout, by reuse detection or by revocation, SHALL end the provider's browser sessions of that sign-in, so that neither layer stays signed in after the other has ended.

#### Scenario: Logout
- **WHEN** a user who signed in on a cookie chain that also runs the provider logs out
- **THEN** no provider browser session of that sign-in loads afterwards

#### Scenario: Reuse detected through the cookie
- **WHEN** a superseded identifier is presented in the cookie after its window
- **THEN** the family is revoked, and no provider browser session of that sign-in loads afterwards
