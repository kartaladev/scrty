## MODIFIED Requirements

### Requirement: A session cookie is judged by the same rules as a session reference
A request carrying the session cookie SHALL be judged exactly as a session reference presented in the `Authorization` header is judged: the shape check before any lookup, the load by digest, the refusal of a missing or expired session, reuse detection, the user reload, the per-request policy, the throttling of refused references, and the split between a refusal and a dependency failure. A cookie SHALL be read as the session cookie only when its name equals the configured name after trimming space and tab alone.

#### Scenario: Unknown cookie value
- **WHEN** a request carries a well-formed session cookie that names no session
- **THEN** it is refused with the authentication-required error, and the refusal counts against the request's source

#### Scenario: Malformed cookie value
- **WHEN** a request carries a session cookie that is not a well-formed session identifier
- **THEN** it is refused with the authentication-required error before any store lookup

#### Scenario: Two session cookies
- **WHEN** a request carries two cookies with the session cookie's name
- **THEN** it is refused with the authentication-required error before any store lookup

#### Scenario: Name padded with Unicode whitespace
- **WHEN** a request carries a cookie named `__Host-scrty-session` preceded by U+2000, and no other session cookie
- **THEN** it is judged as carrying no session cookie, and no session is loaded

#### Scenario: Padded twin beside the real cookie
- **WHEN** a request carries the real session cookie and a cookie of the same name preceded by U+00A0
- **THEN** the real cookie authenticates the request

#### Scenario: Name with space padding
- **WHEN** a request's Cookie header carries ` __Host-scrty-session =<id>` with spaces around the name
- **THEN** the cookie is read as the session cookie

#### Scenario: Superseded identifier after its window
- **WHEN** a request presents, in the cookie, an identifier superseded by a rotation whose grace window has ended
- **THEN** it is refused with an error identifiable as both the authentication-required error and the reused-session error, and the session's family is revoked

#### Scenario: Disabled user
- **WHEN** a request carries the cookie of a session whose user has since been disabled
- **THEN** it is refused with the authentication-required error

#### Scenario: Session store outage
- **WHEN** the session store fails while a request's cookie is loaded
- **THEN** the request fails as a dependency failure, not as a refusal

### Requirement: A browser sign-in answers by what the request prefers
On a cookie chain, the default answer of every issuing endpoint SHALL be a `303 See Other` to the resolved destination for a form post or a request that prefers HTML, and a `200` JSON document carrying the session's idle expiry and no credential for a JSON request. A q-value SHALL be read by RFC 9110's grammar, including a dot with no digits after it. Each endpoint's responder SHALL stay replaceable.

#### Scenario: HTML form post
- **WHEN** a browser posts the sign-in form with `next=/orders`
- **THEN** the response is `303` to `/orders` and sets the session cookie

#### Scenario: JSON request
- **WHEN** a script posts the sign-in as JSON
- **THEN** the response is `200` with a JSON body holding the idle expiry and no credential, and it sets the session cookie

#### Scenario: Q-value with an empty fraction
- **WHEN** a sign-in request sends `Accept: text/html;q=1., application/json;q=0.5`
- **THEN** the response is `303` to its destination

#### Scenario: Consumer responder
- **WHEN** the consumer replaces the login responder with one that answers `204`
- **THEN** a successful sign-in sets the cookie and answers `204`

### Requirement: Cookie overrides that break a guarantee fail at construction
Building a cookie chain SHALL fail with a configuration error when the cookie name is empty or not a valid cookie name, when a name without a `Domain` lacks the `__Host-` prefix, when a `__Host-` name is given a `Domain`, when a `Domain` is given with a name that lacks the `__Secure-` prefix, or when the same-site mode is `None`. `HttpOnly` and `Secure` SHALL have no override.

#### Scenario: Domain with a __Host- name
- **WHEN** the consumer keeps the default name and sets the domain `example.com`
- **THEN** construction fails with a configuration error

#### Scenario: Shared domain with a __Secure- name
- **WHEN** the consumer names the cookie `__Secure-scrty-session` and sets the domain `example.com`
- **THEN** the chain builds, and the cookie is set with `Domain=example.com`

#### Scenario: Host-only name without the __Host- prefix
- **WHEN** the consumer names the cookie `sid`, or `__Secure-sid`, and sets no domain
- **THEN** construction fails with a configuration error naming the `__Host-` rule

#### Scenario: Custom __Host- name
- **WHEN** the consumer names the cookie `__Host-app` and sets no domain
- **THEN** the chain builds, and the cookie is set under that name

#### Scenario: Same-site None
- **WHEN** the consumer sets the same-site mode to none
- **THEN** construction fails with a configuration error

### Requirement: Privilege changes rotate the cookie session
On a cookie chain, the session identifier SHALL change, and the cookie SHALL be re-set, when a second factor is verified, when the user re-authenticates, when the active role is switched, and when the password is changed. Each rotation SHALL keep the previous identifier valid for a grace window, loading only its own state. The successor SHALL keep the idle deadline its rotation gave it. The CSRF token SHALL stay valid across these rotations.

#### Scenario: Sign-in over mTLS on a cookie chain
- **WHEN** a cookie chain that enables certificate binding for its provider signs a user in over mTLS, or re-authenticates them
- **THEN** the session is not bound to the certificate, and the next request's cookie authenticates

#### Scenario: Role switch
- **WHEN** `ada` switches her active role to `audit` on a cookie chain
- **THEN** the response re-sets the cookie with a new identifier, and her CSRF token is still accepted

#### Scenario: Password change
- **WHEN** a user changes their password at the resolve endpoint on a cookie chain
- **THEN** the response re-sets the cookie with a new identifier

#### Scenario: Password change keeps the rotation's idle deadline
- **WHEN** a session whose idle deadline is a few seconds away changes its password at the resolve endpoint on a cookie chain
- **THEN** the saved successor's idle deadline is the rotation's, a full idle timeout from now

#### Scenario: Request in flight during second-factor verification
- **WHEN** a request carrying the pre-verification cookie arrives after the second factor was verified, inside the grace window
- **THEN** it loads the pre-verification session with its second factor still pending, and its answer does not expire the cookie

#### Scenario: Request in flight during re-authentication
- **WHEN** a request carrying the pre-re-authentication cookie arrives after re-authentication, inside the grace window
- **THEN** it loads the pre-re-authentication session with its old authentication time, and its answer does not expire the cookie

#### Scenario: Old identifier presented late
- **WHEN** the identifier replaced at the role switch or at second-factor verification is presented after its window has ended
- **THEN** it is refused as reuse, and the sign-in's family is revoked

#### Scenario: Logout during a role switch
- **WHEN** a logout ends the sign-in while a role switch on it is in progress, before the switch's rotation is stored
- **THEN** the switch fails with the authentication-required error, its response does not re-set the cookie, and no session of the sign-in is stored
