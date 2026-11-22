# problem-details-rendering Specification

## Purpose
Defines the opt-in integration that answers scrty's refusals as RFC 9457 problem details through `github.com/kartaladev/prblm`. Each refusal reaches a client as a typed problem it can act on. The status always agrees with the core's mapping, and nothing the core withholds from a client is revealed.

## Requirements

### Requirement: The integration is an opt-in module
The integration SHALL be its own module, `github.com/kartaladev/scrty/httpsec/prblmsec`. It SHALL have no effect until its mapper is registered with a prblm handler. A consumer who does not register it SHALL get exactly the responses the core and the framework adapters give today.

#### Scenario: Registered or not
- **WHEN** a net/http chain refuses an unauthenticated request and the consumer's error handler writes through a prblm handler, once with the integration registered and once without
- **THEN** with it, the response is a 401 `application/problem+json` document of type `security/authentication-required`
- **AND** without it, the refusal resolves through prblm alone, as prblm's own rules decide

#### Scenario: Core untouched
- **WHEN** a consumer imports only the core module
- **THEN** `github.com/kartaladev/prblm` does not appear in the consumer's `go list -m all` output

### Requirement: The status of a problem is the core's status
For every error the core recognises, the problem's status SHALL equal the status the core's public mapping gives that error, whichever type is chosen. The core recognises a refusal it names, a challenge, and a dependency failure the library reported. A recognised error the core answers 500 SHALL be answered as an `about:blank` 500 problem with no detail. Every other recognised status that has no type of its own SHALL be answered as an `about:blank` problem with that status and no detail.

#### Scenario: Status agrees with the core
- **WHEN** each refusal named in the core's status table is resolved through the integration
- **THEN** each problem's status equals the core's status for that refusal

#### Scenario: Recognised dependency failure
- **WHEN** the error is the password-history-unavailable error wrapping a PostgreSQL error with code `53300`, and a PostgreSQL mapper is registered after the integration
- **THEN** the response is a 500 problem of type `about:blank` with no detail, not the PostgreSQL mapper's 503

### Requirement: A refusal becomes a typed problem
Each recognised refusal SHALL become a problem whose type is a sub-type under the configured prefix (default `security`), with a fixed title and a fixed detail. The type SHALL be chosen only among the types whose status equals the core's status for the error. An error that matches none of them SHALL get its status's default type.

#### Scenario: Type of each refusal
- **WHEN** each refusal below is resolved through the integration with the default prefix
- **THEN** its problem has the sub-type and status the table gives, and a refusal not named for its status has that status's default type

| Sub-type | Status | Refusals |
|---|---|---|
| `authentication-required` | 401 | authentication required (the chain's and the authorization capability's), session idle, session expired, the provider's re-authentication refusal |
| `authentication-failed` | 401 | the status default: authentication failed in every form (including a concealed lock), user store unavailable, a throttled source, a refused magic-link redemption |
| `second-factor-failed` | 401 | invalid second-factor code, throttled second-factor verification or enrolment, throttled passkey registration begin |
| `proof-of-possession-failed` | 401 | missing or invalid DPoP proof, DPoP nonce required, certificate-bound token without its certificate |
| `mfa-required` | 401 | a challenge of the second-factor kind |
| `challenge-required` | 401 | a challenge of any other kind answered 401 |
| `password-change-required` | 403 | a challenge of the password-change kind |
| `mfa-enrolment-required` | 403 | a challenge of the second-factor enrolment kind |
| `account-recovery-required` | 403 | a challenge of the account-recovery kind |
| `reauthentication-required` | 403 | any reauthentication-required refusal |
| `cross-site-request` | 403 | a cross-site request refused by CSRF protection or the signal stream |
| `automation-challenge-required` | 403 | a request refused by the automation-challenge verifier |
| `access-denied` | 403 | the status default |
| `invalid-request` | 400 | the status default |
| `not-found` | 404 | the status default |
| `conflict` | 409 | the status default |
| `request-too-large` | 413 | the status default |
| `password-rejected` | 422 | the status default |
| `account-locked` | 429 | the disclosed account lock |
| `limit-reached` | 429 | the status default |

#### Scenario: Second-factor challenge
- **WHEN** a password login is challenged for a second factor
- **THEN** the problem is a 401 of type `security/mfa-required`

#### Scenario: Wrong password
- **WHEN** a password login is refused for a wrong password
- **THEN** the problem is a 401 of type `security/authentication-failed`

#### Scenario: Wrapped refusal
- **WHEN** the error wraps the access-denied refusal with extra context
- **THEN** the problem is a 403 of type `security/access-denied`

#### Scenario: Challenge wrapping a sentinel
- **WHEN** a challenge of the second-factor kind wraps the access-denied refusal
- **THEN** the problem is a 401 of type `security/mfa-required`

### Requirement: A type never reveals what the status conceals
Where the core gives several refusals one status in order to conceal which of them occurred, the problem SHALL NOT tell them apart: not by type, title, detail or extension member. In particular, a concealed account lock and a user store that could not answer SHALL both be `authentication-failed` with the same title and detail as a wrong password.

#### Scenario: Concealed lock
- **WHEN** the error joins the authentication-failed refusal with the account-locked refusal
- **THEN** the problem is byte-for-byte the problem a wrong password gets on the same request

#### Scenario: User store outage
- **WHEN** a password login is refused because the user store returned a connection error
- **THEN** the problem is byte-for-byte the problem a wrong password gets on the same request

#### Scenario: Disclosed lock
- **WHEN** the consumer enabled lock disclosure and a locked account's login is refused
- **THEN** the problem is a 429 of type `security/account-locked`

### Requirement: A problem carries only fixed text and safe members
A problem's title and detail SHALL be fixed library text, and no error's text SHALL appear in any member. Its only extension members SHALL be `challenge`, `methods`, `max_age`, `rule`, `access_token` and `token_type`. No member SHALL carry a session handle, a submitted credential, a credential ID, a DPoP proof, a certificate, a CSRF token, a candidate password, a user reference or a forwarded host.

#### Scenario: What each member holds
- **WHEN** a problem carries an extension member
- **THEN** it holds only what this list gives:
  - `challenge`: a challenge's kind, as one of the fixed values `mfa`, `password-change`, `mfa-enrolment` or `account-recovery`. A challenge of any other kind has no `challenge` member;
  - `methods`: on `mfa-required`, the usable second-factor methods in the challenge's order, each with `name`, `channel` and `begins`;
  - `max_age`: on `reauthentication-required`, the required recency in whole seconds, when the refusal carries one;
  - `rule`: on `password-rejected`, the policy rule that refused the candidate;
  - `access_token` and `token_type`: as the challenge-token requirement states.

#### Scenario: Methods listed
- **WHEN** `u-1` is enrolled on TOTP and on a challenge method named `passkey`, and `u-1`'s password login is challenged for a second factor
- **THEN** `methods` lists `totp` on the authenticator-app channel with `begins` false, then `passkey` with `begins` true

#### Scenario: Reauthentication window
- **WHEN** a recency guard with a 5-minute window refuses a stale session
- **THEN** the problem is of type `security/reauthentication-required` with `max_age` 300

#### Scenario: Password rule named
- **WHEN** a password change is refused because the candidate is breached
- **THEN** the problem is a 422 of type `security/password-rejected` whose `rule` names the breached rule, and no member contains the candidate

#### Scenario: Dependency text stays out
- **WHEN** a login is refused because the attempt store failed with an error quoting `alice@example.com`
- **THEN** no member of the problem contains `alice@example.com`

### Requirement: A challenge problem delivers the challenge's credential
When a challenge error carries an access token, its problem SHALL carry it as `access_token`, with `token_type` naming the token's type (`Bearer` or `DPoP`). The response SHALL carry `Cache-Control: no-store`. A challenge error that carries no token SHALL produce neither member.

#### Scenario: Challenged login
- **WHEN** a password login over a bearer-token chain is challenged for a second factor
- **THEN** the problem carries `access_token` equal to the challenge's token, `token_type` `Bearer`, and the response carries `Cache-Control: no-store`

#### Scenario: Upstream cache policy does not survive a token
- **WHEN** a consumer middleware sets `Cache-Control: public, max-age=300` before the chain, and a password login is challenged for a second factor, on net/http, gin and fiber
- **THEN** each framework's response carries `access_token` and `Cache-Control: no-store` only

#### Scenario: Challenge raised on a later request
- **WHEN** the password-change gate refuses a session
- **THEN** the problem carries neither `access_token` nor `token_type`

### Requirement: The consumer can withhold the challenge's credential
A consumer SHALL be able to configure the integration so that no problem carries `access_token` or `token_type`. The rest of the challenge problem SHALL be unchanged.

#### Scenario: Token withheld
- **WHEN** the integration is configured to withhold challenge tokens and a password login is challenged for a second factor
- **THEN** the problem is a 401 of type `security/mfa-required` with `methods`, and carries neither `access_token` nor `token_type`

### Requirement: An error the core does not recognise is left to prblm
The integration's mapper SHALL report no match for an error the core does not recognise. The consumer's later mappers, prblm's built-ins and prblm's safe fallback then decide it.

#### Scenario: Application error after the integration
- **WHEN** the integration and a mapper for the consumer's own not-found error are registered, in that order, and a handler behind the chain returns that error
- **THEN** the response is the consumer mapper's problem

#### Scenario: Unknown failure
- **WHEN** the error is a database connection failure that wraps nothing the core or any mapper recognises
- **THEN** the response is prblm's 500 problem with no detail

### Requirement: The type prefix is configurable and checked at construction
The default prefix SHALL be `security`. A consumer SHALL be able to replace it with any valid prblm sub-type. An invalid prefix SHALL be refused when the integration is constructed, never at the first refusal. The definitions the integration offers for prblm's discovery SHALL use the same prefix as its mapper.

#### Scenario: Custom prefix
- **WHEN** the integration is built with the prefix `auth` and a prblm handler with the namespace `/probs`, and a request is refused as access denied
- **THEN** the problem's type is `/probs/auth/access-denied`

#### Scenario: Invalid prefix
- **WHEN** the integration is built with the prefix `Auth/../x`
- **THEN** construction fails with a configuration error, and no mapper is returned

#### Scenario: Documented types
- **WHEN** the integration's definitions are registered with a prblm handler that has a namespace, and discovery is mounted
- **THEN** every type the mapper can produce has a documentation page, and none of the integration's problems triggers prblm's undocumented-type note

### Requirement: A consumer mapper overrides any problem
A prblm mapper the consumer registers ahead of the integration's SHALL replace the integration's problem for the errors that mapper recognises. Every other refusal SHALL keep the integration's problem.

#### Scenario: Consumer's own lock page
- **WHEN** a consumer registers, ahead of the integration, a mapper answering the disclosed account-lock refusal with a 429 that carries `Retry-After: 900`
- **THEN** a locked login receives the consumer's problem, and a wrong password still receives `security/authentication-failed`

### Requirement: Headers the chain set are kept
The integration SHALL NOT set `WWW-Authenticate`. A challenge header the chain set before refusing SHALL survive in the problem response on net/http, gin and fiber.

#### Scenario: Basic challenge kept
- **WHEN** Basic authentication fails and the refusal is rendered through the integration
- **THEN** the response is a 401 problem and keeps the chain's `WWW-Authenticate: Basic` header, once

#### Scenario: DPoP nonce kept
- **WHEN** a DPoP proof lacks a required server nonce and the refusal is rendered through the integration
- **THEN** the response keeps the chain's `DPoP-Nonce` header and its `WWW-Authenticate: DPoP` challenge

### Requirement: Every framework renders the same problem
A refusal rendered through the integration SHALL produce the same status, problem document and security headers on net/http (through the chain's error handler), on gin (through prblm's gin middleware) and on fiber (through prblm's fiber error handler).

#### Scenario: Same problem on three frameworks
- **WHEN** the same challenged password login is sent to a net/http, a gin and a fiber deployment, each rendering through the integration
- **THEN** the three responses carry the same status, the same problem document and the same `WWW-Authenticate` and `Cache-Control` headers

### Requirement: On gin, the chain's own 404s render through prblm's gin middleware
On gin, a 404 refusal on a path that matched no gin route, as at the chain's own endpoints, SHALL be rendered as a problem when prblm's gin middleware is registered before the gin adapter, with or without the gin adapter's rendered-refusals declaration. The declaration is for other error middleware, which writes the response immediately. A gin deployment with no renderer at all answers that 404 with an empty body, as the framework-adapters capability states.

#### Scenario: gin 404 at a chain endpoint, declared
- **WHEN** the gin adapter is given the rendered-refusals declaration, prblm's gin middleware is registered before it, and an MFA verify path names an unknown method that no gin route matches
- **THEN** gin answers a 404 problem of type `security/not-found`, as net/http and fiber do

#### Scenario: gin 404 at a chain endpoint, not declared
- **WHEN** the same request is sent to a gin deployment with prblm's gin middleware registered before the gin adapter, and the adapter is not given the declaration
- **THEN** gin answers the same 404 problem of type `security/not-found`

#### Scenario: gin 404 at a chain endpoint, no renderer
- **WHEN** the same request is sent to a gin deployment with no error middleware and no declaration
- **THEN** gin answers 404 with an empty body

#### Scenario: gin 404 on a matched route
- **WHEN** a guard on a gin route the consumer registered refuses with a not-found refusal
- **THEN** gin answers the 404 problem of type `security/not-found`, with or without the declaration
