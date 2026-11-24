## MODIFIED Requirements

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
| `invalid-token` | 401 | an access token a resource server refused |
| `insufficient-user-authentication` | 401 | an access-token caller whose authentication is too old or too weak |
| `proof-of-possession-failed` | 401 | missing or invalid DPoP proof, DPoP nonce required, certificate-bound token without its certificate |
| `mfa-required` | 401 | a challenge of the second-factor kind |
| `challenge-required` | 401 | a challenge of any other kind answered 401 |
| `password-change-required` | 403 | a challenge of the password-change kind |
| `mfa-enrolment-required` | 403 | a challenge of the second-factor enrolment kind |
| `account-recovery-required` | 403 | a challenge of the account-recovery kind |
| `reauthentication-required` | 403 | a reauthentication-required refusal of a session caller |
| `insufficient-scope` | 403 | an access-token caller missing a required scope |
| `account-inactive` | 403 | the disclosed inactive account |
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

#### Scenario: Stale access token
- **WHEN** a recency guard refuses a stale access token with a 5-minute window
- **THEN** the problem is a 401 of type `security/insufficient-user-authentication`

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

#### Scenario: Concealed inactive account
- **WHEN** an inactive account's correct password is refused with default options
- **THEN** the problem is a 401 of type `security/authentication-failed`, as for a wrong password

### Requirement: A problem carries only fixed text and safe members
A problem's title and detail SHALL be fixed library text, and no error's text SHALL appear in any member. Its only extension members SHALL be `challenge`, `methods`, `max_age`, `rule`, `scope`, `access_token` and `token_type`. No member SHALL carry a session handle, a submitted credential, a credential ID, a DPoP proof, a certificate, a CSRF token, a candidate password, a user reference or a forwarded host.

#### Scenario: What each member holds
- **WHEN** a problem carries an extension member
- **THEN** it holds only what this list gives:
  - `challenge`: a challenge's kind, as one of the fixed values `mfa`, `password-change`, `mfa-enrolment` or `account-recovery`. A challenge of any other kind has no `challenge` member;
  - `methods`: on `mfa-required`, the usable second-factor methods in the challenge's order, each with `name`, `channel` and `begins`;
  - `max_age`: on `reauthentication-required` and `insufficient-user-authentication`, the required recency in whole seconds, when the refusal carries one;
  - `scope`: on `insufficient-scope`, the scopes the refusing requirement names, space-separated;
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
