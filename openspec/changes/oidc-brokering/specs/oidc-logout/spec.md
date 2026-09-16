## Purpose

Ends local sessions that were established through an external OpenID Connect provider, when that provider says its session ended and when the user logs out locally. It covers logout-token verification and its replay bound, the back-channel logout endpoint and how far a logout reaches, the federated identity recorded on each session, and RP-initiated logout.

## ADDED Requirements

### Requirement: A federated session records its provider session when it is created
Every session established by an OIDC login SHALL record, in the write that creates it:
- the provider name;
- the verified issuer;
- the provider session id from the ID token's `sid` claim, or empty when the provider issued none;
- the raw ID token.

The ID token SHALL be kept only as a logout hint. It SHALL never be verified again or accepted as a credential. A session established by any other first factor SHALL record none of these values.

#### Scenario: Recorded at creation
- **WHEN** a login through provider `corp` with issuer `https://idp.example` and `sid` `abc` establishes a session
- **THEN** loading that session returns provider `corp`, issuer `https://idp.example` and provider session id `abc`

#### Scenario: Provider without session ids
- **WHEN** a provider issues an ID token without a `sid` claim and the login establishes a session
- **THEN** the session records an empty provider session id and the login succeeds

#### Scenario: Password session
- **WHEN** a session is established by a password login
- **THEN** it records no provider, issuer, provider session id or ID token

### Requirement: Logout tokens are verified strictly
A logout token SHALL be accepted only when all of the following hold:
- its signature, algorithm, key id, issuer, audience and authorized party pass the same checks as an ID token for the same provider;
- it carries an issued-at time no older than the maximum age (2 minutes by default, replaceable by an option) plus the clock leeway, and no later than now plus the leeway;
- when it carries an expiry, that expiry has not passed;
- it carries a non-empty `jti`;
- it carries an `events` claim containing the back-channel logout event, whose value is a JSON object;
- it carries no `nonce`;
- it carries a subject, a session id, or both.

The contents of the event's object and unknown claims SHALL be ignored. Every verification failure SHALL be one invalid-logout-token outcome, with the specific cause available only to logs. A key set that could not be retrieved SHALL be reported as a provider failure, not as an invalid token. A maximum age of zero or less SHALL fail construction.

#### Scenario: ID token presented as a logout token
- **WHEN** a valid ID token, carrying a `nonce` and no `events` claim, is posted as a logout token
- **THEN** it is refused with the invalid-logout-token outcome

#### Scenario: Stale token
- **WHEN** a correctly signed logout token issued 5 minutes ago is received with the default maximum age
- **THEN** it is refused with the invalid-logout-token outcome

#### Scenario: Missing issued-at
- **WHEN** a correctly signed logout token carries no issued-at time and no expiry
- **THEN** it is refused with the invalid-logout-token outcome

#### Scenario: Neither subject nor session id
- **WHEN** a correctly signed logout token carries neither `sub` nor `sid`
- **THEN** it is refused with the invalid-logout-token outcome

#### Scenario: Extra members in the event object
- **WHEN** a correctly signed, fresh logout token's back-channel event object contains an unrecognised member
- **THEN** the token is accepted

#### Scenario: Consumer maximum age
- **WHEN** the maximum age is configured as 10 minutes and a correctly signed logout token issued 5 minutes ago is received
- **THEN** the token is accepted

### Requirement: Logout-token replay is bounded by issued-at, as a stated limit
The library SHALL NOT keep a record of `jti` values it has seen. The replay bound SHALL be the issued-at window alone. The documentation SHALL state that a captured logout token can be replayed until its issued-at is older than the maximum age plus the leeway. It SHALL state that, for a subject-only token, each replay inside that window ends the user's matching sessions established since. It SHALL also state that widening the maximum age widens that window.

#### Scenario: Replay inside the window
- **WHEN** a valid subject-only logout token is received, the user logs in again through the same issuer, and the same token is received again within the maximum age
- **THEN** the new session is also ended

#### Scenario: Replay after the window
- **WHEN** the same logout token is received again after the maximum age plus leeway has passed
- **THEN** it is refused with the invalid-logout-token outcome and no session is ended

### Requirement: The back-channel endpoint ends sessions named by a verified token
The back-channel logout endpoint SHALL accept only POST requests carrying a `logout_token` form parameter, for a registered provider in its path. It SHALL require no session, cookie or bearer credential. For a verified token:
- when the token carries a session id, whether or not it also carries a subject, the endpoint SHALL end exactly the sessions whose issuer and provider session id both match, through the `sessions` capability;
- when the token carries only a subject, the endpoint SHALL find the link for the provider, issuer and subject through the `identity-linking` capability, and SHALL end the linked user's sessions established through that issuer;
- a subject with no link SHALL end nothing and SHALL be a success.

#### Scenario: Session id preferred
- **WHEN** user `u-1` has two sessions from issuer `https://idp.example` with provider session ids `abc` and `def`, and a verified token carries both `sub` and `sid` `abc`
- **THEN** only the session with provider session id `abc` is ended

#### Scenario: Subject-only logout
- **WHEN** a verified token from issuer `https://idp.example` carries only a subject linked to user `u-1`, and `u-1` has two sessions from that issuer
- **THEN** both sessions are ended

#### Scenario: Unlinked subject
- **WHEN** a verified subject-only token names a subject with no link
- **THEN** the endpoint answers success and no session is ended

#### Scenario: Session id from another issuer
- **WHEN** a verified token from issuer `https://a.example` carries `sid` `abc`, and a session from issuer `https://b.example` has provider session id `abc`
- **THEN** the session from `https://b.example` is not ended

### Requirement: A subject-only logout is scoped to its issuer by default
By default, a subject-only logout SHALL end only the user's sessions established through the issuer that signed the token. Sessions from other issuers and sessions established by other first factors SHALL be spared. A consumer SHALL be able to widen the scope so that a subject-only logout ends every session of the linked user. The documentation for that option SHALL state that it lets that provider end sessions it did not establish.

#### Scenario: Password session survives
- **WHEN** user `u-1` has a password session and a session from issuer `https://idp.example`, and a verified subject-only token for `u-1` arrives from that issuer
- **THEN** the federated session is ended
- **AND** the password session still loads

#### Scenario: Another provider's session survives
- **WHEN** user `u-1` has sessions from issuers `https://a.example` and `https://b.example`, and a verified subject-only token for `u-1` arrives from `https://a.example`
- **THEN** only the session from `https://a.example` is ended

#### Scenario: Consumer widens the scope
- **WHEN** the scope is configured to end all sessions, and user `u-1` has a password session and a session from `https://idp.example`, and a verified subject-only token for `u-1` arrives from that issuer
- **THEN** both sessions are ended

### Requirement: Back-channel responses reveal nothing about sessions or users
A verified token SHALL be answered with status 200, an empty body and `Cache-Control: no-store`, whether any sessions were ended or none. A request without a `logout_token`, or with a token that fails verification, SHALL be answered with status 400 and `Cache-Control: no-store`. The response SHALL NOT say which rule the token failed. A store failure, a link-store failure or a provider key-set failure SHALL be returned as an error that is not the invalid-logout-token outcome, so that it maps to a server-error status. The number of sessions ended SHALL appear only in logs. A request with another method, or to a path that is not the endpoint, SHALL pass through untouched.

#### Scenario: Same answer for zero and many
- **WHEN** one verified token ends 3 sessions and another verified token ends none
- **THEN** both responses are status 200 with an empty body and `Cache-Control: no-store`

#### Scenario: Session store outage
- **WHEN** a verified token arrives and ending its sessions fails because the session store is unavailable
- **THEN** the error is not the invalid-logout-token outcome and the response is not 200

#### Scenario: Forged token
- **WHEN** a token with an invalid signature is posted
- **THEN** the response is status 400 with no description of the failed check

### Requirement: RP-initiated logout offers the provider's end-session URL
When a session that records a provider is ended by a local logout, the library SHALL end the local session first. It SHALL then produce the provider's end-session URL, if the provider advertises or pins an end-session endpoint. The URL SHALL carry:
- the client id;
- the session's ID token as the hint;
- the consumer's configured post-logout redirect URL, when one is configured;
- a state value, when the caller supplies one.

Empty values SHALL be omitted from the URL rather than sent empty. The post-logout redirect URL SHALL be validated at construction: it SHALL be an absolute `https` URL with no user information, or construction fails. A provider without an end-session endpoint, and a session that records no provider, SHALL produce no URL and SHALL NOT be an error. RP-initiated logout SHALL be on by default. A consumer SHALL be able to turn it off, after which a local logout ends the session and produces no URL.

#### Scenario: Federated session with end-session endpoint
- **WHEN** a session from provider `corp`, whose end-session endpoint is `https://idp.example/logout`, is logged out locally with post-logout redirect `https://app.example/bye`
- **THEN** the session is ended
- **AND** the returned URL targets `https://idp.example/logout` with the client id, the session's ID token as hint and `post_logout_redirect_uri=https://app.example/bye`

#### Scenario: Provider without end-session endpoint
- **WHEN** a session from a provider that advertises no end-session endpoint is logged out locally
- **THEN** the session is ended and no URL is returned, without error

#### Scenario: Consumer turns RP-initiated logout off
- **WHEN** RP-initiated logout is turned off and a session from a provider with an end-session endpoint is logged out locally
- **THEN** the session is ended and no URL is returned

#### Scenario: No post-logout redirect configured
- **WHEN** no post-logout redirect URL is configured and a federated session is logged out locally
- **THEN** the returned URL has no `post_logout_redirect_uri` parameter

### Requirement: Logout wiring mistakes fail at construction
Constructing OIDC logout SHALL fail with a configuration error when:
- the back-channel logout path collides with the authorize, callback or redemption path;
- the logout scope is not one of the defined scopes;
- the post-logout redirect URL is invalid.

#### Scenario: Back-channel path shadows the callback
- **WHEN** the back-channel logout path is configured equal to the callback path
- **THEN** construction fails with a configuration error
