# oidc-provider-consent Specification

## Purpose
Defines when the provider asks the user to consent to a client's access, how the consumer's consent page answers, how consent is remembered and revoked, and the stricter rule for offline access.

## Requirements

### Requirement: Consent is required by default
After the login stage, the provider SHALL send the browser to the consent stage unless consent is not needed. Consent SHALL NOT be needed when every requested scope is already covered by consent the user gave that client, and `prompt=consent` was not sent. By default every client SHALL require consent.

#### Scenario: First authorization
- **WHEN** a user authorizes a client for the first time
- **THEN** the resume's `redirect_to` is the consent URL with the handle

#### Scenario: Scopes already granted
- **WHEN** the user consented to `openid profile` for a client, and a later request from that client asks for `openid profile`
- **THEN** no consent stage is shown

#### Scenario: A new scope
- **WHEN** the user consented to `openid profile`, and a later request asks for `openid profile email`
- **THEN** the consent stage is shown

### Requirement: Prompt consent always asks
A request with `prompt=consent` SHALL go through the consent stage whatever consent is remembered, and for a first-party client too.

#### Scenario: Forced consent
- **WHEN** the user already consented to every requested scope, and the request carries `prompt=consent`
- **THEN** the consent stage is shown

### Requirement: First-party clients skip consent for ordinary scopes
A client registered as first-party SHALL skip the consent stage, unless `prompt=consent` was sent or `offline_access` must be asked for.

#### Scenario: First-party client
- **WHEN** a first-party client asks for `openid profile` for the first time
- **THEN** no consent stage is shown, and the code is issued for `openid profile`

### Requirement: Offline access is asked for even from a first-party client
A request for `offline_access` SHALL go through the consent stage unless:
- the user already explicitly consented to `offline_access` for that client at a consent stage, and `prompt=consent` was not sent; or
- the client is pre-authorized for offline access.

This SHALL hold for first-party clients too. Consent to other scopes SHALL never count as consent to `offline_access`. `offline_access` SHALL be honoured only in a request that results in an authorization code.

#### Scenario: First-party client asks for offline access
- **WHEN** a first-party client asks for `openid offline_access` for the first time
- **THEN** the consent stage is shown, although the client is first-party

#### Scenario: Offline access remembered
- **WHEN** the user explicitly consented to `offline_access` for a client, and the client asks for it again without `prompt=consent`
- **THEN** no consent stage is shown, and the grant includes `offline_access`

#### Scenario: Other consent does not cover offline access
- **WHEN** the user consented to `openid profile` for a client, and the client asks for `openid profile offline_access`
- **THEN** the consent stage is shown

#### Scenario: Offline access refused at consent
- **WHEN** the consent page grants `openid` and not `offline_access`
- **THEN** the grant has no `offline_access`, and its refresh tokens end with the sign-in

### Requirement: Consent given to one client never counts for another
Consent given to one client SHALL never count for another.

#### Scenario: Another client asks
- **WHEN** a user consented to `openid profile` for `billing-web`, and `crm-web` asks for `openid profile`
- **THEN** the consent stage is shown

### Requirement: A native first-party client can be pre-authorized for offline access
A consumer MAY pre-authorize a first-party client of application type native for offline access. Its requests for `offline_access` SHALL then be honoured without `prompt=consent` and without the consent stage. Pre-authorizing a web client, or a client that is not first-party, SHALL fail construction.

#### Scenario: Pre-authorized native client
- **WHEN** a pre-authorized first-party native client asks for `openid offline_access`
- **THEN** no consent stage is shown, and the grant includes `offline_access`

#### Scenario: Web client pre-authorized
- **WHEN** a consumer pre-authorizes a web client for offline access
- **THEN** construction fails with a configuration error

### Requirement: The consent page answers with the scopes granted or a denial
The consent stage SHALL be resumed through the resume endpoint, with the same handle, flow cookie and sign-in rules as the login stage, by a sign-in of the same user as the login stage, or by that user's browser session. The answer SHALL either grant a set of scopes or deny. A grant SHALL issue a code bound to the scopes granted, not those requested. A denial SHALL answer `redirect_to` with `error=access_denied`, `state` and `iss`, and SHALL record no consent.

#### Scenario: Partial grant
- **WHEN** a request asked for `openid profile email`, and the consent page grants `openid profile`
- **THEN** the code is bound to `openid profile`, and the tokens carry no `email` scope

#### Scenario: Denied
- **WHEN** the consent page answers with a denial
- **THEN** `redirect_to` carries `error=access_denied`, `state` and `iss`, and no consent is remembered

#### Scenario: Another user at consent
- **WHEN** the login stage was resumed by user `u-1`, and the consent stage is resumed with a sign-in of user `u-2`
- **THEN** the resume is refused, and no code is issued

### Requirement: Granted scopes stay within the request
Granted scopes SHALL be a subset of the requested ones, and SHALL include `openid` when it was requested. Otherwise the answer SHALL be refused as malformed, and the handle SHALL stay unspent.

#### Scenario: Scope not requested
- **WHEN** the consent page grants `admin`, which was not requested
- **THEN** the answer is refused as malformed, and the handle can still be answered

### Requirement: Consent is remembered per user and client
A grant at the consent stage SHALL be remembered for that user and client, adding the granted scopes to any already remembered. Remembered consent SHALL be kept in a consent store, in memory by default, durable through the store adapters.

#### Scenario: Consent accumulates
- **WHEN** the user granted `openid profile` and later `openid email` to one client
- **THEN** the remembered consent for that client covers `openid profile email`

### Requirement: A first-party client's grants can be ended
A user holding no remembered consent for a client, but holding grants of it, SHALL still be able to end those grants, as a first-party client skips consent. Revoking is refused only when the user holds neither.

#### Scenario: A first-party client's grant, with no consent held
- **WHEN** a user with a grant of a first-party client, and no remembered consent for it, revokes consent for that client
- **THEN** that user's grants of that client are revoked, no other client's are, and the request succeeds

#### Scenario: Neither consent nor a grant
- **WHEN** a user with no consent and no grant of a client revokes consent for it
- **THEN** the request is refused, and nothing changes

### Requirement: Users and consumers can revoke consent
The provider SHALL let the consumer revoke a user's consent for a client, and SHALL offer an endpoint where a signed-in user revokes their own consent for a client. Revoking consent SHALL forget the remembered scopes and SHALL revoke every grant of that user and client, so their refresh tokens stop working at once.

#### Scenario: User revokes an application
- **WHEN** a signed-in user revokes their consent for `billing-web`
- **THEN** the next authorization from `billing-web` shows the consent stage, and every refresh token issued to `billing-web` for that user is refused with `invalid_grant`

#### Scenario: Revoking another user's consent
- **WHEN** a signed-in user asks to revoke consent of another user
- **THEN** the request is refused, and nothing is revoked

### Requirement: Users can list the applications with access to their account
The provider SHALL let a signed-in user list the clients they consented to, with each client's name, the scopes granted, whether offline access was granted, and when consent was last given. The list SHALL hold only that user's consents.

#### Scenario: Listing
- **WHEN** a user who consented to two clients lists their applications
- **THEN** both clients are listed with their granted scopes
