## MODIFIED Requirements

### Requirement: First-party clients skip consent for ordinary scopes
A client registered as first-party SHALL skip the consent stage, unless `prompt=consent` was sent, `offline_access` must be asked for, or the request is a device authorization.

#### Scenario: First-party client
- **WHEN** a first-party client asks for `openid profile` for the first time
- **THEN** no consent stage is shown, and the code is issued for `openid profile`

#### Scenario: First-party client's device authorization
- **WHEN** a first-party client's device authorization for `openid profile` is claimed and its login stage resumes
- **THEN** the consent stage is shown

### Requirement: A native first-party client can be pre-authorized for offline access
A consumer MAY pre-authorize a first-party client of application type native for offline access. Its requests for `offline_access` SHALL then be honoured without `prompt=consent` and without the consent stage, except a device authorization, which always asks. Pre-authorizing a web client, or a client that is not first-party, SHALL fail construction.

#### Scenario: Pre-authorized native client
- **WHEN** a pre-authorized first-party native client asks for `openid offline_access`
- **THEN** no consent stage is shown, and the grant includes `offline_access`

#### Scenario: Web client pre-authorized
- **WHEN** a consumer pre-authorizes a web client for offline access
- **THEN** construction fails with a configuration error

#### Scenario: Pre-authorized native client's device authorization
- **WHEN** a pre-authorized first-party native client's device authorization for `openid offline_access` reaches the end of its login stage
- **THEN** the consent stage is shown

### Requirement: The consent page answers with the scopes granted or a denial
The consent stage SHALL be resumed through the resume endpoint, with the same handle, flow cookie and sign-in rules as the login stage, by a sign-in of the same user as the login stage, or by that user's browser session. The answer SHALL either grant a set of scopes or deny. A grant SHALL issue a code bound to the scopes granted, not those requested, or, for a device authorization, approve it with those scopes. A denial SHALL answer `redirect_to` with `error=access_denied`, `state` and `iss`, or, for a device authorization, deny it and answer with the code-entry page carrying `result=denied`. A denial SHALL record no consent.

#### Scenario: Partial grant
- **WHEN** a request asked for `openid profile email`, and the consent page grants `openid profile`
- **THEN** the code is bound to `openid profile`, and the tokens carry no `email` scope

#### Scenario: Denied
- **WHEN** the consent page answers with a denial
- **THEN** `redirect_to` carries `error=access_denied`, `state` and `iss`, and no consent is remembered

#### Scenario: Another user at consent
- **WHEN** the login stage was resumed by user `u-1`, and the consent stage is resumed with a sign-in of user `u-2`
- **THEN** the resume is refused, and no code is issued

#### Scenario: A device authorization denied
- **WHEN** the consent page denies a device authorization
- **THEN** `redirect_to` is the code-entry page with `result=denied`, the device's next poll is answered with `access_denied`, and no consent is remembered

## ADDED Requirements

### Requirement: A device authorization always asks for consent
A device authorization SHALL always reach the consent stage after its login stage, whatever the client's first-party flag, its offline-access pre-authorization, or the consent the user already gave that client. An approval SHALL be remembered as any consent is, so that revoking the client's consent also ends its device grants.

#### Scenario: Consent already remembered
- **WHEN** the user already consented to `openid profile` for a client, and that client's device authorization for `openid profile` reaches the end of its login stage
- **THEN** the consent stage is shown

#### Scenario: Revoking consent ends the device grant
- **WHEN** the user approved a device authorization, and later revokes that client's consent
- **THEN** the device grant's refresh token is refused with `invalid_grant`
