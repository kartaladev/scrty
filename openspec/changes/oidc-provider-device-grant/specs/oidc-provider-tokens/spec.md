## RENAMED Requirements

- FROM: `### Requirement: The token endpoint accepts two grant types by form POST`
- TO: `### Requirement: The token endpoint accepts its grant types by form POST`

## MODIFIED Requirements

### Requirement: The token endpoint accepts its grant types by form POST
The token endpoint SHALL accept only POST requests with a form-encoded body, and SHALL support the `authorization_code` and `refresh_token` grant types, and `urn:ietf:params:oauth:grant-type:device_code` when the provider has enabled the device grant. Any other grant type SHALL be answered with `unsupported_grant_type`, and no option SHALL enable the password grant. A repeated parameter SHALL make the request invalid, and a parameter without a value SHALL be treated as omitted.

#### Scenario: Password grant
- **WHEN** a client sends `grant_type=password`
- **THEN** the response is 400 with `{"error":"unsupported_grant_type"}`

#### Scenario: GET request
- **WHEN** a client sends a token request by GET
- **THEN** the request is refused and no token is issued

#### Scenario: Device grant on a provider that has not enabled it
- **WHEN** a client sends `grant_type=urn:ietf:params:oauth:grant-type:device_code` to a provider built without the device grant
- **THEN** the response is 400 with `{"error":"unsupported_grant_type"}`

### Requirement: Logout ends the grants of the sign-in without offline access
When a sign-in ends by logout, by revocation of its session family, or by a back-channel logout from an upstream provider, the provider SHALL revoke the grants created from that sign-in that do not hold `offline_access`. Grants holding `offline_access` SHALL survive. A consumer MAY register a client so that all its grants end with their sign-in, `offline_access` included. A public client of application type web SHALL be so registered by default, and a consumer MAY turn this off per client. A device grant's sign-in is the one that approved it, and a consumer MAY register a client so that its device grants without `offline_access` survive that sign-in's end.

#### Scenario: Logout with an online grant
- **WHEN** a user logs out of the sign-in a grant without `offline_access` came from
- **THEN** that grant's refresh token is refused with `invalid_grant`

#### Scenario: Logout with an offline grant
- **WHEN** a user logs out of the sign-in a grant holding `offline_access` came from
- **THEN** that grant's refresh token keeps working

#### Scenario: Browser-based public client
- **WHEN** a public web client under the default holds a grant with `offline_access`, and the user logs out of its sign-in
- **THEN** that grant's refresh token is refused with `invalid_grant`

#### Scenario: Consumer ties offline grants to the sign-in
- **WHEN** a client is registered to end its grants with the sign-in, and the user logs out
- **THEN** that client's grant holding `offline_access` is revoked too

#### Scenario: A device grant ends with the approving sign-in by default
- **WHEN** a native client under the default holds a device grant without `offline_access`, and the user logs out of the browser sign-in that approved it
- **THEN** that grant's refresh token is refused with `invalid_grant`

#### Scenario: Consumer lets device grants outlive the approving sign-in
- **WHEN** a client is registered so that its device grants outlive their sign-in, holds a device grant without `offline_access`, and the user logs out of the approving sign-in
- **THEN** that grant's refresh token keeps working

## ADDED Requirements

### Requirement: A device-code exchange succeeds only for an approved authorization
A device-code exchange SHALL succeed only when the device code is known, unexpired, unspent, approved and issued to the authenticated client, and the client is still registered for the device grant. A code issued to another client, or unknown, SHALL be answered with `invalid_grant`. A failure before the exchange SHALL leave the authorization as it was.

#### Scenario: Approved code from its client
- **WHEN** the client that obtained an approved device code polls with it
- **THEN** the response is 200 with an access token, and the authorization is spent

#### Scenario: Another client's device code
- **WHEN** a client polls with a device code issued to another client
- **THEN** the response is `invalid_grant`, and the authorization is unchanged

### Requirement: A device-code poll answers with the authorization's state
While the user has not answered, a poll SHALL be answered with `authorization_pending`. A denied authorization SHALL be answered with `access_denied`, and an expired one with `expired_token`. Each SHALL be a 400 with the token endpoint's error body.

#### Scenario: The user has not answered
- **WHEN** the client polls before the user has approved or denied
- **THEN** the response is 400 with `{"error":"authorization_pending"}`

#### Scenario: The user denied
- **WHEN** the client polls after the user denied
- **THEN** the response is 400 with `{"error":"access_denied"}`

#### Scenario: The authorization expired
- **WHEN** the client polls after the device authorization expired
- **THEN** the response is 400 with `{"error":"expired_token"}`

### Requirement: Polling faster than the interval slows the client down
A poll of a pending authorization arriving sooner than its interval after the previous poll SHALL be answered with `slow_down`, and the authorization's interval SHALL grow by 5 seconds for every later poll. The previous poll's time and the interval SHALL be updated by one conditional write, so that concurrent polls cannot both pass.

#### Scenario: A poll 2 seconds after the last
- **WHEN** a client polls a pending authorization 2 seconds after its previous poll, with the default interval
- **THEN** the response is `slow_down`, and a poll 6 seconds later is also answered with `slow_down`, because the interval is now 10 seconds

#### Scenario: Concurrent polls
- **WHEN** two polls of one pending authorization arrive at once, after the interval has passed
- **THEN** one is answered with `authorization_pending` and the other with `slow_down`

### Requirement: A device code is exchanged once, and its replay revokes what it issued
A device code SHALL be exchanged at most once, also under concurrent polls. A spent device code presented again by the client it was issued to, authenticated and with its key binding holding, SHALL be answered with `invalid_grant` and SHALL revoke the grant the exchange created. Any other presentation SHALL revoke nothing.

#### Scenario: Concurrent polls of an approved code
- **WHEN** two polls of one approved device code arrive at once
- **THEN** exactly one is answered with tokens

#### Scenario: A replayed device code
- **WHEN** the client presents a device code it already exchanged
- **THEN** the response is `invalid_grant`, and the grant's refresh tokens and opaque access tokens stop working

### Requirement: A device-code exchange is refused once its user or sign-in has ended
A device-code exchange SHALL be answered with `invalid_grant` when the approving user no longer exists or is disabled, or when the approving sign-in has ended and the grant would not survive that end.

#### Scenario: The user was disabled after approving
- **WHEN** the user approves, is then disabled, and the client polls
- **THEN** the response is `invalid_grant`, and no grant is recorded

#### Scenario: The approving sign-in ended before the poll
- **WHEN** the user approves without `offline_access`, logs out of that browser sign-in, and the client polls, under the default
- **THEN** the response is `invalid_grant`

### Requirement: A device-code exchange issues tokens as a code exchange does
A successful device-code exchange SHALL record a grant and answer as a code exchange does: an access token, an ID token when `openid` was granted, and a refresh token when the client is registered for the refresh grant. The ID token SHALL carry no `nonce`. `auth_time`, `acr` and `amr` SHALL come from the approving sign-in.

#### Scenario: An OpenID device grant
- **WHEN** an approved device authorization for `openid offline_access` is exchanged by a client registered for the refresh grant
- **THEN** the response holds an access token, an ID token without `nonce` and with the approving sign-in's `auth_time`, and a refresh token

### Requirement: A proof of possession on the exchange binds a device grant
A device-code exchange carrying a valid DPoP proof SHALL bind the grant to the proof's key, as a code exchange binds a public client's grant. A client required to use sender-constrained tokens SHALL be refused without a proof, by the binding's own refusal, leaving the authorization unspent.

#### Scenario: A CLI sends a DPoP proof
- **WHEN** a public client exchanges an approved device code with a valid DPoP proof
- **THEN** the access token is DPoP-bound, and a refresh without a proof of that key is refused

### Requirement: A dependency failure during a poll is not reported as pending
When the provider cannot read or write the device authorization, a poll SHALL fail as a server error, and SHALL NOT be answered with `authorization_pending`, `slow_down` or any answer that tells the client to keep polling as if nothing failed.

#### Scenario: The store is down
- **WHEN** the device authorization store fails during a poll
- **THEN** the token endpoint answers as a dependency failure, and the failure is logged without the device code
