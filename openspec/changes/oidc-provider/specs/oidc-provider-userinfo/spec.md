# Spec Delta

## Purpose

Defines the provider's UserInfo endpoint: which access tokens it accepts, which claims each scope releases, where the claims come from, and how it refuses a request.

## ADDED Requirements

### Requirement: UserInfo accepts only the provider's access tokens for an OpenID grant
The UserInfo endpoint SHALL accept GET and POST, taking the access token from the `Authorization` header, or from a POST's form body, never from the query. It SHALL accept only a valid, unexpired access token this provider issued whose scopes include `openid`, whatever its audience. A first-party token, an ID token, a refresh token or a sign-in credential SHALL be refused.

#### Scenario: Valid token
- **WHEN** a client calls UserInfo with an access token for `openid profile`
- **THEN** the response is 200 with the user's claims

#### Scenario: Token in the query
- **WHEN** a client sends the access token as `?access_token=`
- **THEN** the request is refused as carrying no token

#### Scenario: ID token presented
- **WHEN** a client presents an ID token as the access token
- **THEN** the request is refused with `invalid_token`

#### Scenario: Access token without openid
- **WHEN** a client presents an access token whose scopes lack `openid`
- **THEN** the request is refused with `insufficient_scope`

### Requirement: UserInfo refusals are bearer challenges
A refused UserInfo request SHALL be answered with 401 and a `WWW-Authenticate` challenge naming the error: `invalid_token` for a bad, expired or revoked token, `invalid_request` for a malformed request, and no error code when no token was sent. A token without the needed scope SHALL be answered 403 with `insufficient_scope`. The challenge SHALL use the `DPoP` scheme for a bound token. By default no `error_description` SHALL be sent.

#### Scenario: Expired token
- **WHEN** a client calls UserInfo with an expired access token
- **THEN** the response is 401 with `WWW-Authenticate: Bearer error="invalid_token"`

#### Scenario: No token
- **WHEN** a request to UserInfo carries no token
- **THEN** the response is 401 with a `Bearer` challenge carrying no error code

#### Scenario: Bound token presented as Bearer
- **WHEN** a DPoP-bound access token is presented with the `Bearer` scheme
- **THEN** the response is 401 with a `DPoP` challenge

### Requirement: UserInfo returns claims by scope
The UserInfo response SHALL be a JSON object, unsigned by default. It SHALL always carry `sub`, equal to the `sub` of the ID token for the same grant. Other claims SHALL be released by scope:
- `profile`: `name`, `preferred_username`, and the other profile claims the consumer's claim source provides;
- `email`: `email` and `email_verified`;
- `phone`: `phone_number` and `phone_number_verified`;
- `address`: `address`.

A claim the user does not have SHALL be omitted, never sent as null or empty.

#### Scenario: Profile scope only
- **WHEN** a token for `openid profile` is presented for a user with a name and an email
- **THEN** the response holds `sub` and `name`, and no `email`

#### Scenario: Missing claim
- **WHEN** a token for `openid email` is presented for a user without an email
- **THEN** the response holds `sub` only

### Requirement: Claims come from a replaceable claim source
The provider SHALL obtain a user's claims from a claim source. By default it SHALL read them from the identity store's user: the username as `preferred_username`, and the email and its verified state when supplied. A consumer MAY supply its own claim source, for any standard or custom claim and the scopes that release them, and its values SHALL be returned unchanged. A user who no longer exists or is disabled SHALL be refused with `invalid_token`.

#### Scenario: Consumer adds a custom claim
- **WHEN** the consumer's claim source releases `department` for the scope `org`, and a token for `openid org` is presented
- **THEN** the response holds `department` as the source returned it

#### Scenario: Disabled user
- **WHEN** a valid access token is presented for a user who has since been disabled
- **THEN** the response is 401 with `invalid_token`

#### Scenario: Claim source outage
- **WHEN** the claim source fails
- **THEN** the response is 500, and its body holds no error text

### Requirement: UserInfo responses are not cached
Every UserInfo response SHALL carry `Cache-Control: no-store`.

#### Scenario: Success response
- **WHEN** UserInfo answers 200
- **THEN** the response carries `Cache-Control: no-store`
