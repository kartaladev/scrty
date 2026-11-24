## MODIFIED Requirements

### Requirement: UserInfo accepts only the provider's access tokens for an OpenID grant
The UserInfo endpoint SHALL accept GET and POST, taking the access token from the `Authorization` header, or from a POST's form body, never from the query. It SHALL accept only a valid, unexpired access token this provider issued, whose grant is not revoked, whose scopes include `openid`, and whose audience includes the issuer. A session token, an ID token, a refresh token or a sign-in credential SHALL be refused.

#### Scenario: Valid token
- **WHEN** a client calls UserInfo with an access token for `openid profile`
- **THEN** the response is 200 with the user's claims

#### Scenario: Token in the query
- **WHEN** a client sends the access token as `?access_token=`
- **THEN** the request is refused as carrying no token

#### Scenario: Token in the query beside another method
- **WHEN** a client sends `?access_token=` and also a token in the `Authorization` header
- **THEN** the request is answered 400 with `invalid_request`, and no claim is read

#### Scenario: ID token presented
- **WHEN** a client presents an ID token as the access token
- **THEN** the request is refused with `invalid_token`

#### Scenario: Token for another resource
- **WHEN** a client presents an unexpired `openid` access token whose audience is `https://api.example.com` alone
- **THEN** the request is refused with `invalid_token`

#### Scenario: Grant revoked
- **WHEN** a client presents an unexpired JWT access token of a grant since revoked
- **THEN** the request is refused with `invalid_token`

#### Scenario: Access token without openid
- **WHEN** a client presents an access token whose scopes lack `openid`
- **THEN** the request is refused with `insufficient_scope`
