# Spec Delta

## MODIFIED Requirements

### Requirement: The code exchange authenticates the client and hides provider detail
After completing the flow, the library SHALL exchange the authorization code at the provider's token endpoint. The exchange SHALL carry the flow's PKCE verifier and the configured redirect URL. It SHALL authenticate the client with the client id and secret in the request body by default, or with HTTP Basic client credentials when the provider is configured for that method. The request SHALL be sent through the confined client's form POST, so the rule that no request body is replayed to another origin covers it. A provider error response, a malformed response or a response without an ID token SHALL fail the login as a provider failure. The provider's response body SHALL be logged at most in bounded form and SHALL never be returned to the caller. Unless the provider is configured to keep tokens for forwarding, the provider's refresh token SHALL be discarded, and the provider's access token SHALL be kept only in memory, for the callback that received it, and offered only as the upstream access of the requirement that upstream access reaches only a broker that asks for it; the library SHALL keep no reference to it once that callback returns. For a provider configured to keep tokens, the provider's tokens SHALL be kept on the session as the requirement that a forwarding provider's tokens are kept on the session states, and nowhere else.

#### Scenario: Default client authentication
- **WHEN** a code is exchanged for provider `corp` with no client authentication method configured
- **THEN** the token request carries `client_id` and `client_secret` as form fields and no authorization header
- **AND** it carries the code verifier

#### Scenario: Consumer selects HTTP Basic
- **WHEN** provider `corp` is configured for HTTP Basic client authentication
- **THEN** the token request carries the client id and secret in an HTTP Basic authorization header and no `client_secret` form field

#### Scenario: Provider rejects the code
- **WHEN** the token endpoint answers `invalid_grant` with a description
- **THEN** the login fails as a provider failure
- **AND** the description does not appear in the response to the browser

#### Scenario: Access token outlives no callback
- **WHEN** a callback for a provider not configured to keep tokens receives a token response carrying an access token and a refresh token, and completes
- **THEN** neither token is stored in the flow, handoff or session records, and the callback result's forwarding tokens are empty

## ADDED Requirements

### Requirement: A forwarding provider's tokens are kept on the session
For a provider configured to keep tokens for forwarding, a successful callback SHALL record on the session it creates, in the same write, the access token, the refresh token when one was issued, and the access token's expiry. The tokens SHALL NOT be stored in the flow or handoff records. The callback result SHALL carry them only as a value that prints redacted, and that value SHALL be empty for every provider not configured to keep tokens.

#### Scenario: Consumer configures forwarding
- **WHEN** provider `corp` is configured to keep tokens, and its callback receives access token `at-1` with `expires_in` 3600 and refresh token `rt-1` at 10:00:00
- **THEN** the session created holds `at-1`, `rt-1` and an access-token expiry of 11:00:00
- **AND** the flow and handoff records hold neither token, and the callback result printed with `%+v` contains neither

#### Scenario: No refresh token issued
- **WHEN** a forwarding provider's token response carries no refresh token
- **THEN** the session holds the access token and its expiry, and no refresh token

#### Scenario: Token response without an access token
- **WHEN** a forwarding provider's token response carries an ID token and no access token
- **THEN** the login proceeds and the session holds no provider tokens

### Requirement: A forwarding provider's oversized token fails the login
For a provider configured to keep tokens, an access token or refresh token longer than 16 KiB SHALL fail the login as a provider failure, and no session SHALL be created.

#### Scenario: Oversized access token
- **WHEN** a forwarding provider returns an access token of 20 KiB
- **THEN** the login fails as a provider failure and no session is stored
