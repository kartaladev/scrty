## MODIFIED Requirements

### Requirement: The verify endpoint resolves the challenge and rotates the session
The verify endpoint SHALL match only POST requests to its path, and SHALL read the code from the `code` field of a URL-encoded POST body only, never from the URL query. A body that carries no code, is not a URL-encoded form, or does not parse SHALL be refused as missing credentials before any code is checked, and SHALL NOT be counted against the verification throttle; the endpoint's documentation SHALL state that only a URL-encoded body is read. The default path SHALL be `/mfa/totp`, replaceable by an option. A request with no session SHALL be refused as authentication required, and so SHALL a request whose session carries no resolved caller — the credential the endpoint issues names a principal, so a session without one cannot be answered. Both refusals SHALL happen before the code is read.

The endpoint SHALL be given a token generator at construction, and a chain that enables it without one SHALL fail to assemble: the endpoint's whole purpose on success is to hand back a credential for the rotated session, and it has none to issue without a generator.

On a valid code the endpoint SHALL:
- resolve the session's MFA challenge, which records the second-factor-satisfied time;
- rotate the session handle;
- write the response itself, through a replaceable responder that receives the rotated session;
- answer with a success status without passing the request to later handlers.

Because the endpoint answers the request itself, no later handler runs, so the rotated handle SHALL
reach the caller through that responder or not at all. With no responder supplied the library SHALL
write a credential the caller can use for its next request; a consumer SHALL be able to replace that
whole response, for example to set a cookie instead.

Rotation SHALL NOT strand the caller: a caller that completes its second factor SHALL be able to
make an authenticated request afterwards without signing in again.

On any failure the challenge SHALL stay pending, the handle SHALL be unchanged, and the error SHALL propagate to the consumer's error handling unchanged.

#### Scenario: Successful verification
- **WHEN** a session with the MFA challenge pending posts a valid code
- **THEN** the session reports no pending challenge and a second-factor-satisfied time
- **AND** the previous session handle no longer loads
- **AND** the response carries a credential naming the rotated session, so the next request authenticates

#### Scenario: The caller is not stranded by rotation
- **WHEN** a bearer caller completes its second factor and then requests a protected route with the credential the verify response returned
- **THEN** the request is authenticated and reaches the handler

#### Scenario: Consumer responder
- **WHEN** the endpoint is configured with a responder that sets a session cookie and writes no body
- **THEN** that responder writes the response instead of the library's default
- **AND** it receives the rotated session

#### Scenario: A session with no resolved caller
- **WHEN** a request to the verify path carries a session but no resolved caller
- **THEN** it is refused as authentication required, and no code is read and no failure is recorded

#### Scenario: No token generator
- **WHEN** a chain enables the verify endpoint without a token generator
- **THEN** assembly fails with a configuration error

#### Scenario: Wrong code
- **WHEN** a session with the MFA challenge pending posts a wrong code
- **THEN** the invalid-code error propagates
- **AND** the challenge stays pending and the handle is unchanged

#### Scenario: GET is not verification
- **WHEN** a GET request is made to the verify path
- **THEN** it passes through without verifying anything

#### Scenario: Consumer path
- **WHEN** the endpoint is configured with path `/auth/second-factor` and a pending session posts a valid code there
- **THEN** the challenge is resolved

#### Scenario: Code in the query string
- **WHEN** a session with the MFA challenge pending posts to the verify path with a valid code in the query string and an empty body
- **THEN** it is refused as missing credentials
- **AND** the challenge stays pending and no failure is counted

#### Scenario: Code in the query overrides nothing
- **WHEN** a pending session posts a wrong code in the body and a valid code in the query string
- **THEN** the invalid-code error propagates and the challenge stays pending

#### Scenario: Unreadable body
- **WHEN** a pending session posts a valid code as a multipart form
- **THEN** it is refused as missing credentials, the challenge stays pending, and no failure is counted
