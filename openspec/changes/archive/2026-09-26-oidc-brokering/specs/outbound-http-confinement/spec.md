## ADDED Requirements

### Requirement: A form POST carries the caller's headers
The confined client's form POST SHALL accept request headers from its caller, as its GET already does, and SHALL send them exactly as given, adding and interpreting none of its own beyond the form content type. A request whose redirect is refused by this capability's rules SHALL NOT be sent, so a header that carries a credential, such as HTTP Basic client credentials on a token request, SHALL never reach an origin the rules refuse. A nil header SHALL be the same as no header.

#### Scenario: Basic client credentials are sent
- **WHEN** a form POST to `https://idp.example.com/token` is given an `Authorization` header with HTTP Basic credentials
- **THEN** the request carries exactly that header and the form body

#### Scenario: Credential header is not replayed across origins
- **WHEN** a form POST carrying an `Authorization` header to `https://idp.example.com/token` receives `307` to `https://evil.example.net/token`
- **THEN** no request, and so no header, is sent to `evil.example.net`

#### Scenario: No header
- **WHEN** a form POST is given no header
- **THEN** the request carries only the form content type and the body

### Requirement: A client reports the schemes it allows
The confined client SHALL report whether it allows a given URL scheme, answering exactly as its own scheme check would for a request, so a caller that validates URLs at construction applies the same rule the client enforces at request time. Scheme names SHALL be compared case-insensitively, as URL schemes are.

#### Scenario: Default client
- **WHEN** a client built with this capability's defaults is asked about `https` and `http`
- **THEN** it reports `https` allowed and `http` not allowed

#### Scenario: Consumer allows http
- **WHEN** a client built with `http` among its allowed schemes is asked about `HTTP`
- **THEN** it reports the scheme allowed
