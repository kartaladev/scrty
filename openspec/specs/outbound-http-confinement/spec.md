# outbound-http-confinement Specification

## Purpose

Keeps the HTTP requests scrty itself sends, such as key set fetches and identity-provider discovery or token calls, going only where configuration said, for a bounded time and a bounded size. It also makes sure a redirect target scrty hands to a browser cannot send the user to an origin the consumer never declared.

## Requirements

### Requirement: Only allowed schemes are requested
The confined client SHALL send requests only to URLs whose scheme is allowed. By default only `https` is allowed. The consumer SHALL be able to also allow `http`, which the documentation SHALL state removes transport protection. Any other scheme SHALL be refused at construction. A request to a URL that is empty, cannot be parsed, has a disallowed scheme or has no host SHALL fail before anything is sent.

#### Scenario: Plain http refused by default
- **WHEN** a key set fetch is attempted to `http://idp.example.com/jwks`
- **THEN** it fails before a connection is opened

#### Scenario: Consumer allows http for a local provider
- **WHEN** the consumer allows `http` and a fetch targets `http://localhost:8080/jwks`
- **THEN** the request is sent

#### Scenario: Unsupported scheme
- **WHEN** the consumer tries to allow `ftp`
- **THEN** construction fails

### Requirement: Initial targets can be restricted to allowed origins
The consumer SHALL be able to give the confined client a list of allowed origins. When one is given, a request whose target origin is not on it SHALL fail before anything is sent. When none is given, the client SHALL send to the origin the calling component's configuration names, subject to every other rule here.

#### Scenario: Origin not allowed
- **WHEN** the allowed origins are `https://idp.example.com` and a token request targets `https://evil.example.net/token`
- **THEN** the request fails before it is sent

#### Scenario: Default port equivalence
- **WHEN** the allowed origins are `https://idp.example.com:443` and a request targets `https://IDP.example.com/token`
- **THEN** the request is allowed

### Requirement: Redirects stay on the starting origin and scheme
The confined client SHALL follow a redirect only when the new target uses `https`, or an allowed scheme when the consumer allowed more, and has the same origin as the URL the request started with. Any other redirect SHALL fail the request without sending the redirected request. A redirect check the consumer's own client already carried SHALL run after the library's checks.

#### Scenario: Off-origin redirect
- **WHEN** `https://idp.example.com/jwks` redirects to `https://cdn.example.net/jwks`
- **THEN** the fetch fails and no request is sent to `cdn.example.net`

#### Scenario: Downgrade redirect
- **WHEN** `https://idp.example.com/jwks` redirects to `http://idp.example.com/jwks`
- **THEN** the fetch fails

#### Scenario: Same-origin redirect
- **WHEN** `https://idp.example.com/jwks` redirects to `https://idp.example.com/keys`
- **THEN** the redirect is followed

#### Scenario: Consumer redirect check still runs
- **WHEN** the consumer's client carries its own redirect check that refuses every redirect, and a same-origin redirect arrives
- **THEN** the request fails

### Requirement: Redirect chains are capped
The confined client SHALL follow at most 10 redirects per request by default, and SHALL fail the request at the next one. The consumer SHALL be able to change the cap. Zero SHALL mean redirects are never followed. A negative cap SHALL be refused at construction.

#### Scenario: Endless same-origin loop
- **WHEN** a provider answers every request with a redirect to another path on its own origin
- **THEN** the request fails after 10 redirects instead of running until the timeout

#### Scenario: Redirects disabled
- **WHEN** the consumer sets the cap to zero and the target redirects
- **THEN** the request fails without following it

### Requirement: The final URL is re-checked
Before a response is accepted, the confined client SHALL check the URL that actually produced the response against the scheme, allowed-origin and same-origin rules. A response from any other URL SHALL be rejected, and its content SHALL NOT be returned.

#### Scenario: Redirect followed by a consumer transport
- **WHEN** a consumer-supplied transport follows a redirect itself and the response comes from `https://evil.example.net/token`
- **THEN** the response is rejected and its content is not returned

### Requirement: A request body is never replayed to another origin by the library
The confined client SHALL accept a consumer-supplied client only in a form whose redirect handling it can install. As a result, a `307` or `308` redirect that would resend a request body to another origin SHALL be refused before the redirected request is sent. A token request carrying a client secret and an authorization code is an example of such a body. The documentation SHALL state that a consumer transport which follows redirects on its own bypasses this, leaving only the final-URL re-check.

#### Scenario: Token endpoint redirects with 307
- **WHEN** a token request to `https://idp.example.com/token` receives `307` to `https://evil.example.net/token`
- **THEN** no request, and so no client secret, is sent to `evil.example.net`

### Requirement: Requests are bounded in time
Each request through the confined client SHALL complete within a bounded time, 10 seconds by default, whatever client the consumer supplied. An earlier deadline on the caller's context SHALL take precedence. The consumer SHALL be able to change the bound. A bound of zero or less SHALL be refused at construction.

#### Scenario: Unresponsive provider
- **WHEN** a provider accepts the connection and never answers
- **THEN** the request fails within 10 seconds

#### Scenario: Consumer client without a timeout
- **WHEN** the consumer supplies a client with no timeout and a provider never answers
- **THEN** the request still fails within 10 seconds

#### Scenario: Consumer bound
- **WHEN** the consumer sets the bound to 3 seconds and a provider never answers
- **THEN** the request fails within 3 seconds

### Requirement: Response bodies are bounded
The confined client SHALL read at most a bounded number of response body bytes, 1 MiB by default, and SHALL never read beyond it. A document that does not fit SHALL therefore fail to parse and SHALL NOT be used. The consumer SHALL be able to change the limit. A limit of zero or less SHALL be refused at construction.

#### Scenario: Oversized key set
- **WHEN** a key set endpoint returns a 5 MiB body
- **THEN** at most 1 MiB is read, the fetch fails, and no keys are loaded from it

#### Scenario: Consumer limit
- **WHEN** the consumer raises the limit to 4 MiB and a 2 MiB discovery document is returned
- **THEN** the document is read in full

### Requirement: Origin comparison refuses what it cannot normalise
Two URLs SHALL have the same origin only when both use `http` or `https` and both have a host, and their scheme, host and port are equal after only these steps:
- ASCII case folding of scheme and host;
- removal of a port equal to the scheme's default.

The comparison SHALL NOT apply Unicode case mapping or IDNA mapping. It SHALL NOT compare ports numerically, SHALL NOT strip a trailing root label, and SHALL ignore userinfo. A URL that cannot be parsed, has another scheme or has no host SHALL match nothing, including another such URL.

#### Scenario: Case and default port
- **WHEN** `https://IdP.Example.com:443/a` is compared with `https://idp.example.com/b`
- **THEN** they have the same origin

#### Scenario: Unicode look-alike
- **WHEN** a host containing U+0130 is compared with the same host spelled with ASCII `i`
- **THEN** they are different origins

#### Scenario: Two unparsable values
- **WHEN** `mailto:a@b` is compared with `mailto:c@d`
- **THEN** they do not have the same origin

### Requirement: Browser redirect targets are host-relative or declared
A redirect-target allowlist that scrty uses to send a browser somewhere after a flow SHALL accept an entry only in one of two forms:
- a host-relative path that starts with `/`, is not followed by `/` or `\`, contains no whitespace or control character, and carries no scheme or host;
- an absolute `http` or `https` URL without userinfo, whose origin is in a separately declared list of allowed origins.

Each declared origin SHALL be a scheme, a host and an optional port, optionally followed by a lone `/`, with no other path, query, fragment or userinfo. It SHALL use `https`, except that `http` is permitted on a loopback host.

Any other entry or declaration SHALL be refused at construction, naming the entry and the option at fault. At request time, a requested target SHALL be used only when it exactly equals an entry that is still acceptable under these rules. Otherwise the safe default `/` SHALL be used. By default no origins are declared, so only host-relative entries are accepted.

#### Scenario: Protocol-relative entry
- **WHEN** the consumer configures the allowlist entry `//partner.example.com/landing`
- **THEN** construction fails naming that entry

#### Scenario: Undeclared absolute entry
- **WHEN** the consumer configures the entry `https://partner.example.com/landing` and declares no origins
- **THEN** construction fails naming that entry and the origin declaration it needs

#### Scenario: Cleartext declared origin
- **WHEN** the consumer declares the origin `http://partner.example.com`
- **THEN** construction fails, while `http://localhost:3000` would be accepted

#### Scenario: Consumer declares a partner origin
- **WHEN** the consumer declares the origin `https://partner.example.com` and configures the entry `https://partner.example.com/landing`
- **THEN** a flow asked to return to that exact URL redirects there

#### Scenario: Unlisted request falls back
- **WHEN** a flow is asked to return to `/\evil.example.net` and that value is not an entry
- **THEN** the browser is redirected to `/`

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
