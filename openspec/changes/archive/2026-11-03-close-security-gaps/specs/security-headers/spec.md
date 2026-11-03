## Purpose

Sets the response headers that make browsers enforce HTTPS, refuse injected scripts and framing, and isolate the application's pages, with a fresh script nonce handed to the application's templates.

## ADDED Requirements

### Requirement: Security headers are off until enabled
The chain SHALL set no security response header beyond those it already sets on credential responses until the consumer enables the security-headers layer. Once enabled, the layer SHALL run outside every built-in interceptor, and SHALL set its headers on the response before calling the next one, so that every response the chain produces carries them, including the chain's own refusals and a CORS preflight answer, on every adapter. A consumer interceptor registered ahead of the layer runs outside it, and a response it writes carries no security headers; the documentation SHALL say so. Enabling the layer more than once SHALL fail construction.

#### Scenario: Not enabled
- **WHEN** a chain built without the security-headers layer answers a request
- **THEN** the response carries none of `Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options`, `Referrer-Policy` or `Cross-Origin-Opener-Policy`

#### Scenario: A refusal carries the headers
- **WHEN** the layer is enabled and the chain refuses an unauthenticated request with 401
- **THEN** the 401 response carries the same security headers as a successful response to that route

#### Scenario: Every adapter
- **WHEN** the layer is enabled and the same refusal is produced behind net/http, gin and fiber, each with its default error handling
- **THEN** all three responses carry the same security headers

### Requirement: Document responses get the strict default set
With the layer enabled and no profile matched, a response SHALL carry:
- `Content-Security-Policy` with `script-src 'nonce-<nonce>' 'strict-dynamic'`, `object-src 'none'`, `base-uri 'none'` and `frame-ancestors 'none'`;
- `X-Content-Type-Options: nosniff`;
- `Referrer-Policy: strict-origin-when-cross-origin`;
- `Cross-Origin-Opener-Policy: same-origin-allow-popups`.

It SHALL NOT send `X-XSS-Protection`, `X-Frame-Options`, `Cross-Origin-Embedder-Policy` or `Origin-Agent-Cluster` unless the consumer configures them. The consumer SHALL be able to replace any header's value, add directives to the policy, or remove a header. A directive the consumer adds under a name the default already uses SHALL replace the default's sources for that directive, not duplicate it. A directive name or source holding a `;`, a `,` or a line break SHALL fail construction. A policy with no directive, given as the enforced or the report-only policy of the document profile or of any consumer or API profile, SHALL fail construction with a configuration error naming the option it was given to, so an empty policy never replaces the default; a consumer who wants no policy on a profile removes the header.

#### Scenario: Default document response
- **WHEN** the layer is enabled with no options and a page is served
- **THEN** the response carries the four headers above with those values, and none of the four headers it does not send by default

#### Scenario: Consumer adds a directive
- **WHEN** the consumer adds `img-src 'self' data:` to the policy
- **THEN** the `Content-Security-Policy` header carries that directive alongside the defaults

#### Scenario: Consumer replaces a default directive
- **WHEN** the consumer sets `frame-ancestors 'self'`
- **THEN** the policy carries `frame-ancestors 'self'` once, and not `frame-ancestors 'none'`

#### Scenario: Header injection in a directive
- **WHEN** the consumer adds a source `'self'; script-src *`
- **THEN** building the chain fails with a configuration error naming the policy

#### Scenario: Policy with no directive
- **WHEN** the consumer gives a policy with no directive as the document profile's policy, as an API profile's policy, or as the report-only policy
- **THEN** building the chain fails with a configuration error naming the option, and no response carries an empty `Content-Security-Policy` or `Content-Security-Policy-Report-Only`

#### Scenario: Empty policy set as a raw header
- **WHEN** the consumer sets `Content-Security-Policy` or `Content-Security-Policy-Report-Only` to an empty or blank value with the raw header editor
- **THEN** building the chain fails with a configuration error that points to removing the header instead

#### Scenario: Policy removed explicitly
- **WHEN** the consumer removes `Content-Security-Policy` from an API profile
- **THEN** the chain is built and that profile's responses carry no `Content-Security-Policy`

### Requirement: API responses get a minimal profile chosen by route
The consumer SHALL be able to assign a header profile to the routes a matcher selects, by path prefix or by a function of the request. The library SHALL provide an API profile that sets `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`, `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`, and sets no nonce. The first profile whose matcher selects a request SHALL apply; a request no profile selects SHALL get the document set. The layer SHALL NOT choose a profile by inspecting the response. A path-prefix matcher SHALL match whole path segments, so `/api/` does not select `/apix`.

#### Scenario: API route
- **WHEN** the API profile is assigned to the path prefix `/api/` and a request for `/api/orders` is answered
- **THEN** the response carries the API profile's headers and no nonce is generated

#### Scenario: First match wins
- **WHEN** a consumer profile is assigned to `/api/admin/` and then the API profile to `/api/`, and `/api/admin/users` is requested
- **THEN** the consumer profile applies

### Requirement: Each document response has its own unpredictable nonce
For every request the document profile serves, the layer SHALL generate a nonce of at least 128 bits from a cryptographically secure source, encoded in base64, place it in the policy, and make it readable by the handler from the request context. Two responses SHALL NOT share a nonce. A failure to read randomness SHALL fail the request with a server error rather than serve a predictable nonce or no policy. A request the layer does not serve with a nonce SHALL find no nonce in its context.

#### Scenario: Nonce reaches the handler
- **WHEN** a handler behind the layer reads the nonce from its request context
- **THEN** the value equals the one in that response's `Content-Security-Policy` header

#### Scenario: Two responses
- **WHEN** the same page is requested twice
- **THEN** the two responses carry different nonces

#### Scenario: Randomness fails
- **WHEN** the random source returns an error while a document response is served
- **THEN** the request fails with a server error and the handler does not run

#### Scenario: No nonce on an API route
- **WHEN** a handler on a route the API profile selects reads the nonce
- **THEN** it finds none

### Requirement: HSTS is sent only on secure requests
With the layer enabled, a response to a request the chain judges secure SHALL carry `Strict-Transport-Security: max-age=31536000; includeSubDomains`. A response to a request not judged secure SHALL NOT carry it. The consumer SHALL be able to set the maximum age, including zero to withdraw an earlier policy, and to drop `includeSubDomains`. `preload` SHALL be added only when the consumer opts in, and opting into `preload` with a `max-age` below one year or without `includeSubDomains` SHALL fail construction. A negative maximum age SHALL fail construction.

#### Scenario: Plain HTTP
- **WHEN** the layer is enabled and a request arrives over plain HTTP with no trusted proxy declaring otherwise
- **THEN** the response carries no `Strict-Transport-Security` header

#### Scenario: HTTPS through a trusted proxy
- **WHEN** a trusted proxy forwards scheme `https` for a request the app receives over plain HTTP
- **THEN** the response carries `Strict-Transport-Security`

#### Scenario: Forged scheme from an untrusted peer
- **WHEN** trusted proxies are configured and an untrusted peer sends `X-Forwarded-Proto: https` over plain HTTP
- **THEN** the response carries no `Strict-Transport-Security` header

#### Scenario: Withdrawing the policy
- **WHEN** the consumer sets the maximum age to zero and a secure request is answered
- **THEN** the response carries `Strict-Transport-Security: max-age=0; includeSubDomains`

#### Scenario: Preload without subdomains
- **WHEN** the consumer opts into `preload` and removes `includeSubDomains`
- **THEN** building the chain fails with a configuration error naming the HSTS option

### Requirement: A handler's own header value wins
When the handler sets a header the layer also sets, the handler's value SHALL be the one sent. The layer SHALL NOT wrap the response writer, so streaming, flushing and connection hijacking behave as they do without the layer.

#### Scenario: Handler overrides Referrer-Policy
- **WHEN** the layer is enabled and the handler sets `Referrer-Policy: no-referrer`
- **THEN** the response carries `Referrer-Policy: no-referrer`

#### Scenario: Server-sent events
- **WHEN** a handler behind the layer flushes a streamed response
- **THEN** the flush succeeds as it does without the layer

#### Scenario: Connection upgrade
- **WHEN** a handler behind the layer hijacks the connection for a WebSocket upgrade
- **THEN** the hijack succeeds as it does without the layer

### Requirement: The policy can be reported without being enforced
The consumer SHALL be able to send the policy as `Content-Security-Policy-Report-Only` instead of, or alongside, the enforced policy, and SHALL be able to name a reporting endpoint, which the layer sends as `Reporting-Endpoints` and references with both `report-to` and `report-uri`. A reporting endpoint SHALL be an absolute `https` URL, or construction SHALL fail. When both policies are sent, they SHALL carry the same nonce.

#### Scenario: Report-only rollout
- **WHEN** the consumer selects report-only mode with a reporting endpoint
- **THEN** responses carry `Content-Security-Policy-Report-Only` with the nonce policy, no enforced `Content-Security-Policy`, and a `Reporting-Endpoints` header

#### Scenario: Both policies
- **WHEN** the consumer enforces the policy and also reports a stricter candidate
- **THEN** responses carry both headers, with one nonce shared between them

#### Scenario: Plain-HTTP reporting endpoint
- **WHEN** the consumer names `http://reports.example.com/csp` as the reporting endpoint
- **THEN** building the chain fails with a configuration error naming the reporting endpoint

### Requirement: A hash-based preset serves static single-page builds
The library SHALL provide a policy preset for a static page that lists script hashes the consumer supplies instead of a nonce, so the page can be cached. Selecting it SHALL generate no nonce. A hash that is not a base64 SHA-256, SHA-384 or SHA-512 digest SHALL fail construction, as SHALL the preset with no hash.

#### Scenario: Static shell
- **WHEN** the consumer selects the hash preset with one SHA-256 script hash
- **THEN** the policy's `script-src` lists that hash, and no nonce is generated

#### Scenario: Malformed hash
- **WHEN** the consumer selects the hash preset with `sha256-not-base64!`
- **THEN** building the chain fails with a configuration error naming the hash preset
