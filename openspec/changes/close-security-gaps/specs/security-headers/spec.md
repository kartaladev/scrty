## Purpose

Sets the response headers that make browsers enforce HTTPS, refuse injected scripts and framing, and isolate the application's pages, with a fresh script nonce handed to the application's templates.

## ADDED Requirements

### Requirement: Security headers are off until enabled
The chain SHALL set no security response header beyond those it already sets on credential responses until the consumer enables the security-headers layer. Once enabled, the layer SHALL run outside every authentication interceptor, so that every response the chain produces carries the headers, including the chain's own refusals.

#### Scenario: Not enabled
- **WHEN** a chain built without the security-headers layer answers a request
- **THEN** the response carries none of `Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options`, `Referrer-Policy` or `Cross-Origin-Opener-Policy`

#### Scenario: A refusal carries the headers
- **WHEN** the layer is enabled and the chain refuses an unauthenticated request with 401
- **THEN** the 401 response carries the same security headers as a successful response to that route

### Requirement: Document responses get the strict default set
With the layer enabled and no profile matched, a response SHALL carry:
- `Content-Security-Policy` with `script-src 'nonce-<nonce>' 'strict-dynamic'`, `object-src 'none'`, `base-uri 'none'` and `frame-ancestors 'none'`;
- `X-Content-Type-Options: nosniff`;
- `Referrer-Policy: strict-origin-when-cross-origin`;
- `Cross-Origin-Opener-Policy: same-origin-allow-popups`.

It SHALL NOT send `X-XSS-Protection`, `X-Frame-Options`, `Cross-Origin-Embedder-Policy` or `Origin-Agent-Cluster` unless the consumer configures them. The consumer SHALL be able to replace any header's value, add directives to the policy, or remove a header.

#### Scenario: Default document response
- **WHEN** the layer is enabled with no options and a page is served
- **THEN** the response carries the four headers above with those values, and none of the four headers it does not send by default

#### Scenario: Consumer adds a directive
- **WHEN** the consumer adds `img-src 'self' data:` to the policy
- **THEN** the `Content-Security-Policy` header carries that directive alongside the defaults

### Requirement: API responses get a minimal profile chosen by route
The consumer SHALL be able to assign a header profile to the routes a matcher selects. The library SHALL provide an API profile that sets `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`, `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`, and sets no nonce. The first profile whose matcher selects a request SHALL apply; a request no profile selects SHALL get the document set. The layer SHALL NOT choose a profile by inspecting the response.

#### Scenario: API route
- **WHEN** the API profile is assigned to the path prefix `/api/` and a request for `/api/orders` is answered
- **THEN** the response carries the API profile's headers and no nonce is generated

### Requirement: Each document response has its own unpredictable nonce
For every request the document profile serves, the layer SHALL generate a nonce of at least 128 bits from a cryptographically secure source, place it in the policy, and make it readable by the handler from the request context. Two responses SHALL NOT share a nonce. A failure to read randomness SHALL fail the request with a server error rather than serve a predictable nonce.

#### Scenario: Nonce reaches the handler
- **WHEN** a handler behind the layer reads the nonce from its request context
- **THEN** the value equals the one in that response's `Content-Security-Policy` header

#### Scenario: Two responses
- **WHEN** the same page is requested twice
- **THEN** the two responses carry different nonces

### Requirement: HSTS is sent only on secure requests
With the layer enabled, a response to a request the chain judges secure SHALL carry `Strict-Transport-Security: max-age=31536000; includeSubDomains`. A response to a request not judged secure SHALL NOT carry it. `preload` SHALL be added only when the consumer opts in, and opting into `preload` with a `max-age` below one year or without `includeSubDomains` SHALL fail construction.

#### Scenario: Plain HTTP
- **WHEN** the layer is enabled and a request arrives over plain HTTP with no trusted proxy declaring otherwise
- **THEN** the response carries no `Strict-Transport-Security` header

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

### Requirement: The policy can be reported without being enforced
The consumer SHALL be able to send the policy as `Content-Security-Policy-Report-Only` instead of, or alongside, the enforced policy, and SHALL be able to name a reporting endpoint, which the layer sends as `Reporting-Endpoints` and references with both `report-to` and `report-uri`.

#### Scenario: Report-only rollout
- **WHEN** the consumer selects report-only mode with a reporting endpoint
- **THEN** responses carry `Content-Security-Policy-Report-Only` with the nonce policy, no enforced `Content-Security-Policy`, and a `Reporting-Endpoints` header

### Requirement: A hash-based preset serves static single-page builds
The library SHALL provide a policy preset for a static page that lists script hashes the consumer supplies instead of a nonce, so the page can be cached. Selecting it SHALL generate no nonce.

#### Scenario: Static shell
- **WHEN** the consumer selects the hash preset with one SHA-256 script hash
- **THEN** the policy's `script-src` lists that hash, and no nonce is generated
