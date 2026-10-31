## MODIFIED Requirements

### Requirement: The net/http chain attributes requests to the transport peer
The net/http integration SHALL attribute a request to the host part of its transport peer address by default, and SHALL NOT read any forwarding header unless the consumer configures trusted proxies, in which case attribution SHALL follow the `trusted-proxies` capability. A peer address that is not in host and port form SHALL yield no client address. No framework's own proxy configuration SHALL change the chain's attribution.

#### Scenario: Spoofed header ignored
- **WHEN** no trusted proxies are configured and a client connecting from 198.51.100.7 sends `X-Forwarded-For: 203.0.113.9`
- **THEN** the request is attributed to 198.51.100.7

#### Scenario: Peer without a port
- **WHEN** a request arrives over a transport whose peer address has no port
- **THEN** the request has no client address

#### Scenario: Trusted proxy
- **WHEN** 10.20.0.2 is a trusted proxy for `X-Forwarded-For` and a request from it carries `X-Forwarded-For: 203.0.113.9`
- **THEN** the request is attributed to 203.0.113.9

## ADDED Requirements

### Requirement: Requests expose their host and whether they arrived securely
Every request an interceptor judges SHALL expose its host and whether it arrived over a secure transport, as resolved by the chain: from the transport and the `Host` header by default, from the deployment declaration when the consumer declares the deployment HTTPS, and from trusted proxies when configured. Every adapter the library provides SHALL supply both.

#### Scenario: Direct TLS
- **WHEN** a request arrives over TLS for host `app.example.com` with no trusted proxies configured
- **THEN** an interceptor sees host `app.example.com` and a secure request

#### Scenario: Plain HTTP
- **WHEN** a request arrives over plain HTTP with no proxy configuration and no deployment declaration
- **THEN** an interceptor sees an insecure request

### Requirement: Browser-hardening layers run outside every authentication interceptor
The library SHALL publish three named slots ahead of every existing slot, in this order: security headers, then CORS, then CSRF protection. Each SHALL be empty unless its layer is enabled. Client resolution through trusted proxies SHALL happen before the first interceptor runs. Every response the chain produces, including a CORS preflight answer and a CSRF refusal, SHALL pass through the security-headers slot.

#### Scenario: Preflight carries the headers
- **WHEN** security headers and CORS are enabled and an allowed preflight is answered
- **THEN** the 204 response carries `X-Content-Type-Options: nosniff`

#### Scenario: Consumer interceptor before CORS
- **WHEN** a consumer registers an interceptor immediately before the CORS slot
- **THEN** it runs after the security-headers layer and before the CORS layer

### Requirement: Users can list and end their own sessions
When enabled, the chain SHALL offer endpoints, under `/sessions` by default with a replaceable prefix, that let an authenticated user:
- list their live sessions, marking the one making the request, with creation and last-use times, and the sign-in metadata recorded for each when metadata recording is on;
- end one of their sessions, which revokes that session's family;
- end every session except the current one.

The listing SHALL never return session identifiers, only opaque handles valid for that user. Ending sessions SHALL require a recent authentication, judged by the recency check of the `reauthentication` capability. Ending another user's session through a handle SHALL be refused as not found. The endpoints SHALL be off by default.

#### Scenario: Sign out other devices
- **WHEN** a user with three live sessions, who authenticated 2 minutes ago, ends every session except the current one
- **THEN** the other two sessions and their families are revoked and the current one remains

#### Scenario: Stale session
- **WHEN** a user who authenticated 2 hours ago asks to end one of their sessions with the default recency window
- **THEN** the request is refused with the reauthentication-required error and nothing is revoked

#### Scenario: Another user's handle
- **WHEN** a user presents a session handle that belongs to another user
- **THEN** the request is refused as not found

### Requirement: Login upgrades an outdated password hash when the consumer supplies a write
When the consumer supplies a rehash write, a successful password login whose stored hash the matching encoder reports as needing an upgrade SHALL re-encode the submitted password with the current encoder and pass the new hash to the write, after the login succeeds and on the same request. Neither the re-encoding nor the write SHALL fail the login: an error from either SHALL be logged without the password or any hash. Without a write, no rehash SHALL happen.

#### Scenario: Raised cost
- **WHEN** the encoder is Argon2id at 128 MiB, a user's stored hash is Argon2id at 64 MiB, a rehash write is configured, and the user logs in
- **THEN** the login succeeds and the write receives a new Argon2id hash at 128 MiB

#### Scenario: No write configured
- **WHEN** the same login happens with no rehash write
- **THEN** no new hash is produced

### Requirement: Logout can clear the browser's site data
When the consumer opts in, a successful logout response SHALL carry `Clear-Site-Data` with the directives the consumer chooses from `"cache"`, `"cookies"` and `"storage"`. It SHALL be sent only on a secure request. By default no `Clear-Site-Data` header SHALL be sent.

#### Scenario: Opted in
- **WHEN** the consumer opts into clearing `"cache"` and `"storage"` and a user logs out over HTTPS
- **THEN** the logout response carries `Clear-Site-Data: "cache", "storage"`

### Requirement: A sign-in from an unseen device can notify the user
When the consumer opts in and sign-in metadata recording is on, a completed login whose metadata matches none of the user's sessions of the last 90 days, a replaceable period, SHALL send the user a notice through the sending port, after the login completes and without delaying it. The notice SHALL contain the time and coarse device description, never a token or link secret. Construction SHALL fail when the notice is enabled without metadata recording or without a sender.

#### Scenario: New browser
- **WHEN** the notice is on and a user signs in from a browser whose metadata matches none of their recent sessions
- **THEN** the user receives a sign-in notice

#### Scenario: Notice without metadata
- **WHEN** the consumer enables the notice with metadata recording off
- **THEN** building the chain fails with a configuration error naming the notice
