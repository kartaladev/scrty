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
Every request an interceptor judges SHALL expose its host and whether it arrived over a secure transport, as resolved by the chain: from the transport and the `Host` header by default, from the deployment declaration when the consumer declares the deployment HTTPS, and from trusted proxies when configured. Every adapter the library provides SHALL supply both. A consumer's own request implementation SHALL supply both too, and the chain SHALL read them only through the request, never from the framework.

#### Scenario: Direct TLS
- **WHEN** a request arrives over TLS for host `app.example.com` with no trusted proxies configured
- **THEN** an interceptor sees host `app.example.com` and a secure request

#### Scenario: Plain HTTP
- **WHEN** a request arrives over plain HTTP with no proxy configuration and no deployment declaration
- **THEN** an interceptor sees an insecure request

#### Scenario: Declared HTTPS deployment
- **WHEN** the consumer declares the deployment HTTPS and a request arrives over plain HTTP
- **THEN** an interceptor sees a secure request and the `Host` header's host

### Requirement: Browser-hardening layers run outside every authentication interceptor
The library SHALL publish three named slots ahead of every existing slot, in this order: security headers, then CORS, then CSRF protection. Each SHALL be empty unless its layer is enabled. Client resolution through trusted proxies SHALL happen before the first interceptor runs, and a host-not-allowed refusal, which no interceptor sees, SHALL still carry the headers the security-headers layer would set for that request. Every response the chain produces, including a CORS preflight answer and a CSRF refusal, SHALL pass through the security-headers slot.

#### Scenario: Preflight carries the headers
- **WHEN** security headers and CORS are enabled and an allowed preflight is answered
- **THEN** the 204 response carries `X-Content-Type-Options: nosniff`

#### Scenario: Consumer interceptor before CORS
- **WHEN** a consumer registers an interceptor immediately before the CORS slot
- **THEN** it runs after the security-headers layer and before the CORS layer

#### Scenario: Host refusal carries the headers
- **WHEN** security headers and trusted proxies are enabled and a request is refused as host-not-allowed
- **THEN** the 400 response carries `X-Content-Type-Options: nosniff`

### Requirement: Users can list and end their own sessions
When enabled, the chain SHALL offer endpoints, under `/sessions` by default with a replaceable prefix, that let a user with a full session:
- list their live sign-ins as the `sessions` capability defines, marking the one making the request, also when the request presents a predecessor still within its grace window;
- end one of their sign-ins by handle, which revokes that sign-in's family; ending the current one SHALL act as a logout;
- end every sign-in except the current one.

The listing SHALL never return session identifiers, only opaque handles valid for that user. Ending sign-ins SHALL require a recent authentication, judged by the recency check of the `reauthentication` capability, with its default window and the consumer's override; listing SHALL NOT. A recovery-pending or second-factor-pending session SHALL be refused as the chain refuses such sessions on any other route. A handle that is malformed, unknown or another user's SHALL be refused as not found, and nothing SHALL be revoked. Every response SHALL carry `Cache-Control: no-store`. A session-store failure SHALL fail the request as a dependency failure, and a request whose own context ended SHALL fail with that context's error. The endpoints SHALL be off by default, and enabling them without a session manager SHALL fail construction.

#### Scenario: Sign out other devices
- **WHEN** a user with three live sign-ins, who authenticated 2 minutes ago, ends every sign-in except the current one
- **THEN** the other two families are revoked and the current one remains

#### Scenario: Only the current sign-in
- **WHEN** a user whose only live sign-in is the current one ends every sign-in except the current one
- **THEN** nothing is revoked, and the request succeeds

#### Scenario: Stale session
- **WHEN** a user who authenticated 2 hours ago asks to end one of their sign-ins with the default recency window
- **THEN** the request is refused with the reauthentication-required error and nothing is revoked

#### Scenario: Listing needs no recent authentication
- **WHEN** a user who authenticated 2 hours ago lists their sign-ins
- **THEN** the listing is returned

#### Scenario: Another user's handle
- **WHEN** a user presents a session handle that belongs to another user
- **THEN** the request is refused as not found

#### Scenario: Ending the current sign-in
- **WHEN** a user ends their current sign-in by its own handle
- **THEN** the family is revoked and the request's own session no longer authenticates

#### Scenario: Current during the grace window
- **WHEN** a client presents its previous session reference within the renewal grace window and lists its sign-ins
- **THEN** its own sign-in is marked as the current one

#### Scenario: Store outage
- **WHEN** the session store fails while listing
- **THEN** the request fails with an error the default mapping answers with 500, and its text is fixed library text

### Requirement: Login upgrades an outdated password hash when the consumer supplies a write
When the consumer supplies a rehash write, a password login, Basic authentication or password re-proof whose password verified, and which is not refused afterwards, SHALL ask the current encoder whether the stored hash needs upgrading; when it does, the submitted password SHALL be re-encoded with the current encoder, only once the outcome is decided and only for a login not refused, and the write SHALL receive the user, the stored hash it replaces and the new hash, after the outcome is decided and on the same request, so the consumer can replace the hash only while it is still the stored one. A login challenged for a second factor SHALL still upgrade. Neither the re-encoding nor the write SHALL change the outcome: an error from either SHALL be logged without the password or any hash. Without a write, no rehash SHALL happen.

#### Scenario: Raised cost
- **WHEN** the encoder is Argon2id at 128 MiB, a user's stored hash is Argon2id at 64 MiB, a rehash write is configured, and the user logs in
- **THEN** the login succeeds and the write receives the 64 MiB hash it replaces and a new Argon2id hash at 128 MiB

#### Scenario: No write configured
- **WHEN** the same login happens with no rehash write
- **THEN** no new hash is produced

#### Scenario: Wrong password
- **WHEN** a rehash write is configured and a login with an outdated stored hash fails for a wrong password
- **THEN** the write is not called

#### Scenario: Refused after the password verified
- **WHEN** a rehash write is configured, a login's password verifies against an outdated stored hash, and a post-authentication policy then refuses the login
- **THEN** the password is not re-encoded and the write is not called

#### Scenario: Write fails
- **WHEN** the rehash write returns an error
- **THEN** the login still succeeds, and the error is logged without any hash

#### Scenario: Password changed meanwhile
- **WHEN** a login with the old password verifies the old 64 MiB hash while a password change stores a new hash, and the rehash write then runs
- **THEN** the write receives the old 64 MiB hash as the one it replaces, so a conditional write leaves the new password in place

#### Scenario: Ready-made write is atomic
- **WHEN** the consumer uses the library's ready-made rehash write over a shipped identity store, and a password change commits between the login's verification and the write
- **THEN** the store decides the condition in the write itself, the new password stays, and the login still succeeds

#### Scenario: Challenged for a second factor
- **WHEN** a rehash write is configured and a login with an outdated stored hash is challenged for a second factor
- **THEN** the write receives the upgraded hash

### Requirement: Logout can clear the browser's site data
When the consumer opts in, a successful logout response SHALL carry `Clear-Site-Data` with the directives the consumer chooses from `"cache"`, `"cookies"` and `"storage"`. It SHALL be sent only on a secure request. By default no `Clear-Site-Data` header SHALL be sent. Opting in with no directive, or with another directive, SHALL fail construction.

#### Scenario: Opted in
- **WHEN** the consumer opts into clearing `"cache"` and `"storage"` and a user logs out over HTTPS
- **THEN** the logout response carries `Clear-Site-Data: "cache", "storage"`

#### Scenario: Plain HTTP
- **WHEN** the consumer opts in and a user logs out over plain HTTP
- **THEN** the logout response carries no `Clear-Site-Data`

#### Scenario: Refused logout
- **WHEN** the consumer opts in and a logout is refused for a missing session
- **THEN** the refusal carries no `Clear-Site-Data`

### Requirement: A sign-in from an unseen device can notify the user
When the consumer opts in and sign-in metadata recording is on, a completed sign-in whose metadata matches none of the user's other live sign-ins SHALL send the user a notice through the sending port, after the sign-in is stored and without delaying the response. Matching SHALL compare user agents by default and SHALL be replaceable, and the consumer SHALL be able to supply a port of devices seen earlier, which is consulted beside the live sign-ins. A user's first sign-in, with no other live sign-in and nothing in the port, SHALL NOT be notified. The notice SHALL contain the time and coarse device description, never a token, a link secret, a session handle or the full client address. A failure to send SHALL be logged and SHALL NOT affect the sign-in. Construction SHALL fail when the notice is enabled without metadata recording or without a sender.

#### Scenario: New browser
- **WHEN** the notice is on and a user with a live sign-in from `Firefox/140` signs in from `Safari/19`
- **THEN** the user receives a sign-in notice

#### Scenario: Known browser
- **WHEN** the notice is on and a user with a live sign-in from `Firefox/140` signs in again from `Firefox/140`
- **THEN** no notice is sent

#### Scenario: First sign-in
- **WHEN** the notice is on and a user with no other live sign-in signs in
- **THEN** no notice is sent

#### Scenario: Sign-in not stored
- **WHEN** the notice is on and a sign-in fails after its credential was issued but before its session was stored
- **THEN** no notice is sent

#### Scenario: Notice without metadata
- **WHEN** the consumer enables the notice with metadata recording off
- **THEN** building the chain fails with a configuration error naming the notice
