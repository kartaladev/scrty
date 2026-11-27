## Purpose

Gives a consumer a runnable, generic OpenID Provider to read and copy, and proves in real browsers what Go tests cannot show: the headers a browser really sends, what it does with the library's answers, and how its cookies behave.

## ADDED Requirements

### Requirement: The repository holds a runnable generic provider
The repository SHALL hold a runnable, unbranded OpenID Provider built on `oidcprovider`, that starts with one command and no configuration, and whose issuer, clients and users the reader can set.

#### Scenario: One command
- **WHEN** a reader runs the example with no flags and opens its address in a browser
- **THEN** a fixture user can sign in through a fixture client, and the program's log says its stores are in memory and its users are fixtures

#### Scenario: A standards relying party
- **WHEN** a relying party that follows OpenID Connect is registered through the example's flags or file
- **THEN** it completes a code flow with PKCE against the discovery document's endpoints

#### Scenario: The reader's own https
- **WHEN** the reader starts it with a certificate and key
- **THEN** it serves https with its `__Host-` cookies

### Requirement: Browser tests run in three engines and cannot pass by not running
The browser tests SHALL drive Chromium, Firefox and WebKit, and SHALL skip without a gate, so an ordinary test run needs no browser. The CI job SHALL fail if they did not run.

#### Scenario: An ordinary test run
- **WHEN** `make test` runs with no browser installed
- **THEN** the example's module passes, and its browser tests report skipped

#### Scenario: The CI job
- **WHEN** the `browser` job runs and an engine could not start
- **THEN** the job fails, and `ci-ok` fails with it

### Requirement: A browser's real requests are what the library judges
The browser tests SHALL assert on the headers the server received as well as on what the page saw.

#### Scenario: Same origin
- **WHEN** a signed-in page opens an `EventSource` on its own origin
- **THEN** the server saw `Sec-Fetch-Site: same-origin`, and the first event is `session`

#### Scenario: Cross-site
- **WHEN** a page on another site opens the stream by `EventSource` with credentials, `<script>`, `<img>` and `fetch`
- **THEN** the server saw `Sec-Fetch-Site: cross-site`, answered 401 or 403, no stream opened, and `EventSource` ends closed after one request

#### Scenario: A named sibling
- **WHEN** a same-site sibling opens the stream, once unnamed and once named by CORS with credentials
- **THEN** it is refused, then allowed

#### Scenario: An opaque origin
- **WHEN** a sandboxed frame opens the stream
- **THEN** it is refused

### Requirement: A browser's stream behaviour matches the library's design
The browser tests SHALL show that a real `EventSource` reconnects after a retry-only answer and a close, and stops on a refusal or a final end.

#### Scenario: An ended sign-in
- **WHEN** a user logs out in one tab while another holds a stream
- **THEN** the other tab hears `session_ended`, its reconnect gets 401, and no further request follows

#### Scenario: A place refused
- **WHEN** a sign-in opens one stream more than its cap
- **THEN** that one gets only a `retry`, and the browser comes back after it, while the others stay open

#### Scenario: A maximum age
- **WHEN** a stream reaches its maximum age
- **THEN** it closes with no event, and the browser reconnects

#### Scenario: A shutdown
- **WHEN** the server closes its streams for shutdown
- **THEN** each browser reconnects

#### Scenario: The README's clients
- **WHEN** the two client snippets in the README's session signals section run unchanged against the example
- **THEN** they do what the README says, and they are read from the README at test time

### Requirement: A browser's sign-in works end to end
The browser tests SHALL drive the provider's own flows, including the refusals a browser's cookies and headers decide.

#### Scenario: A code flow
- **WHEN** a browser signs in, resumes by `fetch` with a bearer, consents, and is redirected with a code
- **THEN** a relying party exchanges it, and the flow cookie bound the handle to that browser

#### Scenario: Cross-site posts
- **WHEN** a foreign page posts to resume, logout confirmation and consent revocation
- **THEN** each is refused with 403

#### Scenario: A posted authorization request
- **WHEN** a foreign page posts an authorization request or a logout with no flow cookie
- **THEN** it is answered 303 back as a GET

#### Scenario: Logout
- **WHEN** a relying party starts a logout with and without an `id_token_hint`
- **THEN** it ends the sign-in or asks, honours a registered `post_logout_redirect_uri`, and clears the cookies

#### Scenario: Cookie attributes
- **WHEN** the provider sets its cookies, over http and over https, in each engine
- **THEN** they hold the attributes the library documents, and the test states where an engine differs

#### Scenario: Framing
- **WHEN** a foreign page frames the login and consent pages
- **THEN** the browser refuses
