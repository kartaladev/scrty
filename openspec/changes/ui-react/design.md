# Design

## Context

See proposal.md for why. The package's shape and its compatibility model were accepted by the user
on 2026-11-25 (user decision); where the package lives is still open (Open Questions).

What exists when this change is applied:

- **`browser-session`:** cookie sign-ins; on a cookie chain every issuing endpoint answers a JSON
  request with `200` and `{"idle_expires_at": ...}`, never a credential; refusals are problems.
- **`problem-details-rendering`:** typed problem documents for refusals, including challenges.
- **`csrf-protection`:** `X-CSRF-Token` and `csrf_token` by default; the token is readable only
  through the server-side accessor `CSRFToken(ctx)`.
- **`sign-in-pages`:** the `--scrty-*` design tokens and `.scrty-*` classes.
- **The chain:** `Chain.Endpoints()` lists every endpoint it answers.

## Goals / Non-Goals

**Goals:**
- React teams get working, themable sign-in inside their own app with no credential in JavaScript.
- A mismatch between the package and the server is a clear message, never a silent failure.

**Non-Goals:**
- Other frameworks' packages (Vue, Svelte). The OpenAPI document serves them.
- Token-based (non-cookie) chains: the package targets cookie chains only.

## Decisions

### 1. Hooks plus styled components

Two layers: headless hooks hold the flow logic, challenge handling and errors; styled components
are thin layers over the hooks, themed by the shared `--scrty-*` variables and accepting a
`className`.
- **Default:** use the components. **Override:** use the hooks alone with the consumer's own
  components.
- **Alternatives:** components only (teams with their own design system cannot reach the logic);
  hooks only (every team rebuilds every form).

### 2. A published contract, discovery, and a versioning rule

- The contract version is a constant in `httpsec`, raised by any breaking change to a
  browser-facing request, answer, status or problem type.
- An OpenAPI 3.1 document describes contract `1`. A test compares the paths in
  `Chain.Endpoints()` of a fully enabled chain with the document's paths and fails on a difference.
- `httpsec.EnableDiscovery(opts...)` serves `GET /.well-known/scrty`, off by default, because the
  list of enabled flows tells a scanner what the site runs.
- The package declares the contract versions it supports and checks discovery once per mount.
- **Alternatives:** lockstep versions between the npm package and the Go module (every release
  forces a release of the other, and an upgrade of one side breaks silently); no formal contract
  (users discover breakage in production).

### 3. The CSRF token endpoint

`httpsec.EnableCSRFTokenEndpoint(opts...)` serves `GET /session/csrf-token`, off by default, on
cookie chains only (`ErrConfig` otherwise). It answers `{"token": "..."}` with `no-store` to a
request with a sign-in that the Fetch Metadata and `Origin` check judges same-origin. The token is
not a credential on its own: it is useless without the `HttpOnly` cookie, which a script cannot
read.
- **Alternatives:** a readable `XSRF-TOKEN` cookie (Angular style; one more cookie, and readable by
  every script on every subdomain the cookie reaches); embedding the token in the HTML the app
  serves (needs the app to render HTML server-side, which SPA teams often do not).

### 4. Credentials stay out of JavaScript

The package sends requests with `credentials: "same-origin"` and never reads, stores or forwards a
session identifier or token. Tests assert that no web storage is written.

## Failure modes

| Failure | Category | State | Outcome a caller sees |
|---|---|---|---|
| Server contract newer than the package supports | Configuration | Handled, tested | unsupported-contract message, no requests |
| Flow not enabled on the server | Configuration | Handled, tested | flow-unavailable message |
| Discovery not enabled | Configuration | Handled, tested | the package reports that discovery is required |
| CSRF token request cross-site | Security | Handled, tested | refused; nothing answered |
| CSRF token stale after a new sign-in | State | Handled, tested | the package refetches the token after a sign-in and once after a cross-site refusal |
| Network failure mid-flow | Dependency | Handled, tested | the hook reports a retryable error; no partial state is kept |
| OpenAPI document drifts from the endpoints | Observability | Handled, tested | the project's checks fail |
| An app stores tokens itself | Security | Accepted | the package never hands one out on a cookie chain |

## Risks / Trade-offs

- [npm enters the project's supply chain] → `supply-chain` rules extended to npm: pinned versions,
  lockfile committed, audit in CI.
- [Discovery fingerprints the site] → off by default; documented.

## Open Questions

- **Where the npm package lives (blocks tasks).** Same repository, in a top-level `web/` directory
  with a placeholder `go.mod` so it stays out of the core Go module's download, or a separate
  repository with its own release cadence. The recommendation is the same repository, so a contract
  change and its client change land in one pull request. That the placeholder `go.mod` keeps the
  directory out of the module download is to be checked by building a module zip.

## References

**Researched** (accessed 2026-11-25):
- Decision 1: [Ory Elements](https://www.ory.sh/docs/getting-started/custom-ui-ory-elements) and [kratos-selfservice-ui-react-nextjs](https://github.com/ory/kratos-selfservice-ui-react-nextjs/), a headless server paired with React components (product documentation, not tested).

**Primary documentation:**
- Decision 2: [OpenAPI Specification 3.1](https://spec.openapis.org/oas/v3.1.0).
- Decision 3: [W3C Fetch Metadata Request Headers](https://www.w3.org/TR/fetch-metadata/).

Decision 4 is reasoned from scrty's own settled specs and the established design.
