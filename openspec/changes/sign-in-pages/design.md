# Design

## Context

See proposal.md for why. The user accepted these decisions on 2026-11-25 (user decision); each names
the alternatives considered.

What this change builds on:

- **`browser-session`:** the cookie session, negotiated answers (`303` for forms and HTML requests,
  JSON otherwise), same-origin `next` resolution, rotation on privilege change.
- **The chain:** `Chain.Endpoints()` lists every endpoint; `WithBasePath` moves them; one collision
  check refuses overlapping paths; refusals propagate as errors to a replaceable handler
  (`WithErrorHandler` on net/http, prblmsec middleware on gin and fiber).
- **Security headers:** per-response CSP nonces, `frame-ancestors`, and a hash-based preset.
- **Settled rule:** "rendering belongs to the consumer". This change departs from it: with a page
  set enabled, scrty renders pages and HTML refusals. Without one, nothing changes.
- **Path vocabulary:** kebab-case segments, plural nouns for collections, actions as POSTs to named
  sub-paths.

## Goals / Non-Goals

**Goals:**
- A complete, good-looking set of sign-in pages from one explicit call.
- Every part replaceable, and every replacement that would break a page refused at construction.

**Non-Goals:**
- The provider's login, consent, logout and device pages (`provider-pages`).
- React components (`ui-react`).
- Email templates, dev mode, an admin console.

## Decisions

### 1. Server-rendered `html/template`, vanilla JavaScript only where required

Pages are Go templates embedded with `embed`; the only scripts are the passkey ceremony (WebAuthn
is JavaScript-only) and the TOTP QR code, each under the CSP nonce.
- **Default:** server-rendered. **Override:** any page can be the consumer's own handler (decision 4).
- **Alternative:** an embedded React single-page app. Rejected: Node and npm in scrty's build and
  every consumer binary, bundle rebuilds for any override, version skew, no function without
  JavaScript, risk with the conformance suite's browser.

### 2. A package in the core module

`httpsec/pages`, standard library only. Go links it only when imported.
- **Alternative:** a nested module `httpsec/pagesec`. Rejected: nested modules isolate third-party
  dependencies, and the pages have none.

### 3. Explicit opt-in through a port the chain runs inside `New`

The consumer builds a `*pages.Set` with `pages.New(opts...)` and passes it to
`httpsec.EnablePages(set)`. `httpsec` defines the port `PageSet` (bind to the chain's endpoint
inventory and base path, serve pages and assets, render a refusal); `pages` implements it, so
`httpsec` does not import `pages`. Binding runs inside `New`, which is what lets every page check
fail construction, and what lets the chain route HTML refusals to the set.
- **Default:** no pages. **Override:** the options in decision 4.
- **Alternatives:** Spring-style pages that appear when a sign-in path is on (pages reach production
  undecided, and fingerprint the stack); `pages.New(chain)` after the chain is built (the checks
  would run after `New` returned, and the chain's error handler could not reach the pages).

### 4. The override ladder

| Level | Option | Effect |
|---|---|---|
| L0 | not importing `pages` | headless, as today |
| L1 | `pages.Without(page...)` | page off; its path passes through |
| L2 | `pages.WithTheme(pages.Theme{...})` | `--scrty-*` variables |
| L3 | `pages.WithStylesheet(url)` | consumer CSS after scrty's |
| L4 | `pages.WithTemplates(fs.FS)` | named blocks overridden |
| L5 | `pages.WithMessages(bundle...)` | wording and languages |
| L6 | `pages.WithPage(page, http.Handler)` | page served by the consumer |
| — | `pages.WithPath(page, path)` | page moved |

`pages.WithProductName(name)` is required, because nothing brand-specific is a default.

### 5. Page paths

`/sign-in`, `/sign-in/magic-link/confirm` (already the magic-link default target),
`/sign-in/challenge`, `/account/second-factors`, `/account/reauthenticate`, `/account/password`,
`/account/sessions`, `/recovery`, `/sign-out/confirm`. Pages answer `GET` only; every action posts
to the chain's existing endpoints. Paths follow `WithBasePath` and join the endpoint inventory,
so the existing collision check covers them.

### 6. Routing a challenged or owing sign-in to its page

On a cookie chain with pages, the set's refusal renderer answers an HTML request refused with a
pending second-factor challenge, an owed password change, a recent-authentication requirement or a
missing sign-in with `303` to the matching page, carrying the original path as `next` when the
request was a `GET`. Every other HTML refusal renders the error page. Non-HTML refusals are answered
as without pages.
- **Why the renderer:** the chain already raises these as typed errors; mapping them to pages in one
  place means no page needs to know about the others.

### 7. Theming: Tailwind for scrty's own CSS, CSS variables and semantic classes for consumers

scrty's maintainers author CSS with Tailwind v4 through its standalone CLI (no Node); the compiled
file is committed, and CI fails when regenerating it changes it. The public contract is the
`--scrty-*` custom properties and `.scrty-*` classes. Raw Tailwind utility classes are not part of
it, because Tailwind generates only the classes it finds when it builds, and a consumer's class
would silently have no style.
- **Alternatives:** Tailwind as the consumer's API (silently unstyled classes; a build step for every
  consumer); hand-written CSS (slower to keep polished).

### 8. Named blocks, rendered at construction

Each page is a layout plus named blocks (`signin.header`, `signin.form`, `signin.footer`, …).
`WithTemplates` parses the consumer's files after scrty's, so a `{{define}}` replaces a block. At
bind time every page renders once against a fixture view model; a render error, or output missing
a field the page declares required (CSRF token, handle, credential fields), fails `New`. Templates
receive typed view models holding only what the page shows.
- **Alternative:** whole-file overlays. Rejected: a footer change copies the whole page, hidden
  security fields included.

### 9. Messages

Bundles keyed by message ID, English built in. Language order: `pages.WithLanguage(func(*http.Request) string)`
if given, then `Accept-Language`, then English; a missing message falls back to English. Messages
are text, never HTML.

### 10. Refusal rendering on every framework

net/http: the chain's default refusal answer consults the page set when enabled, unless the
consumer set `WithErrorHandler`, which keeps full control. gin and fiber: their adapters call the
same set when enabled, beside prblmsec's renderer for non-HTML requests.

### 11. Assets

The set serves `scrty.<hash>.css`, its scripts and the default logo under
`<base path>/_scrty/assets/`, with `Cache-Control: public, max-age=31536000, immutable`.

## Failure modes

| Failure | Category | State | Outcome a caller sees |
|---|---|---|---|
| Page set without cookie session, CSRF or headers | Wiring | Handled, tested | `ErrConfig` from `New` |
| Page asked for without its endpoint | Wiring | Handled, tested | `ErrConfig` naming both |
| Page path collides | Wiring | Handled, tested | `ErrConfig` naming the path |
| Override drops CSRF token or handle | Input | Handled, tested | `ErrConfig` naming the block |
| Override fails to parse or render | Input | Handled, tested | `ErrConfig` |
| Markup in a message or product name | Security | Handled, tested | escaped |
| Off-site `next` on a page | Security | Handled, tested | the chain resolves it to `/` |
| A page revealing whether an account exists | Security | Handled, tested | one message, same status |
| Template execution fails at request time | Dependency | Handled, tested | logged once per sample window, `500` error page with no detail |
| Committed CSS stale against templates | Observability | Handled, tested | CI fails |
| Message bundle missing a key | Configuration | Handled, tested | English message |
| Consumer's own handler for a page breaks a flow | Configuration | Accepted | the consumer owns that page; documented contract of the pending state between steps |

## Risks / Trade-offs

- [Departing from "rendering belongs to the consumer"] → only with an explicit `EnablePages`; the
  headless default stays.
- [Block names become a compatibility promise] → documented per page; additive splits only.
- [Generated CSS in the repository] → pinned Tailwind CLI version and a CI freshness check.

## Migration Plan

Additive. Consumers opt in with `EnablePages`; nothing changes for others.

## Open Questions

- Final block names per page are settled while writing each page's template.

## References

**Researched** (accessed 2026-11-25):
- Decision 3: [Spring Security: Form Login](https://docs.spring.io/spring-security/reference/servlet/authentication/passwords/form.html), the default login page until one is named; [spring-security issue 13203](https://redirect.github.com/spring-projects/spring-security/issues/13203), confusion about when the default applies.
- Decision 7: [Tailwind standalone CLI](https://tailwindcss.com/blog/standalone-cli), building without Node; [Tailwind theme variables](https://tailwindcss.com/docs/theme), `@theme` as CSS custom properties.

Decisions 1, 2, 4, 5, 6, 8, 9, 10 and 11 are reasoned from scrty's own settled specs and the
established design.
