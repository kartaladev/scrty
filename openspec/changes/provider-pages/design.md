# Design

## Context

See proposal.md for why. The user accepted the pages decisions on 2026-11-25 (user decision); the
endpoint changes below follow from them.

What exists:

- **The provider's page contract.** A valid authorization request is parked under a handle bound to
  the `__Host-` flow cookie, and the browser goes to the login URL with the handle. Pages read the
  request with `Provider.PendingRequest(handle, flowSecret)` (no PKCE challenge, nonce, state or
  redirect URI in the view). The resume endpoint takes `{"req", "scopes", "deny"}` as JSON with the
  sign-in in `Authorization` (or the provider's browser session at consent) and answers 200 with
  `redirect_to`. Cancel and logout confirmation follow the same JSON shape. Code entry already takes
  form posts and answers with `303`.
- **Required URLs.** The provider refuses to build without login and consent URLs on the issuer's
  origin.
- **`browser-session`:** a cookie chain's sign-in lives in the session cookie; a request carrying the
  cookie and an `Authorization` header is refused; HTML answers are negotiated.
- **`sign-in-pages`:** the page set, the `PageSet` port bound inside `New`, the override ladder.
- **Order:** the provider's endpoints run at `OrderOIDC` (200), before the cookie session (500), so
  they authenticate their own sign-in today; the resume endpoint resolves the `Authorization`
  credential itself.

## Goals / Non-Goals

**Goals:**
- Provider pages that work without JavaScript on a cookie chain.
- No change to any chain that does not use the cookie session.

**Non-Goals:**
- Changing which stages need consent, or what a grant carries.
- Account selection (`prompt=select_account`) beyond showing the request's hint.

## Decisions

### 1. Provider pages join the page set

Login, consent, logout confirmation, code entry and the provider error page are pages of the same
set, switched off and replaced through the same options as every other page.
- **Default:** served whenever the set runs on a provider chain. **Override:** the
  `sign-in-pages` ladder.

### 2. The required URLs stay required; the set supplies them, the chain checks them

`set.ProviderLoginURL(issuer)` and `set.ConsentURL(issuer)` give the absolute URLs for the provider's
options. At bind, the chain compares the provider's URLs with the set's paths under the base path on
the issuer's origin, and fails `New` on a mismatch unless that page is switched off or replaced.
- **Alternative:** defaulting the URLs inside the provider. Rejected: it changes a settled rule and
  turns a construction error into a failure at first use for a provider built without pages.

### 3. The resume endpoint accepts the cookie sign-in on a cookie chain

On a cookie chain, the resume endpoint resolves the session cookie through the shared
session-reference pipeline when no `Authorization` header is present, exactly as it resolves the
header today, and builds the provider's `SignIn` from that session. CSRF protection already covers
provider endpoints that may rest on a cookie, so the forms carry the sign-in's CSRF token.
- **Default:** on for cookie chains; token chains are unchanged. **Override:** none; a cookie chain
  has no other credential to send.

### 4. Form bodies and `303` answers, on cookie chains only

Resume, cancel and logout confirmation accept `application/x-www-form-urlencoded` with the JSON
document's field names (`req`, repeated `scopes`, `deny`, `confirmed`), parsed with
`url.ParseQuery` under the existing body limits, and answer a form post or an HTML-preferring
request with `303` to `redirect_to`, keeping `Cache-Control: no-store`. JSON requests keep the 200
answer.
- **Alternative:** a JavaScript shim on each page that posts JSON and follows `redirect_to`.
  Rejected: pages would stop working without JavaScript, and the conformance browser runs little.

### 5. The continuation after sign-in

The provider login page signs in through the ordinary sign-in endpoints with `next` set to the
set's continuation, `GET /sign-in/continue?req=<handle>`. The continuation:
- when `Sec-Fetch-Site` is `same-origin`, resumes on the server through a resume function the chain
  hands the set at bind (the same code path as the endpoint, with the request's cookie sign-in and
  flow cookie), and answers `303` to where the provider says;
- otherwise, including when the header is missing, renders one "Continue" button that posts the
  resume form, so a cross-site navigation can never resume a request.
- **Why not resume on every `GET`:** a resume issues a code; a navigation another site starts must
  not do that, even though the handle is bound to the victim's flow cookie.
- **Alternative:** always show the button. Rejected: an extra click on every sign-in through the
  provider, including first-party clients that skip consent.

### 6. Consent page content

Scopes are described by message ID `scope.<name>`; a scope with no message is shown by name.
`offline_access` is shown in its own section. Optional scopes are checkboxes, ticked by default;
`openid` is fixed when requested. A device request shows its user code and request time, as the
pending view provides.

### 7. Error pages

A refused authorization request that cannot be redirected (unknown client, unregistered redirect
URI, an end-session hint that fails its checks) is rendered by the set's provider error page through
the same refusal renderer as `sign-in-pages`, with the refusal's status and a bundle message.

## Failure modes

| Failure | Category | State | Outcome a caller sees |
|---|---|---|---|
| Provider URLs and page paths disagree | Wiring | Handled, tested | `ErrConfig` naming both |
| Cross-site navigation to the continuation | Security | Handled, tested | button page, nothing resumed |
| Continuation with an unknown or foreign handle | Input | Handled, tested | provider error page, handle charged to the source |
| Form post without the CSRF token | Security | Handled, tested | refused as cross-site |
| Malformed form body | Input | Handled, tested | refused as malformed |
| Form body on a token chain | Configuration | Handled, tested | refused as malformed, as today |
| Session cookie and `Authorization` both sent to resume | Input | Handled, tested | refused by the `browser-session` guard |
| Store failure after the request is read | Dependency | Handled, tested | `303` to the client with `server_error`, as the provider already answers |
| Scope with no description | Configuration | Handled, tested | shown by name |
| Consumer's replacement page breaks the handle flow | Configuration | Accepted | the consumer owns that page; the pending-view contract is documented |

## Risks / Trade-offs

- [`Sec-Fetch-Site` is absent in old browsers] → those users see a continue button; nothing is
  resumed without it.
- [Two body formats on three endpoints] → one shared reader per endpoint, with table tests covering
  both formats and the token-chain refusal.

## Migration Plan

Additive. Token chains keep the JSON-only contract; cookie chains gain form bodies and `303`.

## References

**Researched** (accessed 2026-11-25):
- Decision 5: [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html), state changes bound to the session and protected against cross-site requests.

**Primary documentation:**
- Decision 5: [W3C Fetch Metadata Request Headers](https://www.w3.org/TR/fetch-metadata/), the `Sec-Fetch-Site` values `same-origin`, `same-site`, `cross-site` and `none`.

Decisions 1 to 4, 6 and 7 are reasoned from scrty's own settled specs and the established design.
