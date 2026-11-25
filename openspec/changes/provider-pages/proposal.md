# Proposal

## Why

When scrty runs as an OpenID Provider, it parks each authorization request and sends the browser to
the consumer's login page, then to their consent page; logout and the device flow send it to a
logout confirmation page and a code-entry page. All four are the consumer's to write today, and the
provider requires the login and consent URLs before it builds. `sign-in-pages` gives scrty a page
set; this change adds the provider's four pages to it, so a consumer running the provider gets
working login, consent, logout and device screens with the same opt-in and the same override ladder.

The provider's page-facing endpoints (resume, cancel, logout confirmation) accept only JSON and
answer `200` with `redirect_to`, which suits a page with JavaScript and a sign-in token in the
`Authorization` header. On a cookie chain there is no such token, and a page without JavaScript
posts a form. Those endpoints need a browser form of their contract.

## What Changes

- **Provider pages in the page set:**
  - login (the sign-in page in provider mode: the client's name, the `login_hint` prefilled, and a
    cancel button);
  - consent (the client, the scopes with their descriptions, `offline_access` shown apart, optional
    scopes chosen individually, allow and deny);
  - logout confirmation;
  - device code entry and its outcome (`approved`, `denied`, `expired`);
  - the provider's error page for a request that cannot be redirected back.
- **Continuing after sign-in:** after the user signs in on the provider login page, the page set
  resumes the parked request on the server and redirects the browser on, when the navigation came
  from the same origin. Otherwise it shows a one-button form that posts the resume.
- **The provider's page-facing endpoints on a cookie chain:**
  - resume, cancel and logout confirmation accept a form body as well as JSON;
  - a form post, or a request preferring HTML, is answered `303` to `redirect_to`;
  - resume accepts the chain's cookie sign-in in place of the `Authorization` header.
- **The required URLs stay required.** The page set supplies the provider's login and consent URLs,
  and construction fails when the provider's URLs and the pages' paths disagree.

## Capabilities

### New Capabilities
- `provider-pages`: the provider's login, consent, logout confirmation, device code-entry and
  error pages, and the continuation after sign-in.

### Modified Capabilities
- `oidc-provider-authorization`: the resume and cancel endpoints accept a form body and the cookie
  sign-in on a cookie chain, and answer an HTML request with `303`.
- `oidc-provider-logout`: the confirmation endpoint accepts a form body on a cookie chain and
  answers an HTML request with `303`.

## Impact

- **Code:** `httpsec/pages` (provider pages, continuation); `httpsec` (form bodies, cookie sign-in
  and negotiated answers at `oidc_resume.go`, `oidc_cancel.go`, `oidc_logout_confirm.go`; the
  resume function the chain hands the page set at bind).
- **Depends on:** `sign-in-pages` archived (and so `browser-session`).
- **APIs:** additive; chains without the cookie session keep today's JSON-only contract.
- **Dependencies:** none added.
