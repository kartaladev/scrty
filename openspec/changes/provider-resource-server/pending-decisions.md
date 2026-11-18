# Pending decisions: provider-resource-server

**Status: on hold (2026-11-18).** Do not apply this change until the decisions below are made.

`proposal.md`, `design.md`, `specs/`, `tasks.md` and `plans.md` describe the **bearer-reuse
design** (option D1-A). That design may be superseded. The user asked that the open questions be
recorded and that nothing be decided yet.

Each decision lists its options, what each costs, and a recommendation. The recommendations are not
decisions.

## What stays decided whichever way the open questions go

These came out of the user's answers on 2026-11-16 and the analysis that followed. None of the
pending decisions reopens them.

- **Claim by shape.** A provider access token is recognised by its shape:
  - a JWT whose header `typ` is `at+jwt` or `application/at+jwt`, compared without regard to case;
  - an opaque token with the provider's `at.` prefix.

  A token that is recognised but fails verification is refused. It is never handed on to another
  credential mode.
- **Binding.** DPoP (or certificate) binding is required by default for this feature only, never
  chain-wide. Accepting unbound tokens is an explicit opt-in.
- **`ErrInvalidToken`.** It is a 401 challenged with `error="invalid_token"`, and only this feature
  returns it.
- **The per-request flow:**
  1. strict header read;
  2. `Provider.VerifyAccessToken`, which checks the grant on every call;
  3. exact audience match, under the `validResource` rule, so a URN is allowed;
  4. binding;
  5. user reload;
  6. proof recorded;
  7. caller published with scopes and the `access-token` factor kind;
  8. stateless policy phase.
- **Same scope beside the resource server:** the password `WithRule` hook and
  `WithInactiveDisclosure` (design decisions 11 and 12).
- **Mobile sign-in** needs nothing new. Native apps sign in through the system browser
  (`ASWebAuthenticationSession`, Android Custom Tabs) as public native clients with PKCE. They never
  use an embedded WebView (RFC 8252 §8.12). scrty's settled `oidc-provider-clients`,
  `oidc-provider-authorization` and `oidc-provider-consent` specs already cover that client shape.

---

## D1. Where the chain accepts the provider's access tokens

**The question.** Should a provider access token be checked by the chain's general bearer mode, or
by the provider's own feature?

**Why it is open.** A chain runs one bearer mode. On a chain that is both the provider and the API
(the consumer's setup), the bearer today also carries the IdP login's first-party token. That is why
the on-disk design needs `WithFirstPartyVerifier`. The user then argued that the verifier's lifetime
is tied to the provider, so the check belongs to `EnableOIDCProvider`.

### Option A — Reuse `EnableBearerToken` (on disk today)

```go
v, _ := op.AccessTokenVerifier("urn:kartala:hris:api", oidcprovider.WithFirstPartyVerifier(firstParty))
httpsec.EnableBearerToken(httpsec.BearerTokenDeps{Verifier: v, Sessions: s, Users: u})
httpsec.WithBearerUnboundGrantTokens() // opt-in for unbound tokens
```

- **Pros:**
  - It is already written and validated.
  - The consumer agreed to this API.
  - It works unchanged for a resource-server-only binary.
- **Cons:**
  - The public verifier routes two token kinds.
  - It needs the `internal/grantclaims` mark, so that a consumer's verifier cannot fake
    "grant-backed".
  - `BearerTokenDeps.Sessions` becomes optional in one case only.
  - `Users` is wired twice.
  - `WithFirstPartyVerifier` exists only because the IdP login uses the same bearer.

### Option B — `WithOIDCAccessTokens(audience)` inside `EnableOIDCProvider`

```go
httpsec.EnableOIDCProvider(op,
    httpsec.WithOIDCAccessTokens("urn:kartala:hris:api"),
    // httpsec.WithOIDCAccessTokensUnbound(), // opt-in
)
// handler: httpsec.AccessTokenFromContext(ctx); route policy: authorize.HasAllScopes(...)
```

- **Pros:**
  - The provider owns the whole check.
  - There is no public verifier, no `WithFirstPartyVerifier`, and probably no grant mark, because
    the check never passes through the public `token.Verifier` port.
  - `EnableBearerToken` is untouched.
  - `Users` comes from `oidcprovider.Deps`.
- **Cons:**
  - It needs a rework of `design.md`, specs, tasks and plans.
  - The consumer must be told the API changed.
  - It fits a resource-server-only binary badly (see D2).
  - On a chain that also runs `EnableBearerToken`, the two must be ordered so that tokens shaped like
    provider tokens never reach the first-party bearer.

### Option C — A separate `EnableProviderAccessTokens` feature (considered, set aside)

This was the first draft. The user set it aside on 2026-11-16 to avoid confusing consumers with a
second token switch. It is listed so the record is complete. Option B differs from it only in where
the switch lives.

**Recommendation:** **B**, if D2 has an answer the user accepts. Otherwise **A**.

**Artifacts to revise if B is chosen:**
- `proposal.md`: what changes, and the API.
- `design.md`: decisions 1–8 and failure modes F1–F31.
- `specs/oidc-provider-resource-server`: replace the bearer wording.
- `specs/http-security-chain`: drop the `Sessions` exception and the bearer binding option.
- `tasks.md` and `plans.md`: regenerate.

---

## D2. A resource server in a separate binary (only if D1-B)

**The question.** Under option B, how does an API binary that does not serve the provider's
endpoints accept the provider's tokens?

| Option | Shape | Pros | Cons |
|---|---|---|---|
| a. Sibling feature | `httpsec.EnableOIDCAccessTokens(op, aud)`, with `op` built on the same store and keys and serving no endpoints | Same code as B under a clear name; real-time revocation through the shared store | Two switches for one check, which is what the user set aside in D1-C |
| b. Provider without endpoints | `EnableOIDCProvider(op, WithOIDCAccessTokens(aud), WithoutOIDCEndpoints())` | One switch | The name misleads: "enable provider" mounts no provider |
| c. Remote check | JWKS verification plus RFC 7662 introspection, with no shared store | Real separation of services | A different trust model. Revocation is only real-time if every call introspects. It belongs to `bff-resource-server`. |
| d. Out of scope | Only the provider and API in one binary is supported for now | Smallest change; matches the first consumer | A second binary has to wait for another change |

**Recommendation:** **d** for this change, keeping **a** as the planned follow-up. **c** stays in
`bff-resource-server`.

---

## D3. The IdP sign-in credential: token or cookie

**The question.** Should the IdP's own login hand the browser a token (today), or set an `HttpOnly`
session cookie, as common identity providers do?

**Where things stand:**
- The settled `csrf-protection` spec already requires CSRF protection for cookie authentication, and
  refuses construction without it.
- The provider already sets `__Host-scrty-op-session`, but only after the first resume.
- Nothing yet signs the browser in through a cookie.

| Option | Pros | Cons |
|---|---|---|
| a. Keep the token (status quo) | No work; works in v0.1.1 | The login page holds a token in script, so an XSS can steal it. The consumer's chain keeps a first-party bearer, which is what forces D1-A's `WithFirstPartyVerifier`. |
| b. Cookie, as its own change, **after** this one | This change ships to the consumer sooner. The cookie design gets its own research. | The consumer's login page uses the token until the cookie change lands. |
| c. Cookie, as its own change, **before** this one | D1 becomes simpler: no first-party bearer on the consumer's chain | Delays the resource server. That change has open sub-decisions (D5). |
| d. Cookie inside this change | One release | Mixes two unrelated risks in one change, and makes it much larger |

**Where the login page can live with a cookie:**
- the provider's origin: works;
- a sibling subdomain: works, with CORS credentials, trusted by the settled CSRF rule;
- another site: does not work reliably, because third-party cookies are blocked.

**Recommendation:** **b**, carved out of `bff-resource-server`'s browser-session part.

---

## D4. If cookie: how a consumer turns it on (only if D3-b, c or d)

**What the code shows (read 2026-11-17):**
- One seam already chooses how the credential is issued for the whole chain:
  `config.credentialIssuer`, in `httpsec/complete.go:131`.
- Eight endpoints issue through it:

| # | Endpoint | File |
|---|---|---|
| 1 | form login | `login.go:410` |
| 2 | passkey login | `passkey_login.go:595` |
| 3 | magic link | `magiclink.go:501` |
| 4 | federated login | `oidc_redeem.go:95` |
| 5 | MFA verify (rotates) | `mfa_verify.go:572` |
| 6 | re-authentication (rotates) | `reauth_resolve.go:67` |
| 7 | session renewal (rotates with grace) | `session_renewal.go:212` |
| 8 | account recovery | `recovery.go:529` |

- A ninth place: the `ChallengeError` token returned while MFA is pending (`errors.go:215`).
- What cookie mode changes is **delivery**: a `Set-Cookie` header in place of the body token. The
  credential itself can be the existing session reference (`issueSessionReference`).

### Option A — A chain mode

```go
httpsec.New(
    httpsec.EnableCookieSessions(httpsec.CookieSessionDeps{Sessions: s, Users: u}), // instead of a bearer mode
    httpsec.EnableCSRF(csrfDeps),        // construction fails without it
    httpsec.EnableFormLogin(formDeps),   // unchanged call; answers with Set-Cookie
    httpsec.EnableMFAVerify(mfaDeps),    // unchanged; rotation replaces the cookie
    httpsec.EnableOIDCProvider(op, ...), // checkBearer accepts cookie mode
)
```

- **Pros:**
  - Every sign-in method follows with one switch.
  - It follows the existing rule that an endpoint never chooses its own credential
    (`complete.go:47`).
  - A cookie the chain cannot read is impossible.
- **Cons:**
  - It adds a third credential mode beside `EnableBearerToken` and `EnableSessionBearer`.

### Option B — An option on each endpoint

```go
httpsec.EnableFormLogin(formDeps, httpsec.WithCookieDelivery())
httpsec.EnablePasskeyLogin(pkDeps, httpsec.WithCookieDelivery())
// ...six more
```

- **Pros:**
  - It looks small.
  - Each endpoint can be switched on its own.
- **Cons:**
  - The option must be repeated on all eight endpoints.
  - Forgetting one hands a token to a chain that reads only cookies.
  - Every mix of cookie and token endpoints needs a construction check. That is the wiring mistake
    `library-design.md` rules out.

**Recommendation:** **A**. The user first suggested changing `EnableFormLogin`. Option A gives the
same result for every sign-in method, not just form login.

---

## D5. Sub-decisions for the cookie change (to settle there, listed here so they are not lost)

| # | Question | Options | Leaning |
|---|---|---|---|
| D5.1 | Callers of the IdP endpoints that are not browsers (scripts, tests, a native app without a browser) | keep a bearer mode as an opt-in beside cookies; or IdP login is browser-only | opt-in bearer |
| D5.2 | An existing cookie at login | always create a new session and ignore the presented cookie (fixation defence) | always new: no real alternative, record as a requirement |
| D5.3 | The password-change gate saves the session rather than rotating it | rotate under cookie mode; keep saving | rotate |
| D5.4 | DPoP-bound sessions (a browser cookie carries no proof) | refuse key-bound sessions at construction under cookie mode; ignore the binding | refuse |
| D5.5 | `SameSite` | `Lax` (works with top-level redirects into the IdP); `Strict` | `Lax`, with CSRF tokens |
| D5.6 | Renewal grace window (both cookies briefly valid) | keep the existing grace; shorten it under cookies | keep, document |
| D5.7 | Custom responders (`WithLoginResponder` and similar) | always pass an empty token in cookie mode; let the consumer choose | always empty, so `HttpOnly` cannot be undone |
| D5.8 | `session.Manager.Rotate` delete failure may leave the old ID alive | **UNREPRODUCED** (a code reading, no test yet). The first red test of that change decides whether it is real. | prove first |
| D5.9 | Logout | clear the cookie and revoke the session together | both: record as a requirement |

---

## D6. `insufficient_scope` when a route needs a scope the token lacks

**The question.** A route policy refuses a token without the needed scope with a 403. Neither the
on-disk design nor option B says whether that 403 carries a challenge.

| Option | Pros | Cons |
|---|---|---|
| a. A 403 with `WWW-Authenticate: DPoP error="insufficient_scope", scope="..."` when the caller authenticated with an access token | RFC 6750 §3.1; the client learns which scope to request | A new mapping from the policy refusal to the challenge path |
| b. A plain 403, as today | No new mapping | The client cannot tell a missing scope from any other refusal |

**Recommendation:** **a**, in this change, whichever way D1 goes.

---

## D7. Ship the parts that do not depend on D1 first

**The question.** Some of this change does not depend on D1–D3 at all:
- the password `WithRule` hook;
- `WithInactiveDisclosure` and `ErrAccountInactive`;
- the `access-token` factor kind;
- scopes on a user principal.

| Option | Pros | Cons |
|---|---|---|
| a. Split them into a small change and release it first | The consumer gets the password and sign-in answers sooner. This change shrinks. | Two releases. Some artifacts are moved between changes. |
| b. Keep everything in this change | One release, one review | All of it waits for D1–D3 |

**Recommendation:** **a**, splitting out the password hook and inactive disclosure. The factor kind
and principal scopes stay here, since only the resource server uses them.

---

## D8. Telling the consumer

The consumer's session agreed to the D1-A API on 2026-11-16 and is waiting for a tagged release. It
has not been told that the design is on hold.

- **Option a:** tell it now that the API may change and the release is on hold.
- **Option b:** tell it after D1 is decided.
- **Recommendation:** **a**, so it does not build against `AccessTokenVerifier`.

---

## Housekeeping (not a design decision)

The following work is uncommitted on the merged branch `fix/harden-chain-boundary`, one commit
behind `origin/main`:
- the archive of `harden-chain-boundary`;
- the merge of its specs into eight main specs;
- this change directory.

A branch from `origin/main` is the clean home for it. Committing is the user's call.

---

## Suggested order once decided

1. D1 and D2, then revise this change (`/opsx:update`) and regenerate `plans.md`.
2. D6, folded into that revision.
3. D7, splitting if chosen.
4. D8, telling the consumer.
5. D3 and D4, opening the cookie change (`/opsx:explore`, then `/opsx:propose`), where D5 is
   settled.

---

## References

**Researched** (consulted 2026-11-16 to 2026-11-18 for the decisions named):
- Reasoned from scrty's own settled specs and code:
  - `csrf-protection` lines 8–15 and 54–70 (D3, D4);
  - `cors` (D3);
  - `oidc-provider-clients` lines 30–75, `oidc-provider-authorization` line 83 and
    `oidc-provider-consent` line 67 (mobile sign-in);
  - `httpsec/complete.go`, `login.go`, `mfa_verify.go`, `reauth_resolve.go`,
    `session_renewal.go`, `recovery.go`, `errors.go` (D4, D5);
  - `bff-resource-server/design.md` and `handoff.md` (D2-c, D3, D5).
- The user's decision of 2026-11-16 to set aside a separate token switch (D1-C), and their
  questions of 2026-11-16 and 2026-11-17 that opened D1 and D3.

**Primary documentation** (relied on and cited as such, not re-checked on these dates):
- [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750): §3.1 `invalid_token` and `insufficient_scope`.
  Supports D6.
- [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068) and
  [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707): `at+jwt` and audience as a resource indicator.
  Supports D1.
- [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662): token introspection. Supports D2-c.
- [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449): DPoP. Supports D1 and D5.4.
- [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252): §8.12 no embedded user-agents, §7 native
  redirect URIs. Supports the mobile note.
- [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700): the password grant must not be used. Supports
  the mobile note.
- [RFC 6265bis](https://datatracker.ietf.org/doc/draft-ietf-httpbis-rfc6265bis/): `SameSite` and the
  `__Host-` prefix. Supports D3, D4 and D5.5.
- [W3C Fetch Metadata](https://www.w3.org/TR/fetch-metadata/): `Sec-Fetch-Site`. Supports D3.
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html):
  a new session ID after login and privilege change. Supports D5.2 and D5.3.
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html):
  login CSRF. Supports D3 and D4.
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) §3.1.2.3: how the
  provider authenticates the user is left to it. Supports D3.

**Unverified** (from memory, not checked):
- Hosted identity providers advise against cross-origin embedded login because it depends on
  third-party cookies (D3).
- Google blocks OAuth in embedded WebViews (mobile note).
- The current status of `draft-ietf-oauth-first-party-apps` (mobile note).
