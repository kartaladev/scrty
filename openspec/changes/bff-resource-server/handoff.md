# Handoff: `bff-resource-server` exploration

Working notes from an `/opsx:explore` session (2026-10-11 to 2026-10-13). This is not an OpenSpec
artifact. Nothing here is decided: `proposal.md` and `design.md` are unchanged, and every decision
below is still waiting on the user. Use this to resume, then fold the outcomes into the artifacts
and delete this file.

## Where we stopped

The question waiting for an answer:

> **Will scrty's first consumers log users in against their own user store, or are they apps whose
> users already live in an external IdP like Keycloak or Entra ID?**

The answer decides which of the two models below comes first (see "The fork").

## 1. The draft design has drifted from the tree

`design.md` was written on 2026-09-24. Since then, passkeys, recovery codes, multi-method MFA, OIDC
MFA assurance, the clock seam and rate limiting have shipped. Checked against the tree on
2026-10-11:

| Draft says | Tree now | Consequence |
|---|---|---|
| Identifier rotation doesn't exist and needs `sessions` (D5) | `session.Manager.Rotate` exists, and MFA verify already uses it (`httpsec/mfaverify.go:447`) | Half of D5 is built. Its failure semantics differ (next row). |
| D5: a failed delete during rotation deletes the new session, so there are "never two live identifiers" | `Rotate`: a failed delete leaves the old entry alive until its own deadline. Serialisation only holds within one process; across replicas the store must enforce it. | Harmless in token mode, because the old ID is only inside a token the client holds. With cookies, a surviving old ID is what a fixation attack plants. Cookie mode may need stricter rotation. |
| Clearing the password-change marker rotates the session | The gate saves rather than rotates, deliberately (`httpsec/passwordchange.go:176-182`). Its reason: "nowhere to hand a new credential back… no earlier holder". | Neither reason holds with cookies: the library can set the cookie itself, and a planted cookie is an earlier holder. The decision reopens. |
| "One login completion seam" | `completeLogin` (`httpsec/logincomplete.go:261`) serves form login, magic link, OIDC handoff and passkey passwordless. MFA verify (`mfaverify.go:464`) and recovery completion (`recoverycomplete.go:448`) mint tokens on their own, and OIDC has `CallbackSuccess`. | Cookie delivery must reach three minting points plus the callback. |
| CSRF coverage: form login, magic link, step-up, password change | Added since: passkey passwordless begin/finish, passkey registration/rename/remove, recovery start/complete/cancel, MFA enrolment, recovery-code regeneration | The login-CSRF and unsafe-endpoint matrix roughly doubles. |
| D8: no first factor at a resource server "until `oidc-mfa-assurance`" | That change shipped: `session.WithFederatedAssurance(amr, acr)` and `internal/assurance.Federated` | The limit can be revisited by mapping `amr`/`acr` into federated assurance. Only possible inside the core module, because `assurance` is internal. |
| D7: `WithClockSkew`, default 60s | The `token` package doc: "no skew is tolerated" | A skew default departs from a settled decision. It must be argued and recorded. |
| D8: the default mapper turns `sub` into `Principal.ID` | scrty tokens carry the **username** as `sub` (the `token` package doc, "The subject") | For scrty-minted tokens, the mapper would put a username into `Principal.ID`. |
| Proposal: "Modified capabilities: none, no specs archived yet" | `sessions`, `http-security-chain`, `http-error-propagation`, `oidc-login`, `token-issuance` and `framework-adapters` are archived specs | These become real MODIFIED deltas. |
| The header layer "mirrors the standard library" | Go 1.27's `net/http.CrossOriginProtection` checks `Sec-Fetch-Site`, falls back to comparing the `Origin` hostname with `Host`, and allows requests carrying neither | Still usable only as a test oracle, because fiber isn't `net/http`. The draft's plan holds. |
| `design.md` has no `## References` section | — | The research rule requires one. |

Why the `Rotate` delete-failure rule matters once the identifier is a cookie:

```
 token mode                               cookie mode
 ----------                               -----------
 old id lives only inside a token         old id may have been PLANTED by an attacker
 the client itself presents               (sibling subdomain, no __Host- prefix)

 MFA satisfied -> Rotate                  MFA satisfied -> Rotate
   write new id       ok                    write new id       ok
   delete old id      FAILS                 delete old id      FAILS
   old id lives until its deadline          old id lives until its deadline
        |                                        |
        v                                        v
 harmless: nobody else holds it           attacker's planted id now carries
                                          the victim's satisfied second factor
```

Where tokens are minted today, every one of which cookie delivery has to reach:

```
 form login ---------+
 magic link ---------+
 OIDC handoff -------+--> completeLogin --> tokens.Generate   (logincomplete.go:357)
 passkey passwordless+
 OIDC callback -------> CallbackSuccess (consumer override, no token by default)
 MFA verify ----------> Rotate --> tokens.Generate            (mfaverify.go:464)
 recovery complete ---> tokens.Generate                       (recoverycomplete.go:448)
 password-change gate -> save, no rotation, no new credential (passwordchange.go:176)
```

These still hold:

- The `oidc` key-set cache exists (`oidc.DefaultJWKSRefetchCooldown` and friends), so reusing it is
  realistic.
- The library already sets three cookies through the exchange on all three adapters:
  - the OIDC flow cookie: `Lax`;
  - the magic-link binding cookie: `Lax`;
  - the passkey binding cookie: `Strict`.
- The established design has no cookie session, CSRF defence or resource-server mode, so there is
  no inherited behaviour to follow or depart from.

## 2. RFC 10017 (OAuth 2.0 for Browser-Based Applications, BCP 212) versus the draft

The draft never consulted RFC 10017. It was read on 2026-10-11 through a fetch tool that
summarises. **The quotes below come from that summary. Re-read §6.1 in full before citing exact
wording.**

| Topic | RFC 10017 §6.1 | Draft's recommendation | Gap |
|---|---|---|---|
| What a BFF is | A **confidential OAuth client** using the authorization code grant with PKCE. It **proxies** browser requests to resource servers, attaching the access token (§6.1, §6.1.3.6). | In-app middleware (Q1-A); the consumer owns the proxy (Q3-A) | The RFC's BFF is a proxy. The draft describes a cookie-session app that also mints tokens. |
| Token sent to APIs | The authorization server's own access token, kept with the session on the server | Mint an internal scrty JWT (Q2-B) | The RFC doesn't describe minting. |
| Refresh | The BFF refreshes with its refresh token and ends the session when that fails. Session lifetime equals the refresh token's maximum lifetime (§6.1.2.2). | No refresh token (Q5-B) | The opposite choice. |
| `SameSite` | **SHOULD** be `Strict` (§6.1.3.2) | `Lax` | A departure that needs a recorded reason. The draft argues email links and the IdP's return, but never against the RFC. Unverified: whether a `Strict` cookie set during the OIDC callback survives the redirect to `next`. |
| Cookie prefix | **SHOULD** use `__Host-Http-` | `__Host-` | The `Http` part marks the cookie as server-set, so script can't forge it. |
| `Path` / `Domain` | **SHOULD** be `/`; **SHOULD NOT** set `Domain` | The same | Aligned. |
| CSRF | **MUST** have a proper defence. **SHOULD** require a static custom request header on every request, backed by strict CORS. Anti-forgery tokens are acceptable but "not necessarily recommended over the CORS approach". Fetch Metadata isn't mentioned. (§6.1.3.3) | Fetch Metadata / `Origin` check, plus a synchronizer token in a readable `__Host-csrf` cookie | The RFC's preferred defence is simpler: no readable cookie, no rotation. Its limit: a plain HTML `<form>` POST can't add a custom header, so it fits a SPA but not a server-rendered login form. |
| Outbound | **MUST** check outbound destinations against an allowlist (§6.1.3.6) | Not mentioned | `outbound-http-confinement` already does this kind of checking. |
| Pattern ranking | BFF, then token-mediating backend, then browser-only client, in decreasing order of security. BFF is "strongly recommended" for business and sensitive apps (§6, §6.1.4.3). | — | — |

## 3. Why a resource server, when the bearer interceptor exists?

For scrty's own tokens with a shared store, **it isn't needed**. `EnableBearerToken` requires
`Verifier`, `Sessions` and `Users` (`BearerTokenDeps`), so every request sees revocation and role
changes at once. That is stronger than stateless verification.

The bearer path falls short in exactly two situations:

1. **The API can't reach scrty's session and user stores.** All three dependencies are mandatory,
   so a stateless deployment can't be wired at all.
2. **The token comes from another issuer**, as in the RFC 10017 model:
   - `sub` isn't a scrty username and `jti` isn't a scrty session, so both reloads fail;
   - `token.Claims` exposes only `Subject()` and `ID()`, so `scope`/`scp`, `azp`, `amr` and `acr`
     can't be read;
   - `signingkey.KeySource` already expects a remote implementation ("expected to cache"), but none
     ships, and there is no JWKS fetching.

**Candidate reshaping, not decided:** extend the existing seams instead of adding a parallel
`resource` package:

```
 today:   Bearer --> token.Verifier --> Sessions.Load(jti) --> Users.Load(sub) --> policy
                       (in-process KeySource)

 option:  Bearer --> token.Verifier --> [stateless mode: ClaimsMapper --> Principal] --> policy
                       ^
                       remote JWKS KeySource (reusing the oidc key-set cache)
                       + richer Claims (scope, azp, amr, acr)
```

- `Sessions` and `Users` become optional only when a claims mapper is supplied, so dropping them
  by accident still fails at construction.
- That is three additions to existing seams, instead of a second verifier with its own rules on
  algorithms, skew and issuer.

## 4. The fork: which role scrty plays for a browser app

### Model 1: scrty is the identity system (recommended first, not decided)

scrty checks the credential, owns the session, and is the only authority APIs trust. An external
IdP is just one more way to prove a first factor; its tokens are discarded, as `oidc-login` does
today.

```
                       login: password | passkey | magic link | recovery
                              | OIDC (IdP used only at login, its tokens discarded)
 +---------+  cookie   +-------------------------------+
 | Browser | --------> | Consumer app + scrty chain    |
 | (no JS  | <-------- |  scrty session = the truth    |
 |  token) | Set-Cookie|  policy, MFA, revocation      |
 +---------+           +---------------+---------------+
                                       | shared session store  -> bearer path (today)
                                       | or scrty-minted JWT   -> stateless API
                                       v
                               +---------------+
                               |  APIs trust   |
                               |  scrty        |
                               +---------------+
```

New work:

- cookie delivery at `completeLogin`, MFA verify, recovery completion and the OIDC callback;
- a cookie-session interceptor that mirrors the bearer path;
- CSRF protection;
- rotation strict enough for cookies (the `Rotate` delete-failure and password-change gaps in §1).

### Model 2: scrty as RFC 10017's BFF

An external IdP is the authority. scrty is a confidential OAuth client that holds the IdP's tokens
on the server and passes them along.

```
 +---------+  cookie   +-------------------------------+   code+PKCE,   +---------+
 | Browser | --------> | BFF (scrty)                   | <------------> |   IdP   |
 |         | <-------- |  session holds IdP access +   |   refresh      | = truth |
 +---------+           |  refresh token (sealed)       |                +---------+
                       |  proxies /api/* attaching     |
                       |  the IdP's access token       |
                       +---------------+---------------+
                                       | Bearer <IdP token>
                                       v
                               +---------------+
                               |  APIs trust   |
                               |  the IdP      |
                               +---------------+
```

On top of Model 1's work it needs:

- `oidc-login` keeping the IdP's tokens instead of discarding them;
- refresh with rotation, safe across replicas;
- a proxy that only forwards to allowlisted destinations;
- APIs that can verify the IdP's tokens (the stateless bearer extension in §3).

### Why Model 1 first

```
  Model 1 (cookie session, CSRF, rotation)
        |
        +--> Model 2 adds: keep IdP tokens, refresh, proxy, verify IdP tokens
```

- Model 2 needs everything Model 1 builds: the browser cookie, CSRF protection and rotation are the
  same in both.
- Four of the five ways to log in today (form, magic link, passkey, recovery) are local. Model 2
  serves only OIDC.
- **This flips** if the first consumers' users mostly live in an external IdP. Then Model 2 isn't a
  later add-on.

### How the draft's open questions depend on each other

```
  Q1 where the BFF lives ------> Q3 who owns the proxy
        |
        v
  Q4 local accounts? ----------> CSRF endpoint matrix, rotation points
                                  (rotation now touches the password-change gate)

  Q2 which token goes to APIs --> Q5 refresh
        |
        +--------------------> D7/D8 only in the "scrty is the issuer" case
                                   (sub = username vs Principal.ID)

  resource-server for an external issuer:  depends on none of Q1-Q5
```

Choosing Model 1 settles Q1, Q3 and Q5 at once. Choosing Model 2 reverses the draft's
recommendations for Q2 and Q5, and makes Q3 a real question.

### What Model 1 would change in the draft

- **Name:** call it a cookie session for browser apps, not a "BFF", and keep that term for Model 2.
- **Questions that go away:** Q1 (in-app), Q3 (the consumer owns the proxy) and Q5 (no refresh) are
  settled by Model 1 itself. Q2 shrinks to whether a stateless API gets a scrty-minted token.
- **Resource-server mode:** becomes the stateless bearer extension of §3.
- **RFC 10017's cookie and CSRF advice** (`SameSite=Strict`, `__Host-Http-`, a static custom
  header) still applies. Where Model 1 departs from it, record the departure in `design.md`.

## 5. Other threads raised, still open

- **Split the change?** Resource-server and stateless-bearer work barely depends on Q1-Q5 and could
  be specified on its own. Under Model 1 it may shrink to an extension of `http-security-chain` and
  `token-issuance`.
- **The magic-link form parameters and body limit** are carried in `design.md` (Risks) but owe
  nothing to this change. They move to whichever change next edits `httpsec/magiclink.go`.
- **`trusted-proxy-client-ip`** is the other unblocked change. Behind a TLS-terminating proxy, the
  CSRF header layer's comparison of `Origin` with the request's own origin depends on how the host
  and scheme are resolved. Check how the two interact when both are designed.

## Next steps when resuming

1. Get the answer to the question at the top.
2. Re-read RFC 10017 §6.1 in full and confirm the quoted wording, especially §6.1.3.2 (cookies) and
   §6.1.3.3 (CSRF).
3. Decide on the split (§5) and the resource-server reshaping (§3).
4. Revise `proposal.md` and `design.md` (`/opsx:update`):
   - the chosen model, and the name;
   - the drift fixes from §1;
   - departures from RFC 10017 recorded as decisions;
   - a `## References` section.

   Then write specs, `tasks.md` and `plans.md` as `tasks-plans.md` requires.

## Sources

**Researched (accessed 2026-10-11):**

- [RFC 10017, OAuth 2.0 for Browser-Based Applications](https://www.rfc-editor.org/info/rfc10017):
  BFF architecture, cookie attributes, CSRF guidance, pattern ranking. Read through a summarising
  fetch; exact quotes still to be confirmed.
- `go doc net/http.CrossOriginProtection` (Go 1.27.1): the standard library's header-layer
  behaviour.
- The tree on 2026-10-11:
  - `go doc ./session` (`Manager.Rotate`);
  - `go doc ./token` (`Claims`, the subject and skew rules);
  - `go doc ./signingkey KeySource`;
  - `go doc ./httpsec` (`BearerTokenDeps`);
  - the `httpsec/*.go` files named above.

## Update after `first-party-sessions` (2026-10-21)

`first-party-sessions` is implemented on `feat/first-party-sessions-impl`. Several rows of §1 and the
work list of Model 1 in §4 change because of it. Re-check them against the tree when resuming:

- **Shared resolution core.** `httpsec/resolve.go` holds one core that loads and judges the session,
  reloads the user, publishes both and runs the per-request phase. The signed-token bearer and the new
  session-reference bearer (`EnableSessionBearer`) both use it. The cookie mode should call the same
  core with a cookie extractor instead of adding a third path. Consumer interceptors get the same steps
  through `(*Exchange).PublishSession` and `EvaluatePerRequest`, and `WithSessionManager` gives the
  chain its manager explicitly.
- **Credential issuance has one seam.** Every credential-issuing endpoint now issues through one
  unexported issuer: form login, magic link, OIDC handoff, passwordless passkey, MFA verify, recovery
  completion and renewal. Cookie delivery can plug in there, instead of reaching each minting point
  in the table of §1.
- **Rotation is now decided by the store.** `Rotate` supersedes through the store's conditional
  `Supersede` and then deletes the old record, so concurrent rotations cannot leave two live heads
  across replicas. That settles the "`Rotate` delete-failure" row of §1: a failed delete leaves the
  old record superseded with an ended window, so presenting it is reuse. The fixation concern for
  cookies still needs its own argument, but it no longer rests on a process lock.
- **Sessions carry families.** Grace-window renewal (`RotateWithGrace`, `EnableSessionRenewal`), reuse
  detection with family revocation, and logout revoking the whole family are in place. A cookie mode
  inherits them.
- **Per-session lifetime.** `WithAbsoluteLifetime` and `WithLoginLifetime` exist, so a cookie's
  persistence can follow the session's chosen lifetime (`LoginResult.Session`).
