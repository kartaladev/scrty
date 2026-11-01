# Design

## Context

See proposal.md for the motivation.

- **No router.** Each built-in interceptor matches its own paths, which it stores when its option runs (`reauthInterceptor.prefix`, `oidcInterceptor.callbackPath`, ...). An option that runs later cannot change them.
- **Settings resolve after the options.** The chain already defers what depends on chain-wide settings: `config.wiring` runs once every option has been applied, so an `Enable*` given before `WithLogger` still gets the final logger.
- **Path validation is per option.** Each option refuses an empty path, one not starting with `/`, and the root. Collision checks exist only inside re-authentication (`reauth_options.go`) and OIDC (`oidc_options.go`).
- **Adapters add nothing.** gin and fiber hand the request path to the core unchanged and hardcode no chain path.
- **Two kinds of path that are not endpoints:**
  - pages the consumer serves, such as the magic-link confirm page (`magiclink.WithConfirmPath`, under the required `linkBaseURL` origin) and the recovery cancel page (`recovery.WithCancelLink`, an absolute URL);
  - the consumer's own routes, which `EnableAuthorization` rules describe.

## Goals / Non-Goals

**Goals:**
- One option relocates every built-in endpoint.
- One description of the enabled endpoints, which the chain, `openapi-document` and `observability` all read.
- Path conflicts and unreachable OIDC callbacks fail in `New`.

**Non-Goals:**
- Mounting the consumer's application. The base path is where scrty's endpoints live, not where the application is served.
- Describing consumer interceptors. The chain cannot know what an arbitrary interceptor answers.
- A public URL. Where the chain is reachable from outside, behind a proxy that strips a prefix, belongs to `openapi-document`'s server URL, not to path matching.

## Decisions

### D1. Per-feature paths are relative to the base path

```go
func WithBasePath(p string) Option
```

- **Rule.** Every built-in endpoint answers at the base path joined with its own path. A per-feature option sets the path *within* the base, so `WithBasePath("/auth")` with `WithLoginRequestPath("/signin")` answers `/auth/signin`.
- **Default:** none. With no base path, the join is the identity and every path is today's.
- **Validation.** Each of these fails `New` with a configuration error naming the option:
  - an empty base;
  - the root `/`, which is meaningless as a base;
  - a base not starting with `/`;
  - a base not in clean form (`path.Clean(p) != p`, which also excludes `//` and `..`).

  A trailing slash is dropped. The per-feature options keep their own validation unchanged.
- **Given twice.** The last call wins, as `EnableAuthorization`'s authorizer already does. That is the consumer changing their mind, not two settings disagreeing.
- **Resolution happens at assembly.** Each path-answering interceptor keeps the path its option declared and gains an unexported resolve step that `New` runs after every option has been applied. Option order therefore does not matter. Everything derived from a path is derived from the resolved one, including the OIDC flow cookie, which is scoped to the callback path.
- **Override:** each per-feature option, within the base. A consumer who wants one endpoint outside the base sets no base and places every endpoint individually, as today.
- **Alternative rejected: the base applies to defaults only, and an explicit path is absolute.** It is additive, but a consumer reading `WithBasePath("/auth")` beside `WithLoginRequestPath("/signin")` cannot tell where login answers. The rule would also be invisible at the call site. Better Auth's `basePath` moves every route together, as this design does.

### D2. The base path covers exactly the endpoints the chain answers

- **Covered:** every built-in endpoint, the key set included. `/.well-known/jwks.json` becomes `/auth/.well-known/jwks.json`.
- **Why the key set moves too:**
  - RFC 8615 roots well-known URIs at the top of the path, so a path under a base is not well-known by that definition;
  - `jwks.json` is not a registered well-known name. The registry has `openid-configuration` and `oauth-authorization-server`, not a key-set name;
  - clients reach scrty's key set through a configured URL, because scrty serves no discovery document;
  - a gateway that forwards only `/auth/*` would otherwise leave the key set unreachable, without anything saying so.

  **Override:** a consumer who wants the key set at the root serves it from their own `KeySetProvider` on their own route. A later registered discovery endpoint would be placed by its own standard (RFC 8414) when it is designed.
- **Not covered:**
  - **Consumer pages.** The magic-link confirm page and the recovery cancel page are served by the consumer's UI, often on another origin. They are configured on components built before the chain. Rewriting them would make one option govern two subsystems, and would point emails at pages that do not exist. The consume endpoint (`/login/magic/consume`) is a chain endpoint and does move. Its godoc and the confirm page's say which is which.
  - **Authorization rules.** Rules describe the consumer's routes. Rebasing them would turn `/projects/{id}` into a path no request uses, and the default-deny rule set would then refuse every route. Built-in endpoints sit outside the authorization stage and never needed rules.

### D3. The endpoint inventory

```go
type Endpoint struct {
    Methods     []string     // the methods it answers, e.g. ["POST"]
    Path        string       // resolved, with segments as {name}: "/auth/mfa/verify/{method}"
    Match       PathMatch    // MatchExact, MatchSegment (the prefix and one segment), or
                             // MatchSubtree (the prefix and everything beneath it)
    OperationID string       // stable: "scrty.login", "scrty.mfa.verify", ...
    EnabledBy   string       // the option that enabled it: "EnableFormLogin"
    Requires    SessionState // none, pending second factor, full session, ...
}

func (c *Chain) Endpoints() []Endpoint
```

- **Every path-answering built-in declares its endpoints** through an unexported method. `New` collects them after resolution and before the collision check (D4), in slot order and then registration order.
- **The view is read-only.** `Endpoints()` returns a copy, built once.
- **Operation identifiers are a documented contract.** They are `scrty.` followed by the feature and step, stable across releases. `openapi-document` uses them as `operationId`s, and `observability` as operation names.
- **Consumer interceptors are not listed.** This is a stated limit. The godoc says so.
- **Later changes extend the record.** `openapi-document` adds request, response and refusal descriptors. This change carries only what the base path, the collision check and route names need.
- **Override:** none. The inventory describes the chain and changes nothing it does.
- **Alternative rejected: each later capability re-collects paths from the interceptors.** That repeats the scattered `checkPaths` pattern three times over.

### D4. One collision check over the resolved paths

- **What it checks.** After resolution, every pair of endpoints is checked.
  - **The rule.** Two endpoints collide when some request path would be answered by both, given how each matches. The code has three ways: exact (login, logout, recovery codes, passkey credentials), the prefix and one segment (OIDC), and the prefix and everything beneath it (MFA and re-authentication begin and verify, which answer even a path naming no method).
  - **One exemption.** Two endpoints of the **same option** that answer **different methods** on one path do not collide. Recovery codes answer GET (the count) and POST (regeneration) on one path. Endpoints of different options collide whatever their methods, as the existing checks treat them.
  - **One extra rule, kept from OIDC.** An exact path equal to another endpoint's prefix, with or without its trailing slash, collides, because a reader cannot tell the two apart.
- **Error.** The configuration error names both options and both resolved paths.
- **What it replaces.** The re-authentication and OIDC checks become declarations in the inventory. The behaviour they pinned is kept, and their tests move to the shared check.
- **Override:** none. A collision means one endpoint silently swallows the other's requests, so it is never a valid configuration.

### D5. An OIDC redirect URL must be able to reach the callback

- **Check.** For each provider, the path of its registered `RedirectURL` must **end with** the resolved callback path followed by the provider's name. Otherwise `New` fails, naming the provider, its redirect path and the resolved callback path.
- **Why "ends with" and not "equals".** A proxy that strips a public prefix is legitimate: the provider redirects to `/public/login/oauth2/callback/corp`, and the chain sees `/login/oauth2/callback/corp`. Equality would refuse that setup. The suffix still catches the drift a base path introduces: a redirect URL left at `/login/oauth2/callback/corp` cannot end with `/auth/login/oauth2/callback/corp`.
- **Pending reproduction.** The first task is a failing test. It moves the callback path (`WithOIDCCallbackPath`, or the base path once it exists) and shows `New` accepting a provider whose redirect URL can no longer arrive. If that test passes on the current code, the gap was wrong and this decision is removed.
- **Override:** `WithoutOIDCRedirectPathCheck()`, for a proxy that rewrites paths beyond stripping a prefix. Its godoc states what it gives up: a mismatch is then found only when a provider redirects.
- **Alternative rejected: no check.** A base path makes the mismatch likely, and the failure would surface only as a provider redirect that never arrives.

### D6. The base path is matched against the path the chain sees

- The chain compares the base against the request path it receives. A consumer whose proxy or `http.StripPrefix` already removes `/auth` sets no base path.
- The godoc says so, and points to `openapi-document`'s server URL for the public prefix.
- **Override:** none needed. The two settings describe different things.

### D7. Compatibility

- No existing call changes behaviour: with no base path, every resolved path equals today's.
- The godoc of every per-feature path option changes, to say the path is relative to the base path.
- The only new refusal is D5's, for a configuration whose callbacks could not arrive.
- Before the first tag (`release-readiness`, `v0.1.0`), none of this needs a compatibility entry. It is still recorded in the changelog.

## Risks / Trade-offs

- **The confirm page and the consume endpoint may be confused.** Their default paths differ by one word. → Both godocs and the README name the difference. The README's base-path section lists what does not move.
- **An endpoint matches a path it does not declare,** and the inventory drifts from what the chain answers. → A conformance test sends a request to every inventoried path and asserts that its endpoint answers. Each interceptor's own tests assert that a path it does not declare passes through.
- **D5's suffix rule wrongly passes or refuses an unusual proxy setup.** → The waiver, whose godoc states the cost. The suffix rule is the narrowest check that still catches base-path drift.
- **Consumers expect consumer interceptors in `Endpoints()`.** → The godoc states the limit. A consumer who wants them listed keeps their own list.

## Migration Plan

Nothing to migrate: existing configurations behave as before. A consumer adopting a base path does three things:

1. Sets `WithBasePath`.
2. Updates each OIDC provider's registered redirect URL. D5 refuses construction until they agree.
3. Points resource servers at the moved key-set URL.

## References

### Researched (accessed 2026-11-01)

**D1: per-feature paths relative to one base**
- [Better Auth: options reference](https://www.better-auth.com/docs/reference/options): `basePath` (default `/api/auth`) mounts every route together; no per-endpoint relocation is described, only `disabledPaths`.

**D2: the key set moves with the base**
- [RFC 8615 §3](https://www.rfc-editor.org/rfc/rfc8615.html): well-known URIs are rooted at the top of the path, and "/foo/.well-known/example" is not one.
- [IANA Well-Known URIs registry](https://www.iana.org/assignments/well-known-uris/well-known-uris.xhtml): no `jwks` or `jwks.json` suffix is registered; `openid-configuration` and `oauth-authorization-server` are.

**D2 (what is not covered), D3, D4, D5, D6, D7**
- Reasoned from scrty's own settled specs (`http-security-chain`, `oidc-login`, `magic-link`, `account-recovery`, `authorization`, `framework-adapters`).

### Primary documentation

- [RFC 8414: OAuth 2.0 Authorization Server Metadata](https://www.rfc-editor.org/rfc/rfc8414.html): where a registered discovery document is placed relative to an issuer with a path, for when such an endpoint is designed.
