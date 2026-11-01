# Proposal

## Why

A consumer who wants scrty's endpoints under one prefix, such as `/auth` behind a gateway, has to move them one at a time. More than twenty path and prefix options are spread over thirteen `Enable*` options, and missing one leaves an endpoint behind at the root.

The chain also has no single view of which endpoints it answers:

- each built-in matches its own paths;
- collisions are checked locally: re-authentication checks its paths against logout, login and MFA, and OIDC checks only its own four;
- two follow-up capabilities need that view and have nothing to read: an OpenAPI document of the enabled endpoints (`openapi-document`), and route names for telemetry (`observability`).

Moving endpoints also exposes a wiring gap. Nothing at construction compares an OIDC provider's registered redirect URL with the path the chain answers its callback on. A base path that moves one and not the other would break every federated login, and nothing would say so until the provider redirected. This is **pending reproduction**: no test shows it yet, and the first task writes one.

## What Changes

- **A base path for every built-in endpoint.** `httpsec.WithBasePath("/auth")` puts every endpoint the chain answers under one prefix:
  - per-feature path options become **relative** to it, so `WithBasePath("/auth")` with `WithLoginRequestPath("/signin")` answers `/auth/signin`;
  - the default is no base path, so every path is exactly what it is today;
  - the key set endpoint moves with the others, to `/auth/.well-known/jwks.json`;
  - an empty base, the root `/`, a base not starting with `/`, and one not in clean form are refused at construction.
- **What the base path does not touch:**
  - the magic-link confirm page and the recovery cancel link, which are the consumer's pages, often on another origin;
  - the consumer's own authorization rules, which describe the consumer's routes, not scrty's.
- **An endpoint inventory.** Every enabled built-in endpoint is described once: method, path pattern, the option that enabled it, a stable operation identifier and the session state it requires. `(*Chain).Endpoints()` returns it, read-only.
- **One collision check for the whole chain.** It runs over the resolved paths and replaces the local checks in re-authentication and OIDC. A collision names both options.
- **OIDC redirect paths are checked at construction.** Each provider's registered redirect URL path must end with the chain's resolved callback path followed by the provider's name. An option waives the check for a proxy that rewrites paths in other ways.
- **Godoc.** Every path option says it is relative to the base path. The magic-link godoc tells the confirm page (not moved) from the consume endpoint (moved).

Not breaking: with no base path set, every request is answered exactly as today. The OIDC check refuses only configurations whose callbacks could never arrive.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `http-security-chain`:
  - the base path and what it covers;
  - the endpoint inventory and its accessor;
  - one chain-wide collision check over the resolved paths;
  - the key-set path scenario under a base path.
- `oidc-login`: a provider's redirect URL path that cannot reach the resolved callback path is a wiring mistake that fails at construction, with a stated waiver.

## Impact

- **Code:**
  - `httpsec`:
    - the base-path option;
    - path resolution at assembly, for every interceptor that answers paths;
    - the inventory and `Endpoints()`;
    - the collision check, replacing `reauthInterceptor.checkPaths` and `oidcInterceptor.checkPaths`;
    - the OIDC redirect check and its waiver.
  - `authenticate/oidc`: read access to each provider's redirect URL, if the relying party does not already expose it.
- **Adapters:** `ginsec` and `fibersec` need no code. They hardcode no chain paths and inherit the core's resolution. Their conformance runs gain base-path scenarios.
- **Tests:**
  - unit tests per resolver and check;
  - `test/httpsecconformance` scenarios on net/http, gin and fiber.
- **Docs:** a README section on the base path, what it covers and what it does not.
- **Builds on** `reauthentication`, whose `/reauth` endpoints are part of the inventory. Implementation starts after it is archived.
- **Followed by** `openapi-document` and `observability`, which read the inventory.
- **No schema change** and **no new dependency.**
