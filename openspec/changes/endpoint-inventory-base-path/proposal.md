# Proposal

## Why

A consumer who wants scrty's endpoints under one prefix, such as `/auth` behind a gateway, has to move them one at a time. Paths are set in four different ways over fifteen `Enable*` options: about thirty `With*Path` and `With*Prefix` options, whole-path overrides on top of the provider's prefix, a struct field (`SessionSignals.Path`), a setting inside an enabling option (the MFA listing's `ListingPath`) and a path passed with a function (`WithPasswordChangeEndpoint`). Missing one leaves an endpoint behind at the root.

The default paths themselves no longer say what each endpoint does. Since the OpenID Provider landed, the chain answers both `/oauth2/authorization/{p}` (scrty signing a user in at another provider) and `/oauth2/authorize` (another application signing a user in at scrty): opposite roles, a few letters apart, under one root. Sign-in methods are spread over `/login`, `/login/magic` and `/passkey/login`.

The chain also has no single view of which endpoints it answers:

- each built-in matches its own paths;
- at least twelve hand-written checks judge path collisions, each with its own list of the other features, which every new feature must extend;
- values derived from one endpoint's path are copied into others (logout exemptions, cross-site exemptions, cookie scopes, the provider's published URLs);
- two follow-up capabilities need that view and have nothing to read: an OpenAPI document of the enabled endpoints (`openapi-document`), and route names for telemetry (`observability`).

Moving endpoints also exposes wiring gaps. Nothing at construction compares an OIDC provider's registered redirect URL with the path the chain answers its callback on; this is **pending reproduction**, and the first task writes the test. Nothing checks that the provider's issuer, from which its discovery documents are placed, agrees with a base path. And routes the consumer gives the chain, such as a recovery cool-down route, would silently stop matching an endpoint that moved, which for the cool-down fails open.

## What Changes

- **A base path for every built-in endpoint.** `httpsec.WithBasePath("/auth")` puts every endpoint the chain answers under one prefix:
  - every path setting, in all four forms, becomes **relative** to it, so `WithBasePath("/auth")` with `WithLoginRequestPath("/signin")` answers `/auth/signin`;
  - the default is no base path;
  - the key set and the provider's endpoints move with the others; the two discovery documents stay where their standards place them from the issuer;
  - a base path that is malformed, moves nothing, or is repeated in a per-feature path is refused at construction.
- **One default path vocabulary.** Defaults are regrouped by what each endpoint does, before the first tag: `/sign-in/{password,magic-link,passkey}`, `/sign-out`, `/sso/{login,callback,handoff,backchannel-logout}/...` for signing in at other providers, `/oauth2/*` only for scrty as a provider, `/passkeys`, `/mfa/challenge/{m}`, `/reauth/challenge/{m}`. The magic-link confirm page default moves to `/sign-in/magic-link/confirm`. Option names do not change.
- **One shape for every endpoint path**: absolute, not the root, clean, and free of characters that need escaping, whichever option sets it.
- **What the base path does not touch:** pages the consumer serves (the magic-link confirm page, the recovery cancel page, the provider's login, consent and logout pages, redirect destinations), the consumer's authorization rules, and consumer interceptors.
- **Everything derived from a path follows the moved path**: gate exemptions, cross-site and cross-origin exemptions, cookie scopes, the provider's published URLs and checks, and session-activity skips.
- **An endpoint inventory.** Every operation of every enabled built-in endpoint is described once: methods, path, how it matches, what it does with other methods, a stable operation identifier, the setting that placed it, and what the request must carry. `(*Chain).Endpoints()` returns it, read-only.
- **One collision check for the whole chain**, within and across features, replacing every hand-written one. Paths may be shared only by declaration. A collision names both settings, both paths and what it would break.
- **Construction-time checks for moved endpoints**, each with a waiver:
  - an OIDC provider's redirect URL path must end with the resolved callback path and the provider's name (`WithoutOIDCRedirectPathCheck`);
  - under a base path, the provider's issuer must cover it, so the OpenID configuration is served under the base (`WithoutOIDCIssuerBasePathCheck`);
  - under a base path, a consumer route left at an endpoint's pre-base path is refused (`WithoutBasePathRouteCheck`); routes given as functions, such as header-profile matchers, cannot be inspected and are documented instead.
- **Godoc and README.** Every path setting says it is relative to the base path; the README lists the default paths, what the base path covers and does not, and the migration steps.

Before the first tag, so no compatibility entry is needed; the changelog records the new defaults and the new refusals.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `http-security-chain`:
  - the base path, its shape and its refusals, and what it covers;
  - the default path vocabulary and the one path shape;
  - derived values following moved paths;
  - stale consumer routes refused;
  - the endpoint inventory and its accessor;
  - one chain-wide collision check;
  - the provider's paths relative to the base, and its issuer covering the base;
  - the key set, MFA listing, login, logout, passkey and recovery-pending requirements, for the new defaults and collision rule.
- `oidc-login`: a redirect URL that cannot reach the resolved callback fails at construction; path collisions are judged chain-wide.
- `oidc-logout`: back-channel path collisions are judged chain-wide.
- `oidc-provider-metadata`: a base path does not move the metadata documents.
- `passkey-authentication`, `multi-factor-auth`, `reauthentication`: new default paths; collisions judged chain-wide.
- `account-recovery`: path collisions judged chain-wide.
- `csrf-protection`, `framework-adapters`, `sender-constrained-tokens`: scenarios use the new default paths.

## Impact

- **Code:**
  - `httpsec`:
    - `WithBasePath`, the shape rule, and resolution in `New` before `validate`, for every interceptor that answers paths, the provider's route maps included;
    - the new default constants;
    - the inventory and `Endpoints()`;
    - the shared collision check, replacing the checks in `mfa_options.go`, `mfa_verify.go`, `mfa_enrol.go`, `passkey.go`, `recovery.go`, `session_renewal.go`, `magiclink.go`, `signals.go`, `reauth_options.go`, `oidc_options.go` and `oidc_provider.go`;
    - derived values reading resolved paths, in the gates, `csrf_exemption.go`, `oidc_cors.go`, `oidc_metadata.go`, `oidc_authorize.go`, `oidc_endsession.go`, `recovery_gate.go` and the cookie-setting endpoints;
    - the issuer, redirect and stale-route checks and their waivers.
  - `authenticate/oidc`: read access to each provider's redirect URL.
  - `authenticate/magiclink`: the confirm page default.
- **Adapters:** `ginsec` and `fibersec` need no code. Their conformance runs gain base-path scenarios.
- **Tests:** every test, example and conformance scenario that names a default path; unit tests per check; `test/httpsecconformance` scenarios on net/http, gin and fiber.
- **Docs:** README sections on the default paths and the base path.
- **Builds on** `reauthentication`, `session-signals` and `oidc-provider`, all archived.
- **Interacts with** the active `bff-resource-server` change: its proposed cross-site exemption overlap check should read the inventory rather than add a hand-written check, and its resource servers point at the key set URL, which a base path moves. `release-readiness` lists this change before the `v0.1.0` tag.
- **Followed by** `openapi-document` and `observability`, which read the inventory.
- **No schema change** and **no new dependency.**

## References

See `design.md`'s References section, which groups the sources by decision.
