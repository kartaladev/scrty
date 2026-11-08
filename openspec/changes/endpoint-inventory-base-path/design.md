# Design

## Context

See proposal.md for the motivation.

- **No router.** Each built-in interceptor matches its own paths, which it stores when its option runs (`formLogin.path`, `reauthInterceptor.prefix`, `oidcInterceptor.callbackPath`, `oidcEndpoints.paths`, `sessionSignals.cfg.Path`, ...). The provider additionally keys its route maps by path when its option runs (`settlePaths`, `routers`). An option that runs later cannot change any of them.
- **Path checks run at three moments.** `New` applies every option, then runs `validate` (every `c.enable` check: re-authentication and OIDC `checkPaths`, recovery and the provider's `check`, `checkDPoPURL`, `checkAssertionEndpoint`), then `build`, which runs the `wire*` steps (`wireMFA`, `wirePasskeys`, `wireMFAEnrolment` judge collisions there), `config.wiring`, `afterWiring` and `commits`. Some checks run inside options themselves (MFA verify against begin, the provider's `settlePaths` and `routers`).
- **Path settings take four forms.** `With*Path`/`With*Prefix` options; whole-path overrides on top of a prefix (`WithOIDCProviderPath`); a struct field (`SessionSignals.Path`) or a setting function inside an enabling option (`ListingPath` in `WithMFAMethodListing`); and a path passed with a function (`WithPasswordChangeEndpoint`). Their validation differs: several refuse only an empty path and accept `signin` or `/`, `WithOIDCProviderPath` accepts dot segments, and the signal stream refuses a trailing slash.
- **Collision checks are scattered.** At least these judge path collisions, each with its own list of the other features: `mfa_options.go` (verify against begin), `mfa_verify.go` and `mfa_enrol.go` (logout against their prefixes), `passkey.go`, `recovery.go`, `session_renewal.go`, `magiclink.go`, `signals.go` (reusing re-authentication's `claimedPaths`/`collides`), `reauth_options.go`, `oidc_options.go`, and the provider's `settlePaths`, `routers`, `checkCollisions`, `checkConsentSubtree`, `oidcForeignPaths` and `oidcForeignPrefixes`. A feature added later must be added to every other feature's list.
- **Values are derived from paths and handed between interceptors.** `config.logoutPath` is copied into the MFA, enrolment, password-change and recovery gates; the recovery gate exempts the enrolment prefixes and passkey paths; the CSRF layer exempts the back-channel prefix and the provider's POST endpoints; the provider's CORS scope, metadata URLs, POST bounce URLs, DPoP URL check and assertion audience check read its paths; the OIDC flow, passkey ceremony and magic-link binding cookies are scoped to a path; session touch skips the signal stream's path.
- **The provider publishes URLs from its issuer.** `publicURL`/`publicPath` publish the issuer's origin followed by the served path, with the issuer's path put in front when the served path is not under it. The OpenID configuration is served at the issuer's path followed by `/.well-known/openid-configuration` when the token endpoint is under the issuer's path, and at the root otherwise; the authorization server metadata at `/.well-known/oauth-authorization-server` followed by the issuer's path. `jwks_uri` names the chain's key set endpoint.
- **Adapters add nothing.** gin and fiber hand the request path to the core unchanged and hardcode no chain path.
- **Paths that are not endpoints:** pages the consumer serves (the magic-link confirm page, the recovery cancel page, the provider's login, consent, logout and logged-out pages, redirect destinations); routes the consumer gives the chain (authorization rules, recovery cool-down routes, cross-site exemptions, header-profile paths).

## Goals / Non-Goals

**Goals:**
- One option relocates every built-in endpoint.
- Default paths that say what each endpoint does, with the relying-party and provider roles apart.
- One description of the enabled endpoints, which the chain, `openapi-document` and `observability` all read.
- Path conflicts, unreachable OIDC callbacks, an issuer that does not cover the base path, and consumer routes left behind by a move fail in `New`.

**Non-Goals:**
- Mounting the consumer's application. The base path is where scrty's endpoints live, not where the application is served.
- Describing consumer interceptors. The chain cannot know what an arbitrary interceptor answers.
- Changing request or response shapes, or option names. Only path values change.
- A public prefix that a proxy strips. The provider's issuer already states its public URL; `openapi-document` will add a server URL for the rest.

## Decisions

### D1. Per-feature paths are relative to the base path

```go
func WithBasePath(p string) Option
```

- **Rule.** Every built-in endpoint answers at the base path followed by its own path. Every path setting, in all four forms, sets the path *within* the base: `WithBasePath("/auth")` with `WithLoginRequestPath("/signin")` answers `/auth/signin`, and `WithOIDCProviderPath(OIDCToken, "/tokens")` answers `/auth/tokens`.
- **The join is concatenation**, never `path.Join`: D4's shape rule makes every operand a clean absolute path, so concatenation cannot produce `/authsignin`, a doubled slash, or a path that escapes the base.
- **Default:** none. With no base path, the join is the identity.
- **Given twice.** The last call wins, as `EnableAuthorization`'s authorizer already does. That is the consumer changing their mind, not two settings disagreeing.
- **Resolution runs in `New` between the option loop and `validate`.** Each path-answering interceptor keeps the path its option declared and gains an unexported resolve step. The provider's `settlePaths` and `routers` move after resolution, and the collision checks that ran inside options or `wire*` steps are retired into D7. Every check and everything derived from a path (D11) then reads resolved paths, so option order does not matter.
- **Override:** each path setting, within the base. A consumer who wants one endpoint outside the base sets no base and places every endpoint individually, as today.
- **Alternative rejected: the base applies to defaults only, and an explicit path is absolute.** A consumer reading `WithBasePath("/auth")` beside `WithLoginRequestPath("/signin")` could not tell where sign-in answers. Better Auth's `basePath` moves every route together, as this design does.

### D2. The base path covers exactly the endpoints the chain answers

- **Covered:** every built-in endpoint, the key set and the provider's endpoints included.
- **Why the key set moves too:**
  - RFC 8615 roots well-known URIs at the top of the path, so a path under a base is not well-known by that definition, and `jwks.json` is not a registered well-known name;
  - clients find the key set through the provider's published `jwks_uri`, which follows the resolved path (D11), or through a URL the consumer configures;
  - a gateway that forwards only `/auth/*` would otherwise leave the key set unreachable, without anything saying so.

  **Override:** the key set path option, within the base; or the consumer serves keys from their own route.
- **Not covered, by their standards:** the two discovery documents. OpenID Connect Discovery §4 places the OpenID configuration at the issuer followed by `/.well-known/openid-configuration`; RFC 8414 §3 places the authorization server metadata by inserting `/.well-known/oauth-authorization-server` between the host and the issuer's path, so it is always at the host root. D8 keeps the first under the base.
- **Not covered, because the consumer owns them:**
  - **Consumer pages:** the magic-link confirm page, the recovery cancel page, the provider's login, consent, logout and logged-out pages, and redirect destinations. They are served by the consumer's UI, often on another origin, and configured on components built before the chain. Rewriting them would point emails and redirects at pages that do not exist. The magic-link redeem endpoint is a chain endpoint and does move; its godoc and the confirm page's say which is which.
  - **Authorization rules.** Rules describe the consumer's routes. Rebasing them would turn `/projects/{id}` into a path no request uses, and the default-deny rule set would refuse every route. Built-in endpoints sit outside the authorization stage.
  - **Routes the consumer gives the chain** (recovery cool-down routes, cross-site exemptions, header-profile paths) are not rebased either; D9 refuses the ones left pointing at a moved endpoint.

### D3. Default paths say what each endpoint does

**Departure from the established design.** The established design, like Spring Security, places relying-party sign-in under `/oauth2/authorization/{p}` and `/login/oauth2/callback/{p}`. Since the provider landed, the chain also answers `/oauth2/authorize`: two opposite roles a few letters apart under one root. Sign-in methods are scattered over `/login`, `/login/magic` and `/passkey/login`. scrty replaces the defaults with one vocabulary, grouped by what each endpoint does, before the first tag:

| Endpoint | Before | Default |
|---|---|---|
| Password sign-in | `/login` | `/sign-in/password` |
| Magic link request, redeem | `/login/magic`, `/login/magic/consume` | `/sign-in/magic-link`, `/sign-in/magic-link/redeem` |
| Magic link confirm page (consumer page, `magiclink.WithConfirmPath`) | `/login/magic/confirm` | `/sign-in/magic-link/confirm` |
| Passwordless passkey | `/passkey/login/{begin,finish}` | `/sign-in/passkey/{begin,finish}` |
| Logout | `/logout` | `/sign-out` |
| SSO start, callback | `/oauth2/authorization/{p}`, `/login/oauth2/callback/{p}` | `/sso/login/{p}`, `/sso/callback/{p}` |
| SSO handoff, back-channel logout | `/login/oauth2/handoff`, `/logout/oauth2/backchannel/{p}` | `/sso/handoff`, `/sso/backchannel-logout/{p}` |
| Passkey registration | `/passkey/register/*` | `/passkeys/register/*` |
| Passkey list, rename, remove | `/passkey/credentials{,/rename,/remove}` | `/passkeys{,/rename,/remove}` |
| MFA begin, re-authentication begin | `/mfa/begin/{m}`, `/reauth/begin/{m}` | `/mfa/challenge/{m}`, `/reauth/challenge/{m}` |
| Provider | `/oauth2/*` | unchanged: `/oauth2` now means only "scrty is the provider" |
| Key set, renewal, signals, sessions, MFA verify/methods/enrolment, recovery, re-authentication verify/methods/password | | unchanged |

- **Rules behind the table:** kebab-case segments; plural nouns for collections (`/passkeys`, `/sessions`); an action that is not a resource is a POST to a named sub-path (`/sign-in/password`, `/mfa/challenge/{m}`), as the Azure guidelines and AIP-136 allow. DELETE is used only where it already is (`/sessions/{handle}`, `/oauth2/consents/{client}`).
- **Why not DELETE for sign-out, or POST to a session collection for sign-in.** Zalando's noun-only style would make sign-out `DELETE /session`. Browser forms send only GET and POST, and form sign-in and sign-out work without JavaScript; the cross-site layer also assumes POST for them.
- **Why the SSO segments are siblings.** With `/sso/{p}` and `/sso/callback/{p}`, a provider the consumer named `callback` would make the two ambiguous. `login`, `callback`, `handoff` and `backchannel-logout` side by side avoid that, and a gateway needs only `/sso/*`.
- **Option names do not change.** `WithLoginRequestPath`, `WithMFABeginPrefix` and the rest keep their names; only their defaults change. The MFA "begin step" keeps its name in godoc; its path says what it does.
- **Override:** every path setting, as today.
- **Alternative rejected: keep the established defaults.** The relying-party and provider roles stay a few letters apart under one root.
- **Alternative rejected: move only the relying-party paths.** It fixes the clash but leaves sign-in methods scattered; the user chose the full vocabulary.

### D4. Every endpoint path has one shape

- **Rule.** The base path and every built-in endpoint path, whatever form sets it: non-empty, starts with `/`, not the root, in clean form once one trailing slash is set aside (`path.Clean`), and made only of letters, digits, `-`, `.`, `_`, `~` and `/`. A path that breaks it fails `New` naming the option that set it.
- **Why one rule.** D1's concatenation is only safe on clean absolute paths. The provider publishes paths as served and refuses ones that need escaping; the signal stream refuses `?`, `#` and `%`; a base path holding any of those would break each guarantee at once.
- **What changes against today.**
  - Refused: `signin`, `/` and dot segments, which several options accept today and which either never matched or matched what the consumer did not mean.
  - Refused: the sub-delimiters `:`, `@`, `+`, `,`, `;`, `=` and `!`, which the provider accepts today and which do match requests. They are refused because a character set every feature can publish and match safely is narrower than what any one feature tolerates.
  - Accepted: a trailing slash on the signal stream path, which it refuses today; the path is matched exactly, so `/session/signals/` simply names that path.

  D13 lists each.
- **Override:** none. The rule is what makes published URLs, prefix matching and D1's join correct; a path outside it cannot be served correctly.

### D5. Base paths that move nothing, or move twice, fail at construction

- **A base path on a chain with no built-in endpoint** fails `New`: it is meaningless configuration (`library-design.md` rule 6).
- **A per-feature path the consumer set at or under the base path**, judged on whole segments, fails `New` naming the option and the doubled result: `WithBasePath("/auth")` with `WithLoginRequestPath("/auth/sign-in/password")` would answer `/auth/auth/sign-in/password`. `/api-keys` under `/api` is not a repeat. Default paths are not judged: a base path such as `/sso` that repeats a default's first segment gives `/sso/sso/login/`, which is what the consumer configured and is documented, not refused.
- **Override:** none for either. A base path that moves nothing does nothing; a path that repeats its own base is never intended, and the godoc of `WithBasePath` says so. A consumer who truly wants `/auth/auth/...` writes the inner `auth` into a base of `/auth/auth`.

### D6. The endpoint inventory

```go
type Endpoint struct {
    Methods      []string     // the methods this operation answers, e.g. ["POST"]
    Path         string       // resolved, with segments as {name}: "/auth/mfa/verify/{method}"
    Match        PathMatch    // MatchExact, MatchSegment (the path and one segment),
                              // MatchSubtree (the path and everything beneath it)
    OtherMethods MethodPolicy // PassThrough, or Refused when the endpoint answers 405
    SharesPath   string       // non-empty when the operation declares it shares its path
    OperationID  string       // stable: "scrty.sign-in.password"
    PlacedBy     string       // the option or setting that placed it: "WithMFAMethodListing"
    Requires     Requirement  // what the request must carry
}

func (c *Chain) Endpoints() []Endpoint
```

- **One entry per operation.** An endpoint answering GET and POST with different meanings (recovery codes) is two entries sharing a path, each declaring the same `SharesPath`. The declared sharers are: recovery codes (`count`, `regenerate`); session management (`sessions.list`, `sessions.end-others`, `sessions.end`); consents (`consents.list`, `consents.revoke`).
- **`Path` and `Match`.** `Match` applies to the part of `Path` before its first `{…}` segment, which only names what the endpoint reads there. `MatchSubtree`: MFA challenge and verify, the three enrolment prefixes, re-authentication challenge and verify. `MatchSegment`: SSO login, callback and back-channel logout, `sessions/{handle}`, `consents/{client}`. Every other entry is `MatchExact`.
- **`Requires`:** `RequiresNothing`, `RequiresAuthentication`, `RequiresPendingSecondFactor`, `RequiresPendingEnrolment`, `RequiresSession`, `RequiresBearer`, `RequiresClientAuthentication`. It names the least the endpoint itself needs before it serves the request, not every state the chain's gates let through:
  - `RequiresAuthentication`: any authenticated caller, whatever the mechanism (session, bearer, API key, Basic). Sign-out declares it.
  - `RequiresSession`: a session. A gate may let a pending session reach the endpoint (passkey registration during enrolment or recovery); that is the gate's rule, stated in the gate's godoc, not the endpoint's requirement.
  - `RequiresClientAuthentication`: the client identifies itself as its registration requires. A public client sends only its identifier (and PKCE at the token endpoint); a confidential client authenticates.
  - Each value's godoc states this, and the inventory test table pins each endpoint's value. A consumer generating security requirements from it (`openapi-document`) reads the least requirement, and documents the gates separately.
- **Every path-answering built-in declares its operations** through an unexported method, at the slot that answers them (the provider's resume and consents at its inner slot). `New` collects them after resolution and after wiring, because some endpoints are switched on only by wiring (the SSO handoff, recovery start, hold and saved codes), and before the collision check (D7), in slot order and then registration order.
- **An operation identifier appears at most once per chain.** A configuration that would list one twice (a built-in enabled twice, such as two key sets) fails `New`, naming the identifier and both settings: an operation that answers in two places has no single identifier for `openapi-document` or `observability` to use. The discovery documents are listed at the paths they are actually served on, outside the base when D8 is waived.
- **The view is read-only.** `Endpoints()` returns a deep copy, built once: the slice and each entry's `Methods` are cloned, so a caller cannot reach the chain's own copy.
- **Operation identifiers are a documented contract**, `scrty.` followed by feature and step, stable across releases. `openapi-document` uses them as `operationId`s, and `observability` as operation names:

  | Feature | Operation identifiers |
  |---|---|
  | Sign-in, sign-out | `scrty.sign-in.password`, `scrty.sign-in.magic-link.request`, `scrty.sign-in.magic-link.redeem`, `scrty.sign-in.passkey.begin`, `scrty.sign-in.passkey.finish`, `scrty.sign-out` |
  | SSO (relying party) | `scrty.sso.login`, `scrty.sso.callback`, `scrty.sso.handoff`, `scrty.sso.backchannel-logout` |
  | Session | `scrty.session.renewal`, `scrty.session.signals`, `scrty.sessions.list`, `scrty.sessions.end-others`, `scrty.sessions.end`, `scrty.password.change` |
  | Second factor | `scrty.mfa.challenge`, `scrty.mfa.verify`, `scrty.mfa.methods`, `scrty.mfa.enrolment.begin`, `scrty.mfa.enrolment.confirm`, `scrty.mfa.enrolment.confirm-email` |
  | Passkeys | `scrty.passkeys.register.begin`, `scrty.passkeys.register.finish`, `scrty.passkeys.register.confirm`, `scrty.passkeys.register.confirm-email`, `scrty.passkeys.list`, `scrty.passkeys.rename`, `scrty.passkeys.remove` |
  | Recovery | `scrty.recovery.complete`, `scrty.recovery.start`, `scrty.recovery.finish`, `scrty.recovery.cancel`, `scrty.recovery.codes.count`, `scrty.recovery.codes.regenerate` |
  | Re-authentication | `scrty.reauth.methods`, `scrty.reauth.challenge`, `scrty.reauth.verify`, `scrty.reauth.password` |
  | Key set | `scrty.key-set` |
  | Provider | `scrty.oauth2.authorize`, `scrty.oauth2.authorize.resume`, `scrty.oauth2.token`, `scrty.oauth2.userinfo`, `scrty.oauth2.revoke`, `scrty.oauth2.introspect`, `scrty.oauth2.end-session`, `scrty.oauth2.end-session.confirm`, `scrty.oauth2.consents.list`, `scrty.oauth2.consents.revoke`, `scrty.oauth2.openid-configuration`, `scrty.oauth2.authorization-server-metadata` |

- **Consumer interceptors are not listed.** This is a stated limit, in the godoc.
- **Later changes extend the record.** `openapi-document` adds request, response and refusal descriptors.
- **Override:** none. The inventory describes the chain and changes nothing it does.
- **Alternative rejected: each later capability re-collects paths from the interceptors.** That repeats the scattered pattern of the collision checks.

### D7. One collision check replaces every hand-written one

- **What it checks.** After resolution, every pair of inventoried operations, within one feature and across features.
  - **The rule.** Two operations collide when some request path would be answered by both, given how each matches (exact, one segment, subtree). An operation whose endpoint answers 405 to other methods claims its path for every method.
  - **One exemption, declared.** Two operations of one feature that declare the same `SharesPath` do not collide when either they answer different methods, or one matches exactly and the other matches its path followed by one non-empty segment (`DELETE /sessions` beside `DELETE /sessions/{handle}`). Sharing is never inferred from the option that placed them: two provider overrides set to one path would otherwise be accepted, and the provider's route map would silently drop one handler.
  - **Kept from OIDC, for any pair that has not declared sharing.** An exact path equal to another operation's prefix, with or without its trailing slash, collides, because a reader cannot tell the two apart. It applies within one feature too (the SSO handoff path equal to the authorize prefix), as the established check does; only declared sharing exempts it.
- **Error.** Names both options or settings that placed the paths (`WithMFAMethodListing`, `WithPasswordChangeEndpoint`, not only the `Enable*`), both resolved paths, and what the collision breaks, keeping the explanations the local checks gave ("a session owing a second factor could not sign out"). When several pairs collide, the first in inventory order is reported, so the error is deterministic.
- **What it replaces.** Every check listed in Context: the MFA, enrolment, passkey, recovery, renewal, magic-link, signal-stream, re-authentication, OIDC and provider collision checks, `claimedPaths` and `collides` included. Their tests move to the shared check's table with their assertions kept, except the error wording. Per-option shape validation moves to D4's single rule.
- **Changed verdicts.** Some cross-feature pairs no current check covers (password sign-in and magic-link request on one path) are refused for the first time. Unifying match kinds also accepts what was refused: re-authentication judged the passkey registration prefix as a subtree, while passkey registration matches four exact paths, so a re-authentication prefix of `/passkeys/register` now builds. Each such case is listed in D13 and pinned by a test.
- **Override:** none. A collision means one endpoint silently swallows the other's requests, so it is never a valid configuration.

### D8. Under a base path, the provider's issuer must cover it

- **Check.** When a base path is set and the provider is enabled, `New` fails naming the issuer and the base path unless the OpenID configuration would be served at or under the base path and every published URL names a path the chain serves. Stated on what is actually served: the issuer's path, trailing slash trimmed, equals the base path or lies under it; and every path the provider serves, and the key set, lie under the issuer's path. Otherwise `servedPaths` places the document at the root, and `publicPath` puts the issuer's path in front of an already-based path, publishing a URL the chain does not serve.
- **Default:** on whenever both a base path and the provider are set. Without a base path nothing changes.
- **Why refuse.** A consumer adopting a base path behind a gateway that forwards only `/auth/*` would otherwise serve discovery at the root, unreachable, and find out at a client's first discovery call.
- **What it does not cover.** The authorization server metadata is always at the host root (RFC 8414 §3). The README says a proxy must route it.
- **Override:** `WithoutOIDCIssuerBasePathCheck()`, for a gateway that routes `/.well-known/*` to the chain. Its godoc states what it gives up: discovery may then be served outside the base. With the waiver, a root issuer and a provider built with `AudienceIssuerOrTokenEndpoint`, the assertion token endpoint (`issuer` followed by `/oauth2/token`) no longer matches the published token endpoint, and the existing assertion endpoint check refuses it; a test pins that. Under the default issuer-only audience that check does not run, and nothing is refused.

### D9. Consumer routes left pointing at a moved endpoint fail at construction

- **Check.** When a base path is set, `New` fails naming the route and the endpoint when a route the consumer gives the chain as a path (a recovery cool-down route, a `WithCSRFExemption` route) would match a request to a built-in endpoint's path as written before the base path was applied.
- **A route at a current path is not stale.** A route that an endpoint answers at its resolved path, for that method, names where the endpoint is now, even when it also matches another endpoint's pre-base path (base `/reauth` with sign-in moved to `/verify/x`: a route at `POST /reauth/verify/x` is sign-in's, not a stale re-authentication route). Such a route is applied, never refused; otherwise the only way out would be the waiver, which drops the check for every route.
- **How routes are compared.** A route is stale only for a method the moved endpoint answers: a `PUT` cool-down route on the re-authentication password path is not refused, since that endpoint never answers `PUT`, and cool-down routes treat `HEAD` as `GET`. Each route is compared in its own matcher's normal form: cool-down routes lower-cased with the trailing slash trimmed, as the cool-down matches them; cross-site exemptions as their pattern matches, `*` segments included. A route "lies under" an endpoint only when that endpoint matches a subtree or a segment; an exact endpoint is hit only by an equal route.
- **Default:** on whenever a base path is set.
- **Why refuse.** Such a route silently stops matching. For the recovery cool-down, that fails open: a sensitive action is allowed during the cool-down.
- **Stated limit.** Routes given as functions cannot be inspected and are not checked: header-profile matchers (`WithHeaderProfile` takes a `RouteMatcher`) and any other function matcher. Their godoc says paths they compare must be resolved ones, and `Endpoints()` gives them.
- **Override:** `WithoutBasePathRouteCheck()`, for a consumer who serves a route of their own at such a path. Its godoc states what it gives up.

### D10. An OIDC redirect URL must be able to reach the callback

- **Check.** For each provider, the decoded path of its registered `RedirectURL` must end with the resolved callback path followed by the provider's name. Otherwise `New` fails, naming the provider, its redirect path and the resolved callback path.
- **Default:** on whenever OIDC login is enabled.
- **Why "ends with" and not "equals".** A proxy that strips a public prefix is legitimate: the provider redirects to `/public/sso/callback/corp`, and the chain sees `/sso/callback/corp`. The suffix still catches the drift a base path or a moved callback introduces.
- **Pending reproduction.** The first task is a failing test. It moves the callback path and shows `New` accepting a provider whose redirect URL can no longer arrive. If that test passes on the current code, the gap was wrong and this decision is removed.
- **Override:** `WithoutOIDCRedirectPathCheck()`, for a proxy that rewrites paths beyond stripping a prefix. Its godoc states what it gives up: a mismatch is then found only when a provider redirects.
- **Alternative rejected: no check.** A base path, and D3's new callback default, make the mismatch likely.

### D11. Everything derived from a path follows the resolved path

- Because resolution runs before `validate` (D1), each value in Context's list is computed from resolved paths: `config.logoutPath` and every gate it is copied into, the recovery gate's exemptions, the CSRF and CORS exemptions, the provider's published and bounce URLs, its DPoP and assertion checks, the three cookie scopes, and session touch's skip of the signal stream.
- Each is pinned by a test under a base path. The inventory drift guard (D6) adds near-miss probes per entry.
- **Override:** none. A derived value that disagreed with the path it derives from would be a defect, not a choice.

### D12. The base path is matched against the path the chain sees

- The chain compares the base path against the request path it receives. A consumer whose proxy or `http.StripPrefix` already removes `/auth` sets no base path. The chain never reads `X-Forwarded-Prefix` (`trusted-proxies`).
- Where the chain is reachable from outside is stated by the provider's issuer for the provider, and later by `openapi-document`'s server URL.
- **Override:** none needed. The two settings describe different things.

### D13. Compatibility

- With no base path and the new defaults, every endpoint answers at D3's paths. Configurations that set paths explicitly keep them, except where D4, D5, D7, D8, D9 or D10 now refuse them.
- Changed verdicts, each pinned by a test:
  - refused: relative paths, `/` and dot segments in options that accept them today (D4);
  - refused: the sub-delimiters `:`, `@`, `+`, `,`, `;`, `=`, `!` in provider paths (D4);
  - accepted: a trailing slash on the signal stream path (D4);
  - refused: base paths that move nothing or that a consumer-set path repeats (D5);
  - refused: a built-in enabled twice so that one operation would be listed twice, such as two key sets on different paths (D6);
  - refused: password sign-in and magic-link request on one path, and other cross-feature pairs no current check covers (D7);
  - accepted: a re-authentication prefix of `/passkeys/register` or `/passkeys`, which re-authentication's subtree judgement refused; its paths no longer overlap any passkey operation (D7);
  - accepted: the MFA method listing under the verify or challenge prefix. The listing answers GET on its exact path, and the prefix answers POST and passes other methods on, so no request reaches both. On the prefix itself or on the logout path it is still refused (D7);
  - accepted: a recovery finish or cancel path shared with the recovery start path or the passkey credentials list while no recovery can be held, since the finish and cancel endpoints then do not exist. With a hold the same configuration is refused (D7).
  - accepted: a path under another feature's prefix that the feature does not answer. Each feature claims only the paths its entries declare, so the signal stream at `/reauth` or `/reauth/stream`, the provider's token at `/sso/login/idp/x` or `/sessions/a/b`, and the SSO handoff (POST) one segment under the authorize prefix (GET) all build: no request reaches both (D7);
  - judged only when served: an endpoint switched off (the SSO handoff without redemption, recovery start without issued codes, recovery finish and cancel without a hold) no longer takes part in collisions (D6, D7).
  - passed through: requests under session management and the provider's consents that their entries do not declare (D6). `DELETE /sessions/a/b`, `DELETE /sessions/` and `GET /sessions/` reach the next handler, and so do the same shapes under `/oauth2/consents`. Today the first two are answered by session management, and the established design claims the whole consents subtree, refusing a deeper path as a foreign consent. Each endpoint now answers exactly what `Endpoints()` lists, so the inventory, the collision check (D7) and an OpenAPI document built from it can trust the list. The drift guard found the gap (`TestChainEndpoints_EveryEntryIsAnswered`, reproduced before the fix).
  - refused: an issuer that does not cover the base path (D8), stale consumer routes (D9), unreachable OIDC callbacks (D10).
- `WithOIDCProviderPath` changes meaning: its path is relative to the base path. With no base path it is the whole request path, as today.
- Before the first tag (`release-readiness`, `v0.1.0`), none of this needs a compatibility entry; it is recorded in the changelog. If this change lands after the tag, each item above becomes a compatibility entry, so `release-readiness` lists this change before the tag.

## Failure modes

Each relevant failure, its state (handled, tested or accepted, per `defensive-coding.md`) and what the caller sees.

| Failure | State | What the caller sees |
|---|---|---|
| A path is checked or derived before the base path is applied | Handled (D1: resolution before `validate`); tested (option-order scenarios, D11 tests) | Nothing: every check and derived value reads resolved paths |
| Base or endpoint path is relative, root, unclean or needs escaping | Handled (D4); tested | Configuration error naming the option |
| Base path moves nothing, or a consumer-set path repeats the base | Handled (D5); tested | Configuration error naming the option and the result |
| A base path repeats a default's first segment (`/sso` gives `/sso/sso/login/`) | Accepted (D5) | Served as configured; documented in `WithBasePath`'s godoc |
| Default layouts that share a path within one feature (session management, consents, recovery codes) | Handled (D7 declared sharing); tested | The chain builds with defaults |
| A caller mutates an entry of `Endpoints()` | Handled (D6 deep copy); tested | The chain and later lists are unchanged |
| A published provider URL names a path the chain does not serve | Handled (D8 predicate covers every served path); tested | Configuration error naming the issuer and the base path |
| Base path given twice | Handled (D1: last wins); tested | The last base path applies |
| Two operations answer one request path, within or across features | Handled (D7); tested | Configuration error naming both settings, both paths and the consequence |
| Two operations share a path without declaring it | Handled (D7); tested | Configuration error, although methods differ |
| An endpoint answers a path it does not declare, or declares one it does not answer | Tested (drift guard with near-miss, parent and other-method probes) | A failing test, not a production surprise |
| Issuer does not cover the base path | Handled (D8); tested | Configuration error naming the issuer and the base path |
| D8 waived with a root issuer and `AudienceIssuerOrTokenEndpoint` | Handled by the existing assertion endpoint check; tested | Configuration error from that check |
| Authorization server metadata outside the base path | Accepted (RFC 8414 §3) | Documented: a proxy must route `/.well-known/oauth-authorization-server/...` |
| Consumer route left at a pre-base path (cool-down fails open) | Handled (D9); tested | Configuration error naming the route and the moved endpoint |
| Cool-down route differing only in case or trailing slash (`POST /Reauth/Password/`) | Handled (D9 compares in the matcher's normal form); tested | Configuration error, as for the exact route |
| Header-profile matcher or another function matcher compares a pre-base path | Accepted (cannot be inspected) | Documented in the godoc; `Endpoints()` gives resolved paths |
| IdP redirect URL not moved with the callback or base path | Handled (D10); tested | Configuration error naming the provider and both paths |
| Redirect URL percent-encoded | Handled (D10 compares the decoded path); tested | Assembled when the decoded path matches |
| Pending session cannot sign out at the moved path | Handled (D11); tested | Sign-out answers at the moved path |
| Cookie scoped to the old path, so the browser never sends it | Handled (D11); tested | Cookies scoped to the moved paths |
| CSRF or CORS exemption left at the old path | Handled (D11); tested | Exemptions apply at the moved paths |
| Consumer confuses the confirm page (not moved) with the redeem endpoint (moved) | Accepted | Godoc of both, README list of what does not move |
| A proxy strips the prefix and the consumer also sets the base path | Accepted (D12) | Every built-in path passes through; README explains to set one or the other |
| Errors lose the explanation the local checks gave | Handled (D7 error format); tested | Each collision error says what would break |
| The signal stream's long-lived GET in the drift guard | Handled in the test (cancelled context) | Not applicable |
| Consumer expects consumer interceptors in `Endpoints()` | Accepted | Godoc states the limit |

## Risks / Trade-offs

- **The rename touches every path test, example and conformance scenario.** → It lands in the same change as the base path, so each test changes once. Defaults are named constants, and tests use them rather than literals where the literal is not the point.
- **D7 is a refactor across every feature.** → The moved tests are the safety net; every refusal the local checks made stays pinned, and newly refused cases are listed.
- **D8's predicate wrongly refuses an unusual deployment.** → The waiver, whose godoc states the cost.
- **D10's suffix rule wrongly passes or refuses an unusual proxy setup.** → The waiver; the suffix rule is the narrowest check that still catches the drift.

## Migration Plan

Nothing to migrate for consumers before the first tag. A consumer adopting a base path:

1. Sets `WithBasePath`, and makes every path it set explicitly relative to it.
2. Updates each OIDC provider's registered redirect URL (D10 refuses construction until they agree), now ending in `/sso/callback/{name}` under the base.
3. Sets the provider's issuer to include the base path (D8), or waives the check when its gateway routes `/.well-known/*`.
4. Rewrites cool-down routes, cross-site exemptions and header-profile paths that name built-in endpoints to the moved paths (D9).
5. Points resource servers at the moved key set URL, and routes `/.well-known/oauth-authorization-server/...` at the host root if it uses it.
6. Updates consumer pages that POST to the provider's resume or logout-confirm endpoints, and any client code that calls built-in endpoints by their old default paths.

## References

### Researched (accessed 2026-11-01)

**D1: per-feature paths relative to one base**
- [Better Auth: options reference](https://www.better-auth.com/docs/reference/options): `basePath` mounts every route together; no per-endpoint relocation is described.

**D2: the key set moves with the base**
- [RFC 8615 §3](https://www.rfc-editor.org/rfc/rfc8615.html): well-known URIs are rooted at the top of the path.
- [IANA Well-Known URIs registry](https://www.iana.org/assignments/well-known-uris/well-known-uris.xhtml): `openid-configuration` and `oauth-authorization-server` are registered; no key-set name is.

### Researched (accessed 2026-11-06)

**D3: default path vocabulary**
- [RFC 6749 §3.1, §3.2](https://www.rfc-editor.org/rfc/rfc6749.txt): the location of the authorization and token endpoints is outside the specification's scope; no path is mandated.
- [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009.txt), [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662.txt): revocation and introspection endpoints are located by the client by other means; no path is mandated.
- [OpenID Connect RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) and [Back-Channel Logout](https://openid.net/specs/openid-connect-backchannel-1_0.html): end-session is learned from discovery; the back-channel URI is registered by the client.
- [Spring Authorization Server: configuration model](https://docs.spring.io/spring-authorization-server/reference/configuration-model.html): provider endpoints under `/oauth2/*`.
- [Spring Security `DefaultOAuth2AuthorizationRequestResolver`](https://raw.githubusercontent.com/spring-projects/spring-security/main/oauth2/oauth2-client/src/main/java/org/springframework/security/oauth2/client/web/DefaultOAuth2AuthorizationRequestResolver.java): relying-party sign-in under `/oauth2/authorization/{registrationId}`, beside the provider's `/oauth2/authorize`.
- [Ory Hydra API spec](https://raw.githubusercontent.com/ory/hydra/master/spec/api.json): provider endpoints under `/oauth2/*`.
- [Ory Kratos API spec](https://raw.githubusercontent.com/ory/kratos/master/spec/api.json): `GET /sessions`, `DELETE /sessions`, `DELETE /sessions/{id}` as a resource collection.
- [Better Auth sign-in routes](https://raw.githubusercontent.com/better-auth/better-auth/main/packages/better-auth/src/api/routes/sign-in.ts) and [sign-out route](https://raw.githubusercontent.com/better-auth/better-auth/main/packages/better-auth/src/api/routes/sign-out.ts): `/sign-in/email`, `/sign-in/social`, `/sign-out`.
- [Better Auth magic-link plugin](https://raw.githubusercontent.com/better-auth/better-auth/main/packages/better-auth/src/plugins/magic-link/index.ts): `/sign-in/magic-link`, `/magic-link/verify`.
- [Supabase Auth OpenAPI](https://raw.githubusercontent.com/supabase/auth/master/openapi.yaml): `/sso`, `/factors/{id}/challenge`, `/factors/{id}/verify`, `/reauthenticate`.
- [Duende IdentityServer demo discovery](https://demo.duendesoftware.com/.well-known/openid-configuration) and [ZITADEL endpoints](https://zitadel.com/docs/apis/openidoauth/endpoints): other provider prefixes (`/connect/*`, `/oauth/v2/*`), showing no single convention.
- [Google AIP-136](https://google.aip.dev/136) and [AIP-122](https://google.aip.dev/122): custom actions as POST with a verb; plural collection identifiers.
- [Microsoft Azure REST guidelines](https://raw.githubusercontent.com/microsoft/api-guidelines/vNext/azure/Guidelines.md): kebab-case segments, pluralised collections, POST for actions.
- [Zalando RESTful API guidelines](https://opensource.zalando.com/restful-api-guidelines/): kebab-case, plural nouns, nouns only in paths (the style D3 departs from for sign-in and sign-out).
- [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/): mandates no registration or login endpoint paths.

**D2, D8: discovery placement**
- [OpenID Connect Discovery 1.0 §4](https://openid.net/specs/openid-connect-discovery-1_0.html): the OpenID configuration is at the issuer followed by `/.well-known/openid-configuration`.
- [RFC 8414 §3](https://www.rfc-editor.org/rfc/rfc8414.txt): the metadata path inserts `/.well-known/oauth-authorization-server` between the host and the issuer's path.

**D4–D7, D9–D13**
- Reasoned from scrty's own settled specs (`http-security-chain`, `oidc-login`, `oidc-logout`, `oidc-provider-metadata`, `magic-link`, `account-recovery`, `passkey-authentication`, `multi-factor-auth`, `reauthentication`, `session-signals`, `csrf-protection`, `trusted-proxies`, `authorization`, `framework-adapters`) and the established design.

### Primary documentation

- [RFC 3986 §3.3](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.3): the path component and its unreserved characters, behind D4's character set.
