## Context

See `proposal.md` for the motivation. This design was captured from an exploration on 2026-11-02, before any spec was written. It separates three things, and says which each item is:

- **Decided:** the user's choices of 2026-11-02, stated as such.
- **Proposed defaults:** recommendations from the research that the user has not yet confirmed. Each says what it would default to and how a consumer overrides it.
- **Open questions:** the decisions still to make. Open question 1 blocks the specs.

### What exists

Read on `main` at `eb1f22a`, plus the in-flight changes' artifacts.

- **scrty as a relying party.** `oidc-login`, `identity-linking` and `oidc-logout` log users in through external providers, link identities, and accept back-channel logout tokens. That code verifies ID and logout tokens with jwx v4 and caches remote key sets through the confined outbound client.
- **Keys and tokens.**
  - `token/signingkey` rotates RS256 (default), ES256 or EdDSA keys and publishes them.
  - `httpsec.EnableJWKSEndpoint` serves the key set at `/.well-known/jwks.json`.
  - `token.Generator.Generate(ctx, id, principal)` signs a fixed claim set: `jti`, `iss`, `sub`, `iat`, `exp`, and an optional audience. It cannot carry `nonce`, `azp`, `auth_time`, `acr`, `amr`, `scope` or `client_id`.
  - A test pins the package's use of jwx to a reviewed allow-list.
- **Sessions** (`session`).
  - **What a session records:** `AuthenticatedAt` (the OIDC `auth_time` meaning), `FirstFactor`, the MFA state, and federated `amr`/`acr`.
  - **Families:** sessions carry a family. `RotateWithGrace` rotates with a grace window and revokes the whole family on reuse, and `RevokeFamily` ends a family.
  - **Lifetimes:** the absolute timeout is 12 hours by default, bounded by `WithMaxAbsoluteLifetime` and `WithMaxFamilyLifetime`.
  - **User-wide operations:** `CountActiveByUser` feeds a concurrent-session limit. `DeleteByUser` and `DeleteByUserExcept` end a user's sessions.
  - **Session bearer:** `httpsec.EnableSessionBearer` accepts a session's own identifier as the bearer credential.
- **Single-use credentials.** `token/onetime` issues a credential for a purpose and a subject, stores only its hash, and makes check-then-consume structural: a refusal between the check and the consume leaves the credential unspent.
- **Client-style secrets.** `authenticate/apikey` shows a 256-bit secret once and keeps a SHA-256 digest.
- **One login completion.** `completeLogin` (`httpsec/complete.go`) closes form login, magic link, OIDC handoff and passkey passwordless. MFA verify and recovery completion issue on their own.
- **In flight.**
  - `close-security-gaps`:
    - DPoP (its D8: one chain-wide feature, bound at every issuing endpoint, refused as `Bearer` once bound);
    - mTLS binding (D9);
    - CORS (D5), security headers (D4) and trusted proxies with `Request.Host()`/`Secure()` (D2, D7);
    - security events (D13);
    - user-facing session listing by family (D12).
  - `pre-release-api-fixes`: `sub` becomes the user identifier by default.
  - `bff-resource-server`:
    - the cookie session and the resource-server mode, both still waiting on its open questions;
    - its exploration notes ask whether scrty or an external IdP is the authority for browser apps. An OpenID Provider in scrty makes scrty an authority, which that change should take into account when it resumes.
- **The established design** has no OpenID Provider side, so there is no inherited behaviour to follow or depart from here. Every decision below rests on the standards and established practice listed in References.

## Goals / Non-Goals

**Goals:**

- A consumer can make their application an OpenID Provider for their own other applications. The OP's defaults pass the OpenID Foundation's Basic OP and Config OP conformance plans with nothing configured beyond issuer, clients and the login and consent URLs.
- Every protocol step that already has a scrty primitive reuses it, rather than building a second mechanism.
- Every port and contract the provider changes is changed before `v0.1.0`, so the features left for later only add.

**Non-Goals** (each a follow-up that only adds, provided v1 leaves its seam):

- **Single sign-on across relying parties.** `prompt=none` and a second relying party skipping login both need the browser to carry a session to the provider's own origin, which is `bff-resource-server`'s cookie session. In v1, `prompt=none` answers `login_required` whenever no resumable login is available.
- **PAR, and a FAPI 2.0 profile switch.** v1 leaves the request-object seam for them.
- **Third-party features:** dynamic client registration (RFC 7591; RFC 7592 is Experimental), pairwise subject identifiers, and the logo and policy URIs.
- **JAR, RAR (RFC 9396), token exchange (RFC 8693) and the device grant (RFC 8628).**
- **Implicit and hybrid flows, and the resource owner password grant.** RFC 9700 and the OAuth 2.1 draft deprecate them.
- **Front-channel logout and OIDC Session Management.** Both depend on third-party cookies, which browsers now block.
- **Official certification.** v1 runs the suite as a CI gate. Certification on the hosted suite is the maintainer's later step.

## Decisions

### 1. scrty builds its own provider; an OpenID Provider library is the last resort (decided 2026-11-02)

- **The decision.** The provider is written on scrty's own primitives and jwx v4. A third-party OpenID Provider library is considered only if building one proves infeasible.
- **The survey behind it.** Live figures were read on 2026-11-02 and drift.
  - **The candidates:**
    - `zitadel/oidc` v3: actively maintained; only its relying party is certified.
    - `ory/fosite`: last standalone release 2024-12-12.
    - `luikyv/go-oidc`: the only certified OP among them, including FAPI 2.0. It is pre-1.0 with a single maintainer, and whether its certification covers the current release is unverified.
  - **The JOSE conflict.** All three depend on `go-jose` and expose its types in their public interfaces. Adopting any of them would add a second JOSE stack beside jwx v4, which the project configuration forbids, even inside a nested module.
  - **A framework dependency.** `zitadel/oidc` also imports chi outside its tests.
- **What scrty takes from them instead:**
  - the shape of the login handoff (decision 4);
  - small storage ports;
  - where their advisories cluster: redirect matching, code and refresh-token reuse, and token binding.
- **What it costs.** No certified library sits underneath. Conformance is therefore proved by running the OpenID Foundation suite (decision 9).
- **Default and override:** not a consumer-facing behaviour. A consumer who prefers a library-backed provider can still run one beside scrty, with scrty as its user store.

### 2. The provider is a thin protocol layer over existing features (decided 2026-11-02)

The user asked that the provider make the most of the features that exist or are being written. Each protocol need maps to one:

```
                     OP protocol layer (new, thin)
  +---------------------------------------------------------------------------+
  | /authorize  /token  /userinfo  /revoke  /introspect  /.well-known/...     |
  +----+----------+----------+---------+--------------------------+-----------+
       |          |          |         |                          |
  end-user     auth code   refresh   access / ID token          metadata
  login        (one-time)  grant     minting                    + JWKS
       |          |          |         |                          |
  form, passkey, token/      session   signingkey KeySource,      EnableJWKSEndpoint
  magic link,    onetime     families? token.Generator (+ new
  MFA, recovery, check-then- (open     claims), cnf from
  upstream OIDC  consume     question  close-security-gaps
  -> completeLogin           1)
```

| Provider need | Reuses | Status |
|---|---|---|
| Authorization code: single use, bound to client, redirect URI, PKCE challenge, nonce | `token/onetime`: check-then-consume, binding, only a hash stored | built |
| Refresh rotation and reuse detection | `session` families and `RotateWithGrace`, or a store sharing their logic | built; how is open question 1 |
| `auth_time`, `max_age`, `prompt=login` | `Session.AuthenticatedAt`, `EnableReauthentication`, the recency guard | built |
| `acr`, `amr` | `FirstFactor`, the MFA state, federated assurance | built |
| Signing keys, JWKS | `token/signingkey`, `EnableJWKSEndpoint` | built |
| Client secrets | the `apikey` pattern: 256-bit secret shown once, SHA-256 digest stored | built (pattern) |
| `private_key_jwt`, client `jwks_uri` | jwx v4, the relying party's key-set cache, `outbound` confinement | built |
| Throttling of the token and authorization endpoints | `ratelimit`, the chain's source throttle step | built |
| End-user login at the provider | every existing first factor, MFA, recovery, upstream OIDC login | built |
| DPoP, mTLS binding | `close-security-gaps` D8, D9 | in flight |
| CORS on token, UserInfo, metadata and JWKS; `frame-ancestors` on provider pages | `close-security-gaps` D5, D4 | in flight |
| Issuer scheme and host behind a proxy | `close-security-gaps` D2, D7 | in flight |
| Audit trail of grants, reuse and revocation | security events, `close-security-gaps` D13 | in flight |
| "Apps with access to my account" | session listing, `close-security-gaps` D12 | in flight |
| Stable `sub` | `pre-release-api-fixes` decision 3 | in flight |
| Back-channel logout sent to relying parties | logout-token shape from `oidc-logout`; delivery over `outbound` | partly built |
| Durable stores | `sqlstore`, `pgxstore`, `gormstore`, conformance suites, migrations, expiry sweeping | built (pattern) |

### 3. Delivered before `v0.1.0`, after the API fixes (decided 2026-11-02)

- **Order:** `close-security-gaps`, then `pre-release-api-fixes`, then this change, then `release-readiness`'s gate and tag.
- **Why before the tag.** The provider changes contracts that would break after it:
  - a session or grant store port, and a security-state migration;
  - the claims `token` issues;
  - the error-body contract of `http-error-propagation`.
  The follow-ups in Non-Goals only add, so they can come after the tag.
- **What it costs.** The tag waits for this change, and the first consumer's adoption, which `release-readiness` says is blocked on the tag, waits with it. Keeping v1 to the scope above is what bounds that wait.

### 4. First-party clients first, and consent delivered in v1 (decided 2026-11-02)

- **The decision.** The first relying parties are the consumer's own applications, registered in configuration. Consent is not left as a seam: v1 delivers it.
- **What consent covers in v1:**
  - remembered consent per user and client, holding the granted scopes;
  - `prompt=consent`, which forces the prompt;
  - consent forced whenever `offline_access` is requested (OIDC Core §11);
  - partial grants: the code is bound to the scopes granted, not those requested;
  - denial, answered `access_denied`;
  - revocation, which also ends that client's grants (whose mechanism follows open question 1).
- **Kept for later.** The third-party features (dynamic registration, pairwise `sub`, logo and policy URIs) stay after the tag.

### Proposed defaults (awaiting the user's confirmation)

Each of these is a recommendation from the research, not a decision. The user confirms or changes them before the specs.

#### P1. Login and consent are handed off through a pending request and resumed through the provider

Every established provider uses this shape: Hydra, node-oidc-provider, Duende IdentityServer, Spring Authorization Server, and `zitadel/oidc`'s `op` package. It fits scrty's rule that the library renders nothing.

```
 RP --(1) GET /authorize?client_id,redirect_uri,code_challenge,nonce,state
        |
        v
 provider: validate client, exact redirect_uri, PKCE S256, prompt/max_age
           persist PENDING REQUEST under an opaque handle (stage: login)
        |  (2) 303 -> consumer login URL ?req=<handle>
        v
 consumer's login page: scrty's existing endpoints -> completeLogin -> session
        |  (3) resume: POST <resume> {handle} + the session credential
        v
 provider: re-check prompt/max_age against Session.AuthenticatedAt
           consent needed? -> stage: consent, 303 -> consumer consent URL ?req=<handle>
                              consumer reads the request by handle (client, scopes, claims)
                              resume with {granted scopes} or {deny}
        |  (4) 303 -> redirect_uri?code&state&iss
        v
 RP --(5) POST /token (client auth, code, code_verifier) -> tokens
```

- **The handle and its binding.**
  - The handle is unguessable and single-use for each stage, and expires after 10 minutes by default (`WithPendingRequestLifetime`).
  - It is bound to the browser that started it, by a `Lax` cookie, as `oidc-login`'s flow cookie already is.
  - A resume that presents a session must be the browser that started the request and must carry that session's credential.
- **Default and override:**
  - **Default:** the consumer configures a login URL and a consent URL.
  - **Override:** the resume endpoint's path and the handle parameter name are replaceable. A consumer who wants no redirect can render both stages on one page by calling the provider's request-lookup function directly.
- **Why resume with the session credential.** v1 needs no cookie session. The cost is that the browser holds no session at the provider's origin between relying parties, which is why SSO is a Non-Goal.

#### P2. Consent is required unless a client is registered as first-party

- **Default:** every client requires consent. `library-design` asks for the safe default, and a client someone forgot to configure should ask the user, not skip the question silently.
- **Override:** a client registered with the first-party flag skips the consent stage, except when `prompt=consent` or `offline_access` asks for it.

#### P3. The provider's endpoints render the error bodies the protocol requires

- **The departure.** scrty's default answers errors with a bare status and no body. But the protocol fixes how each provider endpoint reports an error:
  - the token, revocation and introspection endpoints answer with a JSON `{"error": ...}` body (RFC 6749 §5.2);
  - the authorization endpoint reports errors as redirect parameters to a validated `redirect_uri`, and never redirects to an unvalidated one;
  - UserInfo answers with a `WWW-Authenticate` challenge.

  These endpoints are the first built-ins whose error format a standard fixes. That is a recorded departure, limited to them.
- **Default and override:**
  - **Default:** the protocol's format.
  - **Override:** a consumer may add fields or headers through a responder.
  - **What cannot be overridden:** the `error` code and the status. They are protocol, and changing them would break every client.

#### P4. Access tokens are JWTs per RFC 9068 by default; opaque by option

- **Default:** a JWT with `typ` `at+jwt` and `iss`, `sub`, `aud`, `exp`, `iat`, `jti`, `client_id` and `scope`, signed over the same key source. APIs verify it offline through the JWKS endpoint, which pairs with `bff-resource-server`'s resource-server mode.
- **Override:** opaque access tokens, verified by introspection. Revocation is then immediate, at one store read per request.
- **Where it lands:** `token` must issue these claims; that is a `token-issuance` change.

#### P5. Refresh tokens rotate, and reuse revokes the grant

- **Default:** every refresh rotates. A rotated token presented after its grace window revokes the whole grant (RFC 9700 §4.14.2).
- **Override, per client:** rotation off for a confidential, sender-constrained client. FAPI 2.0 asks for that, and permits rotation only with a time-limited retry using the old token. That retry is what the existing grace window already gives.

#### P6. DPoP and mTLS binding in v1, through `close-security-gaps`

- **What is reused.** DPoP is a chain-wide feature there. Its D8 binds at every endpoint that issues a credential, so the token endpoint joins that list and reuses proof verification, the replay store, nonces and `cnf.jkt`. mTLS binding reuses D9 the same way.
- **What is new for the provider:**
  - refresh tokens of public clients bound to the DPoP key (RFC 9449 §5);
  - the `dpop_jkt` authorization parameter, which binds the code (§10);
  - `dpop_signing_alg_values_supported` in the metadata;
  - a per-client "binding required" setting.
- **Default and override:**
  - **Default:** a proof is accepted and binds the token when the client sends one, as D8's chain default does.
  - **Override:** a client registered as requiring binding is refused without a proof.
- **Constraint inherited from D8.** Enabling DPoP needs a bearer mode on the chain. The provider's own access-token verification at UserInfo counts as one, which the specs must state.

#### P7. Client authentication

- **Supported:** `client_secret_basic`, `client_secret_post` (the Basic OP plan needs both), `private_key_jwt` (RFC 7523, preferred by RFC 9700 §2.5), and `none` for public clients with PKCE.
- **Secrets:**
  - generated by the library: 256 bits, shown once, kept as a SHA-256 digest, as `apikey` does;
  - a consumer-supplied secret shorter than 32 bytes is refused at construction (OIDC Core §16.19).
- **`private_key_jwt` assertions:** the assertion's `jti` goes into a replay store with the same insert-if-absent contract as DPoP's.
- **Default and override:**
  - **Default:** each client declares exactly one method.
  - **Override:** none beyond choosing the method. A client allowed several methods is a downgrade path.

#### P8. Signing algorithms for ID tokens

- **Default:** RS256, which OIDC Core §15.1 makes mandatory to support. It is already `signingkey`'s default.
- **Override:** ES256 and EdDSA per client, from the algorithms the key manager is configured with. A client asking for an algorithm the manager does not hold is a configuration error at construction.
- **FAPI tension:** FAPI 2.0 forbids RS256, so its profile, a Non-Goal here, would change this default.

#### P9. Conformance runs in CI

- **What runs:** the OpenID Foundation conformance suite, its Basic OP and Config OP plans, against a test server built from the provider's defaults. It runs as its own CI job, from the suite's Docker image (Java and MongoDB).
- **Where it runs:** outside `make check`, and outside the release gate's workspace-off builds.
- **What stays open:** whether a green run is a hard precondition for the tag is open question 2.

## Risks / Trade-offs

- **[The tag waits for this whole change]** → v1 stays at the scope above, and every follow-up only adds. The task breakdown, written after open question 1, sizes it.
- **[No certified library underneath]** → the conformance suite in CI (P9), plus test-first coverage of the pitfalls the advisories cluster on: exact redirect matching, code reuse revoking what it issued, refresh reuse, and token binding.
- **[A session can mean two things]** → this is open question 1, and the specs wait for it.
- **[Error bodies depart from the library's default]** → limited to the provider's endpoints, recorded in P3, and pinned by tests against RFC 6749's examples.
- **[RS256 by default conflicts with FAPI 2.0]** → recorded in P8. A FAPI profile is a later, additive switch.
- **[`prompt=none` cannot succeed in v1]** → `login_required` is the correct answer when no login is resumable. The README's *Known limitations* names it until the cookie session lands.
- **[The conformance suite's exact test lists were not read]** (its profile PDF was unreadable) → the first conformance task records which tests run, before the gate relies on them.

## Migration Plan

- Nothing to migrate: the provider is new, and off until a consumer enables it.
- The security-state migration that adds the provider's tables lands in the first migration set, before the tag.

## Open Questions

### 1. How is a grant stored? (blocks the specs)

**Why it matters.** A *grant* is what the provider holds between a user and a client after a successful authorization. It holds:
- the user, the client and the granted scopes;
- when and how the user authenticated (`auth_time`, `amr`, `acr`);
- the current refresh token, and the lineage of the refresh tokens before it.

**What a grant must do:**
- rotate its refresh token;
- detect a rotated token presented again and revoke the whole grant (RFC 9700 §4.14.2);
- give a retry window after rotation (FAPI 2.0's "time-limited retry with the old token");
- expire on idle and absolute deadlines;
- end when the user or an administrator revokes it, or when consent is revoked;
- be listed for the user, and be swept when expired.

**Why sessions are the obvious candidate.** `session` already does nearly all of this for sign-ins:
- families, and `RotateWithGrace` with its grace window;
- reuse that revokes the family, and `RevokeFamily`;
- idle and absolute deadlines with per-session lifetimes;
- digest-only storage of the identifier;
- durable stores with conformance suites, and expiry sweeping.

`first-party-sessions` built and tested that machinery. The question is whether a grant *is* a session, or a separate thing that reuses the same logic.

#### Option A: a grant is a session, tagged with a kind and its client

- **How it works.**
  - The session record gains a kind (sign-in or grant) and a client identifier.
  - A grant is created at the code exchange, in a family of its own. Its refresh token is the session identifier, rotated with `RotateWithGrace`.
- **What it gains:**
  - every mechanism listed above, with no new store, no new migration table and no new conformance suite;
  - `close-security-gaps` D12's session listing can show "applications with access to my account" next to sign-ins.
- **What it costs.** Every operation that today treats "all of a user's sessions" alike must learn the kinds:
  - **Bearer confusion.** With `EnableSessionBearer` on, a session identifier *is* a bearer credential. A refresh token would then authenticate at the consumer's own API as the user, with none of the client's scope limits. Grants must be refused by kind on every bearer path. Missing one is a privilege escalation that a test of the provider alone would not catch.
  - **Concurrent-session limits.** `CountActiveByUser` feeds the concurrent-session limit. Grants would use up the user's sign-in allowance unless counting excludes them.
  - **User-wide deletion.** `DeleteByUser` and `DeleteByUserExcept` serve "log out everywhere", "end other sessions" and password changes. `oidc-logout`'s widened scope also calls `DeleteByUser` (`httpsec/oidc_backchannel.go`). Each would end the user's grants to applications as well. Whether a password change *should* end grants is itself a policy question:
    - ending them is the safer default;
    - most providers keep `offline_access` grants across a logout.
  - **Lifetimes.** One `Sessions` manager has one set of maxima: a 12-hour absolute timeout by default, bounded by `WithMaxAbsoluteLifetime` and `WithMaxFamilyLifetime`. Those fit sign-ins, not 30- to 90-day grants. Option A therefore needs a second `Sessions` manager for grants, over the same store or another one, with its own lifetimes.
  - **Pending-state marks.** `MarkEnrolmentPending` and `MarkRecoveryPending` confine a sign-in. They must never apply to a grant.
  - **The port change is breaking.** It lands on `session.Store` while `close-security-gaps` D12 is adding `ListByUser` to the same port. If A is chosen, the kind should be designed into `ListByUser` in that same pre-tag break, not added after it.

#### Option B: a separate grant store that shares the rotation logic

- **How it works.** The family, grace and reuse logic is extracted from `session` into an internal package, and both `session` and a new grant store use it.
- **What it gains.**
  - A grant is never a bearer credential, never counted as a sign-in and never caught by a user-wide session delete unless a caller asks for it.
  - Lifetimes are the grant's own.
- **What it costs:**
  - a behaviour-preserving refactor of `session`'s rotation code;
  - a second store port, migration table, set of three SQL adapters and conformance suite;
  - a listing that must join two sources to show sign-ins and applications together.

#### Option C: a separate grant store with its own rotation

- Simplest to begin with, but it re-implements reuse detection and the grace window, which are exactly the parts that need race-tested care. Listed so it is recorded as considered. It would need a strong reason to choose.

#### What depends on the answer

- the `session.Store` change, the migration and `store-conformance`;
- every bearer path (`EnableSessionBearer`, `EnableBearerToken`, the resource-server mode in `bff-resource-server`);
- how far logout and password change reach;
- the coordination with `close-security-gaps` D12, which should be settled before D12 is implemented.

#### Questions that help decide

- **Should a user's "log out everywhere" end their applications' access?**
  - If yes, A's shared deletion is a feature.
  - If no, A needs exclusions everywhere, and B fits better.
- **How likely is a consumer to run `EnableSessionBearer` beside the provider?** Under A, that combination is where the escalation risk lives.

### 2. Is a green conformance run a hard precondition for the tag?

- **Recommendation:** yes for the Basic OP and Config OP plans.
- **What it changes:** whether `release-readiness`'s gate names the conformance job. It changes no spec of this change.

### 3. The provider package's name and place

- **Candidates:** a core package under its own concept, such as `oidcprovider` or `provider`, beside `authenticate/oidc` (the relying party).
- **Why it can wait:** it is settled with the specs, and does not change the approach.

## References

### Decision 1: build, not adopt

**Researched (accessed 2026-11-02):**
- GitHub REST API (repository, releases, commits, `go.mod` contents) for [zitadel/oidc](https://github.com/zitadel/oidc), [ory/fosite](https://github.com/ory/fosite), [luikyv/go-oidc](https://github.com/luikyv/go-oidc), [go-oauth2/oauth2](https://github.com/go-oauth2/oauth2), [openshift/osin](https://github.com/openshift/osin), [dexidp/dex](https://github.com/dexidp/dex) and [ory/hydra](https://github.com/ory/hydra):
  - what was read: release dates, maintenance, JOSE dependency, router dependency;
  - live figures as of 2026-11-02, which drift: zitadel/oidc v3.51.16 of 2026-10-15; ory/fosite v0.49.0 of 2024-12-12; luikyv/go-oidc v0.25.0 of 2026-07-23.
- [OSV query API](https://api.osv.dev/v1/query) and [GHSA-j8gq-92xf-382c](https://github.com/advisories/GHSA-j8gq-92xf-382c): zitadel/oidc's opaque-token advisory, fixed in v3.47.0. OSV did not return it, so OSV is incomplete for this module.
- [OpenID certified implementations](https://openid.net/certification/certified-openid-connect-implementations/): luikyv/go-oidc is certified as an OP; zitadel/oidc only as an RP. Whether luikyv's certification covers its current release is unverified.

### Decisions 2 and 4, P1, P2: protocol scope, consent and the handoff

**Researched (accessed 2026-11-02):**
- [OpenID Connect Core 1.0, errata set 2](https://openid.net/specs/openid-connect-core-1_0.html):
  - ID token claims, `prompt`, `max_age`, exact `redirect_uri` matching;
  - `offline_access` and consent (§11);
  - the features mandatory for every OP (§15.1).
- [ISO/IEC 26131:2024](https://www.iso.org/standard/89056.html): OpenID Connect Core 1.0, errata set 2, as an International Standard.
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html): required provider metadata, and which endpoints support CORS.
- [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414.html): authorization server metadata, and where its well-known path differs from OIDC's.
- [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html): the OAuth 2.0 Security Best Current Practice:
  - exact redirect matching and no 307 redirects;
  - PKCE downgrade;
  - code reuse revoking what the code issued;
  - refresh rotation and reuse;
  - no CORS at the authorization endpoint;
  - ROPC forbidden.

  Its publication date and BCP number were not visible in the fetch, so they are unverified.
- [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html) (PKCE) and [RFC 9207](https://www.rfc-editor.org/rfc/rfc9207.html) (`iss` in the authorization response).
- [OAuth 2.1, draft-ietf-oauth-v2-1-17](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-17), dated 2026-10-31:
  - status: still an Internet-Draft;
  - relevance: PKCE required, no implicit grant and no ROPC;
  - not read: its refresh-rotation text, because the fetch was truncated, so that part is unverified.
- Established handoff patterns:
  - [Ory Hydra login and consent flow](https://www.ory.com/docs/oauth2-oidc/custom-login-consent/flow);
  - [node-oidc-provider documentation](https://github.com/panva/node-oidc-provider/blob/main/docs/README.md);
  - [Duende IdentityServer interaction service](https://docs.duendesoftware.com/identityserver/reference/v8/services/interaction-service/);
  - [Spring Authorization Server protocol endpoints](https://docs.spring.io/spring-authorization-server/reference/protocol-endpoints.html);
  - [zitadel/oidc `op` storage](https://raw.githubusercontent.com/zitadel/oidc/main/pkg/op/storage.go).

  All five park the request under a handle, send the browser to the application's own pages, and resume through the provider.

### P3 to P5: errors, access tokens, refresh

**Primary documentation:**
- [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html), §4.1.2.1 and §5.2: authorization and token error responses. Not re-checked on this date.

**Researched (accessed 2026-11-02):**
- [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068.html): the JWT access token profile, `typ` `at+jwt` and its required claims.
- [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662.html) (introspection) and [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009.html) (revocation).
- [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html): resource indicators and audience restriction.
- [FAPI 2.0 Security Profile, Final, 2025-02-22](https://openid.net/specs/fapi-security-profile-2_0-final.html): refresh rotation only with a time-limited retry, sender-constrained tokens, RS256 not allowed.

### P6: DPoP and mTLS

**Researched (accessed 2026-11-02):**
- [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html): authorization-server-side DPoP, covering refresh-token binding (§5), `dpop_jkt` (§10) and the metadata.
- [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705.html): certificate-bound tokens, and securing a TLS-terminating proxy.

Also reasoned from `close-security-gaps` D8 and D9.

### P7, P8: client authentication and algorithms

**Researched (accessed 2026-11-02):**
- [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523.html): `private_key_jwt`.
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html):
  - §9: client authentication methods;
  - §16.19: secret entropy;
  - §15.1: RS256 mandatory.

### P9: conformance

**Researched (accessed 2026-11-02):**
- [OpenID Connect OP conformance profiles](https://openid.net/certification/connect_op_testing/): what Basic OP and Config OP cover and the clients they need. The exact test lists are in a profile PDF that could not be read, so they are unverified.
- [Conformance suite repository](https://gitlab.com/openid/conformance-suite) and [its build-and-run wiki](https://gitlab.com/openid/conformance-suite/-/wikis/Developers/Build-&-Run): running the suite locally with Docker.

### Logout (scope)

**Researched (accessed 2026-11-02):**
- [RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) and [Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html): in v1.
- [Front-Channel Logout 1.0](https://openid.net/specs/openid-connect-frontchannel-1_0.html) and [Session Management 1.0](https://openid.net/specs/openid-connect-session-1_0.html): left out, because their own text admits third-party cookie blocking impairs them.

### Open question 1

Reasoned from scrty's own settled specs (`sessions`, `security-state-stores`, `http-security-chain`, `oidc-logout`), its code, and `close-security-gaps` D12, with RFC 9700 §4.14.2 and the FAPI 2.0 profile above for what a grant must do.
