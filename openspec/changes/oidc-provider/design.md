## Context

See `proposal.md` for the motivation. This design was captured from an exploration on 2026-11-02, before any spec was written. It separates three things, and says which each item is:

- **Decided:** the user's choices of 2026-11-02, stated as such.
- **Proposed defaults:** recommendations from the research that the user has not yet confirmed. Each says what it would default to and how a consumer overrides it.
- **Open questions:** the decisions still to make. None blocks the specs; the proposed defaults P1 to P9 must be confirmed first.

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
| Refresh rotation and reuse detection | `session` families and `RotateWithGrace`, or a store sharing their logic | built; reused through decision 5 (D+) |
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
  - revocation, which also ends that client's grants (the grant rows of that user and client are revoked, decision 5).
- **Kept for later.** The third-party features (dynamic registration, pairwise `sub`, logo and policy URIs) stay after the tag.

### 5. A grant is stored as option D+ (decided 2026-11-02)

> **Status:** decided on 2026-11-02. The user chose option D+, and the recommendations for sub-decisions 2 to 6 below. It was researched and audited the same day, before the decision. Two research tracks fed this section: a survey of the normative sources and of established providers, and an independent review against the code by a reviewer who was not shown the recommendation. Every defect named here is `UNREPRODUCED`: no provider code exists yet. Each is a candidate for the first failing test of the chosen option.

#### The problem

A *grant* is what the provider holds between a user and a client after a successful authorization. It outlives the sign-in that created it, typically by 30 to 90 days, and is renewed through a rotating refresh token.

```
 sign-in (login session)                         grant (what this question is about)
 -----------------------                         ----------------------------------
 user u-1, browser                               user u-1  x  client "billing-web"
 lives hours (12 h absolute by default)          lives 30-90 days
 its id IS a bearer credential                   its refresh token must NEVER be one
 (EnableSessionBearer, bearer jti, renewal)      scopes: openid profile offline_access
                                                 auth_time / amr / acr of the sign-in
                                                 refresh lineage:
                                                   rt1 --rotate--> rt2 --rotate--> rt3 (live)
                                                   rt1 presented again  ==> revoke the grant
```

`session` already does most of what a grant needs:
- families;
- `RotateWithGrace`, whose grace window is FAPI 2.0's "time-limited retry";
- reuse that revokes the family, and `RevokeFamily`;
- idle and absolute deadlines;
- digest-only identifiers;
- three durable stores with conformance suites, and sweeping.

That code (`session/reuse.go`, about 680 lines) is the most race-sensitive in the library. It depends on conditional store operations: `Supersede` (compare-and-set on the observed successor), `MarkPresented`, `SuccessorPresented` and `DeleteFamily`. The question is how grants get that machinery without becoming something a sign-in path can load.

#### What any answer must satisfy

| # | Constraint | Source | Strength |
|---|---|---|---|
| C1 | Each refresh token is bound to one client; the binding is tamper-proof and checked on every refresh | RFC 6749 §6, §10.4; RFC 6819 §5.2.2.2 | MUST |
| C2 | A refresh checks that the grant is still active, and that scopes do not exceed the consented ones | OAuth 2.1 draft-17 §4.3.1; RFC 9700 §4.14.2 | MUST |
| C3 | Public clients get sender-constrained tokens or rotation. A rotated-out token is retained as invalidated, so its reuse is detected | RFC 9700 §2.2.2, §4.14.2 | MUST |
| C4 | Reuse revokes the active refresh token (RFC 9700). OAuth 2.1, RFC 6819 and ASVS 10.4.5 revoke the whole grant | RFC 9700 §4.14.2; OAuth 2.1 §4.3.1; RFC 6819 §5.2.2.3; ASVS 5.0 10.4.5 | MUST (strongest reading) |
| C5 | A DPoP-bound refresh token of a public client is checked against its key on every refresh | RFC 9449 §5 | MUST |
| C6 | At least 128 bits of entropy; confidential at rest. Hashing is a "should" | RFC 6749 §10.10, §10.4; RFC 6819 §5.1.4.1.3 | MUST / should |
| C7 | Revoking a refresh token also invalidates the access tokens of the same grant; users can revoke tokens and consents | RFC 7009 §2.1; ASVS 10.4.9, 10.7.3 | SHOULD / verify |
| C8 | Refresh tokens have an absolute expiry | ASVS 10.4.8 | verify |
| C9 | At logout, tokens without `offline_access` SHOULD be revoked, and tokens with it SHOULD NOT | Back-Channel Logout 1.0 §2.7; OIDC Core §11 | SHOULD / SHOULD NOT |
| C10 | Validation of each token type excludes the others; access tokens are typed `at+jwt` | RFC 8725 §3.12; RFC 9068; ASVS 9.2.2 | MUST |
| C11 | A code yields tokens at most once; a valid replay revokes what the first exchange issued | RFC 9700 §4.2.4; OAuth 2.1 §4.1.3, §7.5.3; ASVS 10.4.2 | MUST / SHOULD |

**Where the sources are silent or disagree:**
- **Password change:** no source requires revoking grants. RFC 9700 and OAuth 2.1 say MAY. ASVS 7.4.3 offers ending "other sessions" as an option, and does not say whether OAuth grants count.
- **Whether reuse also revokes live access tokens:** no source says.
- **Rotation:** FAPI 2.0 forbids it except in extraordinary circumstances, and then only with a retry window.
- **Atomic writes at the code exchange:** no source requires them.

#### How established providers model it

| Provider | Grant versus login session | Refresh tokens at logout | At password change |
|---|---|---|---|
| Ory Hydra | separate tables (the consent flow holds the grant) | revoking a login session "does not invalidate any tokens" | not found |
| Duende IdentityServer | separate `PersistedGrant` store, keyed by the token's SHA-256 | survive by default; a client flag ties them to the session | not documented |
| Spring Authorization Server | separate `OAuth2Authorization` | not tied | none |
| node-oidc-provider | three models: Session, Grant, RefreshToken | session-bound unless `offline_access` | not handled |
| Auth0 | a grant entity; revoking it revokes all its tokens | not documented | not automatic |
| Keycloak | the same session model, separated by an `offline` flag | online tokens end with the session, offline tokens survive | the user chooses whether to log out other sessions |

Five of the six keep grants out of the login-session store, and the sixth separates them by a flag. None of them revokes grants on a password change without being asked, though Keycloak lets the user choose to.

#### Where a refresh token could be mistaken for a sign-in today

The review found three built-in paths that turn a stored session identifier into a sign-in, not one:

```
 presented value                       path                                      result
 ---------------                       ----                                      ------
 Authorization: Bearer <id>       -->  EnableSessionBearer                  -->  Load(id) in its manager
                                       (httpsec/session_bearer.go:145-151)       => signed in as the user
 Authorization: Bearer <JWT>      -->  EnableBearerToken                    -->  Load(jti) in its manager
                                       (httpsec/bearer.go:102)                   => signed in as the user
 POST <renewal> with <id>         -->  EnableSessionRenewal                 -->  rotate + first-party credential
                                       (httpsec/session_renewal.go:282)

 If a grant's lineage lives in the store these managers read, a refresh token
 (or an access token whose jti equals a lineage id) becomes a full sign-in with
 none of the client's scope limits.
```

#### Options

Seven options were considered: four from the first draft (A to D) and three the review added (A′, D+, F).

##### Rejected

- **A: a grant is a session in the same store, with a kind field and kind filters on user-wide operations.** Rejected because it **fails open**:
  - every present and future path that loads by identifier must reject the grant kind, including the three above and any consumer interceptor using `WithSessions` or `PublishSession`. One missed check makes a refresh token a sign-in, and no provider test would notice;
  - rejecting after `Load` is already too late, because loading for renewal records the presentation and may revoke the family;
  - two managers with different policies share one store, and retention is computed by whichever manager writes;
  - it breaks every `session.Store` statement in the same pre-tag window as `close-security-gaps` D12.
- **D as first drafted: a separate store instance over the same code.** Rejected as drafted because it also **fails open**:
  - the SQL session stores have no table-name option: the table is fixed in `internal/pgschema`, in gorm's `TableName()` and in the migration. Two store instances on one database therefore share the `sessions` table, and D silently becomes A without any kind checks;
  - both managers are `*session.Sessions`, so injecting the grant manager into a sign-in path is a type-correct mistake. The in-flight `di-wiring` change would make that easy;
  - the client is not on the lineage record, so every endpoint must read the metadata first or tokens cross clients;
  - a reuse revocation leaves the metadata behind (H4).

  Its strength, reusing the rotation code unchanged, is kept in D+.
- **C: a separate grant store with newly written rotation.** Rejected because it re-implements, and must re-prove across replicas, the exact edge cases `session` already pins:
  - a knocked-out successor;
  - two live heads;
  - a re-rotation racing a recovery;
  - retention after a change of family maximum.

  Two implementations of one security rule drift apart.

##### Not recommended

- **B: extract the family, grace and reuse logic into a shared internal package, used by `session` and by a grant store.** Safe by type, but it carries the highest one-time cost: a behaviour-preserving refactor of `reuse.go` and its invariants on a pre-tag schedule, its race suite run against two record types, and a lineage-capable store in three adapters. "Generic" also means generic store SQL per table. Its benefit over D+ is a cleaner type, not a stronger guarantee.
- **F: one row per grant, holding the current and the previous refresh-token digest, rotated by compare-and-swap.** The smallest state space, with the client, binding and revoked flag on one row. But it remembers only one predecessor. A token two or more rotations old is merely unknown, so presenting it is not detected as reuse. That falls short of RFC 9700 §4.14.2's "information about the relationship is retained" (C3), and fixing it rebuilds the lineage.

##### Runner-up

- **A′: the kind is a partition of one table.** Each store instance is bound to one kind at construction, and every store statement, `Load` included, filters on it, so a sign-in manager cannot load a grant at all. It is fail-closed, keeps one table and one sweeper, reuses the rotation code, and is close to Keycloak's model. Its costs:
  - a predicate on every statement in the in-memory store, the encrypting decorator and three SQL adapters;
  - a breaking change to `session.Store` that must land with `close-security-gaps` D12;
  - per-kind managers;
  - the client binding still needs fields on the session record.

  Choose it if one table matters more than leaving `session.Store` untouched.

##### Chosen: D+

D+ keeps D's reuse of `session` unchanged and adds four guards. Together they make a mis-wiring fail closed, behind two independent barriers, and put every check C1 to C11 needs on one authoritative record.

```
                         +--------------------------- core: oidcprovider ----------------------------+
                         |                                                                            |
  token endpoint ------->|  1. parse "rt.<family>.<secret>"   (format barrier)                        |
                         |  2. grants.Load(family) ------------------------+                          |
                         |       client? revoked? binding? scopes?         |                          |
                         |  3. lineage (provider-private wrapper)          |                          |
                         |       over session.Sessions with grant lifetimes|                          |
                         +-----------------------+-------------------------+--------------------------+
                                                 |                         |
                                                 v                         v
                                  +-----------------------------+   +-----------------------------+
                                  | op_refresh_tokens           |   | op_grants  (AUTHORITATIVE)  |
                                  | same schema as sessions,    |   | family (PK), user, client,  |
                                  | table FIXED by the provider |   | scopes, auth_time, amr, acr,|
                                  | (table barrier)             |   | key binding, code id,       |
                                  | rotation, grace, reuse:     |   | revoked flag, created,      |
                                  | session/reuse.go, unchanged |   | offline (bool)              |
                                  +-----------------------------+   +-----------------------------+

  sign-in paths (EnableSessionBearer, EnableBearerToken, EnableSessionRenewal)
        |
        v
  +-----------------------------+
  | sessions (sign-ins only)    |   never holds a grant's lineage; refresh tokens are not found here,
  +-----------------------------+   and "rt.<family>.<secret>" fails session.ValidIdentifier first
```

**The four guards:**

1. **A table the provider fixes.** The adapters expose a dedicated constructor, for example `pgxstore.NewRefreshTokenStore(pool, cipher)`, whose table (`op_refresh_tokens`) is not configurable. It returns a provider-owned type, so it cannot be passed where a sign-in `session.Store` or `*session.Sessions` is expected, and no consumer-supplied SQL identifier exists.
2. **A provider-private lineage manager.** The `session.Sessions` over that store is created and held inside the provider, so it cannot be injected into a sign-in path. `WithUnusedSuccessorRecovery` is refused for it, because it would keep a superseded refresh token renewable for days, not for FAPI's time-limited retry. The grace window is bounded at 5 minutes.
3. **Domain-separated tokens.** The refresh token is `rt.<family>.<secret>`. The family identifier is not a secret (`pkg/id`), and the secret is the lineage session identifier. The value never passes `session.ValidIdentifier`, so a sign-in path refuses it before any lookup, even if the table guard were bypassed.
4. **An authoritative grant row.** One record holds the client, scopes, `auth_time`, `amr`, `acr`, key binding, code id and a revoked flag. It is read before anything changes state, and it carries the tombstone the lineage cannot:

```
 refresh request (rt.<family>.<secret>, client credentials, DPoP proof)
   |
   v
 [1] parse; malformed --------------------------------------------> invalid_grant (no lookup)
   |
   v
 [2] grants.Load(family)
       missing | revoked | client != authenticated client --------> invalid_grant
       (nothing written: no MarkPresented, no revocation)              (C1, C2)
   |
   v
 [3] binding set and proof key != binding -------------------------> invalid_dpop_proof (C5)
   |
   v
 [4] lineage.LoadForRenewal(secret)
       superseded past grace ==> family revoked; ReuseObserver marks
       the grant row revoked --------------------------------------> invalid_grant (C3, C4)
       s.FamilyID != family ---------------------------------------> invalid_grant
   |
   v
 [5] RotateWithGraceIssuing (grace <= 5 min) --> new rt.<family>.<secret'>
       + access token (typ at+jwt, short-lived) + ID token if requested
```

**How D+ answers each constraint:**

| | How D+ meets it |
|---|---|
| C1, C2 | client, scopes and revoked flag on the grant row, checked at step [2] before any write |
| C3, C4 | the lineage keeps every rotated identifier until retention ends; reuse revokes the family, and the revoked flag ends the grant even if a later read races the deletion |
| C5 | the key binding on the grant row, checked at [3]; `RotateWithGrace` carries a binding but never checks a proof, so the endpoint must |
| C6 | 256-bit secret, stored only as a digest, by the existing session code |
| C7 | revoking the grant ends the lineage; access tokens are short-lived JWTs (see P4) or opaque |
| C8 | the lineage manager's absolute timeout and family maximum |
| C9 | the grant row's `offline` flag decides what logout ends (sub-decision 2) |
| C10 | three barriers: a different table, a format no sign-in path accepts, and `typ` checks in `token` (P4) |
| C11 | the code records the family it created, and the grant row's revoked flag closes the replay race (H2) |

**What D+ costs:**
- **Two writes at the code exchange** (lineage and grant row), in one transaction through each adapter's `WithTx`:
  - a lineage without a grant row fails closed at [2];
  - a grant row without a lineage is an orphan for the sweeper.
- **A second migrated table** with the session schema. It is reached only through that constructor.
- **A grant-row store:** in-memory, `sqlstore`, `pgxstore` and `gormstore`, a migration and a conformance suite.
- **Two sweep tasks**, one renamed (`expiry.Task` supports it), plus an orphan sweep.
- **Unused sign-in fields on lineage records** (MFA state, confinement marks). They are harmless, because the provider alone constructs those records with a fixed set of create options.
- **One extra read per refresh** (the grant row).

#### Risks shared by every option

Each of these is `UNREPRODUCED` and becomes a red test for the chosen option.

- **H2, the code-replay race (C11).** Two redemptions of one code race the grant's commit:

  ```
   redemption 1                          redemption 2 (replay of the same code)
   ------------                          -------------------------------------
   consume code  (wins)
   prepare grant G (family F)            consume code  -> already used
                                         revoke what the code issued: RevokeFamily(F)
                                           -> nothing stored yet, deletes nothing
   commit G                  <-- a live grant the replay should have revoked
  ```

  - **The fix:** the code record names F before commit. The replay writes a tombstone (the grant row's revoked flag, keyed by F), which commit and every refresh check.
  - **Why the other options can't do this:** the lineage alone has no tombstone, which is why A and D as drafted cannot close the race.

- **H3, `auth_time` overstated.** `Prepare` sets `AuthenticatedAt` to the current time (`session/prepared.go:84`). A grant created at the code exchange would claim the exchange time as `auth_time`, and overstate freshness to a relying party checking `max_age`. The grant must copy the sign-in's `AuthenticatedAt`, `amr` and `acr` explicitly.
- **H4, an orphaned grant row.** Reuse revocation deletes the lineage but not the grant row. The `ReuseObserver` marks it revoked, and the sweeper removes it. The observer is not called when the revocation itself fails, so the refresh path must treat a missing lineage as revoked.
- **Access tokens outlive revocation (C7).** A JWT access token stays valid until its expiry whatever the grant storage. P4 answers this with a short lifetime and an opaque option.
- **Token-type confusion (C10).** `token`'s verifier checks no `typ` today, and P4 signs access tokens over the same key source as first-party tokens. Each token type must validate only as itself.

#### Sub-decisions that follow (decided 2026-11-02, as recommended)

| # | Question | Decision | Why |
|---|---|---|---|
| 2 | What does logout end? | Grants without `offline_access` end with the user's sign-in; `offline_access` grants survive; a per-client flag can tie them to the session | C9; Keycloak, node-oidc-provider and Duende behave this way |
| 3 | Does a password change revoke grants? | No by default, with an option to revoke. A self-service "end other sessions" offers a "revoke app access" choice | no source requires it (RFC 9700 MAY); no surveyed provider does it by default |
| 4 | Do security events revoke grants (recovery, MFA reset, passkey clone detection, account disable)? | Yes, by default | they signal possible compromise, where a 90-day grant is what an attacker keeps; ASVS 7.4.2 for a disabled account |
| 5 | What does reuse revoke? | The whole grant | OAuth 2.1 §4.3.1, ASVS 10.4.5; the rotation code already revokes the family, and the grant row adds the tombstone |
| 6 | How do access tokens meet C7 and C10? | JWT access tokens default to 5 minutes and carry `typ` `at+jwt`; `token` enforces `typ` so each type validates only as itself; opaque tokens with introspection remain the option for immediate revocation | RFC 7009 §2.1, RFC 8725 §3.12, RFC 9068 |

#### What follows from the decision

- **Stores:**
  - a fixed-table refresh-token store constructor in `sqlstore`, `pgxstore` and `gormstore`;
  - a grant-row store with its in-memory default, three SQL adapters and a conformance suite;
  - the security-state migration;
  - two sweep tasks plus an orphan sweep.
- **Left alone:** `session.Store` and `close-security-gaps` D12, so the two changes need no coordination.
- **The audit's risks, closed explicitly:**
  - the `typ` checks in `token`;
  - the H2 tombstone;
  - the explicit copy of the sign-in's authentication facts (H3);
  - the H4 rule that a missing lineage reads as revoked.
- **Sub-decision 2:** the provider is told when a sign-in ends (local logout, session-family revocation, back-channel logout from an upstream provider), and ends that user's grants without `offline_access` that came from it.
- **Sub-decision 3:** a password change keeps grants by default. An option on the password-change endpoint revokes them, and the self-service "end other sessions" endpoint of `close-security-gaps` D12 gains a "revoke application access" choice.
- **Sub-decision 4:** account recovery, MFA reset, passkey clone detection and account disable revoke the user's grants by default, each with an option to keep them.

**Default and override, per sub-decision** (`library-design`):

| # | Default | Consumer override |
|---|---|---|
| 2 | grants without `offline_access` end with the sign-in that created them; `offline_access` grants survive logout | per client, tie every grant to the sign-in's lifetime (`offline_access` included) |
| 3 | a password change keeps grants | an option revokes them; the user may choose to revoke them when ending other sessions |
| 4 | security events revoke the user's grants | an option per event keeps them, documented as weakening the response to a compromise |
| 5 | reuse revokes the whole grant | none: weakening it would break OAuth 2.1 §4.3.1 and ASVS 10.4.5, so no option exists (`library-design` rule 4) |
| 6 | JWT access tokens of 5 minutes, typed `at+jwt`, with `typ` enforced | the lifetime per client; opaque tokens with introspection. `typ` enforcement has no override, because it is the C10 guarantee |



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
- **Lifetime (amended 2026-11-02, from the grant-storage audit):** 5 minutes by default, replaceable per client. A JWT access token cannot be revoked before it expires, and RFC 7009 §2.1 asks that revoking a grant also end its access tokens (decision 5, C7). A short lifetime is how a JWT meets that.
- **Typing (amended 2026-11-02):** `token`'s verifier gains `typ` checks, so an access token, a first-party token and an ID token each validate only as themselves (RFC 8725 §3.12, RFC 9068). Today it checks no `typ`, and an access token's `jti` matching a sign-in identifier would resolve as a sign-in through `EnableBearerToken` (decision 5, C10).
- **Override:** opaque access tokens, verified by introspection. Revocation is then immediate, at one store read per request.
- **Where it lands:** `token` must issue these claims and enforce `typ`; that is a `token-issuance` change.

#### P5. Refresh tokens rotate, and reuse revokes the grant

- **Default:** every refresh rotates. A rotated token presented after its grace window revokes the whole grant (RFC 9700 §4.14.2).
- **Override, per client:** rotation off for a confidential, sender-constrained client. FAPI 2.0 asks for that, and permits rotation only with a time-limited retry using the old token. That retry is what the existing grace window already gives.
- **Bounds (amended 2026-11-02):** the grace window is at most 5 minutes, and `session`'s unused-successor recovery is refused for refresh tokens, because it would keep a superseded token renewable for days rather than for a time-limited retry. Reuse revokes the whole grant (decision 5, sub-decision 5).

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
- **What stays open:** whether a green run is a hard precondition for the tag is open question 1.

## Risks / Trade-offs

- **[The tag waits for this whole change]** → v1 stays at the scope above, and every follow-up only adds. The task breakdown, written once P1 to P9 are confirmed, sizes it.
- **[No certified library underneath]** → the conformance suite in CI (P9), plus test-first coverage of the pitfalls the advisories cluster on: exact redirect matching, code reuse revoking what it issued, refresh reuse, and token binding.
- **[A refresh token mistaken for a sign-in]** → three built-in paths turn a stored session identifier into a sign-in. Decision 5 (D+) keeps refresh tokens out of all three by a fixed table and a token format no sign-in path accepts.
- **[A replayed code racing the first exchange leaves a live grant]** (H2, `UNREPRODUCED`) → the grant row's revoked flag, keyed by the family the code records (decision 5).
- **[A grant overstating `auth_time`]** (H3, `UNREPRODUCED`) → the grant copies the sign-in's authentication facts explicitly.
- **[Error bodies depart from the library's default]** → limited to the provider's endpoints, recorded in P3, and pinned by tests against RFC 6749's examples.
- **[RS256 by default conflicts with FAPI 2.0]** → recorded in P8. A FAPI profile is a later, additive switch.
- **[`prompt=none` cannot succeed in v1]** → `login_required` is the correct answer when no login is resumable. The README's *Known limitations* names it until the cookie session lands.
- **[The conformance suite's exact test lists were not read]** (its profile PDF was unreadable) → the first conformance task records which tests run, before the gate relies on them.

## Migration Plan

- Nothing to migrate: the provider is new, and off until a consumer enables it.
- The security-state migration that adds the provider's tables lands in the first migration set, before the tag.

## Open Questions

### 1. Is a green conformance run a hard precondition for the tag?

- **Recommendation:** yes for the Basic OP and Config OP plans.
- **What it changes:** whether `release-readiness`'s gate names the conformance job. It changes no spec of this change.

### 2. The provider package's name and place

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

### Decision 5: how a grant is stored

**Researched (accessed 2026-11-02):**
- [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.txt), §6, §10.4 and §10.10: refresh tokens bound to their client, confidential in storage, and at least 128 bits hard to guess (C1, C6).
- [RFC 6819](https://www.rfc-editor.org/rfc/rfc6819.txt), §5.1.4.1.3, §5.2.2.2 and §5.2.2.3: store hashes rather than clear text, protect the client binding, revoke the grant on reuse (C1, C4, C6).
- [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.txt), §2.2.2, §4.2.4 and §4.14.2: sender-constraining or rotation for public clients, retained rotation relationships, code replay, and revocation on security events "MAY" (C3, C4, C11).
- [OAuth 2.1, draft-ietf-oauth-v2-1-17](https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-17.txt), §4.1.3, §4.3.1, §4.3.3, §7.5.3 and §9.3.2: grant still active, reuse revokes the grant, one token response per code, no revocation on an invalid replay, session-linked refresh tokens for browser apps. It is a draft (C2, C4, C11).
- [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009.txt), §2 and §2.1: refresh-token revocation, and ending the grant's access tokens (C7).
- [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.txt), §5: DPoP-bound refresh tokens for public clients (C5).
- [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705.txt): certificate-bound refresh tokens.
- [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.txt), §3.11 and §3.12, and [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068.txt): explicit typing and mutually exclusive validation (C10).
- [OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html), §2.7, and [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html), §11: refresh tokens at logout with and without `offline_access` (C9).
- [FAPI 2.0 Security Profile](https://openid.net/specs/fapi-security-profile-2_0-final.html), §5.3.2.1: rotation only in extraordinary circumstances, with a time-limited retry.
- [OWASP ASVS 5.0](https://github.com/OWASP/ASVS/tree/master/5.0/en), 7.4.2, 7.4.3, 9.2.2, 10.4.2, 10.4.5, 10.4.8, 10.4.9 and 10.7.3: token typing, reuse, absolute expiry, user revocation, and session termination after a factor change.
- [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html), §5: access and refresh tokens may outlive the authentication session, and IdP and RP sessions are independent. Its subsection numbers were not confirmed.
- [OWASP OAuth 2.0 Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html) and [Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html): sender-constraining combined with rotation, and renewing sessions after a password change.
- Established practice (provider table):
  - [Keycloak server administration guide](https://www.keycloak.org/docs/latest/server_admin/): offline sessions survive logout;
  - [Ory Hydra API specification](https://github.com/ory/hydra/blob/master/spec/api.json): revoking a login session invalidates no tokens; revoking consent sessions does;
  - [Duende IdentityServer documentation](https://docs.duendesoftware.com/identityserver/): persisted grants keyed by a hash, and `CoordinateLifetimeWithUserSession`;
  - [Spring Authorization Server core model](https://docs.spring.io/spring-authorization-server/reference/core-model-components.html);
  - [node-oidc-provider documentation](https://github.com/panva/node-oidc-provider/blob/main/docs/README.md): Session, Grant and RefreshToken models, and `expiresWithSession`;
  - [zitadel/oidc `op` storage](https://raw.githubusercontent.com/zitadel/oidc/main/pkg/op/storage.go);
  - [Auth0 refresh token rotation](https://auth0.com/docs/secure/tokens/refresh-tokens/refresh-token-rotation) and [revocation](https://auth0.com/docs/secure/tokens/refresh-tokens/revoke-refresh-tokens);
  - [Okta refresh token rotation](https://developer.okta.com/docs/guides/refresh-tokens/refresh-token-rotation/).

  Auth0's and Okta's logout and password-change behaviour, and Keycloak's default for offline sessions at a password change, were not verified.

The user chose D+ and sub-decisions 2 to 6 on 2026-11-02. The code paths, the option failure modes and H2 to H4 come from an independent review of scrty's own code (`session`, `httpsec`, the SQL stores, `expiry`) and of `close-security-gaps` D8 and D12. They are reasoned from the code, not reproduced.
