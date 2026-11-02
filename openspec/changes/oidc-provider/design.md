## Context

See `proposal.md` for the motivation. This design was captured from an exploration on 2026-11-02, before any spec was written. It is meant to be the complete record of what was decided and why, as known on that date, so a later reader can check a decision without the conversation it came from.

- **Decided:** decisions 1 to 5 and P1 to P9, all chosen by the user on 2026-11-02. Each states its default, how a consumer overrides it, and what was rejected.
- **The user's standing condition:** the provider must comply with the standards it implements and follow established security practice. "Standards compliance and security practice" maps each requirement to the decision that meets it.
- **Open questions:** only the package name remains, settled with the specs. A few values the specs fix are listed at the end of the compliance section.
- **Not yet reproduced:** risks found by reading code are labelled `UNREPRODUCED`. Each becomes a failing test first when its task starts (`defect-claims`).

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
- **What it costs.** No certified library sits underneath. Conformance is therefore proved by running the OpenID Foundation suite, which gates the tag (P9).
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
  magic link,    onetime     families  token.Generator (+ new
  MFA, recovery, check-then- + grant   claims), cnf from
  upstream OIDC  consume     row (D+,  close-security-gaps
  -> resume (P1)             dec. 5)
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

### P1 to P9: the provider's defaults (decided 2026-11-02)

The research proposed these as defaults P1 to P9. On 2026-11-02 the user confirmed all nine as recommended, including the refinements found while elaborating them. The user's standing condition applies: the provider must comply with the standards it implements and follow established security practice. Where a standard says MUST, the default meets it and no option relaxes it (`library-design` rule 4). Where a standard leaves a choice, the default takes the safer side and the override is documented.

Each decision keeps its P number, because decision 5 and the risks already cite them. Each one records:
- what it decides and why;
- the default and the consumer's override;
- what was rejected;
- how it interacts with decision 5 and its sub-decisions;
- what is still unverified.

#### P1. Login and consent are handed off through a pending request and resumed through the provider

**The decision.**
- The authorization endpoint renders nothing. It validates the request, parks it under an opaque handle, and sends the browser to the consumer's login page.
- The consumer's page signs the user in with scrty's existing endpoints, then resumes the request through the provider.
- Consent is a second stage with the same handle.

Every established provider surveyed uses this shape: Hydra, node-oidc-provider, Duende IdentityServer, Spring Authorization Server, and `zitadel/oidc`'s `op` package. It fits scrty's rule that the library renders nothing.

```
 RP --(1) GET /authorize?client_id,redirect_uri,response_type=code,scope,state,nonce,
 |                        code_challenge(S256),prompt,max_age[,dpop_jkt][,resource]
 v
 provider: [a] client known?  redirect_uri equal to a registered one?   no -> NO redirect (P3)
           [b] everything else valid?                                   no -> 303 redirect_uri?error&state&iss
           [c] park PENDING REQUEST {client, redirect_uri, scopes, state, nonce, challenge,
               prompt, max_age, dpop_jkt, resource} under <handle>, stage = login
           Set-Cookie: <flow cookie bound to handle>; HttpOnly; Secure; SameSite=Lax
 |  (2) 303 -> consumer login URL ?req=<handle>
 v
 consumer login page --> existing scrty endpoints (form, passkey, magic link, upstream OIDC,
 |                       MFA, recovery) --> sign-in credential, held in page memory only
 |  (3) POST <resume> {req:<handle>}  + Authorization: <sign-in credential>  (+ flow cookie)
 v
 provider: handle unspent, unexpired, and matches this browser's flow cookie?
           sign-in passes the chain's policy phase?          (MFA pending -> refused; page continues MFA)
           prompt=login / max_age satisfied by AuthenticatedAt?   no -> page re-authenticates
           consent needed (P2)?  yes -> stage = consent: {"redirect_to": consent URL ?req=<handle>}
                                        consent page reads the request: op.PendingRequest(ctx, handle)
                                        POST <resume> {req, granted scopes} or {req, deny}
 |  (4) {"redirect_to": "https://rp/cb?code=..&state=..&iss=.."}   page sets window.location
 v
 RP --(5) POST /token  (client authentication, code, code_verifier[, DPoP proof]) -> tokens
```

What the consumer writes, as a sketch (names are settled with the specs):

```go
op, err := oidcprovider.New(issuer, clients,
    oidcprovider.WithLoginURL("https://id.example.com/login"),     // required
    oidcprovider.WithConsentURL("https://id.example.com/consent"), // required (decision 4)
)
chain, err := httpsec.New(
    httpsec.EnableFormLogin(loginDeps),    // existing first factors, MFA, recovery ...
    httpsec.EnableMFA(methods),
    httpsec.EnableSessionBearer(sessDeps), // how the login page proves its sign-in to resume
    httpsec.EnableOIDCProvider(op),        // authorize, resume, token, userinfo, revoke, introspect, metadata, logout
)
// The login and consent pages may read the parked request for display.
// It never exposes the PKCE challenge, the nonce or the state.
req, err := op.PendingRequest(ctx, handle)
```

**The handle and its binding.**
- **What it is:** unguessable (at least 128 bits, as RFC 6749 §10.10 asks of any guessable credential), stored only as a digest, and single-use per stage.
- **Lifetime:** 10 minutes by default. This is a proposed value, not a researched one.
- **Binding to the browser:** it is bound to the browser that started the request by a `HttpOnly`, `Secure`, `SameSite=Lax` flow cookie, as `oidc-login`'s flow cookie already is.
  - The attack it stops: an attacker starts a request with their own PKCE verifier and sends the victim the login link. The victim signs in, but the victim's browser lacks the attacker's flow cookie, so the resume is refused. Without the binding, the code would be issued to the attacker's verifier with the victim's identity.
- **Why the resume resists forgery.** It requires the sign-in credential in the `Authorization` header, which a browser never attaches on its own. A cross-site page therefore cannot forge a resume or a consent grant (RFC 6749 §10.12, RFC 9700 §4.7).
- **Why the resume answers JSON, not a redirect.** The resume returns `{"redirect_to": ...}` rather than a 303, as Hydra does:
  - the login page calls it with `fetch`, which cannot usefully follow a cross-origin redirect;
  - the page then navigates at the top level, so the authorization response reaches the relying party as a normal navigation.
- **Redirect status:** every redirect the provider sends is 303, never 307 (RFC 9700 §4.12).
- **Where the pages must live.** The login and consent pages are served from the provider's site, because the `Lax` flow cookie is not sent on cross-site requests. Pages on another site are not supported in v1, and the specs state it.

**Default and override:**

| | Default | Override |
|---|---|---|
| Login and consent pages | the consumer's URLs, required at construction | none needed: the consumer owns the pages |
| Handle lifetime | 10 minutes | `WithPendingRequestLifetime`, bounded by a maximum the specs fix |
| Resume path, handle parameter name | documented constants | replaceable |
| Two pages or one | two stages | one page may handle both, by reading the request with `PendingRequest` and resuming twice |

**Rejected:**
- **The provider renders its own login page.** It breaks the library's rule that it renders nothing.
- **Resuming automatically inside `completeLogin`.** It would change every login endpoint's response contract from JSON to a redirect. It would also miss MFA verify and recovery completion, which issue credentials outside `completeLogin`.
- **A 303 from the resume endpoint.** `fetch` cannot use it across origins, and it hides the target from the page.

**Interactions.**
- **H3, `auth_time`.** The grant copies `AuthenticatedAt`, `amr` and `acr` from the sign-in the resume presented, never the exchange time (decision 5, H3).
- **Sub-decision 2, logout.** The grant row records the sign-in's family, which is the source of the ID token's `sid`. When that sign-in ends, the provider ends the grants without `offline_access` that came from it:
  - local logout;
  - revocation of the session family;
  - a back-channel logout from an upstream provider.

  Back-Channel Logout §2.7 asks exactly this of logout.
- **A refinement recommended in the elaboration and not adopted.** The elaboration also recommended that refreshing a grant without `offline_access` should check the sign-in is still live and record activity on it, as Keycloak's online sessions do. On checking the port, `session.Store` has no lookup by family (it has `DeleteFamily` only), and decision 5 keeps the port unchanged.
  - **What is recorded instead:** a grant without `offline_access` keeps its own idle timeout (P5). Its absolute lifetime is capped at the sign-in's absolute deadline, as known when the grant is created.
  - **What this misses:** a sign-in that merely goes idle does not end the grant by itself. No standard asks for that: Back-Channel Logout §2.7 concerns logout, and NIST SP 800-63B-4 treats the provider's and the relying party's sessions as independent.
  - **The remaining option:** tying grants to sign-in activity needs a family lookup in `session.Store`, which is a later, additive change.
- **The sign-in credential in JavaScript.** The login page holds a sign-in credential in page memory, which is the XSS exposure `bff-resource-server` records. The provider does not widen it, because the credential is the one the page already holds to sign in. The cookie session of `bff-resource-server` removes it in the SSO follow-up.

**Unverified:** the 10-minute handle lifetime is a proposal, not a researched figure.

#### P2. Consent is required unless a client is registered as first-party, and `offline_access` always asks

**The decision.**
- Every client goes through the consent stage the first time.
- Remembered consent that already covers the requested scopes skips the stage.
- A client registered as first-party skips it for ordinary scopes.
- `offline_access` is the exception: even a first-party client asks once, then the answer is remembered.

**Why.**
- **The safe default.** `library-design` asks for the safe default, and a client someone forgot to configure must ask the user rather than skip the question silently.
- **What OIDC Core §11 says** (verified 2026-11-02):
  - "The OP MUST always obtain consent to returning a Refresh Token that enables offline access to the requested resources."
  - "A previously saved user consent is not always sufficient to grant offline access."
  - `prompt=consent` "MUST be used unless other conditions for processing the request permitting offline access to the requested resources are in place".
  - Consent "MUST" be explicitly received, or already held, for `application_type` `web`, and "SHOULD" be for `native`.

  So the first-party flag cannot silently cover `offline_access`.

```go
oidcprovider.Client{
    ID:              "billing-web",
    ApplicationType: oidcprovider.Web,
    FirstParty:      true,                         // skips consent for ordinary scopes
    OfflineAccess:   oidcprovider.OfflineAskOnce,  // default: ask, then remember (Core s11)
}
oidcprovider.Client{
    ID:              "billing-ios",
    ApplicationType: oidcprovider.Native,
    FirstParty:      true,
    OfflineAccess:   oidcprovider.OfflinePreAuthorized, // the consumer asserts Core s11's "other
                                                        // conditions"; refused for a web client
}
```

**Default and override:**

| | Default | Override |
|---|---|---|
| Consent | required for every client; remembered per user and client | `FirstParty` skips it for ordinary scopes |
| `offline_access` | asked once even for a first-party client, then remembered | `OfflinePreAuthorized` for a first-party **native** client only. Construction refuses it for a web client, because Core says MUST there |
| `prompt=consent` | always shows the consent stage, whatever is remembered | none: it is the relying party's explicit request |

**Rejected:**
- **First-party skipping consent by default.** A forgotten flag would then silently skip consent, which is the unsafe direction.
- **Treating remembered consent as covering `offline_access` for ever.** Core says a saved consent "is not always sufficient". v1 remembers it per user and client, and ends that memory with the consent's revocation (decision 4).

**Interactions.**
- **Revoking consent** revokes the grant rows of that user and client (decision 4, decision 5).
- **Partial grants.** The code is bound to the scopes granted, not those requested (decision 4).

#### P3. The provider's endpoints render the error bodies the protocol requires

**The decision.** scrty's default answers errors with a bare status and no body. The protocol fixes how each provider endpoint reports an error, so these endpoints use the protocol's format. It is a recorded departure from `http-error-propagation`, limited to them.

| Endpoint | Error form |
|---|---|
| authorize, before `client_id` and `redirect_uri` are validated | **no redirect.** OIDC Core §3.1.2.6: "If the Redirection URI is invalid, the Authorization Server MUST NOT redirect the User Agent to the invalid Redirection URI." It returns the chain's error, a bare 400 by default, which the consumer may render as an error page |
| authorize, after validation | 303 to `redirect_uri?error=…&state=…&iss=…` (RFC 6749 §4.1.2.1, RFC 9207) |
| token, revocation, introspection | JSON `{"error": "…"}` with `Cache-Control: no-store` (RFC 6749 §5.1, §5.2). Status 400, or 401 with `WWW-Authenticate` for `invalid_client` |
| UserInfo | `WWW-Authenticate: Bearer error="invalid_token"` (RFC 6750 §3), or the `DPoP` scheme for a bound token (RFC 9449) |

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json
Cache-Control: no-store

{"error":"invalid_grant"}
```

**Default and override:**

| | Default | Override |
|---|---|---|
| `error` code and status | the protocol's | none: they are protocol, and changing them would break every client (`library-design` rule 4) |
| `error_description`, `error_uri` | **not sent** | a responder may add them |
| Error page for an unredirectable authorize error | the chain's bare 400 | the consumer's error responder, as for any chain error |

- **Why no description by default.** It follows scrty's fixed-text rule. A description is where internal detail (which check failed, a store error) leaks to a caller, and RFC 6749 makes it optional.

**Rejected:**
- **A bare status, as everywhere else in scrty.** It breaks every OAuth client library.
- **A fully replaceable renderer.** A consumer could then break the protocol, which `library-design` rule 4 says to refuse rather than allow quietly.

#### P4. Access tokens are JWTs per RFC 9068 by default, opaque by option, audience-restricted

**The decision.** The lifetime and the typing were decided with decision 5 (sub-decision 6). Recorded here in full:

```
header  {"typ":"at+jwt","alg":"RS256","kid":"..."}
claims  {"iss":"https://id.example.com","sub":"u-1","aud":"https://api.example.com",
         "client_id":"billing-web","scope":"openid profile","iat":..,"exp":iat+300,
         "jti":"...","auth_time":..,"acr":"..","amr":["pwd","otp"],"cnf":{"jkt":".."}}
```

- **Claims:** the RFC 9068 set, plus `auth_time`, `acr` and `amr` copied from the grant (H3). `cnf` is present when the token is sender-constrained (P6).
- **Lifetime:** 5 minutes. A JWT cannot be revoked before it expires, and RFC 7009 §2.1 asks that revoking a grant also end its access tokens (C7).
- **Typing:** `typ` is `at+jwt`. `token`'s verifier enforces `typ`, so an access token, a first-party token and an ID token each validate only as themselves (RFC 8725 §3.11 and §3.12, RFC 9068; C10).
- **Audience**, refined while elaborating. RFC 9068 requires `aud`, and RFC 9700 §2.3 says access tokens "SHOULD be audience-restricted to a specific resource server":
  - a client allowed to call APIs declares a default audience and the resources it may ask for;
  - a `resource` parameter (RFC 8707) is checked against that list, and a resource outside it is refused with `invalid_target`;
  - a client with neither gets the issuer as audience, so its token is good only at the provider's own UserInfo.

**Default and override:**

| | Default | Override |
|---|---|---|
| Format | JWT, `at+jwt` | opaque per client, verified by introspection; revocation is then immediate, at one store read per request |
| Lifetime | 5 minutes | per client |
| `typ` enforcement | always | none: it is the C10 guarantee |
| Audience | the client's declared default, or `resource` from its allowlist, else the issuer | per client and per request, within the allowlist; no "any audience" option |

**Rejected:**
- **Opaque by default.** Every API call would need a round trip to the provider, and `bff-resource-server`'s planned resource-server mode could not verify offline.
- **One global audience.** One API's token would then work at every other API, which is the counterfeit-resource-server attack RFC 9700 §4.9 describes.
- **Long-lived JWTs with a deny list.** It rebuilds introspection with worse failure modes.

**Where it lands:** `token` issues these claims and enforces `typ`, which is a `token-issuance` change.

#### P5. Refresh tokens rotate, reuse revokes the grant, and grants expire

**The decision.** Rotation and reuse were decided with decision 5:
- a rotated token presented after its grace window revokes the whole grant;
- the grace window is at most 5 minutes;
- `session`'s unused-successor recovery is refused for refresh tokens.

These values were set while elaborating:

| Setting | Default | Override | Basis |
|---|---|---|---|
| Grace window | 30 s, matching `EnableSessionRenewal`'s default | per client, at most `session.MaxRenewalGrace` (5 min) | a time-limited retry for a lost response (FAPI 2.0); Okta's default is also 30 s |
| Grant idle timeout | 30 days | per client | a proposed value; no standard fixes it |
| Grant absolute lifetime | 90 days | per client; must be at least the idle timeout | ASVS 10.4.8 requires an absolute expiry but names no value; 90 days is a proposed value |
| Grant without `offline_access` | also capped at the sign-in's absolute deadline, and ended with the sign-in (P1, sub-decision 2) | per client, tie every grant to the sign-in (sub-decision 2) | Back-Channel Logout §2.7 |
| Rotation | on | off per client, only for a confidential client whose tokens are sender-constrained; refused at construction for a public client | RFC 9700 §2.2.2: public clients need rotation or sender-constraining; FAPI 2.0 discourages rotation for confidential clients |

**Why the lifetimes are bounded.**
- A refresh token is the longest-lived credential the provider issues, and ASVS 10.4.8 requires an absolute expiry.
- The idle timeout ends grants for applications no longer in use.
- A rotating refresh token extends neither limit.

**Rejected:**
- **Rotation off by default.** Public clients would then need DPoP to meet RFC 9700 §2.2.2, and DPoP is optional by default (P6).
- **No absolute lifetime.** It fails ASVS 10.4.8.
- **Recovery of an unused successor**, as `session` allows for sign-ins. It would keep a superseded token renewable for days, not for a time-limited retry.

**Unverified:** the 30-day and 90-day figures are proposals. No standard fixes them.

#### P6. DPoP and mTLS binding in v1, through `close-security-gaps`

**The decision.** DPoP (RFC 9449) and certificate binding (RFC 8705) are in v1. They reuse `close-security-gaps` D8 and D9: proof verification, the `jti` replay store, server nonces, and `cnf`.

```
 authorize ?dpop_jkt=<thumbprint>             -> code bound to that key (RFC 9449 s10)
 token     DPoP: <proof, no ath>              -> access token cnf.jkt, token_type "DPoP"
                                                 public client: grant row key binding = jkt (s5)
                                                 confidential client: refresh token not key-bound
                                                 (RFC 9449 s5: bound to client authentication instead)
 refresh   DPoP: <proof>                      -> grant row key binding checked (decision 5, refresh step 3)
 userinfo  Authorization: DPoP <at> + proof   -> D8 verification, unchanged; refused as Bearer once bound
 mTLS      client certificate at token        -> cnf.x5t#S256 (D9); binding only, not client authentication
```

**What is new for the provider:**
- refresh tokens of public clients bound to the DPoP key (RFC 9449 §5);
- the `dpop_jkt` authorization parameter, which binds the code (§10);
- `dpop_signing_alg_values_supported` in the metadata;
- a per-client "binding required" setting.

**Default and override:**

| | Default | Override |
|---|---|---|
| DPoP | a proof is accepted, and binds the tokens when sent, as D8's chain default does | per client, binding required: a token request without a proof is refused |
| mTLS | a presented certificate binds the access token (D9) | per client, binding required |
| `tls_client_auth` as client authentication | not in v1 | a later additive method |

**A conflict with `close-security-gaps` D8, to resolve there.**
- **The conflict:** D8 makes enabling DPoP with neither bearer mode a configuration error, so a chain that runs only the provider, with no first-party bearer, would be refused.
- **The fix:** D8's rule must count the provider as a DPoP user. That is a delta to `sender-constrained-tokens`, a capability `close-security-gaps` owns.
- **Done 2026-11-02:** amended in `close-security-gaps` (commit `8f50e44` on `feat/close-security-gaps`, before task 8.2 is implemented).
  - **The rule now:** D8 refuses DPoP only when no enabled feature verifies bound credentials.
  - **How it is checked:** the chain reads an internal set that holds the two bearer modes there.
  - **What this change adds:** this change's provider adds itself to that set. That is an implementation detail of `httpsec`, and needs no delta to `sender-constrained-tokens` beyond the token endpoint's binding.

**Rejected:** DPoP as a later follow-up. RFC 9700 §2.2.2 gives public clients two ways to protect refresh tokens, and the D8 machinery is already being built.

#### P7. Client authentication

| Method | v1 | Why |
|---|---|---|
| `client_secret_basic` | yes | Core's default; the Basic OP plan's manual clients use it |
| `client_secret_post` | yes | the Basic OP plan's manual clients use it |
| `private_key_jwt` (RFC 7523) | yes | RFC 9700 §2.5: "It is RECOMMENDED to use asymmetric cryptography for client authentication" |
| `none` | yes | public clients; PKCE is required for every client anyway |
| `client_secret_jwt` | **no** | a symmetric secret both sides can sign with; it adds nothing over `private_key_jwt` and makes the secret usable for forgery |
| `tls_client_auth`, `self_signed_tls_client_auth` | later | they need D9's certificate plumbing for authentication, not just binding |

**Secrets:**
- **Generated by the library:** 256 bits, shown once, kept as a SHA-256 digest, compared in constant time, as `apikey` does.
- **Supplied by the consumer:** at least 32 bytes, or refused at construction (OIDC Core §16.19).

**One method per client.** Each client declares exactly one method. A client allowed several is a downgrade path, where a stolen weaker credential works although a stronger one is registered.

**The `private_key_jwt` audience** (CVE-2025-27370 and CVE-2025-27371):
- **What happened:** on 2025-02-25 the OpenID Foundation disclosed that ambiguous audience values let a malicious authorization server reuse a client's signed assertion at another server. The Foundation says it updated its specifications and certification tests. What those tests now check was not verified.
- **What OIDC Core says:** Core §9 still says the audience "SHOULD be the URL of the Authorization Server's Token Endpoint" (verified 2026-11-02).
- **What the IETF fix says:** `draft-ietf-oauth-rfc7523bis` (still a draft) requires the issuer identifier as the sole audience, and requires the server to reject any other.
- **What scrty does:** it takes the stricter rule by default.

```go
oidcprovider.WithClientAssertionAudience(oidcprovider.AudienceIssuerOnly)            // default (rfc7523bis)
oidcprovider.WithClientAssertionAudience(oidcprovider.AudienceIssuerOrTokenEndpoint) // override for clients
// built to Core's older SHOULD; godoc states it accepts the ambiguity CVE-2025-27370 describes
```

- **Why the strict default costs nothing at conformance:** the Basic OP plan does not use `private_key_jwt`.

**Assertion checks:**
- `iss` and `sub` equal the `client_id`;
- the audience follows the rule above;
- `exp` is present and in the future;
- the `jti` is new: it is inserted into a replay store with DPoP's insert-if-absent contract, kept until the assertion's `exp`;
- the signature verifies against the client's registered `jwks`, or its `jwks_uri` fetched through the confined outbound client and the relying party's key-set cache.

The maximum assertion lifetime is fixed in the specs.

**Default and override:** the method is the client's choice. Nothing else about authentication is overridable beyond the audience compatibility option above.

#### P8. RS256 for ID tokens, other algorithms per client

**The decision.**
- **Default:** ID tokens are signed RS256. OIDC Core §15.1 makes it mandatory to support, and `signingkey` already defaults to it.
- **Per client:** `id_token_signed_response_alg` may name ES256 or EdDSA, when the key manager holds that algorithm. A client naming one it does not hold is a configuration error at construction.
- **Access tokens** use the key manager's default algorithm.
- **Never `none`,** which `token` already refuses.
- **Not in v1:** ID token encryption.

**Rejected:** ES256 by default. Relying parties that support only RS256, which Core allows, would fail, and so would the Basic OP plan.

**Tension recorded:** FAPI 2.0 forbids RS256. Its profile, a Non-Goal here, would change this default when it is added.

#### P9. Conformance runs in CI and gates the tag

**The decision.**
- The OpenID Foundation conformance suite runs its Basic OP and Config OP plans in CI.
- The test server is built only from the provider's defaults.
- A green run of both plans is a precondition for `v0.1.0`. This settles former open question 1 as recommended.

```
 test module: a conformance OP command (scrty defaults + the suite's test clients)
      |
 CI job "conformance" (separate from make check and from the release gate's workspace-off builds):
      docker compose up  conformance-suite (Java + MongoDB)  +  the conformance OP
      run the Basic OP and Config OP plans
      fail on any FAILED or INTERRUPTED result; keep the logs as a CI artifact
      |
 release-readiness's gate names this job; v0.1.0 waits for it to be green
```

**Why it gates the tag.** No certified library sits underneath (decision 1), so the suite is the only external proof that the provider follows the protocol. A failing plan at the tag would mean shipping a provider that standard relying parties may not interoperate with.

**Default and override:** not consumer-facing.

**Unverified.** The first conformance task records each of these before the job is relied on:
- the exact plan names and test lists, which are in a profile PDF that could not be read;
- whether the locally run suite accepts an `http://` issuer or needs TLS with a trusted certificate;
- whether the headless runner (`scripts/run-test-plan.py`) is part of the upstream repository. A third-party guide is the only source found.

**Cross-change:** `release-readiness`'s gate must name the conformance job, which is a change to that change's tasks when this one is planned.

### Standards compliance and security practice

The user asked that the provider comply with the standards it implements and with security practice generally. This section maps each requirement to where the design meets it, so a reviewer can check the specs against it.

- **Labels:** "MUST" and "SHOULD" are the source's own words.
- **Section numbers:** they are given where they were read. Those for RFC 9700 were verified on 2026-11-02.
- **Scope:** an item the provider does not support (implicit flow, ROPC, PAR) is listed under Non-Goals, not here.

#### The authorization request and response

| Source | Requirement | Met by |
|---|---|---|
| RFC 9700 §2.1, §4.1.3; OIDC Core §3.1.2.1 | redirect URIs compared by exact string matching ("MUST utilize exact string matching") | P1 step [a]; no patterns, no localhost port wildcards in v1 |
| OIDC Core §3.1.2.6; RFC 6749 §4.1.2.1 | never redirect to an invalid redirect URI | P3 |
| RFC 9700 §4.11.2 | the authorization server must not be an open redirector | P3: errors before validation are not redirected; `post_logout_redirect_uri` is matched exactly too |
| RFC 9700 §2.1.1; RFC 7636 | PKCE supported; public clients MUST use it; S256 | PKCE with S256 required for **every** client (stricter than the MUST, as OAuth 2.1 does); `plain` refused |
| RFC 9700 §4.8.2 | PKCE downgrade: a `code_verifier` at the token endpoint for a code issued without `code_challenge` is rejected | holds by construction: no code is issued without a challenge, and the token endpoint refuses a verifier that does not match |
| RFC 9700 §2.1, §4.4; RFC 9207 | mix-up defence REQUIRED | `iss` in every authorization response, success and error; `authorization_response_iss_parameter_supported` in the metadata |
| RFC 6749 §10.12; RFC 9700 §4.7 | CSRF on the redirect flow | `state` returned unchanged; PKCE; the resume requires the sign-in credential (P1) |
| OIDC Core §3.1.2.1, §3.1.3.7 | `nonce` returned in the ID token; `prompt`, `max_age`, `auth_time` honoured | P1; `auth_time` from the sign-in (H3) |
| RFC 9700 §4.12 | "MUST NOT use the HTTP 307 status code for redirection" | every provider redirect is 303 (P1) |
| RFC 9700 §2.6 | "CORS MUST NOT be supported at the authorization endpoint" | `close-security-gaps` D5 policy: never on authorize; allowed on token, UserInfo, metadata and JWKS |
| RFC 9700 §4.16 | "Authorization servers MUST prevent clickjacking", by CSP `frame-ancestors` on the authorization endpoint and the pages it leads to | provider responses carry D4's security headers. The login and consent pages are the consumer's: when served through the chain, D4 covers them, and the README states the requirement for pages served otherwise |
| RFC 9700 §4.2.4 | no credential leakage through `Referer` | `Referrer-Policy` from D4 on provider responses; codes are single-use and short-lived |
| OIDC Core §11 | consent for `offline_access` | P2 |

#### The token endpoint, codes and refresh tokens

| Source | Requirement | Met by |
|---|---|---|
| RFC 6749 §4.1.2, §10.5; RFC 9700 §4.2.4; OAuth 2.1 draft §4.1.3 | codes short-lived, single-use, bound to client and redirect URI; replay should revoke what the code issued | `token/onetime` check-then-consume; the H2 tombstone (decision 5); lifetime at most 10 minutes (RFC 6749 §4.1.2 RECOMMENDED), default value fixed in the specs |
| RFC 6749 §5.1 | token responses carry `Cache-Control: no-store` | P3 |
| RFC 6749 §10.4, §10.10; RFC 6819 | refresh tokens bound to the client, stored as digests, at least 128 bits hard to guess | decision 5 (C1, C6) |
| RFC 9700 §2.2.2, §4.14.2 | public-client refresh tokens sender-constrained or rotated; reuse detection | P5 rotation on by default; P6 binding |
| OAuth 2.1 draft §4.3.1; ASVS 10.4.5 | reuse revokes the grant | sub-decision 5 (no override) |
| ASVS 10.4.8 | refresh tokens have an absolute expiry | P5 (90 days) |
| RFC 9700 §2.5; RFC 7523; CVE-2025-27370 | asymmetric client authentication recommended; assertion audience unambiguous | P7 |
| OIDC Core §16.19 | symmetric secrets with enough entropy | P7 (256 bits generated, 32 bytes minimum supplied) |
| RFC 9700 §4.13; RFC 8705 | a TLS-terminating proxy must not let a client forge the certificate header | `close-security-gaps` D2, D7 and D9: trusted proxies only |
| Practice | brute force on client secrets and codes | `ratelimit` on the token endpoint (decision 2) |

#### Tokens

| Source | Requirement | Met by |
|---|---|---|
| RFC 9068; RFC 8725 §3.11, §3.12 | access tokens typed `at+jwt`; mutually exclusive validation | sub-decision 6, P4 |
| RFC 9700 §2.3, §4.10.2; RFC 8707 | access tokens audience-restricted | P4 audience rule |
| RFC 9700 §4.10.1; RFC 9449; RFC 8705 | sender-constrained access tokens | P6 |
| RFC 7009 §2.1 | revoking a grant ends its access tokens | 5-minute JWTs, or opaque tokens (P4) |
| RFC 7662 | introspection is a protected endpoint | introspection requires client authentication; a client may introspect only tokens issued to it or its declared audience (fixed in the specs) |
| OIDC Core §15.1 | RS256 supported | P8 |
| RFC 8725 | no `none`, algorithm allow-lists, key per algorithm | `token`'s existing jwx allow-list; P8 |

#### Logout, accounts and audit

| Source | Requirement | Met by |
|---|---|---|
| Back-Channel Logout §2.7 | refresh tokens without `offline_access` end at logout | sub-decision 2, P1 |
| RP-Initiated Logout | `id_token_hint`, exact `post_logout_redirect_uri` | the `oidc-provider-logout` capability |
| ASVS 7.4.2 | a disabled account's sessions and tokens end | sub-decision 4 |
| ASVS 10.4.9 | users can revoke an application's access | consent revocation (decision 4) and D12's "revoke application access" (sub-decision 3) |
| Practice | an audit trail of grants, reuse and revocation | security events, `close-security-gaps` D13 |
| Practice | no codes, tokens, handles or secrets in logs | the existing redaction rules apply to every new value; specs pin it |

**Values the specs still fix.** These are named here so they are not lost. Each takes the safe side and is pinned by a scenario:
- the authorization code lifetime (at most 10 minutes);
- the maximum pending-request lifetime;
- the maximum `private_key_jwt` assertion lifetime;
- the introspection audience rule.

## Risks / Trade-offs

- **[The tag waits for this whole change, and for a green conformance run]** → v1 stays at the scope above, and every follow-up only adds. The task breakdown sizes it; P9 makes the conformance job part of the gate.
- **[No certified library underneath]** → the conformance suite in CI (P9), plus test-first coverage of the pitfalls the advisories cluster on: exact redirect matching, code reuse revoking what it issued, refresh reuse, and token binding.
- **[A refresh token mistaken for a sign-in]** → three built-in paths turn a stored session identifier into a sign-in. Decision 5 (D+) keeps refresh tokens out of all three by a fixed table and a token format no sign-in path accepts.
- **[A replayed code racing the first exchange leaves a live grant]** (H2, `UNREPRODUCED`) → the grant row's revoked flag, keyed by the family the code records (decision 5).
- **[A grant overstating `auth_time`]** (H3, `UNREPRODUCED`) → the grant copies the sign-in's authentication facts explicitly.
- **[Error bodies depart from the library's default]** → limited to the provider's endpoints, recorded in P3, and pinned by tests against RFC 6749's examples.
- **[RS256 by default conflicts with FAPI 2.0]** → recorded in P8. A FAPI profile is a later, additive switch.
- **[`prompt=none` cannot succeed in v1]** → `login_required` is the correct answer when no login is resumable. The README's *Known limitations* names it until the cookie session lands.
- **[A sign-in credential held by the login page's JavaScript]** → it is the credential the page already holds to sign in, kept in memory only. The resume adds no new exposure, and `bff-resource-server`'s cookie session removes it in the SSO follow-up (P1).
- **[A grant without `offline_access` outliving an idle sign-in]** → it ends at logout, family revocation and upstream back-channel logout, and is capped at the sign-in's absolute deadline. Ending it on idle expiry needs a family lookup in `session.Store`, a later additive change (P1).
- **[Strict `private_key_jwt` audience refusing older clients]** → clients built to Core's token-endpoint audience fail until they send the issuer. The compatibility option exists and is documented as accepting the ambiguity CVE-2025-27370 describes (P7).
- **[Clickjacking on the consumer's login and consent pages]** → RFC 9700 §4.16 puts it on the authorization server, but the pages are the consumer's. D4's headers cover pages served through the chain; the README states the requirement for any other page.
- **[`close-security-gaps` D8 refusing a provider-only chain with DPoP]** → amended there on 2026-11-02: DPoP is refused only when no enabled feature verifies bound credentials (P6).
- **[The conformance suite's exact test lists were not read]** (its profile PDF was unreadable) → the first conformance task records which tests run, before the gate relies on them.

## Migration Plan

- Nothing to migrate: the provider is new, and off until a consumer enables it.
- The security-state migration that adds the provider's tables lands in the first migration set, before the tag.

## Open Questions

Former open question 1, whether a green conformance run is a hard precondition for the tag, was decided on 2026-11-02 as recommended: yes, for both plans (P9).

### 1. The provider package's name and place

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
  - §3.1.2.6: no redirect to an invalid redirection URI (quoted in P3, re-read 2026-11-02);
  - `offline_access` and consent (§11): the consent MUSTs quoted in P2, re-read 2026-11-02;
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

  It is BCP 240, published January 2025 (verified 2026-11-02, superseding an earlier note that these were unverified).
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

**Primary documentation** (not re-checked on 2026-11-02):
- [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html):
  - §4.1.2.1 and §5.2: authorization and token error responses, and 401 with `WWW-Authenticate` for `invalid_client` (P3);
  - §5.1: `Cache-Control: no-store` on token responses (P3);
  - §4.1.2: a maximum code lifetime of 10 minutes RECOMMENDED;
  - §10.10 and §10.12: credential entropy and CSRF (P1).
- [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html), §3: the `WWW-Authenticate` error at UserInfo (P3).

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
  - §9: client authentication methods, and the `private_key_jwt` audience that "SHOULD be the URL of the Authorization Server's Token Endpoint" (re-read 2026-11-02);
  - §16.19: secret entropy;
  - §15.1: RS256 mandatory.
- [OpenID Foundation: Notice of a Security Vulnerability](https://openid.net/notice-of-a-security-vulnerability/), 2025-02-25: CVE-2025-27370 and CVE-2025-27371, the `private_key_jwt` audience ambiguity, and the Foundation's updates to its specifications and certification tests. What the updated tests check was not verified (P7).
- [draft-ietf-oauth-rfc7523bis](https://datatracker.ietf.org/doc/draft-ietf-oauth-rfc7523bis/): the issuer identifier as the sole audience, with others rejected. It is an Internet-Draft, and its details came from a search summary rather than a full read (P7 default).
- Third-party summaries of the CVEs, weighted lower than the notice: [SentinelOne CVE-2025-27370](https://www.sentinelone.com/vulnerability-database/cve-2025-27370/), [Start with Identity CVE-2025-27371](https://startwithidentity.com/cves/cve-2025-27371/), [ICS-CSIRT CVE-2025-27370](https://cve.ics-csirt.io/cve/CVE-2025-27370), [exploit-intel CVE-2025-27370](https://exploit-intel.com/vuln/CVE-2025-27370), [cvelogic CVE-2025-27370](https://www.cvelogic.com/cve/CVE-2025-27370).
- [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.txt), §2.5: "It is RECOMMENDED to use asymmetric cryptography for client authentication" (re-read 2026-11-02).

### P9: conformance

**Researched (accessed 2026-11-02):**
- [OpenID Connect OP conformance profiles](https://openid.net/certification/connect_op_testing/): what Basic OP and Config OP cover and the clients they need. The exact test lists are in a profile PDF that could not be read, so they are unverified.
- [Conformance suite repository](https://gitlab.com/openid/conformance-suite) and [its build-and-run wiki](https://gitlab.com/openid/conformance-suite/-/wikis/Developers/Build-&-Run): running the suite locally with Docker.

The decision that a green run gates the tag (P9) is reasoned from decision 1: no certified library sits underneath.

### Standards compliance and security practice

**Researched (accessed 2026-11-02):**
- [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.txt), BCP 240, January 2025. Each clause below was read and quoted in the compliance tables:
  - §2.1 and §4.1.3: exact redirect matching, and the mix-up defence;
  - §2.1.1: PKCE and S256;
  - §2.3: audience-restricted access tokens;
  - §2.6: no CORS at the authorization endpoint;
  - §4.8.2: PKCE downgrade;
  - §4.12: no 307;
  - §4.16: clickjacking and CSP `frame-ancestors`.

  The rows citing §4.2.4, §4.7, §4.9, §4.10, §4.11.2 and §4.13 rely on those sections' titles in its table of contents, read the same day, not on quoted text.
- The other rows cite sources already listed under the decisions they belong to: P1 to P9, decision 5 and the logout group.

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

The user chose D+ and sub-decisions 2 to 6 on 2026-11-02, and confirmed P1 to P9 the same day. The code paths, the option failure modes and H2 to H4 come from an independent review of scrty's own code (`session`, `httpsec`, the SQL stores, `expiry`) and of `close-security-gaps` D8 and D12. They are reasoned from the code, not reproduced.
