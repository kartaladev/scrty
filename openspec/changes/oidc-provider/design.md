## Context

See `proposal.md` for the motivation. This design was captured from an exploration on 2026-11-02, before any spec was written. It is meant to be the complete record of what was decided and why, as known on that date, so a later reader can check a decision without the conversation it came from.

- **Decided:** decisions 1 to 5 and P1 to P9, all chosen by the user on 2026-11-02. Each states its default, how a consumer overrides it, and what was rejected.
- **Refreshed on 2026-11-04:** the design was rechecked against `pre-release-api-fixes` as it stands in #68 (`501a1a6`), the archived `close-security-gaps`, the OpenID Foundation conformance suite's source, and the standards again. "Decisions from the refresh" (R1 to R16) records the outcome. Where it supersedes an earlier decision, the earlier text says so.
- **The user's standing condition:** the provider must comply with the standards it implements and follow established security practice. "Standards compliance and security practice" maps each requirement to the decision that meets it.
- **Open questions:** none. The user accepted the refresh's four recommendations on 2026-11-04 (R1 to R5). The values and smaller behaviours the specs had to fix are recorded in "Decisions made while writing the specs". The mechanisms the task breakdown had to fix, and the package name, are in "Decisions made while writing the tasks" (T1 to T9).
- **Not yet reproduced:** risks found by reading code are labelled `UNREPRODUCED`. Each becomes a failing test first when its task starts (`defect-claims`).

### What exists

Read on `main` at `eb1f22a`, plus the in-flight changes' artifacts, and refreshed on 2026-11-04 against `main` at `39b035c` and #68 at `501a1a6`. #68 has since merged as `0080ee2`. Its code matches `501a1a6`; only `pre-release-api-fixes/tasks.md` differs.

- **scrty as a relying party.** `oidc-login`, `identity-linking` and `oidc-logout` log users in through external providers, link identities, and accept back-channel logout tokens. That code verifies ID and logout tokens with jwx v4 and caches remote key sets through the confined outbound client.
- **Keys and tokens.**
  - `token/signingkey` rotates RS256 (default), ES256 or EdDSA keys and publishes them.
  - `httpsec.EnableJWKSEndpoint` serves the key set at `/.well-known/jwks.json`.
  - `token.Generator.Generate(ctx, id, principal)` signs a fixed claim set: `jti`, `sub`, `iat`, `exp`, `iss` unless `WithoutIssuer` waives it, and an optional audience. `ConfirmingGenerator.GenerateWith` adds only `cnf`. It cannot carry `nonce`, `azp`, `auth_time`, `acr`, `amr`, `scope` or `client_id`. In #68 it gains a required `SubjectMode()`, and `sub` defaults to the user identifier.
  - A token's lifetime is capped at the key lifetime minus the rotation interval (23 hours by default) when the key source reports them. Since #68 a signing key retires one reload interval after its tokens can have expired, and leaves the store one grace later.
  - A test pins the package's use of jwx to a reviewed allow-list.
- **Sessions** (`session`).
  - **What a session records:** `AuthenticatedAt` (the OIDC `auth_time` meaning), `FirstFactor`, the MFA state, and federated `amr`/`acr`.
  - **Families:** sessions carry a family. `RotateWithGrace` rotates with a grace window and revokes the whole family on reuse, and `RevokeFamily` ends a family.
  - **Lifetimes:** the absolute timeout is 12 hours by default, bounded by `WithMaxAbsoluteLifetime` and `WithMaxFamilyLifetime`.
  - **User-wide operations:** `CountActiveByUser` feeds a concurrent-session limit. `DeleteByUser` and `DeleteByUserExcept` end a user's sessions.
  - **Session bearer:** `httpsec.EnableSessionBearer` accepts a session's own identifier as the bearer credential.
- **Single-use credentials.** `token/onetime` issues a credential for a purpose and a subject, stores only its hash, and makes check-then-consume structural: a refusal between the check and the consume leaves the credential unspent.
- **Client-style secrets.** `authenticate/apikey` shows a 256-bit secret once and keeps a SHA-256 digest.
- **One login completion.** `completeLogin` (`httpsec/complete.go`) closes form login and passkey passwordless. Magic link and OIDC handoff run its two halves, `prepareLogin` and `commit`, around spending their single-use credential. MFA verify and recovery completion issue on their own.
- **Landed since this design was written.** `close-security-gaps` was archived on 2026-11-03 (#45, #66), so its D-numbers below now name built code and settled specs:
  - DPoP (`EnableDPoP`, D8) and certificate binding (`EnableCertificateBinding`, D9);
  - CORS (D5), security headers (D4), CSRF (D6), trusted proxies with `Request.Host()` and `Request.Secure()` (D2, D7);
  - security events (D13), and session management: `EnableSessionManagement`, `Sessions.ListSignIns`, `EndSignIn` and `EndOtherSignIns` (D12).
- **In flight.**
  - `pre-release-api-fixes` (merged in #68, archived 2026-11-04): `sub` is the user identifier by default, with username options; a chain whose generators disagree with its bearer fails to build; a login whose principal has no identifier fails matching `token.ErrNoSubject`; key retirement and deletion as above. R6 records what follows.
  - `split-ci-jobs` (CI shape merged in #68; the change is still active on `main`, with two tasks open): one CI job per check behind an aggregate `ci-ok`, each calling a `make` target except `codeql`. R5 places the conformance job in that shape.
  - `session-signals`: defines its own `session.WithEndObserver`, which collides with T4. R16 resolves it.
  - `bff-resource-server`: the cookie session and the resource-server mode, both still waiting on its open questions. Its exploration notes ask whether scrty or an external IdP is the authority for browser apps. An OpenID Provider in scrty makes scrty an authority, which that change should take into account when it resumes. R2 no longer waits for its cookie session.
- **Rechecked against the merged code (task 1.1, 2026-11-04, `main` at `b18db5c`, with #68 as `0080ee2` and #70 as `b18db5c`).** What the plan left open, as merged:

  | The design's term | As merged |
  |---|---|
  | D8's proof verification, for a non-bearer endpoint | unexported `issuingBinding(ctx, ex.dpop(), ex.certBinding(), ex.Request, ex.bearerCredential) (session.KeyBinding, error)`, `httpsec/dpop.go`. No `dpop` package exists. The provider's endpoints live in `httpsec`, so they call it directly. It records the proof, refuses a missing proof under `Require`, and with a proof and a certificate binds the proof's key alone, as R12 needs |
  | The `jti` and nonce stores | `ReplayStore` (`Record`) for `jti`. There is no nonce store: nonces are sealed by `NonceCipher` and refused with `ErrDPoPNonceRequired` |
  | Internal set of binding verifiers (D8) | `bindingVerifiers []string`, `httpsec/options.go` |
  | Certificate thumbprint (D9) | unexported `certificateThumbprint(*x509.Certificate) string`, and `Exchange.presentedThumbprint`. `session.KeyBinding{JKT, X5TS256}` holds the binding |
  | CSRF exemption (D6) | `WithCSRFExemption(method, pattern string) CSRFOption`, one exact method and path, where `*` matches one segment |
  | CORS routes (D5) | not matched at all: a policy covers the whole chain. Task 9.6's provider-registered exclusion in `cors.go` is therefore needed, and is the only way to meet RFC 9700 §2.6 |
  | Security events (D13) | `event.Sink func(ctx, event.Event)`; `Event` has `Name`, `At`, `Outcome`, `User`, `ClientIP`, `Factor`, `Session` |
  | Session listing (D12) | `Sessions.ListSignIns`, `EndSignIn(ctx, user, handle)`, `EndOtherSignIns(ctx, user, current)`, and `DELETE /sessions`. `Sessions.IdleTimeout()` exists, as R2 assumes |
  | `token.Generator` | `Generate`, `SubjectMode` and an embedded `Verifier`. `ConfirmingGenerator` adds `GenerateWith`. `SubjectUserID` is the zero value and the default. The lifetime check reads `signingkey.LifetimeReporter` |
  | CI (R5) | `ci-ok` has a hand-written `needs`, and `.github/scripts/ci-needs-check.sh` fails when any other job is missing from it. `pincheck` covers workflow references: `docker://` needs `@sha256:`, and others a 40-character SHA with a `# <tag>` comment |

  None of it changes a decision. The corrections it caused are in this section and R6, and `plans.md` now uses these names.
- **The established design** has no OpenID Provider side, so there is no inherited behaviour to follow or depart from here. Every decision below rests on the standards and established practice listed in References.

## Goals / Non-Goals

**Goals:**

- A consumer can make their application an OpenID Provider for their own other applications. The OP passes the OpenID Foundation's Basic OP, Config OP and logout conformance plans with nothing configured beyond issuer, keys, clients and the login, consent and logout URLs, plus one named client setting and one recorded expected result (R1, R5).
- Every protocol step that already has a scrty primitive reuses it, rather than building a second mechanism.
- Every port and contract the provider changes is changed before `v0.1.0`, so the features left for later only add.

**Non-Goals** (each a follow-up that only adds, provided v1 leaves its seam):

- **PAR, and a FAPI 2.0 profile switch.** v1 leaves the request-object seam for them.
- **Third-party features:** dynamic client registration (RFC 7591; RFC 7592 is Experimental), pairwise subject identifiers, and the logo and policy URIs.
- **JAR, RAR (RFC 9396), token exchange (RFC 8693) and the device grant (RFC 8628).**
- **Implicit and hybrid flows, and the resource owner password grant.** RFC 9700 and the OAuth 2.1 draft deprecate them.
- **Front-channel logout and OIDC Session Management.** Both depend on third-party cookies, which browsers now block.
- **Official certification.** v1 runs the suite as a CI gate. Certification on the hosted suite is the maintainer's later step.
- **`user-email`:** an email of the user's own, separate from the username, with a true verified state: columns on `users`, `identity.Details` fields, and the default store persisting what it now discards. v1 releases a username that is an address, with `email_verified` false (R21). A consumer needing more uses `WithClaimSource` until then. Deferred by the user for a quicker release; a stored email would take precedence over the username, so it only adds.

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
| DPoP, mTLS binding | `close-security-gaps` D8, D9 | built |
| CORS on token, UserInfo, metadata and JWKS; `frame-ancestors` on provider pages | `close-security-gaps` D5, D4 | built |
| Issuer scheme and host behind a proxy | `close-security-gaps` D2, D7 | built |
| Audit trail of grants, reuse and revocation | security events, `close-security-gaps` D13 | built |
| "Apps with access to my account" | session listing, `close-security-gaps` D12 | built |
| Stable `sub` | `pre-release-api-fixes` decision 3 | merged (#68) |
| Back-channel logout sent to relying parties | logout-token shape from `oidc-logout`; delivery over `outbound` | partly built |
| Durable stores | `sqlstore`, `pgxstore`, `gormstore`, conformance suites, migrations, expiry sweeping | built (pattern) |

### 3. Delivered before `v0.1.0`, after the API fixes (decided 2026-11-02)

- **Order:** `close-security-gaps` (archived 2026-11-03), then `pre-release-api-fixes` (merged, #68), then this change, then `release-readiness`'s gate and tag.
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
 [4] a direct read compares the family first, so a client naming its own family beside another grant's secret reaches nothing (`REPRODUCED` 2026-11-04, a departure from the established design); then lineage.LoadForRenewal(secret)
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
- **Two writes at the code exchange** (lineage and grant row), first drafted as one transaction through each adapter's `WithTx`, and ordered without one by T9:
  - a lineage without a grant row fails closed at [2];
  - a grant row without a lineage reads as revoked at refresh, and stays until its deadline (R19).
- **A second migrated table** with the session schema. It is reached only through that constructor.
- **A grant-row store:** in-memory, `sqlstore`, `pgxstore` and `gormstore`, a migration and a conformance suite.
- **Two sweep tasks**, one renamed (`expiry.Task` supports it).
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
- **H4, an orphaned grant row.** Reuse revocation deletes the lineage but not the grant row. The provider marks it revoked before deleting the family where it judges the reuse itself, and otherwise the `ReuseObserver` does (R20), and the sweep removes it after that. The observer is not called when the revocation itself fails, so the refresh path must treat a missing lineage as revoked. *Reads* as revoked, refusing the request and writing nothing: R8.
- **H5 and H6:** added by the refresh, in R7 and R8.
- **Access tokens outlive revocation (C7).** A JWT access token stays valid until its expiry whatever the grant storage. P4 answers this with a short lifetime and an opaque option.
- **Token-type confusion (C10), `REPRODUCED` 2026-11-04.** `token`'s verifier checked no `typ`, and P4 signs access tokens over the same key source as first-party tokens, so an `at+jwt` token passed a default verifier (`TestVerifier_TokenType`, failing before the fix with `Expected error with "token: invalid" in chain but got nil`). jwx also wrote `typ: JWT` on first-party tokens by itself. Each token type now validates only as itself.

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
  - two sweep tasks.
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
- **Where the pages must live.** The login and consent pages are served from the issuer's origin. T5's `__Host-` cookie is sent to that host alone, so "the provider's site" as first written here was too wide (R9).

**Default and override:**

| | Default | Override |
|---|---|---|
| Login and consent pages | the consumer's URLs, required at construction | none needed: the consumer owns the pages |
| Handle lifetime | 10 minutes | `WithPendingRequestLifetime`, bounded by a maximum the specs fix |
| Resume path, handle parameter name | documented constants | the path by `WithOIDCProviderPath`. The parameter name has no override: only the consumer's own pages read it, so it is a documented convention (`library-design` rule 3) |
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
- **The sign-in credential in JavaScript.** The login page holds a sign-in credential in page memory, which is the XSS exposure `bff-resource-server` records. The provider does not widen it, because the credential is the one the page already holds to sign in. The browser session (R2) carries only the provider's own decisions, and `bff-resource-server`'s cookie session would remove the page's credential later.

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
         "jti":"...","auth_time":..,"acr":"..","amr":["pwd","mfa"],"cnf":{"jkt":".."}}
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
| Audience | the client's declared default, plus the issuer for an `openid` token (R4), or `resource` from its allowlist and the grant (R15), else the issuer | per client and per request, within the allowlist; no "any audience" option |

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
- **What the IETF fix says:** `draft-ietf-oauth-rfc7523bis` (in the RFC Editor's queue on 2026-11-04, no RFC number yet) requires the issuer identifier as the sole audience, and requires the server to reject any other, the token endpoint URL included.
- **What scrty does:** it takes the stricter rule by default.

```go
oidcprovider.WithClientAssertionAudience(oidcprovider.AudienceIssuerOnly)            // default (rfc7523bis)
oidcprovider.WithClientAssertionAudience(oidcprovider.AudienceIssuerOrTokenEndpoint) // override for clients
// built to Core's older SHOULD; godoc states it accepts the ambiguity CVE-2025-27370 describes
```

- **Why the strict default costs nothing at conformance:** the Basic OP plan does not use `private_key_jwt`. The Dynamic plan does, and sends the token endpoint as `aud`, but it needs dynamic registration, a Non-Goal.

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
- The OpenID Foundation conformance suite runs its Basic OP and Config OP plans in CI, and its logout plans too (R5).
- The test server is built from the provider's defaults, plus the one client setting R1 names.
- A green run of every plan, with only R5's recorded expected result, is a precondition for `v0.1.0`. This settles former open question 1 as recommended.

```
 test module: a conformance OP command (scrty defaults + the suite's test clients)
      |
 CI job "conformance" (separate from make check and from the release gate's workspace-off builds):
      docker compose up  conformance-suite (Java + MongoDB)  +  the conformance OP
      run the Basic OP, Config OP and logout plans (R5)
      fail on any FAILED or INTERRUPTED result; keep the logs as a CI artifact
      |
 release-readiness's gate names this job; v0.1.0 waits for it to be green
```

**Why it gates the tag.** No certified library sits underneath (decision 1), so the suite is the only external proof that the provider follows the protocol. A failing plan at the tag would mean shipping a provider that standard relying parties may not interoperate with.

**Default and override:** not consumer-facing.

**Verified 2026-11-04,** from the suite's source at commit `a5b9635`, and then by building and running it at `475e8bf` (task 1.2), against a throwaway stand-in rather than a real OP. Each line says which facts a run confirmed. R1, R2 and R5 follow from these:
- **Plans (confirmed by a run):** `oidcc-basic-certification-test-plan` (35 modules, including every module R1, R2 and R5 name) and `oidcc-config-certification-test-plan` (one module, `oidcc-discovery-endpoint-verification`). The logout plans are `oidcc-rp-initiated-logout-certification-test-plan` (11 modules) and `oidcc-backchannel-rp-initiated-logout-certification-test-plan` (2 modules).
- **TLS (confirmed by a run):** the Config plan fails on plain `http`: the discovery URL, the issuer and every endpoint must be `https`. A self-signed certificate is accepted on both sides: the server side fetched discovery and JWKS with it, and the scripted browser loaded `/authorize` from it with no certificate error.
- **Runner:** `scripts/run-test-plan.py [--export-dir D] [--expected-failures-file F] [--expected-skips-file F] <plan[variant]> <config.json>` (options confirmed by a run). `--export-dir` must already exist. From its source, not yet exercised: it exits non-zero on unexpected failures, warnings or skips, and on an expected result that does not occur. An expected failure is an entry with `test-name`, `variant`, `configuration-filename`, `current-block`, `condition`, `expected-result` and `comment`.
- **The suite is built from source (read from its compose files).** Its compose files build the server from a Maven jar, and pin only their `mongo` and `maven` images. Whether a published image exists was not checked. R5's pin follows from this.
- **Browser:** HtmlUnit, not a real browser. Its comment says it "barfs at a lot of modern javascript". Whether `fetch` works there is unverified, so the conformance OP's pages are plain server-rendered forms (R5).
- **Clients:** the Basic plan needs `client` and `client2`, each with a secret, and `oidcc-refresh-token` presents one's refresh token as the other.
**Cross-change:** `release-readiness`'s gate must name the conformance job, which is a change to that change's tasks when this one is planned.

### Standards compliance and security practice

The user asked that the provider comply with the standards it implements and with security practice generally. This section maps each requirement to where the design meets it, so a reviewer can check the specs against it.

- **Labels:** "MUST" and "SHOULD" are the source's own words.
- **Section numbers:** they are given where they were read. Those for RFC 9700 were verified on 2026-11-02.
- **Scope:** an item the provider does not support (implicit flow, ROPC, PAR) is listed under Non-Goals, not here.

#### The authorization request and response

| Source | Requirement | Met by |
|---|---|---|
| RFC 9700 §2.1, §4.1.3; RFC 8252 §7.3; OIDC Core §3.1.2.1 | redirect URIs compared by exact string matching, "except for port numbers in localhost redirection URIs of native apps", where the server "MUST allow variable port numbers" | P1 step [a]: no patterns or wildcards. A native client's loopback IP redirect URI may vary in port only (corrected 2026-11-02, while writing the specs; an earlier draft refused any port variation, which RFC 9700 does not allow for native apps) |
| OIDC Core §3.1.2.6; RFC 6749 §4.1.2.1 | never redirect to an invalid redirect URI | P3 |
| RFC 9700 §4.11.2 | the authorization server must not be an open redirector | P3: errors before validation are not redirected; `post_logout_redirect_uri` is matched exactly too |
| RFC 9700 §2.1.1; RFC 7636; OAuth 2.1 draft-17 §7.5.1.1; ASVS 10.4.6 | PKCE supported; public clients MUST use it; S256 | PKCE with S256 required for every client by default; `plain` refused always. A confidential client may be registered to rely on the nonce (R1) |
| RFC 9700 §2.1.1, §4.8.2 | PKCE downgrade: a `code_verifier` at the token endpoint for a code issued without `code_challenge` is rejected | checked at the exchange, because a PKCE-or-nonce client can hold such a code (R1) |
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
| RFC 6749 §4.1.2, §10.5; RFC 9700 §4.2.4; OAuth 2.1 draft §4.1.3 | codes short-lived, single-use, bound to client and redirect URI; replay should revoke what the code issued | `token/onetime` check-then-consume; the H2 tombstone (decision 5); 60 s by default, at most 10 minutes (RFC 6749 §4.1.2 RECOMMENDED) |
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
| RFC 7009 §2.1 | revoking a grant ends its access tokens; a public client may revoke its own | 5-minute JWTs that the provider's own endpoints refuse once revoked (R4), or opaque tokens (P4); R13 |
| RFC 7662 | introspection is a protected endpoint | introspection requires client authentication; a client sees only tokens issued to it, or access tokens for its registered resource identifier |
| OIDC Core §15.1 | RS256 supported | P8 |
| RFC 8725 | no `none`, algorithm allow-lists, key per algorithm | `token`'s existing jwx allow-list; P8 |

#### Logout, accounts and audit

| Source | Requirement | Met by |
|---|---|---|
| Back-Channel Logout §2.4, §2.5, §2.7, §2.8 | token format; retransmit only for recoverable failures; 200 or 204 is success; refresh tokens without `offline_access` end at logout | sub-decision 2, P1, R14 |
| RP-Initiated Logout §2, §3, §4; ASVS 10.6.2 | ask the user unless a hint belongs to the current OP session; redirect only with a hint and an exact match; not an error when no one is logged in | R3 |
| ASVS 7.4.2 | a disabled account's sessions and tokens end | sub-decision 4 |
| ASVS 10.4.9 | users can revoke an application's access | consent revocation (decision 4) and D12's "revoke application access" (sub-decision 3) |
| Practice | an audit trail of grants, reuse and revocation | security events, `close-security-gaps` D13 |
| Practice | no codes, tokens, handles or secrets in logs | the existing redaction rules apply to every new value; specs pin it |

### Decisions made while writing the specs (2026-11-02)

The specs had to fix values and smaller behaviours that P1 to P9 left open. Each takes the safe side within the standards, and each is pinned by a scenario in the named capability. Values marked *proposed* rest on judgement, not on a researched figure.

| Topic | What the specs fix | Override | Capability |
|---|---|---|---|
| Authorization code lifetime | 60 s (*proposed*), single use | up to 10 minutes, RFC 6749 §4.1.2's recommended maximum | `oidc-provider-authorization` |
| Pending-request lifetime | 10 min (P1, *proposed*) | up to 30 minutes (*proposed*) | `oidc-provider-authorization` |
| ID token lifetime | 5 min, matching access tokens (*proposed*) | per client | `oidc-provider-tokens` |
| `private_key_jwt` assertion lifetime | `exp` at most 5 minutes ahead (*proposed*); `jti` kept until `exp` | up to 1 hour | `oidc-provider-clients` |
| Loopback redirect URIs | a native client's loopback IP redirect URI may vary in port only (RFC 9700 §2.1, RFC 8252 §7.3) | none | `oidc-provider-clients` |
| Token types | first-party `scrty+jwt`, access `at+jwt`, ID `JWT`, logout `logout+jwt`. Every verifier accepts only its own type, with no "any type" option | the first-party value, never one of the other three | `token-issuance` |
| Introspection | a client sees tokens issued to it, and access tokens whose audience is its registered resource identifier; anything else is `{"active": false}` | none | `oidc-provider-tokens` |
| Revoking another client's token | refused with `invalid_grant`, revoking nothing. RFC 7009 §2.1 says the request is refused, and RFC 6749 §5.2 defines `invalid_grant` to cover a grant "issued to another client" | none | `oidc-provider-tokens` |
| UserInfo audience | ~~not restricted~~ superseded by R4: the token's audience must include the issuer | none | `oidc-provider-userinfo` |
| Account disable (sub-decision 4) | realised at refresh and UserInfo. A missing or disabled user is refused, and the refresh also revokes the grant. No separate disable event is needed, since the identity store owns that state | none | `oidc-provider-tokens`, `oidc-provider-userinfo` |
| `offline_access` | consent stage unless the user explicitly consented to `offline_access` for that client before (P2's "ask once"), or the native client is pre-authorized. Consent to other scopes never counts | pre-authorization, native first-party only | `oidc-provider-consent` |
| Endpoint paths | prefix `/oauth2`: `/authorize`, `/authorize/resume`, `/token`, `/userinfo`, `/revoke`, `/introspect`, `/logout`, `/consents` | the prefix and each path | `http-security-chain` |
| Chain logout | revokes the sign-in's grants **before** deleting its sessions. A grant-store failure fails the logout and keeps the session, so the logout can be retried and an online grant is never left behind | none | `http-security-chain` |
| Other ends of a sign-in | family revocation for reuse, ending other sessions, passkey removal and session deletion through the manager also end the sign-in's online grants. A failure there is logged and reported, and never undoes the sessions' end | none | `http-security-chain` |
| End-session endpoint | superseded by R3 | see R3 | `oidc-provider-logout` |
| Back-channel delivery | asynchronous, one attempt with a timeout, failures logged and reported; bounded by R14 | a consumer delivery, such as a retrying queue | `oidc-provider-logout` |
| CSRF exemptions | authorization, token, revocation, introspection and end-session are exempt from `close-security-gaps` D6's cross-site check; resume, the logout confirmation and consents stay protected | none | `csrf-protection` |
| Metadata caching | `Cache-Control` of 1 hour on both metadata documents (*proposed*); `jwks_uri` names the chain's JWKS endpoint, which must be enabled | the cache lifetime | `oidc-provider-metadata` |
| Issuer | `https`, no query or fragment | `http` for loopback hosts only, for tests and the conformance job (P9) | `oidc-provider-metadata` |
| Security events | grant created, consent given, denied or revoked, client authentication refused, code replayed, refresh reused, grant revoked with its cause, logout delivery failed | the sink, as D13 | `security-events` |

**Capabilities added while writing the specs.** `csrf-protection` and `security-events`, both introduced by `close-security-gaps`, gain one requirement each. The proposal lists them.

### Decisions made while writing the tasks (2026-11-02)

Breaking the specs into tasks showed where they say *what* must happen and not yet *how*. Each answer below stays inside the specs and the decisions above, and takes the fail-closed side. All are reasoned from scrty's own settled specs and code, read on `main` at `eb1f22a`, with no new external source.

#### T1. The package is `oidcprovider`, at the module root (decided by the user, 2026-11-02)

- **What it decides:** the core package is `github.com/kartaladev/scrty/oidcprovider`, beside `authenticate/oidc` (the relying party). Its HTTP endpoints live in `httpsec`, as every other endpoint does.
- **Why:**
  - the design's sketches already use the name;
  - it reads unambiguously at call sites (`oidcprovider.New`, `oidcprovider.Client`);
  - an authorization server is a concept of its own, not a login method under `authenticate/`.
- **Rejected:**
  - `authenticate/oidc/provider`: it nests a server under the login methods, and `provider.New` reads vaguely;
  - `op`: it is opaque to readers who don't know OIDC.
- **Import direction:** `httpsec` imports `oidcprovider`, never the reverse. `oidcprovider` holds the protocol's domain logic: validation, clients, grants, stores and token minting. It has no HTTP framework dependency and takes no `httpsec` type.

#### T2. A code's single use comes from `token/onetime`, and its request data from a code record

- **What it decides:**
  - the code's secret, digest and single spend are a `token/onetime` token of purpose `oidc-provider.code`, issued unbound;
  - the request data lives in the provider's code record, keyed by the onetime token's identifier:
    - client, redirect URI, challenge, nonce, granted scopes and resources;
    - the sign-in's family and authentication facts;
    - `dpop_jkt`;
    - the grant family `F` chosen at issue (H2).
- **Why unbound:** a code presented by another client must count as used (`oidc-provider-tokens`). A client-bound onetime check would refuse it *without* spending it.
- **The resulting order at the exchange:**
  1. check the code;
  2. if the client differs: consume, then refuse;
  3. if the redirect URI, the verifier or `dpop_jkt` fails: refuse, leaving the code unspent;
  4. consume;
  5. write the grant.
- **Why not a code store with its own compare-and-set:** decision 2 maps codes to `token/onetime`, which already pins check-then-consume, digest-only storage and concurrent single use across three adapters.

#### T3. The grant row identifies the sign-in it came from, and remembers that the sign-in ended

- **What it decides:** besides decision 5's fields, the grant row records:
  - the sign-in's session family, which is the ID token's `sid`;
  - for a federated sign-in, its upstream issuer and upstream session identifier, as the session recorded them;
  - a sign-in-ended mark.
- **One store operation per kind of end.** Ending a sign-in is a single grant-store operation selected by one of:
  - family;
  - user;
  - user except one family;
  - upstream session;
  - user and upstream issuer.

  (R7: it also records a revocation for each matching unspent code. R2: the provider deletes the matching browser sessions itself, through `DeleteBySignIn`, because they are another store.) It revokes the matching grants without `offline_access` (or every matching grant of a client tied to its sign-in), sets the sign-in-ended mark on every matching grant, and returns only the grants it newly marked.
- **Why:**
  - every way a sign-in ends can be matched to its grants without a lookup `session.Store` lacks. Decision 5 keeps the port unchanged, and an upstream back-channel logout knows only the upstream session;
  - returning only newly marked grants makes "a client SHALL be notified at most once for one ended sign-in" (`oidc-provider-logout`) a store guarantee. The chain's logout and the session manager can both report one end, and the second report finds nothing new to notify.

#### T4. The session manager reports each explicit end of a sign-in, and the chain checks the wiring

- **Shape revised by R16,** to share one option with `session-signals`.
- **The gap:** some ends happen inside `session.Sessions`, where the chain cannot see them:
  - a family revoked for reuse during a renewal;
  - `DeleteByUser` and the other user-wide deletions, called by the consumer;
  - `DeleteByExternalSession` from an upstream logout.

  `WithReuseObserver` exists, but there is only one of it, and it covers reuse only.
- **What it decides:**
  - `session` gains a repeatable `WithEndObserver(EndObserver)`. The observer is told after each explicit end through the manager, with the cause, the user, and the family or upstream session when known:
    - reuse revocation, `RevokeFamily`, `Delete`;
    - `DeleteByUser`, `DeleteByUserExcept`;
    - `DeleteByExternalSession`, `DeleteByUserAndExternalIssuer`;
    - `EndSignIn` and `EndOtherSignIns`, `close-security-gaps` D12's.
  - Expiry and sweeping are never reported.
  - `*oidcprovider.Provider` implements `EndObserver`, and `(*session.Sessions).ReportsEndsTo(EndObserver) bool` reports whether a manager was built with it.
- **Fail closed at construction:** `httpsec.EnableOIDCProvider` refuses a chain any of whose session managers does not report to the enabled provider. Forgetting the wiring would otherwise leave online grants alive after logout, silently (`library-design` rule 6).
- **Two kinds of call:**
  - **The chain's logout** calls the provider *before* deleting, so a grant-store failure can fail the logout (`http-security-chain`).
  - **The manager's report** comes *after* the store write. Its failure is logged and reported as an event, and never undoes the end.
- **Settled while building it (2026-11-04):**
  - **A write that matches nothing is still reported.** `Delete` and `DeleteByUser` return no count, so the manager cannot tell. `SignInsEnded` must therefore accept a repeat, which T3's "newly marked" guarantees, and a report naming nobody, which it ignores.
  - **An upstream delete with an empty issuer or session is not reported.** Its contract says it ends nothing, and `{User: u}` with no issuer could read as all of `u`'s sign-ins.
  - **`EndDeleted` ends the family's grants.** `Delete` removes one record, so during a renewal window the family's successor can outlive it. The provider cannot tell, since decision 5 keeps `session.Store` without a family lookup. Ending the grants costs at most one more login, and leaving them would keep online grants alive after an explicit delete, so the safe side is to end them. With no family known, as for a session already expired or gone, no grant can be matched, and the provider logs that.
  - **A nil `KeptFamily` spares nothing.** It is nil when the kept session could not be read: expired, another user's, or a failed read. The provider then ends all of that user's online grants. A sign-in it should have spared must log in again, which is the safe mistake.
  - **On reuse, end observers run before `WithReuseObserver`.** A panic in the reuse observer still propagates, as it did before.
  - **Raw stores do not report.** `authenticate/mfa` reset and the `passkey` revoker (`clone.go`, `manage.go`) accept anything with the store's method, so a consumer can hand them a `session.Store`, which ends sessions with no report that `ReportsEndsTo` could see. Sub-decision 4's grant ports cover MFA reset and clone detection. Lane H4 checks the `manage.go` path when it wires them (task 11.x).
- **Rejected:**
  - asking the consumer to remember to wire an observer, with no check;
  - a chain-side wrapper around the session manager, which would miss calls the consumer makes on the manager directly.

#### T5. The flow cookie carries its own secret, not the handle

- **What it decides:** the flow cookie holds a separate 256-bit random value. The pending request stores only its digest, and a resume or a read must present both the handle and the matching cookie. One browser keeps one value across its parallel requests (R9).
- **Cookie attributes:** the name carries the `__Host-` prefix, which needs `Secure` and `Path=/` and no `Domain`, beside `HttpOnly` and `SameSite=Lax`.
- **Why:**
  - the handle travels in URLs (the login and consent pages' query), so a leaked URL must not also carry the browser binding;
  - `__Host-` stops a sibling subdomain from planting the cookie.

#### T6. Credential formats are distinct by prefix

| Credential | Format | Stored as |
|---|---|---|
| refresh token | `rt.<family>.<secret>` (decision 5) | digest of the secret, in the lineage |
| opaque access token | `at.<id>.<secret>` | digest |
| pending-request handle | `rh.<id>.<secret>` | digest |
| authorization code | the `token/onetime` string (T2) | digest |

- **Why:** none of these passes `session.ValidIdentifier`, and none can be mistaken for another, so each verifier refuses the others' values before any lookup (C10).

#### T7. The lineage store is a type only the adapters can build

- **What it decides:** `oidcprovider.RefreshTokenStore` is a struct whose only field is unexported. The SQL adapters build it through a scrty `internal` package, over a session store bound to the fixed `op_refresh_tokens` table. The in-memory default is a private `session.MemoryStore` inside the provider.
- **Limit:** package `unsafe` can still fill the type, as it can any Go type, and the godoc says so.
- **The default's sweep:** the private `session.MemoryStore` only sweeps once started, and the provider has no lifecycle, so a wrapper sweeps on `Create` and `Supersede`, at most once a minute, by the same rule `Load` applies.
- **Why it holds across modules:** Go's `internal` rule is path-based, so the nested adapter modules can import it and a consumer cannot. That is decision 5's guard 1 made structural: no exported function turns a sign-in `session.Store` into a lineage store.


- **What the adapters settled.**
  - **Binding.** `sqlstore` and `pgxstore` bind a handle in `conn`. `gormstore` binds at the connection, with `lineagePool` on `Statement.ConnPool`, because its session statements come in two kinds, `pgschema`'s text and what gorm builds from its model, and a connection sees both as the text the server is sent. Each adapter's suite now runs a lineage inside a caller's transaction, by `WithTx` and by a resolver.
  - **Direct statements in `gormstore`.** The provider stores run `pgschema`'s text on `Statement.ConnPool`, because gorm's `Exec` reads `@>` as a named argument. That path skips gorm's processor, so the stores apply for themselves what it would give:
    - **The default:** with `gorm.Config.DefaultContextTimeout` unset, nothing changes.
    - **The override:** set, it bounds each statement, by the configuration of the handle the operation resolved to, and a context with its own deadline wins, as with gorm. A store's own BEGIN and COMMIT are not bounded by it; `DefaultTransactionTimeout` bounds the whole transaction, and a context deadline bounds the call.
    - **`DryRun`:** a handle in that mode runs nothing, and is answered `gorm.ErrDryRunModeUnsupported`.
  - **Row reads in `gormstore` (`REPRODUCED` 2026-11-04, then fixed).** Under `PrepareStmt: true`, a failed prepare made `Row().Scan` panic, at every row read in the package, including older ones. Reads now go through `Rows()`, which stays on gorm's processor path and returns the failure. They keep `Row.Scan`'s contract, including the error from closing the rows, because a `RETURNING` write outside a transaction can fail its commit only there, which would otherwise report a charge that was rolled back.

#### T8. Grant revocation on security events is a one-method port in each package that needs it

- **What it decides:**
  - `recovery`, `authenticate/mfa` (`ResetDeps`), `authenticate/passkey`'s clone path, and the password-change gate each declare a one-method port for revoking a user's grants with a cause;
  - `*oidcprovider.Provider` satisfies all of them;
  - when the port is supplied, revocation is the default, and an option per package keeps grants (sub-decision 4). The chain supplies the provider to its own endpoints when it is enabled.
- **Why:** none of those packages imports `oidcprovider`, so no import cycle can form, and each states its own default and override (`library-design`).

#### T9. The code exchange writes the grant row first, then the lineage, without a cross-store transaction

- **What it decides:** this departs from decision 5's "one transaction through each adapter's `WithTx`". The exchange writes the grant row first, keeping any tombstone, and the lineage second. No transaction port joins the two stores.
- **Why it is safe in every interleaving:**
  - a failure between the two writes leaves a grant row with no lineage. The client got an error and holds no refresh token, a refresh on it would read as revoked (H4), and the row stays until its deadline (R19);
  - a replay that lands between the two writes marks the grant row revoked. The lineage then created is unusable, because every refresh reads the grant row first (decision 5, step [2]);
  - a lineage can never exist without its grant row, which is the state that would fail open.
- **Why not a transaction:** it would need a transaction port across stores that consumers may supply separately, and adapters that share one database handle. That buys nothing the order does not already guarantee.

### Decisions from the refresh (2026-11-04)

The user asked for this change to be refreshed against #68, reconsidered for scenarios and edge cases it missed, and checked against the standards and security practice, ahead of #68 finishing. Reading the conformance suite's source showed that the design could not meet its own gate. Everything else below came from reading the settled specs, the code at `501a1a6`, and the standards again.

R1, R2, R3, R4's audience rule and R5's added plans reverse or widen something the user decided on 2026-11-02. The user accepted each on 2026-11-04 (see "Open Questions"). The rest correct a mismatch with a standard, or with scrty's own code, and take the safe side. Every defect named here is `UNREPRODUCED`, since no provider code exists. Each is the red step of the task that names it.

#### R1. PKCE stays required by default, and a confidential client may rely on the nonce (decided 2026-11-04)

- **The problem.** Every Basic OP module but one, `oidcc-ensure-request-with-valid-pkce-succeeds`, sends no `code_challenge`, and the suite does not adapt. Its own summary says "OpenID Connect does not require servers to support PKCE". An OP refusing such a request fails each module at `CheckIfAuthorizationEndpointError`. So "PKCE for every client, no option" and "the defaults pass Basic OP" cannot both hold.
- **What the standards allow.** RFC 9700 §2.1.1: public clients MUST use PKCE, it is RECOMMENDED for confidential clients, and "confidential OpenID Connect clients MAY use the nonce parameter". OAuth 2.1 draft-17 §7.5.1.1 agrees: required unless the client is confidential and the server has reasonable assurance of the nonce. ASVS 10.4.6 requires PKCE outright, so using the option gives that level up.
- **The decision.** The default is unchanged. A client setting `PKCEOrNonce`, for a confidential client only, accepts a request carrying a challenge or a `nonce`, and refuses one carrying neither. The exchange now has to check the downgrade itself (RFC 9700 §4.8.2), since a code without a challenge can exist.
- **The cost at conformance.** `oidcc-ensure-request-without-nonce-succeeds-for-code-flow` sends neither, so it fails under this setting. It is recorded as an expected failure (R5), and R26 records the suite's other expected results. A later official certification would need to settle it with the Foundation: whether certification accepts it was not checked.

| | Default | Override |
|---|---|---|
| PKCE | required for every client | `PKCEOrNonce`, confidential clients only; refused at construction for a public client |
| `plain` | refused | none |

**Rejected:**
- *PKCE optional for confidential clients, with no nonce needed.* It passes every module, but leaves a request protected by `state` alone, below what RFC 9700 asks for.
- *Skipping PKCE in the conformance OP through a test-only hook.* It would test something other than what ships.
- *Dropping Basic OP from the gate.* It is the only external proof of the protocol (decision 1).

#### R2. The provider keeps a browser session of its own, delivering single sign-on in v1 (decided 2026-11-04)

- **The problem.** `oidcc-prompt-none-logged-in` and `oidcc-id-token-hint` send `prompt=none` after a successful login in the same browser, and `CheckIfAuthorizationEndpointError` fails them on `login_required`. `oidcc-max-age-10000` requires the same `auth_time` on the second pass, which a forced fresh login breaks. The suite's browser keeps cookies across the two requests, so a cookie is what they test. OIDC Core §15.1 lists `prompt`, "including none and login", as mandatory for every OP. So "`prompt=none` cannot succeed in v1" fails the gate, and P9's green run could never happen. RP-Initiated Logout's MUST, below, needs the same knowledge.
- **The decision.** After a login stage resumes, the provider sets a `__Host-` cookie holding a new 256-bit secret, with the digest in a provider table beside the user, the sign-in's family and its authentication facts.
  - **What it does:** `/authorize` skips the login stage on a valid session, unless `prompt=login` or `max_age` demands otherwise; `prompt=none` answers from it, with `consent_required` where consent is missing.
  - **How long it lasts:** it never outlives the sign-in as far as the provider can tell. It takes the sign-in's absolute deadline, and the manager's `IdleTimeout()` without use. `Session` activity elsewhere does not extend it, which errs short. T3's end operation deletes it.
  - **What it cannot do:** the consent stage may answer from this cookie, since a browser that skipped the login page holds no credential. So CSRF protection becomes a construction requirement. It does not issue first-party credentials, and it is read only by the provider, so it never passes `session.ValidIdentifier` or reaches a sign-in path.
  - **What it does not see:** a marker placed on the sign-in afterwards, such as a required password change, because `session.Store` has no family lookup (decision 5). An admin's forced change that matters ends the sign-in, which reaches it. Stated in the godoc.

| | Default | Override |
|---|---|---|
| Browser session | on | `WithoutBrowserSessions`: every request shows the login page, `prompt=none` always answers `login_required`, every logout asks. The godoc says this fails Basic OP |
| Lifetime | sign-in's absolute deadline; the manager's idle timeout | none in v1: the sign-in's own timeouts are what the consumer sets |

**This moves a Non-Goal into scope, as the user accepted on 2026-11-04.** Single sign-on was a follow-up waiting on `bff-resource-server`'s cookie session. That change is stalled on open questions, and this session is much smaller than it: one cookie, one table, read only at provider endpoints.

**Rejected:**
- *Waiting for `bff-resource-server`.* It blocks the tag on a change with open questions.
- *Expected failures for the three modules.* It keeps v1 small. But a provider that never answers `prompt=none` is not meeting §15.1 in spirit, cannot do SSO, and must always ask at logout.
- *Reading the sign-in from the session store by family.* It would change `session.Store`, which decision 5 keeps unchanged.

#### R3. End-session asks the user unless a hint names the browser's own sign-in (decided 2026-11-04)

- **The problem.** The spec ended the sign-in on any valid hint, with no question. RP-Initiated Logout §2: the OP "MUST ask the End-User this question if an id_token_hint was not provided or if the supplied ID Token does not belong to the current OP session". The endpoint is also exempt from CSRF, and takes GET, so anyone holding a user's ID token, expired ones included, could end their sign-in and online grants (ASVS 10.6.2's forced-logout denial of service). The first version had no session to compare with. R2 gives it one.
- **The decision.**
  - A valid hint whose `sid` names the browser session's sign-in ends it at once. RP-Initiated's general SHOULD ask is not followed here, as Duende's default does not, and ASVS 10.6.2 accepts validating the hint. `WithLogoutConfirmation` asks every time.
  - Anything else parks the request under a handle and sends the browser to the consumer's logout page, which answers through `/logout/confirm`. A confirmation ends the browser's own sign-in, never the one a hint names, so a hint held elsewhere ends nothing. With browser sessions off, a confirmation ends what a valid hint names, because nothing else identifies it.
  - A hint failing under a key still published is a 400 with no redirect (§4). One signed by a retired key counts as none (R6).
  - Post-logout redirect needs a valid hint and an exact match. `client_id` alone is not enough: §3 forbids it without other means of confirming legitimacy, and the suite fails a redirect with no hint.
- **What it costs.** One more required URL, one more endpoint, and a page the consumer writes.

**Rejected:** *Keeping no confirmation.* It breaks a MUST.

#### R4. UserInfo requires the issuer in the audience, and access tokens name their grant (the audience rule decided 2026-11-04)

- **The audience.** The spec-time table let any audience in. OIDC Core §5.3 is silent, but RFC 9068 §4 says a resource server "MUST validate that the aud claim contains a resource indicator value corresponding to an identifier the resource server expects for itself". UserInfo is one. Under the old rule, any API receiving a token could replay it at UserInfo for the user's claims. The suite does not test this.
  - **Default:** an `openid` token with no `resource` request carries the client's default audience plus the issuer, as Auth0 is known to do (not re-read on this date). An explicit `resource` gets exactly what was asked for, and a client wanting UserInfo may also ask for the issuer. No override, as RFC 9068 §4 is a MUST.
  - **The cost:** a default-audience API can still replay at UserInfo. Sender-constraining closes that (P6). A client with an explicit `resource` and no issuer loses UserInfo, by choice.
- **The grant reference (correction).** The specs promised a revoked token is refused at UserInfo and inactive at introspection, but a JWT named no grant to check. Access tokens now carry `gid`, the grant's family identifier, which is not a secret. It closes `oidcc-codereuse-30seconds`'s warning too. Offline verifiers are unaffected: P4's 5-minute bound still applies to them.

#### R5. The gate runs the logout plans too, in `split-ci-jobs`' shape (the added plans decided 2026-11-04)

- **Plans.** Basic OP and Config OP as before, plus RP-initiated logout and back-channel logout, because v1 ships both and the Foundation's suite tests them (the suite's own CI runs them against its reference provider). The added plans cost CI time, not yet measured, and the user accepted that on 2026-11-04.
- **The job.** A `make conformance` target and a `conformance` job, in the shape `split-ci-jobs` set (#68): the job calls the target a contributor runs, the target is outside `make check`, and `ci-ok` requires the job. The suite is pinned to a full commit hash, because it is built from source, and the images the job names are pinned by digest for `pincheck`. This corrects the first wording, which assumed a suite image.
- **The server.** `https` on a self-signed certificate, because the Config plan refuses `http`. The loopback `http` issuer stays for unit tests, without the `__Host-` prefix, which needs `Secure` (R9).
- **The pages.** The conformance OP serves plain server-rendered forms that resume through the provider's Go API, because the suite drives HtmlUnit. It configures `client` and `client2`, both with PKCE-or-nonce (R1), and users holding profile, email, phone and address claims so the scope modules have something to check.
- **Expected results.** The expected-failures file holds one entry, `oidcc-ensure-request-without-nonce-succeeds-for-code-flow` (R1). The runner fails if it stops failing, so it cannot go stale. Anything else found by task 14.3 is fixed or brought back as a decision, never added silently.

#### R6. What #68 changes for the provider

- **`sub` is always the user identifier.** `pre-release-api-fixes` says an OP's `sub` must never be reassigned, and then offers username modes. So the mode must not reach the provider: `sub` in every provider token is the grant's user identifier, on a chain reading usernames too.
- **The provider takes a key source, not a generator.** `oidcprovider.New` takes `signingkey.KeySource` through the required `Deps.Keys`, which P1's sketch omitted, and builds its own `token.Issuer`s, one per algorithm and over the provider's issuer. Consequently: a username-mode generator cannot reach it, an issuer mismatch cannot be wired, and `token.Generator`, already gaining a required method in #68, gains no other. Task 2.3's typed issue moves from `Generator` to `Issuer`. The chain's subject check needs no tenth route. *Rejected:* an optional interface on `Generator`, as `ConfirmingGenerator` is, because the consumer's generator would still carry a mode.
- **Per-client lifetimes meet the key cap.** A token lifetime above key lifetime minus rotation (23 hours by default) would be refused by `token` for a generator. The issuer applies the same, and construction names the client. A consumer's durable registry is checked as each client is read (R13).
- **Retired keys and old hints.** Core §3.1.2.2 says the OP SHOULD accept expired hints for a recent session, but the provider can verify only what it still publishes: by default, a key is published until about 24 hours and 1 minute after its creation, so a hint stays verifiable for about 23 to 24 hours after it was issued. A rotation outage lengthens that. An old hint cannot be judged, which is different from forged, so it counts as no hint (or `login_required` with `prompt=none`). At logout that means asking. *Rejected:* verifying against keys kept until the store deletes them, which would need a port for it and buys one more key lifetime.
- **A sign-in with no identifier.** #68 makes a login with one fail matching `token.ErrNoSubject`. The resume does the same, for a session stored before that or by a consumer's own path, and issues no code.
- **A session only a late renewal may recover** is not a sign-in that can resume. #68's `admit` passes such a session on for the renewal endpoint only.
- **Cross-check.** A JWKS provider that is the same manager as the key source can be checked at construction. A wrapped one cannot, and the godoc says so, as #68 does for wrapped verifiers.
- **What `token.Issuer` settled while being built (2026-11-04).**
  - **It issues everything but the first-party type.** `Issue.Type` equal to `TypeFirstParty` is refused, so an issuer cannot stand in for a generator with its subject mode.
  - **Options.** `NewIssuer` takes `WithTokenLifetime` and `WithClock`, with the generator's 15-minute default, and refuses every other `Option`, since a generator's alg, subject mode or type would mean nothing there.
  - **Further refusals.** `aud` as a further claim, because it would silently override `Issue.Audience`, an empty `Issue.ID`, and a `cnf` that `WithConfirmation` would refuse, because it would mint a token `Verify` refuses.
  - **Comparison.** `typ` folds ASCII letters only, so `applİcatİon/scrty+jwt` is refused.
  - **Tokens issued before this change** carry `typ: JWT` and are refused. Nothing is tagged yet, so this needs no migration.
- **Background work.** #68's `signingkey` treats a store call cut off by `Shutdown` as no failure, and `notify` replaces a worker whose delivery ends its goroutine. Back-channel delivery follows both (R14).

#### R7. An outstanding code does not outlive the sign-in or the user's grants (H5)

- **The gap.** `EndSignIn` and `RevokeUserGrants` act on grant rows, but a code issued before they ran has no row yet. So a logout, recovery or MFA reset followed within the code's lifetime (60 s by default, 10 minutes at most) by its exchange creates a live grant after the event meant to end it. `UNREPRODUCED`.
- **The decision.** Both operations also record a revocation for family `F` of each matching unspent code, reusing the H2 tombstone: the exchange reads it and answers `invalid_grant`, and if it races, the grant is stored revoked. Logout spares codes holding `offline_access`, as it spares such grants, unless the client is tied to its sign-in, which the code record states as `EndsWithSignIn`. The code record adds the upstream issuer and session, for T3's selectors. No override, because it only carries the existing decisions to a case they missed.
- **Also.** The exchange reads the user, as a refresh does, so a user disabled within those seconds gets no grant.
- **Settled while building the stores (2026-11-04).**
  - **"Unspent" means still held.** The spend lives in `token/onetime`, so a code store lists every unexpired record. That over-reaches harmlessly: a spent code's grant matches the same operation, and tombstones are swept.
  - **An end's tombstone carries the sign-in-ended mark, and `Create` over it keeps the revocation and the mark,** so a racing exchange cannot make a client be notified twice. A plain revocation carries no mark.
  - **Joining.** `GrantStore.UseCodes(UnspentCodes) error` joins the two stores from `New`. A different code store is refused, because replacing it would silently break the first provider's revocations. Two providers may share both stores.
  - **`Create` is refused over a stored grant, and only fills a tombstone.**
  - **No default store grows without bound, and none needs a consumer to sweep it.** The provider's defaults for lineages, code tokens and assertion identifiers sweep on write, at most once a minute, by the provider's clock.
  - **Browser sessions.** `Put` refuses a digest already held, an empty digest or a zero deadline, and lowers an idle deadline past the absolute one. `Touch` only extends, by one conditional write. `WithBrowserSessionStore` with `WithoutBrowserSessions` is a configuration error.
  - **`AccessTokenStore.Revoke` answers `ErrNotFound` for a missing token,** which the provider maps to success (task 7.6, RFC 7009).
  - **The schema (task 12.1).**
    - `op_clients`, `op_consents`, `op_client_assertions` and `op_browser_sessions` have a uuid key with no default plus a unique natural key, as the settled spec requires, so adapters mint the uuid.
    - In `op_grants`, a NULL `created_at` marks a tombstone. An adapter writes a stored grant's time even when it is zero, never NULL, and the suite pins a second `Create` being refused over such a grant.
    - `holds_lineage` defaults to false, as the memory store's tombstone has it, and `Create` writes it explicitly.
    - `max_age` is `bigint`, and lists and maps are `jsonb`, as on sessions.
  - **Text a request can carry.** PostgreSQL refuses a NUL byte or invalid UTF-8 in text and jsonb, and the memory store accepts them, so a request carrying them would answer 500 only on durable stores. The authorization request refuses them as `invalid_request` before anything is parked.
  - **A `jti` over 1024 bytes is refused as `invalid_client`** before the store, because a unique index has a row-size limit (`index row size 3016 exceeds btree version 4 maximum 2704`). The bound is a proposed value.
  - **One lock order across every bulk write (`REPRODUCED` 2026-11-04, then fixed).** `RevokeByUser` and `EndSignIns` took rows in opposite orders, and PostgreSQL aborted one with `40P01` in 91 of 150 rounds, with no injected blocker, so a revocation or an end could be lost. Every statement taking more than one `op_grants` row now takes them in ascending `family` order, with stored grants and tombstones as one stream, because an `ON CONFLICT` on a new key waits like a row lock. `pgschema.GrantBulkWrite` is a Hold, an `INSERT ... SELECT ... ORDER BY family ON CONFLICT DO UPDATE ... WHERE false`, and a Write over the set it took. A re-review confirmed on PostgreSQL 15 and 18, under six plan settings, that suppressed rows are locked and in order. No retry and no advisory lock, since this holds. *Limit:* a consumer's own transaction that has already written a later family can still deadlock, and gets `40P01` to retry.
  - **A grant stored while an end waits.** A grant with no held code, stored during an end's Hold, is left for the next end. The provider never stores one, since each grant comes from an exchange whose code is held.
  - **A code's record is swept a minute past its expiry,** as tombstones are, because an exchange in flight can otherwise lose the record an end needs in order to reach its grant (`REPRODUCED` at store level).
  - **`Advance` moves strictly forward:** login, consent, done, with login to done allowed. Nothing leaves done, and a logout request moves only to done.
  - **What no store can close:** a code created after `EndSignIns` has listed the codes. No store can, and the chain closes it instead, with a check after the resume's writes (R26).

#### R17. Replay detection: valid requests only, for a stated window

- **The gap (`REPRODUCED` 2026-11-04, by `TestProvider_CodeReplay` rows added with the fix).** The spec promised that a replay revokes, with no limit and no condition. The default stores forget a spent code at its expiry, so a replay soon after 60 seconds revoked nothing. And any replay revoked, so a wrong verifier, or another client, could end a grant while holding only a leaked code.
- **Revocation needs a valid request.** A replay revokes only when it comes from the client the code was issued to, authenticated, with the code's redirect URI, verifier and key binding holding. OAuth 2.1 §7.5.3 names the alternative as a denial of service. An invalid replay is still `invalid_grant`.
- **Detection lasts until at least a minute past the code's expiry.** The user chose this over keeping spent codes for a day or for the grant's lifetime. Both of those store a row per exchange, to detect a replay of a code that can no longer yield tokens, and they lengthen the time a leaked public-client code and verifier can end a grant. RFC 6749 §4.1.2 asks for revocation "when possible". The default token store and record store therefore both sweep a minute past expiry, matching the durable stores' tasks, and past that a valid replay is `invalid_grant` with nothing revoked. What is lost is a compromise signal, not protection.
- **The default and the override.** The minute is a floor stated in the spec, not an option. A consumer's own code stores may retain spent codes longer, and detection then lasts as long as they hold them. Both stores must retain together, and a consumer sweeping its own stores gives up the floor if it sweeps sooner than a minute past expiry, which `CodeStore`'s and the options' godoc state.
- **Limits accepted with it:**
  - **A spend failure's cause stays in the log.** A failure at the check or the spend is a dependency failure wrapping fixed text, not the store's error, because `token/onetime` keeps that from its caller and logs its type at ERROR. Recording it per request would add a decorator for a cause already logged.
  - **A store hung past the request's own deadline logs at DEBUG.** `token/onetime` now asks `hangup.ByCaller`, as every other path does, and a context past its deadline is a hang-up by that rule. Under per-request deadlines, a hung store therefore shows nothing at default log levels from this path, and a magic link or recovery token is still answered as invalid. Treating only a cancellation as a hang-up here would make this path disagree with the others, so changing it belongs to the rule as a whole.
  - **A code store needs read-your-writes.** A lost spend that reads back as unspent answers 500 rather than a refusal and revocation, until the code is presented again. It fails closed (`UNREPRODUCED`, no such store exists).
- **Options left for later.** None is in v1. Each can be added after a tag without breaking a consumer, because each only lengthens detection or adds a signal, and the spec's minute stays a floor:
  - **A retention option,** for example `WithSpentCodeRetention`, defaulting to the minute. It keeps spent codes for a period the consumer chooses, and fits a deployment that wants the compromise signal for a day. It costs a row per exchange for that period.
  - **Retention for the grant's lifetime.** The same option with the grant's lifetime as its value, up to 90 days by default. It honours the spec's first wording, for the highest storage.
  - **A compact spent-code record.** It holds the token identifier, a secret digest, the client and the grant family instead of the whole record, so long retention stores less. It needs a store contract and a migration, so it fits only alongside one of the above.
  - **What would reopen this:** a consumer asking for the signal, a conformance or certification requirement on late replays, or a final OAuth 2.1 that requires more than draft-17 does.

#### R18. Tokens are signed before the code is spent

- **The gap.** Signing after both writes would burn the code on a key failure, and leave a live grant and lineage nobody holds.
- **The order.** Signing has no side effect, so it joins the refusal checks, and the spend stays last among them, as every one-time credential in scrty does. The exchange judges `resource`, mints the JWTs for the grant family the code already names, then spends, then writes the grant row and the lineage in T9's order, and only then stores an opaque access token. A key failure is a dependency failure with the code unspent, and the client may retry.
- **What it costs.** Two racing exchanges both sign, and the loser discards its tokens unreturned. Reaching that needs the client's authentication and the code's bindings, so an outsider cannot use it to spend signing work. A store failure after the spend still burns the code and leaves records nobody holds. They fail safe, as no token was returned.
- **The default and the override.** This is an order, not a policy, so there is no option. Reasoned from scrty's own settled specs and the established design.
- **Limits accepted with minting:**
  - **A token can outlive its grant at a resource server.** `exp` is `iat` plus the lifetime, as the spec fixes, and `expires_in` matches it, even when the grant or sign-in ends sooner. The provider's own endpoints refuse it from that moment, while a resource server verifying offline accepts it until `exp`. Short lifetimes are what bound that, as for any self-contained token.
  - **A very large registered audience.** The verifier's size bound follows the request bounds, so a client registering audiences totalling tens of kilobytes would get tokens the provider's own endpoints refuse. It fails closed, and needs a configuration no real client has.

#### R20. A re-presented refresh token answers the same successor

- **The gap (`REPRODUCED` 2026-11-04).** Two requests presenting one token inside its grace both received tokens, as the Review Focus asks, but the second re-rotated, knocking out the first's token. With shared storage, whichever write landed last decided: if it kept the knocked-out token, the next refresh read as reuse and revoked the grant. Under simulated timing that was 26% to 47% of pairs starting together, and 0.3% to 38% at 5 ms apart. The jitter is a model, not a browser measurement.
- **The decision, by the user.** A successor secret is `HMAC-SHA256(key, family, presented secret)`, not random. Re-presenting a token within 10 seconds of its rotation derives the same successor, finds its digest already stored, and answers it with no write, walking to the head if that successor has rotated too. One head remains, and with the chain still, whichever tab's write lands last holds a live token. After the window, inside the grace, a re-presentation re-rotates with a random successor, as a lost response always could.
- **Why a window, and not the whole grace (`REPRODUCED` 2026-11-04).** The same successor removes the divergence reuse detection relies on. Across the whole grace, a thief staying within a grace of the victim was never caught: 200 cycles over 16h40m with a 5-minute grace fired nothing, and it would last to the grant's absolute lifetime. No test can tell such a thief from a second tab. A short window keeps the fix, because the race had faded to 0% by 100 ms in the measurements, and a tab with shared storage already holds `r2` after that. A thief must now land within the window on every cycle, and one miss diverges and fires detection. That is harder, and not impossible, and it matters most to a public client without DPoP, which relies on rotation (RFC 9700 §2.2.2). Rejected by the user: the whole grace with this limit stated; and no same successor at all.
- **Why a key.** Deriving with no key would let anyone holding a stale token compute its live successor, with no presentation for reuse detection to see. Under the key, a successor can only be had by presenting the token to the provider. So a leaked key is as serious as that: its holder can compute the live head from any past token, offline, and nothing fires.
- **The default and the override.** The default key is 32 bytes drawn once in `New`, which needs no configuration and fits the memory stores. A source that cannot supply them fails `New` with `ErrConfig`, as a provider must not degrade silently. `WithRefreshSuccessorKey` supplies at least 32 bytes shared across replicas, and replaces that default. `WithRefreshSuccessorWindow` replaces the 10 seconds, a proposed value reasoned from the measured race and not from a standard. It is at most `session.MaxRenewalGrace`, a client's grace still bounds it, and zero turns the same successor off.
- **The limit, stated.** With no shared key, or after the key changes, a replica derives a different successor, finds no match, and re-rotates with a random one, as deriving again would collide with the record it knocked out. Two tabs on mismatched replicas therefore do not converge. That is no worse than without this decision, and refusing to build cannot be right, as a provider cannot know how many replicas it has. `seal.Cipher` cannot supply the key, because it only seals, and should give a different value each time.
- **How far it reaches.** Only a record's first rotation derives, so a re-rotation can never collide with a derived identifier already stored. The window is half-open, ending at exactly its length, as the grace does. A walk follows the chain while each link is inside its window, carries this key's digest, and has a successor inside its grace, and it stops at 8 links, a proposed value. Past those, nothing is answered from the chain, and the re-rotation reads as reuse. With the window at zero nothing derives, so no key is drawn, a source that cannot supply one then builds, and supplying a key is refused at construction as a contradiction. A rotation `SupersededAt` ahead of the provider's clock is judged by the size of the difference, so replicas a little apart still converge, and one lagging by the window or more does not stretch it.
- **What it does not change.** A token presented past its grace still revokes the grant. So does one presented after the window whose successor has already rotated, even inside its grace, as `session` has always judged it: a stale tab can reach this, and only the window softens it. A tab keeping a private copy after the other has rotated and the grace has passed cannot be told from a thief, under any design. A stale tab re-presenting after the window can still knock out a token, as before this decision.
- **Our own design.** The vendors consulted tolerate reuse in a window, and none documents a deterministic successor. Also rejected: keeping the knocked-out token valid inside the grace, which changes `session`, the memory store, three adapters and conformance, and still fails when the next refresh comes after the grace, as it usually does with 5-minute access tokens; and accepting the limit, which leaves browser clients to serialize their refreshes.
- **Options left for later.** Deriving the key from a consumer's key management service, or several live sibling tokens per head, can be added without breaking a consumer.

**Other limits accepted on the refresh path:**

- **A token's own idle deadline still rules (`REPRODUCED` 2026-11-04).** `session` judges a superseded record's stored idle deadline, so a presentation inside the window or grace that also falls past that deadline is refused, with nothing revoked. A retry or a second tab loses out there, and a thief who rotated just before it is not exposed until the token is presented again past the grace. It needs a client dormant for about the idle timeout, 30 days by default. Changing it would change `session`'s contract for every consumer.
- **A slow user load gets no verdict.** A record re-read before rotating that is superseded and past its grace answers a dependency failure, not reuse, as the token was presented in time. That narrows the gap and does not close it, because the read and the rotation are still apart. It costs one read per rotation.
- **A response can be overtaken.** The head can move during a walk's read, so a tab is answered a token that is good inside its window, and is reuse past its grace. No re-read closes that, as any response can be overtaken in flight.
- **A failed second read after rotating fails closed.** The client can retry inside the grace. A false reuse alarm needs an outage outlasting the grace, and answering tokens on an unread grant row would be worse.
- **The memory stores hold refresh identifiers in process memory.** Only a durable store is held to storing digests, and a process's memory holds the secrets while handling them anyway.
- **`refreshAttempts` is 8, with no override.** Past it the answer is a dependency failure and nothing is revoked. With a shared key, racers converge on one successor, so only rotations that keep conflicting reach it, such as under mismatched keys. Only a token holder can reach it, and a retry inside the grace works. The value is proposed.
- **A refresh stores an opaque token first.** Unlike the exchange (R18), a refresh stores it in the signing step, before the rotation's write, so an access-token store outage cannot burn the presented token and raise a false reuse alarm at a retry past the grace. Any error answer then revokes that one record, detached, and a failure of that is logged.
- **Reuse marks the grant row first.** A reuse the provider judges itself marks the row, then deletes the family, so a failed mark answers a dependency failure with the lineage intact, and presenting the token again retries. A reuse the manager finds on the re-rotation path deletes first, and only the observer marks the row. If that write fails it is logged: the grant reads as revoked at every refresh (H4), but its opaque tokens stay valid until their own expiry, as nothing is left to present. In practice that needs mismatched keys and a failing store together.

#### R21. What ending, revoking and claims settled

- **A disabled user's refresh marks the row first (`REPRODUCED` 2026-11-04).** Deleting the family when the mark failed left nothing to retry through: the next refresh was refused before it could mark the row, and access tokens read as live until they expired. A replayed code keeps its old order, because it can retry through the code record.
- **A first-party client's grants can be ended (`REPRODUCED`).** Such a client skips consent, so requiring a remembered consent left a user no way to end one client's grants, short of every client's. The refusal now needs neither a consent nor a grant.
- **A resource server's identifier cannot be the issuer (`REPRODUCED`).** The issuer is in every default-audience `openid` token, so that value would show a client nearly every token at introspection. `ResourceIdentifier` must be an absolute URI with no fragment, not the issuer, on a confidential client, or the client fails construction.
- **Ending a sign-in budgets each store on its own (`REPRODUCED`).** A hanging grant store would otherwise spare the browser sessions, and nothing retries an observer. The grant store, the hand-on and the browser delete each have 10 seconds, so hanging stores can delay a logout's answer by up to 20 seconds, and its success is unaffected.
- **Empty claims (OIDC Core §5.3.2).** A null or an empty string is omitted. Any other value of a consumer's stays, as a consumer's `groups: []` is its own (`library-design` rule 5).
- **The default claim source reads an email from the username, decided by the user.** `identity.Details` holds no email, and the default stores discard one by a settled decision. A username that is exactly an email address is released as `email`, as recovery's contact resolver already defaults to the username, and just-in-time provisioning uses the email as the username.
  - **`email_verified` is always false from this source.** A username proves nothing about who controls that address, even for a just-in-time user whose upstream proved it, as nothing records that. Claiming true would be a false statement a relying party might trust.
  - **The default and the override.** A consumer's `WithClaimSource` replaces it, and is how a true `email_verified`, or an address apart from the username, is released.
  - **Not an account key.** The address stays out of every lookup, as matching on it would let a caller take over an account by claiming it.
  - **Rejected:** email columns on `users`, with a true verified state, which reverse the settled decision and touch a migration and three adapters for a column nothing else reads; and both together.
  - **Options left for later.** Those columns can be added without breaking a consumer, with a stored email taking precedence over the username.
- **Accepted:** a superseded token is inactive at introspection even inside its grace, and a disabled user's token stays active there until its grant is revoked, bounded by its lifetime. A caller who hangs up before the first read at revocation revokes nothing, as no credential was yet judged. All of this ran on the memory stores; task 12.6 carries the durable round trip.
- **What the durable round trip does not cover.** It runs on all three adapters and PostgreSQL 15 and 18, and scans every table for credentials. Two limits remain. No sealed column holds a value, because the provider writes neither of the columns the migration seals, `external_id_token` and `csrf_token`; sealing is proved by the session stores' own suites. `op_client_assertions` is empty at the scan, because no client in the scenario authenticates by assertion, so the scan is proved to read that table and not to find a row in it.

#### R8. A family identifier is not a credential (H6)

- **The gap.** The refresh token's family is not a secret, yet H4's "missing lineage reads as revoked" could be read as writing a revocation, and the revocation endpoint could revoke by the family alone. Either way, a value holding a real family and a made-up secret would end someone's grant: from any client's own grants, or from a public client that needs no secret. `UNREPRODUCED`.
- **The decision.** A secret that matches no record of the grant writes nothing: a refresh refuses it with `invalid_grant`, and revocation answers success, as RFC 7009 has it. Presenting a superseded secret at revocation or introspection is not a reuse, which only a refresh detects. No override.

#### R9. The flow cookie across tabs, hosts and browsers

- **What the flow cookie keeps (settled while building, 2026-11-04).** A presented value of the shape the provider mints, 32 bytes of unpadded base64url, is kept without asking whether a live request holds it, because `PendingRequestStore` has no lookup by it and an attacker can obtain a live value by starting a request of their own. `__Host-` is what stops planting. Any other value is replaced.
- **What authorization requests settled while being built (2026-11-04).**
  - A `nonce` under `PKCEOrNonce` needs `openid`, because with no ID token nothing would ever check it.
  - `max_age` above int32 is refused, so later arithmetic cannot overflow.
  - `offline_access` dropped with no scope left is `invalid_request`.
  - Under `WithDPoP`, a `dpop_jkt` that is not a SHA-256 thumbprint is `invalid_request`, rather than letting the user log in for a code that can never be exchanged.
  - `id_token_hint` has its own bound of 8 KiB, a proposed value, because a genuine ID token can exceed the general 4 KiB.
  - `WithDPoP()` tells the provider DPoP is on, since a chain cannot change a built provider, and `EnableOIDCProvider` compares `(*Provider).DPoPEnabled()` with `EnableDPoP` (task 8.1).
- **What resuming settled while being built (2026-11-04).**
  - **Write order.** The code token, then its record, then any browser session, and the stage's conditional write is the commit point. Secrets are released only after it. A racing loser gets an unknown handle, and leaves records whose secrets nobody saw, which expire.
  - **After the commit point,** a failure remembering consent, or deleting or touching a browser session, is logged. The user still gets their code, and at worst is asked for consent again.
  - **The consent stage binds the sign-in presented then,** and re-judges freshness against it, since the login stage's sign-in may have ended. A denial grants nothing, so it skips that check.
  - **A hint naming another user** answers `login_required` and spends the handle, because the request has been answered. It is judged after freshness, so what the page can fix comes first.
  - **Answering from a browser session (task 6.8).**
    - `prompt=select_account` skips the session, so it reaches the consumer's page. Core §3.1.2.1 requires a selection or an error, and the provider's job here is to show it.
    - The code is written, then the session is looked at through `Touch`, and `ErrNotFound` withholds it, so an end before the look is refused and an end after it finds the code (R26). At consent, this and the user check run before the stage is spent, so a refusal leaves the handle unspent.
    - `Touch` runs only when the session produced a code or parked at consent, so refused silent polling cannot keep a session alive. Successful polling extends it, up to the absolute deadline.
    - A store failure after validation answers `server_error` by redirect, with `state` and `iss`, as P3 says, under `prompt=none` or not. A failure reading the client has no validated redirect URI, so it is an error with no redirect.
  - **The client is judged as it is now (`REPRODUCED`, then fixed).** A code could be sent to a redirect URI the client had since unregistered. `rejudge` now runs at every resume, for a denial too. It refuses when the URI or code grant is gone, when `openid` was parked and is gone, or when no scope is left, and it leaves out other withdrawn scopes and resources. A consent answer naming a withdrawn scope has it dropped, as refresh does (R13).
  - **A future authentication time** more than 60 seconds ahead needs re-authentication (`REPRODUCED`, then fixed). The leeway is a proposed value, matching `nbf`'s.
  - **What the chain must refuse (task 8.5).** `SignIn` cannot express a session owing MFA or recoverable only by a late renewal, so the provider refuses only one past its deadline, or with no deadline, authentication time or family.
  - **`ResumeInput.IdleTimeout`** carries the manager's idle timeout, because the provider holds no manager (R2). Zero uses a 30-minute default, pinned to `session.New`'s.
- **Two tabs.** T5's single cookie was overwritten by each new request, so a second tab killed the first, and a cross-site navigation to `/authorize` could do the same. A browser holding a valid flow cookie now keeps it, and each pending request stores its digest. `__Host-` stops another host planting one. *Rejected:* a cookie per handle. It lets a hostile site stuff cookies through repeated navigations, up to a header-size denial of service. node-oidc-provider scopes its cookie by path, which `__Host-`'s `Path=/` rules out.
- **Same origin.** Login and consent URLs must be on the issuer's origin, refused at construction otherwise. T5's `__Host-` already made other hosts fail, only at first use.
- **Another browser.** A magic link opened elsewhere, or recovery on another device, cannot resume, since the flow binding is exactly what refuses it. That is the attack P1 stops. The README states it, and the user starts again from the relying party.
- **Plain http.** The loopback issuer's cookie has no prefix and is not `Secure`, because browsers refuse the prefix otherwise.

#### R10. Every exchange records a grant, including for clients with no refresh token

- **The gap.** Clients registered only for `authorization_code` had no stated grant, while H2's tombstone, `gid` (R4) and back-channel logout all need one.
- **The decision.** The row is always written, with a flag saying it holds no lineage, which is what H4's rule checks. It expires at the sign-in's deadline, so an ID-token-only client still gets its logout token.

#### R11. Parsing and transport rules the specs left out

- **Sourced to RFC 6749 §3.1, §3.2 and §2.3.1, and OIDC Core §15.1:** TLS is required at each endpoint, judged by `Request.Secure()`, so a proxy must be declared as trusted; a parameter with no value counts as omitted; a `client_id` or `redirect_uri` given twice is unredirectable; a credential in a token request's query refuses it; `display`, `ui_locales`, `claims_locales` and `acr_values` never cause an error, and the last is shown to the consumer's page; a missing `response_type`, a `response_mode` other than `query`, and a malformed `max_age` answer `invalid_request`; unknown `prompt` values are ignored, as §3.1.2.1 allows.
- **Corrected:** two client authentication methods at once is `invalid_request`, not `invalid_client` (RFC 6749 §5.2). Scope omitted at refresh means the grant's own (§6). `code_verifier` syntax is checked (RFC 7636 §4.1).
- **Bounds (*proposed* values).** `state`, `nonce`, `login_hint` and each `resource` at most 2048 bytes, `scope` at most 4096, each replaceable. Requests are parked by anyone, reflected in redirects, and stored.
- **Redirect URI registration** (RFC 8252 §7.1, §8.4): a private-use scheme must contain a period; `javascript`, `data`, `vbscript` and `file` are always refused; user information is refused; `[::1]` is accepted beside `127.0.0.1`.
- **Metadata** (RFC 8414 §2, RP-Initiated §2.1): `token_endpoint_auth_signing_alg_values_supported` must be present once `private_key_jwt` is listed, and `end_session_endpoint`, once logout is on.
- **Security headers become a construction check.** They were assumed, but the chain's are off until enabled, and RFC 9700 §4.16 says the server MUST prevent clickjacking. A consumer whose pages are served elsewhere states that they carry `frame-ancestors`.

#### R12. DPoP at the token endpoint

The user confirmed on 2026-11-04 that DPoP support is required. P6 stands, and DPoP stays the chain feature `EnableDPoP` turns on. These close what it left open:

| Case | Decision | Source |
|---|---|---|
| Server nonce needed at the token endpoint | 400 with `{"error":"use_dpop_nonce"}` and `DPoP-Nonce`; code unspent, token unrotated. The settled 401 form is for resource servers, so UserInfo keeps it | RFC 9449 §8 |
| `dpop_jkt` while DPoP is off | `invalid_request`. The RFC is silent. Ignoring it leaves the client holding an unbound code it believes is bound, so this takes the safe side | RFC 9449 §10 (silent) |
| A proof and a client certificate together | `cnf.jkt` alone | reasoned; one token, one confirmation |
| Confidential client refreshes with no proof | allowed as `Bearer`, unless the client requires binding. RFC 9449 §5 lets a server issue Bearer, and leaves the client to discard it | RFC 9449 §5 |
| A required client refreshes with no proof | refused | RFC 9449 §5.2 |
| A `DPoP` header while DPoP is off | ignored; `token_type` `Bearer` tells the client | RFC 9449 §5 |
| A bound sign-in at the resume | refused without its proof, as anywhere on the chain | `sender-constrained-tokens` |
| CORS for browser clients | `DPoP` allowed, `DPoP-Nonce` exposed | RFC 9449 §8 |
| A public client's first proof at a refresh, on a grant unbound at the exchange | `invalid_dpop_proof` before any rotation, leaving the token usable (`REPRODUCED` 2026-11-05: it was answered `DPoP`, and the next refresh with no proof succeeded). A refresh token issued beside a proof must be bound, and the RFC does not say a client may start DPoP later. Binding there takes a store write and a race. A client recovers with a new authorization | RFC 9449 §5 |
| A public client's certificate | the grant stores its thumbprint, and a refresh must present the same certificate, refused with `invalid_request` before any rotation (`REPRODUCED` 2026-11-05: it refreshed with none, and downgraded to `Bearer`). RFC 8705 names no code here, and `invalid_grant` would tell the client to discard its token | RFC 8705 §4 |
| An unbound public grant presenting a certificate at a refresh | allowed. The access token carries `x5t#S256`, and the grant stays unbound. Unlike a proof, RFC 8705's binding is a SHOULD, and a client may send a TLS certificate it never meant as a binding, so refusing would break it | RFC 8705 §4 |
| Proofs from an unauthenticated source | accepted. A proof is judged before the client, so such a request writes one replay row with nothing charged. RFC 9449 §4.3 lets the checks run in any order. A row is small and lives for the proof's window, nothing is amplified, and `DPoP.Replay` already states that the store is bounded only by the admitted request rate. A client signs a new proof for each request, so burning one costs it nothing | RFC 9449 §4.3, §11.1 |
| A limiter that cannot answer | fails closed as `invalid_client`, as the chain's other flows do. A healthy client is then told its credentials are wrong during the outage, which is accepted so an outage does not lift the guess limit | reasoned |
| A shared source | a proxy not declared as trusted makes every client one source, so 10 bad requests limit them all. The chain's trusted-proxy setting is the override | reasoned |

#### R13. Clients over time

- **A consumer's registry cannot be checked at construction.** "Wiring mistakes fail at construction" held only for configured clients. A client read from a durable registry passes the same validation when read. A failure counts as an unknown client and is logged with the setting.
- **What the client layer settled while being built (2026-11-04).**
  - **Secrets do not print.** `Client.Secret` and `ClientSecret.Digest` are `SecretBytes`, which renders `[REDACTED]` under every format verb and in JSON, and still assigns from `[]byte`.
  - **`JWKS` holds public keys only.** An `oct` key, or any key with `d`, is a configuration error at construction and on a registry read. `private_key_jwt` takes exactly one of `JWKS` and `JWKSURI`.
  - **Logout pages are required.** `Deps.LogoutURL` and `Deps.LoggedOutURL` are both required at `New`, so a forgotten URL cannot silently turn a mandatory feature off.
  - **Registry reads.** A client read back is validated in full, and one that fails, answers with another client's ID, or holds a raw `Secret`, is treated as unknown and logged. That includes a key algorithm the provider cannot sign, as R6 says.
  - **Rotation.** `NewClientSecret(secret, expiresAt)` builds a digest entry, and `(*MemoryRegistry).PutRegistered` registers up to two. A durable registry returns `RegisteredClient` values built with `NewClientSecret`, so `ClientStore` gains no rotation method.
  - **The JWKS cross-check.** `(*Provider).SignsWith(keys any) bool` compares by identity, and an incomparable value answers false. `EnableOIDCProvider` calls it for a JWKS provider that is a `*signingkey.Keys` (task 8.1), and a wrapped provider builds, since it cannot be compared.
  - **Client authentication's open choices.**
    - More than one method is `invalid_request`, by RFC 6749 §5.2 as R11 says. RFC 7521 §4.2.1 reads as `invalid_client`, through a fetched summary only. A missing or wrong `client_assertion_type`, a mismatched `client_id`, and a non-Basic `Authorization` scheme are `invalid_client`.
    - An assertion's payload must be a JSON object, because jwx's parse recurses into a JWS payload, and an inner `at+jwt` or `alg: none` token would otherwise supply the claims (`REPRODUCED`, then fixed).
    - A key whose `key_ops` omits `verify` is not used (RFC 7517 §4.3).
    - `nbf` allows 60 seconds of leeway, with no option, and `iat` is ignored.
    - An assertion with no `kid` tries each held key and never refetches, so a rotated key without a `kid` waits for the cache lifetime.
    - An outage stays a dependency failure, including a failed `kid` refetch within its window, and an expired key set is never served in place of a failed fetch.
  - **Client key sets have their own cache** (`clientkeys.go`), a departure from P7's "cached through the relying party's". That cache is unexported and tied to `*RelyingParty`, and sharing it means changes outside `oidcprovider/`. It follows the same design: per client, single-flight, and an unknown `kid` refetching at most once per 30-second cooldown. A failed fetch waits one fixed window rather than backing off. `WithClientKeysTTL` replaces its 15-minute default, which matches `oidc.DefaultDiscoveryTTL`.
  - **A moved token endpoint.** `AudienceIssuerOrTokenEndpoint` derives issuer + `/oauth2/token`, but the chain can move the path, and the provider cannot see that. `WithAssertionTokenEndpoint(url)` states it, and `EnableOIDCProvider` compares `(*Provider).AssertionTokenEndpoint()` with the chain's real token path at construction (task 8.1). *Rejected:* a setter the chain calls, which would change a built provider.
  - **A replay across `exp` is refused, for any store (`REPRODUCED` 2026-11-04, then fixed).** A replay could pass the `exp` check just before expiry, and then reach the identifier store after it. A store that forgets at `until` then answered "new", so one assertion was accepted twice, on the system clock with nothing injected (`TestAuthenticateClient_PrivateKeyJWT_ReplayAcrossExpiry`, `expected: 1, actual: 4`). The provider now reads the clock again after `Record` answers new, and refuses if `exp` has passed, which protects a consumer's store too. `MemoryAssertionIDStore` holds a pair until `DeleteExpired` removes it, and the provider's default sweeps a pair only a minute past its `until`. A new assertion reusing a `jti` is therefore refused for that minute.
  - **Refused schemes need no list.** `javascript:`, `data:`, `vbscript:` and `file:` hold no period, so they already fail R11's private-use rule for a native client and the `https` rule for any other. A separate list changed no outcome.
- **Secret rotation.** One digest per client forces downtime to rotate. A client may hold a second, and a secret may carry an expiry. Keycloak's rotation policy has an old-secret expiry in the same way. Default: one secret, no expiry.
- **Client key rotation.** An unknown `kid` refetches `jwks_uri`, at most once per cooldown, 30 s by default, as the relying party's key-set cache already does (`oidc.DefaultJWKSRefetchCooldown`).
- **Assertion typing.** `draft-ietf-oauth-rfc7523bis` says a client assertion SHOULD be typed `client-authentication+jwt`, and that rejecting an untyped one is NOT RECOMMENDED. That is accepted, and a token of another type is refused, so an access token cannot authenticate a client.
- **Public clients.** They may revoke by naming their `client_id` (RFC 7009 §2.1). They may not introspect (RFC 7662 §4, ASVS). Metadata says so.
- **Scopes taken away, or a client removed.** A refresh leaves out scopes the client has lost and says so in `scope`, and may regain them while the grant holds them (RFC 9700 §4.14.2). A removed client is `invalid_client`, and its grants wait for their deadlines.
- **Browser-based public clients.** `draft-ietf-oauth-browser-based-apps` (a draft) says the server SHOULD link a refresh token's lifetime to the user's session. So a public web client's grants, `offline_access` included, end with the sign-in by default. Override per client.
- **Consent across clients.** `draft-ietf-oauth-security-topics-update` (a draft) warns against reusing consent across downstream clients. Consent was already per client, and a scenario now pins it.

#### R14. Back-channel delivery is bounded, and follows no redirect

- **Bounded.** The specs said asynchronous and nothing more. A logout storm could then start goroutines without limit. Delivery uses a bounded pool and queue, stopped by the provider's `Shutdown`, and a worker that ends its goroutine is replaced, as #68 does in `notify`. A drop is reported as a failed delivery. Defaults (*proposed*): 8 workers, a queue of 1024, each replaceable through `WithLogoutDeliveryPool`, and a bound on each delivery through `WithLogoutDeliveryTimeout`. A consumer delivery replaces the POST and runs on the same pool and within the same bound. Workers start on demand, one goroutine per delivery, so `Start` launches nothing and only enforces `signingkey`'s sentinels. A delivery left behind past its bound holds no worker, and at most twice the workers can be left behind at once; past that a delivery fails with the `busy` reason.
- **Reports cannot hold anything (`REPRODUCED` 2026-11-04).** A log handler or sink could delay `EndSignIn`, stop its browser-session deletes by panicking, keep a worker, or hold `Shutdown` past its context. Reports now run on two bounded lanes, started on demand: `records`, one goroutine in order, for log lines; and `events`, up to 64, for the sink. Two, because one bound would let 64 hung sinks stop the log lines. Past 1024 waiting on a lane the newest loses, counted as `lost_events` or `lost_records`, with notes that are not failures counted apart as `lost_notes`. A report is counted from the moment it is owed, so a nil `Shutdown` means every report has been made, and what `Shutdown` finds has room no later end can take. A log handler that panics can lose a line, which `lost_records` counts, and one that always panics can leave that count unsaid, as the godoc states. This follows the common telemetry shape, a bounded queue that drops when full and flushes at shutdown. There is no option, because the bound protects the provider from its sink: a consumer who cannot accept it gives a sink that returns promptly. `EndSignIn` runs grants, browser deletes, hand-on, then its own report, so a hung synchronous sink holds the response and not the deletes.
- **What counts as failed.** A POST or consumer delivery cut off by `Shutdown` is reported as `shutdown`, as the client may not have been told. A store or fetch cut off is only logged. A status, panic or goexit arriving together with the stop or the bound keeps its real reason. A 200 or 204 is judged by status without reading the body, so an oversized body is still a success (`outbound.PostFormStatus`).
- **Context.** It keeps the caller's values, and not its cancellation.
- **Protocol.** Back-Channel §2.8: 200 and 204 are success. §2.5: retransmit only for a recoverable failure, so one attempt by default, and a consumer's queue may do more. The specs read found nothing on redirects, so following none is scrty's own choice, since a target is a registered URI. The `events` value is exactly `{}`, as the suite checks.
- **Outbound policy.** The confined client restricts schemes, origins and redirects, and has no private-address rule, so a first-party relying party on an internal address is reachable. `WithLogoutOutbound` replaces the client for delivery. A client from `WithOutbound` is copied through `outbound.Client.WithoutRedirects`, so "follows no redirect" holds under every option (`REPRODUCED` 2026-11-04: such a client followed a 307 and sent the token again). That client's own time bound still applies, as its godoc states.

#### R15. Multiple resources follow RFC 8707 §2.2

A `resource` at the token endpoint must be within the code's or grant's resources, not only the client's allowlist. The token narrows and the refresh token stays bound to the whole grant, so a later refresh may ask for another of them. Outside that is `invalid_target`. The token's audience is what was asked for: node-oidc-provider allows one audience per token, while RFC 8707 permits more, so it stays permitted, and the client chooses.

**A code granted resources, exchanged with none named.** The standards settle one case and leave the other to the server, and the user chose:

- **One granted:** the audience is exactly that resource, as if it had been named. RFC 9068 §3's example redeems a code from an authorization request naming one resource, with `openid` in scope, into a token whose `aud` is that resource alone. No issuer is added, matching that example and what an explicit `resource` gets (R4), so such a token cannot call UserInfo.
- **Several granted:** `invalid_target`, judged before the spend, so the code stays unspent and the client can retry naming what it wants. RFC 8707 §2.2 leaves acceptance to local policy, and its §3 warns that any audience of a multi-audience token can use it at the others. A client that wants that names them all at the token endpoint, and it stays permitted.
- **None granted:** nothing changes. The client's `DefaultAudience` applies, with the issuer added for `openid`, and otherwise the issuer alone. `AllowedResources` is never a default.
- **Rejected:** all granted resources, which spans services without the client asking; and the default audience regardless, which contradicts RFC 9068's example and can reach a service the user never approved.
- **The default and the override.** The rule has no option, because it follows from what was granted. A consumer chooses the outcome by what its client names, and through `DefaultAudience`.

**Options left for later.** A per-client setting choosing the issuer's addition, or a `defaultResource` hook, can be added without breaking a consumer. Neither is in v1.

#### R19. No orphan sweep

- **The gap (`REPRODUCED` 2026-11-04).** The established design removed a grant whose lineage was missing, to clean up after a failure between T9's two writes. A lineage past its idle timeout is swept too, so the pass also removed live grants of live sign-ins, and their clients were no longer told when the sign-in ended (`oidc-provider-logout`). The pass also loaded every live grant on every run, an extrapolated 15 minutes at a million grants, and gave a consumer no override.
- **The decision, by the user.** There is no orphan pass, and `GrantStore` has no `DeleteOrphans`. This departs from the established design, for the defect above. A grant stays until its own deadline. A row left by a failure between the two writes is harmless: the client got an error and holds no token, a refresh on it reads as revoked (H4), and an end may send its client one logout token for a sign-in it holds nothing from, which a receiver must tolerate anyway.
- **Rejected:** a "lineage written" mark set after the second write, which keeps the cleanup at the cost of a third write with its own failure case and a column; and accepting the loss, which breaks the logout spec.
- **The default and the override.** Rows leave through the grant sweep at their deadline, so the longest a leftover lasts is the client's absolute lifetime, 90 days by default, which a consumer sets per client. There is nothing else to override.
- **Options left for later.** A one-time cleanup task, or the mark above, can be added without breaking a consumer if leftovers ever prove costly in practice.

#### R22. An issuer with a path

- **The gap (`REPRODUCED` 2026-11-05).** The construction check of P7 compared the assertion token endpoint with the path the chain serves. An issuer of `https://id.example.com/auth` behind a router stripping `/auth` was refused, with no setting that worked: moving the prefix stopped the routes matching, and stating the stripped URL refused clients naming the real one.
- **The decision.** The issuer states the public URL, and the served path is planned separately, as Keycloak and node-oidc-provider do. A public URL is the issuer's origin, plus the served path when that is at or under the issuer's path, and otherwise plus the issuer's path and the served path. The check and the metadata documents share this rule. Paths compare in their escaped form, so an encoded spelling does not pass.
- **The default and the override.** No configuration for a stripped chain or for a prefix including the issuer's path. `WithAssertionTokenEndpoint` still states the URL outright.
- **The limit.** A chain cannot see at construction whether a router strips. A chain mounted without stripping must include the issuer's path in its prefix, or the published URLs do not reach it. `EnableOIDCProvider`'s godoc says so.
- **Rejected:** a public-path option, which restates what the issuer already says and can disagree with it.

#### R23. What the chain's construction settled

- **Slots.** `OrderOIDCProvider` is 250, inside CSRF and outside Basic and bearer, for the endpoints a client calls. `OrderOIDCProviderSession` is 850, inside the gates and session touch and outside the authorization stage, so a consumer's rules do not reach resume or consents.
- **The check after wiring.** A wire step cannot return an error, and runs in option order. `checkAfterWiring` runs after every one, so a manager that gains an observer counts wherever its option stands. Every manager the chain records is checked, not only the bearer's.
- **Binding the chain cannot verify.** A client requiring DPoP or a certificate is refused at construction when the chain does not verify it. The spec states the DPoP case, and certificates are the same wiring mistake (`library-design`, rule 6). A consumer's own registry cannot be listed, so `Provider.RequiresBinding` answers false for it and such a client is refused at the token endpoint instead.
- **Framing.** Security headers must restrict framing in the document profile, not only be enabled. `frame-ancestors` may hold `'none'`, `'self'` and named `https` origins, in a typed policy or a raw header. RFC 9700 §4.16's own example names an origin, and OWASP accepts one where framing is needed, so refusing them was stricter than the standard. `*`, a scheme, a wildcard host, a plain `http` origin, an empty or missing directive, and report-only are refused. RFC 9700 §4.16 asks for the older measures too unless a server explicitly drops browsers without CSP level 2. The chain's settled profile sends no `X-Frame-Options`, and this is that explicit choice: a consumer who needs them adds the header with `WithHeader`. `WithOIDCPagesCarryFrameAncestors` remains the override. A route-matched profile cannot be seen at construction, as the godoc says.
- **Paths.** `WithOIDCProviderPath` takes the whole request path, and the prefix does not apply to it. A path holding a character that needs escaping, such as a space, `?`, `#` or `%`, could not be published and compared as served, and is refused.
- **Status.** `ErrDependency` answers 500 before the challenge and table checks, whatever it wraps.
- **`amr` for a local sign-in.** Values follow RFC 8176, asserted only when known. A password gives `pwd`, a satisfied second factor adds `mfa`, and a federated sign-in keeps the upstream's values. A session records that a second factor was met, not which, and RFC 8176 lets `mfa` stand without naming methods, so TOTP is not named; recording the method would change the session schema. A passkey or magic link alone asserts no method, as no registered value can be truthfully claimed: a passkey cannot be told apart as `hwk` or `swk`. A local sign-in has no `acr`, as scrty defines no levels. `WithOIDCSignInAssurance` replaces the mapping whole.

#### R24. What the token endpoint settled

- **Defaults, each *proposed*.** A throttle of 10 failures per source in 15 minutes, replaceable with `WithOIDCTokenLimiter`, and a 64 KiB body bound with 413 above it, replaceable with `WithOIDCTokenBodyLimit`. A throttled source, an unattributable address and a limiter that cannot answer all read as `invalid_client`.
- **Browser endpoints.** A throttled source, a limiter that cannot answer and an unattributable source answer 429 at authorize and resume (RFC 6585), through `ErrOIDCThrottled`. RFC 9110 §15.5.2 says a 401 must carry `WWW-Authenticate`, which these cannot, and a consumer's page reads 401 as "sign the user in", so it could loop. The token endpoints keep `invalid_client`, the answer RFC 6749 gives a client.
- **Reading an authorization request.** A GET parses the raw query strictly and refuses what does not parse, as a POST does, and passes every parameter to the provider, so no fixed list can silently drop one. An unsupported request object answers `request_not_supported` before other parameters are read (OIDC Core §6.1, §6.2).
- **Resume.** A login stage needs a credential in the `Authorization` header, so a consumer's interceptor reading another place cannot resume. Two `Authorization` lines are refused. Consent may still stand on the browser cookie alone.
- **Refusals.** A missing required certificate answers `invalid_request`: RFC 8705 names no code, and `invalid_grant` would tell the client to discard its code. A proof plus a certificate from a client requiring mTLS is refused, as the token would carry only `cnf.jkt`. A repeated `Authorization` header answers `invalid_request`.
- **A credential in the query.** `httpsec.Request` gains `RawQuery`, so the refusal reads the query as received. Go's parser silently drops a pair it cannot decode, so `client_secret=%zz` was not refused (`REPRODUCED` 2026-11-05). Changing what `QueryValues` keeps was rejected: it misses `a=1;client_secret=abc`, and changes what the chain's other checks see. The interface change is free before the first tag.
- **Order.** `AuthenticateClient` is never called before `Token`, because an assertion is single-use. The proof is judged before client authentication, so a valid proof with a wrong secret still records its `jti`. Invalid proofs are charged to the source. Refused grants, nonce requests and failures are not.

#### R25. What the provider's events settled

- **Fields and names.** `event.Event` gains `Client` and `Cause`, with nine names under `scrty_`. A client is named only when the registry held it, so presented text never reaches an event.
- **One event per outcome.** A refresh reuse yields two events, the reuse and the revocation, through a chain as well as outside one. The chain's emitter stays off the lineage manager's context, so the same reuse is not reported a third time as `authn_token_reuse`. A code replay likewise yields two. `GrantRevoked` is reported only by the call that newly revoked the row, with the cause the store keeps. `CodeReplayed` may repeat, as each replay is a real presentation. `GrantStore.Revoke` returns whether this call revoked the grant, following `ConsentStore.Revoke`, so racing callers cannot both report it; the store suite pins this under 32 racers on every adapter. A replay reports before its lineage delete, as a revocation does, so a sink that blocks spends the revocation's budget after the row has already ended the grant.
- **Only what happened.** `GrantCreated` is reported once the credential is handed out. A failed dependency usually decided nothing, so it reports nothing. A failed grant end is one exception, and a failed clone revocation the other, as below: the session did end, and a grant outlived it, so `SignInsEnded` logs it and reports `scrty_grant_end_failed`, as `http-security-chain` requires and OWASP's logging guidance lists session management failures. Grants that did end are reported as they end.
- **Passkey clones.** The `passkey` package alone revokes nothing, as it holds no provider. `passkey.WithGrantRevoker` supplies one at construction, and `passkey.WithoutCloneGrantRevocation` keeps grants; keep wins if both are given. Injecting the chain's provider into a built manager was rejected: it mutates a manager two chains may share. So "revoke by default" holds on a chain with `EnableOIDCProvider` and `EnablePasskeys`, which refuses a manager that has decided neither. A chain using only `(*Passkeys).MFAMethod()` cannot be seen by that check, as the godoc states. A passkey manager takes no raw session store, because a store reports nothing to the provider.
- **A failed clone revocation** reports `scrty_grant_revoke_failed`, as suspension happens once and nothing retries it, through the chain's emitter on the request's context. Off a chain there is no event, only the log, which is never sampled away. Recovery and an MFA reset return theirs.
- **Accepted:** a redundant report failing after a successful logout can fire `scrty_grant_end_failed` though nothing outlived the sign-in. A rare false alarm is safer than risking a missed one.
- **The default and the override.** No sink means no events and no clock read. `WithSecurityEvents` sets one, and a chain's emitter takes its place on the context. `RevokeUserGrants` puts the consumer's own cause in `Cause`, unchanged.

#### R26. A logout's order, and what the suite expects

- **A sign-in's end racing a resume (`REPRODUCED` 2026-11-05).** An end between the bearer's load and the provider's writes left a live browser session, which then outlived the sign-in, against `oidc-provider-authorization`, and a code that made a live grant. A resume now checks after its writes that the sign-in's family still has a live head, through `ListSignIns`. If not, it ends the family and answers `ErrOIDCReauthenticate`; a failed check answers 500 and hands out nothing. An end before that check is caught by it, and an end after it finds the code and browser session already written, so the window R7 accepted is closed for ends through the chain. Consent resting on the browser session alone writes its code before its look at the session, as silent SSO does. Reading the presented identifier again was rejected (`REPRODUCED`): under strict rotation a live sign-in reads as ended, a grace closing mid-request reads as reuse and revokes the family, and an outage failed open. The cost is one user's listing per resume, as `session.Store` has no family lookup. A sign-in that merely expires between the two reads is treated as ended.
- **Limits accepted.** `mfa.ResetEnrolment` revokes nothing when `ResetDeps.Grants` is nil: a package function cannot see a provider, and nothing may change when none is in use, so a consumer using the provider must set it, as its godoc states. A 401 the provider's own routes answer carries a challenge, as RFC 9110 §15.5.2 requires. A 401 from elsewhere in the chain does not, including a bad bearer refused before it reaches `/resume` or `/consents`, and login, MFA verification, passkey management, recovery, renewal and logout. This predates the change, and changing what every chain answers is a follow-up of its own.
- **A fixed list of assertion algorithms.** `assertionAlgs` has no option. It holds only asymmetric algorithms, because a client's registered keys are public and nothing symmetric could safely be keyed by them, and a client's own key type bounds what can verify for it. There is no per-client or provider setting to narrow it further, which a later option could add without breaking a consumer.

- **The order (`REPRODUCED` 2026-11-05).** An end deleted the browser session even when the grant write failed, so a retry from that browser found none, and its confirmation answered success with grants and sessions live. RP-Initiated Logout §2 says the OP MUST log out an End-User who says yes. An end through the endpoints now runs grants, first-party sessions, then the browser session, and spends its handle last through `Provider.SpendLogout`. A caller off the chain does the same, finishing with `EndSignIn(Ended)`, or its handle lives until its deadline. Two confirmations of one handle may both answer 200: each is idempotent, and one logout event fires. While a logout is failing the browser session stays usable, as the first-party session does, and the user has been told it failed.
- **Rejected:** falling back on a hint, which lets an ID token's holder end a sign-in from another browser, against §2's MUST ask; and falling back on the first-party session, at a CSRF-exempt endpoint, which the order makes unnecessary. `EndSignIn` keeps writing both stores for the observer path, as nothing retries an observer (T4).
- **"Keep grants".** The option keeps grants holding `offline_access`. A grant without it ends with its sign-in, whatever the option says, because T4 and R2 define what a sign-in's end does.
- **The logout page** does not show who is asking: §2 requires asking, not naming, and no read exists for a logout handle.
- **UserInfo CSRF.** A cross-site POST to UserInfo stays refused, as `csrf-protection` says "exactly these" endpoints are exempt. An allowlisted origin passes, and a consumer may exempt it. The token never comes from a cookie, so nothing is at risk either way.
- **The conformance suite's expected results.** `oidcc-claims-essential` warns, because `claims` support is OPTIONAL (OIDC Core §5.5) and the provider publishes `claims_parameter_supported: false`; a fixture returning `name` regardless would hide the gap and release a claim beyond the scope. `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported` is skipped, because `request` is OPTIONAL and the provider MUST return `request_not_supported` (§6.1), which it does. Whether official certification accepts a warning is unverified.

#### R16. One end-observer option, shared with `session-signals`

- **The collision.** `session-signals` D5 defines `session.WithEndObserver(func(ctx, EndReport))`: one observer, not reported for `DeleteByExternalSession`, composed by `session.EndObservers`, and refused by its chain option when one is already set. T4 defined the same name, repeatable, with an interface, identity comparison and a report of the upstream session. Both are unbuilt, and neither has landed. Either alone would break the other.
- **The decision.** One option, written once:
  - `session.EndObserver` is an interface, with an `EndObserverFunc` adapter, so `session-signals`' closures still fit;
  - `WithEndObserver` is repeatable;
  - `ReportsEndsTo` compares by identity, and an incomparable value such as a func is simply not the one asked about;
  - `EndReport` adds the upstream issuer and session to D5's fields, and `DeleteByExternalSession` reports them;
  - from D5: the context keeps the caller's values and not its cancellation, panics are recovered, and the kept family is named. T4 first said "the caller's context", where a hang-up could have dropped a revocation.
- **Follow-up in another change.** `session-signals`' design and tasks must follow, including no longer refusing a manager that already has an observer. Task 1.3 did that on 2026-11-04. Whichever change lands first adds the option, and the other adds to it. `session-signals` also adds `(*Sessions).AddEndObserver`, because its chain option wires itself to a built manager; this change needs no such call, since `EnableOIDCProvider` checks the wiring with `ReportsEndsTo`. The wire reasons stay `session-signals`' own, mapped from `EndCause`. Each change carries the shared `sessions` requirements word for word, and the one that lands second drops them from its delta.

## Risks / Trade-offs

- **[The tag waits for this whole change, and for a green conformance run]** → v1 stays at the scope above, and every follow-up only adds. The task breakdown sizes it; P9 makes the conformance job part of the gate.
- **[No certified library underneath]** → the conformance suite in CI (P9), plus test-first coverage of the pitfalls the advisories cluster on: exact redirect matching, code reuse revoking what it issued, refresh reuse, and token binding.
- **[A refresh token mistaken for a sign-in]** → three built-in paths turn a stored session identifier into a sign-in. Decision 5 (D+) keeps refresh tokens out of all three by a fixed table and a token format no sign-in path accepts.
- **[A replayed code racing the first exchange leaves a live grant]** (H2, `REPRODUCED` 2026-11-04) → the grant row's revoked flag, keyed by the family the code records (decision 5).
- **[A grant overstating `auth_time`]** (H3, `REPRODUCED` 2026-11-04) → the grant copies the sign-in's authentication facts explicitly.
- **[Error bodies depart from the library's default]** → limited to the provider's endpoints, recorded in P3, and pinned by tests against RFC 6749's examples.
- **[RS256 by default conflicts with FAPI 2.0]** → recorded in P8. A FAPI profile is a later, additive switch.
- **[A cookie now stands for a sign-in at the provider's own endpoints]** (R2) → it is `__Host-`, `HttpOnly`, single-purpose, stored as a digest, capped by the sign-in's timeouts and ended with it, and CSRF protection is required with it. It does not see markers placed on the sign-in afterwards; the godoc states that.
- **[Basic OP passes only with `PKCEOrNonce` and one expected failure]** (R1, R5) → recorded, and the runner fails if the entry goes stale. Official certification may need more, and was not checked.
- **[A code issued as its sign-in ends]** (R7, R26) → closed for ends through the chain: a resume checks after its writes that the sign-in's family is live, and ends it otherwise. A caller of the Go API off the chain owns the same check.
- **[A hint older than the key retention cannot be judged]** (R6) → it counts as no hint, so the user is asked at logout. No sign-in ends on a value that cannot be verified.
- **[Two active changes define one option]** (R16) → task 1.3 aligns `session-signals` before either is implemented.
- **[A sign-in credential held by the login page's JavaScript]** → it is the credential the page already holds to sign in, kept in memory only. The resume adds no new exposure, and `bff-resource-server`'s cookie session could remove it later (P1).
- **[A grant without `offline_access` outliving an idle sign-in]** → it ends at logout, family revocation and upstream back-channel logout, and is capped at the sign-in's absolute deadline. Ending it on idle expiry needs a family lookup in `session.Store`, a later additive change (P1).
- **[Strict `private_key_jwt` audience refusing older clients]** → clients built to Core's token-endpoint audience fail until they send the issuer. The compatibility option exists and is documented as accepting the ambiguity CVE-2025-27370 describes (P7).
- **[Clickjacking on the consumer's login and consent pages]** → RFC 9700 §4.16 puts it on the authorization server, but the pages are the consumer's. D4's headers cover pages served through the chain; the README states the requirement for any other page.
- **[`close-security-gaps` D8 refusing a provider-only chain with DPoP]** → amended there on 2026-11-02: DPoP is refused only when no enabled feature verifies bound credentials (P6).
- **[Conformance modules have not yet met a real OP]** → task 1.2 ran the suite against a stand-in, which confirms plans, modules and TLS but not how each module judges a provider. R1 and R2's module results stay read from source until 14.1 and 14.2 run them.

## Migration Plan

- Nothing to migrate: the provider is new, and off until a consumer enables it.
- The security-state migration that adds the provider's tables lands in the first migration set, before the tag.

## Open Questions

None. The user answered all four refresh questions on 2026-11-04, each as recommended.

Settled:
- **PKCE and the conformance gate (R1):** PKCE stays the default, and `PKCEOrNonce` is an opt-in for confidential clients, with one recorded expected failure in Basic OP. Rejected: PKCE optional for confidential clients, and dropping Basic OP from the gate. Whether certification accepts that expected failure is still unverified.
- **Browser session and single sign-on in v1 (R2):** a small provider-only browser session, which also delivers SSO. This reverses the 2026-11-02 decision to leave SSO as a follow-up. Rejected: keeping the Non-Goal with three expected failures, and waiting for `bff-resource-server`.
- **Logout confirmation (R3):** ask unless a valid hint names the browser's own sign-in, with `WithLogoutConfirmation` to ask always. Rejected: always asking.
- **UserInfo's audience (R4):** require the issuer in the audience, adding it to a default audience for `openid` tokens. Rejected: requiring the issuer without adding it, and restoring "any audience".
- **Logout plans in the gate (R5):** the gate runs both logout plans. Rejected: Basic and Config only.
- **Former open question 1:** whether a green conformance run is a hard precondition for the tag. Decided on 2026-11-02 as recommended: yes (P9). R5 adds the logout plans to the plans it names.
- **Former open question 2:** the provider package's name and place. Decided by the user on 2026-11-02: `oidcprovider`, at the module root (T1).

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
- Conformance suite: run at `475e8bf` on 2026-11-04 against a stand-in (P9 says which facts), and its source at commit `a5b9635`, read the same day: `OIDCCBasicTestPlan`, `OIDCCConfigTestPlan`, `AbstractOIDCCServerTest`, `OIDCCEnsureRequestWithValidPkceSucceeds`, `AbstractOIDCCSameAuthTwiceServerTest`, `CheckDiscEndpointAllEndpointsAreHttps`, `BrowserControl`, `scripts/run-test-plan.py`. It replaces the profile PDF that could not be read.

The decision that a green run gates the tag (P9) is reasoned from decision 1: no certified library sits underneath.

### Standards compliance and security practice

**Researched (accessed 2026-11-02):**
- [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.txt), BCP 240, January 2025. Each clause below was read and quoted in the compliance tables:
  - §2.1 and §4.1.3: exact redirect matching, its one exception for the port of a native app's loopback redirect URI (citing RFC 8252 §7.3), and the mix-up defence;
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

### Decisions from the refresh, R1 to R16

**Researched (accessed 2026-11-04, primary text unless noted):**
- [OpenID Connect Core 1.0, errata set 2](https://openid.net/specs/openid-connect-core-1_0.html): §3.1.2.1 and §3.1.2.2 (`prompt`, `max_age`, `id_token_hint`, expired hints; R2, R6, R11); §5.3 (silent on audience; R4); §12 (refresh; R11); §15.1 (mandatory features; R2, R11).
- [RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html), §2 to §4 (R3). [Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html), §2.4 to §2.8 (R14).
- [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700), §2.1.1 (R1). [OAuth 2.1, draft-17](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-17), §7.5.1.1 (R1), a draft.
- [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068), §4 and §5 (R4). [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707), §2.2 (R15). [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449), §5, §5.2, §8 and §10 (R12).
- [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749), §2.3, §2.3.1, §3.1, §3.2, §5.2 and §6; [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636), §4.1 (R11). [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252), §7.1, §7.3 and §8.4 (R11). [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414), §2 (R11). [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009), §2.1, and [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662), §4 (R13).
- [draft-ietf-oauth-rfc7523bis](https://datatracker.ietf.org/doc/draft-ietf-oauth-rfc7523bis/), rev 11, RFC Editor's queue, no RFC number on this date: the audience rule and assertion typing (P7, R13). The text read carries an earlier date than the datatracker's, which may reflect only a state change.
- [draft-ietf-oauth-security-topics-update-03](https://datatracker.ietf.org/doc/draft-ietf-oauth-security-topics-update/), a draft: audience injection, and consent across downstream clients (P7, R13).
- [draft-ietf-oauth-browser-based-apps-27](https://datatracker.ietf.org/doc/draft-ietf-oauth-browser-based-apps/), a draft: refresh lifetimes for browser clients (R13).
- [OWASP ASVS 5.0](https://github.com/OWASP/ASVS/tree/master/5.0/en), V10.4 to V10.7: 10.4.6 (R1), 10.6.2 (R3).
- [NIST SP 800-63C-4](https://pages.nist.gov/800-63-4/sp800-63c.html), §3.9 and §4.7: IdP and RP sessions are separate, and the IdP should let the RP ask for fresh authentication (R2).
- Practice, partly read: [Duende end-session](https://docs.duendesoftware.com/identityserver/reference/endpoints/end-session/) (R3, through a fetched summary); [node-oidc-provider](https://github.com/panva/node-oidc-provider/blob/main/docs/README.md) (cookies, confirmation, one audience; R3, R9, R15); [Keycloak administration guide](https://www.keycloak.org/docs/latest/server_admin/) (secret rotation, logout confirmation; R3, R13); Ory Hydra source (`consent/strategy_default.go`; R9). What each does with a code outstanding at logout, or a hint signed by a retired key, was not found. R7 and R6 rest on reasoning.
- Advisories, through the GitHub advisory API: [Keycloak GHSA-f5p5-6xmx-p252](https://github.com/keycloak/keycloak/security/advisories/GHSA-f5p5-6xmx-p252) (URI comparison; exact matching, P1); [Duende GHSA-v9xq-2mvm-x8xc](https://github.com/DuendeSoftware/products/security/advisories/GHSA-v9xq-2mvm-x8xc) (`cnf` validation; R12); [Keycloak GHSA-27gc-wj6x-9w55](https://github.com/keycloak/keycloak/security/advisories/GHSA-27gc-wj6x-9w55) (`error_description` injection; P3). This was not a complete search of OP implementations.

**Unverified:** whether the Foundation's certification accepts R1's expected failure; whether errata set 3 of OIDC Core exists, which secondary sources imply and the published text does not show; and Auth0's audience behaviour, cited in R4 from memory, which task 1.2 does not depend on.

R6, R7, R8, R9, R10 and R16 are otherwise reasoned from scrty's own settled specs and code at `501a1a6`, and from `session-signals`' design.

The user chose D+ and sub-decisions 2 to 6 on 2026-11-02, and confirmed P1 to P9 the same day. The code paths, the option failure modes and H2 to H4 come from an independent review of scrty's own code (`session`, `httpsec`, the SQL stores, `expiry`) and of `close-security-gaps` D8 and D12. They are reasoned from the code, not reproduced.

### R17: replay detection

**Researched (accessed 2026-11-04):**
- [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.txt), §4.1.2: deny a code used more than once, and "SHOULD revoke (when possible)" what it issued.
- [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.txt), §4.2.4: invalidate a code after first use, and SHOULD revoke on a second attempt.
- [OAuth 2.1, draft-ietf-oauth-v2-1-17](https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-17.txt), §7.5.3: revoke only on a valid request, and why an invalid one must not. It is a draft.
- [node-oidc-provider, `authorization_code.js`](https://raw.githubusercontent.com/panva/node-oidc-provider/main/lib/actions/grants/authorization_code.js): an expired code is refused before its consumed check, so that path revokes nothing.
- [ory/fosite, `flow_authorize_code_token.go`](https://raw.githubusercontent.com/ory/fosite/master/handler/oauth2/flow_authorize_code_token.go): a used code revokes, and a code the store cannot find is `invalid_grant` with nothing revoked.

### R15: a resource named only at the authorization request

**Researched (accessed 2026-11-04):**
- [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068.txt), §3: a code from a request naming one resource redeems to a token with that `aud`, and a request with no resource uses a default.
- [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.txt), §2.1, §2.2 and §3: `invalid_target`, acceptance by local policy, and the warning about several audiences.
- [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.txt), §2.3: audience-restrict to one resource server or a small set.
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html): searched, and it does not mention resource indicators.
- [node-oidc-provider `resourceIndicators`](https://github.com/panva/node-oidc-provider/blob/main/docs/README.md): several granted resources must be named at the token endpoint.

### R19: no orphan sweep

Reasoned from scrty's own settled specs and the established design.

### R20: the same successor on re-presentation

**Researched (accessed 2026-11-04):**
- [Auth0, refresh token rotation](https://auth0.com/docs/secure/tokens/refresh-tokens/configure-refresh-token-rotation): a new token inside the leeway, and only the previous token may be reused.
- [Ory Hydra, graceful token refresh](https://www.ory.com/docs/hydra/guides/graceful-token-refresh): a new token on each use, in one chain, described as a workaround for clients that cannot be fixed.
- [Okta, refresh tokens](https://developer.okta.com/docs/guides/refresh-tokens/main/): the previous token stays valid for a grace period, 30 seconds by default.
- [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.txt), [OAuth 2.1, draft-17](https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-17.txt) and [browser-based apps, draft-26](https://www.ietf.org/archive/id/draft-ietf-oauth-browser-based-apps-26.txt): searched for concurrent refresh, and silent on it.

### R22: an issuer with a path

**Researched (accessed 2026-11-05):**
- [Keycloak, using a reverse proxy](https://www.keycloak.org/server/reverseproxy): a non-root path may be stated in the `hostname` URL, sent as `X-Forwarded-Prefix`, or matched with `http-relative-path`.
- [node-oidc-provider, documentation](https://raw.githubusercontent.com/panva/node-oidc-provider/main/docs/README.md): shows an issuer with and without a path at one mount path, and what the host must route for each. Only the first half of the page was read.

### R14: reports on bounded lanes

**Researched (accessed 2026-11-05):**
- [OpenTelemetry, trace SDK](https://opentelemetry.io/docs/specs/otel/trace/sdk/): the batching processor's `maxQueueSize`, default 2048, drops spans when reached, and `Shutdown` includes a flush.

### R26

**Researched (accessed 2026-11-05):** [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html), §5.5 and §6.1, read directly. [RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html), §2, as the reviewer quoted it. [OpenID Foundation, submission of OP results](https://openid.net/certification/op_submission/): says nothing found on warnings, so that question stays unverified.

### R23 to R25

**Researched (accessed 2026-11-05), for R25's failed grant end:**
- [OWASP, Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html): session management failures and application errors are among what to always log.

**Researched (accessed 2026-11-05), for R24's browser endpoints:**
- [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110), §15.5.2, and [RFC 6585](https://www.rfc-editor.org/rfc/rfc6585), §4: a 401 carries a challenge, and 429 is the code for too many requests. The reviewer read §15.5.2 and this session did not re-read either.
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html), §6.1, §6.2: the codes for an unsupported request object, as the reviewer read them.

**Researched (accessed 2026-11-05), for R23's `amr`:**
- [RFC 8176](https://www.rfc-editor.org/rfc/rfc8176.txt), §2: the registered values, and that `mfa` may stand with or without the specific methods.
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html), §2: `amr` and `acr` are optional, and `amr` values should come from that registry.

**Researched (accessed 2026-11-05), for R23's framing:**
- [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.txt), §4.16: authorization servers must prevent clickjacking, and its example allows one named origin in `frame-ancestors`.
- [OWASP, Clickjacking Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html): `'none'` unless a need is identified; `'self'` and named origins are accepted.

Reasoned from scrty's own settled specs and reproduced tests. R24's certificate refusal relies on [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705) naming no error code, as the implementing lane reported; this has not been re-checked.

### R21: an email from the username

Reasoned from scrty's own settled specs and the user's decision. [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html), §5.1 and §5.4, accessed 2026-11-04: `email` and `email_verified` are the `email` scope's claims; §5.3.2: a claim not returned is omitted, not a null or an empty string.

