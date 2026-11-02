# close-security-gaps — session handoff (2026-11-02)

Continue with `/opsx:apply close-security-gaps`. Read this first, then `tasks.md`, `design.md` (decisions
carry "Settled during …" bullets from this session), and `plans.md`.

## State

- Branch `feat/close-security-gaps` at `7dd4ab8`, clean, not pushed. **61/92 tasks ticked.**
- Merged and ticked: 1.1–1.2, group 2 (trusted proxies), group 3 (security headers), group 4 (CORS),
  5.1–5.4 (CSRF core), group 6 (sessions), group 7 (session management), group 10 incl. 10.11
  (password policy, rehash, atomic conditional update), group 13 (supply chain).
- Every module's `go test -race ./...` passed at the last merge. `test/TestRedisLimiter_Fault` fails only
  under the full parallel run (passes alone ×3) — note for 14.1.

## Work parked on branches (not merged)

| Branch | Holds | Status |
|---|---|---|
| `wip/close-security-gaps-dpop` (= worktree `.claude/worktrees/agent-a46691d6e8d05ca65`) | DPoP 8.1–8.9 (reviewed clean, merged with the branch at `4232dcb`) + 8.10–8.12 (commit `207a970`, **unreviewed**) | Review `207a970`, fix, then merge into `feat/close-security-gaps` and tick 8.1–8.12 |
| `wip/close-security-gaps-csrf-h7` (`bd478bb`, based on `5bd0732`) | CSRF 5.5–5.7 + exported `CookieAuthenticator`/`CheckCSRFToken`, tokens only with the default source | **Review found 2 reproduced defects** (below). Merge only after the DPoP lane, then fix |

Stale worktrees (fully merged, safe to remove): `agent-a0a2d5a51548672b4` (passwords),
`agent-a61918197adf13ef4` (session mgmt), `agent-af49ead70dcfa5854` (sessions, locked by a finished agent;
`git worktree remove -f -f`).

## Next steps, in order

1. **Review DPoP `207a970`** (Opus) against tasks 8.10–8.12, D8, `sender-constrained-tokens`. Points the
   implementer raised:
   - **Decision for the user:** nonce key = new consumer-supplied `DPoP.NonceCipher` (`httpsec.NonceCipher`,
     same methods as `session.Cipher`, so `seal.SessionCipher` plugs in; own AAD
     `scrty/httpsec:dpop-nonce:v1`), required with `Nonce: true`; `NonceLifetime` default 5 min (unpinned
     by spec); a fresh nonce is sent past half its lifetime. Record in D8 once confirmed.
   - The `invalid_dpop_proof` challenge on a binding-refused session reference differs from an unknown
     reference's plain challenge — D8 says it must not be distinguishable. Decide and align.
   - Per-route guards (`guards.go`) answer without the `DPoP`/`Bearer` challenge (untested).
   - A nonce-cipher outage is probably charged to the source at magic link / OIDC handoff (UNREPRODUCED).
   - Stale godoc in `bearer.go` ("sets no WWW-Authenticate header").
   - README htmx sample omits nonces; `record.ts` "Node.js 23.6+" note unverified; vector recorded on Node
     WebCrypto, not a browser.
2. **Merge the DPoP lane** into `feat/close-security-gaps` (from a worktree merge, then fast-forward), run
   every module, tick 8.1–8.12.
3. **Merge `wip/close-security-gaps-csrf-h7`** and fix, test-first (one dispatch):
   - **HIGH (reproduced, `TestReview_CookieAuthenticatorBeforeCSRFSlotSkipsToken`):** `CheckCSRFToken`
     returns nil when the CSRF layer has not run (a `CookieAuthenticator` registered at or before
     `OrderCSRF`). Refuse that wiring at construction, or refuse in `CheckCSRFToken` when no layer ran.
   - **MEDIUM (reproduced, `TestReview_BackchannelWildcardPrefixWidensExemption`):** a `*` in
     `WithOIDCBackchannelLogoutPath` becomes a wildcard in the back-channel exemption; and
     `parseCSRFExemption`'s error is discarded (fail at construction instead).
   - Exemptions match `Request.EscapedPath()` (closes the `%2F` gap; also flagged by automated review).
   - `CheckCSRFToken` publishes the checked sign-in's token for `CSRFToken(ctx)` (D6).
   - Build-time "sign-ins carry a token" flag on `loginTailDeps` instead of `signInsCarryCSRFToken(ctx)`
     (`complete.go`, set in `login.go`, `magiclink.go`, `oidc_redeem.go`, `passkey_login.go`).
   - README "CSRF protection" update for `EscapedPath`.
   Then review (Opus), tick 5.5–5.7.
4. Group 9 (mTLS binding; resolution must keep the trusted peer's raw cert header before removing it —
   D9; the resolved-request wrapper must forward any optional interface it reads), group 12 (automation
   challenge), group 11 (security events) — per `plans.md` lanes; group 14 last.

## Small follow-ups not yet scheduled

- gorm session listing: add a statement test that the listing `SELECT` omits `csrf_token` and
  `external_id_token`; the `savedColumnsOmitted` entries are inert (the update map is the guard).

## Rules learned this session

- Run **every module's** `go test -race ./...` (root, ginsec, fibersec, pgxstore, gormstore, webauthn,
  sweep, redisstore, `test`) before each merge — a `store/gormstore`-only test regressed once unnoticed.
- Worktree agents start at an old base; tell them to `git merge --ff-only feat/close-security-gaps` first.
- Integrate a lane by committing in its worktree and merging the branch into it there, then
  fast-forward/merge into the main tree only when the main tree has no overlapping uncommitted work.
