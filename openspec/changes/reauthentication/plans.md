# Re-authentication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A recency guard for consumer routes, and opt-in `/reauth` endpoints that let a signed-in session re-prove itself under a "strongest factor held" policy.

**Architecture:**
- One freshness check on `session.Session` backs every freshness decision.
- The guard is a judge on the existing `Guards.guard` path in `httpsec`, `ginsec` and `fibersec`.
- The endpoints are one new interceptor at slot 655. It reuses the MFA slot's methods and throttle, and the form login's password path.
- The MFA verify and begin endpoints stop serving sessions that owe no challenge.
- Review findings (tasks 9.x) tighten wiring checks, add the post-authentication phase to the password re-proof, and finish the one-implementation-per-control refactors. A strict rotation's lost race is decided by the store through a mark kept on the old row (tasks 10.x).

**Tech Stack:** Go 1.27; `net/http`, gin, fiber v3; testify, gomock (`use-mockgen`), testcontainers (`use-testcontainers`).

**Spec:** `openspec/changes/reauthentication/`. It holds `proposal.md`, `design.md` (D1–D10), `specs/{reauthentication,sessions,multi-factor-auth,account-recovery,passkey-authentication,http-error-propagation,framework-adapters,security-state-stores,schema-migrations,store-conformance}/spec.md` and `tasks.md`. Task numbers (1.1 … 11.2) below are `tasks.md`'s. Every plan task names the ones it implements.

## Global Constraints

- Test-first for every task: write the failing test, run it, and confirm it fails **for the intended reason** (not a compile error), then implement. Where a task preserves behaviour, the red step is a temporarily inverted implementation that the test catches, then restored (`golang-tdd.md`).
- Table tests use the `table-test` skill: the `assert` closure form, `t.Context()`, and a `ctx` modifier where context matters. Mocks use `use-mockgen` (`--typed`, placed by consumer). Durable backends use `use-testcontainers`.
- Every new option names its default in godoc. Every default has a test, and so does at least one override (`library-design.md`).
- Defaults:
  - recency window `15 * time.Minute`;
  - guard clock `clock.System()`;
  - re-proof prefix `"/reauth"`;
  - slot `OrderReauthentication = 655`;
  - challenge TTL `5 * time.Minute`;
  - challenge limit `10` per user and method per hour;
  - challenge purpose `"reauth-challenge:" + method`;
  - password field `password`.
- Statuses: `ErrReauthenticationRequired` and `ErrReauthenticationMethodNotUsable` are 403. Wrong secrets keep their existing 401 sentinels.
- No "any factor" re-proof option exists (D3). Re-proof never applies the same-channel rule (D4).
- D5 is **unpinned behaviour, not a defect** (`defect-claims.md`). Task 5's red test shows today's acceptance, and nothing calls it a bug.
- The project's reference-material rule binds every dispatch: consult it only on demand, never copy from it, never cite it.
- Agents never run `git checkout --`, `restore`, `reset --hard`, `stash` or `clean`, and never edit `openspec/`.
- Tasks 9.1–9.5, 10.3 and 10.4 fix **reproduced** defects (`defect-claims.md`). Each red step is the named reproduction, rewritten in the package's own test file and table form; the originals live in disposable worktrees under `/private/tmp/claude-501/-Users-zakyalvan-Documents-RND-scrty/5335ea06-576b-4616-b14e-50643ee94c82/scratchpad/repro/` and are read, never copied. Tasks 9.6 and 9.7 are refactors with no defect claim.
- Strict-rotation mark: Go fields `Supersession.Strict bool`, `Session.RotatedStrictly bool`; column `rotated_strictly boolean NOT NULL DEFAULT false`; retention of a strictly rotated row = its in-flight window end (`DefaultRenewalGrace`, 30 s, capped at the absolute deadline).

## Review Focus

- `/reauth/verify/TOTP` (method name in another case) is refused as an unknown MFA method (404), never matched to `totp`. Added to Task 7 (6.3).
- A JSON password re-proof body carrying both `username` and `password` checks the session's own user only. Added to Task 8 (6.4).
- An authentication time hours ahead of the guard's clock is fresh (D1). It is pinned explicitly so a later "fix" to refuse it is a visible decision. Added to Task 1 (1.1) and Task 3 (3.2).
- A re-proof on a session-reference bearer chain returns a new reference, and the old reference is refused. On a JWT chain it returns a new token whose session loads. Added to Task 8 (6.5).
- A passkey-only session where a passkey sign-in is one factor re-proves with that passkey: it becomes fresh but never "second factor met" (D4). Added to Task 14 (6.7).
- Two valid re-proofs, or two valid MFA verifications, from one session at once on one server: one wins and the other gets 409, never 401 (D10). Added to Task 13 (7.1), and across two chains sharing a session store in Task 22 (10.4).
- A re-proof prefix with a trailing slash (`/passkey/register/`) collides as its slash-free form does. Added to Task 16 (9.1).
- A post-authentication policy that allows but raises nothing leaves the password re-proof's outcome unchanged (the phase is not a silent refusal). Added to Task 18 (9.4).
- A strictly rotated identifier presented after its window is `ErrExpired` before the sweep and `ErrNotFound` after it, never `ErrReused`, and revokes nothing. Added to Task 21 (10.3).
- A re-proof racing a renewal of the same session: one wins, and the other is refused with the renewal-conflict error (409), leaving the winner's session in place. A GET to `/reauth/verify/totp` passes through untouched. Added to Task 8 (6.5) and Task 6 (6.1).

## Execution lanes and dispatches

Three lanes. Two agents never own one file. Agents that run at the same time each get **their own git worktree** branched from the implementation branch `feat/reauthentication` (`isolation: "worktree"`), because they all compile package `httpsec`. The main session integrates each wave by merging the worktree branches. The files are disjoint, so the merges are clean. Then it verifies.

| Wave | Dispatch | Tasks | Owns | Model, reason | Reviewer |
|---|---|---|---|---|---|
| 1 | A1 | 1.1–1.2 | `session/session.go`, `session/session_test.go`, `httpsec/recovery_codes.go`, `httpsec/recovery_codes_test.go`, `authenticate/passkey/passkey.go`, `authenticate/passkey/{register,manage}_test.go`, README freshness sentences | Opus: a refactor that must keep behaviour while extracting shared code | Opus |
| 1 | B1 | 2.1 | `httpsec/errors.go`, `httpsec/errors_test.go` | Sonnet: known sentinel and registry pattern | Sonnet |
| 1 | C1 | 5.1 | `httpsec/mfa_verify.go`, `httpsec/mfa_begin.go`, their `_test.go`, any caller in `test/` that posts verify or begin from a full session | Sonnet: single-seam admission change with a stated refusal | Sonnet |
| 2 | B2 | 3.1–3.3 | `httpsec/guards.go`, `httpsec/guards_test.go`, `httpsec/example_guards_test.go` (new), README guards section | Opus: security refusal logic written for the first time | Opus |
| 2 | C2 | 6.1–6.2 | `httpsec/reauth.go`, `httpsec/reauth_options.go`, `httpsec/reauth_test.go` (all new), `httpsec/chain.go` (the slot constant and nothing else) | Opus: policy guard written for the first time | Opus |
| 3 | B3g | 4.1 | `httpsec/ginsec/guards.go`, `httpsec/ginsec/guards_test.go` | Sonnet: mirrors the core judge | Sonnet |
| 3 | B3f | 4.2 | `httpsec/fibersec/guards.go`, `httpsec/fibersec/guards_test.go` | Sonnet: mirrors the core judge | Sonnet |
| 3 | C3 | 6.3 | `httpsec/reauth_verify.go`, `httpsec/reauth_resolve.go` (minimal), `httpsec/reauth_verify_test.go` (all new); extends `reauth.go`, `reauth_options.go` | Opus: check-then-consume challenges, throttle sharing | Opus |
| 4 | C4 | 6.4–6.6 | `httpsec/reauth_password.go` (new), completes `httpsec/reauth_resolve.go`, their tests, `httpsec/example_reauth_test.go` (new), README re-authentication section and defaults rows; read-only use of `login.go`'s password path | Opus: password refusal logic, rotation rollback | Opus |
| 5 | A2 | 7.1 | `session/sessions.go`, `session/store.go` (the `ErrRenewalConflict` godoc), `session/sessions_test.go`; in `httpsec`: the concurrent re-proof row in `reauth_resolve_test.go`, a new row in `TestMFAVerifyRotationRefusals` (`mfa_verify_test.go`), godoc in `reauth_resolve.go`, `reauth_options.go`, `mfa_verify.go` (`rotationRefusal`), `errors.go` (`ErrSessionRenewalConflict`) | Opus: ordering under races, keyed lock | Opus |
| 6 | C5 | 6.7 | `httpsec/reauth_resolve.go`, `httpsec/reauth_resolve_test.go`, `httpsec/reauth_test.go` (consumer-prefix row), `httpsec/fibersec/guards.go` (the default constant), godoc in `authenticate/passkey/doc.go`, `authenticate/passkey/register.go`, `httpsec/passkey.go`, README passkey and re-authentication sections | Sonnet: the fix and its test are stated; docs | Opus (assurance rule) |
| 7 | E1 | 6.8 (helpers) | `httpsec/mfa_verify.go` (`spendChallenge`), `httpsec/mfa_begin.go` (`sweepExpired`), `httpsec/reauth_verify.go` (their copies), a new `httpsec/challenge_spend.go` | Sonnet: identical copies moved behind one function | Sonnet |
| 7 | E2 | 6.8 (password order) | `httpsec/login.go` (the handler's order and a new method), `httpsec/reauth_password.go` (`reprove`) | Opus: a behaviour-preserving extraction in the login hot path | Opus |
| 6 | D1 | 8.1 | `test/httpsecconformance/reauth_scenarios.go` (new), its registration in `scenarios.go` | Sonnet: conformance cases in an existing suite | Sonnet |
| 6 | main | 8.2 | runs the gate; edits nothing | — | whole-branch review: Opus |

**Review-findings waves (tasks 9–11).** Wave 8 runs lanes F, G, H, I and J in parallel worktrees; lane K (section 10) starts with them, because its files are disjoint, and its 10.4 waits for wave 8's merge. Wave 9 is conformance and the gate.

| Wave | Dispatch | Tasks | Owns | Model, reason | Reviewer |
|---|---|---|---|---|---|
| 8 | F1 → F2 | 9.1, then 9.3 | `httpsec/reauth_options.go`, `httpsec/reauth_test.go`; for 9.3 also the `WithMFAChallengeStore` option in `httpsec/mfa_begin.go` (a "given" flag) and README defaults rows | Sonnet: the rules and tests are stated | Sonnet |
| 8 | G1 → G2 | 9.5, then 9.6 | `httpsec/reauth.go`, `httpsec/reauth_verify.go`, `httpsec/reauth_verify_test.go`; for 9.6 also `httpsec/mfa_verify.go`, `httpsec/mfa_begin.go` (not the store option), `httpsec/challenge_spend.go` | G1 Sonnet: a stated single-seam change; G2 Opus: behaviour-preserving extraction across two hot paths | G1 Sonnet; G2 Opus |
| 8 | H1 | 9.4 | `httpsec/reauth_password.go`, `httpsec/reauth_password_test.go` | Opus: policy refusal logic written for the first time | Opus |
| 8c | H2 | 9.8 | `policy/policy.go` (`Input`), `policy/concurrent.go`, their tests; `httpsec/reauth_password.go`, `httpsec/reauth_password_test.go` | Opus: policy refusal semantics and a field every policy reads | Opus |
| 8 | I1 | 9.2 | `httpsec/passkey.go` (`wirePasskeys`), the chain's interceptor lookup in `httpsec/options.go`, every test, Example and conformance harness chain that wires MFA and passkeys without re-authentication, README snippets | Sonnet: a stated wiring rule plus its callers | Sonnet |
| 8 | J1 | 9.7 | `internal/guardauth/*`, `httpsec/guards.go`, `httpsec/ginsec/guards.go`, `httpsec/fibersec/guards.go`, their tests | Opus: refactor extracting shared code across three packages | Opus |
| 8 | K1 → K2 → K3 | 10.1, 10.2, 10.3 | `session/store.go`, `session/session.go`, `session/store_memory.go`, `session/store_encrypted.go`, `session/sessions.go`, `session/reuse.go`, their tests; `test/storetest/*`; `store/migrate/securitystate/` (new file); `internal/pgschema/sessions.go`, `internal/storekit/*`; `store/sqlstore/session.go`, `store/pgxstore/session.go`, `store/gormstore/{session,models}.go`; `test/migrate_securitystate_test.go`, `test/gormstore/statements_test.go`, `test/*/session_test.go` | K1 Opus: an interface every store compiles against; K2 Sonnet: the known column pattern across stores; K3 Opus: ordering under races | Opus, Sonnet, Opus |
| 8b | K4 | 10.4 | `test/storetest/session_suite.go` (the two-manager case), `httpsec/reauth_resolve_test.go`, `httpsec/session_renewal_test.go` | Sonnet: conformance and test rows against stated outcomes | Sonnet |
| 10 | L1 | 9.9 | `httpsec/reauth_options.go`, `httpsec/reauth.go`, `httpsec/mfa_options.go`, `httpsec/passkey.go`, `httpsec/recovery_options.go`, `recovery/hold.go` (godoc only), `httpsec/reauth_test.go`, `README.md` | Sonnet: a stated narrowing of a wiring rule, and docs | Sonnet |
| 10 | K5 | 10.5 | `session/store.go`, `session/sessions.go` (godoc), `session/store_memory.go`, `internal/pgschema/sessions.go`, `internal/storekit/*`, `store/{sqlstore,pgxstore,gormstore}/session.go`, `test/storetest/*`, `test/migrate_securitystate_test.go` | Sonnet: the known conditional-update pattern across stores | Sonnet |
| 11 | M1 | 12.1 | `session/sessions.go` (`RotateIssuing`, `Rotate`), `session/sessions_test.go`, `httpsec/reauth_resolve.go`, `httpsec/mfa_verify.go` (`resolve` only), their tests | Opus: ordering of a write against an external step, in two hot paths | Opus |
| 11 | M2 | 12.2 | `httpsec/reauth_verify.go` (`verify`), `httpsec/reauth_verify_test.go`, `policy/policy.go` and `policy/concurrent.go` (godoc) | Opus: policy refusal logic on a new path | Opus |
| 11 | M3 | 12.3, 12.4 | `httpsec/reauth_options.go`, `httpsec/reauth_password.go`, `httpsec/reauth_test.go`, `httpsec/reauth_password_test.go`, `httpsec/fibersec/guards.go` and test | Sonnet: stated wiring rules and a stated short-circuit | Sonnet |
| 12 | M4 | 12.5 | `httpsec/reauth.go`, `httpsec/passkey_manage.go`, `httpsec/recovery_codes.go`, `httpsec/mfa_verify.go` (listing writer only), `session/session.go`, `internal/guardauth/recency.go`, their tests | Opus: behaviour-preserving extraction across packages | Opus |
| 12 | M5 | 12.6 | godoc in `httpsec/mfa_verify.go`, `httpsec/reauth_resolve.go`, `httpsec/recovery_codes.go`, `httpsec/recovery_options.go`; `README.md` | Sonnet: docs | Sonnet |
| 12 | main | 12.7 | runs the gate; edits nothing | — | whole-branch review: Opus |

| 11b | M1b | 12.1 review follow-ups | M1's files plus `httpsec/mfa_enrol_test.go` | Sonnet: the fixes are stated | Sonnet |
| 11b | M2b | 12.2 revised (D6 "Every deny binds") | M2's files; `httpsec/reauth_options.go` godoc of the verify bullet | Opus: security refusal logic, a reproduced fail-open | Opus |
| 11c | M2c | 12.2 federated evidence and godoc (Step 7) | M2's files; `policy/mfa_requirement.go`, `session/sessions_options.go` (godoc) | Sonnet: the fix is stated and shown to work | Sonnet |
| 11c | M1c | 12.1 test-strength follow-ups | `session/sessions_test.go`, `httpsec/mfa_enrol_test.go` | Sonnet: stated test gaps | Sonnet |

- Wave 11 runs M1, M2 and M3 in parallel worktrees (disjoint files). M3 merged after review. M1 and M2 came back with review findings, so wave 11b re-dispatches both on their own branches, in parallel (disjoint files). Wave 12 runs M4 after wave 11 merges (it touches `mfa_verify.go` after M1), then M5, then the gate.

| 9 | D2 | 11.1 | `test/httpsecconformance/reauth_scenarios.go` | Sonnet: conformance cases in an existing suite | Sonnet |
| 9 | main | 11.2 | runs the gate; edits nothing | — | whole-branch review: Opus |

- I1 touches test files other lanes may also edit (chains built in shared fixtures); its worktree merges last in wave 8 and the main session resolves any overlap.
- K4 runs after wave 8 is merged, because its `httpsec` rows sit beside G and H's.

**As run:** waves 1–4 ran as above. Worktrees created with `isolation: "worktree"` started from `main`, so every dispatch's first step fast-forwards to the head of `feat/reauthentication`. C4 runs on its branch until Task 13 lands on it, so wave 4 and wave 5 merge together.

**Compile order:**
- B2 consumes A1's `AuthenticatedWithin` and B1's error type.
- C2 consumes B1's `ErrReauthenticationMethodNotUsable`. C2 also changes C1's files only by calling their unexported helpers, never by editing them.
- B3 consumes B2's exported names.
- C3 and C4 extend C2's files, in their own lane.
- A2 runs on C4's branch, after C4, because it changes C4's concurrent re-proof row.
- C5 runs after D1 and the whole-branch review, which raised it; the gate (8.2) waits on C5.
- E1 and E2 run in parallel worktrees (disjoint files) after C5; the gate (8.2) reruns after both merge.

**Waits:** each wave starts only when the previous wave is merged, verified green, and reviewed clean. Each dispatch's prompt carries:
- the Global Constraints;
- its owned and forbidden files;
- the red-step rule;
- its verification commands;
- the report format: files changed, tests added, the failing output seen at each red step, the final suite output, and anything unfinished.

---

### Task 1: The freshness check (tasks.md 1.1)

**Files:**
- Modify: `session/session.go`
- Test: `session/session_test.go`

**Interfaces:**
- Produces: `func (s *Session) AuthenticatedWithin(now time.Time, window time.Duration) bool`

- [ ] **Step 1: Write the failing test.** `TestAuthenticatedWithin`, a table with `assert func(t *testing.T, got bool)`, with `AuthenticatedAt = 09:00` and window `15m`:

  | now | expected |
  |---|---|
  | 09:10 | true |
  | 09:15:00 | true |
  | 09:15:01 | false |

  Also: `AuthenticatedAt = 09:00:05`, `now = 09:00:00` gives true; `AuthenticatedAt = 12:00`, `now = 09:00` gives true (Review Focus); zero `AuthenticatedAt` with a `24h` window gives false.

  Add `TestSave_KeepsAuthenticatedAt` against `NewMemoryStore`: load, set `AuthenticatedAt` an hour later, `Save`, reload, and assert unchanged.
- [ ] **Step 2: Run and see it fail.** `go test -race -run 'TestAuthenticatedWithin' ./session/` fails as undefined. That is a compile failure, so stub the method to `return false`, rerun, and see the `true` rows fail. `TestSave_KeepsAuthenticatedAt` pins existing behaviour: invert `session/store_memory.go:299` (`rec.AuthenticatedAt = stored.AuthenticatedAt`) temporarily, see it fail, then restore.
- [ ] **Step 3: Implement** the rule `!s.AuthenticatedAt.IsZero() && now.Sub(s.AuthenticatedAt) <= window`, with godoc naming the inclusive end, the future case and the zero case.
- [ ] **Step 4: Run.** `go test -race ./session/` passes.
- [ ] **Step 5: Commit** `feat(session): one check for authenticated within a window`.

### Task 2: Existing freshness checks use it (tasks.md 1.2)

**Files:**
- Modify: `httpsec/recovery_codes.go:150-160`, `authenticate/passkey/passkey.go:~448`, README (the recovery and passkey freshness sentences)
- Test: `httpsec/recovery_codes_test.go` (`TestRecoveryCodes`), `authenticate/passkey/register_test.go` (`TestBeginRegistration`), `authenticate/passkey/manage_test.go` (`TestManageRemove`)

**Interfaces:**
- Consumes: Task 1's `AuthenticatedWithin`.

- [ ] **Step 1: Add cases.** "exactly at the window's end is admitted", at 09:15:00 for 09:00, and "zero authentication time is refused" (`ErrReauthenticationRequired` of each package), to each of the three tests.
- [ ] **Step 2: Red by inversion.** Change each `>` to `>=` temporarily and see the end-of-window case fail. Restore.
- [ ] **Step 3: Replace the comparisons** with `!s.AuthenticatedWithin(now, window)`. Godoc and README say "the session's authentication time (sign-in, satisfied second factor or re-authentication)".
- [ ] **Step 4: Run.** `go test -race -run 'TestRecoveryCodes|TestManage|TestBeginRegistration' ./httpsec/ ./authenticate/passkey/` passes.
- [ ] **Step 5: Commit** `refactor: recovery and passkey freshness use the shared check`.

### Task 3: Refusals (tasks.md 2.1)

**Files:**
- Modify: `httpsec/errors.go` (the declarations, and two rows in the 403 block beside `passkey.ErrReauthenticationRequired`)
- Test: `httpsec/errors_test.go`

**Interfaces:**
- Produces:

  ```go
  var ErrReauthenticationRequired = errors.New("httpsec: reauthentication required")
  var ErrReauthenticationMethodNotUsable = errors.New("httpsec: reauthentication method not usable")
  type ReauthenticationRequiredError struct{ Window time.Duration }
  func (e *ReauthenticationRequiredError) Error() string    // "httpsec: reauthentication required within <window>"
  func (e *ReauthenticationRequiredError) Is(target error) bool // target == ErrReauthenticationRequired
  ```

- [ ] **Step 1: Write the failing tests.**
  - `TestReauthenticationRequiredError`: `errors.Is(&ReauthenticationRequiredError{Window: 5*time.Minute}, ErrReauthenticationRequired)`; `errors.As` gives `5m`; the text contains no `sess-`, user or handle fixture.
  - `TestStatusForError` gains rows for both sentinels and for the wrapped type, each 403.
  - `sentinelRegistry` gains `"httpsec.ErrReauthenticationRequired"` and `"httpsec.ErrReauthenticationMethodNotUsable"`.
- [ ] **Step 2: Run and see it fail.** Stub the declarations first so the failure is the 500 status and the missing `Is`, not a compile error.
- [ ] **Step 3: Implement** the declarations, the rows, and godoc naming the raising guard or endpoint.
- [ ] **Step 4: Run.** `go test -race -run 'TestStatusForError|TestRefusalSentinelsAreDistinct|TestReauthenticationRequiredError' ./httpsec/` passes.
- [ ] **Step 5: Commit** `feat(httpsec): reauthentication refusals`.

### Task 4: Guard options (tasks.md 3.1)

**Files:**
- Modify: `httpsec/guards.go`
- Test: `httpsec/guards_test.go` (`TestNewGuards_Authorizer` grows into `TestNewGuards`)

**Interfaces:**
- Produces:

  ```go
  const DefaultRecentAuthenticationWindow = 15 * time.Minute
  func WithRecentAuthenticationWindow(d time.Duration) GuardOption
  func WithGuardClock(c clock.Clock) GuardOption
  func WithAuthenticationTime(fn func(ctx context.Context) (time.Time, bool)) GuardOption
  ```

  New `Guards` fields: `window`, `clock`, `clockSet`, `authTime`, `authTimeSet`.

- [ ] **Step 1: Failing table cases.** Each of these is `errors.Is(err, ErrConfig)` with the option's name in the message: window `0`, window `-1s`, `WithGuardClock(nil)`, `WithGuardClock((*fakeClock)(nil))`, `WithAuthenticationTime(nil)`. "Defaults" builds with no options and expects success.
- [ ] **Step 2: Run and see** the five error cases fail with a nil error.
- [ ] **Step 3: Implement.** The options record their value and a "given" flag. `NewGuards` validates after options run, using `internal/nilcheck.IsNil` for the clock and the time source so a typed nil is caught, the same check `internal/guardauth.Fallback` applies to the authorizer.
- [ ] **Step 4: Run.** `go test -race -run 'TestNewGuards' ./httpsec/` passes.
- [ ] **Step 5: Commit** `feat(httpsec): recency options on guards`.

### Task 5: The recency guard (tasks.md 3.2–3.3)

**Files:**
- Modify: `httpsec/guards.go`, README (guards section and defaults rows)
- Create: `httpsec/example_guards_test.go`
- Test: `httpsec/guards_test.go`

**Interfaces:**
- Consumes: Task 1, Task 3, Task 4.
- Produces:

  ```go
  func (g *Guards) RequireRecentAuthentication() func(http.Handler) http.Handler
  func (g *Guards) RequireAuthenticationWithin(window time.Duration) func(http.Handler) http.Handler
  ```

- [ ] **Step 1: Write the failing tests.**
  - `TestRecencyGuard`, a table over a controlled clock and a session published with `withSession`. It has one case per scenario of the seven `reauthentication` guard requirements listed in tasks.md 3.2, including:
    - 09:10 fresh, 09:16 stale, 09:15 exact;
    - renewed-at-09:10 still stale at 09:20;
    - zero time with 24h;
    - repeated use at 09:05, 09:10 and 09:14 then 09:16 refused;
    - re-authenticated at 09:30 fresh at 09:40;
    - guards-wide 2h;
    - per-route 5m at 09:06;
    - an API-key principal with no session;
    - a consumer time source reporting 09:00, and one reporting none;
    - a future authentication time (Review Focus);
    - no principal gives 401 `ErrAuthenticationRequired`;
    - no authorizer gives `authorize.ErrAccessDenied`;
    - behind `ResourcePrivileges("projects","project").RequireAny("delete")` gives access denied;
    - the default response is 403 with an empty body;
    - an error handler receives `*ReauthenticationRequiredError{Window: 5*time.Minute}`.

    Assertions are on `routeCalled`, `errors.As` window, status and body.
  - `TestGuardsWiringPanics` gains `RequireAuthenticationWithin(0)` and `(-time.Second)`, whose panic message contains `"window"`, and nil-receiver panics for both methods.
- [ ] **Step 2: Run and see** each case fail on an undefined method. Stub both methods to pass every request, rerun, and see the stale cases fail on `routeCalled`.
- [ ] **Step 3: Implement** both as judges on `g.guard`. The time comes from `g.authTime` when set, else from `SessionFromContext(ctx)`. A missing time refuses. Otherwise refuse unless `s.AuthenticatedWithin(g.clock.Now(), window)`. The per-route window is validated when the guard is built. Godoc per tasks.md 3.3. `ExampleGuards_RequireRecentAuthentication` shows a route guarded by privilege, then recency.
- [ ] **Step 4: Run.** `go test -race -run 'TestRecencyGuard|TestGuardsFailClosed|TestGuardsWiringPanics|Example' ./httpsec/` and `go vet ./httpsec/` pass.
- [ ] **Step 5: Commit** `feat(httpsec): recency guard`.

### Task 6: Re-authentication wiring, admission and listing (tasks.md 5.1 precedes; this is 6.1–6.2)

**Files:**
- Create: `httpsec/reauth.go` (interceptor, dispatch, admission, policy, listing), `httpsec/reauth_options.go`, `httpsec/reauth_test.go`
- Modify: `httpsec/chain.go` (only `OrderReauthentication Order = 655`, with godoc between `OrderPasswordChange` and `OrderPasskeys`)

**Interfaces:**
- Consumes: Task 3's `ErrReauthenticationMethodNotUsable`. From the MFA slot (`c` config): methods, `lookups`, the throttle. From form login: its presence, its `preAuthenticate`, `verifyPassword`, `resetFailures` and its source guard. `writeJSON`-style helpers already used by `writeMFABegin`.
- Produces: design D6's `EnableReauthentication`, `ReauthenticationOption`, `DefaultReauthenticationPrefix`, every `WithReauthentication…` option, `RequireSecondFactorForReauthentication`, `ReauthenticationResult`, `ReauthenticationResponder`, `ReauthenticationMethods`, `ReauthenticationMethodsResponder`. Internally: `func (i *reauthInterceptor) offered(ctx context.Context, s *session.Session) (methods []mfa.Method, password bool, err error)`, the single policy decision every endpoint calls.

- [ ] **Step 1: Write the failing tests.**
  - `TestEnableReauthentication`, a table of construction cases, each `errors.Is(err, ErrConfig)`:
    - no MFA and no form login;
    - second-factor-only without MFA;
    - `WithReauthenticationPrefix("")`;
    - prefix `/mfa/verify`;
    - prefix equal to the logout path;
    - prefix equal to the login path;
    - the listing path colliding with `/mfa/methods`;
    - enabled twice;
    - a JWT chain without `WithReauthenticationTokens`;
    - `WithReauthenticationChallengeTTL(0)`;
    - `WithReauthenticationChallengeLimit(0)`;
    - a nil store and a nil responder.

    Plus "off by default": POST `/reauth/password` reaches the app handler. "Consumer prefix": `/account/confirm/methods` answers. "GET `/reauth/verify/totp` passes through" (Review Focus).
  - `TestOrder` gains `OrderReauthentication` between 650 and 660.
  - `TestReauthAdmission`: no session gives 401; pending MFA gives `*ChallengeError` of kind MFA; pending password change gives a password-change challenge; enrolment-only and recovery-pending are refused by their gates; a reordered chain (interceptor registered before the gates) refuses a pending session as `ErrAuthenticationRequired`.
  - `TestReauthMethods` covers:
    - a TOTP holder gives `{"methods":[{"name":"totp","channel":"authenticator-app","begins":false}],"password":false}`;
    - no-MFA user with form login gives `{"methods":[],"password":true}`;
    - second-factor-only and no MFA gives `{"methods":[],"password":false}`;
    - a lookup error is refused, wrapping the store error, with no body;
    - a consumer responder receives the same `ReauthenticationMethods`;
    - the response carries `Cache-Control: no-store`.
- [ ] **Step 2: Run and see it fail.** Undefined symbols are a compile failure, so first add the option and type declarations with an interceptor that passes everything through. Then see the construction cases return nil and the listing cases reach the app.
- [ ] **Step 3: Implement.**
  - Wiring through `c.enable` and `c.register(i, OrderReauthentication)`, after the MFA slot and form login are known.
  - Admission: session, caller, `MFA` ∈ {None, Satisfied}, `!PasswordChangePending`, zero enrolment and recovery markers.
  - `offered`: `policy.UsableMFAMethods` is **not** used, because it excludes the first factor's channel (D4). Iterate the slot's lookups calling `Enrolled`. The first error refuses. `password = len(methods) == 0 && formLogin != nil && !secondFactorOnly`.
  - The listing, with its default responder.
- [ ] **Step 4: Run.** `go test -race -run 'TestEnableReauthentication|TestOrder|TestReauthAdmission|TestReauthMethods' ./httpsec/` passes.
- [ ] **Step 5: Commit** `feat(httpsec): re-authentication wiring, admission and method listing`.

### Task 7: Second-factor begin and verify (tasks.md 6.3)

**Files:**
- Create: `httpsec/reauth_verify.go`, `httpsec/reauth_resolve.go` (minimal resolve), `httpsec/reauth_verify_test.go`
- Modify: `httpsec/reauth.go` (dispatch), `httpsec/reauth_options.go` (challenge managers)

**Interfaces:**
- Consumes: Task 6's `offered` and admission. The MFA slot's `*mfa.VerifyThrottle`. `readResponse`, `methodSegment` and `spendChallenge`'s logic from `mfa_verify.go`, called and not edited. `onetime.New(purpose, …)`.
- Produces: `func (i *reauthInterceptor) resolve(ex *Exchange, s *session.Session, secondFactor bool) error` in `reauth_resolve.go`. Here it only refreshes, rotates and responds minimally, so these tests can assert success; Task 8 completes it in the same file.

- [ ] **Step 1: Write the failing tests.**
  - `TestReauthVerify` covers:
    - a valid TOTP re-proves;
    - `/reauth/verify/sms` gives `ErrUnknownMFAMethod` with no throttle record (assert the mock limiter saw no `RecordFailure`);
    - `/reauth/verify/TOTP` gives `ErrUnknownMFAMethod` (Review Focus);
    - passkey not enrolled gives `ErrReauthenticationMethodNotUsable`, nothing counted;
    - a wrong code gives `mfa.ErrInvalidCode` with one failure on key `mfa.VerifyThrottleKey(u)`, and the session is unchanged;
    - four failures at `/mfa/verify` plus one at `/reauth/verify`, then a valid code, gives `mfa.ErrVerifyThrottled`;
    - a reused step gives invalid code;
    - a passkey-login session re-proves with the passkey (no `mfa.ErrSameChannel`);
    - a clone and a suspended credential give `passkey.ErrCloneSuspected` and `ErrSuspended`, uncounted, with the user's sessions ended under the default clone response.
  - `TestReauthBegin` covers:
    - begin gives a document with `Cache-Control: no-store`;
    - a challenge from `/mfa/begin/passkey` presented to `/reauth/verify/passkey` gives invalid code, counted;
    - another session's challenge gives invalid code, counted;
    - expiry at 6 minutes with the default TTL;
    - the 11th begin in an hour gives `mfa.ErrVerifyThrottled` with no challenge issued;
    - TTL `2m`, answered at 3 minutes, gives invalid code;
    - a throttled user's begin is refused.
- [ ] **Step 2: Run and see** each fail at dispatch, as the request reaches the app.
- [ ] **Step 3: Implement** the D6 verify order, and begin as admission, policy, throttle check, sweep, then `IssueWithin(ctx, user, limit, WithBinding(s.ID))`. Purposes are `"reauth-challenge:" + name`. The challenge stores join the chain's expiry sweep beside the MFA ones.
- [ ] **Step 4: Run.** `go test -race -run 'TestReauthVerify|TestReauthBegin' ./httpsec/` passes.
- [ ] **Step 5: Commit** `feat(httpsec): second-factor re-authentication`.

### Task 8: Password re-proof, resolve, docs (tasks.md 6.4–6.6)

**Files:**
- Create: `httpsec/reauth_password.go`, `httpsec/reauth_password_test.go`, `httpsec/reauth_resolve_test.go`, `httpsec/example_reauth_test.go`
- Modify: `httpsec/reauth_resolve.go` (complete resolve), `httpsec/reauth.go` (dispatch), README (the re-authentication section after the guards section, and defaults rows)
- Test, additionally: `httpsec/recovery_codes_test.go` and `httpsec/passkey_register_test.go` (one case each)

**Interfaces:**
- Consumes: the form login's `preAuthenticate`, `verifyPassword` (which returns the proved `*authenticate.Authentication`), `resetFailures` and its source guard (`sourceThrottled`, `recordSourceFailure`), called and not edited. `Sessions.Rotate`, `rotationRefusal`, the credential issuer and `withSession`, as `mfa_verify.go` uses them.

- [ ] **Step 1: Write the failing tests.**
  - `TestReauthPassword` covers:
    - a correct password re-proves and the attempt store's `Reset` is called;
    - `username=u-9` with `u-9`'s password gives `ErrAuthenticationFailed`, with the failure recorded for `u-2`'s username;
    - a JSON `{"username":"u-9","password":"…"}` behaves the same (Review Focus);
    - a wrong password is recorded and the session is unchanged;
    - locked gives the login's locked refusal and the encoder's `Match` is never called;
    - a user with no hash gives authentication failed;
    - a missing field gives `ErrCredentialsMissing` with nothing recorded;
    - an oversized body gives `ErrRequestTooLarge`;
    - the store unavailable gives `authenticate.ErrUnavailable`, unrecorded;
    - a TOTP holder gives `ErrReauthenticationMethodNotUsable` with the body unread (a reader that fails if read) and nothing recorded;
    - an enrolment lookup failure is refused and the password is not checked;
    - second-factor-only with a no-MFA user gives method not usable;
    - an empty principal username gives authentication failed;
    - a pre-authentication policy refusal is not charged to the source (limiter of 1 per hour: the second post is refused by the policy, not by `ratelimit` throttling) (D6);
    - a caller whose ID is not the session's user is refused before any password is checked, nothing recorded (D6);
    - a caller whose username alone names another user, with that user's password, is refused before anything is reset or refreshed (D6);
    - a refused password is charged to the request's source.
  - `TestReauthResolve` covers:
    - TOTP at 09:30 sets `AuthenticatedAt` and `MFASatisfiedAt` to 09:30 from the chain's controlled clock, the old handle no longer loads, and the credential authenticates the next request;
    - a password re-proof keeps `MFA == MFANone`;
    - an `MFANone` session that re-proves with TOTP becomes `MFASatisfied`;
    - a session authenticated one minute ago is still served and re-proves ("A fresh session re-proves");
    - with second-factor-only on, a new sign-in of a user with no second factor passes the recency guard ("A fresh sign-in still makes the session fresh");
    - the recency guard passes with the new credential;
    - two concurrent valid re-proofs give exactly one success and one refusal, the winner's session the only one; Task 13 turns the refusal into `ErrSessionRenewalConflict`;
    - a re-proof racing a renewal gives one 409 and the winner's session loads (Review Focus);
    - in session-reference bearer mode a new reference is returned and the old one refused; in JWT mode a new token is returned (Review Focus);
    - a consumer responder receives the rotated session and the library writes nothing;
    - the default response has `Cache-Control: no-store`;
    - refusal log records (a capturing slog handler) contain neither the password nor the code.
  - `TestRecoveryCodes` gains "fresh after a re-authentication": created at 09:00, re-proved at 09:30, posting at 09:40, gets a new set.
  - `TestPasskeyRegistration` gains "freshness from a re-authentication".
- [ ] **Step 2: Run and see** the password cases reach the app, and the resolve cases fail on Task 7's minimal resolve: no rollback, no session-bearer reference, no `MFASatisfied` change.
- [ ] **Step 3: Implement** the password order from D6 (source charged exactly as login charges it; the caller's ID and the proved account both checked against `s.UserID`), and the full resolve: set the fields; `RestoreEnrolmentDeadlines` is not called (full sessions only); `Rotate` with rollback; publish; issue; respond through the default `no-store` responder. Write godoc and the README per tasks.md 6.6. `ExampleEnableReauthentication` wires MFA, form login, re-authentication and a recency-guarded route.
- [ ] **Step 4: Run.** `go test -race -run 'TestReauthPassword|TestReauthResolve|TestRecoveryCodes|TestPasskeyRegister|Example' ./httpsec/` passes, then `go test -race ./httpsec/...` passes.
- [ ] **Step 5: Commit** `feat(httpsec): password re-authentication and session refresh`.

### Task 9: MFA endpoints serve only a pending session (tasks.md 5.1)

Wave 1, lane C, runs before Task 6.

**Files:**
- Modify: `httpsec/mfa_verify.go` (`verify`), `httpsec/mfa_begin.go` (`begin`), and their godoc and `EnableMFA`'s godoc in `mfa_options.go`
- Test: `httpsec/mfa_verify_test.go`, `httpsec/mfa_begin_test.go`, plus callers found by the sweep

**Interfaces:**
- Produces: unchanged signatures. The behaviour is the D5 refusal.

- [ ] **Step 1: Write the test of today's behaviour.** `TestMFAVerify_FullSessionRefused` posts a valid code from an `MFASatisfied` session and asserts `ErrNoMFAChallengePending`, no `Verify` call, no `RecordFailure`, and the handle unchanged. Add a begin twin, an "`MFANone` session of a user enrolled later" case (its authentication time unchanged), "no session first" (401), and "a pending session still served".
- [ ] **Step 2: Run and see** the full-session cases fail **because the request is accepted and the session rotated**. Record that output: it is the evidence that the behaviour was unpinned (D5, not a defect claim).
- [ ] **Step 3: Implement.** In `verify` and `begin`, right after `admit`'s session and caller checks and before the method name is read, refuse `s.MFA != session.MFAPending`. This is a small helper called by both, keeping `admit`'s order. Then sweep the full workspace for verify or begin calls from non-pending sessions with `gopls` references on the endpoint helpers in tests, `test/httpsecconformance` and Examples, and fix them.
- [ ] **Step 4: Run.** `go test -race -run 'TestMFAVerify|TestMFABegin|TestMFAGate' ./httpsec/` passes, then `go test ./...` in `test` passes.
- [ ] **Step 5: Commit** `refactor(httpsec)!: MFA verify and begin serve only a pending session`.

### Task 10: Adapter recency guards (tasks.md 4.1, 4.2)

Two parallel dispatches, one per module.

**Files:**
- Modify: `httpsec/ginsec/guards.go`, `httpsec/fibersec/guards.go`
- Test: `httpsec/ginsec/guards_test.go` (`TestGinGuards`, `TestGin_NewGuards_Authorizer`, wiring-panic tests), `httpsec/fibersec/guards_test.go` (the matching tests)

**Interfaces:**
- Consumes: `httpsec.DefaultRecentAuthenticationWindow`, `*httpsec.ReauthenticationRequiredError`, `httpsec.SessionFromContext`, `session.(*Session).AuthenticatedWithin`, `clock.Clock`.
- Produces: the same three option names and two method names in each package, returning `gin.HandlerFunc` or `fiber.Handler`.

- [ ] **Step 1: Write the failing tests.**
  - gin:
    - stale (16 minutes) gives the handler not called, `gc.Errors` holding the refusal, and status 403;
    - fresh (5 minutes) is called;
    - per-route 5m at 6 minutes gives the window `5m` in the refusal;
    - `RequireAuthenticationWithin(0)` panics, naming the window;
    - each construction error from Task 4.
  - fiber:
    - stale gives a returned error where `errors.As(*httpsec.ReauthenticationRequiredError)` holds window `15m`, and `fibersec.ErrorHandler` renders 403;
    - fresh is called;
    - `WithGuardClock(nil)` gives `ErrConfig`;
    - the wiring panic.
- [ ] **Step 2: Run and see** an undefined method (compile). Stub to pass, and see the stale cases fail.
- [ ] **Step 3: Implement**, mirroring Task 5's judge in each adapter's `guard`. Godoc as in tasks.md 3.3.
- [ ] **Step 4: Run.** `go test -race ./...` passes in `httpsec/ginsec` and in `httpsec/fibersec`.
- [ ] **Step 5: Commit** `feat(ginsec,fibersec): recency guard`.

### Task 13: A lost strict rotation is a renewal conflict (tasks.md 7.1)

Done. Its in-process memory is the first cut that Tasks 19–22 (section 10) replace with the store-decided mark; its within-window outcomes stay pinned.

**Files:**
- Modify: `session/sessions.go` (`Sessions` fields beside `rotating`, `Rotate`, its godoc), `session/store.go` (`ErrRenewalConflict` godoc: "a concurrent rotation")
- Modify, godoc only: `httpsec/reauth_resolve.go`, `httpsec/reauth_options.go`, `httpsec/mfa_verify.go` (`rotationRefusal`), `httpsec/errors.go` (`ErrSessionRenewalConflict`)
- Test: `session/sessions_test.go`, `httpsec/reauth_resolve_test.go`, `httpsec/mfa_verify_test.go`

**Interfaces:**
- Consumes: `Sessions.Rotate(ctx, s) (*Session, error)`, `DefaultRenewalGrace`, `sessionDigest`, the manager clock, `keyedMutex`.
- Produces: no new exported name. `Rotate` returns `ErrRenewalConflict` for a handle it rotated within the in-flight window; `rotationRefusal` already maps that to `ErrSessionRenewalConflict` (409).

- [ ] **Step 1: Write the failing tests.**
  - `session/sessions_test.go`: "a handle already rotated away cannot be rotated again" becomes two rows: rotated at 09:00:00, again at 09:00:10 gives `ErrRenewalConflict`; again at 09:00:31 gives `ErrNotFound`. A never-rotated session whose family was revoked gives `ErrNotFound`. `Load` of the old identifier right after a rotation gives `ErrNotFound` and the successor still loads (no family revocation). `TestManagerRotateConcurrent`: every loser is `ErrRenewalConflict` and the family holds one live head.
  - `httpsec/reauth_resolve_test.go`: the concurrent re-proof row expects `ErrSessionRenewalConflict`, `session.ErrRenewalConflict` in the chain, and 409.
  - `httpsec/mfa_verify_test.go` `TestMFAVerifyRotationRefusals`: two valid codes at once from one pending session give one success and one `ErrSessionRenewalConflict`; the winner's credential authenticates the next request.
- [ ] **Step 2: Run and see** the rows fail with `ErrNotFound` / `ErrAuthenticationRequired` where the conflict is expected.
- [ ] **Step 3: Implement.** After `Supersede` succeeds and while the per-session lock is held, record the old handle's digest until `acceptUntil`. In `Rotate`, when `loadStored` returns `ErrNotFound` and the digest is recorded and unexpired, return `ErrRenewalConflict` without a store write or `judge`. Bound the record, pruning expired entries first-in-first-out. Godoc on `Rotate` states the window and that across managers sharing a store a loser may still get `ErrNotFound`.
- [ ] **Step 4: Run.** `go test -race -count=1 ./session/ ./httpsec/` passes, then `go test ./...` in `test`.
- [ ] **Step 5: Commit** `feat(session): a lost strict rotation is a renewal conflict`.

### Task 14: A same-channel re-proof refreshes freshness only (tasks.md 6.7)

**Files:**
- Modify: `httpsec/reauth_resolve.go` (`resolve`), `httpsec/fibersec/guards.go` (`DefaultRecentAuthenticationWindow = httpsec.DefaultRecentAuthenticationWindow`)
- Modify, docs: `authenticate/passkey/doc.go`, `authenticate/passkey/register.go`, `httpsec/passkey.go`, README (passkey section; re-authentication "Endpoints")
- Test: `httpsec/reauth_resolve_test.go`, `httpsec/reauth_verify_test.go` (E2E passkey row), `httpsec/reauth_test.go`

**Interfaces:**
- Consumes: `resolve(ex, s, secondFactor bool)`; the channel test `/mfa/verify` applies to a method against `s.FirstFactor` (the same-channel rule's helper in `mfa_verify.go` or `policy`, called and not edited).
- Produces: `resolve` takes the verified method's channel (or the method) so it can decide; signature change owned here with its callers in `reauth_verify.go` and `reauth_password.go`.

- [ ] **Step 1: Write the failing tests.**
  - `TestReauthResolve` "a same-channel re-proof refreshes freshness only": `WithoutSecondFactorAtLogin`-style wiring so a passkey sign-in leaves `MFA == MFANone`; that session re-proves at `/reauth/verify/passkey` at 09:30 → `AuthenticatedAt == 09:30`, `MFA == MFANone`, `MFASatisfiedAt` zero, new credential returned.
  - The E2E "a passkey login re-proves with the passkey" row: where the passkey login already met the second factor, the state stays `MFASatisfied` and `MFASatisfiedAt` is unchanged (not moved to the re-proof time).
  - "a different channel meets the second factor": a password session re-proves with TOTP → `MFASatisfied`, `MFASatisfiedAt == now` (existing row; keep).
  - `TestEnableReauthentication` "a consumer prefix moves the endpoints" also posts a valid TOTP code to `/account/confirm/verify/totp` → 200 with a new credential.
- [ ] **Step 2: Run and see** the same-channel row fail with `MFA == MFASatisfied`.
- [ ] **Step 3: Implement.** `resolve` sets `MFA`/`MFASatisfiedAt` only for a second factor whose channel differs from the session's first factor; rollback covers only the fields it changed. Alias the fiber default. Rewrite the step-up docs: a full session re-proves at `/reauth`, not `/mfa/verify`; a same-channel re-proof refreshes freshness without meeting the second factor. README re-authentication "Endpoints": a session owing a challenge is refused by that challenge's gate with its challenge error; a concurrent re-proof or MFA verification on one server gets 409.
- [ ] **Step 4: Run.** `go test -race -count=1 ./httpsec/... ./authenticate/passkey/...`, `go test ./...` in `httpsec/fibersec`, `go vet`.
- [ ] **Step 5: Commit** `fix(httpsec): a same-channel re-proof refreshes freshness only`.

### Task 15: One implementation per control (tasks.md 6.8)

Two parallel dispatches. Behaviour is unchanged, so existing tests are the safety net and each red step is a temporary divergence in the shared code that a login or MFA test and a re-proof test both catch.

**Files (E1, helpers):**
- Create: `httpsec/challenge_spend.go`
- Modify: `httpsec/mfa_verify.go` (`spendChallenge`), `httpsec/mfa_begin.go` (`sweepExpired`), `httpsec/reauth_verify.go` (remove both copies)

**Files (E2, password order):**
- Modify: `httpsec/login.go` (the login handler's order at ~325-360), `httpsec/reauth_password.go` (`reprove`)

**Interfaces:**
- Produces (E1): `func spendChallenge(ctx context.Context, mgr *onetime.Tokens, cm mfa.ChallengeMethod, s *session.Session, response []byte) error` and `func sweepExpired(ctx context.Context, mgr *onetime.Tokens, clock *sweepClock, now time.Time, flow, message string, sampler *logsample.Sampler, log *slog.Logger)`, package-level; the two interceptors keep thin methods or call them directly. Exact parameter types follow the current bodies.
- Produces (E2): `func (l *formLogin) attemptPassword(ctx context.Context, clientIP, username string, password []byte, now time.Time) (*authenticate.Authentication, error)`: source throttle, pre-authentication with the lock refusal and its source charge, the password check with its source charge. It does not reset failures: login resets after it, and the re-proof resets only after confirming the proved account is the session's.

- [ ] **Step 1: Red by divergence.** E1: in the shared `spendChallenge`, temporarily skip the session-binding check; see an MFA verify test and a re-proof test both fail ("another session's challenge"). Restore. E2: in `attemptPassword`, temporarily stop charging the source on a lock; see a login lockout test and the re-proof locked/source rows both fail. Restore.
- [ ] **Step 2: Extract** as above; delete the copies; login and `reprove` call `attemptPassword`.
- [ ] **Step 3: Run.** `go test -race -count=1 ./httpsec/...`, `go vet ./httpsec/`, `golangci-lint run ./httpsec/`, and `go test ./...` in `test`.
- [ ] **Step 4: Commit** `refactor(httpsec): one challenge spend and sweep for MFA and re-proof` (E1) and `refactor(httpsec): one password order for login and re-proof` (E2).

### Task 16: Re-proof paths are checked by how each endpoint matches (tasks.md 9.1)

**Files:**
- Modify: `httpsec/reauth_options.go` (`checkPaths(c *config, option string) error`, ~272)
- Test: `httpsec/reauth_test.go` (`TestEnableReauthentication`)

**Interfaces:**
- Consumes: `eachInterceptor[T](c, fn)` (`options.go:300`); `*passkeyInterceptor` `regPrefix`, `credPrefix`; `*enrolmentInterceptor` `beginPrefix`, `confirmPrefix`, `emailPrefix`; `*sessionRenewal` `path`; `*passwordChangeGate` `path` (when set); `*recoveryInterceptor` `startPath`, `finishPath`, `completePath`, `cancelPath`, `codesPath`; `*magicLinkInterceptor`, `*oidcInterceptor` and `*passwordlessInterceptor` paths, each marked prefix or exact as its `Intercept` matches; the existing logout, form-login, MFA verify, begin and listing entries.
- Produces: no new name. Each entry carries `prefix bool` (matched by prefix); `collides(a, b)` is true when `a == b`, or `b` is a prefix entry and `a` lies under it, or the reverse.

- [ ] **Step 1: Write the failing rows** in `TestEnableReauthentication`:
  - six refusals, `require.ErrorIs(err, ErrConfig)` and the message names the other endpoint: prefix `/passkey/register`; prefix `/passkey/credentials`; prefix `/mfa/enrol`; `WithRenewalPath("/reauth/password")`; `WithPasswordChangeEndpoint("/reauth/password", …)`; `WithRecoveryStartPath("/reauth/password")`;
  - prefix `/passkey/register/` refused like `/passkey/register` (Review Focus);
  - `the_prefix_is_the_form_login_path` and `the_prefix_is_the_logout_path` rewritten: prefix `/login/reauth` and `/logout/reauth` build, `/login` reaches form login and `/login/reauth/methods` the listing.
- [ ] **Step 2: Run** `go test -run TestEnableReauthentication -count=1 ./httpsec/` and see six "expected an error but got nil" and two "collides with the form login path"/"logout path" failures, as `TestReproReauthPathCollisionRefused` and `TestReproReauthPrefixUnderFormLoginPathIsAllowed` showed.
- [ ] **Step 3: Implement** the entries above with logout and form login exact (`prefix: false`), and `collides` in both directions.
- [ ] **Step 4: Run** `go test -race -count=1 -run 'TestEnableReauthentication|TestReauth' ./httpsec/`: PASS.
- [ ] **Step 5: Commit** `fix(httpsec): re-proof paths collide by how each endpoint matches`.

### Task 17: MFA and passkeys need re-authentication (tasks.md 9.2)

**Files:**
- Modify: `httpsec/passkey.go` (`(*config).wirePasskeys`), `httpsec/options.go` (a `reauthOf() *reauthInterceptor` lookup beside `mfaOf`, if absent)
- Modify, callers: every chain in `httpsec` tests and Examples, `test/httpsecconformance` harnesses and README snippets that enable MFA and passkeys without `EnableReauthentication`
- Test: `httpsec/passkey_register_test.go` (or the passkey wiring test file)

**Interfaces:**
- Produces: `New` returns `ErrConfig` with a message naming `EnableReauthentication` when `c.mfaOf() != nil && c.reauthOf() == nil` and passkeys are enabled.

- [ ] **Step 1: Write the failing rows:** MFA + passkeys, no re-authentication → `ErrorIs(err, ErrConfig)` and `ErrorContains(err, "EnableReauthentication")`; MFA without passkeys → builds; MFA + passkeys + re-authentication: an `MFANone` session of a TOTP holder posts a valid code to `/reauth/verify/totp`, then `MFA == MFASatisfied` and passkey registration begin is served.
- [ ] **Step 2: Run** and see the first row fail with no error (the chain builds), as `TestRepro_FullSessionStepsUpAtMFAVerifyWithoutReauthentication` showed the stranded state.
- [ ] **Step 3: Implement** the check in `wirePasskeys`; then fix every caller chain the run breaks by adding `EnableReauthentication()` (with `WithReauthenticationTokens` on token-bearer chains).
- [ ] **Step 4: Run** `go test -race -count=1 ./httpsec/... ./authenticate/passkey/...` and `go test ./...` in `test`: PASS.
- [ ] **Step 5: Commit** `feat(httpsec)!: passkey management on an MFA chain needs re-authentication`.

### Task 18: The password re-proof applies the post-authentication phase (tasks.md 9.4)

**Files:**
- Modify: `httpsec/reauth_password.go` (`reprove`)
- Test: `httpsec/reauth_password_test.go`

**Interfaces:**
- Consumes: `evaluatePhase(ctx, e *policy.Engine, phase policy.Phase, in *policy.Input) policy.Decision` (`login.go:694`), `postAuthenticationInput(p, first factor.Kind, username string, passwordChangedAt, now time.Time) *policy.Input` (`complete.go:138`), `policyDenyReason(d)`, `*ChallengeError{Kind}`; the login's engine through `i.login`.
- Produces: no new name.

- [ ] **Step 1: Write the failing rows** (table, `denyingIn`-style policy fixtures): deny in `PostAuthentication` → `ErrorIs(err, denyErr)`, session handle and `AuthenticatedAt` unchanged, `ResetFailures` not called; a password-change challenge → `errors.As(err, &ce)`, `ce.Kind == policy.ChallengePasswordChange`, `ce.Session == nil`, session unchanged; an allowing policy → re-authenticated (Review Focus).
- [ ] **Step 2: Run** `go test -run TestReauthPassword -count=1 ./httpsec/` and see the deny row fail with "expected error … but got nil", as `TestReproPasswordReproofAppliesPostAuthenticationPolicy` showed.
- [ ] **Step 3: Implement** step 6 of D6's password order: after the proved-account check, evaluate `PostAuthentication` with `postAuthenticationInput(auth.Principal, factor.Password, username, auth.PasswordChangedAt, i.now())`; return on deny or challenge before resetting failures.
- [ ] **Step 4: Run** `go test -race -count=1 -run 'TestReauthPassword|TestReauth' ./httpsec/`: PASS.
- [ ] **Step 5: Commit** `fix(httpsec): a password re-proof applies the post-authentication policy`.

### Task 19: The strict-rotation mark in the contract and the memory store (tasks.md 10.1)

**Files:**
- Modify: `session/store.go` (`Supersession`, the `Store` godoc), `session/session.go` (`Session`), `session/store_memory.go` (`Supersede`, `Load`, `Create`, `Save`), `session/store_encrypted.go` (pass-through)
- Modify: `test/storetest/session_suite.go`, `test/storetest/broken_session_test.go`
- Test: `test/storetest/memory_test.go`

**Interfaces:**
- Produces: `Supersession.Strict bool` ("the supersession is a rotation without grace"); `Session.RotatedStrictly bool` (store-owned, never written by `Create` or `Save`). `Store`'s method set is unchanged, so mocks are not regenerated.

- [ ] **Step 1: Write the failing suite cases:** supersede with `Strict: true` → `Load` returns `RotatedStrictly == true`; with a grace window → false; `Save` of a session with `RotatedStrictly` set → loads false; `DeleteExpired` past a strict row's `RetainUntil` → `ErrNotFound`. Broken variants: one that drops the mark, one whose `Save` writes it; the suite must fail on each.
- [ ] **Step 2: Run** `go test -run 'TestMemory.*Session' -count=1 ./test/storetest/` and see the mark cases fail (the field is never set). Adding the fields alone is the compile step, not the red step.
- [ ] **Step 3: Implement** the fields, the memory store's record and read, and the decorator pass-through.
- [ ] **Step 4: Run** `go test -race -count=1 ./session/ ./test/storetest/`: PASS.
- [ ] **Step 5: Commit** `feat(session): stores keep whether a supersession was strict`.

### Task 20: The durable stores and the migration (tasks.md 10.2)

**Files:**
- Create: `store/migrate/securitystate/<timestamp>_session_strict_rotation.sql` (goose `Up`: `ALTER TABLE sessions ADD COLUMN rotated_strictly boolean NOT NULL DEFAULT false`; `Down`: `DROP COLUMN IF EXISTS rotated_strictly`)
- Modify: `internal/pgschema/sessions.go` (supersede and load statements), `internal/storekit/session_tx.go`, `store/sqlstore/session.go`, `store/pgxstore/session.go`, `store/gormstore/session.go`, `store/gormstore/models.go` (`sessionRow`)
- Test: `test/migrate_securitystate_test.go` (a version constant and column rows), `test/gormstore/statements_test.go`, the backends' `session_test.go` running the 10.1 cases

**Interfaces:**
- Consumes: Task 19's fields.

- [ ] **Step 1: Write the failing migration rows:** column present, non-null, default false; a pre-migration superseded row reads back unmarked; an insert naming no such column succeeds; rollback leaves the pre-migration columns.
- [ ] **Step 2: Run** `go test -run 'TestMigrate|Session' -count=1 ./...` in `test` (Docker) and see the 10.1 mark cases fail on each durable backend and the migration rows fail with the column missing.
- [ ] **Step 3: Implement** the migration and the column in each statement and row model.
- [ ] **Step 3b: Lift the 10.1 gate:** append `sessionStrictRotationCases()` to the cases `RunSessionStoreSuite` runs; delete `runSessionStrictRotationSuite`, `test/storetest/export_test.go` and the extra calls in `memory_test.go` and `sessionVariant`.
- [ ] **Step 4: Run** `go test -race -count=1 ./...` in the root, `store/pgxstore`, `store/gormstore` and `test` modules: PASS. If Docker is unavailable, report it and stop.
- [ ] **Step 5: Commit** `feat(store): persist the strict-rotation mark`.

### Task 21: The manager reads the mark (tasks.md 10.3)

**Files:**
- Modify: `session/sessions.go` (`Rotate`, `Load`; remove `rotated rotatedHandles` and its type), `session/reuse.go` (`RotateWithGrace`, `judge`'s callers)
- Test: `session/sessions_test.go`, `session/sessions_internal_test.go`

**Interfaces:**
- Consumes: Task 19's fields.
- Produces: no new name. `Rotate` supersedes with `Strict: true`, `AcceptUntil = min(now+DefaultRenewalGrace, stored.AbsoluteExpiresAt)`, `RetainUntil = AcceptUntil`, and no `store.Delete`.

- [ ] **Step 1: Write the failing rows:** strict `Rotate` at 09:00:00 then `RotateWithGrace(old, 10s)` at 09:00:05 → `ErrRenewalConflict`, nothing stored (`TestRepro_RotateWithGraceAfterStrictRotationIsRenewalConflict`); `Load(old)` at once → `ErrNotFound`, successor loads; `Load(old)` at 09:00:40 before the sweep → `ErrExpired`, after it → `ErrNotFound`, never `ErrReused` (Review Focus); strict `Rotate(old)` at 09:00:31 → `ErrExpired` before the sweep, `ErrNotFound` after; a strict row's `RetainUntil == AcceptUntil`. Remove the failed-delete test; change "load between the writes" rows to "load after the write".
- [ ] **Step 2: Run** `go test -run 'TestManager|TestRotate' -count=1 ./session/` and see `session not found` where `the session was renewed concurrently` is expected.
- [ ] **Step 3: Implement:** read `RotatedStrictly` right after `loadStored` in `Load`, `Rotate` and `RotateWithGrace`, before `judge`: `Load` → `ErrNotFound` inside the window; the rotations → `ErrRenewalConflict` inside the window; after it, the store's own `ErrExpired` (before the sweep) or `ErrNotFound` passes through. Delete `rotatedHandles`; keep `rotating`. Godoc on `Rotate` and `RotateWithGrace` states the store-decided guarantee.
- [ ] **Step 4: Run** `go test -race -count=1 ./session/ ./httpsec/`: PASS.
- [ ] **Step 5: Commit** `feat(session)!: a strict rotation's lost race is decided by the store`.

### Task 22: Across managers sharing a store (tasks.md 10.4)

**Files:**
- Modify: `test/storetest/session_suite.go` (a case taking two managers over one store)
- Test: `httpsec/reauth_resolve_test.go`, `httpsec/session_renewal_test.go`

- [ ] **Step 1: Write the failing cases:** the suite rotates through manager A, then the old identifier through manager B over the same store → `ErrRenewalConflict` (`TestRepro_RotateOnSecondManagerAfterStrictRotationIsRenewalConflict`); in `httpsec`, a renewal that loses to a re-proof → `ErrSessionRenewalConflict` and 409; two re-proofs through two chains sharing a session store → one success and one 409.
- [ ] **Step 2: Run** on the tree *before* Task 21 merges, where they fail with `session not found` / 401; after Task 21 they must pass. If Task 21 has merged, show the red step by temporarily skipping the mark check in `Rotate` and restoring it.
- [ ] **Step 3: Run** `go test -race -count=1 ./session/ ./httpsec/` and `go test -race ./...` in `test` (Docker): PASS.
- [ ] **Step 4: Commit** `test: a lost strict rotation is a conflict across managers`.

### Task 23: Remaining wiring and lookups (tasks.md 9.3, 9.5)

**9.3 (lane F, after Task 16).** Files: `httpsec/reauth_options.go` (`buildChallenges`), `httpsec/mfa_begin.go` (the `WithMFAChallengeStore` option sets `challengeStoreGiven bool` on `mfaInterceptor`), `httpsec/reauth_test.go`, README defaults table.
- [ ] Red: a row with `WithMFAChallengeStore(st)` and re-authentication without a store → `ErrorIs(err, ErrConfig)`, message naming `WithReauthenticationChallengeStore` and `WithMFAChallengeStore`; it fails with nil today. A row giving `st` to both keeps `TestReproReauthChallengeStoreFollowsSharedMFAStore`'s two-chain begin-on-A, verify-on-B proof and passes. Implement in `buildChallenges` when `i.mfa != nil && i.mfa.challengeStoreGiven && i.challengeStore == nil`. Run `go test -race -count=1 -run 'TestEnableReauthentication|TestReauth' ./httpsec/`. Commit `fix(httpsec): a shared MFA challenge store needs a re-proof store`.

**9.5 (lane G, before Task 24).** Files: `httpsec/reauth_verify.go` (`admitMethod`), `httpsec/reauth.go` (`offered` keeps its full lookup for the password path and listing), `httpsec/reauth_verify_test.go`.
- [ ] Red: TOTP enrolled, a second `challengeStub` whose `enrolledErr` is set; a valid code at `/reauth/verify/totp` re-authenticates; it fails today with "the re-authentication methods could not be looked up" (`TestReproReauthTOTPIgnoresUnrelatedMethodEnrolmentFailure`). Move "a lookup failure refuses and verifies nothing" to the TOTP method's own `enrolledErr`: refused, nothing counted. Implement: `admitMethod` asks only `method.Enrolled(ctx, s.UserID)`; not enrolled → `ErrReauthenticationMethodNotUsable`; `secondFactorOnly` and the password path unchanged. Run `go test -race -count=1 -run TestReauth ./httpsec/`. Commit `fix(httpsec): a second-factor re-proof looks up only its own method`.

### Task 24: One second-factor response check and challenge issue (tasks.md 9.6)

**Files:**
- Modify: `httpsec/mfa_verify.go` (`verify`), `httpsec/mfa_begin.go` (`begin`, `wireChallenges`), `httpsec/reauth_verify.go` (`verify`, `begin`), `httpsec/reauth_options.go` (`buildChallenges`), `httpsec/challenge_spend.go`

**Interfaces:**
- Produces, package-level in `challenge_spend.go`: `checkResponse(ex *Exchange, throttle *mfa.VerifyThrottle, mgr *onetime.Tokens, method mfa.Method, s *session.Session) error` (throttle check, reader, spend for a challenge method, `Verify`, failure recording except `mfa.ErrAuthenticatorRefused` and `mfa.ErrVerifyThrottled`); `issueChallenge(ex *Exchange, mgr *onetime.Tokens, method mfa.ChallengeMethod, s *session.Session, respond MFABeginResponder) error` (sweep, `IssueWithin` with the `ErrIssueLimitReached` mapping, `BeginChallenge`); `challengeManagers(methods []mfa.Method, store onetime.Store, ttl time.Duration, limit int, purpose func(name string) string, ...) (map[string]*onetime.Tokens, error)`. Exact trailing parameters follow the current bodies.

- [ ] **Step 1: Red by divergence:** in the shared `checkResponse`, temporarily count `mfa.ErrAuthenticatorRefused`; see an MFA verify clone row and a re-proof clone row both fail. Restore. In `issueChallenge`, temporarily drop the limit mapping; see an MFA begin and a re-proof begin limit row both fail. Restore.
- [ ] **Step 2: Extract** and delete the copies; admission and resolve stay each path's own.
- [ ] **Step 3: Run** `go test -race -count=1 ./httpsec/...`, `go vet ./httpsec/`, `golangci-lint run ./httpsec/`: PASS.
- [ ] **Step 4: Commit** `refactor(httpsec): one response check and challenge issue for MFA and re-proof`.

### Task 25: One recency judge in `internal/guardauth` (tasks.md 9.7)

**Files:**
- Modify: `internal/guardauth/guardauth.go`, `internal/guardauth/guardauth_test.go`
- Modify: `httpsec/guards.go` (`checkRecency`, `recent`, `authenticationTime`), `httpsec/ginsec/guards.go`, `httpsec/fibersec/guards.go`

**Interfaces:**
- Produces: `type Recency struct{...}`; `func NewRecency(window time.Duration, clk clock.Clock, clockSet bool, authTime func(context.Context) (time.Time, bool)) (*Recency, string)` returning a reason string the adapter words as its own configuration error (empty when valid); `func (r *Recency) Judge(ctx context.Context, window time.Duration) (recent bool, judged time.Duration)` where `window == 0` means the guards-wide window. `guardauth` imports no `httpsec`; each adapter passes the session-based default time source and builds `&httpsec.ReauthenticationRequiredError{Window: judged}`.

- [ ] **Step 1: Write the failing `guardauth` table test** for `Judge` (fresh, at the window's end, stale, zero time, consumer source reporting none, per-route window) and `NewRecency` (window ≤ 0, nil and typed-nil clock, nil source); it fails because `Recency` does not exist yet — that is the compile step; the red step is each row failing against a stub `Judge` returning `true, 0`.
- [ ] **Step 2: Implement** `Recency`, then move each adapter onto it. For each adapter, red by divergence: temporarily make `Judge` treat a zero time as recent and see that adapter's "zero authentication time" row fail. Restore.
- [ ] **Step 3: Run** `go test -race -count=1 ./internal/guardauth/ ./httpsec/` and `go test -race ./...` in `httpsec/ginsec` and `httpsec/fibersec`: PASS.
- [ ] **Step 4: Commit** `refactor: one recency judge for every adapter`.

### Task 26: Conformance and the gate, again (tasks.md 11.1, 11.2)

- [ ] **11.1:** add to `test/httpsecconformance/reauth_scenarios.go`, on net/http, gin and fiber: `ReauthPrefixUnderFormLogin` (builds, both endpoints answer), `RenewalLostToReproofIs409`, `ReauthPasswordRefusedByPostAuthenticationDeny`. Red: register each before its harness wiring and see it fail. Run `go vet ./...` and `go test -race ./...` in `test`. Commit `test(conformance): review findings across adapters`.
- [ ] **11.2:** the main session reruns Task 12's gate and the whole-branch Opus review against all ten spec files, then `openspec validate reauthentication --strict`.

### Task 27: The re-proof's policy input and its recovery cancel (tasks.md 9.8)

Runs on H1's branch after Task 18.

**Files:**
- Modify: `policy/policy.go` (`Input`), `policy/concurrent.go` (`(*ConcurrentSessions).Evaluate`), `httpsec/reauth_password.go` (`reprove`, `postAuthenticate`)
- Test: `policy/concurrent_test.go`, `httpsec/reauth_password_test.go`

**Interfaces:**
- Consumes: `formLogin.cancelHeld heldRecoveryCanceller` (`login.go:126`, the call `completeLogin` makes at `complete.go:322`); `passwordAgeGate(t)` (`complete_test.go:39`).
- Produces: `policy.Input.Reauthenticating bool` — true only for the re-authentication of an existing session; every other builder leaves it false.

- [ ] **Step 1: Write the failing rows.**
  - `policy/concurrent_test.go`: max 3, re-authentication, count 3 → allowed; count 4 → `ErrTooManySessions`; login, count 3 → denied (unchanged).
  - `httpsec/reauth_password_test.go`: `NewConcurrentSessions(f.sessions, 1)` and the user's one session re-proving → re-authenticated (`TestReproPasswordReproofRefusedByConcurrentSessionCapOfOwnSession`); a policy capturing its input sees `Reauthenticating == true`; a held recovery of the user is cancelled by a successful re-proof (`CancelPending` called with the user), and a failing cancel refuses the re-proof with the session unchanged; `passwordAgeGate` refuses the re-proof as it refuses the login.
- [ ] **Step 2: Run** `go test -run 'TestConcurrentSessions' -count=1 ./policy/` and `go test -run TestReauthPassword -count=1 ./httpsec/`; see the cap row fail with `policy: too many concurrent sessions` and the cancel row fail with no `CancelPending` call. The `Reauthenticating` field alone is the compile step.
- [ ] **Step 3: Implement:** `Evaluate` uses `count > max` when `in.Reauthenticating`, else `count >= max`; `reprove` calls `l.cancelHeld(ctx, s.UserID)` (when non-nil) after the proved-account check and before `postAuthenticate`, and sets `Reauthenticating` on the input. Godoc on the field, the policy and `reprove`.
- [ ] **Step 4: Run** `go test -race -count=1 ./policy/... ./httpsec/...` and `go test ./...` in `test`: PASS.
- [ ] **Step 5: Commit** `fix(httpsec): a password re-proof is marked as one, and cancels a held recovery`.

### Task 28: The MFA-store rule needs a challenge method; docs to current behaviour (tasks.md 9.9)

**Files:**
- Modify: `httpsec/reauth_options.go` (`settle`'s store check, ~199; godoc ~62, ~124), `httpsec/reauth.go` (`offered` godoc ~255), `httpsec/mfa_options.go` (~262), `httpsec/passkey.go` (`EnablePasskeys` godoc ~254, `wirePasskeys` error ~396), `httpsec/recovery_options.go` (`EnableAccountRecovery` godoc ~208), `recovery/hold.go` (`CancelPending` godoc ~489), `README.md` (~444, ~793, ~799)
- Test: `httpsec/reauth_test.go` (`TestEnableReauthentication`)

**Interfaces:**
- Consumes: `isChallengeMethod(mfa.Method) bool` (used by `buildChallenges`).

- [ ] **Step 1: Write the failing row:** a TOTP-only MFA slot with `WithMFAChallengeStore(st)` and `EnableReauthentication()` without a store builds (`require.NoError`); the existing passkey-slot refusal row stays.
- [ ] **Step 2: Run** `go test -run TestEnableReauthentication -count=1 ./httpsec/` and see it fail with "WithMFAChallengeStore was given a challenge store but WithReauthenticationChallengeStore was not".
- [ ] **Step 3: Implement:** the check also requires `slices.ContainsFunc(i.mfa.methods, isChallengeMethod)`; reword each godoc and README place listed above to the behaviour D5, D6, D10 and the account-recovery delta state.
- [ ] **Step 4: Run** `go test -race -count=1 ./httpsec/... ./recovery/...`, `golangci-lint run ./httpsec/ ./recovery/`: PASS, 0 issues.
- [ ] **Step 5: Commit** `fix(httpsec): the MFA-store wiring rule needs a challenge method; docs follow`.

### Task 29: A save of a strictly rotated record is refused (tasks.md 10.5)

**Files:**
- Modify: `session/store_memory.go` (`Save`), `internal/pgschema/sessions.go` (`SessionUpdate` gains `AND NOT rotated_strictly`), `internal/storekit/*` if the not-found mapping needs it, `store/gormstore/session.go` (`Save`'s update gains the same `Where`), `session/store.go` and `session/sessions.go` (godoc of `Save`)
- Test: `test/storetest/session_suite.go`, `test/storetest/broken_session_test.go`, `test/storetest/broken_test.go`, `test/migrate_securitystate_test.go`

**Interfaces:**
- Consumes: `Session.RotatedStrictly`, `Supersession.Strict` (Task 19).
- Produces: `Store.Save` returns `ErrNotFound` and writes nothing when the stored record carries the mark.

- [ ] **Step 1: Write the failing cases:** suite case "saving a strictly superseded session is refused": supersede A strictly, `Save` a copy of A loaded before → `ErrorIs(err, session.ErrNotFound)`, and the stored A unchanged (its `Data` not the copy's); case "a grace supersession leaves the mark unset" (explicit `RotatedStrictly == false`); variant `session-save-onto-strict-row` (saves anyway) caught by the harness; migration rows reading a superseded and an unsuperseded pre-migration row back through a store as unmarked; `TestReview_SaveOfStrictlyRotatedSessionIsNotFound` rewritten as a manager-level row in `session/sessions_test.go`.
- [ ] **Step 2: Run** the memory store's suite and each durable backend's, and see the save case fail with "An error is expected but got nil"; the variant reported as uncaught before the case exists.
- [ ] **Step 3: Implement** the condition in each store; an update matching no row is the existing not-found result.
- [ ] **Step 4: Run** `go test -race -count=1 ./session/ ./internal/... ./store/...` (root, `store/pgxstore`, `store/gormstore`) and `go test -race -count=1 ./storetest/ ./sqlstore/ ./pgxstore/ ./gormstore/` plus `-run Migrat .` in `test`: PASS.
- [ ] **Step 5: Commit** `fix(session): a save of a strictly rotated record is not found`.

### Task 30: A rotation runs the caller's step before it is stored (tasks.md 12.1)

**Files:**
- Modify: `session/sessions.go` (`Rotate`), `httpsec/reauth_resolve.go` (`resolve`), `httpsec/mfa_verify.go` (`resolve`)
- Test: `session/sessions_test.go`, `httpsec/reauth_resolve_test.go`, `httpsec/mfa_verify_test.go`

**Interfaces:**
- Produces: `func (m *Sessions) RotateIssuing(ctx context.Context, s *Session, issue func(*Session) (string, error)) (*Session, string, error)` — builds the successor, calls `issue(successor)` before `store.Supersede`, and on an error from `issue` returns it with nothing stored; `Rotate(ctx, s)` is `RotateIssuing(ctx, s, nil)` returning the successor only.

- [ ] **Step 1: Write the failing rows:** session — a step that fails leaves the old identifier loading unsuperseded and no successor stored; httpsec — `TestRepro2ReproofWhoseTokenCannotBeIssuedDoesNotSignTheCallerOut` (TOTP and password rows) rewritten into `TestReauthResolve`; an MFA verify row whose generator fails leaves the pending session loading and pending.
- [ ] **Step 2: Run** `go test -run 'TestReauthResolve|TestMFAVerify|TestManagerRotate' -count=1 ./session/ ./httpsec/` and see `the caller holds no credential that authenticates` / the old identifier not found.
- [ ] **Step 3: Implement** `RotateIssuing`; both `resolve`s issue through it; drop the rollback of fields the failed path no longer changes.
- [ ] **Step 4: Run** `go test -race -count=1 ./session/ ./httpsec/...` and `go test ./...` in `test`: PASS.
- [ ] **Step 5: Commit** `fix: a rotation whose credential cannot be issued stores nothing`.
- [ ] **Step 6: Review follow-ups (dispatch M1b).**
  - `TestReauthResolve` row "two concurrent re-proofs through two chains sharing a session store": take the winner's session ID from the winning response, not from the last ID the generator saw (both racers now issue before `Supersede`); assert the loser's issued ID loads `session.ErrNotFound`. Proof it is fixed: `go test -race -count=50 -run 'TestReauthResolve/two_concurrent_re-proofs_through_two_chains' ./httpsec/` passes 50/50 (36/50 failed before).
  - Rows and messages that still say "rolls … back" (`reauth_resolve_test.go`, `mfa_verify_test.go`) say the session the caller holds is unchanged.
  - `mfa_enrol_test.go` "a rotation that fails": assert the stored session (`h.stored(t, s.ID)`) is still `MFAPending` and not `RotatedStrictly`; see it fail by temporarily saving the mutated copy.
  - `RotateIssuing` pins: a refusal decided before the successor is built never calls `issue`; a step that succeeds with a failing `Supersede` returns an empty credential and the error. The godoc says the in-flight window counts from the instant read before the step.
  - Run Step 4 again: PASS.

### Task 31: A second-factor re-proof applies post-authentication denials (tasks.md 12.2)

**Files:**
- Modify: `httpsec/reauth_verify.go` (`verify`), `policy/policy.go` (`Input.Reauthenticating` godoc), `policy/concurrent.go` (godoc)
- Test: `httpsec/reauth_verify_test.go`

**Interfaces:**
- Consumes: `evaluatePhase`, `postAuthenticationInput` with the session's principal, `s.FirstFactor`, the principal's username and `ex.Authentication.PasswordChangedAt` (what a login carries); `refuseUnenforced`, `ChallengeError`, `policyDenyReason` as the password path uses them; `assurance.New(s.FirstFactor, s.MFASatisfiedAt)` into `in.SecondFactorAtLogin` when `s.MFAAtFirstFactor`.

- [ ] **Step 1: Write the failing rows** (from `TestRepro2ReproofRunsThePostAuthenticationPhase`): cap of 1 with two sessions → TOTP re-proof refused with `ErrTooManySessions`, session unchanged; consumer deny → refused with the reason; an MFA-challenge outcome → re-authenticated.
- [ ] **Step 2: Run** `go test -run TestReauthVerify -count=1 ./httpsec/` and see the cap and deny rows succeed where refusal is expected.
- [ ] **Step 3: Implement** the phase after `checkResponse` and before `resolve`, with `Reauthenticating = true`; refuse on `Deny`; ignore `Challenge` only for `ChallengeMFA`. *(First cut, dispatch M2; its exemption of `ErrSecondFactorSameChannel` and of every challenge was reproduced as failing open and is replaced by Step 6.)*
- [ ] **Step 4: Run** `go test -race -count=1 ./policy/... ./httpsec/...`: PASS, including `TestReauthVerifyEndToEnd`.
- [ ] **Step 5: Commit** `fix(httpsec): a second-factor re-proof applies post-authentication denials`.
- [ ] **Step 6: Every deny binds; the input is the login's own (dispatch M2b, D6 revised).** Failing rows first, in `TestReauthVerify` / `TestReauthVerifyEndToEnd`:
  - a synthetic same-channel deny registered ahead of the cap, and ahead of a consumer deny → refused with the first deny's reason (fails today: re-authenticated);
  - the real `policy.MFA` and `policy.MFARequirement`, in both registration orders, on `/reauth/verify/passkey`, for a session created `WithSecondFactorAtLogin` → re-authenticated (fails today with `{requirement, challenge}`: `policy: this user must enrol a second factor`);
  - a session without `MFAAtFirstFactor` whose user is enrolled only on passkey, `SameChannelRefuse` → refused with `ErrSecondFactorSameChannel`, session unchanged;
  - a `ChallengePasswordChange` outcome → `*ChallengeError{Kind: ChallengePasswordChange}`, no session, unchanged; an unenforced kind → configuration error;
  - a consumer interceptor publishing `u-other` on the session → `ErrAuthenticationRequired` before the phase.
  Then: drop the same-channel exemption; rebuild `SecondFactorAtLogin` from the session; refuse non-MFA challenges as `postAuthenticate` does; check `ex.Authentication.Principal.ID == s.UserID` before the phase. Godoc on `verify`, `EnableReauthentication` (verify bullet), `policy.Input.Reauthenticating`. Run Step 4: PASS.
- [ ] **Step 7: The federated evidence too (dispatch M2c, third review).** Failing row first in `TestReauthVerify`, from `TestReproReproofDropsFederatedAssurance`: an OIDC session recording provider, issuer and `amr=["mfa"]`, `MFARequirement` with `WithMFARequiredForAll`, `FederatedAssuranceRefuse` and a source that meets the evidence → a valid TOTP re-proof re-authenticates (fails today: `policy: the provider did not assert the assurance this login requires`). Then `in.FederatedAssurance = sessionFederatedAssurance(s)` in `secondFactorPhase`. Godoc: the caller check refuses as authentication required before the throttle (not "as the password re-proof does"); `policy.SecondFactorProof` and `MFARequirement`'s `WithoutSecondFactorAtLogin` note name the re-proof rebuild, including sessions created before the option was turned on; `secondFactorPhase` and `policy.Input` name both rebuilt fields and that the proof's time is the session's satisfaction time; `session.WithSecondFactorAtLogin` says a consumer-made session so marked carries a library proof at re-proof. Run Step 4: PASS.

### Task 32: Wiring and the password short-circuit (tasks.md 12.3, 12.4)

**Files:**
- Modify: `httpsec/reauth_options.go` (`settle`), `httpsec/fibersec/guards.go` (`NewGuards`: `buildRecency` before `guardauth.Fallback`), `httpsec/reauth_password.go` (`reprove`: look methods up in order, refuse at the first enrolled)
- Test: `httpsec/reauth_test.go`, `httpsec/fibersec/guards_test.go`, `httpsec/reauth_password_test.go`

- [ ] **Step 1: Write the failing rows:** a re-proof store on a form-login-only chain → `ErrConfig`; fiber `NewGuards(nil, WithRecentAuthenticationWindow(0))` → error names `WithRecentAuthenticationWindow`; three methods with the first enrolled → one `Enrolled` call on `POST /reauth/password`.
- [ ] **Step 2: Run** and see: nil error; "NewGuards needs an authorizer"; `"3" is not less than or equal to "1"`.
- [ ] **Step 3: Implement** each.
- [ ] **Step 4: Run** `go test -race -count=1 ./httpsec/` and `go test -race ./...` in `httpsec/fibersec` and `httpsec/ginsec`: PASS.
- [ ] **Step 5: Commit** `fix(httpsec): an unused re-proof store and fiber's validation order; the password endpoint stops at the first enrolled method`.

### Task 33: One full-session check, one listing writer, one freshness function (tasks.md 12.5)

**Files:**
- Modify: `httpsec/reauth.go` (`isFullSession`), `httpsec/passkey_manage.go` (`fullSessionOnly`), `httpsec/recovery_codes.go` (`challengePending`), `httpsec/mfa_verify.go` (`writeMethodListing`), `httpsec/reauth.go` (`writeReauthMethods`), `session/session.go`, `internal/guardauth/recency.go`

**Interfaces:**
- Produces: `func fullSession(s *session.Session) bool` in `httpsec` (MFA none or satisfied, no pending password change, no enrolment or recovery marker); `func writeMethodsJSON(ex *Exchange, entries []methodListingEntry, extra ...)` or an equivalent shared writer; `func AuthenticatedWithin(at, now time.Time, window time.Duration) bool` in `session`.

- [ ] **Step 1: Red by divergence** for each extraction: make the shared check accept a pending session and see a re-proof, a passkey-management and a recovery-code row fail; drop `no-store` from the shared writer and see both listing rows fail; make the freshness function treat zero as fresh and see a session and a guard row fail. Restore each.
- [ ] **Step 2: Extract** and delete the copies.
- [ ] **Step 3: Run** `go test -race -count=1 ./session/ ./internal/guardauth/ ./httpsec/...`, `golangci-lint run`: PASS.
- [ ] **Step 4: Commit** `refactor: one full-session check, one listing writer, one freshness function`.

### Task 34: Docs (tasks.md 12.6)

- [ ] **Step 1:** Godoc of `rotationRefusal` and both `resolve`s: a lost race through any manager sharing the store is the renewal conflict (409) inside the window. Godoc of the recovery-code regeneration endpoint and the README: on an MFA chain without re-authentication a stale session regenerates only after signing in again. Every place Tasks 30–32 changed states the new behaviour.
- [ ] **Step 2: Run** `go doc` on each changed symbol and `golangci-lint run ./httpsec/`. Commit `docs(httpsec): re-proof and rotation docs follow the second review`.

### Task 35: The gate and the whole-branch review (tasks.md 12.7)

- [ ] As Task 12, then the whole-branch Opus review against every requirement in the change's spec files.

### Task 11: Conformance (tasks.md 8.1)

**Files:**
- Create: `test/httpsecconformance/reauth_scenarios.go`
- Modify: `test/httpsecconformance/scenarios.go` (registration)

**Interfaces:**
- Consumes: the suite's existing runner and per-adapter harness (`runner.go`).

- [ ] **Step 1: Add the scenarios**, each run on net/http, gin and fiber:
  - `ReauthStaleThenTOTP`: refused 403, `/reauth/verify/totp`, then the guarded route returns 200 with the new credential;
  - `ReauthPasswordWithoutSecondFactor`;
  - `ReauthPasswordRefusedForTOTPHolder` (403);
  - `MFAVerifyRefusesFullSession` (403);
  - `ReauthFiberRefusalCarriesWindow`, fiber only.
- [ ] **Step 2: Run and see it fail.** Register them before the harness enables re-authentication, and see 404 or pass-through failures. Then enable it in the harness.
- [ ] **Step 3: Run.** `go vet ./...` and `go test -race ./...` in `test` pass (Docker for durable backends; if Docker is unavailable, report it and run the in-memory set).
- [ ] **Step 4: Commit** `test(conformance): re-authentication across adapters`.

### Task 12: The gate (tasks.md 8.2)

Run by the main session. It edits nothing.

- [ ] **Step 1:** For every module in `go list -m`, run `go build ./...`, `go vet ./...`, `go test -race -count=1 ./...` and `golangci-lint run ./...`. Every command exits 0.
- [ ] **Step 2:** `gofmt -l $(git ls-files '*.go')` prints nothing. `openspec validate reauthentication --strict` reports valid.
- [ ] **Step 3:** The whole-branch Opus review runs against every requirement in the seven spec files. Findings go back to a fresh dispatch of the owning lane, and this step reruns.

**Task-number map:**

| tasks.md | Plan task |
|---|---|
| 1.1 | Task 1 |
| 1.2 | Task 2 |
| 2.1 | Task 3 |
| 3.1 | Task 4 |
| 3.2–3.3 | Task 5 |
| 4.1–4.2 | Task 10 |
| 5.1 | Task 9 |
| 6.1–6.2 | Task 6 |
| 6.3 | Task 7 |
| 6.4–6.6 | Task 8 |
| 6.7 | Task 14 |
| 6.8 | Task 15 |
| 7.1 | Task 13 |
| 8.1 | Task 11 |
| 8.2 | Task 12 |
| 9.1 | Task 16 |
| 9.2 | Task 17 |
| 9.3 | Task 23 |
| 9.4 | Task 18 |
| 9.5 | Task 23 |
| 9.6 | Task 24 |
| 9.7 | Task 25 |
| 9.8 | Task 27 |
| 9.9 | Task 28 |
| 10.5 | Task 29 |
| 12.1 | Task 30 |
| 12.2 | Task 31 |
| 12.3–12.4 | Task 32 |
| 12.5 | Task 33 |
| 12.6 | Task 34 |
| 12.7 | Task 35 |
| 10.1 | Task 19 |
| 10.2 | Task 20 |
| 10.3 | Task 21 |
| 10.4 | Task 22 |
| 11.1–11.2 | Task 26 |

The plan tasks are numbered by component, and the waves above set the execution order.
