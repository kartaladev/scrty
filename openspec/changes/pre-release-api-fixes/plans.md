# Pre-Release API Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. In this repository the main session dispatches every file-writing step to a subagent (`.claude/rules/subagent-delegation.md`), and runs the verification commands itself.

**Goal:** Land the library fixes that would be breaking changes, or broken promises, after `v0.1.0`: the `notify` worker replacement and `ErrConfig` wording, the token subject as user identifier on the generator, the authenticator and the chain, signing-key deletion, the passkey port trim, and the MFA confirmation race closed in the store.

**Architecture:** Lanes over disjoint files, each test-first against the spec deltas, then one whole-branch review. Revised on 2026-11-03 after implementation began: the race in decision 6 reproduced, a scenario sweep added to ten deltas, and the signing-key review found regressions. Tasks 1.1, 1.2, 2.1, 2.2, 3.1, 3.2, 4.1 and 4.2 are implemented and uncommitted in the working tree; this plan covers what remains.

**Tech Stack:** Go 1.27; `go.uber.org/goleak`; testcontainers PostgreSQL for the store conformance suites; gopls for callers and implementers.

**Spec:** `openspec/changes/pre-release-api-fixes/`:
- `proposal.md`;
- `design.md` (decisions 1 to 6);
- `specs/`: `email-notification`, `token-issuance`, `authentication`, `http-security-chain`, `signing-keys`, `multi-factor-auth`, `security-state-stores`, `store-conformance`, `identity-model`, `secrets-at-rest`;
- `tasks.md`.

Plan task N.M is `tasks.md` task N.M.

## Global Constraints

- **Go changes are test-first** (`.claude/rules/golang-tdd.md`): see the failure for the intended reason, then make it pass. A compile error is not a red step. A scenario that passes today is proved by a temporary mutation, edited back.
- **Table tests** use the `table-test` skill's `assert`-closure form with `t.Context()`. Mocks come from `use-mockgen`; PostgreSQL from `use-testcontainers`.
- **Defaults and overrides** (`.claude/rules/library-design.md`):
  - the subject defaults to `Principal.ID`. `token.WithUsernameSubject()`, `authenticate.WithJWTUsernameSubject()` and `httpsec.WithBearerUsernameSubject()` override it, and each option's godoc names the other two;
  - key deletion is on by default, one grace after a key's retire time. `signingkey.WithRetiredKeysKept()` turns it off, and `signingkey.WithRetiredKeyGrace(d)` replaces the grace;
  - each option's godoc names the default it replaces.
- **Construction refuses a mismatch:** a chain with signed bearer tokens whose given token generator reports a different `token.SubjectMode` fails to build with a configuration error.
- **Defect claims** (`.claude/rules/defect-claims.md`): a claim needs a failing test or the label `UNREPRODUCED`.
- **Destructive git commands.** Agents never run `git checkout --`, `restore`, `reset --hard`, `stash` or `clean`, make no commits, and never edit `openspec/`. All work is uncommitted, so one of these would take other lanes' work with it.
- **Navigation** uses gopls at `~/go/bin/gopls`, not text search, for references, callers and implementers (`.claude/rules/gopls-navigation.md`).
- **Verification commands**, from the repository root: `go test -race -count=1 ./...` per changed module, `make check`, `openspec validate pre-release-api-fixes --strict`.
- **Known red until its lane lands:** `TestConfirmEnrolment_DeviceProofBetweenReadAndConfirm` until 4.3; 15 top-level `httpsec` tests and `TestConformance*`, `TestCertificateBinding*` in `test` until 2.3. Other lanes add `-skip` or scope their runs, and say so.
- **Out of scope, report only:** `TestQueuedSender_SendsRacingShutdown`'s timing assertion and `TestPGLimiter_PruneCatchesBrokenVariants/prune-by-checking-window` have each failed intermittently. Do not change them; report any failure with its output.

## Review Focus

1. **A token naming another user reaches a session only a late renewal may recover.**
   - Expected: refused, no successor created, on a path where `resolve` returns early.
   - Test: in task 2.4, "Late renewal with a subject that is not the session's user".
2. **A token whose `sub` is a username reaches a default chain**, from a consumer who changed one side past the build check, or another service.
   - Expected: refused with the authentication-required error before any user reload, consuming no proof, never resolved to another user.
   - Test: in task 2.3, "Subject is not the session's user" with a loader double that fails if called; in 2.4, "Subject refusal consumes no proof".
3. **A consumer's provider returns a principal with a username and no identifier.**
   - Expected: the login fails, with no session stored and no credential handed out.
   - Test: in task 2.4, "Login with a principal that has no identifier". The behaviour is unconfirmed, so a failure is a defect to report.
4. **A key of an algorithm this replica does not sign with is the newest of that algorithm, while another replica signs with it.**
   - Expected: unpublished here, never deleted.
   - Test: in task 3.3, "Retired key of an unconfigured algorithm".
5. **A proven enrolment whose emailed code has expired or run out of attempts is confirmed through the single-call route with a stale read.**
   - Expected: refused, nothing changed. A condition that only checks a live code would pass the other scenarios and bypass the mailbox proof.
   - Test: in task 4.4, "Confirmation refused when the emailed code has expired or run out of attempts", and the broken variant "Store honouring only a live emailed code".

Added for group 6:

6. **A key removed from the store by hand or by a backup restore, with no reload since.**
   - Expected: housekeeping judges from a fresh listing, so the newest key still stored stays.
   - Test: in task 6.4, "Key removed from the store since the last reload".
7. **A provider's own store error that matches `context.Canceled` while the work is running.**
   - Expected: reported as a failure. Only the background work's own context ending silences it.
   - Test: in task 6.3, "Store failure before shutdown".
8. **A typed-nil generator given to `NewJWTAuthenticator`.**
   - Expected: the existing configuration error, and no panic from reading its mode.
   - Test: in task 6.2, a row with a nil `*` generator.

---

## Dispatch map (main session)

| Order | Dispatch | Tasks | Owns | Model, and why |
|---|---|---|---|---|
| 1 (parallel) | P1c | 1.3 | `notify/*_test.go` | Sonnet: test additions against a settled implementation |
| 1 (parallel) | P2b | 2.3, 2.4 | `httpsec/` (production and tests), `token/config.go` godoc only, `test/httpsecconformance/`, the `test` package's chain tests | Opus: refusal logic on the authentication path, and a build check every chain passes through |
| 1 (parallel) | P3b | 3.3 | `token/signingkey/`, `store/seal/signingkey*`, `store/{sqlstore,pgxstore,gormstore}/signingkey.go`, `internal/pgschema/signingkeys.go`, `test/storetest/signingkey_suite.go`, `test/storetest/broken_test.go`, `test/storetest/ambient.go`, `test/storetest/broken_ambient_test.go`, `test/internal/storefix/ambients.go`, `test/{sqlstore,pgxstore,gormstore}/signingkey_test.go`, `test/gormstore/statements_test.go` | Opus: a mistake here deletes keys and can still pass the tests |
| 2 (after P3b) | P4b | 4.3, 4.4 | `authenticate/mfa/`, `internal/pgschema/mfa.go`, `store/gormstore/mfa.go`, `test/storetest/mfa_suite.go`, `test/storetest/broken_mfa_test.go`, `test/internal/storefix/`, and `test/gormstore/statements_test.go` once P3b has finished with it | Opus: a store contract across every store, on a security guarantee |
| 3 (after P4b's review) | P4c | 4.5 | The files in Task 4.5 | Opus: a concurrency barrier test on a security guarantee |
| 2 (after P2b's review) | P2c | 2.5 | `httpsec/` (production and tests), `test/httpsecconformance/` | Opus: refusal logic on the authentication path, and a design choice carried out |
| 3 (after P2c's review) | P2d | 2.6 | `httpsec/`, `token/claims.go` godoc, `authenticate/magiclink` and `recovery` tests | Sonnet: each fix is stated by the review |
| 2 (after P3b) | P3c | 3.4 | `token/signingkey/` only | Opus: ordering across replicas and clocks, where a mistake can pass the tests and still lose keys |
| 3 (after P3c's review) | P3d | 3.5 | `token/signingkey/`, `token/config.go` comment | Opus: the same lane's rule, under the same risk |
| 4 | main | 5.1, 5.2 | — | Opus reviewer for 5.1 |
| 5 (parallel) | P6a | 6.1 | `httpsec/basic.go`, `httpsec/login.go` and their tests | Sonnet: the refusal is stated by decision 3, and form login is the pattern |
| 5 (parallel) | P6b | 6.2 | `authenticate/jwt.go`, `authenticate/jwt_test.go` | Sonnet: the bearer's check is the pattern |
| 5 (parallel) | P6c | 6.3, 6.4 | `token/signingkey/` | Opus: ordering at shutdown, and what deletes keys, where a mistake can pass the tests |
| 5 (parallel) | P6d | 6.6 | `internal/storekit/`, `store/{sqlstore,pgxstore,gormstore}/signingkey.go` | Sonnet: one helper against an existing suite |
| 6 (after P6c) | P6c2 | 6.4 | `token/signingkey/` | Sonnet: edits the dropped version back, keeping 6.3 |
| 6 (after P6c2's review) | P6e | 6.5 | `token/signingkey/` | Sonnet: a benchmark and one early return |
| 6 (after P6a's review) | P6f | 6.7 | `httpsec/` (production and tests), `test/httpsecconformance/` if a fixture needs it | Opus: a refactor on the authentication path that must keep behaviour |
| 7 | main | 6.8 | — | Opus reviewer |

P4b follows P3b only because both change `test/gormstore/statements_test.go`, and P3c follows P3b as the next dispatch of its lane; P3c and P4b share no file and may run together. Each dispatch gets a fresh reviewer that edits nothing: Opus for P2b, P3b, P3c and P4b, and Sonnet for P1c, whose review also covers the unreviewed fold-in of 1.1 and 1.2. Each brief also gives the Go guidance path, since the plugin may not load: `~/.claude/plugins/cache/samber/cc-skills-golang/2.0.1/skills/` (`golang-concurrency`, `golang-database`, `golang-error-handling`, `golang-security`).

**Starting point.** Rebase `feat/pre-release-api-fixes` on `origin/main` (`2ac0bee`, with #67's dependency bumps) before any commit, and run the gate after it. Commits happen only with the user's go-ahead.

---

### Task 1.3: The rest of `email-notification` (decision 1; dispatch P1c)

**Files:** `notify/queued_test.go`, `notify/smtp_test.go`. No production change is expected; if a scenario fails, stop and report it.

- [ ] **Step 1:** map each scenario to its existing test: "Only worker ends its goroutine during the drain", "Goroutine ended after shutdown gave up", "A blocking log handler does not shrink the pool", "Pool does not grow", "An idle worker holds no delivered message" (`TestQueuedSender_IdleWorkerReleasesLastDelivery`), "Ended goroutine's record carries nothing from the sender", "An ended goroutine is reported without configuration", "Message names a sender and no default exists", "Default sender address used". List the ones with no test.
- [ ] **Step 2:** add the missing rows to the existing tables. Assertions: "Pool does not grow" also asserts that the wrapped sender saw each failed message exactly once. "An ended goroutine is reported without configuration" asserts a record reaches `slog.Default` with no logger option; it replaces the default logger, so it cannot run in parallel.
- [ ] **Step 3:** prove each added row with a temporary mutation of `notify/queued.go`, edited back, and record the failing line. `git diff` on `notify/smtp.go` stays empty.
- [ ] **Step 4:** `go test -race -count=5 ./notify/...`, `go vet ./notify/...`, `golangci-lint run ./notify/...`. Expected: PASS, 0 issues.
- [ ] **Step 5: commit, with 1.1 and 1.2,** `fix(notify): replace a queued-sender worker whose delivery ends its goroutine`.

---

### Task 2.3–2.4: The chain's subject option and checks (decision 3; dispatch P2b)

**Interfaces:**
- Consumes: `token.SubjectMode`, `token.SubjectUserID`, `token.SubjectUsername`, `token.Generator.SubjectMode()`.
- Produces: `func httpsec.WithBearerUsernameSubject() BearerTokenOption`; unexported `checkSubjectGenerator(c *config, option, field string, g token.Generator) error`.

- [ ] **Step 1 (red):** write `TestBearer_SubjectIsTheSessionUser`, a table over a chain with signed bearer tokens, with the 2.3 and 2.4 request-time scenarios as rows. Assertions that must appear:
  - "Default token reloads the session's user": loader called through `LoadByUserID("u-1")`, never by username; the handler sees `ID` `u-1` and `Username` `alice`;
  - "Subject is not the session's user" and "Token with no subject": `errors.Is(err, httpsec.ErrAuthenticationRequired)`, no loader call, handler not run;
  - "Subject refusal consumes no proof": the proof's `jti` can still be presented;
  - "Binding judged before the subject": the binding refusal, no loader call;
  - "Session load precedes the subject check": a dependency failure, not the authentication-required error;
  - "Subject refusal keeps the session": still stored, no activity recorded, per-request phase not called;
  - "Late renewal with a subject that is not the session's user": refused, no successor;
  - "Rename keeps a live token working", "Rename under the username subject", "Session's user no longer exists", "Named username no longer exists", "Consumer reads the subject as a username", "Username reassigned to another user".
- [ ] **Step 2 (red):** write `TestChain_GeneratorSubjectModeMustMatchBearer`, a table with "Generator and bearer disagree on the subject", "Every entry point is checked" (one row per entry point: `FormLoginDeps.Tokens`, `SessionRenewalDeps.Tokens`, `WithMagicLinkTokens`, `PasswordlessTokens`, `WithMFATokens`, `WithReauthenticationTokens`, `WithRecoveryTokens`, `WithOIDCTokens`, each also with the options reversed), "Username bearer with a default generator", "Generator and bearer agree on usernames", "Verify-only chain", "Generator reporting the zero subject mode", "No generator with a callback success handler", "Generators on a chain with no signed bearer", and a typed-nil generator, which builds and does not panic.
- [ ] **Step 3:** add "Every issued token authenticates on a default chain" and "Login with a principal that has no identifier" to `test/httpsecconformance`.
- [ ] **Step 4:** `go test -run 'TestBearer_SubjectIsTheSessionUser|TestChain_GeneratorSubjectModeMustMatchBearer' -count=1 ./httpsec/`. Expected: FAIL on assertions. Add a stub option first so this compiles.
- [ ] **Step 5 (green):**
  - in `httpsec/bearer.go`'s `resolver.admit`, after the two binding checks and before `recordProof`: under the default, refuse with `ErrAuthenticationRequired` when `claims.Subject()` is empty or is not `s.UserID`; under the option, refuse only when it is empty. Keep the `cnf` checks unchanged;
  - call `resolver.resolve` with `lookupBySessionUser()` under the default and `lookupByUsername(claims.Subject())` under the option;
  - `checkSubjectGenerator` sits beside `checkBindingGenerator` (`httpsec/dpop.go`), not inside it, since that one returns early when no binding is on. It checks nothing with signed bearer tokens off, and uses `nilcheck.IsNil(g)`. Call it wherever the binding check is called; direct sites are `oidc_options.go:155,158,175`, `magiclink.go:209,219`, `passkey_login.go:365,378`, `mfa_options.go:235,244`, `reauth_options.go:278,287`, `recovery.go:154,162`, and `checkTokenGenerator` (`session_bearer.go:350`) covers `login_options.go:178` and `session_renewal.go:625`. The error names the option and the field;
  - correct the text at `httpsec/bearer.go:134-137`, `:311` and `httpsec/resolve.go:51-63`, and `token.WithUsernameSubject`'s godoc says the chain refuses a mismatch and names `httpsec.WithBearerUsernameSubject`. `WithBearerUsernameSubject`'s godoc names the default it replaces and the two options it must agree with.
- [ ] **Step 6:** fix the fixtures that assumed a username `sub`, starting with `TestReauthChallengeStoreSharedAcrossChains`, `TestChangePasswordEndpointLetsTheNewPasswordIn`, `TestMFAVerifyDoesNotStrandCaller` and `TestMFABegin_ConcurrentBeginsDoNotExceedChallengeLimit`, whose mock `UserLoader`s do not expect `LoadByUserID`. Find the cause of the nil dereference that cut an earlier run short; if it is more than a fixture, report it. A test whose purpose is the username path takes `WithBearerUsernameSubject()` and a matching generator, so that path stays covered.
- [ ] **Step 7:** `go test -race -count=1 ./httpsec/...`, the `httpsec/ginsec` and `httpsec/fibersec` modules, and the `test` module including `test/httpsecconformance`. Expected: PASS, including every test in the known-red list for this lane. A failing "Login with a principal that has no identifier" is reported with its output, not worked around.
- [ ] **Step 8: commit, with 2.2,** `feat(token)!: the token subject is the user identifier by default`.

### Task 2.5: Fold the review of 2.3 and 2.4 (decision 3; dispatch P2c)

**Interfaces:** no new exported name.

- [ ] **Step 1 (red):** review tests that reproduce each finding are named in decision 3. Add them to the tables: the late-renewal and proof rows under usernames, the generator-as-verifier and two-bearer rows, the no-identifier login in three modes, the empty-reference row, and a certificate row for the binding order. See each fail on its assertion.
- [ ] **Step 2 (green):** in `httpsec/bearer.go`, under usernames, `admit` loads the user by username through the reload's own classification, refuses unless its identifier is the session's, and hands the record to `resolve`, so the ordinary path does not load twice. The bearer's enable check asserts `d.Verifier.(token.Generator)` and calls `checkSubjectGenerator`. The login tail refuses a principal with no identifier before anything is prepared to store. `ownActiveUser` refuses an empty reference.
- [ ] **Step 3:** godoc per `tasks.md` 2.5. `WithBearerUsernameSubject` keeps its line, now true, and says a wrapped verifier cannot be checked.
- [ ] **Step 4:** the verification of Task 2.3–2.4's Step 7. Expected: PASS.

### Task 2.6: Fold the review of 2.5 (decision 3; dispatch P2d)

- [ ] **Step 1:** per `tasks.md` 2.6. Each fix has its red step first: the panic for the nil authentication, a missing record for the ERROR log, a surviving mutation for the hang-up row and for each pinned guard.
- [ ] **Step 2:** the verification of Task 2.3–2.4's Step 7, plus `go test -race -count=1 ./authenticate/magiclink/... ./recovery/...`. Expected: PASS.

---

### Task 3.3: The signing-key review's findings (decision 4; dispatch P3b)

**Interfaces:** no new exported name. `KeyStore.Delete` and `WithRetiredKeysKept` exist.

- [ ] **Step 1 (red):** `TestHousekeeping_Retention` gains "Retired key of an unconfigured algorithm": a manager configured for RS256 alone, a store with two ES256 keys older than 50 hours. Assert neither is published, the older is gone, the newer remains. Change the existing row at `keys_retention_test.go:276`, which pins the opposite. See it fail.
- [ ] **Step 2 (red):** add a row to `RunSigningKeyStoreSuite` or the gorm-specific test for "Delete of many keys": more than 65535 identifiers in one call, every named key that is stored gone, no error. See it fail on gorm. Store only a few of the named keys, placed around the bound, so the suite stays quick.
- [ ] **Step 3 (red):** add tests that kill the surviving mutants: a key exactly one lifetime old stays published and stored; reload keeps a key past its lifetime while the store still lists it (no early drop, per the rule's "unlisted" half); the newest stored key is judged from the listing alone, so a held key the store no longer lists does not take its place. A listing that has not caught up delays a delete by one run at worst.
- [ ] **Step 4:** map the remaining scenarios to their tests, adding what is missing: "Key past its lifetime at start is deleted", "Failed delete survives a restart", "Store cannot list during housekeeping", "Held key within its lifetime is kept when the store does not list it", "Newest stored key not yet loaded", "Sealing store forwards a delete", and in `store/seal` or the suite, "A deleted signing key stays deleted".
- [ ] **Step 5 (green):**
  - `token/signingkey/keys_rotate.go`: compute the newest per algorithm over every listed record for the delete decision only. Publishing and `pickCurrent` stay as they are;
  - `store/gormstore/signingkey.go`: batch, or use the JSON statement the other stores use, and let `test/gormstore/statements_test.go:380-382` follow.
- [ ] **Step 6:** godoc: `WithKeyLifetime` says every replica sharing a store must agree, as `WithRetiredKeysKept` does; `record.go:43-45` names far-future keys among those a store keeps; `KeyStore.Delete` says identifiers PostgreSQL text cannot hold count as missing. Replace `context.Background()` at `keys_retention_test.go:422` and `:510` where the skill's form applies.
- [ ] **Step 7:** the broken-store variants cover `store-conformance`'s new requirement ("Store with an over-broad delete", "Store refusing a missing key"), and the ambient-transaction suite covers `Delete`.
- [ ] **Step 8:** `go test -race -count=1 ./token/signingkey/... ./store/seal/... ./store/sqlstore/... ./internal/pgschema/...`, the `store/pgxstore` and `store/gormstore` modules, and in `test`, `./storetest/ ./sqlstore/ ./pgxstore/ ./gormstore/ ./crossbackend/` with Docker. Expected: PASS.
- [ ] **Step 9: commit, with 3.1, 3.2 and 3.4,** `feat(signingkey)!: housekeeping deletes keys after their tokens can have expired`.

### Task 3.4: The retire time and the grace (decision 4; dispatch P3c, after P3b)

**Interfaces:**
- Produces: `func signingkey.WithRetiredKeyGrace(d time.Duration) Option`; default one key lifetime; zero deletes at the retire time.
- `KeyStore`, `Record` and the schema do not change.

- [ ] **Step 1 (red):** write `TestRetireTime`, a table on the fake clock, with each row asserting what is published and what is stored:
  - "Key replaced late stays published": current for 28h, replaced 5m ago, its token verifies; unpublished 23h after replacement with the defaults, and not before;
  - "Key replaced late survives a restart": a second manager over the same store publishes it;
  - "Future-dated key does not hold back retirement";
  - "Retired key waits out its grace": created 25h ago and replaced on time, unpublished and stored;
  - "Old key removed": created 50h ago, replaced on time, gone;
  - "Consumer sets the grace": zero, created 25h ago, gone;
  - "Replica with a fast clock leaves keys in place", "Replica with a slow clock leaves its key in place" and "Replica with a shorter lifetime": two managers with independent fake clocks or lifetimes over one store. Rewrite the review's reproductions from decision 4's test names; they may survive in the session scratch path named in `handoff.md`.
  Add construction rows: "Negative grace" and "Grace and kept keys together" assert `ErrConfig`. Run them, and confirm they fail on assertions. Add the option as a stub first.
- [ ] **Step 2 (green):** one unexported function computes a key's retire time from its record, the known keys and the present time, and every caller uses it: `publishable` (`token/signingkey/keys.go`), `dropLocked`, `retiredForAge` and `deleteRetired` (`keys_rotate.go`). A key with no successor retires at creation plus lifetime; the newest-key and current-key guards still decide what is deleted. A manager remembers its last listing under its lock, and judges a held key over held keys plus that listing, so housekeeping makes no store call and the published set does not flap.
- [ ] **Step 3:** adjust the fixtures the rule changes, starting with "Key past its lifetime after a restart" (replaced 29 days ago) and the rows at `keys_retention_test.go` that use 25-hour-old keys. A key that must be gone now takes 50 hours; do not weaken what a row proves. `token/config.go`'s window comment stays true; confirm it.
- [ ] **Step 4:** godoc: the package doc and `KeyStore` say when a key retires and when it leaves the store. `WithRetiredKeyGrace` names the default it replaces and that it conflicts with `WithRetiredKeysKept`. `WithKeyLifetime`, `WithRetiredKeysKept` and `WithRetiredKeyGrace` say every replica must agree, and the package doc says replicas sharing a store must keep synchronised clocks.
- [ ] **Step 5:** the verification of task 3.3's Step 8. Expected: PASS, and the review's reproductions pass.

### Task 3.5: The reload margin, and the review of 3.4 (decision 4; dispatch P3d)

- [ ] **Step 1 (red):** "A replica still signing before its reload": L=24h, R=6h, reload=30m, a replica that has not reloaded signs a token at the cap with a replaced key; it verifies until it expires. A real token through the real generator and verifier. See it fail with the key not found.
- [ ] **Step 2 (green):** add one reload interval to the later of the two terms in the retire-time function. Adjust the boundary rows, keeping what each proves. A key is published at exactly its retire time, and retires strictly after.
- [ ] **Step 3:** `token/config.go`'s window comment names the late replacement and the margin. `doc.go` drops the limit the margin closes, and keeps the skew and manual-removal limits with the corrected figures.
- [ ] **Step 4:** fold the findings of the 3.4 review, per `tasks.md` 3.5. Pin the configuration with `lifetime - rotation <= reload` by test, and report what `doc.go` should say about it.
- [ ] **Step 5:** the verification of task 3.3's Step 8. Expected: PASS.

---

### Task 4.1: Remove the unused passkey store method (decision 5)

Implemented and reviewed. **Commit:** `refactor(passkey)!: drop the unused DeleteAwaitingSavedCodes port method`.

### Task 4.3–4.4: Close the MFA race in the store (decision 6; dispatch P4b)

**Interfaces:** `EnrolmentStore.Confirm(ctx context.Context, user identity.UserID, gen id.ID, step int64, at time.Time) (bool, error)` keeps its signature. It also reports false, changing nothing, for an enrolment with a device proof.

- [ ] **Step 1 (red):** `TestConfirmEnrolment_DeviceProofBetweenReadAndConfirm` exists in `authenticate/mfa/confirm_race_test.go` and fails. Add the rows "Device proof lands during a confirmation with email confirmation off" (`ConfirmEnrolment` returns `ErrInvalidCode`, nothing changes, the path can still complete) and "Device proof lands after a single-call confirmation" (`ProveDevice` reports no change, no code stored or sent, the confirmation time and step unchanged), and confirm "Out-of-band enrolment with no device proof" passes.
- [ ] **Step 2 (red):** add to `test/storetest/mfa_suite.go` "Confirmation refused after a device proof with no emailed code", "Confirmation refused when the emailed code has expired or run out of attempts" and "Device proof on a confirmed enrolment". Change `confirmKeepsStepCase` to assert refusal, with step 1001, the device-proof time and the emailed code unchanged. Add broken variants to `broken_mfa_test.go`: "Store ignoring the device proof" and "Store honouring only a live emailed code". Run against the in-memory store. Expected: FAIL on assertions.
- [ ] **Step 3 (green):**
  - `internal/pgschema/mfa.go` `EnrolmentConfirm`: add `AND device_proven_at IS NULL`, drop `email_code = NULL`;
  - `MemoryEnrolmentStore.Confirm` (`authenticate/mfa/store_memory.go:96`) and `store/gormstore/mfa.go:200` follow;
  - `authenticate/mfa/store.go`: `Confirm`'s godoc states the condition, and no longer says it clears the code;
  - `authenticate/mfa/totp.go`: `ConfirmEnrolment`'s godoc drops its "Known limit" paragraph.
- [ ] **Step 4:** rewrite what pinned the old contract: `TestTOTPProvingCodeNotReplayableAfterPathCompletion` (`Confirm` now reports false, and the proving code is still not accepted) and the row "Confirm clears an outstanding emailed code and keeps the step forward" (`store_memory_test.go:756`). Use gopls for every other caller of `Confirm` in tests; report any production caller beyond `totp.go:547` and the sealing decorator's forward.
- [ ] **Step 5:** `go test -race -count=10 -run TestConfirmEnrolment_DeviceProofBetweenReadAndConfirm ./authenticate/mfa/`, `go test -race -count=1 ./authenticate/... ./store/seal/...`, the `store/*` modules, and in `test`, `./storetest/ ./sqlstore/ ./pgxstore/ ./gormstore/` with Docker. Expected: PASS, and each broken variant fails its named case.
- [ ] **Step 6: commit** `fix(mfa)!: a device proof refuses the single-call confirm, decided by its write`.

### Task 4.5: Fold the review of 4.3 and 4.4 (decision 6; dispatch P4c)

**Files:** `test/internal/storefix/races.go`, `test/storetest/race.go`, `test/{sqlstore,pgxstore,gormstore}/mfa_test.go` (to run the race on each durable store), `test/storetest/deviceproof_suite.go`, `test/storetest/mfa_suite.go`, `test/storetest/broken_mfa_test.go`, `authenticate/mfa/totp.go`, `authenticate/mfa/totp_test.go`, `README.md`, `store/sqlstore/mfa.go`, `store/pgxstore/mfa.go`, comments in `internal/pgschema/mfa.go`, `store/gormstore/mfa.go` and `authenticate/mfa/store_memory.go`.

- [ ] **Step 1 (red):** add the race case: one pending enrolment on one generation, a confirmation and a device proof released together by a barrier, repeated across independent enrolments. Assert never both succeed. Add the broken variants "Store confirming by reading and then writing" and "Store whose refusal still writes", and see each fail at its named case; a variant the suite passes is the failure to look for.
- [ ] **Step 2:** register `confirmRefusedNoCodeCase`, `confirmRefusedDeadCase` and `proofOnConfirmedCase` in `RunDeviceProofSuite`, and simplify `RunEnrolmentStoreSuite`'s sentence about what that suite runs.
- [ ] **Step 3:** godoc and README per `tasks.md` 4.5. Comments on the forward-only step say safety net, not guarantee. No behaviour changes.
- [ ] **Step 4:** the verification of task 4.3–4.4's Step 5. Expected: PASS, including the race case on every store under `-race`.

---

### Task 5.1–5.2: Integration gate (main session)

- [ ] **5.1:** rebase on `origin/main`, then dispatch a fresh Opus reviewer that edits nothing. It gets the ten spec deltas, decisions 1–6, and `git diff main...HEAD`. Findings are labelled `REPRODUCED` (with a failing check) or `UNREPRODUCED`, and go back to the owning dispatch.
- [ ] **5.2:** run `make check` on a quiet tree and `openspec validate pre-release-api-fixes --strict`, and keep the outputs. Re-check the intermittent failures in Global Constraints, and the `test` package failure seen once during concurrent edits.

---

## Group 6: the review of #68

Every claim here is UNREPRODUCED until its red step. A red step that does not fail stops the task: report it, with the output, and the main session removes the claim's text. Each dispatch gets a fresh reviewer that edits nothing: Opus for P6c and P6f, Sonnet for the rest.

### Task 6.1: A provider returning nothing to Basic (decision 3; dispatch P6a)

**Files:** `httpsec/basic.go`, `httpsec/login.go`, `httpsec/no_identifier_test.go`.

- [ ] **Step 1 (red):** `TestBasic_ProviderReturningNoAuthentication`, a table with rows `(nil, nil)` and `(&authenticate.Authentication{}, nil)`, a provider given directly, and `ada` holding four failures. Assert: status 500, `errors.Is(err, token.ErrNoSubject)`, handler not run, no `WWW-Authenticate` header, four failures remain, one ERROR record of fixed text. Add a row to the form login test asserting the four failures remain.
- [ ] **Step 2:** `go test -run 'TestBasic_ProviderReturningNoAuthentication' -count=1 ./httpsec/`. Expected: the `(nil, nil)` row panics with a nil dereference at `basic.go:251`. Record what the other rows do.
- [ ] **Step 3 (green):** in `basic.go`, straight after the error check, refuse `auth == nil || auth.Principal == nil`, using the sampled record form login's tail uses. In `login.go`, make `resetFailures` conditional on an authentication with a principal; `hadRecentFailures` and the nil replacement keep their behaviour.
- [ ] **Step 4:** `go test -race -count=1 ./httpsec/...`, and the `ginsec` and `fibersec` modules. Expected: PASS.

### Task 6.2: The JWT authenticator checks a generator verifier (decision 3; dispatch P6b)

**Files:** `authenticate/jwt.go`, `authenticate/jwt_test.go`.

- [ ] **Step 1 (red):** `TestNewJWTAuthenticator_SubjectModeAgreement`, a table: generator by username with a default provider, default generator with a username provider (both `errors.Is(err, authenticate.ErrConfig)`); agreeing pairs in each mode (build); a verifier that is not a generator (builds); a typed-nil generator (the existing configuration error, no panic). Run it. Expected: the two disagreeing rows fail on a nil error.
- [ ] **Step 2 (green):** in `NewJWTAuthenticator`, after the nil check, `if g, ok := a.verifier.(token.Generator); ok && g.SubjectMode() != a.subject`, return a wrapped `ErrConfig` naming both options.
- [ ] **Step 3:** rewrite `WithJWTUsernameSubject`'s last paragraph per decision 3, and add the check to `NewJWTAuthenticator`'s godoc.
- [ ] **Step 4:** `go test -race -count=1 ./authenticate/...`. Expected: PASS.

### Task 6.3–6.4: Shutdown, and the listing housekeeping uses (decision 4; dispatches P6c, P6c2)

Steps 1 and 2 are implemented, and stay. Steps 3 to 6 were implemented as first written, and dropped by decision 4 once they REPRODUCED a stale listing deleting the newest stored key. Dispatch P6c2 does Steps 3 to 5 below.

**Files:** `token/signingkey/keys_rotate.go`, `keys.go`, `doc.go` and their tests.

- [ ] **Step 1 (red, 6.3):** `TestShutdown_StoreCallIsNotReported`, a table with rows for rotation, reload and housekeeping, over a store that blocks until its context ends and returns `ctx.Err()`. Assert no error-hook call, no ERROR record, and `Shutdown` returns nil. Add "Store failure before shutdown": a store returning `context.Canceled` on a live context is reported. Run them. Expected: the three shutdown rows fail on a hook call; report any that does not.
- [ ] **Step 2 (green, 6.3):** `km.report` returns at once when its `ctx.Err() != nil`. The context it is given ends only at `Shutdown`, since `Start` builds it with `context.WithoutCancel`. Confirm with gopls that no other caller passes a different context.
- [ ] **Step 3 (6.4):** `deleteRetired` lists the store with `km.store.LoadAll`, and a failed listing reports `signingkey: list retired keys` with `reasonStore` and returns. The rule stays: `newestByAlg`, `retireTimes`, the current and newest guards, and the grace. `km.report`'s shutdown check stays.
- [ ] **Step 4 (6.4):** tests. Remove "A housekeeping run that deletes a key loads nothing from the store". Restore "Store cannot list during housekeeping" per its scenario, and the load counts in `TestLifecycleLoopsRunOnTheClock`. Rename the row on a key the store has lost to the scenario's name, "Key removed from the store since the last reload". Keep the corrected seed of "A held key the store no longer lists…", and "Rotation since the listing leaves the key it replaced in the store" only if it still proves something against a fresh listing. Correct `deleteRetired`'s godoc, `doc.go` and `keys.go` to the store's own listing.
- [ ] **Step 5:** a temporary mutation that decides from `km.listed` fails "Key removed from the store since the last reload" and "Deletion judges a key's successor from the listing alone". Edit it back.
- [ ] **Step 6:** the verification of task 3.3's Step 8. Expected: PASS.

### Task 6.5: A reload with nothing to drop (decision 4; dispatch P6e)

**Files:** `token/signingkey/keys_rotate.go`, a new `token/signingkey/keys_bench_test.go`.

- [ ] **Step 1:** `BenchmarkReload_RetiredKeysKept` over 50, 1000 and 10000 listed keys. Run with `-benchmem -count=10`, and save the output.
- [ ] **Step 2:** `dropUnlistedLocked` returns before calling `dropLocked` when every held key is in the listing.
- [ ] **Step 3:** run the benchmark again and compare with `benchstat`. If 1000 keys shows no gain, edit the change back and report it.
- [ ] **Step 4:** a temporary mutation that always returns early fails `TestHousekeeping_Replicas`, row "Deleted key not republished on reload". Edit it back. `go test -race -count=1 ./token/signingkey/...` passes.

### Task 6.6: One helper for `Delete` (decision 4; dispatch P6d)

**Interfaces:** `func storekit.StorableSet(values []string) (set string, ok bool)`: the JSON array of the values PostgreSQL text can hold, and false when none can. It keeps the input unchanged.

- [ ] **Step 1 (red):** `TestStorableSet`, a table: none, all storable, NUL, invalid UTF-8, a mix, and the input slice unchanged. Add a stub so it compiles, and see it fail.
- [ ] **Step 2 (green):** implement it in `internal/storekit/storekit.go`. Marshalling a `[]string` cannot fail, so it returns no error.
- [ ] **Step 3:** the three `Delete`s call it and return nil on false. The duplicate filter and the `json.Marshal` error branch go.
- [ ] **Step 4:** `go test -race -count=1 ./internal/storekit/...`, the `store/*` modules, and in `test`, `./storetest/ ./sqlstore/ ./pgxstore/ ./gormstore/` with Docker. Expected: PASS.

### Task 6.7: The admit step returns what it loaded (decision 3; dispatch P6f)

**Interfaces:**
- `resolver.admit` and `Exchange.admitRenewal` become `func(ex *Exchange, s *session.Session) (*identity.Details, error)`. A nil record means the caller loads the user by the session's reference, as under the default.
- The `resolver.admitted` field goes.

- [ ] **Step 1 (red):** in `TestBearer_SubjectIsTheSessionUser`, assert the late-renewal row under usernames loads the user once. Run it. Expected: it fails with two loads, by username and then by user identifier.
- [ ] **Step 2 (green):** change the signature, `resolve.go:155`, and `session_renewal.go:334`, which keeps the record for its own load and every check that follows.
- [ ] **Step 3:** `requireUserIdentifier` moves out of `prepareLogin` into `redemption.go`, before its call at `:410`. `completeLogin` keeps its own call before any side effect. Correct the comment at `complete.go:530`.
- [ ] **Step 4:** temporary mutations, edited back: skipping the identifier comparison fails the late-renewal row, and removing the call in `redemption.go` fails `TestMagicLink_NoIdentifier` and `TestOIDCHandoff_NoIdentifierRefusedInsideTheChecks`.
- [ ] **Step 5:** the verification of Task 2.3–2.4's Step 7. Expected: PASS.

### Task 6.8: Group 6's gate (main session)

- [ ] **Step 1:** a fresh Opus reviewer, who edits nothing, checks group 6's diff against the scenarios it covers and decisions 3 and 4. Findings are labelled `REPRODUCED` or `UNREPRODUCED`.
- [ ] **Step 2:** `make check` on a clean worktree, and `openspec validate pre-release-api-fixes --strict`. Keep the outputs.
- [ ] **Step 3: commits,** one per fix, staging exact paths, each carrying its test.
