# Pre-release Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task, under `.claude/rules/subagent-delegation.md`. The main session dispatches, verifies, reviews and commits; subagents write code. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix every defect the 2026-10-23 audit and sibling sweep reproduced, and the unreproduced ones whose red test fails, before `v0.1.0`.

**Architecture:**
- The work runs in ten lanes with disjoint file ownership (`design.md` decision 18).
- Port changes own every implementer, mock and suite of their port.
- Lane F (store isolation) lands before lane E (bounded issuance), which reuses F's transaction helper. Lane D (MFA port) lands before E, because they share conformance fixtures.
- All other lanes run in parallel.

**Tech Stack:** Go 1.27, PostgreSQL 15/18 via testcontainers, pgx v5, database/sql, gorm, fiber v3, gin, jwx v4, uber-go/mock, testify.

**Spec:** `openspec/changes/pre-release-hardening/` (`proposal.md`, `design.md`, `specs/**`, `tasks.md`). Executors read the delta spec and design decision named in each task.

## Global Constraints

- **Test-first** (`golang-tdd.md`): each red test is run and seen failing for the intended reason before any code. A compile error is not a red step.
- **Defect claims** (`defect-claims.md`): an `UNREPRODUCED` item's red test that passes on HEAD drops the item. The implementer reports it, and the main session removes the spec scenario.
- **Library design** (`library-design.md`): every changed default names its override in godoc, or states why there is none.
- **Test conventions:**
  - table tests use the `table-test` skill (`assert` closures, `t.Context()`);
  - mocks come from `use-mockgen`, regenerated with `go generate` when a port changes;
  - PostgreSQL comes through the existing `test` module helpers (`use-testcontainers`).
- **Legacy reference:** consulted only per `legacy-reference.md`, and never cited in code, docs or commits.
- **Ceilings, fixed values:**
  - scrypt `p ≤ 16` and `(N+p)·128·r ≤ 1 GiB`;
  - bcrypt `cost ≤ 16`;
  - Argon2id memory ≤ 1 GiB, iterations ≤ 16, threads ≤ 16, salt ≤ 64 B, key ≤ 64 B.
- **Bounds:**
  - OIDC `next` ≤ 2048 bytes;
  - skew ≤ 5 min;
  - logout max-age ≤ 1 h;
  - attempt store 100,000 identifiers, with identifiers over 256 bytes digested;
  - log sampler 100,000 keys per window;
  - delete loops ≤ 64 passes;
  - TOTP period and token lifetime: whole seconds, at least 1 s.
- **Errors:** every new sentinel is registered in `httpsec/status_test.go` `TestStatusForErrorCoversEverySentinel`, through lane A (task 4.5).
- **Git:** no agent runs `checkout --`, `restore`, `reset --hard`, `stash` or `clean`. The main session commits after each green, reviewed task.

## Review Focus

These five failure modes are implied by the spec but no single task's tests exercise them. Each line names the test added to its owning task.

1. **A bounded insert inside a caller's REPEATABLE READ transaction** must refuse, not over-issue silently. Owner: task 3.1, `TestInsertWithin_RefusesCallerRepeatableReadTx`.
2. **A disabled user's logout** returns authentication-required and leaves the session in the store. That is the documented "refuse, don't revoke" behaviour, not a crash. Owner: task 4.1, the case `"disabled user's logout is refused and revokes nothing"`.
3. **A recovery request naming a saved code plus email-MFA** must still succeed after M4. Owner: task 7.1, the case `"saved code with an emailed MFA code still recovers"`.
4. **A verify-only replica that never calls `Start`** must still drop a past-lifetime key at construction. Owner: task 8.1, the case `"manager never started drops a past-lifetime key"`.
5. **A cool-down marked on `/`** must not match every path once trailing slashes are trimmed. Owner: task 4.2, the case `"root route marked matches only root"`.

---

## Lane F — Store isolation (tasks 1.1–1.5) · Opus

### Task 1.1: READ COMMITTED transaction helper

**Files:**
- Modify: `pgx/identity.go:514` (`atomically`), `pgx/recoverycode.go:159,169`, `pgx/session.go` (supersede tx), `pgx/attempts.go:115-139`, `pgx/limiter.go` (record)
- Modify: the same sites in `sqlstore/` (`identity.go:501`, `recoverycode.go:158,168`, `session.go`, `attempts.go:136`), `gorm/` (`identity_tx.go:15`, `recoverycode.go:179,189`, `session.go:660`, `attempts.go:171`) and `internal/pglimiter/runner.go:98`
- Create: `internal/pgschema/isolation.go`
- Test: `test/pgxstore/isolation_test.go`, `test/sqlstore/isolation_test.go`, `test/gormstore/isolation_test.go`

**Interfaces:**
- Produces: `pgschema.SetReadCommitted = "SET TRANSACTION ISOLATION LEVEL READ COMMITTED"` and `pgschema.CurrentIsolation = "SELECT current_setting('transaction_isolation')"`. One unexported helper per backend:
  - `pgx`: `func (c *conn) readCommitted(ctx context.Context, fn func(pgx.Tx) error) error`
  - `sqlstore`: `func (c *conn) readCommitted(ctx context.Context, fn func(*sql.Tx) error) error`
  - `gorm`: `func readCommitted(ctx context.Context, db *gorm.DB, fn func(*gorm.DB) error) error`

  Each runs `SetReadCommitted` first. Lane E reuses them.

- [ ] **Step 1: Write the failing tests.** The tests set `ALTER DATABASE … SET default_transaction_isolation = 'repeatable read'` on the test's own database. Then:
  - `TestStreak_CountsEveryConcurrentFailureUnderRepeatableReadDefault`: 16 racers, then `require.Equal(t, 17, count)`.
  - `TestRecoveryReplace_KeepsOnlyLaterSetUnderRepeatableReadDefault`: 10 codes remain, and no code of set A matches.
  - `TestProvision_OneWinnerUnderRepeatableReadDefault`: won is 1 and exists is 7, with no `SQLSTATE 40001`.
  - `TestLimiterRecord_NoBackendFailureUnderRepeatableReadDefault`: 0 of 16 racers return `ratelimit: backend unavailable`.
- [ ] **Step 2: Run them and see them fail.** `(cd test && go test -race -count=1 -run 'RepeatableReadDefault' ./pgxstore/ ./sqlstore/ ./gormstore/)`. Expected: FAIL with 40001 and wrong counts, matching the audit's `TestAudit_*` and `TestSweep_*` output.
- [ ] **Step 3: Route the sites through `readCommitted`.** Every store-owned transaction and the `StreakAdd` and limiter-record statements go through it. The autocommit statements become one-statement READ COMMITTED transactions.
- [ ] **Step 4: Run step 2 again, on PostgreSQL 18 and on 15.** Run 15 with `SCRTY_TEST_POSTGRES_IMAGE=postgres:15.19-alpine`. Expected: PASS.
- [ ] **Step 5: Commit** `fix(stores): store-owned transactions run at READ COMMITTED whatever the database default`.

### Task 1.2: Refuse a caller's stronger transaction

**Files:** the `WithTx` savepoint paths of recovery-code replace and `AddStreakFailure` in `pgx/`, `sqlstore/` and `gorm/`; `test/{pgx,sql,gorm}store/isolation_test.go`

**Interfaces:**
- Produces: `var ErrIsolationTooStrong` in each backend package (`pgx.ErrIsolationTooStrong`, etc.), wrapped with the level found.
- Produces an unexported `func (c *conn) requireReadCommitted(ctx context.Context, tx …) error`, called first in the savepoint path. Lane E reuses it.

- [ ] **Step 1: Write `TestRecoveryReplace_RefusesCallerRepeatableReadTx`.**
  - Begin a REPEATABLE READ tx, `WithTx`, then `Replace`.
  - Assert `errors.Is(err, pgx.ErrIsolationTooStrong)`, that the message contains `repeatable read`, and that a following `SELECT 1` in the tx succeeds.
  - Do the same in `sqlstore` and `gorm`.
- [ ] **Step 2: Run it and see it fail.** Expected: `err` is nil, and both sets remain.
- [ ] **Step 3: Implement `requireReadCommitted`** in the savepoint path.
- [ ] **Step 4: Run the tests.** Expected: PASS on all backends.
- [ ] **Step 5: Hand the sentinel to task 4.5. Commit** `fix(stores): READ COMMITTED operations refuse a caller's stronger transaction`.

### Task 1.3: Bounded user-wide deletes (U2, UNREPRODUCED)

**Files:** `pgx/session.go:414` (`deleteUntilNone`), `sqlstore/session.go:389`, `gorm/session.go:519` (`untilNone`); `test/storetest/session_suite.go`

**Interfaces:**
- Produces: `session.ErrDeleteDidNotSettle` (in `session/store.go`), returned after 64 passes that each removed rows. The constant is `maxDeletePasses = 64`, in each backend.

- [ ] **Step 1: Write the storetest case `"deleting a user's sessions settles under concurrent creates"`.**
  - One goroutine creates sessions for `u-1` in a loop until stopped. Another calls `DeleteByUser` with a 5 s context.
  - Assert that it returns in under 2 s, and that `err == nil || errors.Is(err, session.ErrDeleteDidNotSettle)`.
- [ ] **Step 2: Run it.** `(cd test && go test -race -count=1 -run 'settles under concurrent' ./pgxstore/ ./sqlstore/ ./gormstore/)`.
  - Expected: FAIL by hitting the deadline.
  - If it passes on HEAD, report that, skip steps 3–4, and the main session drops the requirement.
- [ ] **Step 3: Bound the loops at `maxDeletePasses`.**
- [ ] **Step 4: Run it.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(stores): user-wide session deletes settle in a bounded number of passes`.

### Task 1.4: Isolation suite in storetest

**Files:** Create `test/storetest/isolation_suite.go`; wire it in `test/{pgx,sql,gorm}store/*_test.go`.

**Interfaces:**
- Produces: `func RunIsolationSuite(t *testing.T, f IsolationFixture)`. `IsolationFixture` supplies a database whose default is REPEATABLE READ and a `BeginRepeatableRead`. A missing input fails the suite, per "Required suite inputs cannot be skipped".

- [ ] **Step 1: Move the task 1.1 and 1.2 cases into `RunIsolationSuite`.** Add the case `"a store inheriting the default fails"` as a self-check against a deliberately broken fixture store.
- [ ] **Step 2: Run against the broken fixture.** Expected: FAIL on the replace and streak cases.
- [ ] **Step 3: Wire it for all three backends.**
- [ ] **Step 4: Run `(cd test && go test -race -count=1 ./...)` on 18 and 15.** Expected: PASS.
- [ ] **Step 5: Commit** `test(storetest): isolation suite proves guarantees under a repeatable-read default`.

### Task 1.5: Review (Opus)

- [ ] A fresh reviewer checks the lane F diff against D8 and the `security-state-stores` and `store-conformance` deltas, and reports `REPRODUCED`/`UNREPRODUCED` for any claimed defect. Findings go to a fresh lane F dispatch.

## Lane D — TOTP enrolment generations (tasks 2.1–2.4) · Opus

### Task 2.1: Generation-conditional `Confirm` and `AcceptStep`

**Files:**
- Modify: `mfa/store.go:140,145`, `mfa/memory.go`, `mfa/totp.go:246,523`, `pgx/mfa.go`, `sqlstore/mfa.go`, `gorm/mfa.go`, `seal/mfa.go`, `internal/pgschema/mfa.go`
- Regenerate: `mfa/store_mock_test.go`, `seal/enrolmentstore_mock_test.go` and `httpsec/enrolmentstore_mock_test.go`, with `go generate ./mfa/ ./seal/ ./httpsec/`
- Modify: `test/storetest/{mfa_suite,deviceproof_suite,broken_mfa_test}.go`, `test/internal/storefix/{races,ambients}.go`, `test/{pgx,sql,gorm}store/broken_test.go`
- Modify: `mfa/{totpreplay_test,totp_test}.go`

**Interfaces:**
- Produces, on `mfa.EnrolmentStore`:
  ```go
  Confirm(ctx context.Context, user identity.UserID, gen id.ID, step int64, at time.Time) (bool, error)
  AcceptStep(ctx context.Context, user identity.UserID, gen id.ID, step int64) (bool, error)
  ```
  A zero `gen` matches nothing.
- `TOTP` passes `Enrolment.Generation` as read. A false result maps to `ErrInvalidCode`.

- [ ] **Step 1: Write the failing tests.**
  - `TestConfirmEnrolment_NeverConfirmsASecretTheCodeWasNotFor`: a store wrapper calls `PutPending(B)` between `Get` and `Confirm`. Assert `ErrorIs(err, mfa.ErrInvalidCode)`, and that `Get` reads as unconfirmed with secret B.
  - `TestVerify_RefusesCodeOfARemovedSecretAfterReEnrolment`: the wrapper deletes and re-enrols as G2 between the check and `AcceptStep`. Assert `ErrInvalidCode`.
  - storetest cases:
    - `"confirm naming a replaced generation is refused"`;
    - `"accept naming a removed generation is refused"`;
    - `"a zero generation writes nothing"`.
- [ ] **Step 2: Run them.** `go test -race -count=1 -run 'NeverConfirms|RemovedSecret' ./mfa/`. Expected: FAIL with `"BBBBBBBBBBBBBBBBBBBB"` confirmed, or a nil error.
- [ ] **Step 3: Change the port, every implementer and the SQL.** The SQL adds `AND generation = $n`. Regenerate the mocks and update the fakes and broken stores.
- [ ] **Step 4: Run the tests.** `go test -race -count=1 ./mfa/ ./seal/ ./httpsec/` and `(cd test && go test -race -count=1 ./storetest/... ./pgxstore/ ./sqlstore/ ./gormstore/)`. Expected: PASS.
- [ ] **Step 5: Commit** `fix(mfa): confirmation and step acceptance are conditional on the enrolment generation`.

### Task 2.2: Whole-second period; `ErrConfig` everywhere

**Files:** `mfa/totp.go:81-143`, `mfa/totpoptions.go:34`, `mfa/throttle.go:95-109`; test `mfa/totp_config_test.go`

- [ ] **Step 1: Write the failing tests.**
  - `TestNewTOTP_RefusesSubSecondPeriod`, a table over 500 ms and 45.5 s, asserting `ErrorIs(err, mfa.ErrConfig)` and no panic.
  - `TestMFAConstructors_ErrorsAreConfigErrors`, a table over a nil store, empty issuer, 7 digits, a nil logger and a nil throttle logger, each asserting `ErrorIs(err, mfa.ErrConfig)`.
- [ ] **Step 2: Run them.** Expected: a divide-by-zero panic at `totp.go:303`, and errors not wrapping `ErrConfig`.
- [ ] **Step 3: Validate the period** (`period < time.Second || period%time.Second != 0`), and wrap each constructor error with `fmt.Errorf("%w: …", ErrConfig)`.
- [ ] **Step 4: Run `go test -race -count=1 ./mfa/`.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(mfa): TOTP period is whole seconds, and every config error is ErrConfig`.

### Task 2.3: Sealed secret bound to its generation (U3, U12)

**Files:** `seal/aad.go:47`, `seal/mfa.go` (callers and `enrolmentFailed` at :276); test `seal/mfa_aad_test.go`

**Interfaces:**
- Produces: `func MFASecretAAD(user identity.UserID, gen id.ID) []byte`.

- [ ] **Step 1: Write `TestSealedEnrolment_RefusesSecretRestoredFromEarlierGeneration`.** Seal a G1 secret, re-enrol as G2, copy the G1 ciphertext onto the row, then `Get`. Assert an error.
- [ ] **Step 2: Run it.** Expected: `Get` succeeds.
- [ ] **Step 3: Add `gen` to the AAD at every seal and open site.** Replace `err == mfa.ErrAlreadyEnrolled` with `errors.Is`. The godoc states that existing sealed secrets need re-enrolment.
- [ ] **Step 4: Run `go test -race -count=1 ./seal/` and the sealed-column suite.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(seal): a sealed TOTP secret is bound to its enrolment generation`.

### Task 2.4: Review (Opus)

- [ ] A fresh reviewer checks against D10 and the `multi-factor-auth`, `security-state-stores`, `secrets-at-rest` and `store-conformance` deltas.

## Lane E — Atomic bounded issuance (tasks 3.1–3.7) · Opus · after lanes F and D

### Task 3.1: `onetime` bounded insert

**Files:**
- Modify: `onetime/store.go:50`, `onetime/manager.go`, `onetime/memory.go` (the in-memory store), `pgx/onetime.go`, `sqlstore/onetime.go`, `gorm/onetime.go`, `internal/pgschema/onetime.go`
- Regenerate: `onetime/mocks_test.go`, `recovery/tokenstore_mock_test.go`, `httpsec/onetimestore_mock_test.go`
- Modify: `test/storetest/{onetime_suite,broken_onetime_test}.go`

**Interfaces:**
- Consumes: the lane F `readCommitted` and `requireReadCommitted` helpers.
- Produces:
  ```go
  // onetime.Store
  InsertWithin(ctx context.Context, tok Token, since time.Time, limit int) (bool, error)
  // onetime.Manager
  func (m *Manager) IssueWithin(ctx context.Context, subject string, limit int, opts ...IssueOption) (string, Token, error)
  var ErrIssueLimitReached = errors.New("onetime: issuance limit reached")
  ```
- The SQL: `pg_advisory_xact_lock(hashtextextended('onetime:'||purpose||':'||subject, 0))`, then `CountRecentBySubject`, then the insert, inside `readCommitted`. Under `WithTx` it calls `requireReadCommitted` first.

- [ ] **Step 1: Write the failing tests.**
  - `TestIssueWithin_ConcurrentBoundedIssuesStayWithinLimit`: 20 goroutines against a limit of 5 give 5 issued and 15 `ErrIssueLimitReached`.
  - storetest race cases:
    - `"bounded inserts for one subject never exceed the limit"`;
    - `"different subjects do not contend"`;
    - `"a refused bounded insert writes nothing"`.
  - `TestInsertWithin_RefusesCallerRepeatableReadTx` (Review Focus 1).
- [ ] **Step 2: Run them and see them fail on behaviour.** A compile error is not the red step. First add `InsertWithin` to the port and the memory store as a plain count-then-insert, so the code compiles. The race case then fails with more than 5 issued.
- [ ] **Step 3: Implement it.** Memory decides under its mutex; the SQL uses the advisory lock. Regenerate the mocks.
- [ ] **Step 4: Run** `go test -race -count=1 ./onetime/` and `(cd test && go test -race -count=1 -run 'Onetime|Isolation' ./...)` on 18 and 15. Expected: PASS.
- [ ] **Step 5: Commit** `feat(onetime): bounded issuance decided under a per-subject lock`.

### Task 3.2: Magic-link and recovery start

**Files:** `magiclink/manager.go:301-309`, `recovery/start.go:69`; tests `magiclink/issuance_race_test.go`, `recovery/start_race_test.go`

- [ ] **Step 1: Write the failing tests.** `TestRequest_ConcurrentBurstStaysWithinIssuanceLimit` has 20 requests against the default 5. It asserts `links ≤ 5` and `emails sent ≤ 5`, with a store that holds the count until all have counted. Also write `TestStart_ConcurrentBurstStaysWithinIssuanceLimit`.
- [ ] **Step 2: Run them.** Expected: `"20" is not less than or equal to "5"`.
- [ ] **Step 3: Replace the `IssuedCount` + `Issue` pairs** with `IssueWithin`. `ErrIssueLimitReached` maps to the existing uniform outcome.
- [ ] **Step 4: Run `go test -race -count=1 ./magiclink/ ./recovery/`.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(magiclink,recovery): per-user issuance limits hold under concurrent requests`.

### Task 3.3: MFA begin (N2) and the sweep clock

**Starts after group 4 has landed.** Task 4.3 edits `writeMFABegin` in the same file.

**Files:** `httpsec/mfabegin.go:119-128,200` (these functions only, handed over from lane A); tests `httpsec/mfabegin_race_test.go`, plus the counting doubles in `httpsec/mfabegin_test.go`

- [ ] **Step 1: Write the failing tests.**
  - `TestMFABegin_ConcurrentBeginsDoNotExceedChallengeLimit`: 12 begins against a limit of 3 issue at most 3.
  - `TestSweepClock_ClaimsAfterClockStepsBackwards`: claim at T, then at T−1h, then at T−1h+window+1s. Assert that the third claim succeeds.
- [ ] **Step 2: Run them.** Expected: 12 issued, and the third claim refused.
- [ ] **Step 3: Use `IssueWithin`.** In `claim`, reset `c.last = now` when `now.Before(c.last)`.
- [ ] **Step 4: Run `go test -race -count=1 -run 'MFABegin|SweepClock' ./httpsec/`.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(httpsec): MFA challenge cap holds under concurrent begins`.

### Task 3.4: Passkey bounded insert and registration begin

**Files:** `passkey/store.go:24`, `passkey/memstore.go`, `passkey/register.go:53-58,204`, `pgx/passkeycredential.go`, `sqlstore/passkeycredential.go`, `gorm/passkeycredential.go`, `internal/pgschema/passkey.go`, `test/storetest/{passkeycredential_suite,broken_passkey_test}.go`, `test/internal/storefix/passkey.go`

**Interfaces:**
- Produces: `passkey.CredentialStore.InsertWithin(ctx context.Context, c *Credential, limit int) (bool, error)`. It uses the advisory key `'passkey:'||user`, and a false result maps to the passkey-limit refusal.
- Registration begin uses `m.registration.IssueWithin(ctx, subject, m.issueLimit)`.

- [ ] **Step 1: Write the failing tests.**
  - `TestFinishRegistration_ConcurrentFinishesStayWithinPasskeyLimit`: limit 1, 4 finishes, and the wrapped store's `Count` waits for all four. Expected: 1 stored and 3 passkey-limit refusals.
  - `TestBeginRegistration_ConcurrentBeginsStayWithinChallengeLimit`.
  - The storetest bounded-insert race cases for passkeys.
- [ ] **Step 2: Run them.** Expected: `"4" is not less than or equal to "1"`.
- [ ] **Step 3: Implement it** on every backend, and move the finish and begin onto the bounded calls. Plain `Insert` stays.
- [ ] **Step 4: Run** `go test -race -count=1 ./passkey/` and `(cd test && go test -race -count=1 -run Passkey ./...)`. Expected: PASS.
- [ ] **Step 5: Commit** `fix(passkey): passkey and registration-challenge limits are decided by the write`.

### Task 3.5: Backup state without eligibility (L8)

**Files:** `passkey/register.go` (`FinishRegistration`), the `passkey` assertion check (`checkAssertion`); test `passkey/backupflags_test.go`

- [ ] **Step 1: Write the failing tests.** `TestFinishRegistration_RefusesBackupStateWithoutEligibility` and `TestFinishLogin_RefusesBackupStateWithoutEligibility`, each with a fake verifier returning BS=1 and BE=0. Assert the authentication-failed refusal, and that nothing is stored or recorded.
- [ ] **Step 2: Run them.** Expected: accepted.
- [ ] **Step 3: Refuse `!BackupEligible && BackupState`** in the core, before the registration check and the login check.
- [ ] **Step 4: Run `go test -race -count=1 ./passkey/...`.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(passkey): refuse a backed-up state without backup eligibility`.

### Task 3.6: Sentinel registration

- [ ] Hand `onetime.ErrIssueLimitReached` to task 4.5. Verify `go test -count=1 -run TestStatusForErrorCoversEverySentinel ./httpsec/` once 4.5 lands.

### Task 3.7: Review (Opus)

- [ ] A fresh reviewer checks against D7 and the `one-time-tokens`, `magic-link`, `account-recovery`, `multi-factor-auth`, `passkey-authentication`, `security-state-stores` and `store-conformance` deltas.

## Lane A — httpsec (tasks 4.1–4.6) · Opus for 4.1, 4.2; Sonnet for 4.3–4.5

### Task 4.1: Own, active user

**Files:** `httpsec/resolve.go:73` (`sessionResolver.resolve`, after the user load), `httpsec/renewal.go` (the renewal path's user reload through `sessionRenewal.users`), `httpsec/recoverycodes_test.go:328-341` (fixture); tests `httpsec/bearer_identity_test.go`, `httpsec/renewal_identity_test.go`. Recovery `Finish`'s defensive ID check belongs to task 7.3, which owns `recovery/hold.go`.

- [ ] **Step 1: Write the failing tests.**
  - `TestBearer_RefusesTokenWhenUsernameReassigned`: the token is for u-1's session, and the loader returns u-2 for the username. Assert `ErrAuthenticationRequired`, and that the handler did not run.
  - `TestBearer_RefusesDisabledUser`.
  - `TestSessionReference_RefusesDisabledUser`.
  - `TestRenewal_RefusesDisabledUser`, with cases inside and after the grace window.
  - `TestBearer_ReEnabledUserAuthenticatesAgain`.
  - The case `"disabled user's logout is refused and revokes nothing"` (Review Focus 2).
- [ ] **Step 2: Run them.** Expected: `handler ran as principal "u-2"`, and `handler ran as disabled user`.
- [ ] **Step 3: Add the check.** After the load: `if details.ID != s.UserID || !details.Active { return ErrAuthenticationRequired }`. Add the same check in renewal. Fix the `TestRecoveryCodes` fixture to use one user ID.
- [ ] **Step 4: Run** `go test -race -count=1 ./httpsec/` and `(cd test && go test -race -count=1 ./httpsecconformance/...)`. Expected: PASS.
- [ ] **Step 5: Commit** `fix(httpsec): a session authenticates only its own, active user`.

### Task 4.2: Cool-down matching

**Files:** `httpsec/recoverycooldown.go:18,45,97`; test `httpsec/recoverycooldown_match_test.go`

**Interfaces:**
- Produces: the unexported `func normalizeRoute(method, path string) Route`:
  - the method upper-cased, with `HEAD` becoming `GET`;
  - the path lower-cased in ASCII;
  - every trailing `/` removed, an empty result becoming `/`.

  It is applied at `EnableRecoveryCooldown` and per request.

- [ ] **Step 1: Write `TestRecoveryCooldown_Matching`.** It is a table with cases:
  - `/Account/Email` and `/account/email/` refused;
  - `HEAD /account/export` on a marked GET refused;
  - `POST /account/email/x` allowed;
  - `GET /account/email` allowed when POST is marked;
  - `"root route marked matches only root"` (Review Focus 5);
  - `POST /MFA/verify/totp` not exempted by the MFA gate.
- [ ] **Step 2: Run it.** Expected: the variants allowed. If the `HEAD` case passes on HEAD, report it as not reproducing and keep it as a regression case.
- [ ] **Step 3: Implement `normalizeRoute`.** Update the godoc: it states the over-match and the fiber caveat for consumer authorization rules.
- [ ] **Step 4: Run `go test -race -count=1 -run 'Cooldown|Gate' ./httpsec/`.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(httpsec): recovery cool-down matches every path a lenient router sends to a marked route`.

### Task 4.3: `no-store`

**Files:** `httpsec/login.go:671` (`writeSuccessDocument`), `httpsec/mfabegin.go:60` (`writeMFABegin`); test `httpsec/nostore_test.go`

- [ ] **Step 1: Write `TestDefaultResponders_AreNotCacheable`.** It is a table over form login, magic-link redeem, MFA verify, MFA begin and passkey login, each asserting `Cache-Control: no-store`. Add a consumer-responder case asserting the header is absent.
- [ ] **Step 2: Run it.** Expected: `expected "no-store" actual ""`.
- [ ] **Step 3: Set the header** in the two writers.
- [ ] **Step 4: Run it.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(httpsec): credential-bearing default responses are never cached`.

### Task 4.4: Guard wiring panics; OIDC `next` bound

**Files:** `httpsec/guards.go:243,258`, `httpsec/oidc_authorize.go:26`; tests `httpsec/guards_wiring_test.go`, `httpsec/oidc_authorize_test.go`

- [ ] **Step 1: Write the failing tests.**
  - `TestOwnershipGuard_PanicsAtWiringOnNilChecker`: `assert.PanicsWithValue` names the checker.
  - `TestOwnershipGuard_PanicsAtWiringOnNilExtractor`.
  - `TestOIDCAuthorize_DropsOverLongNext`: a 4096-byte `next` reaches the broker as `""`.
- [ ] **Step 2: Run them.** Expected: no wiring panic, and the raw `next` is passed through.
- [ ] **Step 3: Implement it.** Panic with `"httpsec: ResourceOwnerships needs a non-nil checker"`, and the equivalent for the extractor. Drop a `next` longer than 2048 bytes.
- [ ] **Step 4: Run `go test -race -count=1 ./httpsec/`.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(httpsec): guards fail at wiring, and OIDC next is bounded`.

### Task 4.5: Sentinel registry

**Files:** `httpsec/status.go:159`, `httpsec/status_test.go:410`

- [ ] **Step 1: Add the rows** for `apikey.ErrRotationRefused`, `onetime.ErrIssueLimitReached`, `session.ErrDeleteDidNotSettle` and the backend `ErrIsolationTooStrong`s to `TestStatusForErrorCoversEverySentinel`.
- [ ] **Step 2: Run it.** Expected: FAIL for each unmapped sentinel.
- [ ] **Step 3: Map them.**
  - `ErrIssueLimitReached` → 429.
  - `ErrRotationRefused` → 409.
  - The isolation and did-not-settle errors → 500.
- [ ] **Step 4: Run it.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(httpsec): map the sentinels the hardening adds`.

### Task 4.6: Review (Opus)

- [ ] A fresh reviewer checks against D1, D4, D14, D15 and the `http-security-chain` delta.

## Lane B — Adapters (tasks 5.1–5.5) · Sonnet · after 4.4

### Task 5.1: fiber route errors

**Files:** `fibersec/middleware.go:41-62`, `fibersec/errors.go:60,78`; test `fibersec/route_errors_test.go`

- [ ] **Step 1: Write the failing tests.**
  - `TestFiber_ErrorHandlerKeepsNonRefusalStatuses`: a route returning a 422, and an unrouted path giving 404.
  - `TestFiber_DefaultErrorHandlerKeepsRouteErrorText`: the response body is `"bad item"`.
- [ ] **Step 2: Run them.** Expected: `expected 422 actual 500`.
- [ ] **Step 3: Implement it.**
  - Capture `nextErr := fc.Next()` inside the closure, and return it unwrapped when `errors.Is(err, nextErr)`.
  - `ErrorHandler`: when `err` is a `*fiber.Error` and not a `*RefusalError`, answer `fe.Code`.
- [ ] **Step 4: Run `(cd fibersec && go test -race -count=1 ./...)`.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(fibersec): a route's own error keeps its status`.

### Task 5.2: fiber cancellation (U6, UNREPRODUCED)

- [ ] **Step 1: Write `TestFiber_ClientDisconnectCancelsChainContext`.** A store lookup blocks on `<-ctx.Done()`, the client closes the connection, and the test asserts that the context ends within 1 s.
- [ ] **Step 2: Run it.** If it passes on HEAD, report that and stop.
- [ ] **Step 3: Derive the chain context** from fiber's request context.
- [ ] **Step 4: Run it.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(fibersec): request cancellation reaches the chain`.

### Task 5.3: Adapter guard wiring

**Files:** `fibersec/guards.go:205,220`, `ginsec/guards.go:259,274`

- [ ] **Step 1: Write the failing tests.** `TestFiber_OwnershipGuardWithNilCheckerFailsAtWiring` and `TestGin_OwnershipGuardWithNilCheckerFailsAtWiring`, plus the extractor twins.
- [ ] **Step 2: Run them.** Expected: no panic.
- [ ] **Step 3: Panic at wiring,** mirroring task 4.4's messages.
- [ ] **Step 4: Run both modules' tests.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(fibersec,ginsec): ownership guards fail at wiring`.

### Task 5.4: fiber cool-down end to end

- [ ] **Step 1: Write `TestFiber_RecoveryCooldownHoldsForEveryPathFiberRoutesToTheMarkedRoute`.** It runs fiber's default config, with `/Account/Email` and `/account/email/` both expected to give 403.
- [ ] **Step 2: Run it** against the branch before task 4.2 lands, if available, to see the red step. Otherwise cite the audit run, which saw `expected 403 actual 204`.
- [ ] **Step 3: No code change.** Task 4.2 provides the fix.
- [ ] **Step 4: Run it.** Expected: PASS.
- [ ] **Step 5: Commit** `test(fibersec): cool-down holds under fiber's lenient routing`.

### Task 5.5: Review (Sonnet)

- [ ] A fresh reviewer checks against D16 and the `framework-adapters` delta.

## Lane C — Password and authentication (tasks 6.1–6.6) · Sonnet for 6.1, 6.2, 6.4, 6.5; Opus for 6.3

### Task 6.1: Record ceilings

**Files:** `password/scrypt.go:83,187,198`, `password/bcrypt.go:37,115`, `password/argon2id.go:99-100,160`; tests `password/ceilings_test.go`, `password/ceilings_internal_test.go`

**Interfaces:**
- Produces these constants: `maxRecordParallelism = 16`, `maxRecordCost = 16` (bcrypt), `maxRecordThreads = 16`, `maxRecordSaltLen = 64` and `maxRecordKeyLen = 64`. Rename `maxRecordFootprint` to cover `(N+p)·128·r`.

- [ ] **Step 1: Write the failing tests.**
  - `TestParseScrypt_RefusesParallelismBeyondFootprintCeiling`: `p = 1073741823` gives `ok == false`.
  - `TestScryptMatch_RecordParallelismBoundsDerivationTime`: `p = 128` gives no match in under 100 ms.
  - `TestBcrypt_RefusesStoredRecordWithExcessiveCost`: cost 20 gives no match in under 100 ms.
  - `TestArgon2idMatch_RefusesThreadsBeyondCeiling`.
  - `TestEncoders_RefuseParametersAboveCeiling`, a table: scrypt p=32, bcrypt cost=17, Argon2id memory 2 GiB. Each gives an error naming the parameter. The Argon2id row is `UNREPRODUCED` until it fails on HEAD.
- [ ] **Step 2: Run `go test -count=1 -run 'Ceiling|Excessive|Parallelism' ./password/`.** Expected: FAIL. The scrypt CPU case takes over 2 s.
- [ ] **Step 3: Check the ceilings** in each parser before deriving, and in each constructor.
- [ ] **Step 4: Run `go test -race -count=1 ./password/`.** Expected: PASS, with no single test over 1 s.
- [ ] **Step 5: Commit** `fix(password): a stored hash cannot demand unbounded work`.

### Task 6.2: bcrypt NUL

**Files:** `password/bcrypt.go:78,115`; test `password/bcrypt_nul_test.go`

**Interfaces:**
- Produces: `var ErrPasswordContainsNUL = errors.New("password: password contains a NUL byte")`.

- [ ] **Step 1: Write the failing tests.** `TestBcryptMatch_RefusesNulJoinedRepetitionOfPassword` (`"hunter2\x00hunter2"` against the hash of `"hunter2"` gives false), and `TestBcryptEncode_RefusesNul`.
- [ ] **Step 2: Run them.** Expected: match true.
- [ ] **Step 3: Refuse `strings.IndexByte(input, 0) >= 0`** in `Encode` and `Match`. Remove `collidesByNulPadding`, which this subsumes. Hand the sentinel to task 4.5 if it should map.
- [ ] **Step 4: Run `go test -race -count=1 ./password/`.** Expected: PASS, including `TestBcryptTreatsANulSuffixAsADifferentPassword`.
- [ ] **Step 5: Commit** `fix(password): bcrypt refuses passwords containing NUL`.

### Task 6.3: Timing for users without a usable hash (Opus)

**Files:** `password/encoder.go:81`, the three encoders, `authenticate/password.go:256,404`, the fixtures `password_refusal_test.go:48` and `sampling_test.go:156,168`; test `authenticate/timing_test.go`

**Interfaces:**
- Produces: `type Recognizer interface { Recognizes(encoded []byte) bool }`, in `password`. It is implemented by the Argon2id, bcrypt and scrypt encoders.

- [ ] **Step 1: Write the failing tests.**
  - `TestPasswordProvider_PasswordlessUserCostsSameAsUnknownUser`: a counting encoder records exactly 1 `Match` call for an empty hash.
  - `TestPasswordProvider_UnrecognisedHashCostsOneVerification`.
  - `TestPasswordProvider_ReferencePasswordNeverAdmits`: the reference password is presented for a hashless user and gives `ErrAuthenticationFailed`.
- [ ] **Step 2: Run them.** Expected: 0 `Match` calls (the `83ns` vs `7.9ms` audit evidence).
- [ ] **Step 3: Implement it.** When the hash is empty, or `Recognizer` reports false, call `_ = a.enc.Match(presented, a.reference)` once, then fail. Fix the three fixtures to use hashed users.
- [ ] **Step 4: Run `go test -race -count=1 ./authenticate/ ./password/`.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(authenticate): a user without a usable hash costs one reference verification`.

### Task 6.4: Nested managers; typed-nil credentials

**Files:** `authenticate/manager.go:66`, `authenticate/password.go:256,404`

- [ ] **Step 1: Write the failing tests.** `TestManager_NestedManagerThatSkipsLetsOuterTryNextDelegate`, and `TestPasswordProvider_TypedNilCredentialsRefusedWithoutPanic` (both `Authenticate` and `VerifyDecoy`, returning `ErrUnsupportedCredentials`).
- [ ] **Step 2: Run them.** Expected: `no eligible authenticator`, and a nil-pointer panic.
- [ ] **Step 3: Implement it.** Skip on `errors.Is(err, ErrNoEligibleAuthenticator)`, and add `if !ok || creds == nil`.
- [ ] **Step 4: Run `go test -race -count=1 ./authenticate/`.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(authenticate): nested managers compose and typed-nil credentials are refused`.

### Task 6.5: OIDC claim cost band

**Files:** `oidc/options_broker.go:226` (`WithPasswordClaimCostRange`, handed over from lane J)

- [ ] **Step 1: Write `TestBroker_RefusesClaimCostBandAboveRecordCeiling`.** A band of 10 to 20 gives a configuration error.
- [ ] **Step 2: Run it.** Expected: construction succeeds.
- [ ] **Step 3: Cap the band's maximum at 16.**
- [ ] **Step 4: Run `go test -race -count=1 ./oidc/`.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(oidc): the password-claim cost band stays within the bcrypt record ceiling`.

### Task 6.6: Review

- [ ] Sonnet reviews 6.1, 6.2, 6.4 and 6.5; Opus reviews 6.3. They check against D2, D3, D17 and the `password-encoding`, `authentication` and `identity-linking` deltas.

## Lane G — Recovery (tasks 7.1–7.4) · Opus

### Task 7.1: The pairing refusal

**Files:** `recovery/recover.go:239` (`shape`); test `recovery/channel_test.go`

- [ ] **Step 1: Write `TestRecoverer_ProofChannels`.** It is a table:
  - an issued code plus an email-channel MFA code gives `ErrMalformed`, with no proof checked or spent;
  - `"saved code with an emailed MFA code still recovers"` (Review Focus 3);
  - an issued code plus TOTP succeeds.
- [ ] **Step 2: Run it.** Expected: `an emailed recovery code plus an emailed MFA code recovered the account`.
- [ ] **Step 3: In `shape`, refuse** `ProofIssued` combined with `method.Channel() == factor.Email`.
- [ ] **Step 4: Run `go test -race -count=1 ./recovery/`.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(recovery): one mailbox never supplies both recovery proofs`.

### Task 7.2: The way-back check follows the rule

**Files:** `recovery/reset.go:19` (`AuthenticatorRef`), the MFA kind's `Held`, `recovery/wayback.go:150,196`; test `recovery/wayback_channel_test.go`

**Interfaces:**
- Produces: `AuthenticatorRef{Kind, ID string; Channel factor.Channel}`. The MFA kind fills `Channel` from the method; it is zero elsewhere.

- [ ] **Step 1: Write the failing tests.** `TestHasWayBack_EmailOnlyMFAWithIssuedCodesIsNoWayBack` (expects false), and `TestHasWayBack_LoaderWithNoDetailsDoesNotPanic`.
- [ ] **Step 2: Run them.** Expected: true, and a nil-pointer panic.
- [ ] **Step 3: In `pairsWithIssuedCode`,** skip refs on the email channel. Treat `d == nil` as a user with nothing.
- [ ] **Step 4: Run `go test -race -count=1 ./recovery/`.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(recovery): the way-back check stops counting a pairing recovery refuses`.

### Task 7.3: ASCII loopback; nil records

**Files:** `recovery/hold.go:175`, `recovery/hold.go:379` (the `passkey/pending.go:146` nil guard moved to task 10.4, which owns `passkey/`)

- [ ] **Step 1: Write the tests.**
  - `TestParseCancelLink_RefusesHTTPOnUnicodeFoldedLocalhost`: `localhoſt` gives a config error, and `LOCALHOST` is fine.
  - `TestHold_FindReturningNothingIsMissing` (S7, `UNREPRODUCED`).
  - `TestHoldFinish_RefusesUserWhoseIDDiffers` (D1's defence in `Finish`, `recovery/hold.go:320`).
- [ ] **Step 2: Run them.** Expected: the first and third fail. If the S7 case passes on HEAD, report it.
- [ ] **Step 3: Implement it.** Fold ASCII using `internal/origin`'s helper, guard nil records, and refuse in `Finish` when `details.ID != rec.User`.
- [ ] **Step 4: Run `go test -race -count=1 ./recovery/`.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(recovery): ASCII-only loopback check, nil records are missing`.

### Task 7.4: Review (Opus)

- [ ] A fresh reviewer checks against D5, D6 and the `account-recovery` delta.

## Lane H — Signing keys (tasks 8.1–8.3) · Opus

### Task 8.1: One publishing predicate

**Files:** `signingkey/manager.go:94,134,166,232`, `signingkey/rotate.go:129,217`; fixtures `housekeep_test.go:96`, `algs_test.go:83`, `boundary_test.go:382`; test `signingkey/restart_test.go`

**Interfaces:**
- Produces: the unexported `func (km *KeyManager) publishable(k storedKey, newestOfAlg bool, now time.Time) bool`, used by `loadFromStore`, `reload` and `housekeep`.

- [ ] **Step 1: Write the failing tests.**
  - `TestRestartedManager_RefusesTokensFromAKeyPastItsLifetime`: verifying a token from a 30-day-old key gives `token: invalid`.
  - `TestRestartedManager_KeepsAStaleSoleKey`: a 3-day-old sole RS256 key is current, and no key is minted.
  - The case `"manager never started drops a past-lifetime key"` (Review Focus 4).
- [ ] **Step 2: Run `go test -race -count=1 -run Restarted ./signingkey/`.** Expected: `published keys after restart: 2`.
- [ ] **Step 3: Implement `publishable`.** Update the fixtures that pin the old construction behaviour, and seed the 25 h duplicate inside the lifetime.
- [ ] **Step 4: Run `go test -race -count=1 ./signingkey/`.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(signingkey): construction publishes no key past its lifetime but keeps each algorithm's newest`.

### Task 8.2: Future-dated keys

**Files:** `signingkey/manager.go:166,232`, `signingkey/rotate.go:217`, `reload_test.go:88-108`

- [ ] **Step 1: Write the failing tests.** `TestRotation_IsNotUndoneByAFutureDatedStoredKey`: after 48 rotations the future key is not the signer and is not published. Also `TestHousekeep_RetiresFarFutureKey`.
- [ ] **Step 2: Run them.** Expected: the future key is still the signer.
- [ ] **Step 3: Implement it.** `repickCurrentLocked` ignores keys with `CreatedAt > now + reloadInterval`. `pastLifetime` also treats `CreatedAt > now + lifetime` as expired. Pass `WithClock` in `reload_test.go`.
- [ ] **Step 4: Run `go test -race -count=1 ./signingkey/` and `(cd test && go test -race -count=1 -run SigningKey ./...)`.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(signingkey): a future-dated key never signs and is retired`.

### Task 8.3: Review (Opus)

- [ ] A fresh reviewer checks against D9 and the `signing-keys` delta.

## Lane I — Policy and bounded memory (tasks 9.1–9.5) · Opus for 9.1; Sonnet for 9.2–9.4

### Task 9.1: Bounded default attempt store

**Files:** `policy/attempts.go:185,192`, `policy/lockout.go:408`; the purge-unsupported tests `policy/expiry_test.go:80-96`, `lockout_test.go:793` and `lockout_cap_test.go:764`; test `policy/attempts_bound_test.go`

**Interfaces:**
- Produces:
  - `func NewMemoryAttemptStore(opts ...MemoryAttemptOption) *MemoryAttemptStore`;
  - `func WithAttemptStoreCapacity(n int) MemoryAttemptOption` (default 100,000);
  - `var ErrAttemptStoreFull`;
  - `MemoryAttemptStore` implements `AttemptReaper`.
- `NewAccountLockoutPolicy` passes its longest retention to the default store through an unexported setter.

- [ ] **Step 1: Write the failing tests.**
  - `TestDefaultLockoutStore_ReleasesIdentifiersOutsideWindow`: 50,000 failures, the window passes, one write, then at most 1 identifier held.
  - `TestDefaultLockoutStore_FullStoreDeniesNewIdentifier`.
  - `TestMemoryAttemptStore_ConsumerCapacity`.
  - `TestMemoryAttemptStore_KeepsHolds`.
  - `TestDefaultLockoutStore_PurgesOldFailures`, which replaces the purge-unsupported case.
- [ ] **Step 2: Run them.** Expected: `"50001" is not less than or equal to "1"`, and purge-unsupported.
- [ ] **Step 3: Implement it.** Prune per key on write, sweep inline once per window, enforce the cap, digest identifiers over 256 bytes, and never sweep holds.
- [ ] **Step 4: Run `go test -race -count=1 ./policy/`.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(policy): the default attempt store stays bounded and fails closed when full`.

### Task 9.2: A missing time or input denies

**Files:** `policy/engine.go:275`, `policy/idle.go`, `policy/passwordage.go`, `policy/enrolmentpath.go`

- [ ] **Step 1: Write the failing tests.** `TestIdleTimeout_ZeroNowDoesNotAllowIdleSession`, `TestPasswordAge_ZeroNowDeniesStalePassword`, `TestEnrolmentPath_ZeroNowIsClosed` and `TestEngine_NilInputDeniesRatherThanPanics`.
- [ ] **Step 2: Run them.** Expected: Allow, and a panic at `concurrent.go:136`.
- [ ] **Step 3: Implement it.** `EvaluatePhase` denies a nil input. Each policy denies `in.Now.IsZero()`.
- [ ] **Step 4: Run `go test -race -count=1 ./policy/`.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(policy): an evaluation without a time or an input is denied`.

### Task 9.3: Outage hold

**Files:** `internal/unavailable/hold.go:24-84`; test `internal/unavailable/hold_bound_test.go`

- [ ] **Step 1: Write the failing tests.** `TestUnavailable_RefuseHoldIsBoundedUnderKeySpray`: 300,000 keys of 1 KB give at most 250,000 held, and an unheld key is answered exceeded. Also `TestHold_SweepsAfterClockStepsBackwards`: 1,001 holds give at most 1.
- [ ] **Step 2: Run them.** Expected: `"300000" ≤ "250000"` fails, and so does `"1001" ≤ "1"`.
- [ ] **Step 3: Implement it.** Add the cap, digest long keys, answer exceeded when full, and reset `sweptAt` when `now.Before(h.sweptAt)`.
- [ ] **Step 4: Run `go test -race -count=1 ./internal/unavailable/`.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(ratelimit): the outage hold stays bounded and keeps sweeping`.

### Task 9.4: Sampler cap; flow names

**Files:** `pkg/logsample/logsample.go:40-49`, `ratelimit/guard.go:118`

**Interfaces:**
- Produces: `func WithCapacity(n int) Option` (default 100,000), and the overflow key `logsample.OverflowKey = "logsample:overflow"`.

- [ ] **Step 1: Write the failing tests.** `TestSampler_BoundsKeysWithinWindow` (U5, `UNREPRODUCED`): one million keys in one window give at most 100,001 held, and the overflow count accounts for the rest. Also `TestNewSourceGuard_RefusesFlowNameWithColon`.
- [ ] **Step 2: Run them.** If the sampler case passes on HEAD, report it.
- [ ] **Step 3: Implement both.**
- [ ] **Step 4: Run `go test -race -count=1 ./pkg/logsample/ ./ratelimit/`.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(logsample,ratelimit): sampler bounded within a window; flow names validated`.

### Task 9.5: Review

- [ ] Opus reviews 9.1; Sonnet reviews 9.2–9.4. They check against D12, D13, D14 and the `security-policy`, `rate-limiting` and `log-sampling` deltas.

## Lane J — Point fixes (tasks 10.1–10.6)

### Task 10.1: API keys (Opus)

**Files:** `apikey/store.go:45`, `apikey/manager.go:62,139,225,342`, `apikey/options.go:86`, the memory store, `pgx/apikey.go`, `sqlstore/apikey.go`, `gorm/apikey.go`, `test/storetest/apikey_suite.go`; regenerate `apikey/mocks_test.go`

**Interfaces:**
- Produces:
  - `apikey.Store.Revoke(ctx context.Context, keyID id.ID, at time.Time) (bool, error)`, true only when this call moved the key from live to revoked;
  - `var ErrRotationRefused = errors.New("apikey: rotation refused")`.

- [ ] **Step 1: Write the failing tests.**
  - `TestRotate_RefusesRevokedKey`.
  - `TestRotate_RefusesExpiredKey`.
  - `TestRotate_ConcurrentRotationsLeaveOneLiveReplacement`: exactly one live key derives from the old one.
  - `TestVerify_EmptyDigestDoesNotAcceptAnySecret`.
  - `TestNewManager_RefusesDigestReturningNothing`.
  - The storetest case `"revoke reports whether it revoked"`.
- [ ] **Step 2: Run them.** Expected: a live key minted for a revoked one, 2 replacements, and a forged secret verified.
- [ ] **Step 3: Implement it.**
  - Refuse revoked and expired keys first.
  - Issue, then revoke conditionally. On false, revoke the replacement and return `ErrRotationRefused`.
  - Refuse empty digests, and probe the digest in `NewManager`.
  - Hand the sentinel to task 4.5.
- [ ] **Step 4: Run** `go test -race -count=1 ./apikey/` and `(cd test && go test -race -count=1 -run APIKey ./...)`. Expected: PASS.
- [ ] **Step 5: Commit** `fix(apikey): rotation refuses dead keys and is decided by the write; empty digests never verify`.

### Task 10.2: OIDC and authorize (Sonnet)

**Files:** `oidc/provision.go:110`, `oidc/authorize.go:44`, `oidc/options_manager.go:203,221`, `authorize/privilege.go:51,89`

- [ ] **Step 1: Write the failing tests.**
  - `TestBroker_RefusesProvisioningForUnicodeFoldedDomain`.
  - `TestAuthorize_BoundsUntrustedNextLength`: a 1 MiB `next` is stored as `""`.
  - `TestManager_RefusesAllowlistEntryOver2048Bytes`.
  - `TestManager_RefusesSkewAbove5Minutes`.
  - `TestManager_RefusesLogoutMaxAgeAboveOneHour`.
  - `TestPrivilegeAuthorizer_DefaultComparerDoesNotFoldDistinctUnicodeNames`, plus a no-break-space case.
- [ ] **Step 2: Run them.** Expected: each misbehaves as the audit recorded.
- [ ] **Step 3: Implement it.** Use ASCII folding and trimming, and add the length and duration bounds.
- [ ] **Step 4: Run `go test -race -count=1 ./oidc/ ./authorize/`.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(oidc,authorize): ASCII-only security comparisons and bounded configuration`.

### Task 10.3: Tokens, sessions, notify (Sonnet)

**Files:** `token/options.go:112,259`, `token/verifier.go:143`, `session/manager.go:361,428` and the other `store.Load` sites (`manager.go:412,696`, `reuse.go:215`, `encrypted.go:159`), `notify/smtp.go:322`

- [ ] **Step 1: Write the failing tests.**
  - `TestVerify_TypedNilPublicKeyIsAnUnusableKeySet`.
  - `TestNewGenerator_RefusesSubSecondLifetime`.
  - `TestManager_LoadOfStoreReturningNoSessionIsNotFound`.
  - `TestManager_FailedFirstUseWriteFailsLoadUnderRecovery` (U4, `UNREPRODUCED`).
  - `TestBuild_WireCarriesNoBareCarriageReturn`.
- [ ] **Step 2: Run them.** Expected: a panic, 8/20 tokens verify, a panic, and a bare CR at offset 158. If U4 passes, report it.
- [ ] **Step 3: Implement it.**
  - `nilcheck.IsNil(pk.Key)` gives the unusable-key-set error.
  - Validate whole seconds.
  - A nil session gives `ErrSessionNotFound`.
  - Return the `markPresented` error when recovery is on.
  - Normalise `\r\n`→`\n`, then `\r`→`\n`, then `\n`→`\r\n`.
- [ ] **Step 4: Run `go test -race -count=1 ./token/ ./session/ ./notify/`.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(token,session,notify): refuse nil port results, whole-second lifetimes, no bare CR`.

### Task 10.4: Passkey and WebAuthn (Sonnet, after lanes E and A)

**Files:** `passkey/relyingparty.go:53`, `passkey/manager.go:372`, `passkey/register.go:40`, `passkey/pending.go:146` (S7: a nil element in a credential list), the ceremony cookie TTL options in `httpsec/magiclink.go:303` and `httpsec/passkeylogin.go:465` (handed over from lane A)

- [ ] **Step 1: Write the failing tests.** `TestValidateRPID` is a table: `Example.com`, `-login.example.com`, and a 64-character label all fail; `login.example.com` and `localhost` pass. Mark it `UNREPRODUCED` until it fails on HEAD. Also write `TestBeginRegistration_LoaderReturningNoUserIsRefused`, `TestCeremonyCookieTTL_RefusesSubSecond`, and a nil-credential-in-list case for `pending.go` (S7, `UNREPRODUCED`).
- [ ] **Step 2: Run them.** Expected: the RP ID cases are accepted, and the begin panics at `manager.go:373`.
- [ ] **Step 3: Implement the DNS-name check, the nil guard and whole-second TTLs.**
- [ ] **Step 4: Run `go test -race -count=1 ./passkey/... ./httpsec/`.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(passkey): RP ID is a DNS name and a missing user is refused`.

### Task 10.5: Documentation and layout (Sonnet; the layout part after `release-readiness` 2.1)

**Files:** `gorm/doc.go`, `layout_guard_test.go:70,116,137,477`, `layout_test.go`

- [ ] **Step 1: Write `TestModuleLayout_NestedModuleViolations`.** It plants a `Mock*` type in a temporary copy of a nested module, and a test-module import, and expects violations. The red step is that it reports none.
- [ ] **Step 2: Run `go test -count=1 -run TestModuleLayout .`.** Expected: `Should NOT be empty, but was []`.
- [ ] **Step 3: Implement it.** Iterate `workspaceModules(t)` except `./test`, running `fileViolations` and a `go.mod` check that no module requires the test module. Add the replica-read stated limit to `gorm/doc.go`.
- [ ] **Step 4: Run it.** Expected: PASS on the clean tree, and FAIL on each plant.
- [ ] **Step 5: Commit** `fix(layout): the layout guard scans every module; gorm states its replica limit`.

### Task 10.6: Review

- [ ] Opus reviews 10.1; Sonnet reviews the rest. They check against D11, D14, D16, D17 and the `api-keys`, `oidc-login`, `oidc-logout`, `identity-linking`, `authorization`, `token-issuance`, `sessions`, `email-notification` and `passkey-authentication` deltas.

## Gate (tasks 11.1–11.4) · main session

- [ ] **11.1** Write the `CHANGELOG.md` `Unreleased` entries, or a hand-off note to `release-readiness`, for every **BREAKING** item in `proposal.md`. Check each item against the proposal.
- [ ] **11.2** Run `make check` on PostgreSQL 18, and `(cd test && SCRTY_TEST_POSTGRES_IMAGE=postgres:15.19-alpine go test -race -count=1 ./...)`. In every module, also run `golangci-lint run ./...`, `govulncheck ./...` and `gofmt -l .`. Expected: all green, with the outputs kept.
- [ ] **11.3** Rerun the audit and sweep reproductions in the scratch exports against the branch, after applying each export's test onto a branch copy. Expected: each passes, or is recorded as dropped (`UNREPRODUCED` and passing on HEAD).
- [ ] **11.4** Run the whole-branch Opus review against every delta-spec requirement and design decision, then `openspec validate pre-release-hardening --strict`. Expected: both clean.
