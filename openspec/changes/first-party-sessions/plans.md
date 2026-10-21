# First-Party Sessions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. In this repository the main session dispatches every code-writing step to a subagent (`.claude/rules/subagent-delegation.md`), and runs the verification commands itself.

**Goal:** Make scrty's sessions usable as first-party credentials at scale:
- coalesced, narrow activity writes;
- per-session lifetimes;
- session families with grace-window rotation and reuse detection (with opt-in recovery for an unused successor);
- a renewal endpoint;
- an opaque session-reference bearer, built on a resolution core that consumer interceptors can use too.

**Architecture:**
- **The session record.** It gains library-only family and supersession fields.
- **The `session.Store` port.** It gains four operations: a narrow activity write, an atomic supersession, a family delete, and a first-presentation mark. Durable stores implement each as one conditional statement, or one transaction that joins a caller's transaction.
- **The `session.Manager`.** It judges grace windows and reuse with its clock, and revokes and reports.
- **The `httpsec` chain.**
  - The signed-token bearer's post-verification steps are extracted into one unexported core, built on two new `Exchange` methods.
  - The new session-reference bearer and the renewal endpoint run through that core.

**Tech Stack:**
- Go 1.27 workspace, with the core module plus the nested `pgx`, `gorm` and `test` modules;
- PostgreSQL 15 and 18;
- `database/sql` over pgx stdlib (`sqlstore`), native `pgxpool` (`pgx`), and gorm;
- testcontainers-go through the `test` module's `RunTestPostgres`;
- testify, clockwork, and uber-go/mock (`mockgen --typed`).

**Spec:** `openspec/changes/first-party-sessions/`:
- `proposal.md`;
- `design.md` (decisions 1 to 13, plus "Defect claims");
- `specs/` (deltas: `sessions`, `security-state-stores`, `store-conformance`, `schema-migrations`, `http-security-chain`, `http-error-propagation`);
- `tasks.md`.

Read the design and the spec deltas your task names before starting it. Plan task N.M is `tasks.md` task N.M.

## Global Constraints

- **Test-first, every task.** Write the test, run it, and see it fail **for the intended reason** before implementing. A compile error is not a red step: add the new API as a stub returning a zero value or `errors.New("not implemented")` first, so the test compiles and fails on behaviour (`.claude/rules/golang-tdd.md`).
- **Table tests** use the `table-test` skill's form: an `assert` closure per case, a `ctx` modifier where context matters, `t.Context()`, and no `want`/`wantErr` fields.
- **Test doubles.**
  - Mocks come from `use-mockgen`. The `session.Store` mock is regenerated from the `//go:generate` line in `session/store.go`.
  - PostgreSQL comes from `RunTestPostgres` (`use-testcontainers`). No hand-rolled database fakes.
  - Broken store variants follow the existing `test/storetest/broken_*_test.go` pattern.
- **The legacy reference.** Never cite, copy or mention it in code, comments, godoc or commits (`.claude/rules/legacy-reference.md`).
- **Defect claims.** A defect claim needs a failing test (`.claude/rules/defect-claims.md`). Task 1.1 decides the one claim this change makes.
- **Library design** (`.claude/rules/library-design.md).
  - Every new option's godoc names the default it replaces.
  - A contradictory configuration is an error from the constructor (`NewManager`, `httpsec.New`) or from `Create` and rotation for per-call values, never a silent adjustment.
  - Configuration errors wrap the package's existing configuration-error sentinel.
- **Unchanged defaults.**
  - Activity interval 0.
  - Lifetime maximum equal to the absolute timeout, and family maximum equal to the lifetime maximum.
  - Renewal grace 30 s, with a hard ceiling of 5 minutes, inclusive.
  - Renewal carries the deadline over.
  - Unused-successor recovery off, and no reuse observer.
  - The signed-token bearer stays the default mode, and `Rotate` stays strict.
- **No identifier in text.** No session identifier, raw or digested, appears in any error text, log record or observer report. Family identifiers may appear.
- **The login lifetime function never sees the password.** `LoginFields` excludes the configured password parameter.
- **Agents** never run `git checkout --`, `restore`, `reset --hard`, `stash` or `clean`, and never edit anything under `openspec/`.
- **New public API** (exact names; any change is the main session's to decide):
  - `session`:
    - `WithTouchInterval(time.Duration) ManagerOption`;
    - `WithMaxAbsoluteLifetime(time.Duration) ManagerOption`;
    - `WithMaxFamilyLifetime(time.Duration) ManagerOption`;
    - `WithUnusedSuccessorRecovery() ManagerOption`;
    - `WithReuseObserver(ReuseObserver) ManagerOption`;
    - `WithFamilyIDGenerator(id.Generator) ManagerOption` (default `id.NewV7Generator` on the manager clock; nil is a configuration error), added after the review of tasks 2.1–2.5;
    - `WithAbsoluteLifetime(time.Duration) CreateOption`;
    - `(*Manager).RotateWithGrace(ctx, s *Session, grace time.Duration, opts ...RotateOption) (*Session, RenewalKind, error)`;
    - `WithSuccessorLifetime(time.Duration) RotateOption`;
    - `type RotateOption func(*rotation)`;
    - `type RenewalKind int`, with `RenewalFresh`, `RenewalReRotation` and `RenewalRecovery`;
    - `(*Manager).RevokeFamily(ctx, family id.ID) (int, error)`;
    - `type ReuseObserver func(ctx context.Context, r ReuseReport)`;
    - `type ReuseReport struct{ User identity.UserID; Family id.ID; SupersededAt, DetectedAt time.Time }`;
    - `ErrSessionReused`, `ErrSessionRenewalConflict`;
    - `MaxRenewalGrace = 5 * time.Minute`;
    - `Session` fields: `FamilyID id.ID`, `FamilyCreatedAt`, `SupersededAt`, `AcceptUntil`, `FirstPresentedAt time.Time`, and `SuccessorDigest []byte`.
  - `session.Store` gains:
    - `RecordActivity(ctx, id string, lastAccessed, idleExpires, olderThan time.Time) error`;
    - `Supersede(ctx context.Context, op Supersession) error`;
    - `DeleteFamily(ctx context.Context, family id.ID) (int, error)`;
    - `MarkPresented(ctx context.Context, id string, at time.Time) error`.
  - `type Supersession struct{ Old string; ObservedSuccessor []byte; AcceptUntil time.Time; Successor *Session; Now time.Time }`. Its godoc states `ObservedSuccessor` is nil for a first rotation.
  - Added 2026-10-21 (recovery decision): `Supersession.RequireUnpresentedSuccessor bool`; `session.ErrSuccessorAdvanced` (store refusal: the observed successor was presented when required unpresented, has been superseded, or is gone; writes nothing); `session.ErrSessionRenewalRequired` (`errors.Is` `ErrSessionExpired`; `Load` with recovery on, past the window, no revocation); `(*Manager).LoadForRenewal(ctx, id string) (*Session, error)`. Strict `Rotate` refuses a superseded session with `ErrSessionRenewalConflict`.
  - `httpsec`:
    - `EnableSessionBearer(SessionBearerDeps, ...SessionBearerOption) Option`;
    - `type SessionBearerDeps struct{ Sessions *session.Manager; Users identity.UserLoader }`;
    - `WithSessionBearerScheme(string) SessionBearerOption`;
    - `EnableSessionRenewal(SessionRenewalDeps, ...SessionRenewalOption) Option`;
    - `type SessionRenewalDeps struct{ Sessions *session.Manager; Users identity.UserLoader; Tokens token.Generator }` (`Sessions` optional, defaulting to the bearer's manager; a different manager is a configuration error, decided after the review of tasks 7.1–7.2);
    - `WithRenewalPath(string)`, `WithRenewalGrace(time.Duration)`, `WithRenewalResponder(RenewalResponder)` and `WithRenewalLifetime(func(*Exchange, *session.Session) time.Duration)`;
    - `type RenewalResponder func(ex *Exchange, r RenewalResult) error`;
    - `type RenewalResult struct{ Credential string; Session *session.Session; User *identity.Details; Kind session.RenewalKind }`;
    - `DefaultSessionRenewalPath = "/session/renewal"`;
    - `WithLoginLifetime(func(*Exchange, LoginFields) time.Duration) LoginOption`;
    - `type LoginFields struct{ /* unexported */ }` with `(LoginFields).Value(name string) (any, bool)`;
    - `(*Exchange).PublishSession(a *authenticate.Authentication, s *session.Session)`;
    - `(*Exchange).EvaluatePerRequest(s *session.Session, p *identity.Principal) error`, refusing with `ErrAuthenticationRequired` unless `s` and `p` are the published ones;
    - `WithSessionManager(*session.Manager) Option` (the chain's manager for activity and per-request marking; takes precedence over built-ins' managers; nil is a configuration error), added after the review of tasks 5.1–5.3;
    - `ErrSessionRenewalConflict`, re-exported from `session` by wrapping, as existing session sentinels are mapped.
  - Added for group 9 (design "Pull request review (2026-10-21)"):
    - `session.Session.AuthenticatedAt time.Time`: when the user last authenticated; set at `Create`, refreshed when a second factor is satisfied, carried over by every renewal; the only time freshness checks read (decided 2026-10-22). `CreatedAt` is when the record was written;
    - every `Store.Create` refuses a session whose `FamilyID` is `id.Nil`, writing nothing (decided 2026-10-22);
    - `session.Supersession.RetainUntil time.Time`: the retention deadline the manager computes (`FamilyCreatedAt` plus the family maximum), written as both deadlines of every record the supersession supersedes;
    - `session.ErrSessionSuperseded`: `Store.MarkPresented` on a superseded record writes nothing and returns it;
    - `(*session.Manager).TouchInterval() time.Duration`, beside `IdleTimeout()` and `AbsoluteTimeout()`;
    - `(*policy.IdleTimeoutPolicy).IdleTimeout() time.Duration` and `(*policy.Engine).IdleTimeouts() []time.Duration`, the idle timeouts the engine's policies enforce;
    - decision 14 (throttling, 2026-10-22): `httpsec.WithSessionBearerLimiter(ratelimit.Limiter) SessionBearerOption` (default: the chain's factory builds `session-reference`, 100 failures per source per minute); `httpsec.WithRenewalLimiter(ratelimit.Limiter) SessionRenewalOption` (default: the factory builds `session-renewal`, 10 renewals per family per 10 minutes, keyed `family:<FamilyID>`); `httpsec.ErrRenewalThrottled`, mapped to 429; a nil limiter is a configuration error for both;
    - removed: the store's family-wide pre-lock and the raise of superseded members' deadlines (`SessionLockFamily`, `SessionExtendSuperseded`, `extendSupersededLocked`).
  - `session.ValidIdentifier(string) bool`: reports whether a string has the exact encoded length and alphabet of a session identifier. It is used by the session-reference bearer to refuse before any lookup.
- **Verification commands**, run from the repository root unless stated:
  - core module: `go test -race -count=1 ./session/... ./httpsec/... ./internal/... ./sqlstore/...`;
  - pgx: `(cd pgx && go test -count=1 ./...)`;
  - gorm: `(cd gorm && go test -count=1 ./...)`;
  - test module: `(cd test && go test -count=1 -run '<Name>' ./...)`;
  - always: `go vet ./...` in each touched module, `gofmt -l .` printing nothing, and `make generate-check` after a mock-affecting change.

## Review Focus

1. **A superseded identifier presented to an endpoint other than the bearer.** Logout, the MFA endpoints and the password-change gate all reach sessions through `Manager.Load`, so reuse must be judged there and not only in the bearer.
   - Expected: any `Load` past the window revokes and returns `ErrSessionReused`; with unused-successor recovery on, it returns `ErrSessionRenewalRequired` and revokes nothing (decision 6, chosen 2026-10-21).
   - Test: added to task 3.4 as a logout-path case in `session` (`Load` then `Delete` sees not-found).
2. **Clock skew between replicas around `AcceptUntil`.** The window end is stored as an absolute time, and judged by the reading manager's clock.
   - Expected: a replica whose clock is ahead refuses earlier, never later than `AcceptUntil` by its own reading.
   - Test: added to task 3.4, with two managers on different fake clocks over one memory store.
3. **A family revoked while a renewal is in flight.**
   - Expected: the in-flight `Supersede` finds no old record, and fails with not-found rather than inserting an orphan successor.
   - Test: added to task 2.3 as a suite case (revoke, then supersede with the observed state, which gives not-found and no insert).
4. **The renewal endpoint called with a session that is itself inside the enrolment-only or recovery-pending state.**
   - Expected: renewal is refused by the existing gates before the endpoint runs, because confinement must not be escaped by renewing.
   - Test: added to task 7.2 (an enrolment-pending session posting to the renewal path is refused by the enrolment gate).
5. **The renewal kind and the observer report leaking identifiers.**
   - Expected: `RenewalResult` carries the successor's credential only, and `ReuseReport` and every error and log carry no identifier.
   - Test: added to task 3.6 (format the report with `%+v` and assert no identifier substring) and task 7.1 (logs captured with a test handler hold no credential).

---

## Dispatch map (main session)

| Order | Dispatch | Tasks | Owns | Model, and why |
|---|---|---|---|---|
| 1 | A1 | 1.1 | `session/touch_race_test.go` | Sonnet: one deterministic test from a stated scenario |
| 2 | A2 | 2.1–2.5 | `session/session.go`, `session/store.go`, `session/memory.go`, `session/encrypted.go`, `session/store_mock_test.go`, `test/storetest/session_suite.go`, `test/storetest/race.go`, `test/storetest/broken_session_test.go`, `test/storetest/broken_race_test.go`, every `sqlstore`, `pgx` and `gorm` session store file, with stubs only (so the tree compiles) | Opus: an interface every later lane compiles against |
| 3a (parallel) | A3 | 3.1–3.3 | `session/manager.go`, `session/options.go`, `session/enrolment.go`, `session/*_test.go` for those | Sonnet: option plumbing against stated contracts |
| 3b (parallel) | B1 | 4.1–4.2 | `migrate/securitystate/`, `test/migrate_securitystate_test.go` | Sonnet: a migration against stated columns |
| 3c (parallel) | C1 | 5.1–5.3, 5.5 | `httpsec/bearer.go`, `httpsec/exchange.go`, `httpsec/context.go`, a new `httpsec/resolve.go`, `httpsec/doc.go`, and their tests | Opus: a behaviour-preserving extraction |
| 4a (after A3) | A4 | 3.4–3.7 | as A3, plus `session/reuse.go` and `session/rotate_grace_test.go` | Opus: races, reuse and revocation logic, written for the first time |
| 4b (after B1, A2) | B2 | 4.3–4.6 | `internal/pgschema/sessions.go`, the `sqlstore`, `pgx` and `gorm` session files, `test/sqlstore`, `test/pgxstore`, `test/gormstore`, `test/storetest/ambient.go` | Opus: conditional writes and transactions |
| 5 (after A4, C1) | C2 | 5.4, 6.1–6.5 | `httpsec/resolve.go`, `httpsec/sessionbearer.go`, `httpsec/logincomplete.go`, `httpsec/mfaverify.go`, `httpsec/recoverycomplete.go`, `httpsec/errors.go`, `httpsec/status.go`, `test/httpsec_*_test.go` | Opus: a security-critical first-time verification path |
| 6 (after C2) | C3 | 7.1–7.2 | a new `httpsec/renewal.go` and `httpsec/renewal_test.go` | Opus: a security endpoint and its races |
| 7 (after C3) | C4 | 7.3–7.5 | `httpsec/renewal.go`, `httpsec/login.go`, `httpsec/logincomplete.go`, and their tests | Sonnet: option plumbing to a stated contract |
| 8 | main | 8.1–8.2 | — | Opus reviewer for 8.1 |
| 9a (parallel) | S1 | 9.1, 9.2 | `session/session.go` (field), `session/reuse.go`, `session/manager.go`, `session/memory.go` and `session/encrypted.go` (carry the field), `session/*_test.go` for them, `httpsec/recoverycodes.go` and its test | Opus: an authentication-time rule and rotation races, security-critical |
| 9a' (after S1) | P1 | 9.1, passkey management | `passkey/manager.go`, `passkey/doc.go`, `passkey/options.go` (godoc), `passkey/*_test.go` for admission, `test/httpsecconformance/passkey_scenarios.go` | Sonnet: the same one-line freshness switch 9.1 made, test first |
| 9b (parallel) | H1 | 9.5 | new `session/interval.go`, `policy/idle.go`, `policy/engine.go`, `httpsec/options.go`, and their tests | Sonnet: a construction check across stated seams |
| 9b' (parallel) | T1 | 9.9 | `httpsec/sessionbearer.go`, `httpsec/sessionbearer_test.go`, `test/httpsec_gin_test.go`, `test/httpsec_fiber_test.go` | Sonnet: the API-key guard's pattern applied to a second flow |
| 9b'' (parallel) | T2 | 9.10 | `httpsec/renewal.go`, `httpsec/renewal_test.go`, `httpsec/errors.go`, `httpsec/status.go`, `httpsec/status_test.go`, the `WithTouchInterval` godoc in `session/options.go` (godoc lines only) | Sonnet: a limiter and a status row against a stated contract |
| 9c (after S1) | D1 | 9.4 | `migrate/securitystate/20261021000000_session_families.sql`, `test/migrate_securitystate_test.go`, `internal/pgschema/sessions.go`, `sqlstore/session.go`, `pgx/session.go`, `gorm/session.go`, `gorm/models.go`, `test/testutils_postgres_test.go` | Sonnet: column defaults, a new column and its plumbing |
| 9d (after S1, parallel with D1) | S2 | 9.3 and 9.6, memory side | `session/store.go`, `session/memory.go`, `session/encrypted.go`, `session/reuse.go`, `session/manager.go`, `httpsec/logout.go` and its tests, every test fixture creating a family-less session, `test/storetest/session_suite.go`, `broken_session_test.go`, `broken_test.go` | Opus: a port change other lanes compile against |
| 9e (after D1, S2) | D2 | 9.3 and 9.6, durable side | `internal/pgschema/sessions.go`, the three durable session files, `test/storetest/ambient.go`, `test/{sqlstore,pgxstore,gormstore}/*_test.go` | Opus: conditional writes and lock order |
| 9f (after D2) | S3 | 9.7 | `session/store.go`, `session/memory.go`, `session/encrypted.go`, `session/manager.go`, the four durable files, the suite files | Opus: an atomic store condition replacing a race guard |
| 9g (after S3) | D3 | 9.8 | `internal/storekit/`, the three durable session files | Opus: a refactor that must keep behaviour |
| 9h | main | 9.11 | — | Opus reviewer |

After each dispatch, the main session runs that dispatch's verification commands, and a fresh reviewer checks the diff against the decisions and requirements it covers. The reviewer is Opus for Opus dispatches and Sonnet otherwise. A2 stubs the durable stores' new methods to return `errors.New("not implemented")`, so the workspace compiles while B2 is pending. B2 then owns those files exclusively.

---

### Task 1.1: Reproduce the stale activity write

**Files:**
- Test: `session/touch_race_test.go` (new)

**Interfaces:**
- Consumes: `session.NewManager`, `WithStore(NewMemoryStore(...))`, `WithClock`, `(*Manager).Create`, `Load`, `MarkEnrolmentPending`, `Save`, `Touch`. These are existing; confirm the signatures with `go doc ./session`.
- Produces: `TestTouch_KeepsAConcurrentlyLoweredDeadline`, the red step for 3.1 if it fails.

- [ ] **Step 1: Write the test**

```go
func TestTouch_KeepsAConcurrentlyLoweredDeadline(t *testing.T) {
	clk := clockwork.NewFakeClockAt(time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC))
	m := newManager(t, session.WithClock(clk)) // helpers_test.go's constructor; add one if absent
	s, err := m.Create(t.Context(), "u-1")
	require.NoError(t, err)

	a, err := m.Load(t.Context(), s.ID) // request A's copy
	require.NoError(t, err)

	b, err := m.Load(t.Context(), s.ID) // request B marks enrolment-pending
	require.NoError(t, err)
	require.NoError(t, m.MarkEnrolmentPending(b, 15*time.Minute))
	require.NoError(t, m.Save(t.Context(), b))

	clk.Advance(time.Minute)
	require.NoError(t, m.Touch(t.Context(), a)) // A finishes

	got, err := m.Load(t.Context(), s.ID)
	require.NoError(t, err)
	assert.Equal(t, b.AbsoluteExpiresAt, got.AbsoluteExpiresAt)
	assert.Equal(t, b.EnrolmentOriginDeadline, got.EnrolmentOriginDeadline)
}
```

- [ ] **Step 2: Run it.** `go test -count=1 -run TestTouch_KeepsAConcurrentlyLoweredDeadline ./session/`
  - Expected if the claim holds: FAIL, with the absolute deadline reported as 21:00 instead of 09:15.
- [ ] **Step 3: Report** the exact output.
  - On FAIL: the claim is `REPRODUCED`. Leave the test in place, failing, as 3.1's red step, and do not fix it here.
  - On PASS: report it and stop. The main session removes the claim from `design.md` before A3.

---

### Task 2.1–2.5: Session model, store port and memory store

**Files:**
- Modify: `session/session.go` (fields), `session/store.go` (port and godoc, `Supersession`), `session/memory.go`, `session/encrypted.go`
- Regenerate: `session/store_mock_test.go`
- Modify: `test/storetest/session_suite.go`, `test/storetest/race.go`, `test/storetest/broken_session_test.go`, `test/storetest/broken_race_test.go`
- Stub: the `sqlstore`, `pgx` and `gorm` session stores (`sqlstore/session.go`, `pgx/session.go`, `gorm/session.go`). Add the four methods returning `errors.New("not implemented")`.

**Interfaces:**
- Produces: the `Session` fields, the four `Store` methods and the `Supersession` type, exactly as in Global Constraints, plus `ErrSessionRenewalConflict`. `Create` sets `FamilyID` from the manager's `id` generator (the `pkg/id` default) and sets `FamilyCreatedAt = CreatedAt`.

- [ ] **Step 1 (2.1 red): suite cases for `RecordActivity`.** Add them in `session_suite.go`'s case table, one `assert` closure per case:
  - `"activity write leaves a fresher record unchanged"`: last accessed 09:19:30, `olderThan` 09:19, so no error and the stored session is unchanged;
  - `"activity write leaves other fields"`: load copy A, change `Data` and `Save` through copy B, then `RecordActivity` from A's values. `Data` is B's, and `LastAccessedAt` is the recorded time;
  - `"activity write on a deleted session is not found and inserts nothing"`;
  - `"activity write on a superseded session changes nothing"`, which uses `Supersede` and stays red until step 3.
  - Add a broken memory variant, `wholeRecordActivity`, whose `RecordActivity` calls `Save`.
- [ ] **Step 2: run the memory runner.** `(cd test && go test -count=1 -run 'TestMemorySessionStore' ./storetest/)`
  - Expected: FAIL with `not implemented` from the stubbed memory methods.
- [ ] **Step 3 (2.2): implement in the memory store.**
  - `RecordActivity`:
    - under the store lock, a missing record is `ErrSessionNotFound`;
    - if `rec.SupersededAt` is set or `!rec.LastAccessedAt.Before(olderThan)`, return nil;
    - otherwise set only `LastAccessedAt` and `IdleExpiresAt`.
  - `MarkPresented` sets `FirstPresentedAt` only if it is zero.
  - `DeleteFamily` deletes every record whose `FamilyID` matches, and returns the count.
  - `Supersede`:
    - load `Old`; missing is `ErrSessionNotFound`;
    - compare `bytes.Equal(rec.SuccessorDigest, op.ObservedSuccessor)`, and on a mismatch return `ErrSessionRenewalConflict` having written nothing;
    - if there is a previous successor, mark it superseded with `AcceptUntil = op.Now` and both deadlines set to its absolute deadline;
    - set `Old`'s `SupersededAt = op.Now`, `AcceptUntil = op.AcceptUntil`, `SuccessorDigest = digest(op.Successor.ID)`, and both deadlines to `Old`'s absolute deadline;
    - insert `Successor`.
    - Use the same digest function as the durable stores (`storekit.SessionDigest`). If it is internal to another package, add a session-local SHA-256 helper with a test pinning equality with `storekit`'s.
  - The encrypted wrapper delegates all four methods, sealing `Successor`'s ID token as `Create` does.
  - Regenerate the mock: `go generate ./session/`.
- [ ] **Step 4: run** the step 2 command and `go test -race -count=1 ./session/...`, then `make generate-check`.
  - Expected: PASS, and `wholeRecordActivity` is caught by the "other fields" case.
- [ ] **Step 5 (2.3 red): suite cases for supersession and families.**
  - `"stale observation is refused and writes nothing"`;
  - `"successor stored in the family with its start time"`;
  - `"load returns a superseded record past its window"`;
  - `"sweep keeps a superseded record until the family's absolute deadline"`;
  - `"family delete counts one family"`: 3 rows in the family plus 1 other row for the same user, so the result is 3 and the other row still loads;
  - `"first presentation keeps the first time"`;
  - `"family and supersession values round-trip at microsecond precision"`;
  - `"save leaves supersession state unchanged"`;
  - `"supersede after family revocation is not found and inserts nothing"` (Review Focus 3).
  - Run them red against stubs that are deliberately wrong (for example, `DeleteFamily` returning 0) to confirm each case can fail, then make them pass.
- [ ] **Step 6 (2.4): race.** In `race.go`, add `sessionSupersessionRace`: 50 sessions × 8 racers, each calling `Supersede` with `ObservedSuccessor: nil`. The pass condition is exactly one nil error per session, with the rest `errors.Is(err, session.ErrSessionRenewalConflict)`. Add `broken_race_test.go`'s `readThenWriteSupersede` variant, which loads, then saves unconditionally. Verify the variant is caught and the memory store passes, with `-race`.
- [ ] **Step 7 (2.5): godoc.** Document each new port method's contract in `store.go`:
  - `Load` returns superseded records;
  - `RecordActivity` never inserts;
  - `Supersede` is conditional on `ObservedSuccessor`;
  - an implementation must be atomic across processes.
  - Run `go doc ./session Store` and `go vet ./...`.
- [ ] **Step 8: commit** `feat(session): session families and supersession in the store port`.

---

### Task 3.1–3.3: Activity interval, lifetimes and families in the manager

**Files:**
- Modify: `session/manager.go`, `session/options.go`, `session/enrolment.go`
- Tests: `session/touch_test.go`, `session/create_test.go`, `session/enrolment_test.go`, `session/rotate_test.go`

**Interfaces:**
- Consumes: the A2 port.
- Produces: `WithTouchInterval`, `WithAbsoluteLifetime`, `WithMaxAbsoluteLifetime`, `RevokeFamily`, and family-keeping `Rotate`.

- [ ] **Step 1 (3.1 red): a `TestTouch` table** in `touch_test.go`:
  - default 0, two writes 10 s apart: both persist, with the idle deadline from the second;
  - interval 1 m, last accessed 30 s ago: no store call (a mocked store expects no `RecordActivity`);
  - interval 1 m, last accessed 60 s ago: `RecordActivity(ctx, id, now, now+idle, now-1m)`;
  - skips only bring expiry earlier: writes at 09:00 and 09:00:50 with a 1 m interval, and `Load` at 09:30:00 is expired;
  - `NewManager` refuses an interval of -1 s, 30 m (equal to idle) and 31 m.
  - Run it together with 1.1, and expect FAIL.
- [ ] **Step 2: implement.**
  - `m.touchInterval` (default 0) is validated in `NewManager`.
  - `Touch` keeps the expired check, then `if m.touchInterval > 0 && now.Sub(s.LastAccessedAt) < m.touchInterval { return nil }`.
  - Otherwise it computes the idle deadline as today, and calls `m.store.RecordActivity(ctx, s.ID, now, idle, now.Add(-m.touchInterval))`. With interval 0 the threshold is `now`, so any older record is written.
  - Update `s` in memory only after the store returns nil.
  - Run step 1's tests and 1.1, and expect PASS.
- [ ] **Step 3 (3.2 red): lifetime tests in `create_test.go`.**
  - The default maximum refuses 30 d and the store sees no `Create`.
  - Maximum 30 d with 30 d: the absolute deadline is creation + 30 d, and idle is at most that.
  - No option: creation + 12 h.
  - `NewManager` refuses a maximum of 1 h under a 12 h absolute timeout.
  - In `enrolment_test.go`: a 30-day session marked at 09:00 and restored at 09:05 has absolute creation + 30 d.
  - Expect FAIL.
- [ ] **Step 4: implement.**
  - `WithAbsoluteLifetime(d)` sets `s.AbsoluteExpiresAt = s.CreatedAt.Add(d)` and records `d` on an unexported creation field, so `Create` can tell "chosen" from "default". The option type stays `func(*Session)`; use an unexported field on `Session`, documented as library-only.
  - `Create` validates `0 < d <= m.maxLifetime` and returns a configuration error before calling the store, then caps idle at absolute.
  - `RestoreEnrolmentDeadlines` sets `absolute := s.EnrolmentOriginDeadline`.
  - Run all `session` tests.
- [ ] **Step 5 (3.3 red): family tests.**
  - Two `Create`s for one user have different `FamilyID`.
  - `Rotate`, then `Rotate` again: all three share `FamilyID` and `FamilyCreatedAt`.
  - `RevokeFamily` returns 2, and the user's other family loads.
  - Expect FAIL on `RevokeFamily` (stubbed) and on family equality, if the clone drops the fields.
- [ ] **Step 6: implement** `RevokeFamily` via `store.DeleteFamily`, and make sure `clone()` copies the new fields. Run all `session` tests with `-race`.
- [ ] **Step 7: commit** `feat(session): coalesced activity, per-session lifetime and families`.

---

### Task 3.4–3.7: Grace rotation, reuse, recovery, renewal lifetime and the observer

**Files:**
- Create: `session/reuse.go` (judging and revocation), `session/rotate_grace_test.go`
- Modify: `session/manager.go` (`Load`, `RotateWithGrace`), `session/options.go`

**Interfaces:**
- Produces: `RotateWithGrace`, `RotateOption`, `WithSuccessorLifetime`, `RenewalKind`, `ErrSessionReused`, `WithUnusedSuccessorRecovery`, `WithMaxFamilyLifetime`, `WithReuseObserver`, `ReuseReport`, and `MaxRenewalGrace`.
- `ErrSessionReused` is declared so that `errors.Is(ErrSessionReused, ErrSessionExpired)` is true, for example `var ErrSessionReused = fmt.Errorf("session: a superseded session was presented after its window: %w", ErrSessionExpired)`.

- [ ] **Step 1 (3.4 red): a `TestRotateWithGrace` table**, on a fake clock and the memory store:
  - the old identifier loads at +20 s;
  - the window is capped at the absolute deadline;
  - a grace of -1 s or 5 m 1 s is a configuration error, and nothing is stored;
  - a grace of exactly 5 m is accepted;
  - re-rotation at +10 s returns S2 with `RenewalReRotation`, and S1 then gives `ErrSessionReused`;
  - `Load` of O at +5 m gives `ErrSessionReused`, which `errors.Is` matches as `ErrSessionExpired`, and S1 is then not found;
  - detection at +9 h still works;
  - first `Load` sets `FirstPresentedAt` once (a mock store expects one `MarkPresented`);
  - `Touch` on a superseded session makes no store write;
  - Review Focus 1: after reuse, `Delete(O)` reports not-found or nil (both acceptable), and the family is gone;
  - Review Focus 2: managers on clocks 09:00:29 and 09:00:31 judge `AcceptUntil = 09:00:30` as inside and as reuse respectively.
  - Expect FAIL.
- [ ] **Step 2: implement.**
  - **`Load`:** after the store returns, if `s.SupersededAt` is set and `!now.Before(s.AcceptUntil)`, then `return nil, m.reuse(ctx, s, now)`.
    - `reuse` calls `DeleteFamily`, then the observer if one is set, then logs at warning with the fixed reason and the family id, and returns `ErrSessionReused`.
    - With recovery on and the successor unpresented, return the record instead, marked for `RotateWithGrace`, through an unexported flag on `Session` that only `RotateWithGrace` reads. A plain request must not authenticate with it, so `Load` returns `ErrSessionReused` for every caller except `RotateWithGrace`'s internal load.
    - On a live, unpresented, non-superseded session, call `MarkPresented`. Its failure is logged at debug and does not fail the load.
  - **`RotateWithGrace`:**
    - validate the grace;
    - use the internal load;
    - mint the identifier and clone with the same family;
    - set the successor's deadline (carry-over, or `WithSuccessorLifetime`: above the lifetime maximum is a configuration error, and a deadline past `FamilyCreatedAt + maxFamily` is cut to it);
    - call `store.Supersede` with `ObservedSuccessor` equal to the loaded `SuccessorDigest`;
    - return the kind.
  - Run it.
- [ ] **Step 3 (3.5 red): a barrier test.**
  - Two managers share one memory store, start behind a `sync.WaitGroup` barrier, and both call `RotateWithGrace(O)`.
  - Exactly one gets a nil error and the other `ErrSessionRenewalConflict`, and the family holds one unsuperseded session.
  - Run it with `-race -count=50`. Prove it bites by temporarily calling a store wrapper that ignores `ObservedSuccessor`: FAIL. Remove the wrapper, and expect PASS.
- [ ] **Step 4 (3.6 red): three tables.**
  - `TestUnusedSuccessorRecovery`:
    - default: a next-day retry gives `ErrSessionReused` and the family is gone;
    - option on, S1 unpresented: S2 with `RenewalRecovery`, and S1 then reuse;
    - option on, S1 loaded once: reuse.
  - `TestRenewalLifetime`:
    - carry-over gives 21:00;
    - 30 d on day 20 of a 90 d family gives now + 30 d;
    - day 80 gives family start + 90 d;
    - 45 d under a 30 d lifetime maximum gives a configuration error and nothing stored;
    - `Rotate` (second-factor verification) never extends;
    - `NewManager` refuses a family maximum below the lifetime maximum.
  - `TestReuseObserver`:
    - none: still revoked;
    - one call after `DeleteFamily` (the order is asserted with a mock store and `gomock.InOrder`), with the report holding the user and family;
    - `fmt.Sprintf("%+v", report)` contains no identifier substring (Review Focus 5);
    - nil gives a configuration error.
  - Expect FAIL, then implement.
- [ ] **Step 5 (3.7): godoc on every new option and method.**
  - The default and the override.
  - The recovery trade-off, in plain words.
  - On `ErrSessionReused` and `WithReuseObserver`, the transaction rule: a consumer that attached a transaction must commit when `errors.Is(err, ErrSessionReused)`, and must audit inside a savepoint.
  - On `WithMaxAbsoluteLifetime` and `WithMaxFamilyLifetime`, the NIST SP 800-63B-4 figures: 30 days at AAL1, 24 h at AAL2.
  - Run `/simplify` on `session/`, then `go test -race -count=1 ./session/...`, `go vet ./...` and `go doc ./session`.
- [ ] **Step 6: commit** `feat(session): grace rotation, reuse detection and renewal lifetime`.

---

### Task 4.1–4.6: Schema and durable stores

**Files:**
- Create: `migrate/securitystate/20261021000000_session_families.sql`, with a timestamp after every existing file.
- Modify: `internal/pgschema/sessions.go`, `sqlstore/session.go`, `pgx/session.go`, `gorm/session.go`, `gorm/models.go`
- Tests: `test/migrate_securitystate_test.go`, `test/storetest/ambient.go`, and the runners in `test/sqlstore`, `test/pgxstore` and `test/gormstore`

**Interfaces:**
- Consumes: the A2 port, the A2 suites, and `RunTestPostgres`.

- [ ] **Step 1 (4.1 red): migration tests.**
  - The columns and types: `family_id uuid NOT NULL` indexed as `sessions_family`, and `family_created_at timestamptz NOT NULL`.
  - Nullable with no default: `superseded_at`, `accept_until`, `successor_digest bytea` and `first_presented_at`.
  - Backfill on a populated table: apply up to the previous version, insert two sessions through a store, apply the new one, and both load with `FamilyID` equal to their row's `id` and `FamilyCreatedAt` equal to `CreatedAt`.
  - Rollback: the column set equals the pre-migration set.
  - Run them on PostgreSQL 15 and 18, and expect FAIL.
- [ ] **Step 2 (4.2): write the migration.**

```sql
-- +goose Up
ALTER TABLE sessions ADD COLUMN family_id uuid;
ALTER TABLE sessions ADD COLUMN family_created_at timestamptz;
UPDATE sessions SET family_id = id, family_created_at = created_at;
ALTER TABLE sessions ALTER COLUMN family_id SET NOT NULL;
ALTER TABLE sessions ALTER COLUMN family_created_at SET NOT NULL;
ALTER TABLE sessions ADD COLUMN superseded_at timestamptz;
ALTER TABLE sessions ADD COLUMN accept_until timestamptz;
ALTER TABLE sessions ADD COLUMN successor_digest bytea;
ALTER TABLE sessions ADD COLUMN first_presented_at timestamptz;
CREATE INDEX sessions_family ON sessions (family_id);

-- +goose Down
DROP INDEX sessions_family;
ALTER TABLE sessions DROP COLUMN first_presented_at, DROP COLUMN successor_digest,
  DROP COLUMN accept_until, DROP COLUMN superseded_at,
  DROP COLUMN family_created_at, DROP COLUMN family_id;
```

  Confirm the goose annotation style against the existing file before writing. Run step 1, and expect PASS.

- [ ] **Step 3 (4.3): statements and `sqlstore`.**
  - In `pgschema`, add:

```sql
-- SessionRecordActivity: $1 id_digest, $2 last_accessed_at, $3 idle_expires_at, $4 older_than
UPDATE sessions SET last_accessed_at = $2, idle_expires_at = $3
WHERE id_digest = $1 AND last_accessed_at < $4 AND superseded_at IS NULL
-- zero rows: SessionExists ($1) decides between nil and not-found

-- SessionSupersedeOld: $1 id_digest, $2 observed successor (NULL for none), $3 now, $4 accept_until, $5 new successor digest
UPDATE sessions SET superseded_at = $3, accept_until = $4, successor_digest = $5,
  idle_expires_at = absolute_expires_at
WHERE id_digest = $1 AND successor_digest IS NOT DISTINCT FROM $2
-- one row affected means the previous successor is exactly $2, the observed one

-- SessionSupersedePrevious: $1 previous digest, $2 now
UPDATE sessions SET superseded_at = $2, accept_until = $2, idle_expires_at = absolute_expires_at
WHERE id_digest = $1
-- unconditional on superseded_at, as the memory store and the spec require; successor_digest is left alone

-- SessionDeleteFamily: $1 family_id
DELETE FROM sessions WHERE family_id = $1
-- repeated until it affects zero rows: under READ COMMITTED a delete blocked by an
-- in-flight Supersede cannot see the successor that transaction inserts

-- SessionMarkPresented: $1 id_digest, $2 at
UPDATE sessions SET first_presented_at = $2 WHERE id_digest = $1 AND first_presented_at IS NULL
```

  - Add the new columns to `SessionInsert` and `SessionSelect`. `SessionUpdate` stays without them, and leaves both deadlines unchanged on a row whose `superseded_at` is set (the suite's "save leaves supersession state unchanged" case pins this).
  - `DeleteFamily` refuses `id.Nil` with an error before running any statement.
  - `Supersede` runs `SupersedeOld`, then `SupersedePrevious` with `ObservedSuccessor` when it is non-nil, then `SessionInsert`, all in one transaction: the attached one if present, otherwise one it opens and commits.
  - If `SupersedeOld` affects zero rows, distinguish a missing record (not-found) from a lost race (renewal conflict) by `SessionExists`.
  - Run `(cd test && go test -count=1 -run 'TestSQLStore.*Session|TestSQLStore.*Race' ./sqlstore/)`, and expect PASS, with the broken variants caught.
- [ ] **Step 4 (4.4): `pgx`.** The same statements, through `pgx`'s exec and transaction helpers. Run the `pgx` session, race and ambient runners.
- [ ] **Step 5 (4.5): `gorm`.** Map the fields with column tags. `Save` must keep omitting the new columns, so extend the existing `Omit` list. Implement through `db.Exec` with the `pgschema` statements, as the other gorm session methods do. Run the `gorm` runners.
- [ ] **Step 6 (4.6 red then green): ambient-transaction cases.**
  - A caller begins a transaction, attaches it, calls `Supersede` and `DeleteFamily`, and rolls back: neither the successor nor the deletion persists.
  - Write the cases red against a broken variant that opens its own transaction, then run them on all three backends.
- [ ] **Step 7: commit** `feat(stores): session families and supersession on PostgreSQL`.

---

### Task 5.1–5.3, 5.5: The shared resolution core and exported publication

**Files:**
- Create: `httpsec/resolve.go`, `httpsec/resolve_test.go`
- Modify: `httpsec/bearer.go` (lines 75–190 move into the core), `httpsec/exchange.go`, `httpsec/context.go`, `httpsec/doc.go`

**Interfaces:**
- Produces: `(*Exchange).PublishSession` and `(*Exchange).EvaluatePerRequest`, as in Global Constraints. Also an unexported `resolveSession(ex *Exchange, s *session.Session, users identity.UserLoader, by userLookup) error`, which C2 extends.

- [ ] **Step 1 (5.1): baseline.** Run `go test -count=1 -run 'Bearer|MFA|PasswordChange|SessionTouch' ./httpsec/` and keep the output.
- [ ] **Step 2 (5.2 red): tests in `resolve_test.go`.**
  - A consumer interceptor calls `ex.PublishSession(auth, s)`, then `SessionFromContext` returns `s`, and after the handler the session's activity was recorded (a mocked store expects one `RecordActivity`).
  - A consumer interceptor calls `ex.EvaluatePerRequest(s, p)` with a policy that challenges for enrolment: the session is saved enrolment-pending, and the enrolment gate refuses with the same challenge error a bearer request gets.
  - Stub both methods first, and expect FAIL on behaviour.
- [ ] **Step 3 (5.3): implement and extract.**
  - `PublishSession` sets `ex.Authentication` and `ex.Session`, and `ex.SetContext(withSession(WithCaller(ex.Context(), a), s))`.
  - `EvaluatePerRequest` is the body of `bearer.go:143–185`, reading the chain's engine and enforcer set from unexported exchange fields that the chain sets when it creates the exchange.
  - The bearer's `Intercept` then calls the two methods.
  - Run the step 2 tests and the 5.1 baseline. Expect identical PASS lists.
- [ ] **Step 4 (5.5): `doc.go`.** Name the two methods in the consumer-interceptor section. Run `go doc ./httpsec | grep -n 'PublishSession\|EvaluatePerRequest'`.
- [ ] **Step 5: commit** `refactor(httpsec): one session resolution core, exported to consumer interceptors`.

---

### Task 5.4, 6.1–6.5: Reuse in the core, and the session-reference bearer

**Files:**
- Create: `httpsec/sessionbearer.go`, `httpsec/sessionbearer_test.go`
- Modify: `httpsec/resolve.go`, `httpsec/bearer.go`, `httpsec/logincomplete.go` (credential issuance), `httpsec/mfaverify.go`, `httpsec/recoverycomplete.go`, `httpsec/errors.go`, `httpsec/status.go`, `httpsec/options.go` (construction checks)
- Tests: `httpsec/bearer_test.go`, `httpsec/status_test.go`, `httpsec/errors_test.go`, `test/httpsec_gin_test.go`, `test/httpsec_fiber_test.go`

- [ ] **Step 1 (5.4 red):** a bearer test with a token whose `jti` names a session superseded past its window. The error matches both `ErrAuthenticationRequired` and `session.ErrSessionReused`, and the family is revoked. Expect FAIL, because today the error is only authentication-required. Implement it in `resolveSession` with `errors.Join(ErrAuthenticationRequired, err)` when `errors.Is(err, session.ErrSessionReused)`. Expect PASS.
- [ ] **Step 2 (6.1 red): a `TestSessionBearer` table.**
  - A live reference authenticates.
  - A malformed value (empty, too short, non-base64url, 44 characters) is refused with no store call, using the mock store with no expectations.
  - The user is reloaded by `UserID`: the mock `UserLoader` expects `LoadByUserID("u-1")` and never `LoadByUsername`.
  - A reused reference gives the double-identity error.
  - Scheme `Session` accepts `session <id>`.
  - Stub `EnableSessionBearer`, and expect FAIL.
- [ ] **Step 3: implement.** Extraction is shared with the signed bearer's `presented` helper. The format check is the identifier's exact encoded length and the URL-safe alphabet, taken from `session`'s identifier constants (export a `session.ValidIdentifier(string) bool` if none exists, with its own test). Then `Load`, `LoadByUserID`, and `resolveSession`. Run step 2.
- [ ] **Step 4 (6.2 red):** construction tests in which `New` fails with a configuration error for:
  - `EnableSessionBearer` plus `EnableBearerToken`;
  - `EnableSessionBearer` plus `FormLoginDeps.Tokens != nil`;
  - the same plus an MFA verify generator, or a recovery generator.
  - Implement the check in chain assembly. Run it.
- [ ] **Step 5 (6.3 red):** with the reference mode on, password login, MFA verify and recovery completion hand their responders `LoginResult.Token == session.ID`, and a request bearing it authenticates. Implement it by giving `loginTailDeps` an unexported `issue func(ctx, s *session.Session, p *identity.Principal) (string, error)`: the generator in signed mode, `s.ID` in reference mode. `completeLogin`, `mfaverify` and `recoverycomplete` call it. Run these together with `go test -count=1 -run 'Login|MFA|Recovery' ./httpsec/`.
- [ ] **Step 6 (6.4 red):** in `status_test.go`, a wrapped `ErrSessionRenewalConflict` maps to 409, and `errors.Join(ErrAuthenticationRequired, session.ErrSessionReused)` maps to 401. In `errors_test.go`, the reuse refusal's `Error()` contains no identifier. Add the `httpsec.ErrSessionRenewalConflict` sentinel wrapping the session one, and the table row. Run it.
- [ ] **Step 7 (6.5):** in the `test` module, a gin and a fiber case: a live reference authenticates and a reused one gets 401. Make no adapter code change. Run `(cd test && go test -count=1 -run 'SessionBearer' ./...)`.
- [ ] **Step 8: commit** `feat(httpsec): opaque session-reference bearer`.

---

### Task 7.1–7.2: The renewal endpoint

**Files:**
- Create: `httpsec/renewal.go`, `httpsec/renewal_test.go`

- [ ] **Step 1 (7.1 red): a `TestSessionRenewal` table**, in reference mode on a fake clock:
  - `POST /session/renewal` gives 200, a JSON credential in the login default's shape, and `Cache-Control: no-store`;
  - the old credential authenticates at +29 s, and at +31 s is reuse;
  - unauthenticated gives `ErrAuthenticationRequired`;
  - `GET /session/renewal` passes through;
  - with the consumer path, a 60 s grace and a responder, the responder gets the successor, the user and `RenewalFresh`;
  - a test `slog` handler captures every record, and none contains either credential (Review Focus 5).
  - Stub, and expect FAIL. Implement: it requires `ex.Session`, calls `RotateWithGrace`, then `deps.Users.LoadByUserID`, issues the credential through the mode's `issue`, and then the responder.
- [ ] **Step 2 (7.2 red):**
  - re-rotation inside the window gives `RenewalReRotation`;
  - with recovery on at the manager, a next-day retry gives `RenewalRecovery`;
  - a concurrent pair (barrier) gives one 200 and one `ErrSessionRenewalConflict`;
  - `WithRenewalGrace(10*time.Minute)` gives a construction error;
  - signed mode without `Tokens` gives a construction error;
  - an enrolment-pending session posting to the path is refused by the enrolment gate (Review Focus 4).
  - Implement, and run with `-race`.
- [ ] **Step 3: commit** `feat(httpsec): session renewal endpoint`.

---

### Task 7.3–7.5: Renewal lifetime, login lifetime and godoc

**Files:**
- Modify: `httpsec/renewal.go`, `httpsec/login.go` (`bind` returns the parsed fields), `httpsec/logincomplete.go`
- Tests: `httpsec/renewal_test.go`, `httpsec/login_test.go`

- [ ] **Step 1 (7.3 red):**
  - with no `WithRenewalLifetime`, 21:00 is carried over;
  - a function returning 30 d under a 30 d maximum and a 90 d family, on day 10, gives now + 30 d;
  - on day 80, the responder's `RenewalResult.Session.AbsoluteExpiresAt` is family start + 90 d;
  - 45 d under a 30 d lifetime maximum gives a configuration error, a 500, and nothing stored.
  - Implement by passing `session.WithSuccessorLifetime(fn(ex, s))` when fn returns more than 0.
- [ ] **Step 2 (7.4 red):**
  - the default gives 12 h;
  - `WithLoginLifetime` returning 30 d when `Value("remember") == true` (JSON) or `"true"` (form) gives 30 d under a 30 d maximum;
  - 30 d under a 12 h maximum gives a configuration error, a 500, and no session (the mock store expects no `Create`);
  - `LoginFields.Value(passwordParam)` reports false.
  - Implement:
    - `bind` keeps the parsed form values or JSON map;
    - `LoginFields` wraps them and drops the password key;
    - `formLogin` calls the function after authentication and appends `session.WithAbsoluteLifetime(d)` to the create options it passes to `completeLogin`.
  - Run `go test -count=1 -run 'Login' ./httpsec/`.
- [ ] **Step 3 (7.5): godoc.** On `EnableSessionRenewal`, `WithRenewal*` and `WithLoginLifetime`, cover:
  - the defaults and the overrides;
  - the commit-on-reuse rule;
  - "switch to the successor as soon as renewal returns, and retry queued requests with it".
  - Run `/simplify` over the touched `httpsec` files, then `go test -race -count=1 ./httpsec/...`, `go vet ./...` and `gofmt -l .`.
- [ ] **Step 4: commit** `feat(httpsec): renewal and login lifetimes`.

---

### Task 8.1–8.2: Integration gate (main session)

- [ ] **8.1:** dispatch a fresh Opus reviewer that edits nothing. It gets every spec delta, the design decisions, and `git diff main...HEAD`, and reports each finding as `REPRODUCED` (with a failing test) or `UNREPRODUCED`. Findings go back to a fresh dispatch of the owning lane.
- [ ] **8.2:** run `make check` and `openspec validate first-party-sessions --strict`, and keep both outputs in the closing report.


---

### Tasks 9.1–9.2: The authentication time, and second-factor rotation in flight

Design: "Pull request review (2026-10-21)", findings 1–3 (finding 1 as decided 2026-10-22). Specs: `sessions` requirements "A session records when the user last authenticated", "Rotation at second-factor verification keeps the old identifier only in flight", "A failed delete does not fail a second-factor rotation"; `http-security-chain` "A renewal does not refresh authentication for freshness checks". Every claim is `UNREPRODUCED` until its first test fails; a test that passes on the current code is reported, and the main session withdraws the decision.

**Files:**
- Modify: `session/session.go` (`AuthenticatedAt time.Time` beside `MFASatisfiedAt`, copied by `clone`), `session/manager.go` (`Create` sets it; second-factor satisfaction refreshes it; `Rotate`), `session/reuse.go` (`RotateWithGrace` carries it over and sets the successor's `CreatedAt` to the renewal time), `session/memory.go` (the six library-only fields that `Save` preserves gain `AuthenticatedAt`, so a stale copy cannot move it), `session/encrypted.go` (nothing to seal; confirm it passes through), `httpsec/recoverycodes.go` (freshness reads `s.AuthenticatedAt` only)
- Test: `session/renewal_test.go`, `session/create_test.go`, `session/rotate_strict_race_test.go`, `httpsec/recoverycodes_test.go`

**Interfaces:**
- Produces: `Session.AuthenticatedAt`; `session.DefaultRenewalGrace` (30 s, exported beside `MaxRenewalGrace` if it does not exist). The renewal endpoint is not touched here: `httpsec/renewal.go` belongs to dispatch T2.
- Consumes: `RotateWithGrace`, `Rotate`, `Store.Supersede`, `Store.Delete`, the second-factor satisfaction path (find it with gopls: the code that sets `MFASatisfiedAt`).

- [ ] **Step 1 (9.1 red):** add the field and stub it unset. Tests:
  - `create_test.go`, "a sign-in records its authentication time": created at 09:00 → `AuthenticatedAt == 09:00`.
  - `renewal_test.go`, "a renewal carries the authentication time over": created 09:00, `RotateWithGrace` at 15:00 → successor `AuthenticatedAt == 09:00`, `CreatedAt == 15:00`.
  - a second-factor case: signed in 09:00, satisfied at 09:20 → `AuthenticatedAt == 09:20`.
  - `httpsec/recoverycodes_test.go`, "regeneration after a renewal still needs reauthentication": sign in 09:00, renew 15:00 through `EnableSessionRenewal`, regenerate 15:01 under the default 15-minute freshness → `recovery.ErrReauthenticationRequired`, no new codes.
  Run `go test -count=1 -run 'Create|Renewal|Recovery|Satisf' ./session/ ./httpsec/`. Expected: FAIL (zero field; regeneration allowed because the successor's `CreatedAt` is 15:00).
- [ ] **Step 2 (9.1 green):** set it in `Create` (`s.AuthenticatedAt = s.CreatedAt` before options run, so a consumer `CreateOption` may still override it), refresh it wherever `MFASatisfiedAt` is set, carry it over in `RotateWithGrace` and `Rotate` (the successor is a clone), keep it in `Save`'s preserved fields, and change `regenerate` to `if i.now().Sub(s.AuthenticatedAt) > i.freshness`. Godoc on the field: what sets it, that renewal never does, that freshness checks read it. Run both packages and the memory conformance runner. Durable runners do not round-trip the field until 9.4: confirm they compile.
- [ ] **Step 3 (9.2 red):** in `session/rotate_strict_race_test.go`, a store wrapper whose `Supersede` signals and waits on a channel lets a `Load` of the old identifier run between the strict rotation's `Supersede` and `Delete`. Case "a load between the writes returns the old session": the old session comes back (same `UserID`, second factor still pending) and the successor loads afterwards. Case "a failed delete does not fail the rotation": a store whose `Delete` errors; `Rotate` returns the successor with nil error; the old identifier loads at +10 s and is reuse at +31 s. Run `go test -count=1 -race -run 'TestRotate' ./session/`. Expected: FAIL (reuse revokes the family; `Rotate` returns the delete error).
- [ ] **Step 4 (9.2 green):** supersede with `AcceptUntil: minTime(now.Add(DefaultRenewalGrace), s.AbsoluteExpiresAt)`, then delete; on a delete error, log at error with the fixed reason and the family id, never an identifier, and return the successor. Keep the per-identifier lock; the two-live-heads tests stay green. Run `go test -count=1 -race ./session/...` and `go test -race -count=50 -run 'Race|Racing|Concurrent' ./session/`.
- [ ] **Step 5: commit** `fix(session): record when the user last authenticated, and let second-factor rotation tolerate requests in flight`.
- [ ] **Step 6 (9.1, passkey management, dispatch P1, red):** in `passkey/manager_test.go` (or the file holding the management-admission tests), a case "registration after a renewal still needs reauthentication": a full session signed in at 09:00 (`AuthenticatedAt` 09:00, `MFA` satisfied at 09:00), renewed at 15:00 (successor `CreatedAt` 15:00, `AuthenticatedAt` 09:00); admitting a registration at 15:01 under the default 15-minute management freshness returns `passkey.ErrReauthenticationRequired`. Also "a fresh second factor admits it": the same session with `AuthenticatedAt` refreshed to 15:00 is admitted at 15:01. Run `go test -count=1 -run 'Fresh|Reauth' ./passkey/`. Expected: FAIL (admitted, because `CreatedAt` is 15:00).
- [ ] **Step 7 (green):** in `passkey/manager.go`, replace the `latest := s.CreatedAt` / `MFASatisfiedAt` block with `if m.clock.Now().Sub(s.AuthenticatedAt) > m.freshness { return ErrReauthenticationRequired }`. Update the `WithManagementFreshness` godoc and `passkey/doc.go` to say the window is measured from the session's authentication time. In `test/httpsecconformance/passkey_scenarios.go`, the fixture that makes a session fresh by setting `MFASatisfiedAt` must set `AuthenticatedAt` too. Run `go test -race -count=1 ./passkey/... ./httpsec/...` and `(cd test && go test -count=1 -run 'Passkey' ./...)`.
- [ ] **Step 8: commit** `fix(passkey): judge management freshness by the authentication time`.

---

### Task 9.3: Every stored session belongs to a family

Design finding 4, decided 2026-10-22. Spec: `security-state-stores` requirement "Every stored session belongs to a family". Done by S2 (memory store, suite, removal of the tolerant paths) and D2 (durable `Create`).

**Files:**
- Modify (S2): `session/memory.go` (`Create` refuses `id.Nil` before writing), `session/encrypted.go` (passes the refusal through), `httpsec/logout.go` (drop the family-less fallback delete: logout always revokes the family), `session/store.go` (`Create` godoc states the rule)
- Modify (D2): `sqlstore/session.go`, `pgx/session.go`, `gorm/session.go` (`Create` refuses `id.Nil` before any statement)
- Test: `test/storetest/session_suite.go` ("creating a session with no family is refused and stores nothing"), `broken_session_test.go` and `broken_test.go` (a variant that accepts it), and every fixture that creates a session without a family (find them by running the suites after the refusal: `session/*_test.go`, `httpsec/*_test.go`, `test/storetest/*`), each given a family with `id.MustParse` or the suite's family helper

- [ ] **Step 1 (red, S2):** the suite case and its broken variant. Run `(cd test && go test -count=1 -run 'TestMemory|TestSuitesCatchBrokenStores' ./storetest/)`. Expected: FAIL (the memory store accepts a family-less session).
- [ ] **Step 2 (green, S2):** add the refusal; give every failing fixture a family (a fixture fix, never a weakened assertion; list them in the report); remove logout's fallback and its family-less test case. Run `go test -race -count=1 ./session/... ./httpsec/...` and the memory runner.
- [ ] **Step 3 (red then green, D2):** the durable runners fail the new case; add the refusal in each `Create`, before any statement. Run the durable session suites on PostgreSQL 18 and 15.
- [ ] **Step 4: commit** (with 9.6) `fix(session): every stored session belongs to a family`.

---

### Task 9.4: Migration defaults and the authentication time column

Design findings 1 and 5. Specs: `schema-migrations` scenario "An older writer's insert" and requirement "The security-state set adds the session authentication time".

**Files:**
- Modify: `migrate/securitystate/20261021000000_session_families.sql` (unreleased): add `authenticated_at timestamptz`, backfill `UPDATE sessions SET authenticated_at = greatest(created_at, coalesce(mfa_satisfied_at, created_at))`, then `SET NOT NULL` and `SET DEFAULT now()`; add `SET DEFAULT gen_random_uuid()` on `family_id` and `SET DEFAULT now()` on `family_created_at`; the Down step drops `authenticated_at` too (`IF EXISTS`, one statement per line as the file's style requires)
- Modify: `internal/pgschema/sessions.go` (insert and select name `authenticated_at`; `SessionUpdate` leaves it alone, like the other library-only columns), `sqlstore/session.go`, `pgx/session.go`, `gorm/session.go`, `gorm/models.go` (map the column; `Save`'s omit list gains it), `test/gormstore/statements_test.go` (pinned statement text)
- Test: `test/migrate_securitystate_test.go`; the existing raw `INSERT INTO sessions` in `test/testutils_postgres_test.go` must still pass without naming the new column (that is the older-writer case)

- [ ] **Step 1 (red):** in `TestSecurityStateMigrations_SessionFamilies`:
  - "an older writer's insert succeeds": after applying, an insert naming neither family column nor `authenticated_at` succeeds, and all three are non-null;
  - "existing rows get their authentication time": a row created at 09:00 with `mfa_satisfied_at` 09:20 before the migration reads 09:20 after it, and one with no second factor reads 09:00;
  - the column snapshot and rollback cases include `authenticated_at`.
  And the session suite's round-trip case asserts `AuthenticatedAt` (S1 already added it to `assertSession`; if not, add it). Run on PostgreSQL 18 and 15 (`SCRTY_TEST_POSTGRES_IMAGE=postgres:15.19-alpine`). Expected: FAIL (SQLSTATE 23502; missing column; zero `AuthenticatedAt` from the durable stores).
- [ ] **Step 2 (green):** write the migration and the store plumbing as listed. Run the migration suite and the durable session suites on both versions.
- [ ] **Step 3: commit** `fix(migrate): default the session family columns and add the authentication time`.

---

### Task 9.5: A coalescing interval shorter than every enforced idle timeout

Design finding 6. Spec: `http-security-chain` requirement "A coalescing interval must be shorter than every idle timeout the policy enforces".

**Files:**
- Create: `session/interval.go` (`(*Manager).TouchInterval() time.Duration`, kept out of `manager.go`, which another dispatch holds)
- Modify: `policy/idle.go` (`(*IdleTimeoutPolicy).IdleTimeout() time.Duration`), `policy/engine.go` (`(*Engine).IdleTimeouts() []time.Duration`, collecting from every policy that has an `IdleTimeout() time.Duration` method, as `UnwiredFederatedAssurance` collects its facts), `httpsec/options.go` (the check in `New`, beside the other engine-introspection checks)
- Test: `session/interval_test.go`, `policy/engine_test.go`, `httpsec/` construction test

- [ ] **Step 1 (red):** in `httpsec`, a construction table: manager `WithTouchInterval(10*time.Minute)` and engine `NewIdleTimeoutPolicy(WithIdlePolicyTimeout(5*time.Minute))` → `New` returns an error wrapping `ErrConfig` that names the interval and the idle timeout; with a 15-minute idle timeout it builds; with interval 0 (the default) and a 5-minute idle timeout it builds. Stub the three accessors to return zero values first. Expected: FAIL (the refused case builds).
- [ ] **Step 2 (green):** implement the accessors and the check: refuse when `interval > 0` and any `idle <= interval`. Godoc on each accessor names what it reports; the `WithTouchInterval` godoc names the new construction rule. Run `go test -race -count=1 ./session/... ./policy/... ./httpsec/...`.
- [ ] **Step 3: commit** `feat(httpsec): refuse a touch interval an idle policy cannot tolerate`.

---

### Task 9.6: Supersession writes only what it supersedes

Design findings 7 and 8. Spec: `security-state-stores` requirements "Superseded sessions are returned by load and kept by the sweep" (retention deadline), "A supersession writes only the sessions it supersedes". This task replaces two earlier review fixes recorded in the design: "The family's deadline grows with renewal" and "Durable stores lock a family in id order". Their conformance cases ("extended family keeps its superseded sessions", "a chain of extending renewals raises every superseded session", the three raise-limit cases) and broken variants are rewritten to the retention rule, and `TestSessionExtendingRenewalLockOrder` is replaced by a lock-order case for the rows a supersession still locks.

**Files (memory side, dispatch S2):**
- Modify: `session/store.go` (`Supersession.RetainUntil` and the `Supersede` godoc), `session/memory.go` (remove `extendSupersededLocked`; set superseded records' deadlines to `RetainUntil`; add a family index used by `DeleteFamily`), `session/encrypted.go` (delegate), `session/reuse.go` and `session/manager.go` (compute `RetainUntil = FamilyCreatedAt + maxFamilyLifetime` for every supersession)
- Test: `test/storetest/session_suite.go`, `broken_session_test.go`, `broken_test.go`, `session/renewal_test.go` (`TestRenewalLifetime_ExtendedFamilyStillDetectsReuse` must still pass: the retention deadline now covers it)

**Files (durable side, dispatch D2):**
- Modify: `internal/pgschema/sessions.go` (remove `SessionExtendSuperseded` and `SessionLockFamily`; add a statement locking the old row and the observed previous successor `ORDER BY id FOR UPDATE`; old-row and previous-successor updates set both deadlines to `RetainUntil`), `sqlstore/session.go`, `pgx/session.go`, `gorm/session.go`
- Test: `test/storetest/ambient.go` (replace `RunSessionExtendingRenewalLockOrder` with a case in which a re-rotation and a family revocation race over the two locked rows under descending row ids, expecting no deadlock), `test/{sqlstore,pgxstore,gormstore}/ambient_test.go`, `test/gormstore/statements_test.go`

- [ ] **Step 1 (red, S2):** suite case "earlier superseded sessions are untouched by later supersessions" (O→S1→S2→S3; O's stored deadlines and supersession fields equal what S1's supersession wrote) and "a superseded record keeps the retention deadline" (`RetainUntil` 21:00 written as both deadlines). Broken variant: a store that rewrites every superseded family member. Expected: the first case FAILS against the current memory store (the raise rewrites O on S3's supersession when it extends), and the variant is caught.
- [ ] **Step 2 (green, S2):** add `RetainUntil`, compute it in the manager, write it in the memory store, remove the raise, add the family index (`map[id.ID]map[string]struct{}` maintained in `putLocked` and `deleteLocked`). Rewrite the superseded raise cases to the retention rule. Run `go test -race -count=1 ./session/...` and `(cd test && go test -count=1 -race -run 'TestMemory|TestSuitesCatchBrokenStores' ./storetest/)`. Durable runners fail the new cases until D2: confirm they compile.
- [ ] **Step 3 (red, D2):** run the durable session runners; record the failing new cases.
- [ ] **Step 4 (green, D2):** implement as listed under Files. Run the session, race, ambient and broken suites on every backend on PostgreSQL 18 and 15, and the new lock-order case `-count=10 -race`.
- [ ] **Step 5: commit** `refactor(session): a supersession writes only what it supersedes`.

---

### Task 9.7: First presentation decided by the store

Design finding 9. Spec: `security-state-stores` scenario "Superseded session not marked".

**Files:**
- Modify: `session/store.go` (`ErrSessionSuperseded`; `MarkPresented` godoc), `session/memory.go`, `session/encrypted.go` (return the sentinel bare), `session/manager.go` (replace `recheckAfterMark`: on `ErrSessionSuperseded`, re-load and judge; otherwise no second read), `internal/pgschema/sessions.go` (`SessionMarkPresented ... WHERE first_presented_at IS NULL AND superseded_at IS NULL`; zero rows then distinguishes missing, superseded and already presented), the three durable session files
- Test: `test/storetest/session_suite.go`, `broken_session_test.go`, `broken_test.go`, `session/unused_successor_test.go`, `session/unused_successor_race_test.go`

- [ ] **Step 1 (red):** suite case "marking a superseded session's first presentation returns the superseded-session error and writes nothing", with a broken variant that marks it anyway. Manager test "a first presentation under recovery makes one load and one mark" with a counting store wrapper. Stub the sentinel first. Expected: FAIL (the store marks it; the manager loads twice).
- [ ] **Step 2 (green):** implement in every store and the manager. `TestUnusedSuccessorRecovery_FirstPresentationRacingRecovery` (every forced order, including the advancing-clock case) must stay green at `-race -count=50`. Run the suites on every backend, PostgreSQL 18 and 15.
- [ ] **Step 3: commit** `refactor(session): the store decides a first presentation of a superseded session`.

---

### Task 9.8: Shared durable-store helpers

Design finding 10. No behaviour change.

**Files:**
- Modify: `internal/storekit/` (new helpers beside `SessionDigest`: the digest argument for a nil-or-digest observation, the not-found-unless-exists check, the mapping from a supersession refusal cause to its sentinel), `sqlstore/session.go`, `pgx/session.go`, `gorm/session.go`
- Test: `internal/storekit` unit tests for each helper (table form); the existing suites unchanged

- [ ] **Step 1 (red):** unit tests for the three helpers against stubs that return zero values. Expected: FAIL.
- [ ] **Step 2 (green):** implement, then switch the three stores to them, leaving transaction and savepoint code per driver. Run the session, race and ambient suites on every backend, `golangci-lint run` in root, `pgx`, `gorm`, and `go vet ./...` in each.
- [ ] **Step 3: commit** `refactor(stores): share the session stores' driver-agnostic helpers`.

---

### Task 9.9: Unknown session references throttled per source

Design decision 14. Specs: `http-security-chain` requirements "Unknown session references are throttled per source" and "The session-reference guard's limiter is replaceable".

**Files:**
- Modify: `httpsec/sessionbearer.go` (a `guard sourceGuard` built in the bearer's enable step with `c.resolveSourceGuard("EnableSessionBearer", sessionReferenceFlow, b.limiter, defaultSessionReferenceFailureLimit, defaultSessionReferenceFailureWindow, c.refusalInterval)`; constants `sessionReferenceFlow = "session-reference"`, `defaultSessionReferenceFailureLimit = 100`, `defaultSessionReferenceFailureWindow = time.Minute`; `WithSessionBearerLimiter`)
- Test: `httpsec/sessionbearer_test.go`; `test/httpsec_gin_test.go`, `test/httpsec_fiber_test.go` (one flooded-source case each)

**Interfaces:**
- Consumes: `sourceThrottled(ctx, g, clientAddr, flow, sampler, log, now)`, `recordSourceFailure(ctx, g, src)` and `resolveSourceGuard` in `httpsec/throttle.go`, exactly as `httpsec/apikey.go` uses them.
- Produces: `WithSessionBearerLimiter(l ratelimit.Limiter) SessionBearerOption`.

- [ ] **Step 1 (red):** a `TestSessionBearerThrottle` table on a fake clock, with a mocked `ratelimit.Limiter` where counting matters and the memory limiter where flow matters:
  - "a flooded source is refused before any lookup": 100 well-formed unknown references from `203.0.113.7`, then a live one; the 101st request is refused with the bearer's refusal, and the mocked session store expects no `Load` for it;
  - "malformed values count": 100 malformed values from one source, then a live reference, is refused;
  - "live sessions spend nothing": 1,000 requests with a live reference are all served;
  - "a policy refusal is not recorded": a valid session the per-request policy denies 200 times leaves the source unthrottled;
  - "a consumer limiter receives the failures": `WithSessionBearerLimiter(mock)` expects `RecordFailure` once per refused reference with the source key;
  - "the shared factory builds the flow": a `ratelimit.LimiterFactory` mock expects `NewLimiter("session-reference", 100, time.Minute)`;
  - "nil limiter": `WithSessionBearerLimiter(nil)` fails `New` with the configuration error.
  Run `go test -count=1 -run 'TestSessionBearerThrottle' ./httpsec/`. Expected: FAIL (no guard; nothing refused, no factory call).
- [ ] **Step 2 (green):** add the guard in the order `apikey.go` uses: claim the header, `sourceThrottled` before the format check, `recordSourceFailure` on every refusal of the presented reference (format, load, user reload), never on a policy decision. Godoc on `EnableSessionBearer` and `WithSessionBearerLimiter`: the default, the override, fail-closed on backend outage, and the shared-address limit (configure the client address: gin's and fiber's trusted-proxy settings). Run `go test -race -count=1 ./httpsec/...` and `(cd test && go test -count=1 -run 'SessionBearer' .)`.
- [ ] **Step 3: commit** `feat(httpsec): throttle unknown session references per source`.

---

### Task 9.10: Renewals throttled per family

Design decision 14. Specs: `http-security-chain` requirement "Renewals are throttled per family"; `http-error-propagation` (renewal throttled → 429).

**Files:**
- Modify: `httpsec/renewal.go` (a `limiter ratelimit.Limiter` built in the enable step from `c.rateLimiterFactory().NewLimiter(sessionRenewalFlow, defaultRenewalLimit, defaultRenewalWindow)` unless `WithRenewalLimiter` gave one; constants `sessionRenewalFlow = "session-renewal"`, `defaultRenewalLimit = 10`, `defaultRenewalWindow = 10 * time.Minute`; the key `"family:" + s.FamilyID.String()`), `httpsec/errors.go` (`ErrRenewalThrottled`), `httpsec/status.go` (row → 429), `session/options.go` (`WithTouchInterval` godoc only)
- Test: `httpsec/renewal_test.go`, `httpsec/status_test.go`, `httpsec/errors_test.go`

**Interfaces:**
- Consumes: `ratelimit.Limiter` (`Exceeded(ctx, key) (bool, error)`, `RecordFailure(ctx, key) error`), the chain's limiter factory.
- Produces: `WithRenewalLimiter(l ratelimit.Limiter) SessionRenewalOption`, `ErrRenewalThrottled`.

- [ ] **Step 1 (red):** in `renewal_test.go`, a `TestSessionRenewalThrottle` table on a fake clock:
  - "an eleventh renewal of a family is refused": ten renewals of one family 30 s apart succeed; the eleventh returns an error matching `ErrRenewalThrottled`, the presented session is not superseded, and nothing new is stored;
  - "another family is unaffected": the same user's second sign-in renews successfully while the first family is at the limit;
  - "the window slides": after 10 minutes the family renews again;
  - "retries count but fit": a renewal and two re-rotations inside the grace window, then normal renewals, stay under the limit;
  - "a limiter outage refuses the renewal": a limiter whose `Exceeded` returns an error refuses with `ErrRenewalThrottled` and rotates nothing (fail closed);
  - "a consumer limiter is used": `WithRenewalLimiter(mock)` expects `Exceeded` and `RecordFailure` with key `family:<id>`;
  - "nil limiter": `WithRenewalLimiter(nil)` fails `New` with the configuration error.
  In `status_test.go`, `ErrRenewalThrottled` → 429, and it is registered among the public refusals. Run `go test -count=1 -run 'TestSessionRenewalThrottle|TestStatusFor' ./httpsec/`. Expected: FAIL.
- [ ] **Step 2 (green):** in `Intercept`, after the session is known (including the recovery pass-through's `LoadForRenewal` result) and before `RotateWithGrace`: `exceeded, err := r.limiter.Exceeded(ctx, key)`; if `exceeded || err != nil`, return `ErrRenewalThrottled` (log a limiter error at warning, behind fixed text); then `r.limiter.RecordFailure(context.WithoutCancel(ctx), key)` for every attempt that reaches rotation, success or refusal, logging an error at warning. Add the status row. Run `go test -race -count=1 ./httpsec/...`.
- [ ] **Step 3 (godoc):**
  - `EnableSessionRenewal`: the per-family limit, its default and override, that it counts renewals rather than failures and is keyed by family so it cannot throttle other users; and the multi-tab advice: clients sharing one credential across tabs should serialise renewals, because a second renewal inside the window re-rotates and knocks out the successor the first tab already holds, and that tab's next request is then reuse.
  - `WithTouchInterval` (`session/options.go`): recommend an interval, for example one minute, for deployments with busy clients, and restate the bound it costs (idle expiry up to one interval early).
  Run `go doc ./httpsec EnableSessionRenewal` and `go doc ./session WithTouchInterval`.
- [ ] **Step 4: commit** `feat(httpsec): throttle renewals per family`.

---

### Task 9.11: Gate for group 9 (main session)

- [ ] Dispatch a fresh Opus reviewer that edits nothing, over the group's commits, against every requirement named in Tasks 9.1–9.10, design decision 14 and the design section "Pull request review (2026-10-21)". Findings go back to a fresh dispatch of the owning lane.
- [ ] Run `make check` on go1.27.3 or later, and `openspec validate first-party-sessions --strict`. Keep both outputs; push the branch to update the pull request.
