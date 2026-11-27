# Design

## Context

See proposal.md, Why, for the measurements.

**The shared child helper.** `limiterPortErrInChild(t, envName, marker, row)` in `httpsec/mfa_enrol_porterr_test.go`:
- marks its subtest parallel;
- re-runs the test binary for one row under a one-minute budget;
- requires the child to exit 0 and print `marker+row`.

Its godoc carries the contract for callers. The archived `parallel-port-error-children` sets out why this is safe beside the sequential rows that swap `slog.Default()`: a parallel row starts only after its parent's body returns.

**The three copies.** `throttlePortErrInChild` (`httpsec/throttle_porterr_test.go`), `redemptionPortErrInChild` (`httpsec/redemption_porterr_test.go`) and `backchannelPortErrInChild` (`httpsec/oidc_backchannel_porterr_test.go`) each take only `(t, row)`.
- Each bakes in its own row environment variable and marker.
- The bodies match the helper's, except that they have no `t.Parallel()`, and that the redemption and backchannel copies quote 12 lines of a failing child's output against the helper's 8.
- Their callers, found by grep (gopls confirms them during implementation): `generator_porterr_test.go:267`, `redemption_porterr_test.go:377` and `:639`, `throttle_porterr_test.go:241`, `oidc_backchannel_porterr_test.go:263`.

**The fixture hash.** `e2eEncoder(t)` (`httpsec/integration_test.go:1629`) builds Argon2id at the floor the encoder accepts: 19456 KiB, 2 iterations, 1 thread. Two fixtures were found before implementation that call `e2eEncoder(t).Encode(e2ePassword)` each time they are built: `newRecoveryHarness` (`httpsec/helpers_test.go:3593`) and `newPwlDeployment` (`httpsec/passkey_login_test.go:181`). Task 2.2's gopls sweep found four more with the same call: `e2eDeployment.wireUsers`, `newIssuingBaseOver`, `newEventsWorldOf` and `newAuditWorld`. Measurements lists all six. Other `e2eEncoder` callers pass the encoder to an authenticator, so it is used to verify, and stays as it is.

**The rehash rig.** `newRehashRig` (`httpsec/login_rehash_test.go:101`):
- stores a hash at `rehashOldMemory` (19 MiB, 2 iterations);
- verifies a login against it;
- rewrites it with an encoder at `rehashNewMemory` (46 MiB, 2 iterations).

`NeedsUpgrade` reports an upgrade only when the stored parameters are below the encoder's (`authenticate/password/argon2id.go`). So the tests need new memory strictly above old, and nothing more.

**The encoder's floor.** Construction refuses less than 46 MiB at 1 iteration, or less than 19 MiB at 2 or more iterations (`authenticate/password/argon2id.go`). No real encoder can be cheaper than `e2eEncoder`.

## Goals / Non-Goals

**Goals:**
- Every child-process row in `httpsec` runs through the one parallel helper.
- A fixture's stored hash of `e2ePassword` is derived at most once per test process.
- `go test -race -count=1 ./httpsec` runs in at most 300 s on the maintainer's machine and on a 4-CPU CI runner.

**Non-Goals:**
- Replacing the real encoder with `MockEncoder` in any row. Every login in these fixtures still verifies a real Argon2id hash.
- Changing the child budget, the helper's arguments to the child, or row selection.
- Any library, `Makefile` or CI change.

## Decisions

### 1. The copies become thin wrappers over the shared helper

- **What.** Each copy keeps its name and its `(t, row)` signature, so no caller changes. Its body becomes a single call: `limiterPortErrInChild(t, <its env var>, <its marker>, row)`.
- **The excerpt.** The helper's excerpt of a failing child's output rises from 8 lines to 12, the larger of the two counts in use. No row then reports less on failure than it does today.
- **Why not delete the wrappers and change the callers.** Keeping each name keeps the diff to the three files that own them, and each caller still reads as its own file's helper. Inlining them can come later and gains nothing now.
- **The contract applies to the callers.** Calling the helper makes these rows parallel, under the godoc contract:
  - call it once per subtest;
  - from a test with no `t.Setenv` or `t.Chdir` ancestor;
  - a caller that must act after its rows finish wraps them in `t.Run("group", …)`.

  Implementation checks each caller against it, with gopls references and a read of each enclosing function's tail.
- **Default:** concurrency up to `-parallel`. **Override:** `-parallel N`, as in the archived change. This is test code with no library consumer, so there is no other override point.
- **Alternatives considered:**
  - **Adding `t.Parallel()` to each copy.** It fixes the speed but keeps four copies of the guard, and the next fix to one would miss the others, as this one did.
  - **Deleting the copies.** It touches five call sites to save three one-line wrappers.

### 2. One fixture hash per test process

- **What.** A package-level `e2eHash(t)` in `httpsec/integration_test.go` returns a hash of `e2ePassword` from `e2eEncoder`'s parameters, computed once with `sync.OnceValues`. `newRecoveryHarness` and `newPwlDeployment` use it in place of `e2eEncoder(t).Encode(e2ePassword)`.
- **Why it is safe.**
  - An Argon2id hash is a string that embeds its own salt and parameters. Verifying it reads it and never changes it, so concurrent tests can share it.
  - The fixtures only need some valid hash of `e2ePassword` to log in. None of them asserts on the hash's salt or bytes. Implementation checks each fixture before switching it.
- **Not switched:**
  - a test that needs distinct hashes, a salt it controls, or a hash the encoder later rewrites;
  - the rehash rig, which stores and rewrites its own hash (decision 3).

  An `e2eEncoder` caller that only passes the encoder to an authenticator is also left as it is.
- **The error path.** `e2eHash` gets an error from the shared `OnceValues` function and fails the calling test with it, through `require.NoError`. A panic in the derivation reaches every caller, as `sync.OnceValues` documents.
- **Override:** none. Test fixture.
- **Alternatives considered:**
  - **`MockEncoder` for rows whose subject is not the password.** It is cheaper still, but those rows would stop verifying a real hash, and the boundary between rows that care and rows that do not would need judging row by row. It stays a non-goal unless measurement shows this change falls short.
  - **A precomputed hash literal in the source.** Same effect, but it bakes the encoder's parameter encoding into the test file, and goes stale silently if the encoder's format changes.

### 3. The rehash rig's target drops to 20 MiB

- **What.** `rehashNewMemory` changes from `46 * 1024` to `20 * 1024`, with 2 iterations kept. The stored hash stays at the 19 MiB floor, so an upgrade still exists, and every assertion that names the constant follows it.
- **The sentinel stays.** The literal `argon2id$47104$2$a$b-changed-meanwhile` (`httpsec/login_rehash_test.go`) is a record that changes during the test and is never verified. It is left as it is unless implementation finds an assertion that ties it to `rehashNewMemory`.
- **Override:** none. Test fixture.

## Failure modes

| Failure | State | What is seen |
|---|---|---|
| A caller of a former copy breaks the helper's contract: post-loop code, a `t.Setenv`/`t.Chdir` ancestor, or a second call | Tested: task 1 checks each caller before the switch | A second call panics. The other two are accepted in the archived design's terms. Implementation reports any caller that breaks the contract, and stops. |
| A former copy's failure output shrinks | Handled by decision 1 | The helper quotes 12 lines. |
| An induced child failure or wrong marker under a former copy is no longer caught | Tested: task 1 induces both in a `SourceThrottle` row | The row fails, naming itself. |
| A test relied on its fixture hash being fresh, with a distinct salt or bytes | Tested: task 2 checks each switched fixture; the full package run is the regression check | A test that compared hashes fails. That fixture is reverted to its own hash and the reason recorded. |
| The one-time derivation fails | Handled: `require.NoError` in every caller | Every test using `e2eHash` fails with the encoder's error. |
| The rehash tests lose their upgrade case at 20 MiB | Tested: the rehash tests, which assert an upgrade from 19 MiB and none when current | A failing assertion. 20 MiB at 2 iterations is above the floor, so construction accepts it. |
| The package still exceeds 300 s on CI | Tested: task 4 measures it | Implementation stops and reports, and the goal is not relaxed without the maintainer's decision. |

## Risks / Trade-offs

- **The gain on CI depends on cores.** Decision 1 divides about 40–65 s of serial child time by `-parallel`. Decisions 2 and 3 remove about one derivation per affected row, whatever the core count. Neither is measured before implementation. → Task 4 measures both locally and on CI.
- **Shared state in tests.** `e2eHash` is the package's first process-wide fixture value. → It is immutable, computed once, and read-only to callers, so sharing it is safe.

## Correction to the archived `parallel-port-error-children`

That change's Context says every child-process row goes through `limiterPortErrInChild`, and its Measurements count 236 rows in 26 tests. Its audit and review missed the three copies, because each was taken for a thin wrapper. The archive is left as it was written. This design records the correction, and its Measurements give the new counts.

## Measurements

Taken on 2026-11-27 on the maintainer's machine (14 CPUs, Go 1.27.4), with all three decisions applied. The machine was not fully idle: the load average was about 10, mostly from a system media-analysis process. Local figures drift.

**Package, `go test -race -count=1 -timeout 300s -json ./httpsec`:**
- `Elapsed`: **134.2 s**, against 234–262 s before this change and the 300 s goal.
- Rows with a `pause` action: 9620.
- Rows that never paused: 2330 leaf rows totalling 50.8 s, against 139.5 s before. The longest are the `TestPortErrors_TokenGenerator/recovery_completion` rows, at about 0.7 s each.

**CI, manual run 46018648963 on commit `37f0333`, 4-CPU runners:**
- `httpsec` took 278.1 s on the PostgreSQL 15 / Redis 7 leg and 235.5 s on the PostgreSQL 18 / Redis 8 leg. Both are within the 300 s goal, against 335.1 s and 283.9 s in run 45031759267.
- The PostgreSQL 15 leg has 22 s of headroom. Runner speed drifts, so a later run may come closer to the goal.

**Decision 1, the copies go through the helper:**
- `TestPortErrors_SourceThrottle` alone ran in 16.2 s with 0 `pause` events before, and 5.0 s with 14 after.
- The five tests that call a former copy ran in 74.8 s before and 31.5–37.0 s after. 50 child rows now pause: SourceThrottle 14, Redemption 12, TokenGenerator 12, OIDCRedemption 6, BackchannelLinkStore 6.
- With a `t.Fatal` induced in a child row, the row fails with "the child failed:" and the child's output. With a wrong marker printed, it fails with "the child printed no line". Both edits were reverted.

**Decision 2, one fixture hash per process:**
- `TestPortErrors_RecoveryCooldown/live/Unwrap_panicking_with_nil`, run alone with a CPU profile: 1.06 s before, 0.70 s after.
- Argon2's share of that profile rose, from 19.6% to 39.4%, contrary to task 2.3's expectation. A process that runs one row still derives the shared hash once and verifies one login. So a one-row run removes the fixture's other derivations, not the Argon2 work itself. The saving across rows shows in the package figure above.
- Fixtures switched to `e2eHash`: `newRecoveryHarness`, `newPwlDeployment`, `e2eDeployment.wireUsers`, `newIssuingBaseOver`, `newEventsWorldOf` and `newAuditWorld`. Each was checked: no test compares their hash, changes the password, or rehashes, and every authenticator they wire uses `e2eEncoder`'s parameters.
- Kept: `password_outage_test.go`, which hashes a different password; the `example_*` tests; and the rehash rig.

**Decision 3, the rehash target:**
- At `rehashNewMemory = 19 * 1024`, the upgrade cases of `TestLogin_Rehash*` and every `form_login` row of `TestPortErrors_RehashWrite` fail. At `20 * 1024`, they pass.
- `TestPortErrors_RehashWrite` wall time: 17.7 s before, 11.6 s after.

## Migration Plan

Test-only. Merge after CI's `test` legs pass within the goal. To roll back, revert the commit.

## References

### Decision 1, the copies become thin wrappers; Decision 2, one fixture hash per process; Decision 3, the rehash target

**Researched (accessed 2026-11-22):**
- Per-row times from `go test -race -count=1 -timeout 300s -json ./httpsec` on the maintainer's machine (14 CPUs, Go 1.27.4). Local; it drifts.
- A CPU profile and a mid-row goroutine dump of `TestPortErrors_SourceThrottle/basic,_the_IPv6_aggregate_limiter's_check/live/self-cycle_through_Unwrap()_[]error`: 1.03 s of wall time, 10 ms of CPU, the parent blocked waiting on its child in `throttlePortErrInChild`.
- A CPU profile of `TestPortErrors_RecoveryCooldown/live/Unwrap_panicking_with_nil`: about 90% of its CPU in `golang.org/x/crypto/argon2` and race instrumentation.
- A source comparison of the three copies with `limiterPortErrInChild`, and a read-only trace of the fixtures that hash, with file and line references as given under Context.

**Primary documentation:**
- [`sync.OnceValues`](https://pkg.go.dev/sync#OnceValues): "invokes f only once and returns the values returned by f. The returned function may be called concurrently". A panic repeats on every call. Checked with `go doc` on Go 1.27.4.
- [`golang.org/x/crypto/argon2`](https://pkg.go.dev/golang.org/x/crypto/argon2): `IDKey`'s memory and time costs.
- [`testing` package, "Subtests and Sub-benchmarks"](https://pkg.go.dev/testing#hdr-Subtests_and_Sub_benchmarks): when parallel subtests start.
