# Proposal

## Why

After `parallel-port-error-children`, the `httpsec` package runs in 234–262 s on the maintainer's machine, and in 284 s and 335 s on CI (run 45031759267). The CI goal had to be re-baselined from 300 s to 400 s. Of the local 234 s, 139.5 s are rows that still run one at a time. Measured on 2026-11-22, two causes explain most of that time, and neither is the one the earlier design assumed:

- **Three copies of the child-process helper were never made parallel.**
  - `throttlePortErrInChild`, `redemptionPortErrInChild` and `backchannelPortErrInChild` each re-implement the shared `limiterPortErrInChild` rather than call it.
  - The earlier audit and review took them for thin wrappers around it. A goroutine dump of a 1.03 s `TestPortErrors_SourceThrottle` row shows the parent blocked waiting on its child, while the row's CPU profile shows 10 ms of work.
  - Their rows still run one at a time: about 14.4 s in `SourceThrottle`, 12.4 s in `Redemption`, 6.1 s in `OIDCRedemption`, 6.2 s in `BackchannelLinkStore`, and part of `TokenGenerator`'s 32.8 s.
- **Row fixtures derive a real Argon2id hash on every row.**
  - A CPU profile of a 0.99 s `TestPortErrors_RecoveryCooldown` row spends about 90% of its time in `golang.org/x/crypto/argon2` and race instrumentation together. A later profile of the same row splits this: about 20% in argon2's own frames, and about 75% in race-detector reads that the profiler attributes to no Go caller. That those reads come from argon2's memory-bound loop is likely but unverified.
  - `newRecoveryHarness` and `newPwlDeployment` call `e2eEncoder(t).Encode(e2ePassword)` each time a row builds its harness. `e2eEncoder` is already at the cheapest parameters the encoder accepts (19 MiB, 2 iterations, 1 thread), so the cost is how many times the hash is computed, not how expensive each one is.
  - The rehash rig (`newRehashRig`) derives two or three times per row, once at 46 MiB.

Fixing both restores headroom on CI, where a 4-CPU runner gives the least concurrency, and lets the CI goal return to 300 s.

## What Changes

- **The three copied launchers go through the shared helper.**
  - `throttlePortErrInChild`, `redemptionPortErrInChild` and `backchannelPortErrInChild` call `limiterPortErrInChild` with their own row environment variable and marker, and their duplicate bodies are removed. Their rows then run concurrently, under the same contract as every other child row.
  - The helper reports the first 12 lines of a failing child's output, the larger of the two counts the copies use, so no row reports less than before.
- **Fixture hashes are derived once per test process.** The fixtures that need a stored hash of `e2ePassword` share one real Argon2id hash, computed once at `e2eEncoder`'s parameters. Logins still verify against a real hash with the real encoder.
- **The rehash rig's target cost drops from 46 MiB to 20 MiB**, still at 2 iterations. An upgrade from the 19 MiB stored hash still exists, so the rehash tests test the same rule at less cost.
- **Goal:** `go test -race -count=1 ./httpsec` runs in at most 300 s on both the maintainer's machine and a 4-CPU CI runner, which restores the original CI goal.
- **Not in scope:**
  - replacing the real encoder with a mock in any row;
  - lowering `e2eEncoder` below the encoder's floor;
  - any `Makefile`, CI or library change.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

None. This changes how a test package runs, not any specified behaviour, so the change opts out of specs (`skip_specs: true`).

## Impact

- **Test code only, in package `httpsec`:**
  - the shared helper in `httpsec/mfa_enrol_porterr_test.go`;
  - the three copied launchers in `httpsec/throttle_porterr_test.go`, `httpsec/redemption_porterr_test.go` and `httpsec/oidc_backchannel_porterr_test.go`;
  - the fixture hash, in `httpsec/integration_test.go`, and its callers in `httpsec/helpers_test.go`, `httpsec/passkey_login_test.go` and the other files that encode `e2ePassword` for setup;
  - `rehashNewMemory` in `httpsec/login_rehash_test.go`.
- **No library code, public API, dependency, `Makefile` or CI workflow change.**
- **The archived `parallel-port-error-children`** states that all child rows go through one helper, and counts 236 rows in 26 tests. Both were incomplete. This change's design records the correction, and the archive is left as it was written.

## References

### The three copied launchers; fixture hashes derived per row

**Researched (accessed 2026-11-22):**
- `go test -race -count=1 -timeout 300s -json ./httpsec` on the maintainer's machine (14 CPUs, Go 1.27.4): per-row times of rows that never paused. Local; it drifts.
- A CPU profile and a mid-row goroutine dump of one `TestPortErrors_SourceThrottle` row, and a CPU profile of one `TestPortErrors_RecoveryCooldown` row, both under `-race`.
- A source comparison of the three copied launchers with `limiterPortErrInChild`: they are identical except for the missing `t.Parallel()` and a 12-line excerpt of a failing child's output, against the helper's 8.
- CI run 45031759267: `httpsec` at 283.9 s and 335.1 s. Live; it drifts.

**Primary documentation:**
- [`golang.org/x/crypto/argon2`](https://pkg.go.dev/golang.org/x/crypto/argon2): the memory and time costs of `IDKey`, which `e2eEncoder` already sets to the encoder's floor.
- [`sync.OnceValues`](https://pkg.go.dev/sync#OnceValues): computes a value and an error once, safely for concurrent callers.
