# Handoff: restructure-layout, paused 2026-10-31

Paused at the user's request, between dispatches. Nothing is pushed: the user chose to push once, after group 16, so every gate's push/CI step (11.5, 12.3, 13.6, 14.3, 15.6, 16.4) is still open even where its review and local checks are done.

## On the branch (`refactor/restructure-layout`, local commits)

| Group | State | Commit |
|---|---|---|
| 11 (D15 renames) | done; review clean; evidence 0 unaccounted | `ad5625b` |
| 12 (D16 storekit, `WithUserRoles` godoc) | done; review clean | `00fa48f` |
| 15 (D18 verifier and generator require iss/aud; empty refused) | done; V1–V3 reviewed clean; evidence 0 unaccounted | `5b5683d` (artifacts `f77110b`) |

## Saved in worktrees, not yet on the branch

Each lane is one WIP commit on its worktree branch, based on `ad5625b`. Its files are disjoint from groups 12 and 15, so it should cherry-pick cleanly.

| Lane | Worktree branch / commit | Tasks | Next step |
|---|---|---|---|
| U (D19) | `worktree-agent-a94e6d0745c5f754b` / `62b60a0` | 13.1–13.5 | U1+U2 reviewed (findings folded as 13.5). Run **one Opus review of U3's delta** (caller cancellation, godoc). Then fix the `ErrUnavailable` and `ErrAuthenticationFailed` godoc in `authenticate/authenticate.go`, which should now exclude a load the caller's own cancellation ended. Then cherry-pick, and add an `added` row for `authenticate.ErrUnavailable` and `test` rows for any renamed cases. Commit with the 13.x ticks. |
| L (D20) | `worktree-agent-aa12c77171f3d5a11` / `9472673` | 16.1–16.2 | Not reviewed yet: the plan has one Opus review for L1–L3. Then **L3 (16.3)**: widen `ratelimit.Limiter` to embed `Charger`, collapse the transitional `unavailable.Limiter` and the `charger_mock_test.go`/`backendDouble` in `internal/unavailable`, regenerate the mocks, drop the transitional "skip non-Charger" guards, and switch `recovery.Codes` to Charge/Refund. **Base L3 on the L worktree.** |

Two worktrees can be removed once checked: `agent-adb0929a3a7ee8f78` (S1, applied in `00fa48f`) and `agent-acfa326e788e081cf` (V lane, applied in `5b5683d`). Each still holds its uncommitted copy of the applied diff.

## Not started

- **K1 (14.1–14.2), `WithAPIKeyOwners`.** Starts once the U lane is on the branch, because it returns `ErrUnavailable`.
- **17.1.** Update the old names that group 11's sweep reported in active changes' artifacts, and the artifacts of `idiomatic-api-shape`, `key-port-context` and `trusted-proxy-client-ip`.
- **17.2.** Push, CI green including the Docker suites, then one Opus whole-branch review.

## Artifact updates owed (main session)

- **`plans.md` Task 51 departs from what L2 built.** Update the task to say:
  - Redis keeps its existing no-trim rule (the newest-limit cap only), which the "shorter-window instance does not disarm a longer one" case requires;
  - the PG refund uses `array_position` plus slicing, not `array_remove`;
  - the PG charge is `INSERT … ON CONFLICT DO UPDATE … WHERE`, run in its own READ COMMITTED transaction through a new `Runner.QueryRowReadCommitted`;
  - the statements live in `internal/pgschema/ratelimit.go`.
- **D20 should state** the decorator's refund routing: the breaker state at refund time decides the store, and a refund never removes more than one failure.
- **Notes from the V-lane review**, all low severity:
  - `NewVerifier`'s and `NewGenerator`'s failure lists omit the empty-value refusal;
  - no test pins that the empty-value error names the waiver;
  - whitespace-only claims are accepted. Record this as a known limit in D18's Risks, or refuse it.
- **D19 log level for a hang-up:** it is still error-level `reason=user-loader` with `cancelled=true`. A debug-level record under its own key would keep hang-ups from crowding out real outage records in the sampler. This is the user's call.
- **Notes from the U-lane review:**
  - two older recovery test comments say "an outage is not counted against the source", while `countsAgainstRecoverySource` does count unmarked outages;
  - wording only, for the whole-branch review.

## Known flake

`test.TestPGLimiter_HeldRow/sqlstore/record_gives_up_on_a_held_row_within_its_timeout` failed once under the full parallel `make check` (it waits for PostgreSQL to drop a session waiting on a lock). It passed 5 of 5 alone. `UNREPRODUCED`; L2 has since turned that test into a table.

## Resume

`/opsx:apply restructure-layout`. The next dispatches in order:
1. U3 review, then cherry-pick the U lane;
2. L1–L2 review, in parallel with K1;
3. L3;
4. 17.1;
5. the single push and the 17.2 gate.
