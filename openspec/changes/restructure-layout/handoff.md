# Handoff: restructure-layout, paused 2026-10-31 after CI

84 of 86 tasks are done. Groups 11–16 are implemented, reviewed and closed: the branch was pushed at `0dd5c6a` and CI run 41181844119 passed `make check` on both matrix legs (postgres 15.19 with redis 7.4.11, postgres 18.6 with redis 8.10.2). No worktree is left. This file and the gate ticks are the only commits after `0dd5c6a`, and they are not pushed.

## Left

1. **17.1 needs the user's decision.** Its work is done: no renamed identifier appears in another active change; `idiomatic-api-shape` and `key-port-context` name the files the restructure merged into; `key-port-context` notes D18's construction rule and D19's outage answer. Its stated check, `openspec validate --all --strict`, fails on things outside this change, exactly as it does at `HEAD` before this work: `bff-resource-server` and `trusted-proxy-client-ip` have no deltas yet, and older main specs have long-requirement warnings. Non-strict, only those two changes fail. Ask whether to tick 17.1 on that basis or narrow its check.
2. **17.2:** `make check`, `evidence/check.sh all` (set `APIDIFF=$(command -v apidiff)` and `EMPTY_EXPORT=$PWD/empty.export` from `evidence/`), `openspec validate restructure-layout --strict`, push, CI green, then one Opus whole-branch review against every requirement of the change's ten deltas (`module-layout`, `test-provisioning`, `token-issuance`, `authentication`, `http-error-propagation`, `http-security-chain`, `identity-model`, `api-keys`, `rate-limiting`, `account-recovery`). Each claimed defect needs a failing test or `UNREPRODUCED`.

The evidence check was 0 unaccounted on every axis at `0dd5c6a`.

## Decisions taken this session, recorded in `design.md`

- D18: a blank issuer or audience is refused like an empty one (user).
- D19 was reworked twice:
  - a client that leaves during the user load is charged to its source only (user);
  - a hang-up is logged at debug under its own sampler key (user);
  - after a security review reproduced a throttle bypass, a lock-state oracle and a partial-outage enumeration path, an unavailable store answers exactly as a wrong password (401, Basic challenge) and is charged to the source, never the account (user);
  - a recovery's own user lookup follows the same rule;
  - a non-ASCII username the database cannot encode is "not found".
- D17: a loader answering for another user is refused and counted; a refused key keeps its last-use stamp.
- D20: the PostgreSQL charge, refund and isolation as built, and the decorator's refund routing.

Taken by the main session, which the user may overrule:
- a held account answering a slow outage faster than a free one is an accepted risk (D19 Risks);
- a recovery outage is charged to the source even under `WithRecoveryCountRefusals(false)`.

## Notes for 17.2's review

- `TestOutboundTimeout/the_bound_ends_a_call_the_consumer's_client_would_have_left_running_for_ever` (`outbound/client_test.go:596`) failed once under a local full `make check` and passed in the next runs and in CI. `UNREPRODUCED`; no lane touched `outbound`.
- `evidence/check.py` gained a `coverage` row kind, which accepts a drop only down to a recorded floor, with the reason in a comment above the row. It is used once, for `internal/unavailable` at 246/252: the two uncovered new blocks run only when a charge or refund panics.
- The untracked `openspec/changes/bff-resource-server/handoff.md` predates this session and belongs to that change; it was left alone.

## Resume

`/opsx:apply restructure-layout`. Read this file, settle 17.1 with the user, run 17.2, and delete this file once both are done.
