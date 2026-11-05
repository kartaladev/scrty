# Handoff: session-signals

Written 2026-11-05, for a fresh session. `/opsx:apply session-signals` reached its end, and group 9 then reopened it: every finding from reviewing #73, with its proof in the design's "Review of the pull request".

## Where things are

- **Branch:** `feat/session-signals`, in the worktree `.claude/worktrees/session-signals`. Work only there: the shared checkout holds other uncommitted work.
- **PR:** #73, a draft targeting `main`. It carries one commit of `oidc-provider`'s: the end observers.
- **Pushing:** SSH fails from here at times. A push goes over HTTPS: `git -c credential.helper= -c credential.helper='!gh auth git-credential' push https://github.com/kartaladev/scrty.git feat/session-signals:feat/session-signals`. The user asked for #73 to be updated at each commit that lands.
- **`go.work.sum`** shows one modified line from the Go tooling: never stage it.
- **Progress:** run `openspec instructions apply --change session-signals --json`.

## Merge order

The user let the two sessions decide. Whichever of #72 and #73 is ready first merges first. It is stated at the top of #73's description, and the user can overrule it. Neither session merges: that is the user's click.

- `oidc-provider` is told when #73 merges. It merges `main` in, and does not rebase: never touch its branch.
- If #72 lands first, rebase onto it: convert its 11.1 from `RevokeFamily` to `Logout`, and add `Request.RawQuery()` to this branch's doubles.

## Before archive

- Fold in the workflow follow-ups in `tasks.md`.
- After `oidc-provider` is archived, drop this change's copies of the shared `sessions` requirements, and change the "a sign-in logged out" line with a `MODIFIED` delta.

## Decisions the user may overrule

Made while the user was away; the design records each. `RetryableError`; the limit on a recovery failing partway; the 500 ms wait for an end report; ready-first. `authenticate.ErrUnavailable` staying 401 is settled by `http-error-propagation`, and `oidc-provider` confirmed no decision for 503 was made there.

## What this run learned

- **Reviews found real defects every round, and the ones that mattered came from real conditions.** `.claude/worktrees/.session-signals-tools/real-libraries` and `readme-harness` are how to reproduce them.
- **Run conformance at `-parallel 4` on a loaded machine.** At the default, PostgreSQL cleanup times out with no failed assertion.
- **A memory shortage can kill a background job.** It is not a test failure, and is not to be restarted without being asked.
- **Commit scripts must stop on a failed test,** and `go test -run` exits 0 when nothing matches.
- **gopls diagnostics in the session are often stale,** especially across worktrees. Trust `go build` and `go test`.
- **Scratch files go in the session's scratchpad,** never `/tmp`, which other sessions share.
