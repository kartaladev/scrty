# close-security-gaps — session handoff (2026-11-02, second session)

Local working note: **untracked, never commit it**. Stage OpenSpec files by name, never the whole change
directory. Continue with `/opsx:apply close-security-gaps`; read this, then `tasks.md`, `design.md` and `plans.md`.

## State

- `feat/close-security-gaps` at `97189b2`, clean, **not pushed**. **73/92 ticked** (DPoP 8.1–8.12 merged and
  ticked this session).
- The DPoP lane was reviewed and fixed over four rounds. Its decisions are in D8: the consumer-supplied
  `NonceCipher` (the user's choice); one nonce per replica; a request with a valid nonce never waits on a seal;
  a `NonceLifetime` floor of 10 s; the nonce round trip and dependency failures are not charged; guards carry
  the challenge; the internal `bindingVerifiers` set.
- The feature branch also carries `8805626`, the `session-signals` proposal. It is identical to PR #44, so
  whichever merges second applies cleanly.

## In flight: CSRF lane (5.5–5.7)

- Worktree `.claude/worktrees/csrf-h7`, branch `lane/csrf-h7`, at `fdba8d3`. Clean, with the feature branch
  merged in up to `97189b2`.
- `8db556a` fixed the HIGH bypass and the MEDIUM back-channel `*` defect, plus escaped-path exemptions, token
  publishing and the build-time token flag. The Opus review was **clean**.
- `fdba8d3` is the follow-up: encoded back-channel prefixes, encoded dot segments in fixed exemption segments,
  and token-issuance rows for magic link and passkey. Every module is green serially. Its Sonnet review was
  **stopped by the pause before it reported**.
- **Next:**
  1. Re-run the Sonnet review of `git diff HEAD~1 HEAD` in that worktree. It should check the `RawPath`
     escaping check in `backchannelExemption`, and whether double encoding (`%252e`) can widen a fixed segment.
  2. Merge the feature branch into the lane, run every module serially, then `git merge --ff-only lane/csrf-h7`
     in the main tree.
  3. Tick 5.5–5.7.

## Then

- Group 9 (mTLS binding; D9), group 12 (automation challenge; D15), group 11 (security events; D13). All three
  touch login and the issuing endpoints, so run them one after another, or in worktrees with care.
- Group 14 last: 14.1 every module with the race detector, 14.2 `govulncheck`/`gofmt`/`vet`, 14.3 a
  whole-branch review.

## Other changes

- **`session-signals`:** proposal only, at PR #44 (`docs/session-signals-proposal`, worktree
  `.claude/worktrees/session-signals-pr`). Lands after this change and before `release-readiness` tags.
  Specs and design are next (`/opsx:continue session-signals`); the fiber v3 streaming fit is the first
  design question.
- **`release-readiness`** fails `openspec validate`, independent of this session's work. Its `authentication`
  MODIFIED block omits the scenarios "Key source outage", "Caller leaves during verification" and "Caller leaves
  with a cause". Fix before archive.

## Worktrees

- Merged and removable: `agent-a46691d6e8d05ca65` (DPoP), `agent-a0a2d5a51548672b4`, `agent-a61918197adf13ef4`,
  and `agent-af49ead70dcfa5854` (locked; remove with `git worktree remove -f -f`).
- Live: `csrf-h7` and `session-signals-pr`.

## Small follow-ups not yet scheduled

- gorm session listing: a statement test that the listing `SELECT` omits `csrf_token` and `external_id_token`.
- Conformance has no scenario that sends a CSRF token through gin or fiber.

## Rules learned

- Run every module's suite **serially** before each merge. Parallel runs cause false failures in the database,
  limiter and `outbound` timing tests.
- Worktree agents start at an old base, so merge the feature branch into a lane before dispatching to it.
- A stopped reviewer may leave a mutation behind. Check `git status` in its worktree and edit it back.
