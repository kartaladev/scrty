# Handoff: `oidc-provider` implementation

Working notes for resuming `/opsx:apply oidc-provider` in a new session. This is not an OpenSpec artifact, and it decides nothing the artifacts do not. Read it, carry on, fold anything still open into the artifacts, and delete this file before archive.

## Where we stopped

The user asked to stop when in-flight work finished, in order to reset the session. No new dispatch was started after that.

- **Progress:** 35 of 79 tasks ticked on `feat/oidc-provider`. Groups 1 to 6 and task 12.1 and 12.2 are done, reviewed and committed.
- **Remaining:** 7.1 to 7.10, 8.1 to 8.7, 9.1 to 9.6, 10.1, 10.2, 11.1 to 11.8, 12.3 to 12.6, 13.1, 14.1 to 14.3, 15.1 to 15.3. `openspec instructions apply --change oidc-provider --json` is the source of truth.
- **Nothing is pushed.** `feat/oidc-provider` and its lane branches exist only on this machine. The user has not asked for a push.

## Branches

| Branch | Holds | State |
|---|---|---|
| `feat/oidc-provider` | everything ticked | based on `main` at `b18db5c` (#70) |
| `feat/oidc-provider-g` | tasks 7.1, 7.2, one commit (`638a1e7`) on top of `fa5667a` | verified, **not reviewed, not merged, not ticked** |
| `feat/oidc-provider-pgx` | task 12.3, one commit (`82a88cc`) on top of `4f4f784` | reviewed, one test gap, **not merged, not ticked** |
| `feat/oidc-provider-gorm` | task 12.4, one commit (`fbf534f`) on top of `4f4f784` | reviewed, two defects open, **not merged, not ticked** |
| `feat/session-signals` | the `session-signals` change, in `.claude/worktrees/session-signals` | owned by the `session-signal` session |

**Do not rewrite `feat/oidc-provider`.** `feat/session-signals` was branched from it at `c257bb2`, and rebases onto it. It merges to `main` only after `oidc-provider` does.

The shared checkout stays on `feat/pre-release-api-fixes`, with other uncommitted work. Do not touch it. Work from a worktree of `feat/oidc-provider`.

## Lanes not yet merged

Each is committed on its own branch, passed verification, and is **not ticked**. None has reached `feat/oidc-provider`. All three were built on commits now behind its tip, and they should cherry-pick cleanly, since each touches its own files.

**`feat/oidc-provider-pgx` (`82a88cc`), task 12.3: reviewed, no code defect.** One test gap to fold first: nothing runs a lineage statement inside a caller's transaction, so skipping `boundTo` when `ambient` is true in `store/pgxstore/tx.go:92` passes the suite. The reviewer's proof is `TestProbe_AmbientOneConn`. Also check `sqlstore` and `gormstore` for the same gap, as the review looked only at `pgxstore`.

**`feat/oidc-provider-gorm`, task 12.4: reviewed, two defects `REPRODUCED`, not fixed.** T7 and the connection-level rewrite held: on one `*gorm.DB`, prepared and not, no statement crossed tables.
1. **Panic under `PrepareStmt: true` when a prepare fails.** GORM's `QueryRowContext` returns an empty `sql.Row`, and `Scan` panics. Triggers: a cancelled context on a first prepare, a missing table, a caller's aborted transaction. Sites: `store/gormstore/oidcprovider_stores.go:76`, `oidcprovider_grants.go:164`, and `session.go:912,942`. The `session.go` ones predate this change, and `:942` is proven; lineages inherit them. `TestReview_QueryRowFailureIsAnError/prepared=true/*` fails with `invalid memory address or nil pointer dereference`. `assertFailedUnit`'s trigger fires after the prepare, so it misses this.
2. **`DefaultContextTimeout` ignored on direct pool calls.** `oidcprovider_stores.go:39`, with `:76`, `:157`, `:371` and `oidcprovider_grants.go:164,204` on the same path; only `exec` was run. `TestReview_ConsumerStatementTimeout/provider_store_through_the_connection_pool`: `"5.970278417s" is not less than "4s"`. Fix it or document the limit.
3. **A mutant survived:** dropping the rewrite in `PrepareContext` (`oidcprovider_lineage.go:68`). By reading, nothing calls it, so test it or remove it.

Proofs and working fixes, if the scratchpad still exists, are under `/private/tmp/claude-501/-Users-zakyalvan-Documents-RND-scrty/62386f90-96ed-4581-90a0-649b785e6a93/scratchpad`: `review-gorm/test/gormstore/review_proof_test.go`, `review-gorm-fix/`, and `review-pgx/test/pgxstore/zz_probe_test.go`. If they are gone, the descriptions above are enough to rewrite them. Those proofs are read-only references, not to be copied in.

**`feat/oidc-provider-g` (`638a1e7`), tasks 7.1 and 7.2: verified with `-race -count=5`, not reviewed.** H2, H3 and H5 were each seen failing, so the design's `UNREPRODUCED` labels on them can be changed to `REPRODUCED` once this merges. Its open items are under "What each later dispatch must carry".

## How the work has been run

Each step is a dispatch of a fresh agent, in its own worktree on its own branch off `feat/oidc-provider`:

1. **Dispatch.** Name the model and a one-line reason, as `.claude/rules/subagent-delegation.md` requires. Agents commit nothing, edit nothing under `openspec/`, and report red-step output.
2. **Verify in the main session.** Run tests with `-race`, `go vet`, `gofmt -l`, and `golangci-lint`, including lint on `test/` packages, which agents have skipped. Use `head`, never `tail -1`, on `openspec validate`, whose last line hides failures.
3. **Review.** A fresh Opus reviewer gets the code and the requirements, not the lane's conclusions, and must prove defects by a failing test in a scratch copy. Tell it to leave proof files in place and name their paths. These reviews have found real bugs every time, so do not skip them.
4. **Fold findings** with a fresh dispatch: Sonnet when the finding states the fix, Opus when it needs concurrency or design judgement. Re-review a fix that changes a concurrency mechanism.
5. **Commit in the lane, cherry-pick to `feat/oidc-provider`, then record.** Tick tasks, and write what the lane settled into `design.md`, specs and `plans.md`. Commit as one docs commit. If `tasks.md` content changed, run `/superpowers:writing-plans`. Remove the lane's worktree and branch.

Details that have caught us:

- Commit messages end with `Co-Authored-By`, and never a `Claude-Session` trailer or session link, as the user's `CLAUDE.md` says. The same goes for PR descriptions.
- `go.work.sum` gains a `brotli` line whenever the tools run. Never stage it. Stage by path.
- `gopls` diagnostics in the session about scratchpad worktrees ("not included in your workspace", "undefined") are noise. Trust `go build` and `go test`.
- `test/`, `store/sqlstore`, `store/pgxstore` and `store/gormstore` are nested modules. Docker is available. Durable tests run on the default image and with `SCRTY_TEST_POSTGRES_IMAGE=postgres:15.19-alpine`.
- The plan assigned Opus to `pgxstore` and `gormstore`. They were run on Sonnet, with Opus reviews, because `internal/pgschema` already holds the reviewed SQL.
- Tell agents to back up into the session's scratchpad, not `/tmp`, because `/tmp/x` caught stray copies twice.

## Next steps, in order

1. **Tell `session-signal` your name** (see "Coordination"). Ask whether it has reached dispatch C5 or committed its `ResponseWriter` change.
2. **Worktree.** Add one for `feat/oidc-provider` under the new session's scratchpad. All of this session's worktrees were removed, and only branches remain. Run `/golang-how-to` before Go work, as `.claude/rules/golang-skills.md` requires.
3. **Fix `gormstore`'s findings:** Sonnet, since the review states them, with an Opus re-review because `session.go` is existing code. Add the `pgxstore` test gap, and check `sqlstore`'s. These are separate lanes, as the files do not overlap.
4. **Merge 12.3 and 12.4:** cherry-pick both, tick them, and record in `design.md` what the adapters settled: `lineagePool` for GORM, and statements on `Statement.ConnPool` because GORM's `Exec` treats `@>` as a named argument. Then delete the two branches.
5. **Review `feat/oidc-provider-g`** with a fresh Opus reviewer, and take the user's decision on a replay after the sweep (below). Fold findings, cherry-pick, tick 7.1 and 7.2.
6. **Continue group 7 from 7.3.** The plan's dispatches are 7.3 to 7.4 (Sonnet), 7.5 (Opus), 7.6 to 7.8 (Opus), 7.9 to 7.10 (Sonnet). The minting ones now need a signing-order decision, so judge whether Sonnet still fits. `plans.md`'s "Delegation lanes" table gives the rest of the order. Task 12.5 can run beside group 7, and 12.6 needs the exchange.

## What each later dispatch must carry

These were found while building earlier groups. Each is also in `design.md` or `plans.md` unless marked otherwise, but they are easy to miss.

**Group 7 (from the lane's report on 7.1 and 7.2; not yet in the artifacts).**
- **Decide:** a replay after the sweep revokes nothing with the default stores (`REPRODUCED` by a throwaway test: "a replay 5 minutes after the exchange revokes", `Should be true`). `sweepingCodeTokens` forgets a spent code once it is past expiry, so detection lasts only until the next sweep. Either narrow the spec's "a replay revokes", or retain spent codes longer. Durable stores need the same answer in 12.5.
- **7.3 and 7.4:** mint in `exchangeCode` at the `res :=` line, from `grant`, `record.Nonce`, `rc` and `r.Binding`. `TokenType` and `ExpiresIn` are empty until then.
- **7.3 and 7.4, decide:** signing failures come after both writes, so a failure burns the code and leaves a live row and lineage nobody holds. Sign before the spend, or use `CreateIssuing`'s shape.
- **7.3 and 7.4:** `resource` must be judged before the consume, beside `codeBindingsHold`, so `invalid_target` leaves the code unspent. `ID token auth_time` (H3) can only be asserted in 7.3.
- **7.5:** add refresh-refused assertions to `TestProvider_CodeReplay`'s `racing_commit` and `after_exchange`. Replace the temporary `unsupported_grant_type` answer for a refresh client. Settle `Provider.lineages(rc)`, which builds a manager per call, against where the reuse observer goes and that `Sessions` holds the lock serialising `Rotate`.
- **7.5:** the refresh reuse race is proved over the in-memory lineage store here, and over each adapter in 12.6 (`store-conformance`).
- **7.6:** `AccessTokenStore.Revoke` answers `ErrNotFound` for a missing token, which the provider maps to success (RFC 7009).
- **7.8:** `SignInsEnded` picks its selector from the report's fields, not by listing causes, and a nil `KeptFamily` spares nothing (`plans.md`). The provider deletes browser sessions through `DeleteBySignIn`, because `EndSignIns` does not. `EndDeleted` ends the family's grants.
- **Worth a decision:** `codeTokens()` builds a manager per call, and lane G needs the same, so a field set in `New` would be tidier. `doc.go` still needs the group's godoc.

**Group 8.**
- **8.1:** the end-reporting check runs in a `c.wire` step, after wiring. Compare `DPoPEnabled()` with `EnableDPoP`, and `AssertionTokenEndpoint()` with the chain's real token URL. Check `SignsWith` only for a `*signingkey.Keys`, and let a wrapped provider build.
- **8.5:** `SignIn` cannot express a session owing MFA or recoverable only by a late renewal, so the chain must refuse those. `ResumeInput.IdleTimeout` and `AuthorizeInput.IdleTimeout` come from the chain's manager.

**Group 9.**
- `RequireBinding: BindingDPoP` is not enforced in `Token`. Only `Token` knows the client, so a required client with no proof needs a check before the consume, or `invalid_dpop_proof` cannot leave the code unspent.
- `TokenRequest` holds `Form` and `Query` as well as `Credentials.Form` and `Credentials.Query`, which take the request's when unset. 9.1 may want one source.
- `issuingBinding(ctx, ex.dpop(), ex.certBinding(), ex.Request, ex.bearerCredential)` in `httpsec/dpop.go` is D8's entry point.
- 9.6's CORS needs its provider-registered exclusion, since a policy covers the whole chain.

**Group 11.**
- Lane H4 edits `httpsec/logout.go`, `password_change.go`, `recovery.go` and `passkey_manage.go`, which `session-signals`' dispatch C5 edits too. They must not run together. See "Coordination".
- **Not in a task yet:** `authenticate/passkey`'s `manage.go` (lines 163, 197) and `clone.go:168`, and `authenticate/mfa/reset.go:249`, accept a raw `session.Store`, which ends sessions with no report `ReportsEndsTo` can see. Sub-decision 4's grant ports cover MFA reset and clone detection. H4 must check the `manage.go` path.

**Group 12.**
- **12.5:** code records sweep a minute past expiry, and `keepRevoked` is a minute past the longest code lifetime.
- **12.6:** could repeat `no_credential_in_any_column` through a real issue, because the adapters' tests store records directly.

**Group 15 or the whole-branch review.**
- `release-readiness`'s gate must name the conformance job.
- Not in a task: `WithIDGenerator` has no provider option, and the design calls the handle parameter "replaceable" while only the constant `HandleParam` exists. Check both against `library-design.md` rule 2.
- Known risk, recorded in the design: a code issued just as its sign-in ends. `Touch` narrows it, and it is not closed.

## Coordination with `session-signals`

The `session-signal` session builds that change on `feat/session-signals`, committing locally, and agreed to message this session:

- before its dispatch C5, which shares files with group 11;
- when its `ResponseWriter` change is committed, because group 8 writes new `httpsec` tests;
- before changing `session/end_observer.go` or the shared `sessions` spec text.

What was agreed:

- It adds `(*Sessions).AddEndObserver`, and `ReportsEndsTo` answers yes for an added observer, so group 8's check must run after wiring.
- It adds `session.EndLogout` and `(*Sessions).Logout` on its own branch, for a chain logout that today reports `EndFamilyRevoked` with no user. Its own message said the user approved that, which this session could not confirm.
- Because `oidc-provider` lands first, it drops the shared `sessions` requirements at its rebase and uses a `MODIFIED` delta for its logout line. Our spec stays without that line until then.

**A new session has a new address.** Use `ListAgents` to find `session-signal`, and tell it this session's new name, because the agreed messages will otherwise arrive at a session that no longer exists.

## Decisions the user has made

- PR #70's open questions, all as recommended: `PKCEOrNonce` (R1), a provider browser session with SSO in v1 (R2), logout asking unless a hint names the browser's own sign-in (R3), UserInfo requiring the issuer (R4), and the logout plans in the gate (R5).
- `oidc-provider` must support DPoP.
- `session-signals` runs in parallel, stacked on `feat/oidc-provider` (option 2), so it merges after.

## Still unverified

- Whether official certification accepts R1's expected failure.
- How each conformance module judges a real provider. Task 1.2 ran the suite against a stand-in, at `475e8bf`; 14.1 and 14.2 run it for real.
- CI time for the added logout plans.

## Scratch

The session's scratchpad, which a new session may not be able to rely on, holds only disposable material: review proofs, scripts and the conformance clone. Everything worth keeping is in a commit or in this file.

## Update: second session, stopped at the usage limit

This supersedes "Next steps" 1 to 5 and "Lanes not yet merged" where they differ.

- **Told `session-signal`** this session's name, `oidc-provider`. A later session must do so again. It is not at C5, and its `ResponseWriter` change is uncommitted: it adds `Stream`, so group 8's test doubles need that method after the rebase. It adds an `EndLogout` row to `TestProvider_EndSignIn` when it rebases.
- **Merged to this branch:** `pgxstore`'s commit, with its ambient transaction test, and `sqlstore`'s same test (the gap existed there). Both reviewed by mutant, every row red. **Task 12.3 is not ticked yet.** Tick it with 12.4.
- **`feat/oidc-provider-gorm`, at `62d549f`:** rebased on this branch, all four findings fixed, verified in the main session on the default image only. **Not re-reviewed, not merged, not ticked.** Next: an Opus re-review of the fix commit, a run with `SCRTY_TEST_POSTGRES_IMAGE=postgres:15.19-alpine`, a cherry-pick of both commits, then tick 12.3 and 12.4 and record `lineagePool` and the timeout rule in `design.md`. Check that `scanRow` stays on gorm's processor path, and that each many-grant statement is bounded separately.
- **`feat/oidc-provider-g`: review interrupted, with no final report.** The Opus reviewer was stopped during its mutation pass. Its interim message said its proof tests fail on the commit and pass with candidate fixes, so **expect `REPRODUCED` findings, which this session has not read or checked.** Its proofs are in `/private/tmp/claude-501/-Users-zakyalvan-Documents-RND-scrty/bff13c6d-670e-4235-af08-e711bde90918/scratchpad/review-g/oidcprovider/review_proof_test.go`. Run a fresh review, or read that file first, and do not merge the lane before then.
- **Replay after the sweep: not yet put to the user.** Researched on 2026-11-04. RFC 6749 §4.1.2 says deny, and "SHOULD revoke (when possible)". RFC 9700 §4.2.4 says SHOULD revoke. node-oidc-provider refuses an expired code before its consumed check, and fosite treats a code it cannot find as plain `invalid_grant` with nothing revoked, so neither revokes once a code is expired or gone. The recommendation to offer is to narrow the spec: revoke while the record is held, at least until a minute past the code's expiry. Longer retention stores more, and for a public client lets whoever holds a leaked code end the grant for longer.
- Session worktrees `oidc`, `wt-gorm` and `wt-g` are under `/private/tmp/claude-501/-Users-zakyalvan-Documents-RND-scrty/bff13c6d-670e-4235-af08-e711bde90918/scratchpad`. If they are gone, the branches hold everything; run `git worktree prune`.
