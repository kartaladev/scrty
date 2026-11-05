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

## Update: second session

This supersedes every section above wherever they differ. In particular the top's progress, branches, lanes and next steps are stale; "What each later dispatch must carry" is still useful for groups 8 to 12. `openspec instructions apply --change oidc-provider --json` is the source of truth for progress.

### State

- **46 of 79 tasks ticked** on `feat/oidc-provider`. Merged: groups 1 to 6, 7.1 to 7.8, 12.1 to 12.5.
- **Pushed:** the branch is on `origin`, with **draft PR #72** against `main`. Its body lists what is in and left, so update it when asked. CI skips drafts (`ci.yml`), so **no CI has run**. The commits after the last push are docs only. The user asks before each push.
- **Do not rewrite `feat/oidc-provider`**: `feat/session-signals` is stacked on it.
- **SSH** to GitHub failed for a while with `Permission denied (publickey)`, then recovered, cause unknown. Try SSH first. If it fails, ask the user: they approved one HTTPS push through `gh` once, and that does not carry over.

### Lanes committed, not merged, not ticked

**`feat/oidc-provider-g9` (`69b90db4`), task 7.9, back-channel logout: verified by its agent and by the main session's run, NOT reviewed.** Next: a fresh Opus reviewer, because it is concurrency. Open items:
- **Decide:** the spec's "SHALL follow no redirect" under a consumer's `WithOutbound(o)`. `outbound.Client` cannot be copied with a redirect cap, so such a client may follow same-origin redirects, and a final 200 counts as success. The default and `WithLogoutOutbound` are strict. A one-method addition to `outbound` would close it.
- **Worth challenging:** workers start on demand, so `Start` launches nothing and only enforces `signingkey`'s sentinels.
- **Record in `design.md`:** `WithLogoutOutbound`, `WithLogoutDeliveryTimeout`, `WithLogoutDeliveryPool`, the `busy` reason and the cap on calls left behind. R21's "up to 30 seconds" is now 20, as the hand-on never waits. R14's "a consumer delivery takes over all of it" is not what was built: it runs on the pool and within the bound. Plans 7.9's `Close(ctx)` step is superseded by its own `Start`/`Shutdown` steps.
- **Carried to group 8:** `EnableOIDCProvider`'s godoc names `Start` and `Shutdown`.
- **Carried to 7.10:** the seam is `config.logoutFailed`, called from `reportLogoutFailure`. A drop's report runs on the caller's goroutine, inside the logout, so the sink must not block. A client with no URI also takes a queue place, so a drop may report a client with no one to tell. `SignInsEnded` has a comment for its failure event.

**`feat/oidc-provider-dur` (`45eeecc9`), task 12.6, `test/oidcprovider_durable_test.go`: reviewed, findings open; no backend defect found.** It proves restart, the reuse race and the stale read on all three adapters and PostgreSQL 15 and 18. Fold first (Sonnet), then cherry-pick and tick:
- The credential scan's positive control only checks a non-secret UUID, so a blind scan passes (`REPRODUCED`). Plant a known credential and expect a hit.
- Case 8's hard-coded load count passes with the defect present if it drifts too low (`REPRODUCED`). Also assert the other tab's write landed between the rotation's read and its `Supersede`.
- Revoke asserts the lineage rows are gone but not the `op_grants.revoked` mark.
- Gaps: consents and clients use memory stores, so `op_consents` and `op_clients` stay empty, and no sealed column is exercised. Use the adapters' `NewConsentStore` and `NewClientStore`.
- Uppercase hex is unscanned; negligible, as no store writes it.

### Next, in order

1. **Worktree:** add one for `feat/oidc-provider` under the new session's scratchpad. Run `/golang-how-to`.
2. Review 7.9 (Opus), fold, cherry-pick, tick. Fold 12.6 (Sonnet), cherry-pick, tick.
3. 7.10 events (Sonnet is what the plan says; it touches every provider path, so it runs alone in that package).
4. Group 8 (Opus), then groups 9 and 10 in parallel worktrees, then group 11, then 13 to 15. Before group 11, message `session-signal` (see below).

### Decisions the user made this session

All are in `design.md`, with sources. Read R15 and R17 to R21 before touching those paths.
- **R17:** only a valid replay revokes, until at least a minute past the code's expiry.
- **R15:** a code granted one resource and exchanged with none named gets exactly that resource, with no issuer, as in RFC 9068's example. Several: `invalid_target`, code unspent.
- **R19:** no orphan sweep; a grant stays until its own deadline. `DeleteOrphans` is gone.
- **R20:** a token re-presented within 10 seconds of its rotation answers the same successor, derived under `WithRefreshSuccessorKey`, with `WithRefreshSuccessorWindow`. **Not the whole grace**: across it, a thief staying inside the grace was never caught. This is our own design, as no vendor documents it, and the PR flags it.
- **R21:** the default `email` claim comes from a username that is exactly an address, with `email_verified` always false. Email columns are the `user-email` follow-up in the Non-Goals and `config.yaml`.
- **The user wants a quicker release.** They were offered, and have not chosen, trimming the follow-up review rounds on small fixes, or dropping scope such as 11.4 or the logout plans in the conformance gate. Do neither without asking. Opus reviews of first-time security code stay, as they found real bugs every time.
- R18 (sign before the spend) follows the check-then-consume rule.

### Decided by the main session, open to the user's challenge

A store hung past the request's own deadline logs at DEBUG through `hangup.ByCaller`. A spend failure wraps fixed text. A token's own idle deadline still rules inside the window. A failed second read after rotating fails closed. The memory stores hold refresh identifiers in process memory. `refreshAttempts` is 8 and the walk's bound is 8 links, both proposed.

### Carried to later tasks

- **9.2:** `RequireBinding` is enforced in `Provider.Token`, before the spend and before a rotation, not only in `httpsec`. A marker sits in `exchange.go`.
- **11.1:** `EndSignIn` returns `([]ClientToNotify, error)`. The end-session call stays `RevokeFamily`, and `session-signals` changes it to `Logout` at its rebase.
- **13.1 and 14.1:** the conformance OP's users need a `ClaimSource` for `email_verified` true, phone and address.
- **Whole-branch review:** `httpsec`, `authenticate` and `recovery` last ran when `token/onetime` changed. `authorize.go` shares `validResource`.

### Coordination with `session-signals`

Find it with `ListAgents` and tell it this session's name; it may have been reset too, and its handoff is `openspec/changes/session-signals/handoff.md`.
- It is cleared to run dispatch C5b, which edits `httpsec/password_change.go`, `recovery.go`, `passkey_manage.go`, `passkey_register.go`, `mfa_enrol.go` and the MFA removal endpoint, on its own branch. Conflicts surface at its rebase onto this branch.
- We promised to message it before group 11 starts. Its "after each successful write" call must sit after our revoke-before-write in `password_change.go`.
- Group 8's `httpsec.ResponseWriter` test doubles gain a `Stream` method at its rebase; leave them alone here.
- **The user asked it for a draft PR, stacked on `feat/oidc-provider`. It was waiting for the user's direct confirmation, and had not created it at last report.**

### Details that caught us this session

- `golangci-lint` refuses to run in parallel, and prints "parallel golangci-lint is running" as its last line, which looks like nothing happened. Check for `0 issues.` before trusting a lint run.
- Reviewers should mutate in a scratch copy and never count a build failure or a timeout as a kill. Agents' reports of what they saw failing have been worth checking: `tail` or a filter can hide a package's `FAIL`.
- `git push` needs the branch named, as this worktree has no upstream set.
- Proofs from this session's reviews, if the scratchpad survives, are under `/private/tmp/claude-501/-Users-zakyalvan-Documents-RND-scrty/bff13c6d-670e-4235-af08-e711bde90918/scratchpad`: `review-g9` does not exist yet; `review-dur`, `review-g68b`, `review-g5c`.

## Update: third session

Supersedes the sections above where they differ. Stopped at a usage limit with agents still running, so their results are unknown: check each worktree's `git status` before trusting it. Uncommitted work there may be partial.

**47 of 79 ticked; 12.6 merged.** Nothing else from this session is on `feat/oidc-provider`. The user asked to parallelize subagents wherever possible. This session's name for `session-signal` was `oidc-provider [fc109e]`; tell it the new one.

Worktrees are under `/private/tmp/claude-501/-Users-zakyalvan-Documents-RND-scrty/06d48fe0-a406-44d7-b082-ed4b34ef1f3e/scratchpad/`. Branch stack, cherry-pick in this order: `feat/oidc-provider-g9` (`69b90db4`, 7.9), `-g10` (`3613358f`, 7.10), `-g9fix`, `-h1` (`2d086532`, 8.1 to 8.3 so far), `-h2`.

- **`lane-g9fix`, 7.9's review fold (Opus), uncommitted, not verified.** F1 `WithoutRedirects`, F2 to F4 one report mechanism, F5 report a POST cut off by `Shutdown`, F6 to F8, three mutant gaps. Re-review it: it changes a concurrency mechanism. Proofs: `review-g9/`.
- **7.10 review (Opus), report not received.** Proofs, if any: `review-g10/`. Known open: a chain's refresh reuse also emits the lineage manager's `authn_token_reuse`, three events in all.
- **`lane-h1`, the rest of 8.1 (Sonnet), uncommitted, not verified.** Accessors `BrowserSessionsEnabled`, `Issuer`, `RequiresBinding`, the blocked rows, collisions, `builtInSlots`. The certificate-binding row is scope the main session added; the user has not confirmed it.
- **8.1 to 8.3 review (Opus), report not received.** Copy: `review-h1/`.
- **`lane-h2`, 9.1 and 9.2 (Opus), uncommitted, not verified.** Reports the client-credential helper that 9.3 and 9.4 reuse.

**Seam for later `httpsec` lanes:** overwrite the lane's stub, keep its type name, implement `routes()`; see `httpsec/oidc_provider.go`. Delete `oidc_stub.go` with the last stub.

**Next:** gather those five results, then 8.4 to 8.7 and group 10 together, then 9.3 to 9.6, then group 11 after messaging `session-signal`.

**Record in `design.md` when 7.9 and 8.1 merge:** R14's disagreements (`WithLogoutOutbound`, `WithLogoutDeliveryPool`, `WithLogoutDeliveryTimeout`, the `busy` reason, a cap of twice the workers, on-demand workers with `Start` launching nothing, a consumer delivery running on the pool); 7.10's `Event.Client` and `Cause`, nine names, and no event for `SignInsEnded`'s dependency failure; `OrderOIDCProvider` 250 and `OrderOIDCProviderSession` 850, `checkAfterWiring`, the path rules, `ErrDependency` answering 500 first. Fix plans 7.9's `Close(ctx)` and fake clock lines.

### Third session, after the handoff above

**7.10 review: not clean, 11 `REPRODUCED`, none fixed; the 7.9 fold may overlap 1, 6, 10 and 11.** Proofs: `review-g10/oidcprovider/review_g10_test.go`, run with `go test -tags reviewg10 -race -run 'TestReview_' -count=1 ./oidcprovider/` (finding 1 with `REVIEW_G10_CRASH=1`). Throwaway fixes: `fix_g10.py`; mutants: `review-g10-mutants.txt`, both in the scratchpad.
1. High: a registry or log-handler panic on `reportLogoutFailed`'s goroutine kills the process.
2. High: 7.10 turns `httpsec` red: `TestSecurityEvents_Emitted` needs the nine names in `reportedElsewhere`. Add `./httpsec/` to 7.10's verification.
3. A public client refused at introspection (`revoke.go:72`) reports no `ClientAuthRefused`.
4. A refresh reuse through a chain emits three events; two is right. Keep the chain's emitter off the manager's context.
5. `GrantRevoked` repeats for an already revoked grant, with a false cause (`reportEnded`, `exchange.go:576`). The store must say whether the row was newly revoked.
6. A blocking sink on the worker path stops other clients' deliveries.
7. `GrantCreated` fires before the credential is handed out (`exchange.go:289`); move it before `return res, nil`.
8. A stored replay revocation goes unreported when the lineage delete fails.
9. A retried client revocation reports twice (`revoke.go:114`).
10. `Shutdown` can answer nil with a report goroutine held: `enterReport` ignores `finished`.
11. A burst of drops loses events past 64, and the godoc does not say so.

Also: `TestProvider_NoSecretsInLogs` does not run an assertion, malformed-credential, UserInfo, `VerifyAccessToken` or introspection refusal. `Event.Cause` says "never free text" while `RevokeUserGrants` passes a consumer's string. `design.md:50` lacks `Client` and `Cause`.

**Rest of 8.1:** the agent's rows pass; only finding 2 keeps `httpsec` red. Still uncommitted in `lane-h1`, and not verified by the main session.

### 7.9 fold, reported finished

`lane-g9fix`: F1 to F8 folded by the agent's report, uncommitted, not verified by the main session, and not re-reviewed (required: it changes a concurrency mechanism). `httpsec` was not run. Check it against the 7.10 findings: 7.10's 1, 6, 10 and 11 should be run from their proofs, not assumed closed.

Record in `design.md`:
- Reports run on two `reportLane`s, on demand: `records` (1 goroutine, in order, log lines) and `events` (up to 64, registry read and sink), each with 1024 waiting. Past that the newest loses, counted as `lost_events` or `lost_records`. A full queue at `Shutdown` loses nothing. No option: the bound protects the provider from the sink. A tight burst can outrun a healthy handler, and the `records` cap is the knob.
- New `outbound` exports: `WithoutRedirects` and `PostFormStatus` (reads no body, so an oversized 200 is a success).
- `EndSignIn`'s order is grants, browser delete, hand-on, then `reportEnded`, so a hung synchronous sink holds the response but not the deletes.
- A consumer delivery cut off by `Shutdown` also reports `shutdown`. Status, panic and goexit keep their real reason, at the bound as well.
- An event's `At` is stamped on reaching the sink. `WithOutbound`'s own time bound still applies. `Shutdown` is not callable from a log handler or sink. A sink panic with a panicking log handler still escapes `EndSignIn`, after the work is done.

### 8.1 to 8.3 review, reported finished

Commit `2d086532`: 5 `REPRODUCED`, none fixed, none in routing, slots or `StatusForError`. Proofs: `review-h1/httpsec/oidc_provider_review_test.go`, `go test -count=1 -run 'TestReview_' ./httpsec/`. Sketch fixes, not code to take: `review-h1-fix/`. Mutants: `review-h1-mut/`, `review-h1-scripts/`. Some may be affected by the uncommitted rest of 8.1 in `lane-h1`; rerun them there.
1. A consumer's wrapper around the same `*signingkey.Keys` as `Deps.Keys` is falsely refused (`oidc_provider.go:375`). Refuse only when the provider's source is itself a `*signingkey.Keys`.
2. **Needs a decision.** An issuer with a path behind `http.StripPrefix` is falsely refused by the assertion endpoint check (`:512`), with no workable override. Accept issuer path + served path (loosens the check for an unstripped chain), or add an explicit public-path option. 10.1's endpoint URLs depend on this.
3. `WithoutHeader("Content-Security-Policy")`, `WithCSPReportOnly()` and `frame-ancestors *` still build (`:524`). Add a check that the document profile forbids framing; state that a route-matched profile cannot be seen at construction.
4. `WithMFAMethodListing`'s path is not in the collision check (`:422`). The rest of 8.1 reports adding this: confirm.
5. Paths holding `?`, `#` or `%` are accepted and never match (`oidc_provider_options.go:80`, `:105`).
- `UNREPRODUCED`, no token endpoint yet: a percent-encoded assertion URL passes the check; compare `u.EscapedPath()`.
- 21 mutants survive: slot positions need ordering assertions, plus collision rows, a provider-first option order, and a `ChallengeError` wrapping a dependency failure.
- Artifacts: plans 8.1 says `c.wire`, the code uses `checkAfterWiring`. A refused `id_token_hint` has no sentinel or status row: R3 says 400, so 11.1 must add one to `errors.go`.

For later lanes: `routes()` must be pure, as it runs twice before `settle`. No CSRF seam exists: `settleExemptions` overwrites `l.exempt`, so 11.7 needs a helper or a `csrfExempt` field on `oidcRoute`, and until then group 9's endpoints refuse cross-site browser POSTs on a CSRF chain. Calling `next` passes the request on to the application, so answer a wrong method yourself. Outer routes run before `certificateSlot`, so call `ex.presentedThumbprint()`. `opFixture.wired` changes with the CSRF row.

### 9.1 and 9.2, reported finished

`lane-h2`: uncommitted, not verified by the main session, not reviewed (Opus: first-time security logic). Its `httpsec` is red only on 7.10's `TestSecurityEvents_Emitted`. 9.1 and 9.2 went red together against the stub, so the agent inverted 20 guarantees instead (`mutate_h2.py` in the scratchpad). Rows proving "unrotated" advance the clock past the grace, as R20's window hides a rotation otherwise.

Unfinished: `Provider` needs a loopback accessor, so `WithLoopbackHTTPIssuer` over plain HTTP is refused for now, which fails safe; 9.4 needs the same. The DPoP and certificate construction refusals it reports are in `lane-h1`'s uncommitted work, which this lane does not hold.

Helpers for 9.3 and 9.4, in `httpsec/oidc_client_auth.go`: `readOIDCClientRequest`, `setOIDCNoStore`, `writeOIDCRefusal`, and `oidcClientThrottle`. Never call `AuthenticateClient` before `Token`: an assertion is single-use.

Record in `design.md`: new options `WithOIDCTokenLimiter` and `WithOIDCTokenBodyLimit` (64 KiB, 413 above it); a throttle of 10 failures per source in 15 minutes (*proposed*), failing as `invalid_client`; invalid proofs charged to the source; a missing required certificate answers `invalid_request`; a proof plus a certificate from a client requiring mTLS is refused; a repeated `Authorization` header answers `invalid_request`; the proof is judged before client authentication, so a valid proof with a wrong secret still records its `jti`.

**All five agents have now reported.** Merge order: g9, g10, g9fix, a fold of 7.10's findings, h1, a fold of its findings, h2.

### Merge order with `session-signals` (supersedes "merges after")

Agreed with `session-signal` on 2026-11-05: whichever of #72 and #73 is ready first merges first, probably #73. That session reported that the user delegated the order, which this session did not hear directly, so #73's description states the change for the user to see. Neither session merges; the merge stays the user's click. `session-signal` rebases #73 onto `main`, carrying the end-observer commit `442c9f19`, and messages when it has rebased and when it merges. `feat/oidc-provider` is still not rewritten: when #73 lands, merge `main` in. Group 11 still gets its notice first, and 11.1 uses `Logout` only if it is on `main` by then, otherwise `RevokeFamily`.

**Pushes:** the user asked for PR #72 to be updated for each commit, so each commit landing on `feat/oidc-provider` is pushed and the PR body kept current. Lane branches stay local until their review is clean. While the user is away, a decision is researched first and takes the option closest to standard security practice, then listed for the user's review.

### State at the second usage limit (supersedes the lane lists above)

**47 of 79 on `feat/oidc-provider`, and nothing below is ticked.** `feat/oidc-provider-int` (worktree `lane-int` in this session's scratchpad) holds 7.9, 7.10, 8.1 to 8.7, 9.1 to 9.6 and group 10 in merge order, reviewed and folded. Its `httpsec` and `oidcprovider` passed under `-race` when last run.

Next, in order:
1. Cherry-pick `498e7c35` from `feat/oidc-provider-g10fix` onto `int`: the second delivery fold, committed there and not yet on `int`. Read the Opus review of `16599168` and `498e7c35` (proofs in `review-g10fix/`), fold what it found, and re-run.
2. Run the `test/` module whole on a quiet machine, on the default image and `postgres:15.19-alpine`. It only passed with `-p 1 -parallel 4 -timeout 45m` under load, and the events fold never got one clean pass on its final tree, so a store defect is not ruled out.
3. Cherry-pick `int` onto `feat/oidc-provider`, tick 7.9, 7.10, 8.1 to 8.7, 9.1 to 9.6, 10.1 and 10.2, push, update PR #72, and remove the lane branches.
4. Message `session-signal`, then group 11 (needs a CSRF exemption seam: `routes()` must stay pure, and `settleExemptions` overwrites `l.exempt`), then 13 to 15. `oidc_stub.go` goes with the last stub.

Decisions taken while the user was away, for their review: the merge order; `amr` as `pwd` and `mfa` (narrows "naming both factors"); named `https` origins may frame the pages, no `X-Frame-Options`; UserInfo `invalid_request` is 400 and a token sent two ways is refused; a public client's first proof at refresh is refused and a certificate-bound grant must present its certificate; `Request` gains `RawQuery`; 429 at authorize and resume. Each is in `design.md` with sources.

### Opus review of `16599168` and `498e7c35`: 3 `REPRODUCED`, none fixed

Proofs: `review-g10fix/oidcprovider/review_proofs_test.go`. Adapters' `Revoke` and the delivery accounting held, and no token works past a revocation.
1. Medium: a slow sink makes `RevokeConsent` fail and keep the consent (`endsignin.go:249`). Give the consent write its own budget, as `EndSignIn` does. Moving the report after the write loses events: do not ship that.
2. Low-medium: a consumer's cause spelled `sign_in_ended` reports twice (`events.go:84`): `endedEarlier := g.Revoked && (g.RevokeCause != CauseSignInEnded || !g.RevokedAt.Equal(g.SignInEndedAt))`.
3. Low: a line lost to a handler panic is not counted (`backchannel.go:482`): an unfinished task in `toLog` adds to `unsaid.records`.
- `UNREPRODUCED`, low: one narrow way past `shutdownRoom`; the loss is still counted.
- Test gaps: `sayLost` dropping `lost.records` on a panic; `answerLineage` and `revokeOnReuse` passing `true` for `newly`; `startLane`'s `reopen` looks dead.
- Artifacts: `events.go:26` and `doc.go:273` overclaim "a sink cannot change the outcome"; R14's "only the count" and `Shutdown`'s "every report" omit finding 3; the `security-events` reuse scenario omits the case where something else revoked first.

Fold these (Opus) after step 1 above, before merging.

## Update: fourth session (supersedes everything above where they differ)

**75 of 79 ticked.** Open: 14.2 (job must appear on the PR), 14.3 (all four plans pass in CI), 15.2 (re-review), 15.3 (final gate). All lanes are merged and removed. The only worktree is `/private/tmp/claude-501/-Users-zakyalvan-Documents-RND-scrty/06d48fe0-a406-44d7-b082-ed4b34ef1f3e/scratchpad/oidc`, on `feat/oidc-provider`.

**Local, not pushed:** the commits after `fd59636e` on `feat/oidc-provider`, up to `79758648` and this handoff: the whole-branch review's folds. Hold them until the two results below are clean. The scratchpad may not survive; if `gate-*.log` or `review-final2/` are gone, rerun them.

**In flight when the user paused:**
1. Local gate on a frozen copy of `79758648` (`/private/tmp/claude-501/-Users-zakyalvan-Documents-RND-scrty/06d48fe0-a406-44d7-b082-ed4b34ef1f3e/scratchpad/gate`): `GOFLAGS=-p=2 make check`, then `go test -race -count=1 -p 2 -timeout 45m ./...` in `test/` with `SCRTY_TEST_POSTGRES_IMAGE=postgres:15.19-alpine`, then `make conformance`. Logs: `/private/tmp/claude-501/-Users-zakyalvan-Documents-RND-scrty/06d48fe0-a406-44d7-b082-ed4b34ef1f3e/scratchpad/gate-check.log`, `gate-pg15.log`, `gate-conf.log`.
2. Opus re-review of `e9571a31` and `6ae79965`, which must report nothing open for 15.2. Proofs, if any: `/private/tmp/claude-501/-Users-zakyalvan-Documents-RND-scrty/06d48fe0-a406-44d7-b082-ed4b34ef1f3e/scratchpad/review-final2`. Its priority: can the resume's family-liveness check wrongly end a live sign-in, or hide a head behind a listing bound; does `WithIDGenerator` break a flow relying on the default's format.

**Next, in order:**
1. Read those two results, and rerun whichever is missing. Fold any findings, verify, re-review only if a concurrency mechanism changed.
2. Push `feat/oidc-provider` and update PR #72's body (the user asked for the PR to be updated for each commit; lanes stay local until clean). Check the last `git log` for no session link.
3. **The user said: mark #72 ready once the review is clean.** Do so only then. Ready starts CI, as `ci.yml` skips drafts. Merging stays the user's.
4. Watch CI. Tick 14.2 when the job appears and reports all four plans. Tick 14.3 and 15.2 and 15.3 on green. Triage per 14.3: a provider defect gets a failing unit test and a fix; a job misconfiguration is fixed in the job; nothing enters the expected files without a decision in `design.md`. CI's `/etc/hosts` step, artifact upload and cold-build time have never run; `test/` may need `-p` limited, as it timed out under heavy load.
5. Before archive: delete this handoff.

**How to work, as the user asked:** parallelize subagents wherever possible. While the user is away, research a decision first, take the option closest to standard security practice, record it in `design.md` with sources, and list it for review. Validate before every docs push (`openspec validate oidc-provider --strict`, push only on "is valid"). Rerun tests after rebasing or stacking, as a lane green alone was red when stacked. Run `actionlint` (`go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12`), which caught a CI job that could not start.

**Coordination.** `session-signal` has this session's old name; send it the new one with `ListAgents`. #73 is marked ready, all 37 tasks done, rebased on `main`, not merged. Ready-first was agreed, and it messages at its merge. When #73 merges: merge `main` in, do not rebase; this branch is not rewritten. Then add `Stream` to `ResponseWriter` doubles, keep its `Logout(ctx, user, family)` call in `logout.go` (`finishLogout` in `httpsec/oidc_endsession.go` has the one `RevokeFamily` to convert too), and check new endpoints set headers before a response begins. If #72 is ready first, tell it, and it rebases onto us and adds `RawQuery()` to its doubles. Merging either PR is the user's click. Its report that the user delegated the merge order was never heard from the user directly: #73's description states it.

**Decisions taken while the user was away, for their review**, each in `design.md`: ready-first merge order; `amr` as `pwd` and `mfa`, narrowing "naming both factors"; named `https` origins may frame pages, no `X-Frame-Options`; UserInfo `invalid_request` is 400 and a token sent two ways is refused, and a cross-site UserInfo POST stays refused; a public client's first proof at refresh is refused, and a certificate-bound grant must present its certificate; `Request` gains `RawQuery`; 429 at authorize and resume; a logout's order is grants, first-party sessions, browser session; "keep grants" keeps only `offline_access` grants; the logout page does not name who is asking; a passkey manager takes no raw store, and a provider chain refuses one undecided on clones; `scrty_grant_end_failed` and `scrty_grant_revoke_failed`; the suite's expected warning and skip. **Left as follow-ups:** 401s with no challenge elsewhere in the chain, including a bad bearer before `/resume` and `/consents`. **Unverified:** whether official certification accepts a warning.

### Results of the two in-flight runs (fourth session)

**Local gate on `79758648`: clean.** `make check`, `test/` on PostgreSQL 15 under `-race` (12 packages), and `make conformance` (all four plans, only the expected results) all exit 0. Rerun after the folds below.

**Opus re-review: 3 `REPRODUCED`, none fixed, so do not push or mark #72 ready yet.** Proofs: `review-final2/oidcprovider/zzreview_mid_end_test.go`, `review-final2/httpsec/zzreview_challenge_test.go`, `zzreview_misc_test.go`; rewrite them from this if the scratchpad is gone.
1. Medium-high: `EndSignIn` sweeps codes first and deletes browser sessions second (`oidcprovider/endsignin.go:63,67`). A code written between the two passes `Touch` and misses the sweep, so it exchanges for tokens after the end, on ends that run one pass: `session.EndSignIn`, `EndOtherSignIns`, reuse. A stolen browser cookie can retry silent authorize for this window. Fix, proven: delete browser sessions first, then sweep codes. Test: an end in progress reaches a code from resume consent and from authorize.
2. Low-medium, needs a decision: a bad bearer at `/resume` and `/consents` answers 401 with no `WWW-Authenticate` when DPoP is off (`httpsec/oidc_consents.go:187` only sees refusals from inside the endpoint). RFC 9110 §15.5.2 MUST; RFC 6750 §3.1 SHOULD `invalid_token` for a presented bad token. Proven fix: an `Intercept` on `oidcOuterRouter` adding the challenge. Choose these two endpoints, or the bearer refusal chain-wide (`bearer.go`, `session_bearer.go`). This revises the follow-up recorded in R26.
3. Low-medium, needs a decision: `confirmSignIn` (`httpsec/oidc_resume.go:244-255`) lists sign-ins through the chain's manager only, so a consumer's bearer publishing a session from its own manager reads as ended: `EndSignIn` runs on that family and the resume answers 401. Docs at `httpsec/oidc_provider.go:450-458` state no limit (`library-design` rule 4). State the limit and pin the refusal, or add an option naming the manager. No real fix is built.

Non-blocking: `WithIDGenerator`'s godoc should say IDs must be non-zero and unique; `httpsec/oidc_cors_test.go:16,97` still say "once task 10.1 lands"; silent authorize releases a code when `Touch` fails with an outage, where consent answers 500; a head passing its deadline mid-request ends the sign-in's grants, as `confirmSignIn`'s doc states; a login-stage resume failing its check has already dropped the previous browser session.

Clean: resume race on live sign-ins, `checkDPoP`, refused-refresh log, `WithIDGenerator` flows, redaction, removed code.

**Next, before step 1 of the list above:** fold these three (Opus: finding 1 is ordering), rerun the gate, re-review the fold, then push and mark #72 ready.
