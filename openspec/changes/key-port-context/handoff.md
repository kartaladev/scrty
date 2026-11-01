# Handoff: `key-port-context` implementation

Written 2026-11-01, at the end of the first `/opsx:apply key-port-context` session. Resume with
`/opsx:apply key-port-context` on branch `feat/key-port-context`.

## Where we stopped

- **27 of 32 tasks ticked.** Open: 6.5, 6.6 (one blocking review finding), 6.9, 7.1, 7.2.
- **Branch `feat/key-port-context`**, 17 commits on `main` (`8d5ad45` … `79ffb68`), not pushed, no PR.
  Every code commit was verified (tests, vet, lint, gofmt) and reviewed by a fresh agent; the last
  three (`b0f0e42`, `a7aee1e`, `79ffb68`) were each built and tested on their own in a scratch
  worktree.
- **Working tree:** clean apart from this note and the artifact edits committed with it.
  `openspec/changes/bff-resource-server/handoff.md` is untracked and belongs to another change.

## Decisions taken with the user during this session (already in the artifacts)

1. **D8 widened to verification** (`50295b9`): a bearer whose request is cancelled during
   verification answers with the context's error and its own fixed text, no ERROR record. Task 2.8,
   scenarios in `http-security-chain` and `authentication`.
2. **A grace rotation whose step outlives the window stores nothing** (`2a13920`): fails matching
   `context.DeadlineExceeded`; for fresh and re-rotation renewals the capped window is used, for
   recovery renewals the uncapped one. `sessions` scenario "A step that outlives the grace stores
   nothing", D7 and its Risks entry.

Decided by the main session, recorded in `design.md` (uncommitted until this note's commit):
- the renewal endpoint does **not** classify a hang-up during rotation or issuing (S2 review, option
  A: consistent with login completion and D8 as written);
- redemptions cancel held recoveries after the consume (D7 table);
- the recovery hook is the option `recovery.WithCredentialIssuer`, the store-failure residue after
  the spends, and no charging of an issuing failure (D7, "Recovery." sub-bullets);
- a recovery's MFA proof is judged after issuing (Risks);
- `oidc-login` "Consume fails" now says "no access token is handed out".

## Next steps, in order

### 1. Close 6.5 and 6.6: one fix dispatch (Sonnet, then a Sonnet reviewer)

The S3 review of `a7aee1e` found the code correct but one **blocking coverage gap**: the refusals
for a misbehaving consumer redeemer can each be deleted with the whole suite green.
- `httpsec/redemption.go` `issue` (~386–398), `redeemed` (~410–417), `decidedAs` (~422–432).
- Add rows to `TestRedeemerGuard` (`httpsec/magiclink_test.go`): a redeemer that runs only the
  policy check (refused, `policy.ErrDenied`, no session); runs every check twice (succeeds,
  `issued == 1`, one session); re-runs the policy check for another user after issuing (refused, no
  session). Add the OIDC equivalents (check run twice; re-run for another candidate). Each row must
  be seen failing under its mutation: drop `!r.login.decidedAs(r.out)` from `redeemed`; make
  `issue`'s re-entry return nil without comparing; remove the issue-once short-circuit.
- The reviewer's probe is at
  `/private/tmp/claude-501/-Users-zakyalvan-Documents-RND-scrty/7818f8f2-95ae-455f-af3f-b27c26f8acf2/scratchpad/s3review/repo/httpsec/zz_review_test.go`
  (scratchpad; may be gone in a new session).

Fold the S3 non-blocking findings into the same dispatch:
- a row that an issuing failure cancels no held recovery and leaves the link redeemable;
- `Redeemer` godoc (`httpsec/magiclink.go` ~96–111): name the new refusals (skips the issuing check,
  out of order, re-run for another login after issuing → `policy.ErrDenied`, after the link is
  spent) — a stated limit for a replaceable port (library-design rule 4);
- `HandoffRedeemer` godoc (`httpsec/oidc.go` ~82–105): the single check also issues; run twice
  issues once; a re-run for another candidate is refused;
- `httpsec/complete.go` ~431–433 comment (the OIDC provider session is now set on the prepared
  session before `commit`, not through `opts`) and `completeLogin` godoc ("Form login … pass none"
  is wrong: form login passes `WithAbsoluteLifetime`);
- `TestOIDCRedeemAssurance` (`httpsec/oidc_redeem_test.go` ~852–857): assert `issued <= 1` and that
  the issued identifier loads nothing, instead of `NotContains(body, "access_token")`.

Then tick 6.5 and 6.6.

### 2. Task 6.9: godoc and README sweep (Sonnet)

- README wherever it describes the issuing order: a credential is issued before anything is stored
  or spent, and an issuing failure is a dependency failure.
- `httpsec/login_options.go` `EnableFormLogin` step 5 still reads "open the session, and issue the
  access token".
- Godoc of every seam 6.1–6.8 changed (`go doc` each); `golangci-lint run ./...`.
- Fold the S4 review's non-blocking items (all in `recovery/` and `httpsec/recovery*`):
  - N1: assert the hang-up row of `TestRecoverer_IssueFailureSpendsAndEndsNothing` writes no ERROR
    `msgIssueFailed` record, and the other rows do (`recovery/recover_complete.go` ~251);
  - N2: `{name: "a nil credential issuer", opts: with(recovery.WithCredentialIssuer(nil)), assert:
    configError}` beside the nil-ID-generator row (`recovery/recoverer_test.go` ~205);
  - N3: a `recovery` row with no issuer → `Credential == ""`, session stored and recovery-pending
    (the default is covered); optionally a `Result.Session` godoc pointer to `WithCredentialIssuer`;
  - N4: an `httpsec` row passing `WithRecoveryCore(recovery.WithCredentialIssuer(<fails>))` that
    still recovers with the chain's token;
  - N6: reflow the long comment line in `httpsec/recovery.go` `resolve` (~251).

### 3. Task 7.1: the gate

`make check` locally, then push and open the PR, and get CI green on both PostgreSQL and Redis
matrix jobs. Container-start flakes seen locally during this session, none reproduced on re-run:
`TestSigningKeyStore_SealedColumns` (one 60 s failure under heavy parallel Docker load),
`TestKeycloak` (container not ready after 310 s, passed alone in 18 s), `TestRunTestRedis`
(container start). Watch for them; re-run the package alone before suspecting the change.

### 4. Task 7.2: whole-branch review (Opus), then `openspec validate key-port-context --strict`

Against every requirement of the eleven deltas and D1–D8. Give the reviewer these explicit probes:
- **Stale old-record state across a grace rotation's step** (an automated security review flagged
  `session/reuse.go` `RotateWithGraceIssuing` as TOCTOU; the S1 review reproduced that a save of the
  old session during the step is not carried to the successor, and showed it predates this change
  in `RotateWithGrace`). Currently `UNREPRODUCED` as a security defect: revocation during the step
  makes `Supersede` fail, and challenge marks are re-derived per request. The probe: can a
  confinement mark saved during the step be escaped through the successor? A failing test makes it
  a defect; otherwise record it as accepted.
- The review-only follow-ups that skipped their own reviewer (`f6326e0`, `4bf8364`, `6166de0`),
  which were small test-plus-godoc changes verified by inversion.

## Questions for the user, not yet asked

1. **A hang-up during issuing.** A signer that honours a cancelled request returns the context's
   error; login completion, redemptions and renewal answer it as a dependency failure (D7), while
   recovery logs it at DEBUG and charges nothing. D8 covers verification and resolution only. Widen
   D8 to issuing (consistent answers, no ERROR noise for a client that left), or leave it?
2. **Recovery core with no issuer.** The S4 reviewer recommends keeping `WithCredentialIssuer`
   optional (the core cannot pick a token issuer; a session-reference consumer has nothing that can
   fail) and pinning the default with a test (step 2, N3). Confirm, or refuse construction without
   one.

## Deviations from `plans.md`

- R3 (task 2.8) added mid-session; S1b, S1c, S2b, C2, R3b, B2 were extra fix dispatches from reviews.
- S3 and S4 ran in parallel instead of in sequence (disjoint files; both consumed the completion
  step only), and 6.9 moved out of S4 into its own dispatch.
- S3 replaced the planned `spend` hook on the completion step with a split
  (`prepareLogin` → `preparedLogin.commit`) and a redemption step run as a redeemer check
  (`httpsec/redemption.go`); S4 used `recovery.WithCredentialIssuer` instead of `Request.Issue` and
  a `Finish` parameter. Both are recorded in `design.md`.
- `plans.md` was not rewritten for these: they change dispatch shape, not tasks.

## Workflow follow-up (from `tasks.md`)

Archive after the review and before `release-readiness` is applied; verify the archived specs carry
every modified and added requirement of the eleven deltas.
