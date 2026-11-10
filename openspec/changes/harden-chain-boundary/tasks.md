# Tasks

**How tasks are worked:**
- **Test-first.** Every Go task writes the failing test, runs it, and confirms it fails for the intended reason; a compile error is not a red step. Then it implements, re-runs, and refactors with the tests green.
- **Reproductions.** Where a reproduction exists in `repro/`, it becomes the red step. It is ported into the package's own suite and helpers, and it keeps the same cases.
- **Maintainer tasks.** Tasks marked **(maintainer)** merge, tag or publish. Only the maintainer does them, never an agent.
- **Model per dispatch:**
  - Opus for groups 2–6: ordering on a hot path, and security refusal logic written for the first time;
  - Sonnet for group 7 and for scenario and godoc additions;
  - each dispatch gets a fresh reviewer of the same tier.
- **Files.** Groups 2–6 change `httpsec/chain.go` and `httpsec/exchange.go`, so they run in order, as one lane. Group 7 owns `httpsec/options.go` and `httpsec/authorization.go`'s option, and may run in parallel with group 2.
- **Branch.** Everything happens on the public branch `fix/harden-chain-boundary` and merges through an ordinary pull request with CI (design decision 8).

## 1. Branch and baseline (design decision 8)

- [x] 1.1 Confirm two things on `main`:
  - `release-readiness`'s release-probe trigger fix is merged: `git log origin/main -- .github/workflows/release-probe.yml` shows the commit adding `workflow_dispatch`;
  - `descriptive-parameter-names` is merged: `git grep -n TestExportedParametersHaveDescriptiveNames origin/main -- layout_test.go` finds the guard.

  If either is missing, stop.
- [x] 1.2 Cut branch `fix/harden-chain-boundary` from `origin/main` and carry this change's directory onto it. Verify that `git branch --show-current` names it and that `git merge-base HEAD origin/main` equals `git rev-parse origin/main`.

## 2. The interceptor fold is built once (decision 5)

- [x] 2.1 Red: port `repro/httpsec_assemble_bench_test.go.txt` into `httpsec` as `BenchmarkAssemble` and `BenchmarkChainRequest`, and record a `-count=10 -benchmem` baseline in the scratchpad. Add `TestAssemble_TerminalPerRun`, a table test with these cases:
  - an interceptor that passes `next` an exchange it built itself gets an `ErrConfig` error, not a panic;
  - a different chain assembled inside an interceptor of the first, on the same exchange, reaches the first chain's own terminal after its own;
  - `next` called twice runs the terminal twice;
  - concurrent requests on one chain each reach their own terminal (`-race`).

  Verify that the first case fails today for the intended reason (the terminal runs) and that the others pass.
- [x] 2.2 Build the per-registration steps once in `build`. `Assemble` records the terminal on the exchange, on a per-exchange stack keyed by chain, and runs the prebuilt fold. Verify that 2.1 passes under `-race`, that `go test ./httpsec/... -count=1` and the conformance suite (`test/httpsecconformance`, all three adapters) pass, and that `benchstat` shows the fold's allocations at no more than two per request. Record the numbers in `design.md` decision 5.

## 3. Dot segments are refused at the chain's entry (decision 1; spec "A request path with a dot segment is refused before the chain runs", "Every adapter refuses a path its router could resolve differently")

- [x] 3.1 Red: add `TestChain_RefusesDotSegments` in `httpsec`, a table test over `Middleware()` with these cases:
  - refused with 400 before any interceptor: `/a/../b`, `/a/./b`, `/a/%2e%2e/b`, `/a/%2E%2E/b`, `/a%2F..%2Fb`;
  - refused: an undecodable path, driven through a test `Request` whose `EscapedPath` holds `%zz`;
  - not refused: `/files/report..v2.txt`, `/.well-known/jwks.json`, `/a//b`;
  - with security headers on, a refused request carries them.

  Port `TestFiber_AuthorizationRuleSeesRoutedPath` and `TestFiber_RecoveryCooldownSeesRoutedPath` from `repro/fibersec_pathdiff_repro_test.go.txt` into `httpsec/fibersec`, real listener included, without the upper-case case (design decision 7). Verify that all three fail today, showing the handler ran.
- [x] 3.2 Implement the entry check in the step `Assemble` returns, before client resolution, writing the refusal as client resolution does. Verify that 3.1 passes, that the full `httpsec`, `fibersec` and `ginsec` suites pass, and that `repro/ginsec_pathdiff_repro_test.go.txt`'s gin and ServeMux cases, ported as `TestGin_NonCanonicalTargetsNeverReachTheHandler`, pass.
- [x] 3.3 Add a conformance scenario to `test/httpsecconformance` that sends `/x/%2e%2e/y` and `/public/../admin/users` over a real connection. Verify that it answers 400 with no body on net/http, gin and fiber, and that it fails if the entry check is disabled temporarily (then restore it by editing it back).
- [x] 3.4 Godoc:
  - `Request.Path` no longer promises parity with a router's view, and says dot segments are refused first;
  - `EnableAuthorization` and `PathPrefix` say that on fiber, letter case and trailing slashes reach one route, and that a `GET` predicate has to cover `HEAD`;
  - `EnableRecoveryCooldown` says that dot-segment paths are refused before it runs.

  Verify with `go doc` on each symbol, and that `go vet` and the lint pass.

## 4. A chain entered twice on one request runs once (decision 4; spec "A chain entered again on a request it already ran on lets it through", "A chain mounted twice on one framework runs once")

- [x] 4.1 Red: port `TestRepro_DoubleMount` from `repro/ginsec_double_repro_test.go.txt` into `httpsec/ginsec`, and add the fiber equivalent in `httpsec/fibersec`. Add `TestChain_ReentryPassesThrough` in `httpsec`, covering:
  - the same chain nested on one request: the inner run does nothing;
  - a different chain nested: both run;
  - the same chain on an in-process forward to another path: it runs again.

  Verify that the ported tests fail today with two authenticator calls, and that the forward case passes today.
- [x] 4.2 Implement the context marker (chain, method, escaped path) and the pass-through. Verify that 4.1 passes and the three adapter suites and the conformance suite pass.
- [x] 4.3 Godoc for `ginsec` and `fibersec` (`doc.go` and `Middleware`): routes registered before the middleware is added are not guarded; one chain mounted twice runs once; two different chains both run. Verify with `go doc` and the lint.

## 5. No session is published once the gates have begun (decision 2; spec "A session cannot be published once the gates have begun")

- [x] 5.1 Red: port `TestRepro_ConsumerAuthenticatorAfterGatesIsJudgedByThem` from `repro/httpsec_lateauth_repro_test.go.txt` into `httpsec`, with all ten cases. The six late cases expect 500, an `ErrConfig` error from `PublishSession`, and the handler not run. The four bearer-slot controls are kept as they are. Add the "no gate enabled" case, expecting publication to succeed. Verify that the six late cases fail today, showing a 200.
- [x] 5.2 List every library caller that sets a session with gopls references on `PublishSession` and on `Exchange.Session`, and move each one to the unexported publishing path. Implement the mark at the first gate's prebuilt step, and the refusal in `PublishSession`, with one sampled log record per chain. Verify that 5.1 passes, and that `go test ./httpsec/... -count=1 -race` and the conformance suite pass.
- [x] 5.3 Godoc for `PublishSession` and `RegisterInterceptor`: the refusal, the slots an authenticator belongs at, and that a consumer interceptor at a built-in's exact slot runs in option order. Verify with `go doc` and the lint.

## 6. The authorization stage refuses a session owing a built-in challenge (decision 3; spec "The authorization stage refuses a session owing a built-in challenge")

- [x] 6.1 Red: add `TestGateExemptions_NeverReachTheAuthorizationStage`. For each gate's exemptions, it sends a request from a session owing that gate's challenge and asserts the chain answers it before slot 900. It passes today; confirm it bites by temporarily exempting one consumer route, then restore it. If it fails without that change, stop and report the exemption: the design's fallback decides it.
- [x] 6.2 Red: add `TestAuthorization_RefusesOwingSession`, a table over the four owed challenges with rules and without. A session is set on the exchange directly, past every gate, and each case expects the gate's error and status, with the second-factor methods for MFA. A full session is permitted. Verify that the owing cases fail today with a 200.
- [x] 6.3 Implement the check at the start of the authorization stage. Verify that 6.1 and 6.2 pass, and that the `httpsec` suite and the conformance suite pass.

## 7. Single-value options given twice fail at construction (decision 6; spec "Single-value chain options given twice fail at construction")

- [x] 7.1 Red: port `TestRepro_SecondSingleValueOptionIsSilent` from `repro/httpsec_wiring_repro_test.go.txt` into `httpsec` as `TestNew_SingleValueOptionGivenTwice`. It covers all five options, each with the same value twice and with two values, and expects the error to name the option. Add `TestEnableAuthorization_ChecksEveryAuthorizer` (nil, then valid) and keep the two-authorizers case passing. Verify that the five-option cases and the nil case fail today.
- [x] 7.2 Implement the refusals, and the per-call authorizer check. Verify that 7.1 passes and the `httpsec` suite passes, and that no test elsewhere in the workspace builds a chain with a duplicate option (`make test`).
- [x] 7.3 Godoc on each of the five options: "Given twice, New refuses the chain." Verify with `go doc`.

## 8. Integration gate

- [x] 8.1 Run a whole-branch review with a fresh Opus reviewer that edits nothing. It checks the diff against every requirement in this change's two spec deltas and decisions 1–7, and enumerates how the change fails before judging it. Verify that every finding is fixed or declined in `design.md`.
- [x] 8.2 After groups 10 and 11 are complete, on the branch head, run `make check`, `make release-check VERSION=v0.1.1` (after task 9.1's file changes) and `openspec validate harden-chain-boundary --strict`, with Docker up so the conformance and integration suites run. Verify that all three are clean before the pull request is opened, and that CI on the pull request is green.

## 9. Release `v0.1.1` (decision 8)

- [x] 9.1 Follow `RELEASING.md` steps 1–2 for `v0.1.1` on the branch:
  - a `0.1.1` changelog entry: `Security` (the three defects, each with its effect and the affected version `v0.1.0`) and `Changed` (decision 6; the 400 for dot-segment paths; "Exported signatures use descriptive parameter names (no API change)" from `descriptive-parameter-names`);
  - every nested requirement bumped to `v0.1.1`;
  - `retract v0.1.0` in the root `go.mod`, with a comment pointing at the `0.1.1` changelog entry's `Security` section.

  Verify that `SCRTY_RELEASE_VERSION=v0.1.1 go test -run TestNestedModulesRequireReleasedVersions .` passes and `go mod edit -json | jq .Retract` shows `v0.1.0`.
- [ ] 9.2 **(maintainer)** Recheck that the release-probe fix is on `main`. Merge the pull request, then verify that CI on `main` is green for the merged commit before any tag.
- [ ] 9.3 **(maintainer)** Follow `RELEASING.md` steps 3–8 for `v0.1.1`. Verify:
  - the gate passed locally and in CI;
  - the nine tags are on one commit;
  - the root tag was pushed on its own;
  - the `release-probe` run triggered by that push passed.
- [ ] 9.4 **(maintainer)** Step 9: publish the release notes with the nine SBOMs. Verify that `gh release view v0.1.1` lists nine assets.

## 10. Review and security findings (decisions 1, 2, 3, 4, 6; design "Reproductions", review rows)

Two lanes. Lane A (10.1–10.4, Opus) owns `httpsec/chain.go`, `httpsec/exchange.go`, `httpsec/resolve.go` and their tests, and runs in order. Lane B (10.5–10.6, Sonnet) owns `httpsec/authorization.go` and `httpsec/ginsec` tests, and runs in parallel with lane A. Each red step is the stored reproduction, ported into the package's suite and helpers with the same cases.

- [x] 10.1 Red: port `TestChain_RetriedPassPublishesBeforeGates` and `TestChain_SecondChainCannotPublishPastFirstChainsGates` from `repro/httpsec_gatemark_repro_test.go.txt` into `httpsec`. Add these cases:
  - the second chain mounted with a built-in authenticator (the session bearer) instead of a consumer one;
  - a gate that panics, and a run after it on the same exchange that publishes at the bearer slot.
  - a handler that forwards the request in-process to another path through the same gated chain, which publishes (control, the case `TestReauthResolve` hit);
  - a handler that forwards through a different chain enabling the same gates, which publishes, and whose own second-factor gate then refuses a session owing a second factor;
  - a chain inside the gates enabling only some of the outer chain's gates, which is refused with 500.

  Verify that the retried-pass case fails with the late-publication error and the nested cases fail with a 200, and that the controls pass.
- [x] 10.2 Make the gate mark hold only during the first gate's frame (put back on return, deferred), record it on the run's marker, and refuse publication when an enclosing run of another chain is marked and the publishing chain does not enable every gate that run's chain enables (decision 2's gate-set condition), in both `PublishSession` and the unexported publishing path. Correct the comment in `Assemble`'s step. Verify that 10.1 passes, and that `go test ./httpsec/... -count=1 -race`, the `ginsec` and `fibersec` suites and the conformance suite pass.
- [x] 10.3 Red: port `TestChain_EntryRefusalCarriesSecureHeadersBehindTrustedProxy` from `repro/httpsec_entry_backstop_repro_test.go.txt` into `httpsec`, with both controls (a clean path carries HSTS; an untrusted peer forging the scheme gets none). Add a case where client resolution refuses a request that also holds a dot segment, expecting the client-resolution refusal. Verify that the main case fails with the header missing and the controls pass.
- [x] 10.4 Move the dot-segment check to after client resolution, before any interceptor. Update `refuseAtEntry`'s godoc and `Request.Path`'s if they say "before client resolution". Verify that 10.3 passes, that `TestChain_RefusesDotSegments`, the fiber and gin path tests and the conformance dot-segment scenario still pass, and that `go test ./httpsec/... -count=1 -race` passes.
- [x] 10.5 Red: port the log case of `TestAuthorization_BackstopSurfacesMethodLookupFailure` and `TestAuthorization_BackstopLooksUpMethodsOnlyForSecondFactor` from the same file into `httpsec`. Keep the status case as a regression guard. Verify that the log case fails showing only the wiring record. Then write a distinct sampled record when the method lookup fails, with no error text and no identifier, and remove `EnableAuthorization`'s deferred nil-authorizer check (no red step: `TestEnableAuthorization_ChecksEveryAuthorizer` covers the check that remains). Verify that the ported tests and the `httpsec` suite pass.
- [x] 10.6 Port `repro/ginsec_double_swap_repro_test.go.txt` into `httpsec/ginsec` as `TestGin_DoubleMountPassesRewritesThrough`. It pins the accepted behaviour of decision 4: the swap cases are served on the first judgement and the authenticator runs once, the no-middleware control runs once, and the path-rewrite control runs the chain again. Confirm it bites by temporarily dropping the pass-through, then restore it by editing it back. Verify that the `ginsec` suite passes.
- [x] 10.7 Changelog: in the `0.1.1` Security entry, the authenticator bullet also names a second chain run inside the gates, and the `Changed` entry for the 400 does not say "before client resolution". Verify by reading the entry against decisions 1 and 2.
- [x] 10.8 Run a whole-branch review with a fresh Opus reviewer that edits nothing. It checks the group 10 diff against the revised requirements and decisions 1–4 and 6, and enumerates how the change fails before judging it. Verify that every finding is fixed or recorded in `design.md`.
- [x] 10.9 **(maintainer decision)** Decide the whole-branch review's two reproduced findings. Decided 2026-11-10: fix both before release (tasks 10.11–10.12; design decisions 2 and 3).
- [x] 10.10 Pin each check on its own: internal tests of `token`'s header helpers (`matchesKey`, the missing- and empty-`alg` refusal) and of `oidcprovider`'s `namesAlgorithm` equality, each shown to bite by removing that check alone, and a test that `Exchange.publishingChain` skips a run whose terminal is running, shown to bite by removing that filter. Verify that `go test -race -count=1 ./token/... ./oidcprovider/... ./httpsec/` passes.
- [x] 10.11 Red: port `TestChain_GatedChainInsideGatelessChainServesOwingSession` from `repro/httpsec_nested_chains_repro_test.go.txt` into `httpsec`, with the spec's other scenarios as cases: a full session from the enclosing chain is let through to the inner handler; the inner chain's own resolved session is the one judged; the same for the recovery, enrolment and password-change gates and the recovery cool-down, each refusing an owing session from the enclosing chain. Verify that the owing cases fail today with 200. Then implement one helper returning the session a request carries (`ex.Session`, else the request context's session), and use it in every built-in that judges the request's session, found with gopls references on `Exchange.Session`. Verify that the cases pass and that `go test ./httpsec/... -count=1 -race`, the ginsec and fibersec suites and the conformance suite pass.
- [x] 10.12 Red: port `TestChain_CoveringChainOnSharedExchangePublishes` into `httpsec`, with cases: the covering chain on the same exchange publishes; the inner chain's own late authenticator on the same exchange is refused; a nested chain lacking a gate on the same exchange is refused; the retried-pass and late-authenticator suites stay green. Verify that the covering case fails today with the late-publication error. Then mark each run's entry on the exchange from its gate frame, restored with it, and have `PublishSession` treat only the publishing run's own mark as a late publication; another marked run refuses a publisher lacking one of its gates. Verify that the cases pass and that `go test ./httpsec/... -count=1 -race` passes.
- [x] 10.13 Changelog: the `0.1.1` Security entry names the gated chain inside a gateless chain, also affecting `v0.1.0`, as fixed. Verify by reading the entry against decisions 2 and 3.
- [x] 10.14 Run a review of 10.11–10.12 with a fresh Opus reviewer that edits nothing, against decisions 2 and 3 and the requirements "A session cannot be published once the gates have begun" and "A chain's built-ins judge a session an enclosing chain published". It enumerates how the change fails before judging it. Verify that every finding is fixed or recorded in `design.md`.
- [x] 10.16 Fold the 10.14 review, except the context restore, which moved to group 12:
  - port `repro/httpsec_shared_exchange_repro_test.go.txt` (red: a gateless chain's built-in publishes inside the outer chain's gates on a shared exchange with the context replaced), and refuse it in the built-in publishing path from the exchange's own marks;
  - per-gate tests asserting the backstop's bypass record is absent when each gate refuses;
  - keep the enrolment endpoints on `ex.Session`, with a test that they answer `ErrAuthenticationRequired` inside a gateless chain;
  - rename the shadowed `i` in the gate frame.

  `TestChain_RunPutsBackTheContextItFound`, already in the tree and red, stays red until task 12.2. Verify that the 10.16 tests pass, that `go test ./httpsec/... -count=1 -race` fails only on that test, and that the ginsec and fibersec suites and `make lint` pass.
- [x] 10.17 Review 10.16 with a fresh Opus reviewer that edits nothing, against decisions 2, 3 and 5 and their rows. Verify that every finding is fixed or recorded.
- [ ] 10.15 After groups 12–14, on the branch head, re-run task 8.2's gate: `make check`, `make release-check VERSION=v0.1.1` in a clean worktree on a quiet machine (sequentially, not beside other test runs), `openspec validate harden-chain-boundary --strict`, and CI on the pull request. Verify that all are green, then update the pull request body.

## 11. Dependencies and the header algorithm (decision 9; specs `token-issuance`, `oidc-provider-authorization`)

- [x] 11.1 Take the open Dependabot updates: jwx/v4 4.6.0 (root direct, nested modules indirect), testcontainers-go and its postgres, redis and mailpit modules 0.44.0 to 0.45.0 (`test/go.mod` only), CodeQL init and analyze 4.39.3 pinned by commit in `.github/workflows/ci.yml`. Verify that every workspace module builds, vets and passes `go test -race -count=1 ./...` with the container suites running, and that the root layout guards, `make pincheck`, `make test-isolated` and `make vuln` pass.
- [x] 11.2 Red: add `TestVerifier_RefusesHeaderWithoutAlg` in `token`, a table over a token signed with the current RS256 key whose header carries its `kid` and `typ` and: no `alg`, an empty `alg`, and a non-string `alg`, each expecting the invalid-token error, plus a control with `alg` present that verifies. In `oidcprovider`, add a hint with no `alg`, signed with a published key, to the authorization endpoint's hint tests (expecting `invalid_request`) and to the end-session endpoint's hint tests (expecting its refusal of a bad hint). Verify that the no-`alg` cases fail today: the verifier returns no error, and the hint is accepted.
- [x] 11.3 Require `alg` in the header before verifying, in `token.Verifier` and in the hint check, refusing as each refuses a bad signature. Correct `token.Verifier`'s comment if it no longer matches. Verify that 11.2 passes, and that `go test -race -count=1 ./token/... ./oidcprovider/...` and the `test` module's token and OIDC provider suites pass.
- [x] 11.4 Changelog: in the `0.1.1` entry, `Changed` names the refusal of a token or hint whose header has no `alg`, and a dependencies line names jwx 4.6.0 and testcontainers 0.45.0. Verify by reading the entry against decision 9.
- [x] 11.5 Run a review of group 11 with a fresh Opus reviewer that edits nothing, against decision 9, the two spec deltas, and the jwx 4.6.0 behaviour changes it lists. It enumerates how the change fails before judging it. Verify that every finding is fixed or recorded in `design.md`.
- [x] 11.7 Fold the group 11 review (decision 9's new rows): red tests first, a `TestVerifyKeySelection` row and a `TestValidateAuthorizationRequest` hint row whose header names `RS384`, and one naming `none`, over a valid RS256 signature, each refused. Show them bite by skipping jwx's algorithm match temporarily (`jws.WithSkipAlgorithmMatch(true)`), then add scrty's own equality check beside the missing-`alg` check in both paths. Fold the `TestVerifier_RefusesHeaderWithoutAlg` rows into `TestVerifyKeySelection`. Move `TestProvider_EndSession_HintMustNameItsAlgorithm`'s rows into `httpsec`'s `TestOIDCEndSession`. Narrow the comment on `errNoAlgorithm` to the missing-`alg` branch. Verify that `go test -race -count=1 ./token/... ./oidcprovider/... ./httpsec/` passes.
- [x] 11.8 The release gate's local proxy writes no `@v/list` (decision 10). Red first: a `tools/cmd/releaseproxy` test that the proxy holds `.info`, `.mod` and `.zip` for the release version and no `list` file, seen failing on the current code. Verify that the `tools` module's tests pass (`cd tools && GOWORK=off go test -count=1 ./...`), and that `make release-check VERSION=v0.1.1` no longer reports `version v0.1.1 already exists` (run in task 8.2).
- [x] 11.6 Close Dependabot pull requests #85 to #95 with a comment that points to this change's pull request, once this branch carries the updates.

## 12. A chain run leaves the caller's exchange as it found it (decision 11; spec "A chain run leaves the caller's exchange as it found it")

One Opus lane, after 10.17: it changes `httpsec/chain.go` and `httpsec/exchange.go` and every test that reads an exchange after its run, so it cannot share the package with another lane.

- [x] 12.1 Red: `TestChain_RunPutsBackTheContextItFound` (in the tree) is red with its 7 cases. Add `TestChain_RunPutsBackTheExchangeItFound`, a table over a chain that assembles a different chain on its own exchange, with an outer interceptor reading the exchange after the inner step returns. It has one case for each field decision 11 restores:
  - `Session`, `Authentication` and `bearerCredential`;
  - the late-renewal fields;
  - `perRequest`, `csrfOptOut` and `raised`.

  It also has these cases:
  - a recovered panic;
  - three chains on one exchange, where each level reads its own run's state after the level below returns;
  - the caller's own context, set with `SetContext` before the outer run, is the one after it;
  - an exchange refused once and run again reports the second refusal (`refusalReported` cleared at the outermost entry);
  - control: an inner refusal is reported once.

  Run it, and report which cases fail. A field whose case passes before any change is reported, not restored. The main session then drops it from decision 11, the spec requirement and the proposal.
- [x] 12.2 Implement the restore in the step `Assemble` returns, deferred, for the context and every field 12.1 showed leaking, and clear `refusalReported` when an outermost run starts. Move the 12 helper sites and 26 tests that read an exchange after its run to read inside the terminal. Find them with gopls references on the helpers, then run the suite. Godoc on `Exchange`, `Exchange.Context` and `Chain.Assemble`: a run's state is read inside the terminal, and the step puts back what it found. Verify:
  - 12.1 passes;
  - `go test ./httpsec/... -count=1 -race`, the ginsec and fibersec suites and the conformance suite pass;
  - `BenchmarkAssemble/run/8` is flat across `-benchtime=1000x` and `-benchtime=16000x`;
  - `benchstat` shows `Assemble/run/8` and `ChainRequest/0` and `/8` allocations unchanged from decision 5's figures.
- [x] 12.3 Changelog (main session): the `0.1.1` `Changed` entry says that an exchange's context, session and authentication read after the chain's step returns are what they were before the run. Verify by reading the entry against decision 11.
- [x] 12.4 Review group 12 with a fresh Opus reviewer that edits nothing, against decision 11, its spec requirement, and decisions 2, 4 and 5, whose rows it must not break. It enumerates how the change fails before judging it. Verify that every finding is fixed or recorded in `design.md`.

## 13. Work detached from the caller's cancellation has a deadline (decision 12; specs `security-state-stores`, `passkey-authentication`)

- [x] 13.1 **(maintainer decision)** Confirm decision 12's fixed bounds (5 s, 10 s for revocations) with no exported option in `v0.1.1`, or choose `v0.2.0` with an option. The reason for no option is Semantic Versioning's rule that a patch adds no API. `gorelease` does not enforce it for a `v0` base. If the maintainer chooses `v0.2.0`, stop: the main session revises decisions 8 and 12, task 9.1 and this group before any code.
- [x] 13.2 Inventory (Sonnet, read-only): list every `context.WithoutCancel`, and every `context.Background()` or `context.TODO()` that detaches work, in production code across the workspace. Use a text search, since this is a call-site inventory, with gopls to find each site's callee. Put each site in decision 12's classes 1–5, with the kind of bound (write or revocation) for class 4, naming the callee and the site's handling of that callee's error. The main session records the table in decision 12 and settles any site the agent marks unsure.
- [x] 13.3 `internal/detach` (Sonnet): red first, `TestBounded`, a table test asserting that the returned context has a deadline at most the given duration away, keeps the parent's values, is not cancelled when the parent is, and is cancelled by its own cancel function. Then implement `func Bounded(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc)`, `const WriteTimeout = 5 * time.Second` and `const RevocationTimeout = 10 * time.Second`. Verify `go test -race -count=1 ./internal/detach/`.
- [x] 13.4 Bound the class-4 sites from 13.2's table, in lanes that each own their packages and those packages' tests:
  - lane A (Sonnet): `authenticate/mfa` and `authenticate/passkey`;
  - lane A2 (Opus, because the fetch runs under singleflight): `authenticate/passkey/webauthn/metadata.go`;
  - lane B (Sonnet): `session` and `recovery`;
  - lane C (Sonnet): `httpsec` outside `chain.go` and `exchange.go`, after group 12 has landed;
  - lane D (Sonnet): every class-4 site 13.2 finds outside lanes A–C, such as `oidcprovider/endsignin.go:181`, `authenticate/oidc` and `policy/lockout`.

  Lanes A, A2, B and D run in parallel with one another; C runs after group 12.

  Each lane goes red first. It adds, per package, a table test whose cases are that package's class-4 sites. A mockgen double of the callee records whether its context has a deadline within the site's bound (5 s for a write, 10 s for a revocation). A second case returns `context.DeadlineExceeded`, so the test can assert the site's existing outcome for a store error. The test also has a case per class-5 site in the package, asserting that the call carries no library deadline: limiter calls, and lane B's session end observers. Run the tests and confirm the class-4 deadline cases fail. Then apply `detach.Bounded` with the site's kind of bound, or the site's own bound where it has one, with the cancel deferred.

  Lane A2's red test is a consumer fetch that waits on its context and is never released. It expects the context to carry a deadline of `outbound.DefaultTimeout`, and the registration to be refused with the attestation-refused refusal. Lane A2 also corrects `MetadataBlob`'s godoc, which promises no deadline.

  Verify each lane's packages with `go test -race -count=1`, then `make lint`.

  Lane B wrote `recovery`'s bounds before its tests, so its red step is redone (maintainer, 2026-11-11). A fresh Sonnet dispatch takes lane B's production edits out of `recovery`, and keeps its tests and `recovery/detached.go`. It runs the tests and confirms that the deadline cases fail because no deadline is carried. Then it puts the edits back unchanged and confirms they pass.
- [x] 13.7 The bound's expiry is not a hang-up (decision 12, settled point; Sonnet). The lane owns `internal/detach`, `internal/hangup` and `token/onetime`'s tests. It runs after lane B's red is redone, because `recovery` compiles against `detach`. Red first:
  - in `hangup`'s `TestByCaller`, add a case: a context from `detach.Bounded` whose bound has passed, with an error matching its `DeadlineExceeded`, is not a hang-up;
  - in `token/onetime`, add a test: `Consume` under a `detach.Bounded` context whose store waits until that context ends logs its failure at ERROR, not DEBUG. Use `testing/synctest` so the bound passes without real waiting.

  Confirm both fail because the call is classed as a hang-up. Then have `detach.Bounded` end its context with an internal cause (`context.WithTimeoutCause`), and have `hangup.ByCaller` report false when that cause ended the context. Keep `TestBounded` and every existing `TestByCaller` case green. Verify `go test -race -count=1 ./internal/... ./token/... ./recovery/... ./session/...` and `make lint`.
- [x] 13.5 Changelog (main session): the `0.1.1` `Changed` entry says that detached store work now has a bound where it had none (5 s, 10 s for revocations), that limiter calls and consumer callbacks are left to their owners, and that a consumer metadata fetch is bounded. Verify by reading the entry against decision 12.
- [x] 13.6 Review group 13 with a fresh Opus reviewer that edits nothing, against decision 12, its two spec deltas and the inventory table. It checks that the inventory search missed no site, and enumerates how the change fails before judging it. Verify that every finding is fixed or recorded in `design.md`.

## 14. A cancelled send, and the remaining context hand-offs (decisions 13, 14; spec `email-notification`)

These are independent of groups 12 and 13 and of one another, so they run in parallel with them as separate lanes. Each group-14 lane runs in its own git worktree (`isolation: worktree`), because the lanes' red steps would otherwise fail the suites and the lint that 10.16 and group 12 run in the shared tree. The main session integrates each lane once its review is clean.

- [x] 14.1 `notify` (Opus, because the connection deadline and the context timer race): red first, port `repro/notify_cancel_repro_test.go.txt` into `notify`'s suite as a table test, `TestSMTPSender_CallerEndedSendReportsContextError`. It has these cases:
  - cancel while waiting for the greeting: the error matches `context.Canceled`, and the sender's logger records nothing at error level;
  - the caller's deadline passes mid-transfer: the error matches `context.DeadlineExceeded`;
  - the sender's own deadline passes with the caller's context live: today's timeout error, not matching either.

  Confirm the first two fail. Then, when the exchange fails, look at the context `Send` received, not the one `send` derives with the sender's deadline. If it has ended, or its deadline has been reached by the clock, join its error with the network error. Have the send-failure log go to DEBUG for such a send, through the library's hang-up classification. Verify `go test -race -count=1 ./notify/...`.
- [x] 14.2 `fibersec` (Sonnet): red first, a test whose log handler reads a value from the request's context, with a stream that panics. It expects the panic record to carry the value. The test sets slog's default logger, so it does not run in parallel. Then log under `context.WithoutCancel` of the request's context, on both the panic and the `Goexit` branches. Verify the fibersec suite.
- [x] 14.3 `oidcprovider/events.go` (Sonnet): make the context value hold what the reuse event needs instead of a context. This is a refactor under the existing event tests. Show they bite by breaking the route temporarily, then restore it by editing it back. Verify `go test -race -count=1 ./oidcprovider/...`.
- [x] 14.4 Godoc (Haiku, wording given by the main session): `expiry/sweep` `Start`, the signing-key lifecycle's `Start` and the memory session store's `Start` say the loop keeps the start context's values, a store transaction included, so start it from a context with no transaction attached. The `ginsec` package and `Middleware` godoc say that when the chain passed the request on, a gin middleware before the chain reads the chain's context on `c.Request` after `c.Next()` returns. The godoc of the session end observer and of the event sink says the library gives their context no deadline, so the consumer's code bounds its own work (decision 12, class 5). Verify with `go doc` and `make lint`.
- [x] 14.5 Changelog (main session): the `0.1.1` `Changed` entry says that a cancelled SMTP send's error matches the context's error. Verify by reading the entry against decision 13.
- [x] 14.6 Review group 14 with a fresh Sonnet reviewer that edits nothing, against decisions 13 and 14 and the `email-notification` delta. It enumerates how the change fails before judging it. Verify that every finding is fixed or recorded in `design.md`.

## Workflow follow-up

- Archive the change after 9.4, syncing `http-security-chain`, `framework-adapters`, `token-issuance`, `oidc-provider-authorization`, `oidc-provider-logout`, `security-state-stores`, `passkey-authentication` and `email-notification`.
- Consider a construction-time authenticator role (`RegisterAuthenticator`) for the next minor (design: Non-Goals).
- Consider, for the next minor, an exported option to lengthen decision 12's bound and a `WithoutTx` helper for background starts (design: Non-Goals).
