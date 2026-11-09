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
- [ ] 8.2 On the branch head, run `make check`, `make release-check VERSION=v0.1.1` (after task 9.1's file changes) and `openspec validate harden-chain-boundary --strict`, with Docker up so the conformance and integration suites run. Verify that all three are clean before the pull request is opened, and that CI on the pull request is green.

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

## Workflow follow-up

- Archive the change after 9.4, syncing `http-security-chain` and `framework-adapters`.
- Consider a construction-time authenticator role (`RegisterAuthenticator`) for the next minor (design: Non-Goals).
