# Harden the chain boundary: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the three security defects reproduced in `v0.1.0` (fiber dot-segment bypass of the rules and of the recovery cool-down; session publication after the gates), make double mounting and duplicate single-value options loud, build the interceptor fold once, and ship `v0.1.1` through an ordinary pull request, disclosing the defects in its changelog.

**Architecture:** All runtime changes sit in the core chain (`httpsec/chain.go`, `httpsec/exchange.go`).
- The fold is prebuilt at construction.
- The step that `Assemble` returns does four things: it records the run's terminal, refuses dot-segment paths, passes a re-entered chain through, and then runs the prebuilt fold.
- The first gate's prebuilt step marks the exchange and its run's marker while the gate's frame runs. Publication is refused while its own exchange is marked, or while an enclosing run of another chain is marked and the publishing chain lacks one of that chain's gates (group 10).
- The authorization stage refuses any session that still owes a built-in challenge.

The adapters change in documentation only.

**Tech Stack:** Go 1.27, `net/http`, gin, fiber v3, testify, mockgen, testcontainers (conformance and integration suites).

**Spec:**
- `openspec/changes/harden-chain-boundary/design.md`, decisions 1 to 8;
- `specs/http-security-chain/spec.md`;
- `specs/framework-adapters/spec.md`;
- `tasks.md`, the task numbers below.

## Global Constraints

- No exported identifier is added or removed (proposal, Impact: API).
- The dot-segment refusal is `ErrMalformedRequest` (400), raised after client resolution and before any interceptor, with no opt-out (decision 1; moved by task 10.4).
- A late `PublishSession` returns an error wrapping `ErrConfig` (500) and publishes neither the caller nor the session (decision 2).
- The single-value refusal text is `"<option> was given twice; one chain has one <thing>"` (decision 6).
- Every Go task is test-first. Its red step is seen failing for the intended reason; a compile error is not a red step (`golang-tdd.md`).
- Table tests use the `table-test` skill (`assert` closure form, `t.Context()`). Mocks come from `use-mockgen`, containers from `use-testcontainers`.
- A defect claim needs a failing test (`defect-claims.md`). The red steps come from `repro/*.go.txt`.
- Agents never run `git checkout --`, `restore`, `reset --hard`, `stash` or `clean`, and never commit, tag or push. The main session owns git and `openspec/`.
- The work happens on the public branch `fix/harden-chain-boundary` and merges through an ordinary pull request with CI. There is no security advisory, no CVE request and no Go vulnerability database report (decision 8).

## Review Focus

1. **A request whose path is already `//`-heavy** (`/a//b`, `//`) must still be served. Pinned in task 3.1's "not refused" cases.
2. **A HEAD request on a refused dot-segment path** gets the same 400. Added to task 3.1 as the case `HEAD /a/../b`.
3. **A refused request under trusted proxies with a forwarded path header** is judged by its request path, not a header. Added to task 3.1: with `EnableTrustedProxies`, `X-Forwarded-Prefix` is ignored, and `/a/../b` is still 400.
4. **A consumer interceptor that publishes `nil` after the gates** (signing out the caller) is not refused, because only a non-nil session is. Added to task 5.1 as the case "nil session after the gates".
5. **A stream** (`EnableSessionSignals`) on a chain mounted twice still opens once and closes cleanly. Added to task 4.1 as the case "stream on a double mount".
6. **Three chains deep** (gated A, then gateless B, then gateless C, each mounted inside the last). C's publication is refused because the walk passes B to find A. Added to task 10.1 as the case "third chain inside the gates".
7. **A gated inner chain inside a gated outer chain** whose own bearer authenticates. It is refused when it lacks one of the outer chain's gates (decision 2's gate-set condition): the outer chain's second-factor gate, the inner's password-change gate only. Added to task 10.1 as the case "gated chain inside the gates". An inner chain with every outer gate publishes; that is the forward case.
8. **An outer run that has finished** (its marker `done`) but whose context is reused by a later chain. A finished run's mark refuses nothing. Added to task 10.1 as the case "finished outer run".

---

### Task 1.1: Prerequisites on `main` (main session)

- [ ] **Step 1:** Run `git fetch origin && git log origin/main --oneline -- .github/workflows/release-probe.yml`. It must show the commit adding `workflow_dispatch`. Then run `git grep -n TestExportedParametersHaveDescriptiveNames origin/main -- layout_test.go`, which must find the guard. If either check fails, stop: `release-readiness` and `descriptive-parameter-names` land first.

### Task 1.2: Branch (main session)

- [ ] **Step 1:** Run `git switch -c fix/harden-chain-boundary origin/main`. The untracked `openspec/changes/harden-chain-boundary/` directory comes along.
- [ ] **Step 2:** Verify that `git branch --show-current` prints `fix/harden-chain-boundary` and that `git merge-base HEAD origin/main` equals `git rev-parse origin/main`.

---

### Task 2.1–2.2: Prebuilt fold (Opus implementer, Opus reviewer)

**Files:**
- Modify: `httpsec/chain.go` (`Chain`, `Assemble`, `build`)
- Modify: `httpsec/exchange.go` (`Exchange`)
- Test: `httpsec/chain_fold_test.go` (new)
- Test: `httpsec/chain_bench_test.go` (new, ported from `repro/httpsec_assemble_bench_test.go.txt`)

**Interfaces:**
- **Produces, in `Chain`:**
  - `fold Next`, the prebuilt outermost step;
  - `firstGate int`, the index in run order of the first registration whose interceptor is `*recoveryGate`, `*enrolmentInterceptor`, `*mfaInterceptor` or `*passwordChangeGate`, or -1 when there is none. Task 5.2 uses it.
- **Produces, in `Exchange`:**
  - `terminals [2]runTerminal` and `extra []runTerminal`, where `type runTerminal struct{ chain *Chain; next Next }`;
  - `func (e *Exchange) pushTerminal(c *Chain, t Next)`, `func (e *Exchange) popTerminal(c *Chain)` and `func (e *Exchange) terminalFor(c *Chain) (Next, bool)`, which returns the topmost entry for `c`.
- **The innermost prebuilt step** calls `terminalFor(c)`. When there is no entry, it returns `fmt.Errorf("%w: an interceptor passed on an exchange this chain is not running", ErrConfig)`.

- [ ] **Step 1: Baseline.** Port the benchmarks as `BenchmarkAssemble` (8 consumer interceptors, `Assemble` plus run) and `BenchmarkChainRequest` (net/http, 0 and 8 interceptors). Run `go test -run XXX -bench 'BenchmarkAssemble|BenchmarkChainRequest' -benchmem -count=10 ./httpsec/ > <scratch>/fold-before.txt`.
- [ ] **Step 2: Write the failing test.** `TestAssemble_TerminalPerRun` is a table test with cases:
  - "foreign exchange": an interceptor calls `next(NewExchange(ex.Context(), ex.Request, ex.Writer))`. Assert `errors.Is(err, ErrConfig)` and that the terminal was not called.
  - "nested different chain": an interceptor of chain A runs `B.Assemble(next)(ex)`. Assert the order `[A-int, B-int, A-terminal]`.
  - "next twice": assert the terminal ran twice.
  - "concurrent": 64 goroutines, each with its own terminal recording its own id. Assert each saw its own.
- [ ] **Step 3: Run it.** `go test -run TestAssemble_TerminalPerRun -race -count=1 ./httpsec/`. Expected: only "foreign exchange" fails, because the terminal runs.
- [ ] **Step 4: Implement.** `build` composes `fold` from the sorted registrations. `Assemble(terminal)` returns a step that pushes the terminal, runs the existing entry logic, calls `c.fold(ex)`, and pops on return via `defer`.
- [ ] **Step 5: Verify.**
  - `go test ./httpsec/... -race -count=1` passes;
  - `cd test && go test ./httpsecconformance/... -count=1` passes;
  - benchmarks are re-run into `fold-after.txt`, and `benchstat fold-before.txt fold-after.txt` shows `BenchmarkAssemble/only/8` (the fold alone) at 2 allocs/op or fewer;
  - the main session records the numbers in design decision 5.

### Task 3.1–3.4: Dot-segment refusal (Opus implementer, Opus reviewer)

**Files:**
- Modify: `httpsec/chain.go` (the step `Assemble` returns)
- Create: `httpsec/path_canonical.go`, holding `func refuseDotSegments(escaped string) error`
- Test: `httpsec/path_canonical_test.go`
- Test: `httpsec/fibersec/pathdiff_test.go` (ported)
- Test: `httpsec/ginsec/pathdiff_test.go` (ported)
- Modify: `test/httpsecconformance/request_scenarios.go`
- Godoc: `httpsec/exchange.go` (`Request.Path`), `httpsec/authorization.go`, `httpsec/headers.go` (`PathPrefix`), `httpsec/recovery_cooldown.go`

**Interfaces:**
- **Produces:** `refuseDotSegments(escaped string) error`. It returns nil, or an error wrapping `ErrMalformedRequest`. It splits both `escaped` and `url.PathUnescape(escaped)` on `/`, and refuses a `.` or `..` segment in either. It also refuses a path that fails to decode.

- [ ] **Step 1: Write the failing tests.**
  - `TestChain_RefusesDotSegments`, through `Middleware()`. Expect 400 with no handler call for:
    - `/a/../b`, `/a/./b`, `/a/%2e%2e/b`, `/a/%2E%2E/b`, `/a%2F..%2Fb`;
    - `HEAD /a/../b`;
    - `/a/../b` with `EnableTrustedProxies` and `X-Forwarded-Prefix: /x`;
    - a test `Request` whose `EscapedPath()` is `/a/%zz`.

    Expect the handler to be called for `/files/report..v2.txt`, `/.well-known/jwks.json` and `/a//b`.

    With `EnableSecurityHeaders()`, the 400 carries `X-Content-Type-Options: nosniff`.
  - Port `TestFiber_AuthorizationRuleSeesRoutedPath` and `TestFiber_RecoveryCooldownSeesRoutedPath` from the repro file, dropping the upper-case case and switching the assertion to `assert.Equal(t, 400, status)`.
- [ ] **Step 2: Run.**
  - `go test -run TestChain_RefusesDotSegments -count=1 ./httpsec/`;
  - `cd httpsec/fibersec && go test -run 'TestFiber_(AuthorizationRule|RecoveryCooldown)SeesRoutedPath' -count=1 .`

  Expected: FAIL. The handler runs with 200.
- [ ] **Step 3: Implement.** Call `refuseDotSegments(ex.Request.EscapedPath())` first in the returned step. On error, apply `c.headers.applyHeaders` and `c.refusalSteps` exactly as the client-resolution refusal does, and return the error.
- [ ] **Step 4: Verify.** Run `go test ./httpsec/... -count=1` in the root, in `httpsec/fibersec` and in `httpsec/ginsec`. The ported `TestGin_NonCanonicalTargetsNeverReachTheHandler` passes. (Task 3.2.)
- [ ] **Step 5: Conformance (task 3.3, Sonnet).** Add the scenario "dot segments are refused on every adapter". It sends raw request lines for `/x/%2e%2e/y` and `/public/../admin/users` over `net.Dial`. Assert 400 and an empty body.
  - Run `cd test && go test ./httpsecconformance/... -run 'Scenarios' -count=1` and expect PASS.
  - Comment out the call from step 3 and expect FAIL. Restore it by editing it back.
- [ ] **Step 6: Godoc (task 3.4, Sonnet).**
  - `Request.Path`: "The chain refuses a path with a `.` or `..` segment before anything reads it; Path is otherwise the path as sent, decoded, and may differ from the path a router serves in letter case and trailing slashes."
  - `EnableAuthorization` and `PathPrefix`: the fiber case and trailing-slash sentence, and the HEAD sentence.
  - `EnableRecoveryCooldown`: the dot-segment sentence.

  Verify with `go doc ./httpsec Request.Path` (and the others), then `make lint`.

### Task 4.1–4.3: Same chain runs once (Opus implementer, Opus reviewer)

**Files:**
- Modify: `httpsec/chain.go`
- Test: `httpsec/chain_reentry_test.go`
- Test: `httpsec/ginsec/double_mount_test.go` (ported)
- Test: `httpsec/fibersec/double_mount_test.go`
- Godoc: `httpsec/ginsec/doc.go` and `middleware.go`, `httpsec/fibersec/doc.go` and `middleware.go`

**Interfaces:**
- **Produces:**
  - `type chainRun struct{ chain *Chain; method, path string }`, stored under the unexported key `chainRunKey{}`;
  - `func ranOn(ctx context.Context, c *Chain, method, path string) bool`. It walks only the nearest marker, which links to its parent's.

- [ ] **Step 1: Write the failing tests.**
  - `TestRepro_DoubleMount`, ported for gin and written fresh for fiber. Assert one authenticator call and one limiter `Reset`.
  - `TestChain_ReentryPassesThrough`, with cases:
    - same chain nested: the interceptor count is 1;
    - different chain nested: both run;
    - same chain on an in-process forward to `/other`: it runs twice;
    - stream on a double mount: the signal stream opens once and the handler returns.
- [ ] **Step 2: Run.** Both double-mount tests fail with `expected: 1, actual: 2`. The forward case passes.
- [ ] **Step 3: Implement.** In the returned step, after the dot-segment check: if `ranOn(ex.Context(), c, method, escapedPath)`, return the terminal's result directly. Otherwise put the marker on the context before client resolution.
- [ ] **Step 4: Verify.** The three adapter suites and the conformance suite pass. (Task 4.2.)
- [ ] **Step 5: Godoc (task 4.3, Sonnet).** Add the three sentences of design decision 7 to `ginsec` and `fibersec`. Verify with `go doc` and `make lint`.

### Task 5.1–5.3: No publication after the gates (Opus implementer, Opus reviewer)

**Files:**
- Modify: `httpsec/chain.go`, the prebuilt step at `firstGate`
- Modify: `httpsec/exchange.go`: `PublishSession`, and a new unexported `publishSession`
- Modify: `httpsec/resolve.go`, and every caller that gopls reports
- Test: `httpsec/publish_after_gates_test.go` (ported)

**Interfaces:**
- **Consumes:** `Chain.firstGate` (task 2).
- **Produces:**
  - `Exchange.gatesBegun bool`;
  - `func (e *Exchange) publishSession(a *authenticate.Authentication, s *session.Session) error`, which is today's body of `PublishSession`;
  - `PublishSession`, which returns `fmt.Errorf("%w: a session was published after the chain's gates had begun; register the authenticator at OrderBearerToken", ErrConfig)` when `e.gatesBegun && s != nil`.

- [ ] **Step 1: Write the failing test.** Port `TestRepro_ConsumerAuthenticatorAfterGatesIsJudgedByThem` with all ten cases. The six late cases expect status 500, `errors.Is(publishErr, ErrConfig)` and no handler call. Add the cases:
  - "no gate enabled": publishing succeeds and the handler reads the session;
  - "nil session after the gates": no error, and the caller is cleared.
- [ ] **Step 2: Run.** `go test -run TestRepro_ConsumerAuthenticator -count=1 ./httpsec/`. Expected: the six late cases fail with 200.
- [ ] **Step 3: Audit.** Run `gopls references` on `Exchange.PublishSession` and on the `Exchange.Session` field. Move every library caller to `publishSession`. The implementer reports the list.
- [ ] **Step 4: Implement.** The prebuilt step at `firstGate` sets `ex.gatesBegun = true` before calling the gate. `PublishSession` checks it, and on refusal writes one record through `logSampled` with the key `"late-session-publication"`.
- [ ] **Step 5: Verify.** `go test ./httpsec/... -race -count=1` and the conformance suite pass. (Task 5.2.)
- [ ] **Step 6: Godoc (task 5.3, Sonnet).** `PublishSession` gets the refusal and the slots to use. `RegisterInterceptor` gets those slots, plus the sentence about built-in slot-mates running in option order. Verify with `go doc` and `make lint`.

### Task 6.1–6.3: Authorization-stage backstop (Opus implementer, Opus reviewer)

**Files:**
- Modify: `httpsec/authorization.go` (`authorization.Intercept`)
- Test: `httpsec/authorization_owing_test.go`, `httpsec/gate_exemptions_test.go`

**Interfaces:**
- **Consumes:**
  - `owedChallenge(*session.Session) policy.ChallengeKind` (`full_session.go`);
  - the gates' existing error constructors;
  - `Chain.challengeMethods`, for MFA.
- **Produces:** the stage refuses when `ex.Session != nil && owedChallenge(ex.Session) != policy.ChallengeNone`.

- [ ] **Step 1: Write the enumeration test.** `TestGateExemptions_NeverReachTheAuthorizationStage` builds, for each gate, a session owing that gate's challenge. It sends a request to each exempted endpoint and asserts that a consumer interceptor at `Before(OrderAuthorizer)` never runs. It passes today.
- [ ] **Step 2: Prove it bites.** Temporarily exempt `/consumer` in the password-change gate, and confirm the test fails. Restore it by editing it back. If the test fails without that edit, stop and report the exemption.
- [ ] **Step 3: Write the failing test.** `TestAuthorization_RefusesOwingSession` is a table over recovery, enrolment, MFA and password change, each with rules and without. A consumer interceptor at `After(OrderLogout)` sets `ex.Session` directly. Assert the gate's error via `errors.As(err, &*ChallengeError)` with the matching kind, and for MFA its methods. The "full session" case expects 200.
- [ ] **Step 4: Run.** Expected: the owing cases fail with 200.
- [ ] **Step 5: Implement** the check before `a.rules` is consulted.
- [ ] **Step 6: Verify.** The `httpsec` suite and the conformance suite pass. (Task 6.3.)

### Task 7.1–7.3: Single-value options (Sonnet implementer, Sonnet reviewer; may run beside task 2)

**Files:**
- Modify: `httpsec/options.go` (`WithLogger`, `WithClock`, `WithPolicyEngine`, `WithRateLimiterFactory`, `WithErrorHandler`)
- Modify: `httpsec/authorization.go` (`EnableAuthorization`)
- Test: `httpsec/options_once_test.go`

**Interfaces:**
- **Produces:** the `config` fields `loggerGiven`, `clockGiven`, `engineGiven`, `limiterFactoryGiven` and `errorHandlerGiven` (all `bool`). The `<thing>` names are "logger", "time source", "policy engine", "rate-limiter factory" and "error handler".

- [ ] **Step 1: Write the failing tests.**
  - `TestNew_SingleValueOptionGivenTwice`: five options times {same value, two values}. Assert `errors.Is(err, ErrConfig)` and that the message contains the option's name.
  - `TestEnableAuthorization_ChecksEveryAuthorizer`: the case "nil then valid" expects an error naming `EnableAuthorization` and "authorizer". The case "two valid" expects success, both rules applied in order, and the second authorizer judging them.
- [ ] **Step 2: Run.** `go test -run 'TestNew_SingleValueOptionGivenTwice|TestEnableAuthorization_ChecksEveryAuthorizer' -count=1 ./httpsec/`. Expected: FAIL with `An error is expected but got nil`, except the "two valid" case.
- [ ] **Step 3: Implement** the given-flags, and `requireDep` on each `EnableAuthorization` call's `az` when that call is applied.
- [ ] **Step 4: Verify.** `make test` passes across the workspace, with no chain anywhere giving a duplicate option.
- [ ] **Step 5: Godoc (task 7.3).** Add "Given twice, New refuses the chain." to each of the five options. Verify with `go doc`.

---

### Task 8.1: Whole-branch review

- [ ] **Step 1:** Dispatch a fresh Opus reviewer that edits nothing. It reads both spec deltas and design decisions 1 to 7, enumerates the failures category by category, and then checks the diff. Each finding is fixed in a fresh dispatch of the owning lane, or declined in `design.md`.

### Task 8.2: Local gate, then CI on the pull request

- [ ] **Step 1:** With Docker running, after task 9.1, group 10 (task 10.8 clean) and group 11 (tasks 11.5, 11.7 and 11.8 done):
  - `make check`;
  - `make release-check VERSION=v0.1.1`;
  - `openspec validate harden-chain-boundary --strict`.

  Save the output to the scratchpad. All three must pass before the pull request is opened.
- [ ] **Step 2:** After the pull request is opened, `gh pr checks <pr> --watch` ends with every check passing.

### Group 10: Review and security findings

The proofs are in `repro/` and ran red on `fcec3a8f` (design, Reproductions). Lane A (10.1–10.4) runs in order on Opus, because it is ordering on the hot path and security refusal logic. Lane B (10.5–10.6) runs on Sonnet beside it. Each prompt carries the Global Constraints, the failure rows of the decision it covers, and the files it must not touch.

### Task 10.1–10.2: Frame-scoped gate mark, refused inside another chain's gates (lane A, Opus implementer, Opus reviewer)

**Files:**
- Modify: `httpsec/chain.go` (`chainRun`, the first gate's frame in `buildFold`, the comment in the step `Assemble` returns that says a nested run "keeps the outer run's mark")
- Modify: `httpsec/exchange.go` (`PublishSession`, `publishSession`, the late-publication error)
- Test: `httpsec/publish_after_gates_test.go` (extend)

**Interfaces:**
- Produces: `chainRun.gatesBegun atomic.Bool`; `func gatesRunning(ctx context.Context, c *Chain) bool`, which walks `nearestRun(ctx)` and its `parent` links and reports any run not `done` whose `gatesBegun` is set and whose chain enables a gate `c` does not (decision 2's gate-set condition; a run of `c` itself never counts). Each `Chain` holds its enabled gates as a fixed-size value computed in `build` from the one helper that names the four gates (decision 3), so the comparison allocates nothing; `errPublishedInsideGates`, a second error wrapping `ErrConfig` whose text says to "mount this chain outside the other chain's gates or authenticate in the outer chain".
- Consumes: `nearestRun`, `chainRun.done`, `Exchange.gatesBegun` (task 5.2).

- [ ] **Step 1: Red.** Port both tests from `repro/httpsec_gatemark_repro_test.go.txt` into `publish_after_gates_test.go` with the package's helpers. Keep their cases and controls, and add:
  - "built-in authenticator inside the gates": chain B uses the session bearer, not a consumer authenticator. Expect 500, and the handler not run.
  - "third chain inside the gates", "gated chain inside the gates" and "finished outer run" (Review Focus 6–8). The first two expect 500. The last expects publication to succeed.
  - "gate panics": the first gate panics, the panic is recovered, and a second `Assemble` run of the same exchange publishes at `OrderBearerToken`, which must succeed.
  - "forward through the same chain" (control): a chain with the second-factor gate and an authenticator at `OrderBearerToken`; its handler serves `r.Clone(r.Context())` for another path through `c.Middleware()`. The forward's authenticator publishes a full session; expect 204 from the forwarded handler and no `ErrConfig`.
  - "forward through a chain with the same gates": the handler forwards through a different chain that also enables the second-factor gate, whose authenticator publishes a session owing a second factor. Expect publication to succeed and that chain's gate to refuse with its `ChallengeError` (kind `ChallengeMFA`); the forwarded handler does not run.
  - "chain with fewer gates inside the gates": outer chain enables the second-factor and password-change gates; the inner chain only the password-change gate, and publishes a session owing a second factor. Expect 500 and `ErrConfig`, handler not run.
  - `TestGatesRunning` (internal) gains cases for the gate-set comparison: an enclosing marked run whose chain's gates the publishing chain covers (false), lacks one (true), and two marked enclosing runs where only the outer one is uncovered (true).
- [ ] **Step 2:** Run `go test -run 'TestChain_RetriedPassPublishesBeforeGates|TestChain_SecondChainCannotPublishPastFirstChainsGates' -count=1 -v ./httpsec/`. Expected:
  - the retried pass FAILs with `a session was published after the chain's gates had begun`;
  - each nested case FAILs with status 200 and the handler run;
  - the controls PASS.
  On the task 10.2 tree as first implemented (refusing every enclosing marked run), the two forward cases and `TestReauthResolve`'s racing-renewal case are the red step for the gate-set condition: they FAIL with `a session was published by a chain run inside another chain's gates` (500), and the fewer-gates case PASSes.
- [ ] **Step 3: Implement.**
  - **The first gate's frame:** saves `ex.gatesBegun` and sets it, then sets `gatesBegun` on this chain's own run (the nearest run whose `chain` is this chain). It restores both in a `defer`. `terminalCount() == 1` no longer clears the mark.
  - **`PublishSession`:** refuses with `errLatePublication` when `ex.gatesBegun` is set, and with `errPublishedInsideGates` when `gatesRunning(ex.Context(), chain)` is true, `chain` being the chain whose run published.
  - **`publishSession`:** refuses with `errPublishedInsideGates` when `gatesRunning(ex.Context(), chain)` is true. The resolution core returns that error unchanged.
  - **Logging:** both refusals go through the existing sampled late-publication log.
- [ ] **Step 4:** Run `go test ./httpsec/... -count=1 -race`, then `go test -count=1 ./...` in `httpsec/ginsec` and `httpsec/fibersec`, then the conformance suite (`go test -count=1 ./httpsecconformance/...` in `test`, with Docker running). Expected: PASS, including `TestPublishSession_GateMarkOnOneExchange`, the late-authenticator suite from task 5.1, and `TestReauthResolve`.

### Task 10.3–10.4: Entry check after client resolution (lane A, after 10.2; Opus implementer, Opus reviewer)

**Files:**
- Modify: `httpsec/chain.go` (the step `Assemble` returns; `refuseAtEntry`)
- Modify: `httpsec/path_canonical.go`, and `Request.Path` godoc in `httpsec/exchange.go`, wherever they say "before client resolution"
- Test: `httpsec/path_canonical_test.go` (extend)

**Interfaces:**
- Consumes: `refuseDotSegments(escaped string) error`, `c.clients.begin(ex)`.

- [ ] **Step 1: Red.** Port `TestChain_EntryRefusalCarriesSecureHeadersBehindTrustedProxy` from `repro/httpsec_entry_backstop_repro_test.go.txt`, with both controls:
  - a clean path carries `Strict-Transport-Security`;
  - an untrusted peer that forges `X-Forwarded-Proto: https` gets none.

  Add the case "client resolution refuses first": a forwarded host that the allowlist refuses, on `/a/../b`. It expects the client-resolution refusal's status and error, not `ErrMalformedRequest`.
- [ ] **Step 2:** Run `go test -run 'TestChain_EntryRefusalCarriesSecureHeadersBehindTrustedProxy' -count=1 -v ./httpsec/`. Expected: the main case FAILs with `Strict-Transport-Security` empty, and the controls PASS.
- [ ] **Step 3: Implement.** Move the `refuseDotSegments` call to just after a successful `c.clients.begin(ex)`. The refusal is written as it is today, through `refuseAtEntry`. No interceptor runs before it.
- [ ] **Step 4:** Run `go test ./httpsec/... -count=1 -race` and the conformance dot-segment scenario on all three adapters. Expected: PASS, including `TestChain_RefusesDotSegments` and `TestFiber_AuthorizationRuleSeesRoutedPath`.

### Task 10.5: Backstop log on a method-lookup failure; one nil-authorizer check (lane B, Sonnet implementer, Sonnet reviewer)

**Files:**
- Modify: `httpsec/authorization.go` (`owedRefusal`, `logOwing`, `EnableAuthorization`)
- Test: `httpsec/authorization_owing_test.go` (extend)

**Must not touch:** `httpsec/chain.go`, `httpsec/exchange.go` (lane A).

- [ ] **Step 1: Red.** Port `TestAuthorization_BackstopSurfacesMethodLookupFailure` (both cases: status and log) and `TestAuthorization_BackstopLooksUpMethodsOnlyForSecondFactor` from `repro/httpsec_entry_backstop_repro_test.go.txt`. The log case asserts a record whose message contains `could not be looked up` and that carries no error text, session ID or user ID.
- [ ] **Step 2:** Run `go test -run 'TestAuthorization_Backstop' -count=1 -v ./httpsec/`. Expected:
  - the log case FAILs with `only the wiring-mistake record exists`;
  - the status case PASSes;
  - the method-lookup test PASSes.
- [ ] **Step 3: Implement.** On a lookup error, `owedRefusal` writes one sampled error record per chain. Its message is `httpsec: session owing a built-in challenge reached the authorization stage; its second-factor methods could not be looked up`, and its `hint` is the existing one. It returns the error unchanged. The wiring record stays for the success path. Remove the deferred nil-authorizer check `EnableAuthorization` registers through `c.enable`. This step has no red: `TestEnableAuthorization_ChecksEveryAuthorizer` covers the check that remains.
- [ ] **Step 4:** Run `go test ./httpsec/... -count=1`. Expected: PASS.

### Task 10.6: Pin the double-mount pass-through (lane B, Sonnet implementer, Sonnet reviewer)

**Files:**
- Test: `httpsec/ginsec/double_mount_test.go` (extend)

- [ ] **Step 1:** Port `repro/ginsec_double_swap_repro_test.go.txt` as `TestGin_DoubleMountPassesRewritesThrough`, asserting the accepted outcome (decision 4):
  - **credential swap:** the handler sees `u-1`, and the authenticator ran once;
  - **invalid credential swap:** 200, and the handler sees `u-1`;
  - **Host swap and query swap:** the handler runs;
  - **no middleware:** the chain runs once;
  - **path rewrite:** the authenticator ran twice, and the handler sees `u-2`.
- [ ] **Step 2: Make it bite.** Temporarily make `ranOn` return false, then run `go test -run TestGin_DoubleMountPassesRewritesThrough -count=1 -v .` in `httpsec/ginsec`. Expected: the swap cases FAIL. Restore `ranOn` by editing it back, never with git.
- [ ] **Step 3:** Run `go test -count=1 ./...` in `httpsec/ginsec`. Expected: PASS.

### Task 10.7: Changelog (main session; `CHANGELOG.md` is release prose)

- [ ] **Step 1:** In `## [0.1.1]` → `### Security`, extend the third bullet: an authenticator in a second chain run inside the gates, through any adapter, is refused the same way. In `### Changed`, remove any "before client resolution" wording from the 400 entry. Verify with `grep -n 'client resolution' CHANGELOG.md`, which must print nothing that contradicts decision 1.

### Task 10.8: Review of group 10 (Opus reviewer, edits nothing)

- [ ] **Step 1:** Dispatch a fresh Opus reviewer over the group 10 diff. It works against:
  - the revised `http-security-chain` requirements "A request path with a dot segment is refused before the chain runs" and "A session cannot be published once the gates have begun";
  - decisions 1–4 and 6, and their failure rows.

  It enumerates how the change fails before judging it. Each claimed defect carries a failing test or the `UNREPRODUCED` label. Findings go to a fresh dispatch of the owning lane, or are recorded in `design.md` by the main session.

### Group 11: Dependencies and the header algorithm (decision 9)

Task 11.1 is done: the dependency agent applied the updates in an isolated worktree and ran the whole workspace there; the main session applied its `go.mod`/`go.sum` diff and the CodeQL pins. Tasks 11.2–11.3 are one dispatch on Opus (security refusal logic written for the first time), owning `token/` and `oidcprovider/` only, so it runs beside lane A's 10.3–10.4.

### Task 11.2–11.3: Refuse a header with no `alg` (Opus implementer, Opus reviewer in 11.5)

**Files:**
- Modify: `token/verifier.go` (the header check after the signature, `checkTokenType` or a sibling; the comment that says a header naming none fails)
- Modify: `oidcprovider/authorize.go` (`judgeHintToken`)
- Test: `token/verifier_test.go`, `oidcprovider/authorize_test.go`, `oidcprovider/endsession_test.go` (extend)

**Must not touch:** `httpsec/` (lane A), any `go.mod`/`go.sum`, `CHANGELOG.md`, `openspec/`.

**Interfaces:**
- Consumes: `ErrInvalid` (token), the hint verdicts `hintRefused` and friends (oidcprovider).
- Produces: no exported identifier.

- [ ] **Step 1: Red.** `TestVerifier_RefusesHeaderWithoutAlg`, a table over a token signed with the current RS256 key whose protected header carries its `kid` and `typ` and: no `alg`; `"alg":""`; `"alg":1`. Each asserts `errors.Is(err, ErrInvalid)` and no claims. A control with `alg` `RS256` verifies. Build the tokens by signing the header and payload bytes with the key directly, since jwx's signer always writes `alg`. In `oidcprovider`, add a hint with no `alg`, signed with a published key, as a case of the authorization endpoint's hint tests (expect `invalid_request`) and of the end-session endpoint's hint tests (expect its existing refusal of a bad hint).
- [ ] **Step 2:** Run `go test -run 'TestVerifier_RefusesHeaderWithoutAlg' -count=1 -v ./token/` and the two hint tests. Expected: the no-`alg` cases FAIL (no error from the verifier; the hint accepted); the empty and non-string cases may already pass, and the control passes.
- [ ] **Step 3: Implement.** Before trusting the parsed token, read the protected header through `jws.Parse` (as `checkTokenType` already does) and refuse when `alg` is absent or empty, with `ErrInvalid` in the verifier and the bad-signature verdict in the hint check. One unexported helper per package is enough; no shared package is added for it.
- [ ] **Step 4:** Run `go test -race -count=1 ./token/... ./oidcprovider/...`, and in `test` the token and OIDC provider suites (`go test -race -count=1 -run 'Token|OIDCProvider|Provider' ./...`, Docker up). Expected: PASS.

### Task 11.4: Changelog (main session)

- [ ] **Step 1:** In `## [0.1.1]` → `### Changed`, add: token verification and the ID token hint check refuse a header with no `alg` (and that `token.Verifier` accepted one on `v0.1.0`, against its documentation). Add a `Changed` line naming the dependencies: jwx 4.6.0, testcontainers 0.45.0 (test module). The changelog follows Keep a Changelog, which has no dependencies section.

### Task 11.5: Review of group 11 (Opus reviewer, edits nothing)

- [ ] **Step 1:** Dispatch a fresh Opus reviewer over the group 11 diff (the `go.mod`/`go.sum` changes, `ci.yml`, `token/`, `oidcprovider/`), against decision 9, the `token-issuance` and `oidc-provider-authorization` deltas, and the jwx 4.6.0 changes decision 9 lists. It enumerates how the change fails before judging it.

### Task 10.9: The whole-branch review's open findings (maintainer)

- [ ] **Step 1:** The maintainer chooses, for each finding in design.md's Open Questions, a fix or an accepted row. A fix starts from the matching test in `repro/httpsec_review108_repro_test.go.txt` as its red step, on Opus (security refusal logic on the hot path).

### Task 10.10: Pin each header and publishing check on its own (Sonnet implementer)

**Files:**
- Test: `token/verifier_internal_test.go` (create, `package token`), `oidcprovider/authorize_internal_test.go` (create or extend, `package oidcprovider`), `httpsec/publish_inside_gates_internal_test.go` (extend)

- [ ] **Step 1:** Table tests calling the unexported helpers directly: `matchesKey` refuses a header `alg` that differs from every key under its `kid`; the header reader refuses a missing and an empty `alg`; `namesAlgorithm` refuses a header `alg` that differs from the key's. Each must fail when that one check is removed (edit, run, edit back).
- [ ] **Step 2:** A `publishingChain` test with a two-entry run stack whose top entry's terminal is running: the result is the entry below. It must fail when the running filter is removed.
- [ ] **Step 3:** `go test -race -count=1 ./token/... ./oidcprovider/... ./httpsec/`. Expected: PASS.

### Task 10.11: Built-ins judge a session an enclosing chain published (Opus implementer: security refusal logic on the hot path)

**Files:**
- Create: `httpsec/request_session.go` (one unexported helper, `requestSession(ex *Exchange) *session.Session`: `ex.Session` when set, else the session on `ex.Context()`)
- Modify: every built-in that reads the request's session to judge it. Find them with gopls references on `Exchange.Session`; at least the recovery gate, the enrolment gate, the second-factor gate (`mfa_verify.go`), the password-change gate, the recovery cool-down, and the authorization stage's backstop (`authorization.go`)
- Test: `httpsec/nested_session_test.go` (create)

**Must not touch:** `httpsec/exchange.go`, `httpsec/chain.go` (task 10.12 runs beside it).

- [ ] **Step 1: Red.** Port `TestReview108_GatedChainInsideGatelessOuterServesOwingSession` as a table: an owing session from the enclosing chain, for each of the four gates and the cool-down, is refused with that built-in's own error and status, and the handler does not run; a full session is let through and the inner handler reads it; when the inner chain resolves its own session, that one is judged.
- [ ] **Step 2:** Run it. Expected: the owing cases FAIL with 200; the controls PASS.
- [ ] **Step 3: Implement** the helper and use it in each built-in. A built-in that also writes the session back (for example after a renewal) keeps writing `ex.Session` as today.
- [ ] **Step 4:** `go test ./httpsec/... -count=1 -race`, the ginsec and fibersec suites, and the conformance suite. Expected: PASS.

### Task 10.12: The exchange's mark records its chain (Opus implementer, beside 10.11)

**Files:**
- Modify: `httpsec/chain.go` (the first gate's frame), `httpsec/exchange.go` (the mark field, `PublishSession`)
- Test: `httpsec/publish_after_gates_test.go` (extend)

**Interfaces:** each run's entry on the exchange (`runTerminal`) carries its own `gatesBegun`, set and restored by its gate frame; the exchange-level bool goes. `gateMarkRefusal` decides before `publishSession`: the publishing run's own mark is `errLatePublication`; another marked run on the exchange is `errPublishedInsideGates` unless the publisher covers its gates; `gatesRunning` then covers enclosing runs on other exchanges. (Implemented this way rather than recording only the chain, which would miss an outer chain's late authenticator behind a covering chain; design decision 2.)

- [ ] **Step 1: Red.** Port `TestReview108_SameExchangeCoveringChainPublishes`, and add: the inner chain's own late authenticator on the shared exchange is refused; a nested chain lacking a gate on the shared exchange is refused. Expected today: the covering case FAILs with the late-publication error; the other two PASS.
- [ ] **Step 2: Implement** as in Interfaces. A publication from the handler (`publishingChain()` nil) stays refused by the gate-set check.
- [ ] **Step 3:** `go test ./httpsec/... -count=1 -race`. Expected: PASS, including the retried-pass, late-authenticator, gate-panics and forward suites.

### Task 10.13: Changelog (main session)

- [ ] **Step 1:** Extend the `0.1.1` Security entry with the gated chain inside a gateless chain, affecting `v0.1.0`.

### Task 10.14: Review of 10.11–10.12 (Opus reviewer, edits nothing)

- [ ] **Step 1:** A fresh reviewer over the 10.11–10.12 diff, against decisions 2 and 3 and the two requirements, enumerating failures first.

### Task 10.15: Gate again (main session)

- [ ] **Step 1:** `make check`; `make release-check VERSION=v0.1.1` in a clean worktree of the head, not at the same time as `make check` (golangci-lint refuses a parallel run); `openspec validate harden-chain-boundary --strict`; then `gh pr checks 100 --watch`. Expected: all green.

### Task 11.7: Fold the group 11 review (Opus implementer: security verification logic; Opus reviewer in 10.8's whole-branch pass)

**Files:**
- Modify: `token/verifier.go` (`readHeader` or a sibling: equality of the header `alg` with the selected key's algorithm; the `errNoAlgorithm` comment), `oidcprovider/authorize.go` (`namesAlgorithm` becomes the equality check against `signature`)
- Test: `token/verifier_test.go` (`TestVerifyKeySelection` rows; fold `TestVerifier_RefusesHeaderWithoutAlg` into it), `oidcprovider/authorize_test.go`, `httpsec/oidc_endsession_test.go` (`TestOIDCEndSession` rows), `oidcprovider/endsession_test.go` (remove the moved test)

**Must not touch:** `httpsec/chain.go`, `httpsec/exchange.go`, `httpsec/resolve.go`, `httpsec/path_canonical*.go`, `httpsec/nethttp.go` (lane A, 10.3–10.4), `go.mod`/`go.sum`, `openspec/`.

- [ ] **Step 1: Red.** Rows with header `{"alg":"RS384"}` and `{"alg":"none"}`, the current `kid` and `typ`, signed RS256: the verifier returns `ErrInvalid`; as a hint, `invalid_request`. They pass today, so make them bite: add `jwt.WithVerifyOption(jws.WithSkipAlgorithmMatch(true))` temporarily, see them FAIL (the token verifies, the hint is accepted), and remove it by editing.
- [ ] **Step 2: Implement** the equality check in both paths, refusing as a missing `alg` is refused. Fold and move the tests as listed.
- [ ] **Step 3:** `go test -race -count=1 ./token/... ./oidcprovider/... ./httpsec/`. Expected: PASS.

### Task 11.8: Release proxy without a version list (Sonnet implementer; the gate's own tooling)

**Files:**
- Modify: `tools/cmd/releaseproxy/main.go` (the function that writes `@v/` files)
- Test: `tools/cmd/releaseproxy/main_test.go`

- [ ] **Step 1: Red.** A test that runs the proxy writer for a module at `v0.1.1` and asserts `v0.1.1.info`, `v0.1.1.mod` and `v0.1.1.zip` exist and `list` does not. Expected today: FAIL, `list` exists. Update any existing assertion that expects `list`.
- [ ] **Step 2: Implement:** stop writing `list`. Update the godoc that describes the proxy's layout.
- [ ] **Step 3:** `cd tools && GOWORK=off go test -count=1 ./...` and `GOWORK=off go vet ./...`. Expected: PASS. The end-to-end proof is `make release-check VERSION=v0.1.1` in task 8.2.

### Task 11.6: Close the Dependabot pull requests (main session)

- [ ] **Step 1:** After the branch carrying 11.1 is pushed, `gh pr close <n> --comment "..."` for #85 to #95, the comment naming this change's pull request. Verify with `gh pr list --author app/dependabot --state open`, which lists none of them.

### Task 9.1: Release files (Haiku for the given `go mod edit` diff, main session for `CHANGELOG.md`)

- [ ] **Step 1:** Run the `go mod edit -C <dir> -require=...@v0.1.1` commands of `RELEASING.md` step 2, and `go mod edit -retract=v0.1.0` in the root, with a comment on the retract pointing at the `0.1.1` changelog entry's `Security` section.
- [ ] **Step 2:** Add the `## [0.1.1] - <date>` entry: `Security` (three bullets, each with its effect and the affected version `v0.1.0`), `Changed` (decision 6; dot-segment 400; "Exported signatures use descriptive parameter names (no API change)"), and the link references.
- [ ] **Step 3:** Verify:
  - `SCRTY_RELEASE_VERSION=v0.1.1 go test -run TestNestedModulesRequireReleasedVersions -count=1 .` passes;
  - `go mod edit -json | jq .Retract` lists `v0.1.0`.

### Tasks 9.2–9.4: Merge and release (maintainer)

- [ ] **9.2:** Recheck task 1.1 step 1. Merge the pull request, and wait until CI on `main` is green for the merge commit.
- [ ] **9.3:** Follow `RELEASING.md` steps 3–8 for `v0.1.1`: the root tag is pushed alone, and the run of `gh run list --workflow release-probe --limit 1` that it triggered passes.
- [ ] **9.4:** Step 9: `gh release view v0.1.1 --json assets --jq '.assets | length'` prints `9`.