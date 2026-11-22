# Harden the chain boundary: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the three security defects reproduced in `v0.1.0` (fiber dot-segment bypass of the rules and of the recovery cool-down; session publication after the gates), make double mounting and duplicate single-value options loud, build the interceptor fold once, bring the library's context hand-offs in line with Go's idioms (groups 12–14), and ship `v0.1.1` through an ordinary pull request, disclosing the defects in its changelog.

**Architecture:** The chain's runtime changes sit in the core chain (`httpsec/chain.go`, `httpsec/exchange.go`); groups 13 and 14 touch detached calls across packages, `notify`, `oidcprovider` events and godoc.
- The fold is prebuilt at construction.
- The step that `Assemble` returns does four things: it records the run's terminal, refuses dot-segment paths, passes a re-entered chain through, and then runs the prebuilt fold.
- The first gate's prebuilt step marks the exchange and its run's marker while the gate's frame runs. Publication is refused while its own exchange is marked, or while an enclosing run of another chain is marked and the publishing chain lacks one of that chain's gates (group 10).
- The authorization stage refuses any session that still owes a built-in challenge.
- The step puts back, on return, the exchange's context and the run-scoped fields it found (group 12).

The adapters change in documentation only.

**Tech Stack:** Go 1.27, `net/http`, gin, fiber v3, testify, mockgen, testcontainers (conformance and integration suites).

**Spec:**
- `openspec/changes/harden-chain-boundary/design.md`, decisions 1 to 14;
- `specs/http-security-chain/spec.md`;
- `specs/framework-adapters/spec.md`;
- `specs/token-issuance`, `oidc-provider-authorization`, `oidc-provider-logout` (group 11), `security-state-stores`, `passkey-authentication` (group 13), `email-notification` (group 14);
- `tasks.md`, the task numbers below.

## Global Constraints

- No exported identifier is added or removed (proposal, Impact: API). `internal/detach` is internal. An exported bound option is new API, which Semantic Versioning keeps out of a patch. `gorelease` does not enforce that for a `v0` base, so reviewers hold it (decision 12).
- Detached-work bounds are `detach.WriteTimeout = 5 * time.Second` and `detach.RevocationTimeout = 10 * time.Second`; a site with its own bound keeps it. Limiter port calls and consumer callbacks get no library bound (decision 12, class 5).
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
9. **Three chains on one exchange** (A assembles B, B assembles C), each publishing. After C returns B reads B's state, and after B returns A reads A's. Added to task 12.1 as the case "three chains on one exchange".
10. **A caller that set its own context on the exchange before the run** gets exactly that context back, not the adapter's. Added to task 12.1 as the case "caller's own context".
12. **An exchange refused once and run again** reports the second run's refusal. Added to task 12.1 (`refusalReported` cleared at the outermost entry).
11. **A detached site that discards the callee's error today** (`_ =` or log only) keeps doing so on a timeout, without a new refusal. Added to task 13.4's outcome cases.

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

- [ ] **Step 1:** The maintainer chooses, for each finding in design.md's Open Questions, a fix or an accepted row. A fix starts from the matching test in `repro/httpsec_nested_chains_repro_test.go.txt` as its red step, on Opus (security refusal logic on the hot path).

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

- [ ] **Step 1: Red.** Port `TestChain_GatedChainInsideGatelessChainServesOwingSession` as a table: an owing session from the enclosing chain, for each of the four gates and the cool-down, is refused with that built-in's own error and status, and the handler does not run; a full session is let through and the inner handler reads it; when the inner chain resolves its own session, that one is judged.
- [ ] **Step 2:** Run it. Expected: the owing cases FAIL with 200; the controls PASS.
- [ ] **Step 3: Implement** the helper and use it in each built-in. A built-in that also writes the session back (for example after a renewal) keeps writing `ex.Session` as today.
- [ ] **Step 4:** `go test ./httpsec/... -count=1 -race`, the ginsec and fibersec suites, and the conformance suite. Expected: PASS.

### Task 10.12: The exchange's mark records its chain (Opus implementer, beside 10.11)

**Files:**
- Modify: `httpsec/chain.go` (the first gate's frame), `httpsec/exchange.go` (the mark field, `PublishSession`)
- Test: `httpsec/publish_after_gates_test.go` (extend)

**Interfaces:** each run's entry on the exchange (`runTerminal`) carries its own `gatesBegun`, set and restored by its gate frame; the exchange-level bool goes. `gateMarkRefusal` decides before `publishSession`: the publishing run's own mark is `errLatePublication`; another marked run on the exchange is `errPublishedInsideGates` unless the publisher covers its gates; `gatesRunning` then covers enclosing runs on other exchanges. (Implemented this way rather than recording only the chain, which would miss an outer chain's late authenticator behind a covering chain; design decision 2.)

- [ ] **Step 1: Red.** Port `TestChain_CoveringChainOnSharedExchangePublishes`, and add: the inner chain's own late authenticator on the shared exchange is refused; a nested chain lacking a gate on the shared exchange is refused. Expected today: the covering case FAILs with the late-publication error; the other two PASS.
- [ ] **Step 2: Implement** as in Interfaces. A publication from the handler (`publishingChain()` nil) stays refused by the gate-set check.
- [ ] **Step 3:** `go test ./httpsec/... -count=1 -race`. Expected: PASS, including the retried-pass, late-authenticator, gate-panics and forward suites.

### Task 10.13: Changelog (main session)

- [ ] **Step 1:** Extend the `0.1.1` Security entry with the gated chain inside a gateless chain, affecting `v0.1.0`.

### Task 10.14: Review of 10.11–10.12 (Opus reviewer, edits nothing)

- [ ] **Step 1:** A fresh reviewer over the 10.11–10.12 diff, against decisions 2 and 3 and the two requirements, enumerating failures first.

### Task 10.16: Fold the 10.14 review (Opus implementer: hot-path ordering and refusal logic)

**Files:** `httpsec/exchange.go` (`publishSession`), `httpsec/chain.go` (the gate frame's shadowed `i`, renamed `at`), `httpsec/mfa_enrol.go` (endpoints back on `ex.Session`), tests in `httpsec/publish_after_gates_test.go`, `httpsec/publish_inside_gates_internal_test.go` and `httpsec/nested_session_test.go`. The context restore is task 12.2's, not this task's.

- [ ] **Step 1: Red.** Port `TestChain_GatelessBuiltInOnSharedExchangeWithReplacedContextPublishes` (FAILs: the built-in publishes). Add per-gate rows asserting no bypass record, and an enrolment-endpoint row expecting `ErrAuthenticationRequired` inside a gateless chain (FAILs today: served).
- [ ] **Step 2: Implement.** `publishSession` refuses from the exchange's own marks as `gateMarkRefusal` does, except the publishing run's own mark. Enrolment endpoints read `ex.Session`; the enrolment gate keeps judging with `requestSession`.
- [ ] **Step 3:** `go test ./httpsec/... -count=1 -race`: only `TestChain_RunPutsBackTheContextItFound` fails (red until 12.2). ginsec, fibersec and `make lint` pass.

### Task 10.17: Review of 10.16 (Opus reviewer, edits nothing)

- [ ] **Step 1:** A fresh reviewer over the 10.16 diff against decisions 2, 3 and 5.

### Group 12: A chain run leaves the caller's exchange as it found it (decision 11)

One Opus lane after 10.17. It owns `httpsec/chain.go`, `httpsec/exchange.go`, and every `httpsec` test helper that reads an exchange after its run. No other lane writes `httpsec` while it runs.

### Task 12.1–12.2: Restore the run's state on return (Opus implementer: hot-path ordering, a refactor that keeps decisions 2, 4 and 5)

**Files:**
- Modify: `httpsec/chain.go` (the step `Assemble` returns), `httpsec/exchange.go` (a small unexported snapshot type and the godoc of `Exchange` and `Exchange.Context`), and the godoc of `Chain.Assemble`
- Modify: the 12 helper sites that set `out.handled = ex` and the 26 tests that read `handled.Context()` or its fields after the run. Find them with gopls references on the helpers.
- Test: `httpsec/chain_reentry_test.go` (`TestChain_RunPutsBackTheContextItFound`, already present), `httpsec/run_scope_test.go` (create: `TestChain_RunPutsBackTheExchangeItFound`)

**Interfaces:** `type runScope struct{ ctx context.Context; session *session.Session; authn *authenticate.Authentication; bearerCredential, renewal string; chargeRenewal func(context.Context); admitRenewal func(*Exchange, *session.Session) (*identity.Details, error); perRequest *perRequestPhase; csrfOptOut bool; raised policy.ChallengeKind }` with `func (ex *Exchange) saveScope() runScope` and `func (ex *Exchange) restoreScope(runScope)`. It holds only the fields 12.1 showed leaking. `refusalReported`, the terminal stack, the gate marks, `Request`, `Writer` and the certificate fields are never in it.

- [ ] **Step 1: Red.** `TestChain_RunPutsBackTheExchangeItFound`, a table (`table-test` skill) over an outer chain whose interceptor at slot 100 assembles an inner chain on the same exchange, then reads the exchange after the inner step returns. The cases are:
  - the inner chain publishes a session: `ex.Session` and `ex.Authentication` are the outer run's, nil here;
  - the inner bearer resolves a credential: `bearerCredential == ""`;
  - an inner late renewal: `renewal == ""` and both renewal funcs are nil;
  - the inner chain is built `WithoutCSRFProtection` and the outer is not: `csrfOptOut == false`;
  - `perRequest` is the outer chain's;
  - the inner chain raises a consumer challenge: `raised == policy.ChallengeNone`;
  - an inner interceptor panics and the outer recovers it: every field is as before the inner step;
  - three chains on one exchange: each level reads its own run's state after the level below returns;
  - caller's own context: a context set with `SetContext` before the outer run is the one after it;
  - an exchange refused once and run again: the second refusal is reported;
  - control: the inner chain refuses with an event sink wired, and the outer chain's refusal is not reported again (`refusalReported` survives).
- [ ] **Step 2:** Run `go test -run 'TestChain_RunPutsBack' -count=1 ./httpsec/`. Expected: the 7 context cases FAIL. Report which field cases fail and which pass. A field whose case passes is left out of `runScope`, and the main session drops it from decision 11, the spec requirement and the proposal.
- [ ] **Step 3: Implement.** `scope := ex.saveScope(); defer ex.restoreScope(scope)` at the top of the step, before the re-entry check, so a pass-through entry is covered too. When the terminal stack is empty on entry (an outermost run), clear `refusalReported`. Move each helper and test to read inside the terminal. Add the godoc.
- [ ] **Step 4:** Verify:
  - `go test ./httpsec/... -count=1 -race`, the ginsec and fibersec suites, and the conformance suite pass;
  - `go test -run '^$' -bench 'BenchmarkAssemble/run/8' -benchtime=1000x` and `16000x`: ns/op within noise;
  - `benchstat` on `Assemble/run/8` and `ChainRequest/0` and `/8`, `-count=10`: allocs/op equal to decision 5's recorded figures.

### Task 12.3: Changelog (main session)

- [ ] **Step 1:** `0.1.1` `Changed`: an exchange's context, session and authentication read after the chain's step returns are what they were before the run; read a run's state in the terminal.

### Task 12.4: Review of group 12 (Opus reviewer, edits nothing)

- [ ] **Step 1:** A fresh reviewer over the group 12 diff against decision 11, its requirement, and the rows of decisions 2, 4 and 5. It enumerates failures first, with particular attention to panics, the pass-through, nested runs on one exchange, and the decision 2 marks.

### Group 13: Work detached from the caller's cancellation has a deadline (decision 12)

13.1 gates the group. 13.2 and 13.3 run in parallel. 13.4's lanes run after 13.3, because they import `internal/detach`.

### Task 13.1: Confirm the bound (maintainer)

- [ ] **Step 1:** The maintainer confirms the fixed bounds (5 s, 10 s for revocations) with no option in `v0.1.1`, or chooses `v0.2.0`. The reason is Semantic Versioning's rule, not `gorelease`. In the second case, stop and revise decisions 8 and 12, task 9.1 and group 13 first.

### Task 13.2: Inventory (Sonnet, read-only)

- [ ] **Step 1:** `rg -n 'context\.WithoutCancel' --glob '*.go' --glob '!*_test.go' --glob '!.claude/.legacy' --glob '!test/**'`. Repeat it for `context\.(Background|TODO)\(\)` and keep the hits that detach work. For each site, name the callee (with gopls), the class (1–5 of decision 12), the kind of bound for class 4 (write or revocation), the lane (A, A2, B, C or D), and what the site does with the callee's error. Report it as a table. The main session writes it into decision 12.

### Task 13.3: `internal/detach` (Sonnet implementer)

**Files:** Create `internal/detach/detach.go` and `internal/detach/detach_test.go`.

**Interfaces:** `const WriteTimeout = 5 * time.Second`; `const RevocationTimeout = 10 * time.Second`; `func Bounded(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc)`, which is `context.WithTimeout(context.WithoutCancel(ctx), d)`.

- [ ] **Step 1: Red.** `TestBounded`, a table whose cases are:
  - the deadline is set and `0 < time.Until(deadline) <= d`, for `WriteTimeout` and `RevocationTimeout`;
  - a parent value is readable;
  - cancelling the parent leaves `Err() == nil`;
  - calling the returned cancel makes `Err()` `context.Canceled`.

  Run it. Expected: FAIL, with `Bounded` stubbed to return `context.WithoutCancel(ctx)` and a no-op cancel; a compile error is not the red step.
- [ ] **Step 2:** Implement. `go test -race -count=1 ./internal/detach/`. Expected: PASS.

### Task 13.4: Bound the class-4 sites (Sonnet lanes A, B, C and D; Opus lane A2; Opus reviewer in 13.6)

**Lanes and files:** the class-4 and class-5 sites in 13.2's table, by package:
- **A:** `authenticate/mfa` and `authenticate/passkey`;
- **A2:** `authenticate/passkey/webauthn/metadata.go`, which runs under singleflight;
- **B:** `session` and `recovery`;
- **C:** `httpsec`, outside `chain.go` and `exchange.go`, after group 12 has landed;
- **D:** every other package 13.2 lists, for example `oidcprovider/endsignin.go`, `authenticate/oidc` and `policy/lockout`.

Each lane takes the final site list from 13.2's table, and owns its packages' tests.

**Interfaces:** consumes `detach.Bounded` from 13.3.

- [ ] **Step 1: Red.** For each package, a table test `Test<Component>_DetachedCallsCarryDeadline` with one case per class-4 site. A mockgen double (`use-mockgen` skill) records the deadline and asserts it is within the site's bound: `WriteTimeout`, or `RevocationTimeout` for a revocation. A second case per site returns `context.DeadlineExceeded`, and asserts the site's existing outcome for a store error from that call. A case per class-5 site in the package asserts that its context has no library deadline: limiter calls and session end observers. Lane A2 adds `TestMetadata_ConsumerFetchHasDeadline`: a consumer fetch that blocks on `<-ctx.Done()`. Its context carries a deadline `outbound.DefaultTimeout` away, and the registration is refused with the attestation-refused refusal. Test it through the deadline value, without sleeping for the full timeout. Lane A2 also corrects `MetadataBlob`'s godoc.
- [ ] **Step 2:** Run each new test. Expected: the deadline cases FAIL (`no deadline`). The outcome cases PASS, because they pin today's handling.
- [ ] **Step 3: Implement.** At each class-4 site, `ctx, cancel := detach.Bounded(ctx, detach.WriteTimeout)` (or `RevocationTimeout`), then `defer cancel()`. A site with its own bound keeps it. A site with several independent writes bounds each one.
- [ ] **Step 4:** `go test -race -count=1` on the lane's packages, then `make lint` (`lostcancel` included). Expected: PASS.
- [ ] **Step 5: Lane B's red, redone (Sonnet).** Save lane B's `recovery` production diff (`recover.go`, `codes.go`, `grants.go`, `hold.go`, `recover_complete.go`, `reset.go`) to the scratchpad. Copy the six files there too. Reverse only that diff with `git apply -R`, and keep `recovery/detached.go`, `recovery/recoverer.go` and the tests. Do not use `checkout`, `restore`, `reset` or `stash`. Then run `go test -race -count=1 -run DetachedCallsCarryDeadline ./recovery/`. Expected: the deadline cases FAIL with "no deadline", and the outcome cases PASS. Put the six files back from the copies, unchanged. Rerun. Expected: PASS. Then run `make lint`.

### Task 13.7: The bound's expiry is not a hang-up (Sonnet implementer, after 13.4 step 5)

**Files:** Modify `internal/detach/detach.go` and `internal/hangup/hangup.go`, and their tests. Add a test in `token/onetime`.

**Interfaces:** `detach.Bounded` keeps its signature. Internally it uses `context.WithTimeoutCause(context.WithoutCancel(ctx), d, errBoundReached)`. `detach` exposes the check to `hangup` as `func BoundReached(ctx context.Context) bool`, which is `errors.Is(context.Cause(ctx), errBoundReached)`. `hangup.ByCaller` returns false first when `detach.BoundReached(ctx)`.

- [ ] **Step 1: Red.** Add a `TestByCaller` row, "a detach bound that passed, with err its DeadlineExceeded". It uses `detach.Bounded(ctx, time.Nanosecond)`, waits for `Done`, and expects `isNotHangUp`. Then add `TestTokens_ConsumeBoundExpiryLogsError` in `token/onetime`. Under `synctest.Test`, `Consume` runs with a `detach.Bounded(ctx, detach.WriteTimeout)` context. The store double blocks until its context ends and returns `ctx.Err()`. Assert that the captured log record is at `slog.LevelError`.
- [ ] **Step 2:** Run both tests. Expected: FAIL. The row is reported as a hang-up, and the record is at DEBUG.
- [ ] **Step 3:** Implement the cause and the check. Add a `TestBounded` row: once the bound passes, `BoundReached` is true; after the returned cancel, it is false.
- [ ] **Step 4:** `go test -race -count=1 ./internal/... ./token/... ./recovery/... ./session/...`, then `make lint`. Expected: PASS.

### Task 13.5: Changelog (main session)

- [ ] **Step 1:** `0.1.1` `Changed`: detached store work has a bound where it had none (5 s, 10 s for revocations), while limiter calls and consumer callbacks are left to their owners. A consumer-supplied WebAuthn metadata fetch is bounded by `outbound.DefaultTimeout`.

### Task 13.6: Review of group 13 (Opus reviewer, edits nothing)

- [ ] **Step 1:** A fresh reviewer reruns 13.2's search and compares it with the table. It checks each site's timeout outcome against today's handling of a store error, and enumerates failures first.

### Group 14: A cancelled send, and the remaining hand-offs (decisions 13, 14)

Four independent lanes, which run in parallel with groups 12 and 13, each in its own git worktree (`isolation: worktree`). Their red steps would otherwise fail the suites and the lint that 10.16 and group 12 run in the shared tree. The main session integrates each lane once its review is clean.

### Task 14.1: SMTP cancellation (Opus implementer: the connection deadline and the context timer race)

**Files:** `notify/smtp.go`, and the send-failure log site found with gopls (references on the `smtp send failed` record's function); test `notify/smtp_cancel_test.go` (create).

- [ ] **Step 1: Red.** `TestSMTPSender_CallerEndedSendReportsContextError`, a table using the existing `startScriptedServer` and `scriptSilentGreeting` helpers. The cases are:
  - cancel after 100 ms: `errors.Is(err, context.Canceled)`, and a capturing `slog` handler sees no record at `slog.LevelError`;
  - the caller's deadline at 100 ms with the sender at 30 s: `errors.Is(err, context.DeadlineExceeded)`;
  - the sender at 200 ms with the caller live: neither matches, and the error is the timeout.
- [ ] **Step 2:** Run it. Expected: the first two FAIL (`got *diag.Fault: notify: the greeting … failed`). The third PASSes.
- [ ] **Step 3: Implement.** Keep the context `Send` received (`callerCtx`), separate from the one `send` derives with the sender's deadline (`smtp.go:317`). When `exchange` fails, the caller has ended the send if `callerCtx.Err() != nil` or `callerCtx`'s deadline has been reached by the clock. In that case return `errors.Join(callerErr, err)`, where `callerErr` is `callerCtx.Err()` or `context.DeadlineExceeded`. At the log site, log such a send at DEBUG through `hangup.ByCaller`.
- [ ] **Step 4:** `go test -race -count=1 ./notify/...`. Expected: PASS.

### Task 14.2: fibersec stream-panic log context (Sonnet implementer)

- [ ] **Step 1: Red.** In `httpsec/fibersec`, not parallel because it sets slog's default logger, a stream that panics. A capturing log handler reads a context key set by a fiber middleware before the chain, and the test asserts the panic record saw the value. Expected: FAIL (it logs under `context.Background()`).
- [ ] **Step 2: Implement.** Log under `context.WithoutCancel` of the request's context, on both the panic and the `Goexit` branches. Run the fibersec suite. Expected: PASS.

### Task 14.3: Events without a context in a context (Sonnet implementer)

- [ ] **Step 1:** In `oidcprovider/events.go`, the context value holds the emitter, or the values the reuse event needs, not a `context.Context`. Break the routing temporarily: the existing event tests must FAIL. Restore it, then run `go test -race -count=1 ./oidcprovider/...`. Expected: PASS.

### Task 14.4: Godoc (Haiku; the main session gives the exact wording in the prompt)

- [ ] **Step 1:** Add the godoc to:
  - `expiry/sweep` `Start`, the signing-key lifecycle's `Start` and the memory session store's `Start`: "The loop keeps the values of ctx for its whole life, including a store transaction attached to it; start it from a context with no transaction attached.";
  - the `ginsec` package doc and `Middleware`: "When the chain passes the request on, c.Request carries the chain's context afterwards, so a gin middleware registered before the chain reads that context after c.Next() returns. A refused request's c.Request is unchanged.";
  - the session end-observer option and the event-sink option: "The library gives this function's context no deadline; bound your own work."

  Verify with `go doc` on each symbol, and `make lint`.

### Task 14.5: Changelog (main session)

- [ ] **Step 1:** `0.1.1` `Changed`: a cancelled SMTP send's error matches the context's error, and is not logged at ERROR.

### Task 14.6: Review of group 14 (Sonnet reviewer, edits nothing)

- [ ] **Step 1:** A fresh reviewer over the group 14 diff against decisions 13 and 14 and the `email-notification` delta, enumerating failures first.

### Task 10.15: Gate again (main session, after groups 12–14)

- [ ] **Step 1:** Run, in order and never at the same time:
  - `make check`;
  - `make release-check VERSION=v0.1.1` in a clean worktree of the head, on a quiet machine (golangci-lint refuses a parallel run, and `TestSessionDelete_SettlesUnderConcurrentCreates` has an 8 s bound that a loaded machine misses);
  - `openspec validate harden-chain-boundary --strict`;
  - `gh pr checks 100 --watch`.

  Expected: all green. Then update the pull request body, with no session link.

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