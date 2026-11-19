# Tasks

**How tasks are worked:**
- **Test-first.** Every Go task writes the failing test, runs it, and confirms it fails for the intended reason; a compile error is not a red step. Then it implements, re-runs, and refactors with the tests green. Table tests follow the `table-test` skill.
- **Model per dispatch:**
  - Opus for group 2: a core public API and security-relevant recognition logic;
  - Opus for group 4: concealment and refusal mapping written for the first time;
  - Opus for group 5: it changes a settled refusal path, and a mistake there would pass most tests and still be wrong;
  - Sonnet for groups 3, 6, 7 and 8: module scaffolding, parity tests against a stated contract, consumer documentation, and repository lists;
  - each dispatch gets a fresh reviewer of the same tier.
- **Files.**
  - Group 2 owns the core files: `httpsec/errors.go`, `httpsec/complete.go` and `httpsec/mfa_verify.go`, plus their tests.
  - Groups 3–4 own `httpsec/prblmsec/**`. They need `LookupStatus` and `TokenType`, so they start after group 2 lands.
  - Group 5 owns `httpsec/ginsec/middleware.go`, a new `httpsec/ginsec/options.go`, their tests, and `ginsec`'s godoc for the option. It needs no new core API, so it may run in parallel with groups 2–4.
  - Group 6 owns the `test/` module's new parity files, and runs after groups 4 and 5.
  - Group 7 owns the consumer documentation: `README.md`, `httpsec/prblmsec`'s `doc.go` and `example_*_test.go`, and the cross-references in `httpsec/doc.go`, `httpsec/ginsec/doc.go` and `httpsec/fibersec/doc.go`. It runs after group 6, so every snippet mirrors code that is already tested.
  - Group 8 owns `go.work`, `.github/dependabot.yml`, `tools/repocheck/**`, `RELEASING.md` and `CHANGELOG.md`, and may run in parallel with group 2.
- **Branch.** `feat/problem-details-rendering` from `origin/main`, merged through a pull request with CI.

## 1. Branch

- [x] 1.1 Cut `feat/problem-details-rendering` from `origin/main` and carry this change's directory onto it. Verify that `git branch --show-current` names it and that `git merge-base HEAD origin/main` equals `git rev-parse origin/main`.

## 2. Core: recognising lookup and challenge token type (design decisions 2, 5)

- [x] 2.1 Red: add `TestLookupStatus` (table) in `httpsec`. Cases:
  - every `statusTable` row: recognised, with the row's status;
  - each challenge kind: recognised, 401 or 403;
  - each explicit 500 branch: recognised, 500;
  - a `diag.Fault` built over a store error: recognised, with `StatusForError`'s status;
  - `password.ErrHistoryUnavailable` wrapping a connection error: recognised, 500;
  - a consumer error and `nil`: unrecognised, 500.

  Each case also asserts that the status equals `StatusForError(err)`. Seeing the red step: the test fails because the lookup reports no errors as recognised (stub it to return `StatusForError(err), false` first). Green: implement `LookupStatus` and re-express `StatusForError` through it. Verify with `go test -run 'TestLookupStatus|TestStatusForError' -count=1 ./httpsec/`.
- [x] 2.2 Red: add `TestLookupStatus_DependencySentinelInventory`. It lists every exported core sentinel whose godoc calls it a dependency or unavailability failure that maps to 500, and asserts each is recognised. Before writing it, inventory them with gopls workspace symbols (`Err*Unavailable`, `ErrDependency`, `ErrHistoryUnavailable`, `ErrLookupUnavailable`), and report the list. Green: add the missing ones to the lookup. Verify with `go test -run TestLookupStatus_DependencySentinelInventory -count=1 ./httpsec/`.
- [x] 2.3 Red: extend the challenge-error tests:
  - a challenged password login on a bearer chain has `TokenType == TokenTypeBearer`;
  - a DPoP-bound login has `TokenTypeDPoP`;
  - an MFA verification raising a password-change challenge carries the rotated token's type;
  - the password-change gate's challenge, which carries no token, has an empty `TokenType`.

  Green: set `TokenType` at the three construction sites (`complete.go`, `mfa_verify.go` ×2) from `tokenTypeOf`. Verify with `go test -run 'Challenge' -count=1 ./httpsec/`.
- [x] 2.4 Godoc:
  - `LookupStatus`: what "recognised" means, and the comma-ok pairing with `StatusForError`;
  - `ChallengeError.TokenType`;
  - the package doc's "Failing closed" section names the lookup.

  Verify with `go doc ./httpsec LookupStatus`, plus `go vet ./... && gofmt -l . && go test -count=1 ./httpsec/...`, all clean.
- [x] 2.5 A refusal that carries a credential is never cacheable (design decision 5, whole-branch review finding). Red: `TestChallengeToken_NoStore` (table) in `httpsec`, over a real chain whose error handler records the response headers, with a middleware ahead of the chain that sets `Cache-Control: public, max-age=300`. Cases:
  - a challenged password login on a bearer chain: `Cache-Control` is exactly `[no-store]`;
  - an MFA verification raising a further, token-bearing challenge: exactly `[no-store]`;
  - a DPoP-bound challenged login: exactly `[no-store]`;
  - the password-change gate's challenge, which carries no token: `[public, max-age=300]`, unchanged.

  Before writing it, find every site that returns a `ChallengeError` with a `Token` (gopls references on `ChallengeError`; expected `complete.go` and `mfa_verify.go` ×2) and report the list. See the token-bearing cases fail on the upstream value. Green: set `Cache-Control: no-store` with a replacing set on the exchange's writer at each site, before the refusal is returned. `ChallengeError.Token`'s godoc says the response must stay `no-store`. Verify with `go test -race -run 'TestChallengeToken_NoStore|Challenge' -count=1 ./httpsec/`.
- [x] 2.6 Restore `errors.As` semantics in the challenge walks (design failure modes, whole-branch review finding). The walks are `firstChallenge` in `httpsec` and the mapper's walk in `prblmsec`. Red: a table test in each package with these cases:
  - an error that presents a `*ChallengeError` only through its own `As(any) bool` method: `StatusForError` is 401, `LookupStatus` is `(401, true)`, and the mapper gives the challenge's type and members. Today it is 500;
  - a typed-nil `*ChallengeError` joined ahead of a real one: the real challenge is still found, as today;
  - a challenge wrapped 101 levels deep through `Unwrap() error` is found, as `errors.As` finds it on `main`;
  - behind a typed nil, where only the nil-skipping fallback searches: a challenge at depth 100 is found, and one at depth 101 is not, so the rest of the chain decides (500), with no panic;
  - a challenge offered through an `As` method and joined behind a typed nil: 500, the accepted outcome in design.md;
  - a chain holding a challenge through `As` and a direct one: the mapper's status equals `StatusForError`'s.

  See the `As` cases and the 101-wrap case fail. Green: each walk tries `errors.As` first and keeps a non-nil result, then falls back to the nil-skipping walk. Verify with `go test -race -run 'Challenge|LookupStatus|StatusForError' -count=1 ./httpsec/` and `go -C httpsec/prblmsec test -race -count=1 ./...`.

## 3. `httpsec/prblmsec` module and construction (decisions 1, 6)

- [x] 3.1 Create the module `github.com/kartaladev/scrty/httpsec/prblmsec`:
  - it requires `github.com/kartaladev/prblm v0.2.0` and the core through the workspace;
  - its package doc names the opt-in contract;
  - add it to `go.work`.

  Red: `TestNew` (table) covers:
  - the default construction succeeds with prefix `security`;
  - `WithTypePrefix("auth")` succeeds;
  - an invalid prefix (`Auth/../x`, `""`, `a//b`), a nil option and a duplicated option each fail with `errors.Is(err, ErrConfig)`, and no `*Problems` is returned.

  Green: implement `New`, the options and `ErrConfig`. Prefix validity comes from recovering only `prblm.DefineType`'s construction panic. Verify with `go test -run TestNew -count=1 ./...` in `httpsec/prblmsec`.
- [x] 3.2 Red: `TestTypes_DocumentEveryType`. A prblm handler built with `WithNamespace("/probs")` and `p.Option()` serves discovery. For every sub-type in the spec's table, `GET /probs/<prefix>/<sub-type>` answers 200 JSON with that status, and an `AddErrorHook` records no `ErrUndocumentedType` or `ErrInvalidType` note when each type's problem is answered. Green: define the types in `New` from one table, and implement `Types()` and `Option()`. Verify with `go test -run TestTypes -count=1 ./...`.

## 4. Mapping refusals to problems (decisions 3, 4, 5)

- [x] 4.1 Red: `TestMapper_TypePerRefusal` (table) covers one case per row of the spec's type table, plus every refusal the spec names. It asserts the type and that the status equals `httpsec.StatusForError(err)`. It also covers:
  - a challenge wrapping access-denied gives `mfa-required`;
  - a recognised 500, 405 or 501 gives `about:blank` with no detail.

  Green: implement status-first type selection. Verify with `go test -run TestMapper_TypePerRefusal -count=1 ./...`.
- [x] 4.2 Red: `TestMapper_ConcealsWhatStatusConceals`. Encode the JSON problem for each of these on the same request and assert the bytes are identical:
  - a wrong password;
  - authentication-failed joined with account-locked;
  - `authenticate.ErrUnavailable` wrapping a connection error.

  The disclosed lock gives a 429 `account-locked`. Watch it fail by temporarily giving `ErrUnavailable` its own type. Verify with `go test -run TestMapper_Conceals -count=1 ./...`.
- [x] 4.3 Red: `TestMapper_Members` (table) covers:
  - `methods` order and fields, a non-nil empty list rendered `[]`, and nil omitted;
  - `challenge` on every challenge type;
  - `max_age` 300 for a 5-minute window, and omitted for `Window <= 0`;
  - `rule` from `password.RejectedError`, and omitted without one;
  - a typed-nil `*ChallengeError` neither panics nor gets members;
  - no member or detail contains the text `alice@example.com`, carried in the cause.

  Verify with `go test -run TestMapper_Members -count=1 ./...`.
- [x] 4.4 Red: `TestMapper_ChallengeToken` (table) covers:
  - a token with `TokenType` Bearer gives `access_token`, `token_type` and a `Cache-Control: no-store` problem header;
  - DPoP gives `token_type` `DPoP`;
  - no token gives neither member;
  - a token without `TokenType` gives `access_token` only;
  - `WithoutChallengeToken` gives neither member, with the rest unchanged.

  Verify with `go test -run TestMapper_ChallengeToken -count=1 ./...`.
- [x] 4.5 Red: `TestMapper_DefersUnrecognised` covers:
  - a consumer error with a consumer `prblm.Status(errApp, 404)` mapper registered after the integration gives 404;
  - an unknown error gives prblm's 500 with no detail;
  - a recognised dependency failure wrapping a fake error that a later mapper maps to 503 stays 500;
  - a consumer mapper registered ahead for the disclosed lock wins, and a wrong password still gives `authentication-failed`.

  Verify with `go test -run TestMapper_Defers -count=1 ./...`.
- [x] 4.6 Godoc for every exported identifier of `prblmsec`. Each option names the default it replaces: prefix `security`, token delivered. Verify with `go doc -all ./` in the module, where every exported symbol has a doc comment, plus `go vet`, `gofmt -l` and `golangci-lint run` in the module, all clean. The package overview and the examples are group 7.

## 5. gin: refusals left for an error middleware (design decision 10)

- [x] 5.1 Red: `TestMiddleware_RefusalsRendered` (table) in `httpsec/ginsec`, run over a real gin engine. Cases:
  - **default, no error middleware:** `GET /sso/login/nope` gives 404 with an empty body (the settled scenario, still green);
  - **declared, with error middleware:** an error middleware registered before `ginsec` writes `{"error":"rendered"}` with `Content-Type: application/json` for every `c.Errors` entry, and `GET /sso/login/nope` gives 404 with that body and `Content-Type`;
  - **declared, no error middleware:** gives 404 with gin's `404 page not found` text, containing no refusal text, and no route handler ran;
  - **declared, matched route:** a refusal on a registered route is left open as before;
  - **declared, other status on an unrouted path:** for example a 400, left open as before;
  - **option twice, nil option:** the same as the option given once, and as the default respectively.

  Seeing the red step: add `Option`, `WithRefusalsRendered` and the variadic parameter with no effect first. The "declared, with error middleware" case then fails with an empty body. Green: `refuse` skips `WriteHeaderNow` when the option is set. Verify with `go test -race -run TestMiddleware_RefusalsRendered -count=1 ./...` in `httpsec/ginsec`.
- [x] 5.2 Godoc:
  - `WithRefusalsRendered` names the default it replaces (an empty 404 on unrouted paths), and what breaking the declaration costs (gin's text 404). It also says to register the error middleware before `ginsec.Middleware`;
  - `Middleware` and the package's "Refusals" section name the option.

  Verify with `go doc ./httpsec/ginsec WithRefusalsRendered`, which shows it, plus `go vet ./...`, `gofmt -l .` and `golangci-lint run` in `httpsec/ginsec`, all clean, and the existing `ginsec` and test-module gin suites green: `go test -count=1 ./...` in `httpsec/ginsec`, and `go test -run Gin -count=1 ./` in `test/`.

## 6. Parity across net/http, gin and fiber (decision 7)

- [x] 6.1 In the test module, require `github.com/kartaladev/prblm/adapters/ginprblm v0.2.0` and `.../adapters/fiberprblm v0.2.0`. Red: `TestProblemParity` (table over the three frameworks) runs one chain configuration three ways: net/http through `WithErrorHandler(h.Write)`, gin with `ginprblm.Middleware` before `ginsec.Middleware(chain, ginsec.WithRefusalsRendered())`, and fiber with `fiberprblm.ErrorHandler`. Cases:
  - unauthenticated gives `authentication-required`;
  - a challenged password login gives `mfa-required` with `access_token` and `Cache-Control: no-store`;
  - a failed Basic login keeps `WWW-Authenticate: Basic` exactly once;
  - a DPoP nonce refusal keeps `DPoP-Nonce` and `WWW-Authenticate: DPoP`;
  - an unknown handler error gives prblm's 500;
  - an unknown identity provider in a federated login path, and an unknown MFA method in a verify path, with `ginsec.WithRefusalsRendered()` on the gin deployment: all three give the 404 `not-found` problem;
  - the same requests on a gin deployment with `ginprblm.Middleware` and without the option: the same 404 `not-found` problem (`ginprblm` defers the header, design decision 10). Red: first assert the old empty-body expectation and see it fail;
  - the same requests on a gin deployment with no renderer at all and no option: 404 with an empty body (the `framework-adapters` default, pinned);
  - a not-found refusal from a guard on a gin route the consumer registered gives the `not-found` problem on all three.

  Except for the no-renderer case, it asserts the same status, document and headers on all three. Verify with `go test -run TestProblemParity -count=1 ./` in `test/`.
- [x] 6.2 Red: `TestProblemParity_GuardRefusal` covers a net/http guard with `WithGuardErrorHandler(h.Write)` and the gin and fiber guards. A guard refusal gives the same typed problem as the chain's for the same error. Verify with `go test -run TestProblemParity_Guard -count=1 ./`.
- [x] 6.3 The module-graph check: a consumer of the core only has no `github.com/kartaladev/prblm` in `go list -m all`. Extend `TestCoreDependencies` and `TestConsumerModuleGraph` (`layout_test.go`) to list `github.com/kartaladev/prblm`, and watch them fail by temporarily adding the requirement to the root `go.mod`. Verify with `go test -run 'TestCoreDependencies|TestConsumerModuleGraph' -count=1 .` at the root.
- [x] 6.4 Extend `TestProblemParity` (whole-branch review findings):
  - **upstream cache policy:** each framework's server gets a middleware ahead of the chain that sets `Cache-Control: public, max-age=300`, and a challenged password login gives `access_token` and `Cache-Control` exactly `[no-store]` on all three. Red: run it before 2.5 is green, or with 2.5's header set temporarily removed, and see it fail on the upstream value;
  - **matched-route 404 without the option:** the guard not-found case on a consumer gin route also runs on gin with `ginprblm.Middleware` and no `WithRefusalsRendered` (`extraGin: ginProblemsOnly`), with the same problem as net/http.

  Verify with `go test -race -run TestProblemParity -count=1 ./` in `test/`.

## 7. Consumer documentation (design decisions 9, 10)

- [x] 7.1 Runnable examples in `httpsec/prblmsec` (`example_test.go`), each with an `// Output:` block, so `go test` checks it and pkg.go.dev shows it:
  - `Example_netHTTP`: a namespace, `p.Option()`, and the chain's and guards' error handlers set to `h.Write`. Output: the 401 `authentication-required` problem for an unauthenticated request;
  - `Example_challengedLogin`: the `mfa-required` problem with `methods`, `access_token` and `token_type`, and the `Cache-Control: no-store` header;
  - `ExampleWithTypePrefix`: the type `/probs/auth/access-denied` (namespace `/probs`, prefix `auth`);
  - `ExampleWithoutChallengeToken`: the same challenge without the token members;
  - `ExampleProblems_Mapper`: manual registration with `prblm.WithTypes(p.Types()...)` and `prblm.WithMappers(p.Mapper(), appMapper)`, where the app's own error gets the app mapper's problem;
  - `Example_override`: a consumer mapper for `lockout.ErrAccountLocked` registered ahead of `p.Option()`, giving 429 with `Retry-After: 900`, while a wrong password keeps `authentication-failed`.

  The `// Output:` values come from the spec, not from running the code. To confirm each example bites, temporarily change one expected line, see `go test` report the output diff, then edit it back. Verify with `go test -run Example -count=1 ./...` in the module.
- [x] 7.2 Write the package overview in `httpsec/prblmsec/doc.go`. Sections:
  - **What it is:** the three pieces, and what stays prblm's.
  - **Wiring:**
    - net/http;
    - gin: `ginprblm.Middleware` registered before `ginsec.Middleware(chain)`, with no `httpsec.WithErrorHandler` and no option needed;
    - fiber: `fiberprblm.ErrorHandler` in place of `fibersec.ErrorHandler`.
  - **Problem types:** the type table, and that status always equals `httpsec.StatusForError`.
  - **Extension members.**
  - **The challenge credential:** delivered by default, `WithoutChallengeToken`, and that hooks see it.
  - **Ordering and overrides.**
  - **Always set a namespace.**
  - **Stated limits:**
    - ports must not return a `prblm.Describer` or `*prblm.Problem`;
    - on gin, `ginprblm` renders the chain's own 404s with or without `ginsec.WithRefusalsRendered()`; the option is for a consumer's own error middleware that writes immediately, and gin with no renderer at all gives those 404s an empty body;
    - context errors scrty does not recognise are prblm's to map.

  The gin and fiber snippets are prose. They mirror `TestProblemParity` in the test module, and each says so (`Mirrors TestProblemParity`). Verify with `go doc ./` in the module, which shows every section, and a reviewer check that each snippet matches the test or example it names.
- [x] 7.3 Write a `README.md` section, "Problem details (RFC 9457)", placed after "Security events" and before "Known limitations":
  - install (`go get github.com/kartaladev/scrty/httpsec/prblmsec@<version>` with the lockstep version);
  - wiring for net/http, gin (`ginprblm.Middleware` before `ginsec.Middleware(chain)`, no option needed) and fiber;
  - customisation: prefix, withholding the token, and a consumer override;
  - an example response for a challenged login;
  - the type table;
  - "Defaults" and "Stated limits" subsections, as other README sections have.

  Each snippet names the example or test it mirrors. Verify with `git grep -n "Problem details (RFC 9457)" README.md`, which finds the section, and a reviewer check that each snippet's mirror exists and matches.
- [x] 7.4 Add cross-references at the places consumers already read about rendering:
  - **`httpsec/doc.go`:** "Failing closed" and `WithErrorHandler` name `prblmsec` as the ready-made renderer.
  - **The `ginsec` and `fibersec` "Refusals" docs:**
    - each names `ginprblm` or `fiberprblm` with `prblmsec`;
    - `fibersec.MapError`'s doc points to it for a rendered body;
    - `ginsec` says `ginprblm` needs no option, and points users of an error middleware that writes immediately to `WithRefusalsRendered`.
  - **`README.md`:** the MFA passage that says the consumer's error handler must deliver `ce.Token` (around line 764) names `prblmsec`, which does that by default. So do the README's Modules table and its install list.

  Verify with `git grep -n prblmsec httpsec/doc.go httpsec/ginsec/doc.go httpsec/fibersec/doc.go README.md`, which finds each, plus `go vet ./...` and `gofmt -l .` clean in the three modules.

## 8. Layout, release and supply chain (decision 8)

- [x] 8.1 Red: extend `TestIntegrationModulesUnderTheirConcept` and `TestNoUnlistedIntegrationModule` (`layout_test.go`), and `tools/repocheck`'s expectations, with `httpsec/prblmsec`, and confirm they fail before the module is listed. Green: add `.github/dependabot.yml`'s gomod entry for `/httpsec/prblmsec`, and add the module to the layout lists. Verify with `go test -count=1 ./...` in `tools`, and `go test -run 'TestModuleLayout|TestIntegrationModules|TestNoUnlisted|TestGoWork' -count=1 .` at the root.
- [x] 8.2 `RELEASING.md` lists `httpsec/prblmsec` among the lockstep modules and tags. `CHANGELOG.md`'s Unreleased section, under Added, names the module, `httpsec.LookupStatus`, `ChallengeError.TokenType` and `ginsec.WithRefusalsRendered`, and notes that `ginsec.Middleware` is now variadic (code storing it as a `func(*httpsec.Chain) gin.HandlerFunc` value breaks). Verify with `git grep -n prblmsec RELEASING.md CHANGELOG.md .github/dependabot.yml go.work`, which finds each.
- [x] 8.3 Whole-tree gate on the branch, all clean:
  - `go work sync`;
  - `go vet ./...` and `go test -race -count=1 ./...` in every workspace module;
  - `gofmt -l .`;
  - `govulncheck ./...` in `httpsec/prblmsec` and `test`.

## 9. Review

- [x] 9.1 A whole-branch review (Opus, fresh agent) against every requirement in this change's five spec deltas and the consumer documentation of group 7, which first enumerates how the change fails (`defensive-coding.md`). Findings go back to a fresh dispatch of the owning group. Verify that the review is clean and that 8.3 is re-run green after fixes.

## 10. One bounded, recovering walk classifies a refusal (design decision 11)

Order: 10.1 first. Then 10.2–10.3 (core) and 10.5 (fibersec) can run in parallel. Then 10.10 (panic frames), then 10.9 (remaining walks) and 10.4 (mapper) in parallel. Then 10.9b (10.9 review fixes) and 10.13a (no-allocation walk) in parallel, then 10.9a, then 10.12 (internals, sanitizer, then call sites in groups). Then 10.11 (prblm v0.2.1), then 10.6 (docs), 10.7 (gate) and 10.8 (review).

- [x] 10.1 `internal/errwalk`. Red: `TestFlatten` (table), with these cases:
  - order: root first, then depth first, through `Unwrap() error` and `Unwrap() []error`, each node's `Unwrap` called once;
  - a nil entry in `Unwrap() []error` is skipped but counts 1; a nil from `Unwrap() error` ends the branch;
  - a nil-pointer node (`reflect` Kind `Pointer` and `IsNil`) is skipped, none of its methods is called (a counter that would panic proves it), and it counts 1. A nil map or slice error type is not skipped;
  - budget: every examined entry counts, including the root, repeats, nil entries and typed nils. 1,000 succeed and the 1,001st aborts with reason `budget`. When the list plus the pending entries would pass 1,000, the walk aborts at once: one node with a 20,000-entry `[]error` of itself aborts without allocating proportionally, and one with a million nil entries aborts promptly;
  - a panicking `==` (a comparable type holding an incomparable value), and `panic(nil)` under `GODEBUG=panicnil=1`, both abort with `panic`;
  - a node over budget whose `Unwrap` would panic aborts with `budget`, because the count comes before any method call;
  - the walk order equals the order in which stdlib `errors.Is` consults its nodes, on nested joins, a wrap inside a join, a join inside a wrap and a diamond;
  - a self-cycle through `Unwrap() error`, a self-cycle through `Unwrap() []error`, and a cycle through `errors.Join` all abort with `budget` within a test timeout;
  - 25 levels of `errors.Join(n, n)` abort with `budget` in under 100 ms;
  - a panicking `Unwrap` aborts with reason `panic` and carries the recovered value.

  Also `TestMatch` for the matching helpers over the list: `Is` matches by `==` when comparable or by the node's `Is` method; `As[T]` matches by type or by the node's `As` method, first in list order; a panicking `Is` or `As` aborts with `panic`. Green: implement. Verify with `go test -race -run 'TestFlatten|TestMatch' -count=1 ./internal/errwalk/`.
- [x] 10.2 Core lookup over the walk. Red: `TestLookupStatus_HostileChains` (table) in `httpsec`, with these cases:
  - a self-cycle through each `Unwrap` form: `(500, false)`;
  - a fan-out of 25 levels: `(500, false)`, promptly;
  - a panicking `Is` method and a panicking `As` method: `(500, false)`, no escape;
  - a nil `*password.RejectedError` joined ahead of `authorize.ErrAccessDenied`: `(403, true)`;
  - a nil `*ChallengeError` joined ahead of an error whose `As` presents a challenge: that challenge's status;
  - a challenge 1,000 links in is found, and one past the budget gives `(500, false)`.

  The cycle and fan-out cases hang or crash before the change, so run them in a subprocess or under a timeout so that the red step is observable. Green: `LookupStatus` flattens once and classifies every check over the list. `firstChallenge` and its fallback are replaced. `StatusForError` stays `s, _ := LookupStatus(err)`. Update `TestStatusForError_ChallengeWalk`'s fallback-depth cases to the new rules. All existing lookup, agreement and inventory tests stay green. Verify with `go test -race -run 'LookupStatus|StatusForError|Challenge' -count=1 ./httpsec/`.
- [x] 10.3 Reporting. Red: `TestLookupStatus_AbortIsLogged`:
  - a cyclic error looked up once through the free function writes exactly one Error record to `slog.Default()` (swapped for the test, not in parallel), with reason `budget` and no error text;
  - a panicking `Is` writes one record with reason `panic`.

  `TestChain_AbortLogsToChainLogger`: a chain built with the consumer's `WithLogger` that dispatches a cyclic error writes the record to that logger and nothing to the default. Green: an unexported lookup variant returns the abort. The chain's error dispatch logs it with the chain's logger, using `diag.PanicAttrs` for a panic. The exported functions log to `slog.Default()`. Verify with `go test -race -run 'Abort' -count=1 ./httpsec/`.

  Review follow-up, both with red tests:
  - **Quiet sites under a consumer error handler.** Under `WithErrorHandler`, the quiet sites (the refusal event, the basic challenge header, OIDC consent, the session-signals checks) log an abort through the chain's logger and sampler. A chain with `WithLogger`, security events, and a handler that writes 418 without classifying, refusing a cyclic error, writes exactly one record.
  - **Per-reason sampling keys.** The sampling key is per reason, so a budget abort followed by a panic abort in one window writes two records.
- [x] 10.4 Mapper over the walk. Red: extend `TestMapper_ChallengeWalk` and add `TestMapper_HostileChains` in `httpsec/prblmsec`, calling `MapError` directly:
  - for each hostile chain in 10.2 the mapper's status agrees with `LookupStatus`: nil for the aborted ones;
  - the typed-nil `RejectedError` case gives the access-denied problem;
  - an aborted chain writes exactly one record, the lookup's, not a second.

  Green: `firstNonNil`, the specifics loop and `ruleOf` classify over the walk's list. The mapper returns nil without walking again when the lookup reports unrecognised. Verify with `go -C httpsec/prblmsec test -race -count=1 ./...`.
- [x] 10.5 fibersec refusal unwrapping over the walk. Red: `TestErrorHandler_HostileChains` in `httpsec/fibersec`, with these cases:
  - a cyclic error;
  - a panicking `As`;
  - a nil `*RefusalError` ahead of a real one.

  Each case must reach the handler's status without hanging or panicking. Green: the `errors.As` for `*RefusalError` and `*fiber.Error` (`errors.go`) and the `errors.Is(err, nextErr)` on the refusal path (`middleware.go`) use the walk. Verify with `go -C httpsec/fibersec test -race -count=1 ./...`.
- [x] 10.10 Panic frames captured at recovery (design decision 11, reporting).
  - Red: `TestFlatten_PanicCarriesFrames` in `internal/errwalk`. A panicking `Unwrap`, `Is` or `As` gives a `*PanicError` whose captured frames include the panicking method's function, not only errwalk's own functions.
  - Red: a test in `httpsec` that the abort record's frames name the panicking method, not `lookup` or `handleError`.
  - Red: a test in `httpsec/fibersec` that its abort record carries the panic's type and frames. This closes the open review finding that fibersec logged `reason` only.
  - Green:
    - the walker's deferred recover captures the stack (`runtime.Callers`) into the abort value;
    - `internal/diag` gains a formatter that redacts these captured frames as `diag.PanicAttrs` does;
    - the core and fibersec log helpers use it.

  Verify with `go test -race -run 'Panic|Abort' -count=1 ./internal/... ./httpsec/` and `go -C httpsec/fibersec test -race -count=1 ./...`.
- [x] 10.9 Every other inspection of the refused error on the refusal path uses the walk (design decision 11).
  - First inventory, with gopls, every stdlib `errors.Is` or `errors.As` that runs over the refused error before or beside the lookup, and report it. Expected:
    - `refused()`'s outage check;
    - `authorization.go`'s check;
    - `answerRetryOnly` and `markPerRequestThrottle` in `signals_retry.go`;
    - `eventsink.GuardRefused`;
    - the DPoP guard challenger;
    - `hangup.ByCaller`.
  - Red: for each site, a test sends a cyclic error and an error with a panicking `Is` through that path. On the current code the first hangs and the second panics. After the fix, each gets the fail-closed outcome with no hang and no panic.
  - Red: on a session-signals abort, one record is written as `classification-aborted` through the signals logger, not as a dependency failure.
  - Red: a `Chain` not built by `New` that dispatches a cyclic error writes one record to the default logger.
  - Green: each site checks over one `errwalk.Flatten`. Its existing order and outcome stay the same for every non-hostile error.

  Verify with `go test -race -count=1 ./...` in the root module.
- [x] 10.9b Fixes from the 10.9 review (design decision 11 failure rows). Each item needs a failing test first.
  - A quiet site (`reportQuietly`: authorization, the DPoP challenge, `answerRetryOnly`, `markPerRequestThrottle`, `emitPerRequestDenial`, `recordThrottledBearer`, and the DPoP guard path through `challenge()`) reports whenever its own walk aborted and the request's lookup did not.
    - Each site has a row using an error whose `Is` panics only for the sentinel that site checks. Each row fails with `expected: 1 actual: 0` first.
    - Under a consumer handler, each site also needs its own row, because only two sites have one today.
    - Correct the `authorization.go` comment "the dispatch answers it 500".
  - `emitRefusal` marks the refusal reported on the exchange when its walk aborts. A nested chain with `WithRefusalLogInterval(0)` then writes exactly one record. It fails with 2 first.
  - A consumer error wrapping `ErrDPoPNonceRequired` on a DPoP chain without nonces no longer panics. It is refused as the plain DPoP refusal with no nonce header. Reproduce the nil-pointer panic first.
  - Verify with `go test -race -count=1 ./...` (root).
- [x] 10.9a The rest of 10.9 (design decision 11 failure rows). Each item needs a failing test first.
  - `dpopAnswersChallenge` (`oidc_consents.go`) and the switch in `emitResponseRefused` (`challenge_spend.go`) use the walk. An `Is` that panics only for the sentinel each one checks no longer escapes.
  - A guard refusal behind `WithGuardErrorHandler`, whose `GuardRefused` event or DPoP challenge aborts, writes exactly one record to the default logger. It fails with 0 records first (the 10.9b re-review's rows G1, G1b, G2 and the gin probe).
  - Remove the process-wide reporter (`eventsink.SetGuardAbortReporter`):
    - `GuardRefused` returns its abort to the caller, and so does the guard's DPoP challenge.
    - Each guard's `refuse` applies the reporting rule itself: httpsec `guards.go`, ginsec `guards.go` and fibersec's guard.
    - The existing guard rows stay green.
    - New tests pin the rule with and without `WithGuardErrorHandler`, on each of the three guards.
  - These refusal-path reads, which the 10.12 inventory found and 10.9 missed, use the walk:
    - `resolve.go` `emitLoadRefusal`;
    - `dpop_nonce.go` `NonceCipher.Open` (around line 263), and the check around line 296 if it can see a consumer error;
    - `signals_retry.go` `streamErr` (around line 155), if it can see a consumer error;
    - `oidc_login.go` `emitCallbackRefused`;
    - `passkey_login.go` `emitPasskeyRefused`;
    - `challenge_spend.go` line 201 (the `emitResponseRefused` switch);
    - `mfa_enrol.go` `refusalReason`.
  - `oidcprovider/events.go` around line 222 moved to 10.12 (10.9a review). It reads the error only after `registry.go:353` has already read the consumer registry's error with stdlib `errors.Is`. A hostile error hangs or panics there first, so converting line 222 alone protects nothing, and the sanitizer at the registry read covers both.
  - Verify with `go test -race -count=1 ./...` (root).
- [ ] 10.12 Consumer-port errors are sanitized where they enter the library (design decision 11).
  - First, the internals with the most reach, read through the walk directly:
    - `diag.Failure` and `diag.causeOf` (`internal/diag/diag.go`);
    - `depfault.Silent` and `depfault.record` (`internal/depfault/depfault.go`).

    Red: each is handed a cyclic error and an error whose `Unwrap` panics, and hangs or panics on the current code. After the fix it returns its defined safe answer: `Failure` omits `cancelled`, `causeOf` returns the error unchanged, and `Silent` reports false.
  - Then the sanitizer:
    - `porterr.Sanitize(err error, unavailable error) error`, in `internal/porterr`, which every flow can import.
    - It walks `err` once. When the walk completes, it returns `err` unchanged. When the walk aborts, it returns a fixed library error that `errors.Is(_, unavailable)` matches, carries no consumer text, and reports one record.
    - Unit-test it first.
  - Then apply it at every port call site, in groups of at most six call sites per dispatch, in the order of the 10.12 inventory:
    - session and bearer;
    - login, password and lockout;
    - Basic, API key and JWT;
    - throttle and limiters;
    - recovery and magic link;
    - OIDC client;
    - OIDC provider (several dispatches), including the client registry read at `oidcprovider/registry.go:353` that `events.go:222` depends on (moved from 10.9a);
    - passkey;
    - MFA and enrolment, including the `method.Verify` read at `httpsec/challenge_spend.go:174` (named by the 10.9a review);
    - authorization;
    - token and one-time, including the `IssueWithin` read at `httpsec/challenge_spend.go:278` (named by the 10.9a review);
    - `store/seal`;
    - `expiry/sweep`, including the `PurgeExpired` read at `httpsec/challenge_spend.go:110` (named by the 10.9a review), and the webauthn `MetadataSource` in its nested module.
  - Per call site, the red test has the port's mock return a `cycleOne`, a `cycleMany` (in a subprocess) and a `panicUnwrap`. These hang, crash or panic on the current code. After the fix, the flow takes its existing branch for a failing port, and one record is written. A non-hostile parity row pins the old outcome.
  - Where that branch conceals (unknown user, unknown credential, a concealed lock, uniform recovery), assert the response is byte-identical to a plain port outage.
  - Verify each dispatch with `go test -race -count=1 ./...` in the affected modules.
- [x] 10.13a The walker does not allocate for chains that fit (design decision 11, performance).
  - Add a buffer-taking walk, for example `errwalk.FlattenInto(buf []error, err error) (Chain, error)`, that fills the caller's buffer and grows onto the heap only past its capacity. Keep `Flatten`.
  - The lookup, the mapper and fibersec use it with a stack array, for example `var buf [16]error`. Choose the size from the benchmark rows.
  - Red: `testing.AllocsPerRun` on `LookupStatus` for `bare-sentinel`, `wrap-5` and `join-3-challenge` asserts 0 allocations attributable to the walk, measured against the pre-walk baseline's count.
  - Re-run 10.13's benchmarks on an idle machine. The deltas against the pre-walk baseline go into the report.
- [x] 10.13 Benchmark the classification (design decision 11, performance).
  - Add `BenchmarkLookupStatus` and `BenchmarkMapError`. Their rows are: a bare sentinel, a 5-deep wrap, a 3-way join with a challenge, an unknown error, and a 50-link chain.
  - Run each against the pre-walk baseline `c1bf3e97` (a `git archive` export; `main` has no `LookupStatus` or prblmsec) and against the branch, with `-count=10 -benchmem`, and compare them with `benchstat`.
  - Report the deltas. A regression above 10% on any row is a finding: it goes back as a fix, or is recorded in design.md with its reason.
- [ ] 10.11 Require prblm v0.2.1 (design decision 8).
  - Require `github.com/kartaladev/prblm v0.2.1` in `httpsec/prblmsec`.
  - In `test`, require it together with `adapters/ginprblm v0.2.1`. `adapters/fiberprblm` stays on v0.2.0.
  - Run `go work sync`, then `go mod tidy` in each changed module. Check that no `go.sum` lost its `/go.mod h1:` lines.
  - Red: a `TestProblemParity` case where the route fails with an error whose own `As` method panics. With prblmsec registered, net/http and gin answer a 500 problem, and nothing escapes. On v0.2.0 the panic escapes `Respond`. Run it before the bump to see that.
  - Verify with `go -C httpsec/prblmsec test -race -count=1 ./...` and `go -C test test -race -run TestProblemParity -count=1 ./`.
- [ ] 10.6 Documentation. Write these:
  - godoc of `LookupStatus` and `StatusForError`: the bound, the typed-nil skip, fail-closed and the log record, and that consumer code calling stdlib `errors.Is` or `errors.As` on the same error is not protected;
  - prblmsec's package doc and the README section: the limit under prblm v0.2.0. A cycle hangs or dies in prblm's Describer step before the mapper runs, a panicking `As` escapes prblm's status-hint step, and gin's `Context.Error` walks the chain first;
  - CHANGELOG `[Unreleased]`:
    - Fixed: the status lookup no longer hangs, crashes or panics on a cyclic, fanned-out or panicking error chain, or on a typed-nil `*password.RejectedError`;
    - Changed: a challenge offered through an `As` method behind a typed nil is now found, and a chain over 1,000 links is unrecognised.

  Verify with `go doc ./httpsec LookupStatus` and `gofmt -l .`.
- [ ] 10.7 Re-run the 8.3 gate in full, the `test` module on an idle machine.
- [ ] 10.8 A whole-branch review (Opus, fresh agent) against decision 11 and the two new `http-error-propagation` requirements. It first enumerates how the change fails. Findings go back to a fresh dispatch of the owning task.

## Workflow follow-up

- Archive with `/opsx:archive` after merge; the next lockstep release tags `httpsec/prblmsec/vX.Y.Z` (maintainer).
