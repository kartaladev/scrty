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

- [ ] 9.1 A whole-branch review (Opus, fresh agent) against every requirement in this change's five spec deltas and the consumer documentation of group 7, which first enumerates how the change fails (`defensive-coding.md`). Findings go back to a fresh dispatch of the owning group. Verify that the review is clean and that 8.3 is re-run green after fixes.

## Workflow follow-up

- Archive with `/opsx:archive` after merge; the next lockstep release tags `httpsec/prblmsec/vX.Y.Z` (maintainer).
