# Design

## Context

See `proposal.md` for why. What exists today:

- **Core contract.** `httpsec.StatusForError` (`httpsec/errors.go`) is the one public mapping from an error to a status. It checks in a fixed order, and returns 500 both for an error it does not know and for the dependency failures it deliberately answers 500:
  1. issuing failures, `ErrChallengeUnavailable`, `oidcprovider.ErrDependency` and `recovery.ErrDependency`, all answered 500;
  2. `*ChallengeError`, by kind;
  3. the ordered `statusTable`.
- **Rendering is the consumer's.**
  - The net/http chain answers a refusal through `WithErrorHandler`, and guards through `WithGuardErrorHandler`. The default is a bare status.
  - On gin, `ginsec` puts the refusal on gin's error channel with the status set but not committed.
  - On fiber, `fibersec` returns a `*RefusalError` that wraps the refusal and a `*fiber.Error` carrying the status. `fibersec.ErrorHandler` is the bare-status default.
- **Fixed text for dependency failures.** A consumer dependency's failure is returned as an `internal/diag.Fault`: fixed text, with the library sentinels it stands for and the cause reachable (`diagnostic-redaction`).
- **Challenge tokens.** `ChallengeError.Token` is the only way a challenged login's new credential reaches the client. Verification that raises a further challenge rotates the session, so the client's old token stops working (`complete.go:700`, `mfa_verify.go:602,704`). The token's type is computed by the unexported `tokenTypeOf(session)`.
- **prblm v0.2.0** (core: standard library only; MIT).
  - `Handler.Resolve` tries, in order: a `*Problem` or `Describer` in the chain, scoped mappers, consumer mappers (`WithMappers`, in order), built-ins (its own sentinels, body errors, deadline errors), a `WithStatus` hint, and finally a 500 with no detail.
  - A `Mapper` returns nil for an error it does not own.
  - `Response.MergeInto` replaces only the header names the problem sets: `Vary` is merged, and `Cache-Control` is set only when absent.
  - `ginprblm.Middleware(opts...)` and `fiberprblm.ErrorHandler(opts...)` reuse the same response step. The fiber handler reads a `*fiber.Error` code as a status hint.

## Goals / Non-Goals

**Goals:**
- One mapping, owned and tested by scrty, from every refusal the core recognises to a typed RFC 9457 problem. Its status always agrees with `StatusForError`.
- No new oracle: a problem never separates refusals that the status table merges to conceal them.
- The same problem on net/http, gin and fiber.

**Non-Goals:**
- **Changing any default response.** Without the module, nothing changes.
- **The OpenID Provider's protocol bodies.** OAuth errors at the token, revocation, introspection and UserInfo endpoints are written by the provider itself and never reach an error handler (`http-error-propagation`).
- **Localised titles and details.** A consumer replaces them with a mapper of their own (decision 6).
- **`Retry-After` on 429s.** Refusals carry no delay. A consumer adds it with a mapper or an enricher, as prblm documents.
- **A prblm-side mapper (`prblm/mappers/scrtymap`).** See decision 1.

## Decisions

### 1. An opt-in nested module, `httpsec/prblmsec`

The integration is its own module, at `github.com/kartaladev/scrty/httpsec/prblmsec`, with package `prblmsec`.
- **Dependencies.** In production code it requires only `github.com/kartaladev/prblm` and the scrty core. The core never imports it, so the settled "the core renders nothing" decision stands for the core module (spec delta to `http-error-propagation`).
- **Tests.** The cross-framework parity tests need gin, fiber, `ginprblm` and `fiberprblm`. They live in the test module, so `prblmsec`'s `go.mod` never lists a framework.
- **Default and override:** nothing happens until the consumer registers it. Registering is the override of the core's bare-status default.
- **Alternatives:**
  - (b) A `scrtymap` module inside prblm. Rejected: the mapping must move in lockstep with scrty's refusal table and be tested against scrty's own refusals. A mapper released on prblm's cadence would lag every new sentinel.
  - (c) A renderer in the core. Rejected: it reverses a settled decision, and puts prblm in every consumer's module graph.

### 2. `httpsec.LookupStatus(err) (status int, ok bool)` in the core

The mapper must answer the errors scrty owns and stay out of the way of everyone else's. A later `pgxmap` or `sqlmap` mapper, or the consumer's own, decides those. `StatusForError` cannot say which is which, because it returns 500 for both kinds.

The core gains a comma-ok lookup. `StatusForError` becomes `s, _ := LookupStatus(err); return s`, so the two cannot disagree. `ok` is true when any of these holds:
- a `statusTable` row matches;
- the error is or wraps a `*ChallengeError`;
- one of the explicit 500 branches matches: issuing failure, `ErrChallengeUnavailable`, `oidcprovider.ErrDependency` or `recovery.ErrDependency`;
- the error is or wraps a `*diag.Fault`, a dependency failure the library reported under fixed text, whatever status that gives;
- the error matches a named dependency-unavailable sentinel the core returns unwrapped, such as `password.ErrHistoryUnavailable` or `password.ErrLookupUnavailable`. The implementation inventories these, and a test pins the list.

`LookupStatus(nil)` is `(500, false)`, matching `StatusForError(nil) == 500` while declining to claim it.

- **Why it matters for security, not only for neatness.** Under "treat 500 as no-match", a recognised dependency failure falls through to later mappers. For example, history unavailable caused by PostgreSQL `53300` would be remapped by `pgxmap` to 503, contradicting the settled "SHALL map to 500". It would also let a consumer's driver mapper produce a status for a failure the core deliberately flattened.
- **Established practice:**
  - gRPC pairs the lossy `status.Code(err)`, which is `Unknown` for foreign errors, with `status.FromError(err) (s, ok bool)`, where `ok` is false for errors it does not own.
  - Spring's `HandlerExceptionResolver` returns `null` for "not handled, continue the chain". That is distinct from an empty result, which means "handled".
  - prblm's own `Mapper` contract returns nil for "not mine".
  - Effective Go names comma-ok as the idiom for telling "absent" from a zero value, as stdlib's `os.LookupEnv` does.
- **Default and override:** a pure function with no configuration, and nothing to override. A consumer handler can now use it too.
- **Alternatives:**
  - (b) Treat a 500 from `StatusForError` as no match. Rejected for the reason above.
  - (c) Export the status table. Rejected: it freezes internals, and the table's order is semantic, so a consumer iterating it could get precedence wrong.
  - (d) A `prblm.Describer` on core errors. Rejected: it puts prblm in the core.

### 3. Typed problems: status first, then a type among that status's types

`Mapper().MapError(ctx, err)` works in four steps:
1. It calls `LookupStatus`, and returns nil when `!ok`.
2. It takes the candidate types whose status equals the looked-up status, in the order of the spec's table. Within one status, specific checks run before the default: a challenge by kind, then the specific sentinels (`errors.Is` or `errors.As`), then the status's default type.
3. A recognised status with no type (500, 405, 501) gets an `about:blank` problem with that status and no detail.
4. It attaches the cause with `prblm.WithCause(err)`, so prblm's hooks still reach the original error by `errors.Is` and `errors.As`.

**Why filtering by status gives the concealment guarantee.** `StatusForError` already resolves every precedence question: challenge over sentinel, and a concealed lock joined with authentication-failed answering 401. A type can only be chosen from the looked-up status's own set, so it can never contradict that resolution. For example, the `account-locked` type (429) cannot be chosen for an error whose status is 401. `authenticate.ErrUnavailable` maps to 401, and no 401 type tests for it, so it reaches the 401 default, `authentication-failed`. That is the same title, detail and members as a wrong password, which is what the spec's "byte-for-byte" scenarios pin.

**What drift costs.** A sentinel added to the core table later gets its status's default type with the right status. The worst case is a less specific type, never a wrong status or a leak.

- **Default and override:** the types in the spec's table under the prefix `security`. `WithTypePrefix` replaces the prefix (decision 6). A consumer mapper registered ahead of the integration replaces any single problem.
- **Alternatives:**
  - (b) Status-only `about:blank` problems. Rejected by the maintainer (2026-11-18): an MFA challenge and a wrong password are both 401, and a client cannot tell them apart.
  - (c) One type per sentinel. Rejected: it would publish the concealed distinctions (lock, outage, throttle), and every internal sentinel would become client API.

### 4. What a problem carries

- **Title and detail.** Each is a fixed English string per type, also used for the type's discovery documentation.
- **Extension members.** Each member is set with `Problem.Set`. All names are valid prblm extension names.
  - `challenge`: on every challenge type, a fixed token the integration owns, in the sub-types' kebab-case vocabulary: `mfa`, `password-change`, `mfa-enrolment` or `account-recovery`. A kind outside that list, such as a consumer's own, has no `challenge` member. Its type still says it is a challenge.
    - **Not `ChallengeKind.String()`:** that method returns Go constant names for logs, and a bare number for a consumer's kind. Exposing it would make a rename in `policy` a wire break. Maintainer's choice, 2026-11-18.
  - `methods`: on `mfa-required`, a list of `{name, channel, begins}`, with `channel` the `factor.Channel` string. An empty, non-nil list is rendered `[]`, which tells the caller only sign-out is left. A nil list (no session) is omitted.
  - `max_age`: on `reauthentication-required`, `floor(Window / time.Second)`, only when the refusal is a `*ReauthenticationRequiredError` with `Window > 0`. Rounding down never tells a client a staler proof will do.
  - `rule`: on `password-rejected`, the `password.Rule` string from a `password.RejectedError`. A rejection with no `RejectedError` in the chain has no `rule`.
- **Never in a problem:** text from the error. `Detail` is never derived from `err.Error()`.

- **Default and override:** as above. A consumer who wants other wording or members registers a mapper ahead (decision 6).

### 5. The challenge's credential is delivered by default

When `ChallengeError.Token` is not empty, the problem carries `access_token`, and `token_type` from the new `ChallengeError.TokenType`. The problem also sets `Cache-Control: no-store` itself. prblm's own default is `no-store` too.

- **The core sets `no-store` too (whole-branch review finding, 2026-11-18; maintainer's choice).** prblm v0.2.0's `Response.MergeInto` keeps any `Cache-Control` already on the response (`respond.go:70-73`). So a consumer middleware that sets `Cache-Control: public, max-age=300` ahead of the chain won over the problem's `no-store`, and the `access_token` went out cacheable (reproduced by the review). The core therefore sets `Cache-Control: no-store` on the response, replacing any earlier value, wherever it returns a `ChallengeError` that carries a `Token`. It does so before the refusal propagates, as it does for `WWW-Authenticate`. This covers every renderer: `prblmsec`, a consumer's own `WithErrorHandler`, gin and fiber. It matches the core already owning `Cache-Control` on token-bearing success responses, and RFC 6749 §5.1.
  - **Default and override:** none. A response carrying a credential is never cacheable, which is a guarantee, not a policy (`library-design.md` rule 4). A consumer error handler that deliberately overwrites the header after the refusal owns that choice.
  - **Alternative rejected:** (b) accept and document that an upstream `Cache-Control` wins. Rejected by the maintainer: a shared cache could store the token whenever a consumer got the middleware order wrong.

- **Core change.** `ChallengeError` gains `TokenType TokenType`, set wherever `Token` is set, from the existing `tokenTypeOf(session)`. A renderer therefore never re-derives it from `Session.KeyBinding`, and so cannot drift from the login success document.
- **Consumer-built errors.** A `ChallengeError` the consumer builds with a `Token` and no `TokenType` gets `access_token` and no `token_type`. The library does not guess `Bearer` for a token that may be DPoP-bound.
- **Why on by default** (maintainer's choice, 2026-11-18). Without it, a bearer-token client cannot continue a challenged login. After a rotated challenge it holds a credential that no longer works. Both are dead ends that the integration exists to remove. The credential is the pending session's, so it is only good for answering the challenge.
- **Default and override:** on. `WithoutChallengeToken()` withholds both members, for cookie-only deployments or a consumer who delivers the token another way.
- **Alternatives:** (b) off by default. Rejected by the maintainer: it is safe, but leaves the flows broken by default.

### 6. API shape and configuration errors

```go
p, err := prblmsec.New(prblmsec.WithTypePrefix("auth")) // options optional
// p.Mapper() prblm.Mapper   — the mapper alone
// p.Types()  []*prblm.Type  — definitions for prblm.WithTypes / discovery
// p.Option() prblm.Option   — WithTypes(p.Types()...) then WithMappers(p.Mapper())

h := prblm.NewHandler(prblm.WithNamespace("/probs"), p.Option(), prblm.WithMappers(appMappers...))
chain, _ := httpsec.New(httpsec.WithErrorHandler(h.Write) /* , ... */)
guards, _ := httpsec.NewGuards(az, httpsec.WithGuardErrorHandler(h.Write))
// gin:   engine.Use(ginprblm.Middleware(prblm.WithNamespace("/probs"), p.Option()), ginsec.Middleware(chain))
// fiber: fiber.New(fiber.Config{ErrorHandler: fiberprblm.ErrorHandler(prblm.WithNamespace("/probs"), p.Option())})
```

- **Constructor errors.** `New` returns an error rather than panicking, as scrty's constructors do. It returns `prblmsec.ErrConfig` for:
  - a prefix that is not a valid prblm sub-type (lowercase letters and digits in `/`-separated segments, with single `-`, `_` or `.` between). Validity is prblm's own. `New` builds every type with `prblm.DefineType`, which panics on an invalid sub-type, recovers only that construction-time panic, and returns `ErrConfig` wrapping it. scrty never restates prblm's grammar, so the two cannot drift;
  - a nil option;
  - an option given twice, as `httpsec.New` refuses.
- **Immutability.** `Problems` is immutable after `New`. The types are defined once there, so `Mapper` and `Types` always agree on the prefix, and everything is safe for concurrent use.
- **Ordering.** prblm runs consumer mappers in registration order. `Option()` registers the integration's mapper where it appears among the options, and the godoc says to put it before the application's mappers.
- **Missing namespace.** Without a prblm namespace, a sub-type is sent relative and prblm reports `ErrInvalidType` to its hooks. The godoc and the examples always set one. This is prblm's rule, not one scrty overrides.
- **Default and override:** prefix `security` (`WithTypePrefix`) and token on (`WithoutChallengeToken`). Any single problem can be replaced by a consumer mapper ahead of the integration's (spec scenario "Consumer's own lock page").

### 7. Framework wiring, and the headers the chain set

- **net/http.** The consumer passes `h.Write` to `WithErrorHandler` and `WithGuardErrorHandler`. The chain has already put `WWW-Authenticate`, `DPoP-Nonce` and the security headers on the writer. `MergeInto` replaces only names the problem sets, and the problem sets only `Cache-Control`, and only on a token-bearing challenge. So they survive.
- **gin.** `ginprblm.Middleware` is registered before `ginsec.Middleware`, reads the refusal from `c.Errors`, and writes the problem. `ginsec` set the status without committing it, so the problem's status, which is the same status, is written.
- **fiber.** `fiberprblm.ErrorHandler` replaces `fibersec.ErrorHandler` as `fiber.Config.ErrorHandler`. The refusal is reached through `*RefusalError`'s `Unwrap() []error`. The integration's mapper runs before prblm's `*fiber.Error` hint, and an unrecognised inner error falls to that hint (500).
- **fiber headers, by code reading.** fiberprblm's `send` (`adapters/fiberprblm/handler.go`, read at 003affb) projects only the problem's own header names from the fiber response, merges them by `MergeInto`'s rules, and writes back only those names. So an interceptor's `WWW-Authenticate` survives. The parity test pins this, so a later prblm version that changes it fails the Dependabot bump.
- **No change upstream.** prblm already has everything this design uses: the `Mapper` contract, `WithCause`, `Problem.Set`, `DefineType`, `MergeInto`, and adapters that take `prblm.Option`. Two upstream additions would be nice to have, and neither is needed:
  - an exported sub-type validator, which would let `New` validate a prefix without the recover described in decision 6;
  - a handler option to rank consumer mappers above step 1's `Describer` (see failure modes).

### 8. Dependency, layout and release

- **Versions.** `prblmsec` requires `github.com/kartaladev/prblm v0.2.0`. The test module also requires `adapters/ginprblm v0.2.0` and `adapters/fiberprblm v0.2.0`.
- **Where the module is listed.** `go.work`, `.github/dependabot.yml`, `tools/repocheck`'s module expectations, `RELEASING.md`'s module list, and the lockstep tag set (`httpsec/prblmsec/vX.Y.Z`).
- **Live figures** (read 2026-11-18; they drift): prblm is MIT, its tags are `v0.1.0` and `v0.2.0`, its last push was 2026-11-18, and it has 0 stars. Both projects have the same owner. The release gate's `govulncheck` and SBOM steps cover the new module like any published module (`supply-chain`).

### 9. Consumer documentation follows the repository's three places

Consumers learn scrty from three places, and the module is documented in each:
1. **Runnable examples.** They have `// Output:` blocks, so `go test` checks them and pkg.go.dev shows them. They live in `prblmsec` for net/http only, so the module never requires gin or fiber.
2. **The package overview.** `doc.go` covers wiring for all three frameworks, the type table, members, the token, ordering and stated limits.
3. **A `README.md` section.** It sits beside the other capability sections, with "Defaults" and "Stated limits" subsections.

- **Snippets that can't run as examples.** The gin and fiber snippets are prose, and each names the parity test it mirrors (`TestProblemParity` in the test module). A reviewer checks that each matches, which is how prblm's own README keeps its snippets honest.
- **Cross-references.** Every place that today tells the consumer to render a refusal themselves now names `prblmsec`:
  - `httpsec`'s "Failing closed" section and `WithErrorHandler`;
  - the "Refusals" sections of `ginsec` and `fibersec`, and `fibersec.MapError`;
  - the README passage requiring the error handler to deliver `ce.Token`.

  A consumer who reads any of these finds the ready-made option.
- **gin with `ginprblm` needs no declaration.** `ginprblm.Middleware` defers the response header, so it renders the chain's own 404s with or without `ginsec.WithRefusalsRendered()` (decision 10). The `prblmsec` docs and the README gin snippets therefore show `ginsec.Middleware(chain)` with no option. They name the option as the declaration for a consumer's own error middleware that writes immediately, and state that gin with no renderer at all answers those 404s with an empty body.
- **Default and override:** not applicable, since this is documentation.
- **Alternatives:**
  - (b) gin and fiber examples in the test module. Rejected: pkg.go.dev shows examples only for the package they belong to.
  - (c) A separate docs site. Rejected: the repository has none, and the README is where consumers already look.

### 10. `ginsec.WithRefusalsRendered()`: the consumer declares an error renderer

**The problem.** On a path gin matched no route for, `ginsec`'s `refuse` (`middleware.go:154`) sends a 404 immediately with an empty body (`gc.FullPath() == ""`, then `WriteHeaderNow`). That covers every 404 at the chain's own endpoints, because they are not gin routes: an unknown identity provider, an unknown MFA method, passkey not found, sign-in not found.

- **Why it was settled.** With no error middleware, gin's `serveError` (gin v1.12, `gin.go:764`) writes `404 page not found` for a 404 nothing wrote, and the other adapters send an empty body (`framework-adapters`).
- **What it costs an error middleware.** An error middleware that writes after `c.Next()` on gin's own writer finds the response already sent, and cannot render a problem there.
- **What it does not cost `ginprblm` (finding, 2026-11-18, corrects the original assumption).** `ginprblm.Middleware` v0.2.0 swaps in a `deferredWriter` (`writer.go:14-23`). On it, `WriteHeader` and `WriteHeaderNow` only record the status, and the response commits on the first body write. So `refuse`'s `WriteHeaderNow` sends nothing, and `ginprblm` renders the `not-found` problem with or without the option. The parity test pins both. This decision originally assumed `ginprblm` was blocked too; it is not.
- **What doesn't fix it.**
  - A consumer `NoRoute` handler never runs: `refuse` aborts first.
  - gin issue #4189 asks only for an opt-in skip of global middleware on 405, which would not change this.
  - The fix has to be in `ginsec`. srvr, the consumer that meets this gap, confirmed it cannot own a `ginsec` change and will adopt the option once it ships (2026-11-18).

**The decision.** `ginsec.Middleware(chain *httpsec.Chain, opts ...Option) gin.HandlerFunc`, with `type Option func(*config)` and `func WithRefusalsRendered() Option` (the maintainer's choice of name).
- With the option, `refuse` still registers the error, sets 404 and aborts, but skips `WriteHeaderNow`. An error middleware registered earlier writes after `c.Next()`, and `serveError` sees `Written()` and adds nothing.
- Without the option, nothing changes.
- **Detection rejected.** `ginsec` cannot reliably detect a downstream error middleware in gin, so the consumer declares it.
- **Kept after the finding** (maintainer's choice, 2026-11-18). `ginprblm` users do not need the option, but error middleware that does not defer the write, such as a consumer's own JSON middleware, still does. The option, its `ginsec` tests and the `framework-adapters` scenarios stay as they are.

- **Default and override:** the default is unchanged (an empty 404). The option is the override. The declaration is the consumer's promise: the library cannot check it, so its godoc names what breaking the promise costs.
- **Option rules.**
  - The option carries no value, so giving it twice is harmless rather than refused. That departs from `httpsec.New`, which refuses repeated single-value options because two values would conflict. Here there is nothing to conflict, and `Middleware` returns no error to refuse with.
  - A nil `Option` is skipped, for the same reason.
- **Compatibility.** Adding a variadic parameter keeps every existing call compiling. The only break is code that stores `ginsec.Middleware` as a `func(*httpsec.Chain) gin.HandlerFunc` value. That is allowed before the next tag, and recorded in `CHANGELOG.md`.
- **Alternatives:**
  - (b) Leave the limit documented. Rejected by the maintainer: gin users of an error middleware that writes immediately would get empty 404s exactly where a client needs to know what went wrong. (The rejection was first argued for `ginprblm` users. The finding above shows they are not affected, and the maintainer kept the option for the other middleware.)
  - (c) A consumer route mirroring every chain endpoint path, so that `FullPath()` is not empty. Rejected: it is untested, breaks with `WithBasePath`, and conflicts with gin's wildcard rules.
  - (d) Always leave the 404 open. Rejected: it breaks the settled parity of the no-middleware default.

| Failure | State | Outcome |
|---|---|---|
| Option set, error middleware renders | Handled, tested | The middleware's body and status are sent |
| Option not set, `ginprblm.Middleware` registered before `ginsec` | Handled, tested (parity test) | `ginprblm`'s deferred writer holds the early 404 uncommitted, so the `not-found` problem is sent, as with the option |
| Option not set, a consumer error middleware that writes immediately | Accepted, documented | The early 404 is already sent with an empty body, and the middleware cannot render it. The godoc names the option for this case |
| Option set, no error middleware | Accepted, documented, tested | 404 with gin's generic text. Still fails closed, carries no scrty text, and differs from the other adapters' empty body |
| Option set, error middleware registered after `ginsec` | Accepted, documented | It never sees the refusal, as for every refusal today. Gin's text 404 is sent |
| Option set, middleware renders only some errors | Accepted, documented | A skipped no-route 404 gets gin's text, and other refusals get the bare status |
| Option given twice, or a nil option | Handled, tested | Same as once, or skipped |
| Option not set (default), no error middleware | Handled, tested | An empty 404, exactly as today. The existing scenario stays green |
| A 404 on a route the consumer registered | Handled, tested | Unaffected by the option: left open, as today |
| A refusal of another status on an unrouted path | Handled, tested | Unaffected: only the 404 was ever sent early |
| A gin guard used globally, refusing 404 on an unrouted path (a consumer authorizer returning a 404-mapped sentinel) | Accepted, documented | Guards do not take the option, so the 404 is committed with an empty body, which fails closed as on net/http. `WithGuardErrorHandler` renders guard refusals directly. A guard option is not worth its API cost |

### 11. One bounded, recovering walk classifies a refusal

Before this decision, the core lookup and the mapper classified an error with stdlib `errors.Is` and `errors.As`, about 80 full chain walks for one unrecognised error, plus a nil-skipping fallback. The stdlib calls have no bound and no recovery. On a consumer-built error that misbehaves, they fail in ways the library cannot stop:
- a cycle through `Unwrap() error` loops forever;
- a cycle through `Unwrap() []error` overflows the stack, a fatal error that `recover` cannot catch;
- a join that fans out costs seconds with no cycle at all: 25 levels of `errors.Join(n, n)` took 4.25 s in prblm's probe;
- an error's own `Is` or `As` method may panic;
- a typed nil makes `errors.As` stop on it, and makes a value-receiver `Is` panic (`password.RejectedError`).

The Go maintainers have declined cycle detection in `errors` (golang/go #34957, #40589, #70746), so the library has to protect its own classification.

**Decision.** A single walker in `internal/errwalk` flattens the chain once. The core lookup (`LookupStatus`, `StatusForError`), the prblmsec mapper and fibersec's refusal unwrapping all classify by scanning that one list, so they cannot disagree. Its rules are pinned, and prblm adopts the same rules for its v0.3.0 hardening, so a consumer sees one rule across both libraries.
- **Order:** root first, then depth first, the order `errors.Is` and `errors.As` visit. Each node's `Unwrap` is called once. A nil entry in an `Unwrap() []error` is skipped and costs nothing. A nil result from `Unwrap() error` ends that branch.
- **Matching:** a node matches a target as `errors.Is` or `errors.As` would: by `==` when comparable, a direct type match, or its own `Is` or `As` method. "First match" means first in list order, so precedence is unchanged.
- **Typed nil:** a node whose dynamic value is a nil pointer (`reflect` Kind `Pointer` and `IsNil`) is skipped entirely. None of its methods is called, and it costs nothing. Nil maps, slices, funcs and chans are not treated as nil.
- **Budget:** each node appended to the list counts 1, the root and repeats included. Appending the 1,001st node aborts the walk. The count is taken when a node is visited, before any of its methods is called.
- **Panic:** a panic in a node's `Unwrap`, `Is` or `As` call, made during the walk, is recovered and aborts the walk.
- **Abort outcome:** both aborts (budget, panic) fail closed. The lookup answers 500, unrecognised (`ok == false`). The mapper, which starts from the lookup, then returns nil, as for any unrecognised error, and prblm answers with its own 500. The mapper never walks the chain again after the lookup aborted, so it adds no second record. Nothing guesses what an unreached or panicking link would have said.
- **Reporting:** one Error-level slog record per aborted classification, with a constant message, a `reason` attribute (`panic` or `budget`) and, for a panic, the redacted panic attributes (`diag.PanicAttrs`). The walker reports the abort to its caller and never logs by itself. A caller that holds the chain's logger (the chain's error dispatch, session signals) logs there. The free functions `LookupStatus` and `StatusForError`, the prblmsec mapper and the gin and fiber adapters log to `slog.Default()`. The reasons are internal, not exported.

**Default and override.** The rules have no options. The bound and the fail-closed outcome are a guarantee, not a preference, and a consumer who could raise the budget could reopen the hang (`library-design.md` 4). The consumer controls where the record goes, through the chain's `WithLogger` or `slog.SetDefault`.

**What it changes against `main`:**
- A challenge more than 1,000 links deep is no longer found. That is an unrealistic chain.
- A typed nil whose methods are nil-safe and meaningful is ignored, where stdlib would honour it. The library builds no such error.
- A challenge offered through an `As` method behind a typed nil is now found, because the walk keeps going past the nil.
- A typed-nil `*password.RejectedError` no longer panics the lookup. It is skipped, and the rest of the chain decides.

**The line scrty cannot cross.** The walker protects scrty's own classification only.
- Consumer code that calls stdlib `errors.Is` or `errors.As` on the same error still sees the typed nil, and still hangs or panics. The hardened lookup and stdlib-based code can therefore disagree about one error.
- prblm v0.2.0 walks the error itself, before or outside the scrty mapper. Its Describer step hangs or dies on a cycle before the mapper runs. A panicking `As` method escapes `Respond` from its status-hint step. gin's own `Context.Error` and fiberprblm's hint walk the chain too.
- prblm v0.2.1 recovers the status-hint step, and v0.3.0 is to adopt this walker's rules. Until then, the godoc and README state the limit.

**Alternatives.**
- A depth limit only: rejected, because it does not stop fan-out.
- Skipping a panicking link and continuing: rejected. The skipped link may be the one that decided precedence, a concealed lock for example, so the answer could reveal what concealment hides.
- A new exported `ClassifyError(err) (status, ok, fault)`: rejected for now. It adds public API, and every adapter would have to change to call it.

### Failure modes

| Failure | State | Outcome |
|---|---|---|
| Error the core does not recognise | Handled, tested | Mapper returns nil. Later mappers, then prblm's 500 |
| Recognised dependency failure wrapping a driver error (`53300`) | Handled, tested | 500 `about:blank`, not the driver mapper's status |
| Concealed lock / user-store outage | Handled, tested | Byte-identical to a wrong password |
| Challenge wrapping a sentinel | Handled, tested | Challenge's type and status |
| Typed-nil pointer in the chain (`*ChallengeError`, `*password.RejectedError`, any type) | Handled, tested (decision 11) | The walker skips the node entirely and calls none of its methods, so a value-receiver `Is` cannot panic. The rest of the chain decides: a real challenge or refusal joined behind it is found. Consumer code calling stdlib `errors.As` on the same error still sees the nil |
| An error presents itself as a `*ChallengeError` only through its own `As(any) bool` method | Handled, tested (decision 11) | Recognised as that challenge, as `errors.As` recognises it: its status, type and members. This also holds when it is joined behind a typed nil, because the walker keeps going past the nil |
| A challenge more than 1,000 links into the chain | Handled, tested (decision 11) | The walk's budget runs out. The classification fails closed with 500, unrecognised, and is reported with reason `budget`. Legitimate chains are far below the budget |
| A cyclic error chain, through `Unwrap() error` or `Unwrap() []error` | Handled, tested (decision 11) | The budget stops the walk at 1,001 visited links: no hang, no stack overflow. The result is 500, unrecognised, reported with reason `budget`. prblm v0.2.0's own walks still hang or die on the same error before the scrty mapper runs, and so does consumer code calling stdlib. Documented as the line scrty cannot cross |
| A join that fans out (`errors.Join(n, n)` nested) with no cycle | Handled, tested (decision 11) | The budget counts repeats, so the walk stops after 1,000 visits instead of 2^depth. The result is 500, unrecognised, reported with reason `budget` |
| An error's own `Unwrap`, `Is` or `As` method panics during the walk | Handled, tested (decision 11) | Recovered. The classification aborts and fails closed with 500, unrecognised, and is reported with reason `panic` and the redacted panic attributes. It never guesses what the panicking link would have said. Under prblm v0.2.0 a panicking `As` method still escapes `Respond` from prblm's own status-hint step; v0.2.1 recovers it |
| An aborted classification nobody can see | Handled, tested (decision 11) | One Error-level slog record per abort, to the chain's logger where the caller holds it, else `slog.Default()`. The record carries a constant message and the reason, and never the error text |
| A consumer wants a larger budget or a different typed-nil rule | Accepted, documented (decision 11) | No option. A configurable bound could reopen the hang, so the rules are fixed (`library-design.md` 4). The consumer controls only where the record goes |
| `Methods` nil vs empty | Handled, tested | Omitted vs `[]` |
| `Window <= 0`, or a rejection without `RejectedError` | Handled, tested | `max_age` / `rule` omitted |
| Token present without `TokenType` (consumer-built) | Handled, tested | `access_token` only |
| Token-bearing problem cached | Handled, tested | `Cache-Control: no-store` on all three frameworks |
| A consumer middleware set `Cache-Control` before the chain, and a token-bearing challenge is refused | Handled, tested (decision 5) | The core replaces it with `no-store` before the refusal propagates, so prblm's merge keeps `no-store`. Tested in the core and on all three frameworks |
| A consumer error handler overwrites `Cache-Control` after the refusal | Accepted, documented | The consumer's handler writes the response and owns its headers. The godoc of `ChallengeError.Token` says the response must stay `no-store` |
| Invalid prefix, nil or duplicate option | Handled, tested | `ErrConfig` from `New` |
| A `*Problems` not built by `New` (nil, or a zero value after ignoring `New`'s error) | Handled, tested, documented | `Mapper`, `Types` and `Option` on a nil pointer panic when the handler is wired, before any traffic. A zero value registers no types, and its mapper matches nothing, so prblm alone decides. The godoc says a `Problems` comes only from `New` |
| A consumer port's error wraps a library refusal sentinel, which a type within the same status tests for (for example a cause wrapping `ErrAuthenticationRequired` under a refused recovery) | Accepted, documented | The status is unchanged, but the type can follow the port's sentinel instead of the refusal, which can reveal that a dependency was involved. Nothing the library ships produces it. Only the consumer can prevent it, so the godoc warns that ports must not return library refusal sentinels, next to the warning about describers |
| A very long prefix | Accepted | It is the consumer's own construction-time configuration, not request input. prblm's grammar is the only check, and no length bound is added |
| New core sentinel without a type | Handled, tested | Status default type. A test asserts status agreement for every sentinel the spec names |
| `LookupStatus` and `StatusForError` disagree | Handled, tested | Impossible by construction. An agreement test covers every table row, kind and an unknown error |
| A dependency-unavailable sentinel left out of `LookupStatus` | Handled, tested | Inventory test pins the list. Left out, it would fall to prblm, where the status may differ from 500 |
| Mapper registered after a consumer mapper or built-in that also matches a scrty refusal | Accepted, documented | That mapper wins. The godoc says to register the integration first |
| A consumer port returns a `*prblm.Problem` or `Describer`, which scrty wraps in a `Fault` with the cause reachable | Accepted, documented | prblm's step 1 renders the consumer's problem ahead of every mapper, so it can reopen the outage oracle. Only the consumer can prevent it, so godoc warns that ports must not return describers |
| prblm hooks (`OnError`, `AddErrorHook`) receive a token-bearing problem | Accepted, documented | A hook that logs extensions logs the token. Godoc names `WithoutChallengeToken` and `access_token` |
| Unrecognised context errors (`DeadlineExceeded`) | Accepted | prblm's built-in maps them (504). A context error inside a library `Fault` stays 500 |
| No prblm namespace | Accepted, documented | Relative types plus prblm's `ErrInvalidType` note |
| Mapper panics | Accepted | prblm contains it, reports a `*PanicError` and falls back to its 500 |
| gin 404 at a chain endpoint (no gin route matched) | Handled, tested (decision 10) | With `ginprblm.Middleware`, the `not-found` problem, as on net/http and fiber, with or without `ginsec.WithRefusalsRendered()`. With no renderer at all, an empty 404 (the `framework-adapters` default). With an error middleware that writes immediately, the option is needed, else an empty 404. The parity test covers `ginprblm` both ways and the no-renderer default |
| fiberprblm drops interceptor headers | Handled, tested | Not the case at 003affb (code reading, decision 7). The parity test pins it |
| prblm breaking change in a later version | Accepted | Dependabot proposes the bump, and the parity tests gate it |
| A held identifier (`lockout.ErrAccountHeld`, the disclosed lock) | Handled, tested | `account-locked` (429), the spec table's "disclosed account lock". A concealed lock still answers 401 `authentication-failed` |
| The parity tests do not pin the problem media type or `no-store` (group 6 review) | Judged not a gap (whole-branch review) | Each parity observation includes `Content-Type` and is compared across net/http, gin and fiber. The token-bearing cases assert `Cache-Control` is exactly `[no-store]` |

## Risks / Trade-offs

- [The type table becomes client API] → Sub-types are stable once tagged. Adding a type is compatible, but renaming or merging one is a breaking change under the release policy.
- [A typed 401 tells clients more than a bare 401] → Only distinctions the status table already makes, plus the challenge kinds the core already exposes to handlers. The concealment invariant is tested.
- [Token in a response body] → `no-store`, opt-out, and documented hook exposure (decision 5).
- [Two owners for one org's libraries] → Lockstep versions are scrty's. prblm is pinned and bumped by Dependabot like any dependency.

## Migration Plan

Additive. It ships in the next lockstep release with a `CHANGELOG.md` entry under Added: the new module, `LookupStatus` and `ChallengeError.TokenType`. Rollback means not registering the mapper. Removing the module before a tag costs nothing.

## References

### Decision 1: module placement

Reasoned from scrty's own settled specs (`module-layout`, `release-policy`, `http-error-propagation`) and `openspec/config.yaml`'s layout context.

**Researched** (2026-11-18):
- [kartaladev/prblm at 003affb: README, package doc, `mappers/pgxmap`](https://github.com/kartaladev/prblm/tree/003affb): mappers for other libraries are opt-in modules that do nothing until registered, the pattern this module follows on scrty's side.

### Decision 2: recognising status lookup

**Researched** (2026-11-18):
- [grpc-go `status.FromError` and `status.Code`](https://pkg.go.dev/google.golang.org/grpc/status#FromError): a lossy code function paired with a comma-ok lookup whose `ok` is false for foreign errors.
- [Spring `HandlerExceptionResolver`](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/web/servlet/HandlerExceptionResolver.html): `null` means "not handled, continue the chain", distinct from an empty, handled result.
- [Effective Go, Maps](https://go.dev/doc/effective_go#maps): the comma-ok idiom for telling absence from a zero value.
- [kartaladev/prblm `Mapper`](https://github.com/kartaladev/prblm/blob/003affb/mapper.go): a mapper returns nil for an error it does not recognise, and resolution continues.

### Decisions 3 and 4: typed problems and their contents

**Researched** (2026-11-18):
- [RFC 9457 §3.1.1, §3.2, §5](https://www.rfc-editor.org/rfc/rfc9457.html):
  - `type` identifies the problem, and should lead to human-readable documentation;
  - clients must ignore unknown extension members;
  - problem details must not leak implementation details.
- [kartaladev/prblm README: problem types, discovery, extension name rule](https://github.com/kartaladev/prblm/blob/003affb/README.md): the sub-type grammar, namespace resolution and `ErrInvalidType` behaviour this design relies on.

Concealment rules are reasoned from scrty's own settled `http-error-propagation` and `diagnostic-redaction` specs.

### Decision 5: challenge token

**Primary documentation:**
- [RFC 6749 §5.1](https://www.rfc-editor.org/rfc/rfc6749#section-5.1): responses carrying tokens are sent with `Cache-Control: no-store`.
- [kartaladev/prblm `respond.go` at v0.2.0](https://github.com/kartaladev/prblm/blob/v0.2.0/respond.go) (researched 2026-11-18, read from the module cache): `Response.MergeInto` copies the problem's `Cache-Control` only when the response has none (lines 70-73). This is why the core, not the mapper, must set `no-store` on a token-bearing challenge.
- [RFC 9449 §5](https://www.rfc-editor.org/rfc/rfc9449#section-5): `token_type` `DPoP` for a DPoP-bound access token.

### Decision 7: framework wiring and headers

**Researched** (2026-11-18):
- [kartaladev/prblm `respond.go` `Response.MergeInto`](https://github.com/kartaladev/prblm/blob/003affb/respond.go): replaces only the header names the problem sets, merges `Vary`, and sets `Cache-Control` only when absent.
- [kartaladev/prblm `adapters/ginprblm`, `adapters/fiberprblm`](https://github.com/kartaladev/prblm/tree/003affb/adapters): `Middleware(opts...)` and `ErrorHandler(opts...)`. A `*fiber.Error` code is a status hint.

**Primary documentation:**
- [RFC 9110 §11.6.1](https://www.rfc-editor.org/rfc/rfc9110#section-11.6.1): a 401 carries `WWW-Authenticate`, which is why the chain's header must survive.

### Decision 10: the gin declaration

**Researched** (2026-11-18):
- [gin v1.12.0 `gin.go` `serveError` and `handleHTTPRequest`](https://github.com/gin-gonic/gin/blob/v1.12.0/gin.go), read from the module cache: the no-route chain is global middleware plus `NoRoute` handlers, run inside `serveError`. That function writes its default body only when nothing was written and the status is still the error code.
- [gin-gonic/gin issue #4189](https://github.com/gin-gonic/gin/issues/4189) (open): asks for an opt-in skip of global middleware on 405 only. It would not change the no-route 404 path.
- [kartaladev/prblm `adapters/ginprblm/writer.go` at v0.2.0](https://github.com/kartaladev/prblm/blob/adapters/ginprblm/v0.2.0/adapters/ginprblm/writer.go), read from the module cache: `Middleware` installs a `deferredWriter` whose `WriteHeader` and `WriteHeaderNow` only record the status, and the response commits on the first body write (`writer.go:14-23`). The basis for the finding that `ginprblm` renders the chain's no-route 404 with or without the option.

Otherwise reasoned from scrty's own settled `framework-adapters` spec, and from srvr's confirmation that it consumes `ginsec` and cannot change it.

### Decision 8: dependency

**Researched** (2026-11-18; live figures drift):
- [kartaladev/prblm repository metadata](https://github.com/kartaladev/prblm): MIT, tags `v0.1.0` and `v0.2.0`, 0 stars, last push 2026-11-18. The core `go.mod` has no requirements.

### Decision 11: one bounded, recovering walk

**Researched** (2026-11-19):
- [golang/go #34957](https://github.com/golang/go/issues/34957), [#40589](https://github.com/golang/go/issues/40589) and [#70746](https://github.com/golang/go/issues/70746), opened and read by the prblm research session: all closed. The maintainers place cycle detection outside the `errors` package, so a library that must not hang protects its own walk.
- Go 1.27.4 `src/errors/wrap.go`, read from the toolchain: `Is` and `As` loop over `Unwrap() error` and recurse over `Unwrap() []error`, with no cycle check, no bound and no `recover`.
- kartaladev/prblm v0.2.0 (`handler.go`, `builtins.go`, `panic.go`, `respond.go`), read from the module cache and probed by the prblm research session. Every outcome was reproduced with a named probe test.
  - The handler runs its Describer, mapper, built-in and status-hint steps in that order. Every chain walk in it is unbounded.
  - A cycle hangs or overflows the stack in the first step.
  - A panicking `As` method escapes from the status-hint step.
  - A typed nil yields a wrong 500 or 413.
  - 25 levels of `errors.Join(n, n)` take 4.25 s.
- prblm maintainer decisions relayed by the prblm session (2026-11-19):
  - v0.2.1 recovers the status-hint step and arms `Recover`'s fallback before its broken-connection check, in the core and in `adapters/ginprblm`.
  - v0.3.0 adopts the same walker rules as this decision: the 1,000-link budget counting repeats, typed-nil skip by `reflect` Kind `Pointer` and `IsNil`, recover-and-fail-closed only around the error's own methods, and one report per error.
- github.com/pkg/errors v0.9.1 `errors.go:275-288`, read by the prblm research session: `Cause` loops with no bound. This is established practice that leaves the guard to the caller.

**Primary documentation:**
- [Go `errors` package](https://pkg.go.dev/errors): how `Is` and `As` walk the tree, and when `As` panics.
- [Go spec, Method sets](https://go.dev/ref/spec#Method_sets): calling a value-receiver method through a nil pointer dereferences it.
- [Go `reflect` package](https://pkg.go.dev/reflect): `Kind`, `Pointer` and `IsNil`, the typed-nil test.

Otherwise reasoned from scrty's settled `http-error-propagation` and `diagnostic-redaction` specs and the repository's existing panic-reporting pattern (`diag.PanicAttrs`).
