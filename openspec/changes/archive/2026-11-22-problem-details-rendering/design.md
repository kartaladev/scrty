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

- **Versions** (revised 2026-11-20, when prblm v0.3.0 was tagged before task 10.11 ran).
  - `prblmsec` requires `github.com/kartaladev/prblm v0.3.0`.
  - The test module also requires `adapters/ginprblm v0.3.0` and `adapters/fiberprblm v0.3.0`. Both adapters require core v0.3.0 and use its bounded walk, so all three move together.
  - v0.3.0 changes no exported identifier. It walks each error chain once, in `errors.Is` order, within 1,000 entries, and answers a cyclic, too-deep or panicking error (in `Unwrap`, `Is` or `As`) with the safe 500 at once. prblm's own steps therefore no longer hang, overflow the stack or let a panic escape before scrty's mapper runs, which closes the limit this design documented under v0.2.0 and v0.2.1.
  - Behaviour that changes for a consumer: hooks receive a note wrapping `prblm.ErrUnwalkableError` instead of `*PanicError` reports; a `WithStatus` hint joined beside a sentinel is decided by `errors.Is` order; typed-nil pointers in the chain are skipped. Task 10.11 checks scrty against each.
  - v0.2.1, the version first planned, recovered three panics v0.2.0 let escape but kept prblm's unbounded walks.
- **Other dependencies** (user's request, 2026-11-20). Task 10.11 also takes the bumps the open Dependabot PRs propose, in every workspace module, so the branch lands on current dependencies. Each bump's release notes and OSV record are read first, and a breaking change or advisory goes to the maintainer before it is taken. Read on 2026-11-21 (16 PRs, ten distinct bumps): none breaks an API scrty uses. The maintainer confirmed v0.3.0 after its behaviour changes were put to them, and chose exactly the Dependabot versions over newer patch releases (fasthttp 1.79.0, klauspost/compress 1.20.5, gocron 2.23.2, unassessed), which arrive in a later round. Taken: fiber/v3 3.7.0, fasthttp 1.78.0, klauspost/compress 1.20.4, x/crypto 0.59.0 (fixes GO-2026-5932 in `openpgp`, which scrty does not import), x/sync 0.25.0, x/mod 0.43.0 (tools), goose/v3 3.30.1, pgx/v5 5.13.0 (its changelog names a `Rows.Values` panic fix, GHSA-w9rp-vfrh-q8vv, that OSV did not return on that date; it also stops putting `sslcert`/`sslkey` into `TLSConfig.Certificates`), gocron/v2 2.23.1.
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

**Decision.** A single walker in `internal/errwalk` flattens the chain once. The core lookup (`LookupStatus`, `StatusForError`), the prblmsec mapper and fibersec's refusal unwrapping all classify by scanning that one list, so they cannot disagree. So does every other place where scrty inspects the refused error on the refusal path:
- `refused()`'s outage check and the authorization check in httpsec;
- the session-signals retry and throttle checks;
- the security-event guard refusal;
- the DPoP guard challenger;
- the caller-hang-up check.

Each of these inspects the error before or beside the lookup, so an unbounded one would hang the request before the lookup could stop it (task 10.9).

The library also protects every error returned by a consumer-supplied port before it enters a flow (task 10.12). Examples are the session store, the rate limiter, the Basic authenticator, the API-key store, and the login, recovery, passkey and OIDC ports. A port is the consumer's code, but the library's guarantee is that classifying any error it is handed never hangs, crashes or panics. A store bug must not become a stuck request.
- **A boundary sanitizer, not per-check conversion.** Where a port's error enters the library, one helper walks it once with the bounded walker.
  - If the walk completes, the error passes through unchanged, and the existing checks downstream still read it with stdlib `errors.Is` and `errors.As`. That is safe, because the walk has just shown the chain is finite and within budget.
  - If the walk aborts (a cycle, a fan-out, or a panicking `Unwrap`), the error is replaced by a fixed library error that matches the port's own unavailable sentinel. The abort is reported once, and nothing hostile travels further.
  - This means one change per port call site instead of per check: the inventory counted about 180 checks behind those call sites.
- **Where it goes** (maintainer's choice, 2026-11-19). The sanitizer goes immediately after every port call whose error the library reads, including calls whose error is only logged. Log-only calls are included so that their aborts are recorded too: `diag.Failure` is walk-safe, but it writes no abort record. The only calls skipped are those whose error is only compared with nil and then dropped, since nothing reads it; the 10.12 inventory lists them. Placing it at the shared failure helpers (`storeFailed`, `keyStoreFailed`) was rejected: it would depend on nothing between the call and the helper ever inspecting the error, an invariant spread across files that any later edit could break. It would also leave log-only aborts unseen, and let errors that pass straight up reach other packages raw.
- **A port with no unavailable sentinel** (maintainer's choice, 2026-11-19). Examples are the session `Store`, `identity.UserLoader` on the session-reload path, and `apikey.Store` management. These sites pass the internal sentinel `porterr.ErrUnwalkable`. The fixed error then matches no library refusal, so the site's existing catch-all branch handles it, a dependency failure as for any other store error. No public sentinel is added.
  - Rejected: new public per-port sentinels. They grow the API for a case the catch-all already answers.
  - Rejected: borrowing the nearest existing sentinel. `authenticate.ErrUnavailable` answers 401 where the reload sites answer 500, so it would change their outcome.
  - The name follows prblm v0.3.0's `ErrUnwalkableError`, so the two libraries describe the case alike.
- **The consumer's own refusal and write errors are port errors too** (maintainer's choice, 2026-11-19). A consumer's magic-link or one-time-token refusal check and the password policy's write return errors the library promised to return unchanged.
  - The default: they are sanitized like every other port error. A walkable error still comes back unchanged, as the same value. Only an unwalkable one is replaced by the fixed error.
  - The specs say so: magic-link, one-time-tokens, password-policy and diagnostic-redaction carry the exception, and two new http-error-propagation requirements state the boundary rule.
  - There is no override. The consumer keeps full control of every error it can return, except one the library cannot inspect. That one could only hang or crash the library's own reads, so `library-design.md` 4 draws the line here.
  - Where the library tells the consumer's error apart from its own by identity, it must treat the fixed error as the consumer's. Example: redemption's `countsAgainstSource` in httpsec, found by the 10.12 group 5 review.
  - Rejected: exempting these errors and reading them with the bounded walker at every library check instead. Decision 11 already rejected per-check conversion as an invariant any later edit could break.
- **Where the sanitizer's record goes** follows decision 12: the component's own logger option, else the logger of the chain handling the request, else `slog.Default()` at record time. Task 10.14 converted every no-logger site that has a context in scope (10.12-wide review N1).
  - A site whose component holds a logger calls `porterr.SanitizeTo(ctx, logger, err, unavailable)`. Under decision 12 that logger is the consumer's option or the routing default, so the record lands where the consumer configured, with the request's context and its trace attributes.
  - A site whose component has no logger at all calls `porterr.SanitizeTo(ctx, nil, err, unavailable)` when a context is in scope. A nil logger resolves exactly as the routing default does. `porterr.Sanitize`, which has no context, is kept for a site with no context in scope; no production code calls it now.
    - Components built without a logger option fall here: the encrypting session store (`NewEncryptedStore`), the concurrent-sessions policy, `ProvisionerWrite` and `ConditionalProvisionerRehash`, the recovery authenticator-reset planner, recovery's MFA enrolments kind and the way-back check, the MFA enrolment reset (`ResetEnrolment`), the policy engine and `policy.UsableMFAMethods`.
    - Inside a chain their records reach the chain's logger; outside one, `slog.Default()`.
    - Superseded (maintainer's choice, 2026-11-20, decision 12): the first cut sent these to the default logger even inside a chain (accepted by the 10.12 group 1 review), and an intermediate cut limited the context lookup to the policy engine and `UsableMFAMethods`.
    - Rejected: new exported logger options on each of them. The routing default reaches the same logger without growing a tagged module's API.
  - The sanitizer's record is not sampled, as on the default-logger paths (failure row "A hostile error recurs on every request").
  - Found by the dispatch 1 review: the first cut always wrote to the default logger.
- **The outcome of an abort is the site's existing branch for a failing port, not a new 500.** That branch was already designed to conceal: a user-store outage reads exactly like a wrong password, and recovery start is uniform. So an abort is never a not-found, a throttle or an outage claim, and never an enumeration oracle.
- **Accepted:** an `Is` method that panics only for one particular sentinel passes the walk, which calls no `Is`, and panics later at a stdlib check. net/http recovers that panic per request, so it neither hangs nor crashes the process. A caller outside net/http, such as a job or a gRPC handler calling `apikey.Keys.Revoke` or `Verify` directly, receives the panic in its own goroutine, as from any call into the consumer's code, and recovers it or not by its own policy. It is recorded in the failure table.
- **Not ports:**
  - The library's own internals that read these errors on almost every path (`diag.Failure`, `diag.causeOf`, `depfault.Silent`, `depfault.record`) take the walk directly, because a hostile error could reach them before any sanitizer.
  - The SQL drivers' reads of `database/sql` and pgx errors are out of scope: the consumer supplies only the connection handle, not the errors.

**Performance.**
- The walk replaces many stdlib traversals with one flatten per classification.
- The walker flattens into a buffer the caller provides, a fixed array on the caller's stack. A chain that fits takes no heap allocation, and only a longer chain grows onto the heap. Task 10.13 found the first cut allocating on every call (`chain-50`: 8 B to 2,112 B), and this rule removes that.
- Task 10.13 benchmarks the lookup and the mapper against the pre-walk baseline on an idle machine.
- **Measured** (task 10.13a, 2026-11-19, `c1bf3e97` against `ca2d9887`, 10 alternating rounds, benchstat, Apple M4 Pro, go1.27; figures drift by machine):
  - `LookupStatus` time per call: −23% to −38% on every row. Allocations drop to 0 on bare-sentinel, wrap-5, join-3-challenge and unknown (from 1–2).
  - `MapError` time per call: −6% to −33% on every row.
  - `MapError` allocations: 0 on unknown, and fewer than the baseline on the recognised rows: 1, 1 and 4, from 2, 2 and 5. The remaining allocations build the returned `*prblm.Problem`, not the walk, which the unknown row shows takes none.
  - `chain-50` allocates as it grows past the stack buffer (lookup 1,664 B, mapper 3,440 B), which is accepted.

Its rules are pinned, and prblm adopts the same rules for its v0.3.0 hardening, so a consumer sees one rule across both libraries.
- **Order:** root first, then depth first, in the order `errors.Is` and `errors.As` visit. Each visited node's `Unwrap` is called once. A nil entry in an `Unwrap() []error` is skipped. A nil result from `Unwrap() error` ends that branch.
- **Matching:** a node matches a target as `errors.Is` or `errors.As` would: by `==` when the target's type is comparable, by a direct type match, or by the node's own `Is` or `As` method. "First match" means first in list order, so precedence is unchanged. For a pointer or interface target, a match whose value is nil is not a match: neither a nil node nor an `As` that reports true but sets nothing.
- **Typed nil:** a node whose dynamic value is a nil pointer (`reflect` Kind `Pointer` and `IsNil`) is skipped entirely, and none of its methods is called. Nil maps, slices, funcs and chans are not treated as nil. A typed-nil root yields an empty list. That is not an abort, so the lookup falls through to 500, unrecognised.
- **Budget:** every entry the walk examines counts 1. That includes the root, every real node, every repeat, every nil entry in an `Unwrap() []error`, and every typed nil. The count is taken before any method of the entry is called. Examining the 1,001st entry aborts the walk.
  - Entries waiting to be visited count too: when the list plus the entries still pending would pass 1,000, the walk aborts at once. They are certain to be examined, so the abort is certain anyway. This stops one node's huge `[]error` from allocating or looping before the budget trips.
  - Every entry counts so that one number bounds all the work: a node returning a million nils plus itself would otherwise cost about 0.5 s per walk.
- **Panic:** a panic in a node's `Unwrap`, `Is` or `As` call, or in the `==` comparison, made during the walk is recovered and aborts the walk. That includes `panic(nil)` under `GODEBUG=panicnil=1`: a call that did not return normally counts as a panic.
- **Abort result:** on either abort, `Flatten` returns no list, so a caller can never classify a partial chain.
- **Abort outcome:** both aborts (budget, panic) fail closed. The lookup answers 500, unrecognised (`ok == false`). The mapper, which starts from the lookup, then returns nil, as for any unrecognised error, and prblm answers with its own 500. The mapper never walks the chain again after the lookup aborted, so it adds no second record. Nothing guesses what an unreached or panicking link would have said.
- **Reporting:** one Error-level slog record per aborted classification, with a constant message, a `reason` attribute (`panic` or `budget`) and, for a panic, the redacted panic attributes: the panic's type and its frames.
- The frames are captured inside the walker's deferred `recover`, while the panicking stack still exists, and travel on the abort value. Formatting them after the recover would only show the logging site (task 10.10).
- The walker reports the abort to its caller and never logs by itself.
- A caller that holds the chain's logger logs there: the chain's error dispatch, and session signals. Session signals log an abort as `classification-aborted`, not as a dependency failure. The free functions `LookupStatus` and `StatusForError`, the prblmsec mapper and the gin and fiber adapters log to `slog.Default()`. The reasons are internal, not exported.

**Default and override.** The rules have no options. The bound and the fail-closed outcome are a guarantee, not a preference, and a consumer who could raise the budget could reopen the hang (`library-design.md` 4). The consumer controls where the record goes, through the chain's `WithLogger` or `slog.SetDefault`.

**What it changes against `main`:**
- A challenge more than 1,000 links deep is no longer found. That is an unrealistic chain.
- A typed nil whose methods are nil-safe and meaningful is ignored, where stdlib would honour it. The library builds no such error.
- A challenge offered through an `As` method behind a typed nil is now found, because the walk keeps going past the nil.
- A typed-nil `*password.RejectedError` no longer panics the lookup. It is skipped, and the rest of the chain decides.
- An `As` method that reports true but sets nothing is no longer a match. Before, `errors.As` took it and the challenge check fell to 500. Now the rest of the chain decides, which can give a refusal's status instead. The library defines no `As` method.

**The line scrty cannot cross.** The walker protects scrty's own classification only.
- Consumer code that calls stdlib `errors.Is` or `errors.As` on the same error still sees the typed nil, and still hangs or panics. The hardened lookup and stdlib-based code can therefore disagree about one error.
- prblm v0.2.1, the version required (decision 8), walks the error itself, before or outside the scrty mapper. Its Describer step hangs or dies on a cycle before the mapper runs, and gin's own `Context.Error` and fiberprblm's hint walk the chain too.
- v0.2.1 already recovers a panicking `As` method in prblm's status-hint step, so with scrty's mapper registered such an error answers a 500 problem instead of escaping. Cycles remain until prblm v0.3.0 adopts this walker's rules. The godoc and README state the limit.

**Alternatives.**
- A depth limit only: rejected, because it does not stop fan-out.
- Skipping a panicking link and continuing: rejected. The skipped link may be the one that decided precedence, a concealed lock for example, so the answer could reveal what concealment hides.
- A new exported `ClassifyError(err) (status, ok, fault)`: rejected for now. It adds public API, and every adapter would have to change to call it.

### 12. A record lands where the consumer configured

Maintainer's choice, 2026-11-20: every record of every component, in this change. Before, about 25 components filled `slog.Default()` into their logger at construction. A consumer who configured only the chain's `httpsec.WithLogger` therefore saw the chain's own records there, and every component's records (including the 10.12 port aborts) on the process default. The captured default was also stale: a consumer who called `slog.SetDefault` after wiring got records rewritten through the old default's bridge. Verified on Go 1.27.4: an Error record came out at INFO level, a Debug record was dropped, and the context was lost.

**Decision.** Each record resolves its destination when it is written, in this order:
1. the component's own logger option, when the consumer gave one;
2. else the logger of the chain handling the request, read from the record's context;
3. else `slog.Default()`, read at record time.

**Mechanism: a routing handler, not a nil field** (10.14 audit, 2026-11-20).
- `internal/ctxlog` gains a constructor for a logger whose `slog.Handler` routes. For each record, `Enabled` and `Handle` look up the chain's logger on the context and delegate to its handler, else to `slog.Default().Handler()` at that moment. `WithAttrs` and `WithGroup` are recorded and replayed onto the resolved handler.
- Every component's constructor fills this routing logger where it filled `slog.Default()`. Its logger option replaces it. The field is never nil.
- Call sites do not change: they keep calling `c.logger.LogAttrs(ctx, …)`. There is no per-site lookup to forget, and loggers a component hands to its children (passkey to `onetime`, `depfault`, the memory limiter) route too.
- `slog.Handler` receives the logging call's context so that handlers can read its values (`log/slog` documentation), so routing at the handler is idiomatic slog.
- The chain answers the internal context key (`ctxlog.Key`) from its per-request run value only when it was given `WithLogger`. Otherwise it delegates to the enclosing context, so an enclosing chain's logger is found and the innermost configured chain wins. It never answers a nil or a routing logger. The chain's own default is the routing logger too. A refusal the gin or fiber adapter reports before the route was reached (an interceptor refused) has no route context, so the adapter takes the context of the outermost run on that request's exchange, which is the chain it mounted; with no run it falls back to the request's context. Accepted: when chains are nested on one exchange, such a pre-route refusal is reported on the outermost chain's logger, not the innermost's. Both loggers serve the same request and consumer, so nothing crosses requests; following the innermost run would need the context restored as each nested run unwinds.
- `porterr.SanitizeTo` with a nil logger resolves as the routing logger does.
- A lint rule (`forbidigo`) bans `slog.Default()` outside `internal/ctxlog`, so no new capture can appear.
- Rejected:
  - A nil logger field with a resolve call at each of about 200 log sites. A forgotten site would use the wrong logger or panic (a nil `*slog.Logger` panics on `LogAttrs`, verified). Nothing would catch it, and it breaks the construction checks that refuse a nil field and the wiring that hands a logger on.
  - Passing the chain's logger at wiring time. Consumers build components before the chain, and one component can serve two chains.
  - Installing a handler through `slog.SetDefault`. That changes process-global state, which a library must not do.
  - An attribute-only contextual handler (trace ids). It does not move a record to another destination.

**A nil logger option is a configuration error** (maintainer's choice, 2026-11-20). Every component's logger option refuses nil with that component's `ErrConfig` from its constructor, naming the option. Before, about 13 options ignored nil and the rest refused it. A nil there is almost always an uninitialised variable, and leaving the option out already means "route". This is a compatibility change on options tagged in v0.1.0 and v0.1.1 (`library-design.md` 7), recorded in the CHANGELOG under Changed.

**Samplers.** A component keeps one sampler. Sampling exists to stop a flood, and a component's key space is what floods.
- Two chains sharing a component with different loggers share its windows. A record for chain B can be suppressed while chain A's is written (accepted, documented).
- The suppressed-count summary has no request context. It goes to the component's own option, else to the destination that the summarised key's own records went to, remembered per sampler key when a sampled record is written (`ctxlog.Summaries`), else the routing default. A key's count therefore only goes where that key's own records went: sampler keys can carry a user identifier, and a component shared by several chains must not write one chain's identifier into another chain's log (maintainer's choice, 2026-11-21, raised by a security review of the 10.14 lanes; it replaces "the logger last resolved").
- Nothing is keyed by `*slog.Logger`, so nothing grows with the loggers seen.

**Default and override.** The default routes as above. The consumer overrides per component with its logger option, per chain with `httpsec.WithLogger`, and for everything else with `slog.SetDefault`, which now takes effect even after wiring.

**What it changes against `main`:**
- Records of a component used inside a chain now go to the chain's logger when the component has no option, and are filtered by that logger's level. A chain logger at Warn drops a component's Info and Debug records that used to reach the default.
- `slog.SetDefault` after construction is honoured.
- A nil logger option fails construction in every component.
- The same component logs to the chain inside a chain and to the default outside one.

### 13. A generator that answers the nil identifier is a failing dependency

Maintainer's choice, 2026-11-20: every place scrty asks a consumer-replaceable `id.Generator` for a new identifier, in this change (raised by the 10.12 7j review). `id.Nil` means "no identifier", and no generator scrty ships returns it, but nothing stopped a consumer's generator from answering `(id.Nil, nil)`. The 2026-11-20 inventory found 62 production call sites. Two already refused the nil identifier: the session family (a configuration error) and TOTP's enrolment generation. Everywhere else the nil identifier was used as a real one. In the OpenID Provider every grant would join one family, so revoking one family could revoke other users' grants; in the store backends rows would be keyed on the nil identifier.

**Decision.**
- A new `internal/idgen` package has one function, `New(g id.Generator) (id.ID, error)`. It calls `NewID`, returns the generator's error unchanged, and returns the fixed sentinel `idgen.ErrNil` ("the identifier generator returned the nil identifier", no consumer data) when the answer is the nil identifier with no error.
- Each of the 60 remaining call sites calls it in place of `NewID`. The site's existing branch for a failing generator answers `ErrNil`, so the outcome is that site's dependency failure (the OpenID Provider's `server_error`, a store's failure error, a refused issuance). Nothing is stored under the nil identifier. The task 10.12 sanitizer stays where it is, right after the call.
- The two sites that already refuse keep their behaviour: the session family stays a configuration error (the settled sessions behaviour), and TOTP keeps its own refusal.
- The store backends (`sqlstore`, `pgxstore`, `gormstore`) use it too, so a row is never inserted under the nil identifier.
- `idgen.New` writes no record of its own. The site's failure branch reports it as it reports any generator failure.
- A nil generator, untyped or typed, is answered with the fixed sentinel `idgen.ErrNoGenerator`, never a panic (10.15a review). Constructors already refuse a nil generator, so only a library bug reaches it. A panic inside the consumer's `NewID` is not recovered by `New`; see the failure row.
- `passkey`'s generator option already refuses a nil or typed-nil generator with `passkey`'s configuration error, as every other component's option does (`library-design.md` 6). The 2026-11-20 inventory said otherwise; the 10.15 lane e dispatch found the refusal on `main` and pinned it with a typed-nil row. No option changes, so there is no CHANGELOG entry under Changed.

**Default and override.** No option. The generator stays replaceable as before; the contract that it never answers the nil identifier is now enforced instead of assumed.

**Rejected.**
- Accepting and documenting it: a shared grant family breaks isolation between users, and the consumer cannot see it happen.
- A nil check written out at each site: 60 copies, any of which can be forgotten. One helper keeps the rule in one place.
- Retrying on the nil identifier: it hides a broken generator, and it needs a bound and a policy the consumer did not ask for.

### 14. A consumer panic on a goroutine the library started is recovered

Maintainer's choice, 2026-11-20: fix it in this change, after a sweep. Decision 11 accepts a consumer port that panics because net/http recovers the panic per request. That holds only on the request's own goroutine. The 10.12 P5 dispatch reproduced the exception: a consumer WebAuthn metadata fetch that panics runs inside singleflight's `DoChan`, which re-raises the panic on a goroutine of its own, so no request recovery sees it and the process exits. The sweep of the same day listed every goroutine the library starts that calls consumer code. Seven already recover (the queued notifier, back-channel delivery and its report lanes, the signal bus, the signal stream's reads, sign-in notices, the client-keys fetch). These do not:
- the WebAuthn metadata refresh (`DoChan`, the consumer fetch);
- the OIDC relying party's remote fetch (`DoChan`, through the consumer's HTTP client);
- the signing-key manager's rotation loops (the key store, the error hook, the clock);
- the memory session store's housekeeping (the clock);
- the expiry sweeper's scheduled jobs, around the task itself, which the runner already recovers (the locker, the observer, the clock).

**Decision.**
- A new `internal/recovered` package has `Call(ctx context.Context, log *slog.Logger, what string, f func() error) (err error)`. It runs `f`, recovers a panic, including `panic(nil)` (detected by whether `f` returned), writes one Error record with `diag.PanicAttrs` and the constant message naming `what`, and returns the fixed sentinel `recovered.ErrPanicked`. It never re-panics.
- Each listed site wraps its consumer call in it, on the library's goroutine, and answers the site's existing outage: the metadata refresh answers `errMetadataUnavailable` (the registration is refused, as on a fetch outage); the remote fetch answers its fetch failure; a rotation loop iteration reports a failed run through the error hook's path and the loop goes on; housekeeping skips the cycle and goes on; a sweeper job reports a failed run and the scheduler goes on.
- The panic is recovered where the consumer code is called, not around the goroutine as a whole, so a loop survives and keeps its state.
- The fasthttp connection watcher in `fibersec` is left as it is: the connection is fasthttp's, not a port the consumer configures (accepted row).
- At the WebAuthn metadata refresh the recovery covers the whole refresh run on the flight goroutine: the consumer's fetch, the library's decode of the fetched blob and the cache build (maintainer's choice, 2026-11-21, raised by the 10.16 lane b review). The blob is network-supplied bytes, so a panic in third-party parsing on that goroutine would otherwise exit the process. The answer is the same `errMetadataUnavailable`.
- The OIDC relying party's discovery and key-set refreshes follow the same rule, since their flights also call the consumer's clock and HTTP client and parse network-supplied bytes (10.16 lane c review, which reproduced a crash from a panicking clock). A panic there is answered as that fetch failing: every waiter gets `ErrDiscoveryFailed` and the backoff window opens, as for a transport error. It writes two records: the recovery's Error record, and the existing Warn for a failed fetch, whose text carries only `ErrPanicked`'s fixed message.

**Default and override.** No option. The guarantee is that consumer code run on a library goroutine never takes the process down; the record goes where decision 12 routes it.

**Rejected.**
- Recovering around each goroutine's whole body: a rotation loop or a scheduler would end on the first panic and stop working silently.
- Replacing singleflight's `DoChan` with `Do`: `Do` re-panics in every waiting caller, and the waiting callers have different requests; the first panic still ends the shared flight for all of them.
- Leaving it documented: a crash from consumer code on a library goroutine is the outcome decision 11 promises cannot happen.

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
| A cyclic error chain, through `Unwrap() error` or `Unwrap() []error` | Handled, tested (decision 11) | The budget stops the walk at 1,001 visited links: no hang, no stack overflow. The result is 500, unrecognised, reported with reason `budget`. Under prblm v0.2.x, prblm's own walks hung or died on the same error before the scrty mapper ran; v0.3.0 bounds them too and answers the safe 500 (decision 8). Consumer code calling stdlib still hangs or dies on it. Documented as the line scrty cannot cross |
| One node's `Unwrap() []error` is huge: many copies of itself, or millions of nil entries | Handled, tested (decision 11, task 10.1 review) | Pending entries and nil entries count against the budget, so the walk aborts at once, without allocating in proportion or scanning the slice repeatedly. The result is 500, unrecognised, reported with reason `budget` |
| `panic(nil)` from a node's method, under `GODEBUG=panicnil=1` | Handled, tested (task 10.1 review) | A call that did not return normally counts as a panic. The walk aborts with reason `panic` and never passes the call as a silent success |
| A join that fans out (`errors.Join(n, n)` nested) with no cycle | Handled, tested (decision 11) | The budget counts repeats, so the walk stops after 1,000 visits instead of 2^depth. The result is 500, unrecognised, reported with reason `budget` |
| A consumer's random source, identifier generator or connection returns an error whose text names a user or a host | Handled, tested (whole-branch review 10.8, reproduced) | The returned error carries fixed library text (`diag.Wrap`), with the cause still reachable by `errors.Is`, as the diagnostic-redaction requirement says; before, `fmt.Errorf("…: %w")` copied the consumer's text into it in TOTP enrolment, the MFA emailed-code draw, one-time token issue, the session manager's identifiers and CSRF token, and the SMTP sender's connection deadline (`*_DependencyErrorTextIsFixed`, `TestSMTPSender_SendKeepsConnectionDeadlineTextOutOfError`). A generator failure still does not match `idgen.ErrNil`; only the nil identifier does |
| A consumer's default SMTP sender (`WithSMTPFrom`) contains a carriage return or line feed (CodeQL `go/email-injection` triage, reproduced) | Handled, tested | `NewSMTPSender` refuses it, wrapping `ErrUnsafeHeaderValue` and never quoting the value; before, `Send` checked only the message's own To, From and Subject, and wrote the default into the `From` header unchecked (`TestNewSMTPSender` default-sender rows). The other CodeQL alerts on this branch were already open on `main` and are false positives or intended (dismissed with reasons): SHA-256 over lookup keys tagged as passwords by name, logged client addresses and opt-in usernames, the request-path header check, a test helper's advisory-lock key, and an unreachable allocation size |
| A consumer's family-identifier generator returns an unwalkable error during `session.Sessions.Prepare`, called from httpsec's sign-in completion or the recovery flow, which hold a request context (lint triage, unreproduced) | Accepted (decision 12) | `Prepare` takes no context because it touches no store, so its one abort record is written on a background context: it goes to the session manager's own logger, else `slog.Default()`, not to the chain's logger. `Create` and `CreateIssuing` pass their request context and route to the chain. Routing it would need a context-taking `Prepare`, a new exported API, so the signature is kept; the call sites carry a `contextcheck` exception saying so |
| An error's own `Unwrap`, `Is` or `As` method panics during the walk | Handled, tested (decision 11) | Recovered. The classification aborts and fails closed with 500, unrecognised, and is reported with reason `panic` and the redacted panic attributes. It never guesses what the panicking link would have said. Under prblm v0.2.0 a panicking `As` method still escaped `Respond` from prblm's own status-hint step; v0.2.1 recovered it, and v0.3.0 answers it with the safe 500 before any step runs (decision 8) |
| An aborted classification nobody can see | Handled, tested (decision 11) | One Error-level slog record per abort, to the chain's logger where the caller holds it, else `slog.Default()`. The record carries a constant message and the reason, and never the error text |
| A consumer's own middleware, outside the fiber adapter, wraps a refusal whose classification already aborted | Accepted, documented (task 10.5 review) | The adapter classifies the wrapped error again, as it did on `main`, so the request writes a second record. The rule is one record per aborted classification, so this over-reports and never goes silent. Avoiding it would mean hiding the refusal's inner error from the consumer's own `errors.Is`, or exporting a way to see an abort, and neither is worth it for an error a consumer wrapped twice |
| A consumer's `WithErrorHandler` replaces the chain's dispatch, and an inspection inside the library aborts (the refusal event, the basic challenge header, OIDC consent, session signals) | Handled, tested (task 10.3 review) | The chain's dispatch classifies nothing under a consumer handler, so the quiet sites report instead.
- **Which chain:** the chain that answers the error, the one at the bottom of the exchange's run stack, whose middleware created the exchange. With one chain assembled inside another, that is the outer chain, not the inner one that raised the refusal.
- **Records:** each site logs through that chain's logger and sampler under the same per-reason key, so several sites on one request collapse to one record in the window.
- **Over-reporting, never silence:** a second record is accepted in three cases:
  - the consumer's handler also calls the free functions, which write to the default logger;
  - the consumer turns sampling off with `WithRefusalLogInterval(<=0)`, so each quiet site writes its own record;
  - a chain mounted in fiber or gin also carries `WithErrorHandler`, which applies to net/http only, so the adapter's classification and the quiet site both report. |
| Two abort reasons in one sampling window | Handled, tested (task 10.3 review) | The sampling key is per reason (`classification-aborted:budget`, `classification-aborted:panic`), so a budget abort never hides a later panic abort |
| A hostile error recurs on every request through a path that logs to the default logger (guards, a consumer's `WithErrorHandler` calling the free functions, the gin and fiber adapters, the mapper) | Accepted, documented | The chain's own dispatch is sampled through the chain's sampler. These paths have no sampler, and adding one would mean process-global state. They write one record per aborted classification, and the consumer limits the rate in its own slog handler. The godoc says so |
| A consumer port (store, limiter, authenticator) returns a cyclic, fanned-out or `Unwrap`-panicking error | Handled, tested (task 10.12) | The boundary sanitizer replaces it with a fixed library error matching the port's unavailable sentinel, and reports one record. The flow then takes its existing branch for a failing port, so the abort conceals exactly as an outage does. It is never a not-found, a throttle claim or an enumeration oracle.
- **Lockout effect (10.12 group 2.1 review).** Suppose a consumer's authenticator answers a real wrong password with a hostile chain. Then, as for an outage, nothing is recorded against the username, so per-account lockout does not advance for those attempts. The source throttle is still charged, and an Error-level abort record is written. This is fail-closed: the attempt is refused. Only the consumer's own authenticator can produce such a chain, never the client |
| A consumer limiter factory (`NewLimiter`) returns an error with a hostile `Error` method at construction | Accepted (10.12 inventory) | The constructor formats the factory's error text into its configuration error. A hanging or panicking `Error` method therefore fails at startup, which is the consumer's own wiring code, before any traffic. No request path is exposed |
| A consumer port returns an error whose `Is` panics only for one particular sentinel | Accepted, documented (task 10.12) | It passes the sanitizer's walk, which calls no `Is`, and panics at a later stdlib check. net/http's per-request recovery catches it: the request fails, and the process neither hangs nor crashes. Outside net/http (a job, a CLI, a gRPC handler calling a component such as `apikey.Keys` directly), the panic reaches the caller's goroutine unrecovered by the library, and the caller's own recovery policy decides (10.12 group 3.2a review). Where the goroutine is the library's own, there is no caller to decide: the expiry runner and sweeper run tasks and the lock listener on scheduler goroutines with no recover, so a stdlib read there would crash the process, against the expiry-sweeping requirement that the process SHALL NOT crash. Those reads therefore use the bounded walk, which recovers the panic and answers a plain failure, or a cancellation skip for a context error (10.12 E1 review, reproduced). One accepted gap remains: an error that truly matches `ErrTaskPanicked` and panics only on `context.Canceled` gets the right reason but no abort record, since the walk stops at the first match. Converting every check behind every port (about 180) was weighed and declined in favour of the sanitizer.
| A consumer store's load returns no record and no error, breaking its port contract | Handled, tested (task 10.12, OIDC provider) | Answered as that store failing outright: a dependency failure (server_error) through an unexported fixed sentinel, never a not-found reading such as `invalid_grant` or a revocation's 200. Refusing instead would let a replay go unrevoked or report a revocation that did nothing. Applies to every single-record load the 10.12 OIDC provider dispatches touch (7c review), the remembered-consent load included (7h review; before, it read as nothing remembered and re-prompted consent), and `identity.UserLoader` (maintainer's choice, 2026-11-20): its contract makes a miss `ErrUserNotFound`, so a load with no user and no error is a broken contract, not a missing user. Refresh answers server_error and revokes nothing, the browser session answers server_error instead of the login page, and the code exchange and UserInfo answer a dependency failure instead of `invalid_grant` or `invalid_token`. This departs from the established design, which read such an answer as a missing user and so revoked the grant on refresh: a revocation on a contract-breaking answer cannot be undone, while a server_error can be retried. Rejected: keeping the established reading (7d review). |
| A hostile error from the DPoP nonce cipher's `Open` (task 10.12 H3b review) | Handled, tested; accepted departure from "Where it goes" | The site is not sanitized: it already reads the error only through bounded walks (`hangup.ByCallerWalk`, `walkRefusal`) and answers an abort as the cipher failing (500 behind `session.ErrCipherUnavailable`), never as a refused nonce, which would start a retry loop. Sanitizing with `ErrUnwalkable` would turn it into exactly that refused nonce. Its one record goes through the chain's sampler under the per-reason key, as for every quiet site, so a second abort in one window is counted in the suppressed summary rather than written (reproduced in review); `WithRefusalLogInterval(<=0)` writes each one. One reporting place covers both the walk's abort and an `Is` that panics only for the sentinel |
| A consumer error whose `Error()` method panics or is slow (10.12-wide review) | Accepted (decision 11) | The sanitizer's walk and the library's own logging (`diag`) never call `Error()`; they report the error's Go type. A consumer who formats the error, or a stdlib `fmt.Errorf("%w")` the library still uses on a walkable error, calls it: on a request goroutine a panic is recovered per request by net/http, and a slow one is the consumer's own code's cost. On a library goroutine, decision 14's `recovered.Call` covers any such read |
| A user loader answers neither a user nor an error (10.12-wide review) | Accepted, inconsistent across components; follow-up change | Three readings exist. The OpenID Provider treats it as a dependency failure (this change, maintainer's choice). Passkey reads it as the user not found (maintainer's choice). Account recovery reads it as a user with nothing to recover (settled `account-recovery` spec). Aligning them changes settled behaviour, so it is left to a follow-up change rather than done here |
| A delegate of the authenticator chain (`authenticate.FirstOf`) returns an unwalkable error that claims a skip (`ErrUnsupportedCredentials`, `ErrNoEligibleAuthenticator`) (10.12-wide review, W-A) | Handled, tested (`TestPortErrors_FirstOf`, reproduced) | Before, the chain read the claim as a skip and authenticated through the next delegate (fail open). Each delegate's error is now sanitized before the skip check, so a cycle, fan-out or panicking `Unwrap` ends the walk as that delegate failing: not authenticated, no later delegate called, one abort record. A nested chain passes the fixed fault up without a second record. `FirstOf` holds no logger, so the record goes to the chain's logger, else `slog.Default()` at record time (decision 12). A legitimate skip chain deeper than the walk's 1,000-entry budget would also become an outage. That is accepted, and it fails closed. The password encoder sites follow the same rule: the construction probe's error stays `ErrConfig` with its record on the authenticator's logger, the upgrade's encode is answered as a failed upgrade, and the policy's encode is never read as too long |
| A consumer-written `httpsec.Request` integration, or a consumer middleware's `http.ResponseWriter`, returns an unwalkable error from `Body` or `FlushError` (closing 10.12-wide review, reproduced: a cycle hung the request and a panicking `Unwrap` panicked out of the chain) | Handled, tested (maintainer's choice, 2026-11-21) | The request integration is a port, not transport: scrty ships three implementations and documents it as replaceable, unlike a SQL driver. Each read is sanitized where it enters, so a hostile error is answered as that read failing, with one abort record; a cycle that claims `ErrRequestTooLarge` is never answered as too large. A genuine too-large body is unchanged. On the signals stream, the context the stream body runs on, which hides the request's values on purpose, now answers the chain's logger too, so the stream's abort record reaches it: that logger is configuration, not request data, and the session, identifiers, caller and tenant stay hidden. A consumer writer's `Write` error is not sanitized (accepted): the library compares it only with nil and walks it nowhere, and only the consumer's own stream body sees it |
| A request context's cancellation cause, set by a consumer middleware with `context.WithCancelCause`, is unwalkable (10.12 closing re-check, reproduced: a cyclic cause hung every hang-up check) | Handled, tested (maintainer's choice, 2026-11-21) | The cause is consumer input: the library reads it only through its bounded walk, never stdlib `errors.Is`. A hostile cause is answered as an unrelated one and is never joined into an error the library returns; a genuine bound or context error is read as before. Each hang-up check that reads the cause writes its own abort record, so a request with several checks writes several (over-reporting, never silence, as for the quiet sites; recording once per request would need state on the context) |
| A consumer `http.Client` given to the outbound client returns an unwalkable error from its transport, or from reading a body (10.12 closing re-check) | Handled, tested (maintainer's choice, 2026-11-21) | The consumer's HTTP client is a port, not transport like a SQL driver, consistent with recovering its panics (decision 14): its errors are sanitized where they enter, so the OIDC fetch flights cannot hang on one. A genuine transport error maps as before. The abort record goes to the calling component's logger, which each library caller attaches to the request context (`ctxlog.With`), else the context's logger, else `slog.Default()`; a consumer calling the outbound client directly gets the context's or the default. Only the back-channel logout delivery hands the fixed fault on alone as the failure's cause; the other callers keep it wrapped under the outbound client's text (accepted: neither carries consumer text) |
| A consumer identifier generator or random source handed to the one-time token layer returns an unwalkable error (10.12 closing re-check, reproduced: passkey registration hung) | Handled, tested | Sanitized inside the mint, where it enters, so the callers' check for the issue limit cannot hang on it; the other consumer random sources (pending authorization, passkey registration, the OIDC flow, the session manager's identifiers and CSRF tokens, the API key issue) and the session manager's family generator are sanitized the same way, as magic links and the OIDC handoff already were (10.12 final re-check, reproduced: session rotation's refusal check hung on a session random source's cycle) |
| A consumer's claim source answers neither claims nor an error | Accepted (task 10.12, 7f review) | Not a load of a record: no claims is a valid answer, so UserInfo answers `sub` alone, as before. Only a store or user loader answering nothing breaks a contract. |
| A consumer port returns an unwalkable error while the caller has already hung up | Accepted, tested (task 10.12) | The fixed error matches only the port's unavailable sentinel, so the site answers a dependency failure, not "the caller left", and writes an Error-level abort record. It fails closed and matches what a plain outage on a live request returns; only the log level differs from a plain hang-up (10.12 group 7a review).
- **The hang-up check:** one place answers differently. If the `Is` panics only when asked about the context's own error, the bounded hang-up check (`hangup.ByCaller`) aborts and treats the error as not a hang-up, instead of panicking. The caller then reads the error as "not a hang-up". Where the check guards an outage branch, that branch writes an Error-level failure record or answers a dependency failure. Where it sits inside a predicate such as `X && hangup.ByCaller(...)` (the login and recovery password loads), the attempt counts as a failed credential: the throttle is charged and a failed-authentication event is emitted. Either way the abort fails closed, but it is not reported as `classification-aborted` |
| A quiet site's own walk aborts on a sentinel-specific panic that the lookup never meets (task 10.9 review) | Handled, tested (task 10.9b) | A quiet site reports whenever its own walk aborted and the request's lookup did not, so nothing aborts unseen. That rule is the one `emitRefusal` already follows |
| Nested chains with sampling off, where the refusal event aborts in both runs (task 10.9 review) | Handled, tested (task 10.9b) | The abort marks the refusal as reported on the exchange, so the outer run does not report it again |
| A consumer error wrapping `ErrDPoPNonceRequired` on a chain without DPoP nonces (task 10.9 review; on `main` too) | Handled, tested (task 10.9b) | It used to dereference a nil nonce source and panic out of the request. `ErrDPoPNonceRequired` wraps `ErrInvalidDPoPProof`, so without server nonces it is now answered as that invalid proof: 401, `DPoP error="invalid_dpop_proof"`, and no `DPoP-Nonce` header. The fix is in the core interceptor that the gin and fiber mounts run, so it covers them too |
| Two different quiet sites abort on one request while the lookup does not, with sampling off | Accepted, documented (task 10.9b) | Each site writes its own record, so there are two. That is over-reporting, the same class as the sampling-off row, and never silence |
| An error whose `Is` answers differently from one call to the next | Accepted, documented | A quiet site's lookup and the dispatch's lookup can disagree on whether classification aborted. The result is one extra record or one missing, never a hang or a panic. Such an error breaks the `errors.Is` contract, and nothing can classify it reliably |
| The walker allocating on every classification (task 10.13 benchmark: `chain-50` 8 B to 2,112 B) | Handled, tested (task 10.13a) | It flattens into a caller-provided stack buffer, so chains that fit take no heap allocation. Benchmarks against the pre-walk baseline on an idle machine pin it |
| A guard refusal behind `WithGuardErrorHandler`, whose security event or DPoP challenge aborts | Handled, tested (task 10.9a) | A guard's security event and DPoP challenge return their abort to the guard, which applies the reporting rule itself. This holds for the net/http, gin and fiber guards.
- **With `WithGuardErrorHandler` set**, the guard's own classification is replaced, so the guard logs the abort once to the default logger. Guards hold no chain logger.
- **Without it**, the guard logs only when its own lookup will not abort.

No process-wide reporter is installed. A process-wide reporter could not see each guard's own handler setting, and it would be the global state this design avoids. Nothing aborts unseen |
| A selective `Is` method that panics only for one sentinel, reached after the lookup succeeded (DPoP answer check, response-refused event switch) | Handled, tested (task 10.9 follow-up) | Uses the walk. The abort drops the extra challenge or event and is reported once. This covers the response-refused switch on the spend path only. On the MFA `Verify` path, `Verify`'s error is read with stdlib `errors.Is` (`mfa.ErrVerifyThrottled`) before the switch runs. That read is at a consumer port, so it falls under the accepted port row and the task 10.12 sanitizer (10.9a review) |
| Another inspection of the refused error runs before or beside the lookup, on the refusal path | Handled, tested (task 10.9) | It uses the same walk. A cyclic or panicking error can no longer hang or crash the request before the lookup's bound applies |
| A consumer wants a larger budget or a different typed-nil rule | Accepted, documented (decision 11) | No option. A configurable bound could reopen the hang, so the rules are fixed (`library-design.md` 4). The consumer controls only where the record goes |
| A component without a logger option writes a record while handling a request in a chain that has `WithLogger` | Handled, tested (decision 12) | The routing logger resolves the chain's logger from the record's context, so the record is written there and not to `slog.Default()` |
| A component's own logger option and a chain logger are both present | Handled, tested (decision 12) | The option wins |
| A component writes a record outside any chain, or on a context rebuilt from `context.Background()` | Handled, tested (decision 12) | `slog.Default()` at record time. A context detached with `context.WithoutCancel` keeps its values, so it still reaches the chain's logger |
| The consumer calls `slog.SetDefault` after building components | Handled, tested (decision 12) | Honoured: the default is read at record time, never captured. Before, the captured default rewrote records through the old bridge (level lost, Debug dropped, context lost; verified on Go 1.27.4) |
| Nested chains, the inner one without `WithLogger` | Handled, tested (decision 12; 10.12 A1 review N1) | The inner run delegates the key to the enclosing context, so the outer chain's logger is used. With both configured, the inner one wins |
| The routing logger is found on the context (a chain configured with it, or a value placed by mistake) | Handled, tested (decision 12) | The handler never delegates to a routing handler; it falls to `slog.Default()`. No self-loop |
| A typed-nil or wrong-type value under the internal key | Handled, tested (decision 12) | Treated as absent |
| A nil logger passed to any component's logger option | Handled, tested (decision 12, maintainer's choice) | The constructor returns that component's `ErrConfig`, naming the option |
| A chain logger at a higher level than the default | Accepted, documented (decision 12) | `Enabled` follows the resolved handler, so a component's lower-level records are dropped as the consumer's chain logger dictates. The godoc and the spec say so |
| A component shared by two chains with different loggers, under sampling | Accepted, documented (decision 12) | One sampler window per key across both. The first record of chain B in a window can be suppressed while chain A's was written |
| A sampler's suppressed-count summary, which has no request context | Handled, tested (decision 12) | It goes to the component's own logger option, else to the destination that key's own sampled records went to, else the routing default. A key whose identifier belongs to one chain is never summarised into another chain's log, even when one component serves several chains with different loggers; the per-key memory is bounded and dropped after each summary. Accepted: if a summary is reported between another chain's write of the same key and that write being noted, the summary goes to the chain that already received a record for the key, so no key reaches a new chain; only the suppressed count can include records from the other chain |
| A record written with `context.Background()` inside a request (construction-time warnings, the memory limiter's warnings, background key rotation and expiry runs, `LookupStatus`, fibersec's abort report) | Accepted, documented (decision 12) | No request context exists, so it goes to the component's option, else `slog.Default()`. Each call that has a request context in scope passes it; the 10.14 inventory lists those that cannot |
| A consumer `slog.Handler` panics in `Enabled` or `Handle` | Accepted on a request's goroutine (decision 12); handled on a library goroutine (decision 14) | The routing handler does not recover it, as `slog` itself does not. On a request's goroutine net/http recovers it per request, and the panic is the consumer's handler's, as it was before with a consumer logger. On a goroutine the library started there is no request recovery, so decision 14 applies: the library's loops and flights write their records through a recovering guard, and a handler panic loses that one record but neither crashes the process nor stops the loop (signing-key loops, memory session housekeeping, the expiry sweeper, the OIDC relying party's flights; 10.16 reviews, reproduced). The whole-branch review (10.8) found three more goroutines whose recover path logged through the consumer's handler, so a panicking handler re-panicked and ended the process: the queued notifier's workers, the sign-in notice goroutine and the OpenID Provider's client-key-set flight, whose consumer clock also ran under a mutex. Each now writes through a recovering guard, or runs its whole flight in `recovered.Call` with no consumer code under the lock (reproduced: `TestQueuedSender_SurvivesPanickingLogHandler`, `TestSignInNotice_SurvivesPanickingLogHandler`, `TestClientKeySets_ClockPanicOnFlight`). A record a request goroutine writes, such as the dropped-notice summary, keeps the raw logger, so it still routes by the request's context |
| A new `slog.Default()` capture added by a later edit | Handled (decision 12) | `forbidigo` rejects `slog.Default()` outside `internal/ctxlog` |
| A consumer's identifier generator answers the nil identifier with no error | Handled, tested (decision 13) | `idgen.New` returns `idgen.ErrNil`, and the site takes its branch for a failing generator: a dependency failure, nothing stored. The session family keeps its configuration error and TOTP its own refusal |
| A stored authorization code whose grant family is the nil identifier (10.15 lane b review) | Handled, tested (decision 13; maintainer's choice, 2026-11-21) | The code exchange answers a dependency failure and stores no grant, as for any store answer that breaks its contract. Only a contract-breaking code store, or a code issued before the nil-identifier refusal within the code's short lifetime, can return one. The replay of a spent code refuses it the same way, before any revocation, so a replay never revokes under the nil family, which would reach other users' grants issued before the refusal. An access or refresh token issued under the nil family before the refusal is accepted until it expires: its family comes from a signed claim or a digest-checked record, so a caller cannot forge one, and no new grant is stored under the nil family |
| The signing-key manager's consumer clock fails on a rotation loop: `After` panics or returns a nil channel, or `Now` panics while a failure is being sampled (10.16 lane d review) | Handled, tested (decision 14) | The run is reported failed and the loop waits one interval on the system timer before its next step, so it neither stops silently nor spins; a consumer driving the loop with a fake clock sees one real interval in that case. A `Now` that panics while a failure is sampled writes the failure unsampled, over-reporting rather than losing it. A consumer `slog.Handler` that panics while the loop logs is recovered too, since it is consumer code on a library goroutine |
| The expiry sweeper's consumer distributed locker or clock fails on a scheduler goroutine (10.16 lane f) | Handled, tested (decision 14) | gocron v2 recovers only a job function's panic, and only with its `AfterJobRunsWithPanic` listener; the sweeper's job is the expiry runner's `RunTask`, which already recovers the task. The locker and clock run on gocron's own goroutines with no recovery, so the sweeper guards them: a `Lock` that panics or answers neither a lock nor an error is a lock failure and the run is skipped; an `Unlock` panic is recorded; a clock or timer call that panics, or answers a nil timer or channel, falls back to the system clock for that call. Each panic writes one record without its value, and the scheduler goes on. A `Lock` that panics after it took the lock leaves that lock held, since the sweeper is handed nothing to release; it expires by the locker's own lease, as the `WithDistributedLocker` godoc states (accepted) |
| The memory session store's housekeeping writes a record (a recovered clock panic, a nil timer channel) (10.14 lane c) | Accepted (decision 12; maintainer's choice, 2026-11-21) | `session.MemoryStore` has no logger option. Its housekeeping runs off any request, so no chain's logger reaches it: its records go to `slog.Default()` as it is when written, and a consumer redirects them with `slog.SetDefault`. The memory store is a development and single-process default, and its records are rare |
| A hostile consumer error at passkey's second-factor `PresentedChallenge(response []byte)` (10.14 lane e1) | Accepted (decision 12; maintainer's choice, 2026-11-21) | The error is sanitized as everywhere, but the method, part of `mfa`'s consumer-implementable interface, has no context, so its abort record goes to the passkey manager's logger, else `slog.Default()`, never the chain's. Only the destination of a rare record differs, never the outcome; changing the interface would break consumers who implement it |
| Consumer code on a library goroutine calls `runtime.Goexit` (for example `t.FailNow` in a test fake) (10.16 lane b review) | Accepted (decision 14) | `recovered.Call` writes its one "panicked" record and the goroutine exits. Inside a singleflight flight no result is sent, so a waiter waits until its own context ends; the flight's key is deleted, so the next call starts a fresh flight. Reproduced at the WebAuthn metadata refresh; the OIDC relying party's flights behave the same. It is already so without the recovery, and Goexit is not a failure a production dependency produces |
| A consumer's identifier generator panics in `NewID` | Accepted (decision 13) | Not recovered, as before. net/http recovers it per request; elsewhere the caller's recovery policy decides. No library-owned goroutine calls a generator |
| `idgen.New` handed a nil generator, untyped or a typed nil pointer (10.15a review) | Handled, tested (decision 13) | `idgen.ErrNoGenerator`, with the nil identifier and no call to `NewID`, never a panic. Only a library bug reaches it, since every constructor refuses a nil generator |
| A consumer's identifier generator answers the same non-nil identifier twice | Accepted (decision 13) | Not checked: detecting it needs memory of every identifier issued. The store's own uniqueness answers it where the identifier is a key, as a store failure |
| Consumer code panics on a goroutine the library started (the metadata refresh, the remote fetch, signing-key rotation, session housekeeping, sweeper jobs) | Handled, tested (decision 14) | Recovered where the consumer code is called. One Error record with the panic's type and frames, never its value's text; the site answers its existing outage, and a loop or scheduler goes on. `panic(nil)` counts as a panic. Before, the process exited (reproduced for the metadata fetch) |
| A consumer panic on a request's own goroutine | Accepted (decisions 11 and 14) | Not recovered by the library. net/http recovers it per request; elsewhere the caller's recovery policy decides |
| A panicking `net.Conn` under fibersec's client watcher | Accepted (decision 14) | The connection is fasthttp's, not a consumer port. Left unrecovered |
| A nil generator, untyped or typed, given to `passkey`'s generator option | Handled, tested (decision 13; already so on `main`, pinned in 10.15) | `passkey`'s configuration error, naming the identifier generator, as every other component's generator option does |
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

Mostly additive. It ships in the next lockstep release with a `CHANGELOG.md` entry under Added: the new module, `LookupStatus` and `ChallengeError.TokenType`. Rollback means not registering the mapper. Removing the module before a tag costs nothing.

Decision 12 is not additive. The CHANGELOG lists under Changed:
- component records now go to the chain's logger inside a chain;
- `slog.SetDefault` after wiring is honoured;
- a nil logger option fails construction.

A consumer who wants the old destination passes `slog.Default()` explicitly to each component's logger option.

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

**Researched** (2026-11-19):
- [kartaladev/prblm release v0.2.1](https://github.com/kartaladev/prblm/releases/tag/v0.2.1): tags `v0.2.1` and `adapters/ginprblm/v0.2.1`, both on commit 5742e04. The prblm session confirmed that both resolve through the Go proxy. The release fixes three panics that escaped prblm's recovery: the status-hint step, net/http `Recover`'s broken-connection check, and gin Recovery's broken-connection check. It changes no API, and ginprblm v0.2.1 still requires core v0.2.0.

**Researched** (2026-11-20):
- [kartaladev/prblm release v0.3.0](https://github.com/kartaladev/prblm/releases/tag/v0.3.0), published 2026-11-20: core `v0.3.0` (commit 678dfc5), `adapters/ginprblm/v0.3.0` and `adapters/fiberprblm/v0.3.0` (commit a881cbb, both requiring core v0.3.0), `mappers/validatormap/v0.1.1`. The prblm session reported that all resolve through the Go proxy. Its "Upgrading from v0.2.1" section is the source of the behaviour changes listed in decision 8.
- The open Dependabot PRs of kartaladev/scrty (16 on 2026-11-20; the list drifts, and task 10.11 re-reads it).

**Researched** (2026-11-21), for the bumps task 10.11 takes:
- [OSV query API](https://api.osv.dev/v1/query): no advisory on any FROM or TO version except [GO-2026-5932](https://api.osv.dev/v1/vulns/GO-2026-5932) (x/crypto `openpgp`, fixed in 0.59.0, not imported by scrty).
- [Go module proxy](https://proxy.golang.org): the `go` directive of each TO version; none above 1.27.
- [gofiber/fiber v3.7.0](https://github.com/gofiber/fiber/releases/tag/v3.7.0): static middleware confines symlinks by default; other additions opt-in.
- [valyala/fasthttp v1.78.0](https://github.com/valyala/fasthttp/releases/tag/v1.78.0): no API break; client redirect, chunked-EOF and parsing behaviour changes.
- [klauspost/compress v1.20.4](https://github.com/klauspost/compress/releases/tag/v1.20.4): bug fixes, gzhttp among them.
- [golang.org/x/crypto](https://go.googlesource.com/crypto), [x/sync](https://go.googlesource.com/sync), [x/mod](https://go.googlesource.com/mod) commit logs between the tags: SSH-only, a `syncmap` rename, a dependency update.
- [pressly/goose v3.30.1](https://github.com/pressly/goose/releases/tag/v3.30.1) and v3.30.0: parser, ENVSUB and version-sort fixes.
- [jackc/pgx CHANGELOG, 5.13.0](https://github.com/jackc/pgx/blob/master/CHANGELOG.md): the `Rows.Values` panic fix and the TLS certificate change.
- [go-co-op/gocron v2.23.1](https://github.com/go-co-op/gocron/releases/tag/v2.23.1): DST and stop-time fixes.

### Decision 11: one bounded, recovering walk

**The consumer's own refusal and write errors as port errors** (2026-11-19): reasoned from scrty's own settled specs (magic-link, one-time-tokens, password-policy, diagnostic-redaction, `library-design.md` 4 and 5) and the established design. No external source bears on it.

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

### Decision 12: a record lands where the consumer configured

**Researched** (2026-11-20, by two 10.14 audit agents; claims they could not verify are left out):
- [Go `context` package](https://pkg.go.dev/context): values are for request-scoped data that transits APIs, not optional parameters; the `Value` contract (same result for the same key) that the chain's run value keeps.
- [golang/go #58243](https://github.com/golang/go/issues/58243): a Go maintainer's view that a logger in a context is acceptable, and the removal of `NewContext`, `FromContext` and `Ctx` from the slog proposal over the hidden-dependency objection. The reason this design keeps the context lookup internal and puts it in a handler, not in an exported accessor.
- [zerolog](https://pkg.go.dev/github.com/rs/zerolog) (`Ctx`), [logr](https://pkg.go.dev/github.com/go-logr/logr) (`NewContext`, `FromContext`, `FromContextAsSlogLogger`), [go-grpc-middleware v1 ctxzap](https://pkg.go.dev/github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap) and [v2 logging](https://pkg.go.dev/github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging): established practice is split between carrying a logger in a context and carrying only fields.
- Go 1.27.4 `log/slog` (`logger.go` `SetDefault` and `handlerWriter`, `handler.go` `defaultHandler`), read from the toolchain, and a scratch program: a captured default loses level, Debug records and context after `SetDefault`; a nil `*slog.Logger` panics on `LogAttrs`.

**Primary documentation:**
- [`log/slog` `Handler`](https://pkg.go.dev/log/slog#Handler): `Enabled` and `Handle` receive the call's context so a handler can use its values.
- [`testing/slogtest`](https://pkg.go.dev/testing/slogtest): the handler-contract test the routing handler is checked against.

The nil-option rule and the scope are the maintainer's choices, reasoned from `library-design.md` 6 and 7.

### Decision 13: a generator that answers the nil identifier

**Researched** (2026-11-20):
- The scrty inventory of `id.Generator.NewID` call sites (62 in production, 2 already refusing the nil identifier), and `pkg/id` godoc: `Nil` "means 'no identifier', and no generator scrty ships returns it"; the `Generator` godoc promises nothing about it.

Otherwise reasoned from scrty's own settled specs: the `sessions` requirement that family identifiers come from a replaceable generator, and the `security-state-stores` requirement that a family revocation naming the nil identifier is refused. The scope is the maintainer's choice.

### Decision 14: a consumer panic on a library goroutine

**Researched** (2026-11-20):
- golang.org/x/sync v0.24.0 `singleflight` (`singleflight.go`, read from the module cache by the P5 dispatch, which reproduced the crash): `DoChan` runs the function on a new goroutine and re-raises a panic there with `go panic(e)`, so no caller can recover it.
- The scrty sweep of library-started goroutines (22 sites, 3 singleflight uses), and the house patterns that already recover consumer code on such goroutines: `internal/eventsink.Deliver`, `internal/storekit.BestEffort`, the queued notifier's workers, back-channel delivery.

**Primary documentation:**
- [Go spec, Handling panics](https://go.dev/ref/spec#Handling_panics): `recover` stops a panic only in the deferred functions of the panicking goroutine.

The scope is the maintainer's choice.
