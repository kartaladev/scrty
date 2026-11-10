# Design

## Context

See `proposal.md` for why. The requirements are in `specs/http-security-chain/spec.md` and `specs/framework-adapters/spec.md`.

The current state that shapes the approach:

- **How the chain runs a request.**
  - `Chain.Assemble(terminal)` folds the sorted registrations around `terminal` on every call. All three adapters call it once per request, because the terminal holds the framework's own request: gin's `*gin.Context`, fiber's `fiber.Ctx`, or net/http's writer and request.
  - Before the first interceptor, the returned step does three things: it hands the exchange the chain's per-request phase, it puts event delivery on the context, and it resolves the client (`clientResolver.begin`), refusing a disallowed host with the security headers applied.
- **How each adapter reads the path.** `Request.Path()` is the decoded path and `Request.EscapedPath()` the path as sent. On fiber both come from fasthttp's `PathOriginal()`, which is never normalised. Fiber itself routes on a path it normalises: it removes dot segments, decodes unreserved escapes (all escapes under `UnescapePath`), and matches without regard to case or a trailing slash by default.
- **What reads the path.**
  - Authorization rules, header profiles (`PathPrefix`) and the recovery cool-down (`normalizeRoute`, which folds case and trailing slashes) read `Path()`.
  - CSRF exemptions and DPoP's `htu` read `EscapedPath()` and match it exactly.
  - Every built-in endpoint and gate exemption is an exact match.
- **How sessions are published.** `Exchange.PublishSession` is the only function that puts a session into the request context, and its only caller in the library is the resolution core (`resolve.go`), which runs at the bearer slot (500). The gates (recovery 598, enrolment 599, second factor 600, password change 650) each judge `ex.Session` as it stands when they run, and let a request with none through.
- **How events see nesting.** `events.go` already supports one chain's `Assemble` running inside another's on the same exchange (`refusalReported`).

## Goals / Non-Goals

**Goals:**
- Close the three reproduced defects with the safe outcome by default, and have each closed by a test that was red on `v0.1.0`.
- Make the wiring gaps loud: double mounting, single-value options given twice.
- Reduce the per-request cost of `Assemble` without adding API.
- Ship `v0.1.1` through an ordinary pull request, with the defects disclosed in its changelog.

**Non-Goals:**
- **Case-folding or trailing-slash folding of `Path()` on fiber.** That would silently change every exact-match endpoint and every consumer predicate written with capitals. It stays the consumer's to write rules knowing fiber's routing, now stated where rules are written (decision 7).
- **A construction-time role for consumer authenticators,** such as a `RegisterAuthenticator`. It would add API in a patch release, and decision 2 already fails closed at runtime. It is recorded as a candidate for a later minor.
- **Enforcing consumer challenge kinds at the authorization stage.** Only the consumer's own gate knows where it sits.
- **Checking routers other than ServeMux and gin behind the net/http adapter.** Decision 1 covers them anyway, because the refusal does not depend on the router.

## Decisions

### 1. Refuse dot segments at the chain's entry, in the core

The step `Assemble` returns refuses, after client resolution and before any interceptor, a request whose escaped path either:
- fails to decode once (`url.PathUnescape`), or
- holds, when it and its decoded form are each split on `/`, a segment equal to `.` or `..`.

The refusal is `ErrMalformedRequest` (400). It is written like a client-resolution refusal: the security headers and the features' refusal steps are applied, and the error goes to the adapter's error handling. `//` is not refused: no router reaches a different handler through it (both fiber and ServeMux keep or redirect it), and refusing it would turn away harmless clients.

- **Default and override:** on, with no opt-out.
  - RFC 3986 §5.2.4 has clients remove dot segments before sending, and browsers do, so a server only receives one from a client that chose to send it.
  - No route legitimately needs a segment that is exactly `.` or `..`.
  - An opt-out would hand back the bypass this closes, on a framework that resolves such paths before routing. `library-design.md` rule 2 asks for the reason when a default has no override, and this is it.
- **Why after client resolution:** the first version ran the check before it. The review then reproduced a defect: behind a TLS-terminating trusted proxy, the 400 was missing HSTS and the other headers sent only on secure responses. The header profile read the connection's own scheme, not the forwarded one. The spec requires the refusal to carry the security headers. RFC 6797 §7.1 has an HSTS host send the header on any response over secure transport, and every other refusal in the chain is written after resolution. Client resolution reads no path, so nothing it does depends on the path being canonical.
- **Alternatives:**
  - (b) Have the fiber adapter return fiber's routed path. It passed the reproductions, but it ties `Path()` to fiber internals and double-decodes `%252e` under `UnescapePath`. Folding case on top of it would break every exact match written with capitals.
  - (c) Refuse lenient fiber configurations. Dot segments are resolved by fiber in every configuration, so this fixes nothing that matters. It would also make fiber's defaults a configuration error.
  - Fixing it per adapter would leave a consumer's own adapter exposed. One check in the core covers every adapter, including ones we have not written.

| Failure | State | Outcome |
|---|---|---|
| `..`, `.` or their percent-encoded spellings in any segment | Handled, tested | 400, no interceptor runs |
| A segment holding `/` once decoded (`%2F`) that builds `..` | Handled, tested | 400 |
| An escape that does not decode | Handled, tested | 400 |
| A legitimate encoded `..` inside an identifier segment (`/files/%2e%2e`) | Accepted | 400: such an identifier cannot be addressed by path, and it moves into the query or body |
| Double encoding (`%252e%252e`) | Accepted | Not a dot segment after one decode. Fiber decodes at most once, so no router in scope resolves it to `..` |
| Fiber case or trailing-slash variants | Accepted (decision 7) | Rules match what the consumer wrote. Documented where rules are written |
| `..;` or `..\` (also `%5C`) segments | Accepted | Not refused. None of the routers in scope (ServeMux, gin, fiber) treats `;` or `\` as a separator, and the fiber reproduction confirms they never reach the guarded handler. A proxy in front that normalises them is outside the chain's view |
| Empty path, `OPTIONS *`, absolute-form targets (`http://h/a/../b`) | Handled, tested | The first two hold no dot segment and pass. An absolute-form target is split on `/` like any other, so its `..` is refused |
| Very long paths | Accepted | One linear scan with no allocation on a clean path. The server's request-line limit bounds it |
| Cost per request | Accepted | The check allocates nothing on a clean path, and one allocation for a path holding `%`. On fiber, `EscapedPath()` copies the path out of fasthttp's buffer on every request now, because the check reads it |
| An adapter whose `EscapedPath()` returns a normalised path | Documented | The check is blind to what it cannot see. `Request.EscapedPath`'s godoc requires the path exactly as sent, so a consumer writing an adapter knows the check depends on it |
| Header-profile matchers and refusal steps read the refused path | Accepted | They decide only which headers go on the empty 400 |
| The entry 400 behind a TLS-terminating trusted proxy | Handled, tested | It carries the headers sent only on secure responses, as any refusal does. A forged forwarded scheme from an untrusted peer does not turn them on |
| A request that client resolution refuses and that also holds a dot segment | Accepted | It gets the client-resolution refusal. Both are refusals, and nothing reaches an interceptor |
| The CSRF exemption matcher's own dot-segment branches are no longer reachable through the chain | Accepted | The entry refusal is the single guard. The matcher keeps its branches as defence in depth, and they are no longer pinned by a test, because no request that reaches them can carry a dot segment |
| How the refusal is observed | Accepted | Like the client-resolution refusal: no chain event (`ErrMalformedRequest` has none mapped). The 400 goes through the adapter's error handling, where the consumer can see and log it |
| Existing tests that sent dot-segment paths expecting a later refusal (unknown OIDC provider, CSRF, CSRF exemptions) | Handled | They now expect the earlier `ErrMalformedRequest`, which is the requirement. A fiber test of `Path()` decoding that used `corp%2F..` now uses an input with no dot segment |

### 2. A session cannot be published once the first gate has been entered

At construction, the chain finds the first registration in run order whose interceptor is one of the four gates. Its frame in the fold (decision 5) marks the exchange before calling the gate. When the gate returns, the frame puts back the value the mark had before. The mark therefore holds exactly while the gates, and everything they pass the request to, are running. The frame also records the mark on its run's marker in the request context (decision 4), so it can be seen from a different chain run inside it, whichever adapter mounts that chain.

`PublishSession`, the exported function, refuses a non-nil session in two cases:
- its own exchange is marked;
- an enclosing run of another chain, found through the run marker's parent links, is marked.

It returns an error wrapping `ErrConfig` (500) that names the late publication and the slots to use, and publishes nothing. The chain writes one sampled log record per chain for it.

The resolution core and any built-in that sets a session publish through an unexported path. That path does not check its own exchange's mark, because the core runs at `OrderBearerToken`, before its own gates. It does refuse, with the same error class, when an enclosing run of another chain is marked; that error says to mount the chain outside the other chain's gates. The audit for such built-ins is a gopls references query, not a grep.

The frame-scoped mark and the check of enclosing runs were added after review. Two defects were reproduced against the first version, which set the mark for the whole run and kept it on the exchange only:
- **A retried pass:** a consumer interceptor before the bearer slot that calls `next` twice had its authenticator refused on the second pass (`TestChain_RetriedPassPublishesBeforeGates`).
- **A chain mounted inside another chain's gates:** a gateless chain mounted with `Middleware` inside a gated chain built a fresh exchange with no mark. It published a session owing a second factor that no gate judged, and the handler served it with 200 (`TestChain_SecondChainCannotPublishPastFirstChainsGates`).

- **Why mark the gate's frame, not a slot number:** a threshold such as "slot above 650" misses a consumer at slot 601, between two gates, and a slot-mate registered after `EnableMFAEnrolment`. Both were reproduced.
- **Why at publication:** that is the only point a consumer has to put a session where the handler and the authorizer read it. A refusal there means nothing past the gates can claim a session at all.
- **Default and override:** on whenever a gate is enabled, with no opt-out. The fix for a refused chain is to register the authenticator at `OrderBearerToken`, no later, which the godoc of `PublishSession` and `RegisterInterceptor` and the error itself say. "No later" matters: the recovery cool-down sits just after `OrderBearerToken` and judges a request by the session it carries when it runs, so an authenticator between the cool-down and the first gate would publish a session the cool-down never saw. The whole-branch review reproduced this against an earlier wording that allowed anywhere before `OrderAccountRecovery`, and a test now pins both slots
- **Alternatives:**
  - A construction-time authenticator role (non-goal; later minor).
  - The authorization-stage backstop alone (decision 3). It leaves consumer interceptors between the gates and slot 900 seeing a confined session.
  - "Document the slot", which the reauthentication design already rejected for the same shape of problem.

| Failure | State | Outcome |
|---|---|---|
| Consumer authenticator after logout, between gates, or a later slot-mate of a gate | Handled, tested | 500, nothing published, handler not run |
| Consumer assigns `ex.Session` directly, an exported field | Accepted, with decision 3 as backstop | The session never reaches the request context. The authorization stage still refuses it if it owes a challenge |
| A different chain nested on the same exchange authenticates after the outer chain's gates | Handled, tested | Refused with 500, by a consumer or a built-in authenticator alike, because authenticating inside another chain's gates is the same bypass. The outer run's marker is the enclosing run the check finds |
| A gated chain nested on the same exchange before the outer chain's gates | Accepted, fails closed | The nested chain's gates set the mark, so the outer chain's own authenticator, still before its gates, is refused with 500. A contrived configuration |
| `PublishSession` on an exchange after its outermost run returned | Accepted | The mark was put back when the gate's frame returned, so the call is allowed. It reaches nothing: the handler has run and no chain reads the exchange again |
| A consumer interceptor before the bearer slot calls `next` twice (a retry) | Handled, tested | The mark is put back after each pass, so the authenticator publishes before the gates on both passes |
| A different chain run inside another chain's gates, through any adapter, publishes a session | Handled, tested | Refused with 500, whether a consumer or a built-in authenticator publishes, and the handler does not run. The error says to mount the chain outside the other chain's gates, or to authenticate in the outer chain |
| No gate enabled | Handled, tested | Nothing to bypass; publishing is allowed anywhere |
| A built-in that publishes at or after the gates | Handled | The resolution core (`resolve.go`, reached only at `OrderBearerToken`) uses the unexported path. gopls finds no other library caller of `PublishSession`; the other built-ins that set a session assign the field directly (`complete.go`, `mfa_verify.go`, `reauth_resolve.go`, `recovery.go`) |
| The mark left over from an earlier run of the same exchange | Handled, tested | The gate's frame puts the mark back on return, and a panic out of a gate takes the same deferred path. A second run of one exchange publishes at the bearer slot as normal |
| A chain mounted with `Middleware` or an adapter inside another chain's gates (a fresh exchange) | Handled, tested | The outer run's mark is read from the run marker on the context, so the inner chain's publication is refused as in the row above |
| A gateless chain not run inside a gated chain, sharing its session store | Accepted (Open Questions) | Nothing on that chain judges an owed challenge, as for any chain without the gate |
| The marker's parent links are walked on every publication | Accepted | A walk only as deep as the chains nested on one request, usually one. It reads an atomic flag per run and allocates nothing |
| A result published with no session after the gates | Accepted | Only a non-nil session is refused, as specified. A stateless caller is not what the gates judge, and setting one is the same as `WithCaller` on the context |
| `PublishSession(nil, nil)` as a sign-out leaving an earlier caller on the context | Out of scope, UNREPRODUCED | Existing behaviour, seen in the code during group 5 but not tested. It does not change with this decision |
| The refusal's log record | Handled, tested | One sampled error record per window per chain, with no session, family or user identifier |

### 3. The authorization stage refuses a session owing a built-in challenge

Before evaluating rules, the authorization stage checks `ex.Session` against the gates this chain registers, in their run order. When the session owes the challenge of a registered gate, the stage refuses with the error that gate returns, including the second-factor methods (`challengeMethods`). A challenge whose gate the chain does not register is not refused (see the failure table).

- **Why:** defence in depth for the direct field assignment that decision 2 accepts, and for a future slot change that moves a gate.
- **Exemptions:** before the stage is enabled, a test enumerates every gate exemption and asserts that none hands an owing session on past slot 899. Each exempted endpoint is answered by the chain itself. If one is found that hands it on, the stage reuses that gate's exemption predicate rather than refusing it; this is recorded as a finding first.
- **Default and override:** on, with no opt-out, for the same reason as decision 2.

| Failure | State | Outcome |
|---|---|---|
| A session owing a challenge reaches slot 900 | Handled, tested | The gate's own error and status |
| A gate exemption that reaches the handler | Tested (enumeration) | None found: 68 owing-session requests across every exempted endpoint are all answered before slot 900. The shared-predicate fallback is not needed |
| A session owing several challenges | Handled, tested | The challenge whose gate runs first wins: recovery, enrolment, second factor, then password change |
| The MFA method lookup fails | Handled, tested | The gate's own fixed-text error and status; the store's text stays out |
| A session owing a challenge whose gate this chain does not enable | Accepted (decided 2026-11-10 while the maintainer was away; flagged for review) | Not refused by the stage, matching what the chain does without the backstop. Existing tests pin that a chain without a gate lets such a session through (`TestEnrolmentGate/… without the gate`, `TestBearerMarksEnrolment`). Refusing every owed challenge would close one more case: a second, gateless chain sharing the session store serving a token whose login still owes MFA. It would also refuse challenges nothing on that chain can satisfy, and it would reverse those pinned tests. That case is UNREPRODUCED as a defect and stays as on `v0.1.0`. The spec requirement says so, with its own scenario |
| The stage catches an owing session, which always means a consumer bypassed the gates | Handled, tested | Besides the gate's own refusal, one sampled error record per chain names the bypass and the slots to use, with no session or user identifier |
| The second-factor method lookup fails at the stage | Handled, tested | Same 500 and wrapped error as the gate gives for the same failure. Existing tests already pin this, and the review confirmed it (`TestAuthorization_BackstopSurfacesMethodLookupFailure`, status case). The log record says that the method lookup failed, not only that the gates were bypassed, so an operator can tell an outage from a misordered chain. It carries no error text, which may hold identifiers. The returned error reaches the adapter's error handling. The first version logged only the wiring record, and the review reproduced that (same test, log case) |
| The stage looks up methods for an owed challenge other than the second factor | Accepted | `challengeMethods` answers nothing for those kinds without calling the store, which a test confirms. No observable effect |
| A session assigned after slot 900 (a consumer at `After(OrderAuthorizer)`, or a slot-mate of the stage registered after it) | Accepted, documented | Out of the stage's reach. Such an assignment changes only `ex.Session`, never the request context the handler reads, because a consumer cannot write the session context key. The stage's godoc says so |
| `ex.Session` and the request context's session diverge | Accepted | Only possible if a consumer reuses another context through `ex.SetContext`. The stage reads `ex.Session` |
| The four gate types listed in more than one place drift apart | Handled | One helper names the gates, and both the fold (decision 2's mark) and the stage use it |

### 4. A chain entered again on a request it ran on passes through

The step `Assemble` returns puts a marker on the exchange's context, holding the chain and the request's method and escaped path. When it is entered on a context that already carries its own marker for the same method and path, it calls the terminal directly: no interceptor, no client resolution, no events. A different chain, or the same chain for a different method or path, runs in full. That keeps an in-process forward to another route from skipping that route's rules.

- **Default and override:** on, with no override. Running one chain twice on one request has no meaning a consumer could want, and the second run re-verifies credentials and touches the counters again.
- **Alternatives:**
  - Refusing the second entry: it fails closed, but it breaks applications that mounted the chain twice harmlessly and are secure today.
  - Counting entries: more state, and no different outcome.

| Failure | State | Outcome |
|---|---|---|
| Same chain at application and group | Handled, tested on gin and fiber | Runs once |
| Two different chains nested | Accepted, documented | Both run, and each counts its own attempts |
| In-process forward to another path with the same context | Handled, tested | The chain runs for the new path |
| Context marker lost by an adapter | Handled, tested by the adapter scenarios | Would run twice, as today: no regression |
| Chain A, then chain B, then A again on one request | Handled, tested | Each marker links to its parent, so the third entry finds A's run and passes through |
| A request's context kept past its run (detached, or reused from a goroutine after the handler returned) and sent through the chain again | Handled, tested | A finished run's marker is flagged done (atomically, since another goroutine may read it), so the chain runs in full |
| An exchange run a second time | Handled, tested | Runs in full: a new run never links to a finished one |
| A consumer middleware between two mounts rewrites the path | Handled | The chain runs again for the new path, as for a forward |
| A consumer middleware between two mounts changes the Host, a header or the query, or a framework re-dispatches on the same path (gin `HandleContext`, fiber `RestartRouting`) | Accepted, documented, tested (reviewed with the maintainer 2026-11-10) | The second mount passes the request through, so it is judged as it reached the first mount. On `v0.1.0`, the second mount judged it again. `TestGin_DoubleMountSecondEntryAfterCredentialSwap` reproduces this. A swapped valid credential, a swapped invalid credential, a Host swap and a query swap are all served on the first judgement. A path rewrite runs the chain again. Only consumer code between the mounts can cause it; a client cannot alone. The alternatives were weighed: widening the marker with Host, query and the credential headers covers only those headers and reads as a broader promise than it is, and dropping the pass-through brings back the reproduced double run. The behaviour matches established practice: Spring's `OncePerRequestFilter` skips a second pass on a request attribute alone, without comparing headers, where this chain also runs again on a path change. The gin and fiber godoc tells consumers to put anything that changes what a rule reads before the first mount. A test pins the pass-through and the path-rewrite control |
| A goroutine started by the handler sends the same method and path through the same chain while the outer run is still live | Accepted | It passes through, as a nested entry would. An exchange and its request context belong to one goroutine (`Exchange` godoc), and that request has already been judged |
| Cost | Measured | One allocation per request (the marker is itself the context): `ChainRequest/0` and `/8` 21 → 22 allocs/op, +80 B/op |

### 5. Build the interceptor fold once

At construction the chain builds one step per registration. Step *i* calls interceptor *i* with step *i+1*, and the innermost step calls the terminal of the current run. `Assemble(terminal)` returns a step that records `terminal` on the exchange for this chain, on a small per-exchange stack kept in an inline array, runs the entry checks, and calls the prebuilt fold. It removes the entry on return. Same-chain nesting cannot happen once decision 4 is in place, so the innermost step finds its own run's terminal by looking up the topmost entry for this chain. The gate mark of decision 2 is set by step *firstGate*.

- **Default and override:** no behaviour change, and no new API.
- **Acceptance:** `BenchmarkAssembleOnly8` and a full request through eight interceptors. On `v0.1.0` they measured 10 allocs/op, and 31 against 23 with no interceptors. Measured before and after with `benchstat`, the allocations attributable to the fold must drop to at most two per request, and the conformance suite must stay green on all three adapters.
- **Alternatives:**
  - A new `Chain.Run(ex, terminal)`: it adds API in a patch release.
  - Keeping the per-request fold: it is the documented trade-off today, and the user asked for the improvement.

| Failure | State | Outcome |
|---|---|---|
| An interceptor calls `next` with an exchange it built itself | Handled, tested | The innermost step finds no terminal for the chain, and returns an `ErrConfig` error (500), not a panic |
| A nested different chain overwrites the terminal | Handled, tested | Entries are keyed by chain, so each innermost step finds its own |
| An interceptor calls `next` twice | Handled, tested | The terminal runs twice, as today. The gate mark is put back after each pass (decision 2), so an authenticator before the gates publishes on both passes |
| An interceptor keeps `next` and calls it after its run returned (for example from a goroutine) | Handled, tested | The run's entry is gone, so the innermost step returns an `ErrConfig` error instead of reaching a finished terminal |
| An interceptor panics | Handled, tested | The entry is removed on the way out (`defer`), so a recovered panic leaves no stale terminal behind |
| More chains nested on one exchange than the inline array holds | Handled, tested | Entries spill to a slice on the exchange |
| The same chain entered again on one exchange, before decision 4 | Handled, tested | The innermost step marks its entry as running, so the inner run finds the outer terminal instead of recursing |
| The terminal calls `next` of its own, still-running run | Changed, accepted, tested | It gets an `ErrConfig` error. On `v0.1.0`, the terminal ran again. The fold is shared, so this call cannot be told apart from a nested run of the same chain calling the outer run's `next`, which the running mark exists for |
| The stack grows into a new array while an entry is marked running | Handled, tested | The mark is cleared by position, not through a pointer into the old array |
| An interceptor runs `next` in a goroutine and returns before it finishes | Accepted | An exchange belongs to one goroutine, which the `Exchange` godoc states. Such a goroutine races, as it did on `v0.1.0` |
| Concurrent requests | Handled, tested | The prebuilt steps are immutable, and each exchange belongs to one request (64 concurrent requests under `-race`) |
| `Assemble(nil)` | Accepted, unchanged | It panics when the terminal is reached, as before |

**Measured** (2026-11-10, `benchstat`, n=10, darwin):

| Benchmark | allocs/op before → after | ns/op before → after |
|---|---|---|
| `Assemble/only/8` | 10 → 1 | 78.1 → 7.7 |
| `Assemble/run/8` | 13 → 4 | 283 → 131 |
| `ChainRequest/0` (net/http) | 23 → 21 | 1522 → 962 (noisy before: ±91%) |
| `ChainRequest/8` (net/http) | 31 → 21 | 1095 → 1007 |

The fold accounts for one allocation per `Assemble` (`only/8`). The other three in `run/8` come from the entry logic, which is outside the fold. With eight interceptors, a request now allocates as much as with none. These figures are for the fold alone. Decision 4's re-entry marker adds one allocation per request, so on the finished branch `Assemble/run/8` is 5 allocs/op and `ChainRequest/0` and `/8` are both 22. One departure from the plan: each per-exchange entry carries a `running` flag, and the lookup returns a position (`topTerminal`), not a `Next`. The flag is what lets the same chain nest before decision 4, and the position is what lets the flag be cleared safely when the stack grows. The fold is built once in `New`. `Assemble` also runs the same `sync.Once`, so a `Chain` that did not come from `New` still gets its fold.

### 6. Single-value options are refused when given twice

`WithLogger`, `WithClock`, `WithPolicyEngine`, `WithRateLimiterFactory` and `WithErrorHandler` record that they were given. A second call fails with `"<option> was given twice; one chain has one <thing>"`, the form the `Enable*` options already use. This holds even for the same value: the error handler is a function and cannot be compared, and one rule for all five is simpler to state than a rule that depends on the type.

`EnableAuthorization` keeps its documented last-wins authorizer and its appended rules, because that is a recorded decision for wiring split across modules, and base-path decision D1 relies on it. It now checks each call's authorizer for nil when that call is applied. That check is the only one: the deferred check the option also registered can never fail once the apply-time check exists, so it is removed (found by the review, with no behaviour to reproduce; the existing nil-authorizer test covers the remaining check).

- **Default and override:** these are wiring rules, so there is nothing to override. A consumer who meant to replace a value removes the first option.
- **Compatibility:** a chain that built on `v0.1.0` by giving one of these options twice now fails construction. This is listed under `Changed` in the changelog, which the release policy requires under v0 too. The user chose this scope on 2026-11-09: only the undocumented last-wins options, leaving the documented authorizer and base-path rules alone.

| Failure | State | Outcome |
|---|---|---|
| Second policy engine hides the first's challenges from the enforcer check | Handled, tested | Construction fails |
| Absent authorizer in an earlier `EnableAuthorization` call | Handled, tested | Construction fails, naming the option and the authorizer |
| A shared option slice plus an application override | Accepted | Construction fails, telling the consumer to remove one |

### 7. Documentation of what stays the consumer's

- **`EnableAuthorization` and `PathPrefix`:** on fiber, the router treats letter case and trailing slashes as one route, so a matcher has to as well. A matcher on `Method() == "GET"` also has to cover `HEAD`, which both fiber and ServeMux route to GET handlers.
- **`RegisterInterceptor`:** a consumer interceptor at a built-in's exact slot runs before or after it according to option order. An authenticator belongs before the gates.
- **`ginsec` and `fibersec`:** routes registered before the middleware is added are not guarded. Mounting one chain twice runs it once; two different chains both run.
- **`Request.Path`:** the godoc no longer promises parity with what a router serves. It states that the chain refuses dot segments before anything reads the path.

### 8. Release and disclosure

- **Where the work happens.** On the public branch `fix/harden-chain-boundary`, cut from `main`, merged through an ordinary pull request. CI and branch protection apply as for any change. Before the pull request is opened, the full local gate also passes on the branch head: `make check`, `make release-check VERSION=v0.1.1`, and the conformance suite with Docker.
- **Why not a private fork (rejected).** A temporary private fork of a draft advisory keeps the fix secret until release, but runs no CI and bypasses branch protection. Secrecy protects consumers running the vulnerable version in production, and there are none yet. The maintainer chose the public branch on 2026-11-10.
- **Release steps.** After the merge, CI runs on `main`. Then the maintainer follows `RELEASING.md` for `v0.1.1`, using the revised step 7 from `release-readiness`.
- **What `v0.1.1` carries:**
  - all nine modules, at the same version;
  - `retract v0.1.0` in the root module's `go.mod`, where both defects' code lives. A consumer of `v0.1.0` sees the retraction through `go list -m -u`. The nested modules need none: each `v0.1.1` requires the root at `v0.1.1`;
  - a changelog entry listing the three defects under `Security` and decision 6 under `Changed`.
- **Disclosure: changelog and retraction only (departure from `SECURITY.md`).** `SECURITY.md` says a fixed vulnerability is disclosed in a repository security advisory, a Go vulnerability database report and a changelog `Security` entry. For these three defects, only the changelog entry and the retraction are made. No advisory is drafted or published, no CVE is requested, and nothing is reported to the Go vulnerability database. This is the maintainer's decision of 2026-11-10, because no consumer runs scrty in production. It applies to this change only. `SECURITY.md` is unchanged, and later vulnerabilities follow it.
- **What a `v0.1.0` user sees (accepted failure mode).** `govulncheck` reports nothing for `v0.1.0`, because no database entry exists. The signals are `go list -m -u` showing `v0.1.0` as retracted, with the retraction comment pointing at the `0.1.1` changelog entry, and that entry's `Security` section.
- **Exposure before the tag (accepted failure mode).** The defects and their reproductions are public from the moment the branch is pushed until `v0.1.1` is tagged. The maintainer tags as soon as CI on `main` is green for the merge commit.

## Open Questions

- **Refusing owed second-factor states on every chain.** The authorization stage refuses only challenges whose gate the chain registers (decision 3). A gateless chain run inside a gated chain's gates is now refused at publication (decision 2). What remains is a gateless chain mounted on its own, not inside a gated one, that shares the session store. The group 6 review leaned toward refusing the second-factor, enrolment and recovery states on every chain, failing closed even where that chain cannot satisfy them. That would close the remaining case. Left for the maintainer to decide, as a follow-up change with its own red test, not in this patch.

## Risks / Trade-offs

- **[A client that sends dot segments on purpose (for example a crawler's normaliser bug) now gets 400]** → No browser does this, and the 400 carries no detail. Recorded in the changelog.
- **[The gate mark makes a nested-chain design fail with 500 on its first request]** → It fails closed and visibly. The error names the slots to use.
- **[The fold rewrite changes a hot path every request takes]** → The conformance suite runs on all three adapters, with a benchmark comparison, and the Opus reviewer checks ordering, re-entry and the terminal lookup specifically.
- **[The fix is public before `v0.1.1` is tagged]** → Accepted: no consumer runs scrty in production (decision 8). The tag follows the merge as soon as CI on `main` is green.
- **[`govulncheck` never flags `v0.1.0`]** → Accepted (decision 8). The retraction and the changelog are the only signals.
- **[The release-probe fix in `release-readiness` has not landed when `v0.1.1` is tagged]** → Task 1.1 checks that it is on `main` before the branch is cut, and task 9.2 checks again before tagging.

## Migration Plan

1. A consumer upgrades all scrty modules to `v0.1.1`.
2. A chain that gives one of the five options twice fails construction with an error naming the option. The consumer removes the duplicate.
3. A consumer authenticator registered after the gates now gets 500 on publishing. The consumer moves it to `OrderBearerToken`.
4. **Rollback:** pin `v0.1.0`. That reintroduces the defects, and `go` warns because the version is retracted.

## References

### Decision 1: dot segments

**Researched** (2026-11-09):
- [gofiber/fiber v3 `ctx.go` and `path.go` (`normalizeRequestPath`), and `app.go` `Config`](https://github.com/gofiber/fiber/tree/v3.6.1), read from the module cache: fiber removes dot segments and decodes unreserved escapes before routing, and `CaseSensitive`, `StrictRouting` and `UnescapePath` default to false.
- [valyala/fasthttp v1.77.0 `uri.go`](https://github.com/valyala/fasthttp/blob/v1.77.0/uri.go), read from the module cache: `PathOriginal` is the path as sent, never normalised.

**Primary documentation:**
- [RFC 3986 §5.2.4, Remove Dot Segments](https://www.rfc-editor.org/rfc/rfc3986#section-5.2.4): dot segments are resolved by the client when it forms a target. A server that receives one is facing a client that chose to send it.

### Decision 8: release and disclosure

**Researched** (2026-11-09):
- [GitHub Docs: Collaborating in a temporary private fork](https://docs.github.com/en/code-security/security-advisories/working-with-repository-security-advisories/collaborating-in-a-temporary-private-fork-to-resolve-a-repository-security-vulnerability): CI cannot access the fork and branch protection is not enforced, which is the cost that led to rejecting the private fork.

Otherwise reasoned from scrty's own `SECURITY.md`, `RELEASING.md` and the settled `release-policy` spec, together with the maintainer's decision.

### Decisions 2–7

Reasoned from scrty's own settled specs (`http-security-chain`, `framework-adapters`, `release-policy`) and the archived reauthentication and endpoint-inventory-base-path designs. The reproductions are listed below.

### Review revisions (2026-11-10)

Researched, accessed 2026-11-10:
- [RFC 6797 §7.1–7.2, HTTP Strict Transport Security](https://www.rfc-editor.org/rfc/rfc6797#section-7.2): an HSTS host sends the header on responses over secure transport, and never over plain HTTP. Supports running the entry check after client resolution (decision 1).
- [Spring Framework, `OncePerRequestFilter`](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/web/filter/OncePerRequestFilter.html): a filter skips a second pass on one request when an "already filtered" attribute is present, with no comparison of request state. Supports keeping decision 4's pass-through.
- [Spring Security, `HttpFirewall`](https://docs.spring.io/spring-security/reference/servlet/exploits/firewall.html): established practice is to reject un-normalised paths by default. The page does not say how that rejection is ordered against forwarded-header handling, so that point is unverified.

## Reproductions

Each test was red on `v0.1.0`, in a disposable export, and the main session re-ran it on 2026-11-09. The files are kept in `repro/` as `.go.txt`, so no module compiles them. Each becomes the red step of its task.

| Claim | Test | Command (in the export) | Red output |
|---|---|---|---|
| Fiber authorization bypass | `TestFiber_AuthorizationRuleSeesRoutedPath` (`repro/fibersec_pathdiff_repro_test.go.txt`) | `go test -run 'TestFiber_AuthorizationRuleSeesRoutedPath' -count=1 .` in `httpsec/fibersec` | `the /admin/users handler ran (status 200)` for `dot-dot_segment`, `encoded_dot-dot_segment`, `dot_segment_then_dot-dot`, `encoded_slash_under_UnescapePath`, `upper-case_path_against_catch-all` |
| Fiber cool-down bypass | `TestFiber_RecoveryCooldownSeesRoutedPath` (same file) | same directory | `the marked handler ran (status 200)` for `dot_segment`, `encoded_dot_segment`, `dot-dot_segment` |
| Gin and ServeMux are not exposed | `TestGinRoutingOfNonCanonicalTargets` (`repro/ginsec_pathdiff_repro_test.go.txt`) | `go test -run TestGinRoutingOfNonCanonicalTargets -count=1 .` in `httpsec/ginsec` | Passes: 404 or a redirect, and the handler never runs |
| Authenticator after the gates | `TestRepro_ConsumerAuthenticatorAfterGatesIsJudgedByThem` (`repro/httpsec_lateauth_repro_test.go.txt`) | `GOWORK=off go test -run '…' -count=1 ./httpsec/` | Six cases `Should not be: 200`. The four bearer-slot controls pass |
| Double mount runs twice on success | `TestRepro_DoubleMount` (`repro/ginsec_double_repro_test.go.txt`) | `go test -run TestRepro_ -count=1 .` in `httpsec/ginsec` | `expected: 1, actual: int32(2)` (authenticator calls, limiter resets) |
| Second single-value option accepted | `TestRepro_SecondSingleValueOptionIsSilent` (`repro/httpsec_wiring_repro_test.go.txt`) | `go test -run TestRepro_ -count=1 .` in `httpsec` | `An error is expected but got nil` for `WithLogger` and `WithPolicyEngine` |

The review of the first implementation (2026-11-10) added these. Each test ran on `fcec3a8f` in a disposable worktree.

| Claim | Test | Command | Red output |
|---|---|---|---|
| A retried pass is refused before the gates | `TestChain_RetriedPassPublishesBeforeGates` (`repro/httpsec_gatemark_repro_test.go.txt`) | `go test -run 'TestChain_RetriedPassPublishesBeforeGates' -count=1 .` in `httpsec` | `a session was published after the chain's gates had begun` on the second pass. The control without the retry passes |
| A chain mounted inside another's gates publishes an unjudged session | `TestChain_SecondChainCannotPublishPastFirstChainsGates` (same file) | same directory | `the handler ran with session owing a second factor as an authenticated caller no gate judged (status 200, publish err <nil>)`. The control, the same session published in the gated chain, is refused |
| The entry 400 lacks secure-only headers behind a trusted proxy | `TestChain_EntryRefusalCarriesSecureHeadersBehindTrustedProxy` (`repro/httpsec_entry_backstop_repro_test.go.txt`) | `go test -run 'TestChain_EntryRefusalCarriesSecureHeadersBehindTrustedProxy' -count=1 .` in `httpsec` | `Strict-Transport-Security` empty: `the refusal lacks the secure-only header the same request gets on a clean path`. Both controls pass: a clean path carries HSTS, and an untrusted peer forging the scheme gets none |
| The backstop's log hides a method-lookup failure | `TestAuthorization_BackstopSurfacesMethodLookupFailure`, log case (same file) | same directory | `no record carries the store failure; only the wiring-mistake record exists` |
| The backstop's status differs from the gate's on a method-lookup failure | same test, status case | same directory | Refuted: passes, gate and stage both `500 … the usable MFA methods could not be looked up` |
| Double mount: a rewrite between the mounts is not judged again | `TestGin_DoubleMountSecondEntryAfterCredentialSwap` (`repro/ginsec_double_swap_repro_test.go.txt`) | `go test -run 'TestGin_DoubleMountSecondEntryAfterCredentialSwap' -count=1 .` in `httpsec/ginsec` | Credential swap `expected: "u-2" actual: "u-1"`; invalid credential `expected: 401 actual: 200`; Host and query swaps served. Both controls pass (no middleware, path rewrite). This is the accepted behaviour of decision 4, which group 10 pins rather than changes |

The upper-case fiber case is not closed by decision 1. It is accepted as the consumer's to match (decision 7), so it is left out of the carried-forward test rather than kept as a test that can never pass. `TestRepro_NilOption` and `TestRepro_SameSlotOrderDependsOnOptionOrder` assert behaviour that is documented and stays. They are not carried forward as red steps.
