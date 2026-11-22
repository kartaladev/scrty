# Design

## Context

See `proposal.md` for why. The requirements are in the deltas under `specs/`: `http-security-chain` and `framework-adapters` (decisions 1–7, 11), `token-issuance`, `oidc-provider-authorization` and `oidc-provider-logout` (decision 9), `security-state-stores` and `passkey-authentication` (decision 12), and `email-notification` (decision 13).

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
- Follow Go's context idioms across the library (decisions 11–14), found by a sweep of every package on 2026-11-11: a chain run leaves its caller's exchange as it found it, work detached from the caller's cancellation has a deadline, a cancelled send says so, and the remaining context hand-offs are documented or corrected.

**Non-Goals:**
- **Case-folding or trailing-slash folding of `Path()` on fiber.** That would silently change every exact-match endpoint and every consumer predicate written with capitals. It stays the consumer's to write rules knowing fiber's routing, now stated where rules are written (decision 7).
- **A construction-time role for consumer authenticators,** such as a `RegisterAuthenticator`. It would add API in a patch release, and decision 2 already fails closed at runtime. It is recorded as a candidate for a later minor.
- **Enforcing consumer challenge kinds at the authorization stage.** Only the consumer's own gate knows where it sits.
- **Checking routers other than ServeMux and gin behind the net/http adapter.** Decision 1 covers them anyway, because the refusal does not depend on the router.
- **Exported options in this release for the bounds of decision 12, or a `WithoutTx` for background starts (decision 14).** Each adds exported API, and under Semantic Versioning a patch release adds none. `gorelease` would not catch it: it skips the compatible-change check while the base version is `v0` (`cmd/gorelease/report.go`, checked in the pinned source by the audit of 2026-11-11), so this is the project's own rule, held by review. Both are candidates for the next minor.

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

`PublishSession`, the exported function, refuses a non-nil session in three cases:
- the publishing run's own entry on the exchange is marked by its gate frame (a late publication);
- another run's entry on the same exchange is marked and the publishing chain does not enable every gate that run's chain enables;
- an enclosing run of another chain, found through the run marker's parent links, is marked, and the publishing chain does not enable every gate that run's chain enables.

It returns an error wrapping `ErrConfig` (500) that names the late publication and the slots to use, and publishes nothing. The chain writes one sampled log record per chain for it.

The resolution core and any built-in that sets a session publish through an unexported path. That path does not check its own run's mark, because the core runs at `OrderBearerToken`, before its own gates. It does refuse, with the same error class, when another run's entry on the same exchange is marked, or an enclosing run of another chain is marked, and the publishing chain lacks one of that run's gates; that error says to mount the chain outside the other chain's gates. The same-exchange check was added in task 10.16, after the 10.14 review reproduced a gateless built-in publishing on a shared exchange whose context had been replaced. The audit for such built-ins is a gopls references query, not a grep.

The frame-scoped mark and the check of enclosing runs were added after review. Two defects were reproduced against the first version, which set the mark for the whole run and kept it on the exchange only:
- **A retried pass:** a consumer interceptor before the bearer slot that calls `next` twice had its authenticator refused on the second pass (`TestChain_RetriedPassPublishesBeforeGates`).
- **A chain mounted inside another chain's gates:** a gateless chain mounted with `Middleware` inside a gated chain built a fresh exchange with no mark. It published a session owing a second factor that no gate judged, and the handler served it with 200 (`TestChain_SecondChainCannotPublishPastFirstChainsGates`).

The gate-set condition was added while group 10 was implemented. The first version of the cross-chain check refused every chain run inside a marked run. A handler runs inside its chain's gates, so that also refused a handler forwarding the request in-process through a gated chain, the same chain included. Decision 4 says such a forward runs in full. The check returned 500, and the existing `TestReauthResolve` case that serves a racing renewal through the chain from inside the second-factor gate failed. A throwaway test reproduced the same 500 for a same-chain forward from the handler. A chain mounted inside the gates and a chain the handler calls run in the same place, so position cannot tell them apart. What tells the bypass apart is whether the inner chain's own gates judge what it publishes. A chain that enables every gate the enclosing chain enables judges the session the same way the outer chain would, so its publication is allowed. A chain missing one of those gates is refused. The maintainer chose this rule on 2026-11-10 over two others: skipping only runs of the same chain, which still refuses a forward to an equally gated chain, and dropping the cross-chain check, which reopens the reproduced 200.

- **Why the gate set, not the chain's identity:** Spring Security re-applies its filters on a forward and authorizes the forwarded dispatch again, carrying over the security context of the original request. A forward is judged by the chain it goes through. A chain with the same gates gives the same judgement, whichever chain it is.

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
| A different chain nested on the same exchange authenticates after the outer chain's gates | Handled, tested | Refused with 500, by a consumer or a built-in authenticator alike, when the nested chain lacks one of the outer chain's gates. A nested chain covering every gate publishes, on the same exchange as on a fresh one: each run's entry on the exchange carries its own mark, set and restored by its gate frame, and only the publishing run's own mark is a late publication; another run's mark refuses only a publisher that lacks one of its gates. The whole-branch review reproduced the earlier refusal of a covering chain on the same exchange (`TestChain_CoveringChainOnSharedExchangePublishes`); the maintainer chose to fix it before release (2026-11-10) |
| A gated chain nested on the same exchange before the outer chain's gates | Handled | The nested chain's mark is not the outer chain's own, so the outer chain's authenticator, still before its own gates, is judged by the gate-set rule like any publication inside another chain's gates: refused when the outer chain lacks one of the nested chain's gates |
| The inner chain's own late authenticator on a shared exchange | Handled, tested | Its own run's mark is set, so it is a late publication: 500 |
| Why the mark is per run, not "the chain that set it" | Handled, tested | Recording only the chain would let an outer chain's late authenticator publish once an interceptor past its gate ran the rest of the chain through a covering chain: the mark would name the inner chain, and the outer chain's own run would be skipped. Found while implementing task 10.12; a per-run mark refuses it (`outer chain's late authenticator behind a covering chain`) |
| A consumer replaces the context on a shared exchange to hide the enclosing run | Handled, tested | Marks on the same exchange are read from the exchange itself, not the context, in both `PublishSession` and the built-in publishing path, so a gateless inner chain is still refused, by a consumer or a built-in authenticator. The 10.14 review reproduced the built-in path missing that check (`TestChain_GatelessBuiltInOnSharedExchangeWithReplacedContextPublishes`) |
| An exchange run many times | Handled, tested (decision 11) | Each run puts back the context it found when it returns, so the context does not grow and a context-session lookup stays one short walk. The 10.14 review measured `BenchmarkAssemble/run/8` growing from 27 µs to 1 ms per run over 16,000 runs of one exchange before this |
| A gate reverted to judging only `ex.Session` | Tested | Each gate's own refusal is pinned: the backstop's bypass record is absent when a gate refuses, so a gate that stops judging the enclosing session is noticed |
| A gate frame reached on an exchange where its chain has no run (a step kept past its run) | Handled, tested | Refused with the existing not-running error before the gate runs |
| Publication with no chain running interceptors (from a handler), or an enclosing marked run with no chain recorded | Handled, fails closed | Treated as enabling no gate, so any enclosing marked run of a gated chain refuses it. From a handler, publication is refused by the gate-set rule (`errPublishedInsideGates`), since the handler runs inside its chain's own marked run |
| `PublishSession` on an exchange after its outermost run returned | Accepted | The mark was put back when the gate's frame returned, so the call is allowed. It reaches nothing: the handler has run and no chain reads the exchange again |
| A consumer interceptor before the bearer slot calls `next` twice (a retry) | Handled, tested | The mark is put back after each pass, so the authenticator publishes before the gates on both passes |
| A different chain run inside another chain's gates, through any adapter, publishes a session, and it lacks one of the enclosing chain's gates | Handled, tested | Refused with 500, whether a consumer or a built-in authenticator publishes, and the handler does not run. The error says to mount the chain outside the other chain's gates, or to authenticate in the outer chain |
| No gate enabled | Handled, tested | Nothing to bypass; publishing is allowed anywhere |
| A built-in that publishes at or after the gates | Handled | The resolution core (`resolve.go`, reached only at `OrderBearerToken`) uses the unexported path. gopls finds no other library caller of `PublishSession`; the other built-ins that set a session (`complete.go`, `mfa_verify.go`, `reauth_resolve.go`, `recovery.go`) assign the field and put it on the context with `withSession` directly, without the gate check. Each answers the request itself, so nothing after it reads that session |
| The mark left over from an earlier run of the same exchange | Handled, tested | The gate's frame puts the mark back on return, and a panic out of a gate takes the same deferred path. A second run of one exchange publishes at the bearer slot as normal |
| A chain mounted with `Middleware` or an adapter inside another chain's gates (a fresh exchange) | Handled, tested | The outer run's mark is read from the run marker on the context, so the inner chain's publication is refused as in the row above |
| A handler forwards the request in-process through the same chain, or through a different chain that enables every gate the outer chain enables | Handled, tested | Publication succeeds. The inner chain's own gates judge the session, so a session owing a challenge is refused by that gate, not served |
| A chain inside the gates enables some of the outer chain's gates but not all | Handled, tested | Refused with 500: the gate it lacks would leave its challenge unjudged |
| Several enclosing marked runs | Handled, tested | The publishing chain must cover the gates of every marked enclosing run. The walk compares gate sets of fixed size and allocates nothing |
| Consumer code inside the gates sends the request on with a context not derived from the request's (`context.Background()`, or a context from elsewhere through `SetContext`) | Accepted, documented | On another exchange, the enclosing run is no longer visible, so the inner chain is judged as a chain on its own: a gateless one publishes. On the same exchange the marks are read from the exchange, so it is still refused (the row above). Nothing can see a run the consumer dropped, and the code doing it can already assign a session. Reproduced as behaviour by the review (a throwaway test). The `PublishSession` and `SetContext` godoc say a new context must derive from the current one |
| Consumer code calls a `next` captured from another chain's interceptor while both runs are live on one exchange, so the publishing chain is misidentified | Accepted, UNREPRODUCED | The same misuse as reusing `next` after its run (decision 5's rows). No adapter, forward, nesting or retry reaches it |
| The gate-set encoding drifts from the helper that names the gates | Handled, tested | A test asserts every gate kind has a position in the set and that the set fits its type, so a missing kind cannot silently read as covered |
| A gate's exemptions differ between two chains with the same gates | Accepted | Each chain's exemptions cover only the endpoints that chain answers itself, and those answer the request (decision 3's enumeration). A forwarded request is judged by the inner chain's exemptions, as any request to that chain is |
| A gateless chain not run inside a gated chain, sharing its session store | Accepted (Open Questions) | Nothing on that chain judges an owed challenge, as for any chain without the gate |
| The marker's parent links are walked on every publication | Accepted | A walk only as deep as the chains nested on one request, usually one. It reads an atomic flag per run and allocates nothing |
| A result published with no session after the gates | Accepted | Only a non-nil session is refused, as specified. A stateless caller is not what the gates judge, and setting one is the same as `WithCaller` on the context |
| `PublishSession(nil, nil)` as a sign-out leaving an earlier caller on the context | Out of scope, UNREPRODUCED | Existing behaviour, seen in the code during group 5 but not tested. It does not change with this decision |
| The refusal's log record | Handled, tested | One sampled error record per window per chain, with no session, family or user identifier |

### 3. The authorization stage refuses a session owing a built-in challenge

Before evaluating rules, the authorization stage checks `ex.Session` against the gates this chain registers, in their run order. When the session owes the challenge of a registered gate, the stage refuses with the error that gate returns, including the second-factor methods (`challengeMethods`). A challenge whose gate the chain does not register is not refused (see the failure table).

- **Which session is judged:** every built-in that judges the request's session (the four gates, the recovery cool-down, and this stage) reads one helper: the chain's own `ex.Session`, or, when the chain resolved none, the session on the request context, which only an enclosing chain can have put there (a consumer cannot write that key). The whole-branch review reproduced the need: a gated chain mounted inside a gateless chain that published a session owing a second factor built a fresh exchange with no session, so its gate and this stage judged nothing, and its handler served the session from the context with 200 (`TestChain_GatedChainInsideGatelessChainServesOwingSession`). `v0.1.0` behaves the same. The maintainer chose to fix it before release (2026-11-10), over documenting it as a known issue.
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
| A gated chain mounted inside a gateless chain that published an owing session | Handled, tested | The inner chain's gate judges the context's session and refuses with its challenge; the handler does not run |
| The inner chain resolves a session of its own while the context carries the enclosing chain's | Handled, tested | The chain's own session is judged. It is the one the chain's handler sees too, because publishing puts it on the context |
| `ex.Session` and the request context's session diverge through `ex.SetContext` with a foreign context | Accepted, documented | The built-ins judge `ex.Session` when set, the context's session otherwise. A context not derived from the request's is already documented as hiding the enclosing runs (decision 2) |
| A full session from the enclosing chain on a chain whose rules require an authenticated caller | Handled, tested | Let through, as on `v0.1.0` |
| The enrolment gate's own endpoints (begin, confirm, email) inside a gateless chain | Accepted, tested | They stay on the chain's own `ex.Session`, like the second-factor endpoints below: the gate judges with the enclosing session, the endpoints answer `ErrAuthenticationRequired`, and enrolment goes through the chain that owns the session. The first implementation served the enclosing session there; the 10.14 review found that those endpoints save the session through the inner chain's session store, which writes another chain's session into a different store when the two differ. Decided 2026-11-11 in favour of failing closed and one rule for every endpoint |
| The second-factor verify, begin and listing endpoints, the saved recovery-codes endpoint and the password-change resolve endpoint inside a gateless chain | Accepted | They stay on `ex.Session`, because they need the chain's own authentication and rotate the session. The inner gate refuses the owing session, and the inner chain's verify endpoint answers it with `ErrAuthenticationRequired`. The challenge is paid through the chain that owns the session. Fails closed |
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

### 9. A token header must name its algorithm, and the dependencies follow Dependabot

The maintainer asked, on 2026-11-10, for the open Dependabot updates to be taken on this branch, with every feature proven unbroken:
- `lestrrat-go/jwx/v4` 4.5.0 to 4.6.0: the root module directly, and the nested modules indirectly;
- `testcontainers-go` and its postgres, redis and mailpit modules 0.44.0 to 0.45.0, in the `test` module only;
- `github/codeql-action` init and analyze 4.39.2 to 4.39.3, pinned by commit.

The whole workspace passed build, vet, `-race` tests with the container suites running, the layout guards, `pincheck`, `test-isolated` and `vuln` on the upgraded modules.

jwx 4.6.0 changes behaviour in places scrty reaches:
- **A header with no `alg` (jwx #2422):** with one key given, `jwt.Parse` now verifies under the key's algorithm instead of refusing. The ID token hint check (`judgeHintToken`, used by the authorization and end-session endpoints) refused such a hint on 4.5.0 and accepts it on 4.6.0. Separately, `token.Verifier`, which selects the key from a set, accepted a header with no `alg` on 4.5.0 already, against the comment that says a header naming none fails. A test reproduced it in a scratch copy on both versions (`TestProbe_VerifierRefusesHeaderWithoutAlg`, `token: invalid` expected, got nil). Neither is a forgery: the signature is still checked under the algorithm recorded on the key, so the issuer's private key is still needed.
- **NumericDate parsing:** a negative `nbf` or `iat` now parses as a date before 1970 where it used to fail, a negative `exp` is still refused as expired, and a malformed string date is now refused at parse. Each needs the issuer's key to produce, and RFC 7519 does not forbid them.

Decision, made by the maintainer on 2026-11-10: both verification paths require `alg` in the header before the signature is checked (the verifier after fetching its keys, the hint check after finding the published key, so a hint under a retired key still counts as none), refusing as each refuses a bad signature today (`token.Verifier`: an invalid-token error; the hint check: the hint is refused, `invalid_request`). The other callers (the OIDC client, the client-assertion check, DPoP, WebAuthn metadata) already require `alg` themselves.

- **Why refuse:** RFC 7515 §4.1.1 makes `alg` required, and RFC 8725 §3.1 asks a verifier to check the algorithm. Relying on the library's default for a missing header is what changed under us. An explicit check holds whatever the library does next.
- **Default and override:** on, with no override. A token without `alg` is malformed; no consumer needs it accepted.
- **Alternatives:** fixing only the hint check, which the upgrade caused, and leaving the older `token.Verifier` gap for a later release; accepting both as harmless and correcting the comment.

| Failure | State | Outcome |
|---|---|---|
| Access or ID token with no `alg`, signed with the current key | Handled, tested | `token.Verifier` refuses it as invalid |
| ID token hint with no `alg`, at the authorization or end-session endpoint | Handled, tested | Refused as a hint that fails its checks: `invalid_request` at authorization, the end-session endpoint's existing refusal of a bad hint |
| `alg` present but empty, or not a string | Handled, tested | Refused like a missing `alg` |
| Negative `nbf`/`iat`, negative `exp` on a hint, malformed string dates | Accepted | jwx 4.6.0's parsing, as above. Producing them needs the issuer's key |
| A later jwx release changes the missing-`alg` default again | Handled | scrty's own check runs before the library's |
| `make vuln` lists known vulnerabilities in required modules that scrty's code does not call | Accepted | `govulncheck` reports none reachable. Not compared against `main` |
| testcontainers 0.45.0 moves the CockroachDB and Dex adapters and the redis client examples into separate modules | Accepted | scrty uses none of them; every module builds and the container suites pass |
| A header naming an algorithm other than the key's, over a valid signature under the key's algorithm | Handled, tested | Refused by scrty's own equality check, next to the missing-`alg` check, in both paths, and by jwx's default match behind it. Each check is pinned on its own by unit tests of the unexported helpers, since through the public path either one refuses alone. The group 11 review showed that only jwx's default algorithm-match check enforced it, and that no test would notice if the default changed (a mutation skipping the match let `"alg":"RS384"` and `"alg":"none"` over an RS256 signature verify). The same reasoning as for a missing `alg` applies |
| A refusal's error text quotes the presented `alg` (jwx's unknown-algorithm or mismatch text) | Accepted, unchanged from `v0.1.0` | The error is returned to the consumer, never rendered by the chain, and the bare status carries no body. The comment on scrty's own refusal says only that one carries no header value |
| Every presented token's header is parsed before its signature is checked | Accepted | One extra parse per token, bounded by the verifier's maximum token size |
| Indirect requirements tidy moved with the upgrade (`magiconair/properties` 1.18.12 and `moby/go-archive` 0.3.3 in `test`; `valyala/fastjson` dropped everywhere) | Accepted | Real releases; `go mod verify` and `go mod tidy -diff` are clean |
| The end-session endpoint judges hints with the same check | Handled, tested | One function judges hints for both endpoints; the `oidc-provider-logout` delta states it |
| A hint whose payload is itself a signed token | Accepted, UNREPRODUCED as a defect | Refused today, pinned by the existing row `hint wrapping a token of its own`. While task 11.7 temporarily turned off jwx's algorithm match, that row failed too, so the refusal rests on jwx's default handling of nested tokens rather than on a check of scrty's own. No shipped configuration turns the match off. A later jwx change would show up as that row failing |

### 10. The release gate's local proxy does not list the release version

`make release-check` serves the release-to-be from a local file proxy (`tools/cmd/releaseproxy`) placed before the public proxy in `GOPROXY`, so nested modules can resolve the root at the release version. The proxy wrote an `@v/list` file naming that version. `gorelease` reads a base module's existing versions with `go list -m -versions`, which takes the first proxy's list, so it saw the release version as published and refused: `version v0.1.1 already exists`. `v0.1.0` passed only because its base was `none`, which skips the listing. A scratch check showed it: with the local list, `go list -m -versions github.com/kartaladev/scrty` printed `v0.1.1`; without it, the listing fell through to the public proxy (`v0.1.0`), and `go list -m github.com/kartaladev/scrty@v0.1.1` still resolved locally.

- **Decision (maintainer, 2026-11-10):** the local proxy serves `.info`, `.mod` and `.zip` for the release version and writes no `@v/list`. Version listing then answers what is really published, and exact versions still resolve locally.
- **Default and override:** none; this is the gate's own tooling, not published.

| Failure | State | Outcome |
|---|---|---|
| The release version already published | Handled | `gorelease` sees it through the public proxy and refuses, as it should |
| The release version not published | Handled, tested | `gorelease` proceeds; exact lookups resolve from the local proxy |
| A tool in the gate asks the local proxy for `latest` or a version list | Accepted | It gets the public answer; the gate pins every version it needs |
| The public proxy unreachable | Accepted | The listing fails, and the gate stops with that error, as any network failure in it does |

### 11. A chain run leaves the caller's exchange as it found it

The 10.14 review found that a chain run's context leaks up to its caller. The step `Assemble` returns derives a context (event delivery, the run marker, the published session) and stores it on the exchange, and nothing puts the caller's back. Each later run on the same exchange then wraps the one before. After a nested run, the outer chain reads the inner chain's context. A sweep of every package on 2026-11-11 found this upward leak only in `httpsec`.

The step records, on entry, what a run may change on the exchange. It puts that back when the run returns, deferred, so a panic takes the same path. This applies to every entry, the decision 4 pass-through included, where it changes nothing. It restores:
- **the context:** `ex.Context()`, which publishing and `SetContext` replace during the run;
- **what the run resolved:** `Session`, `Authentication`, `bearerCredential`, and the late-renewal fields (`renewal`, `chargeRenewal`, `admitRenewal`);
- **what the run's chain configured:** `perRequest`, `csrfOptOut` and `raised`.

It does not restore two kinds of field:
- **the request's own facts:** `Request`, `Writer`, and the certificate thumbprint, which describe the one request whichever chain reads them;
- **the state that coordinates runs on one exchange:** `refusalReported`, the terminal stack and the gate marks. They exist to be seen across runs. `refusalReported` in particular stops an outer chain reporting a refusal an inner chain already reported. It is cleared when an outermost run starts (no other run live on the exchange), so an exchange run again reports that run's own refusal; nested runs still share it.

A field restore in this list is kept only if its red test fails first (`defect-claims.md`). The context restore is reproduced (`TestChain_RunPutsBackTheContextItFound`, 7 cases). The field leak is reproduced too: every field case of `TestChain_RunPutsBackTheExchangeItFound` failed before the restore, each on its own field (task 12.1, 2026-11-11), so no field was dropped. The restore is one deferred copy of a `runScope` value, taken before the re-entry check so a pass-through entry and a panic are covered too.

- **Why:** this is Go's own idiom. A context derived for a call belongs to that call: `net/http` middleware passes `r.WithContext(ctx)` to `next` and never writes it back, and the `context` package says not to keep a context in a struct for later use. The exchange holds the run's context only while the run is live. The fields follow the same scope, so that after a run `ex.Session` and the context agree.
- **Alternatives:**
  - Reset at the next entry (option B, rejected). It caps the growth, but the caller still sees the finished run's state until then, and the reset reads state the caller may have meant to keep.
  - Restore the context only (rejected by the maintainer, 2026-11-11). It leaves `ex.Session` and the context disagreeing after the run.
- **Default and override:** on, with no override. A caller has no use for a finished run's derived state. Code that needs the run's state reads it inside the terminal, where it is live; the library's adapters already do.
- **Compatibility:** code that reads `ex.Context()`, `ex.Session` or `ex.Authentication` after the step returns now gets what was there before the run. No library code does. About 22 `httpsec` test functions did, through 12 helper sites that keep the exchange and read it after the run (50 reads, by gopls references), and one test outside them (`TestExchangePublishSession`). Each helper site now takes a copy of the exchange inside the terminal, so those tests read the run's state where it is live. The changelog lists it under `Changed`.

| Failure | State | Outcome |
|---|---|---|
| One exchange run many times | Handled, tested | Context depth and per-run cost stay flat (`TestChain_RunPutsBackTheContextItFound`; `BenchmarkAssemble/run/8` flat across `-benchtime` values) |
| An interceptor or the terminal panics | Handled, tested | The deferred restore runs, and a recovered panic leaves the caller's exchange as it was |
| A nested chain on a shared exchange publishes a session, and the outer chain's code after `next` reads the exchange | Handled, tested | It reads its own run's session, authentication and configuration |
| Composition: an outer chain's interceptor runs another chain's step around the rest of its own run (`inner.Assemble(next)(ex)`), and an outer interceptor past that point changes the exchange (rotates the session, as `mfa_verify.go` and `reauth_resolve.go` do) | Accepted, documented, tested (decided by the main session 2026-11-11 while the maintainer was away; flagged for review) | The outer run's interceptors past the composition point run inside the inner run, so what they set is put back with it when the inner step returns. An outer interceptor before that point reads, after `next`, the state from before the inner step, which may be a session its own run has since rotated away. Before the restore it read the rotated session. The 12.4 review reproduced it (`TestChain_ComposedInnerStepPutsBackWhatTheOuterRunSetInside`, pinned as behaviour). Read a run's state inside the terminal, as the `Exchange` and `Assemble` godoc say. The alternative was to snapshot around the terminal and re-apply what it changed after the restore; it was rejected because the context the terminal leaves is layered on the inner run's own, so the two cannot be separated without keeping the inner run's layers. No library path composes chains this way. The ID-token and cookie side of a rotation is done by the endpoint inside the run, so a stale read after the step is a read, not a re-issue |
| The late-renewal fields in a real nested renewal | Accepted | Restored generically with the other fields; their only readers are the renewal endpoint inside the same run (the 12.4 review traced `resolve.go`, `session_bearer.go` and `session_renewal.go`). The red test sets them directly rather than through a real renewal, which proves the copy and not a nested renewal flow |
| An inner chain reports its refusal, and the outer chain sees the error | Handled, tested | `refusalReported` is not restored, so the refusal is reported once, as before |
| An exchange refused once and run again | Handled, tested | `refusalReported` is cleared at the outermost entry, so the second run's refusal is reported. On `v0.1.0` it was swallowed (REPRODUCED by that case of `TestChain_RunPutsBackTheExchangeItFound` before the fix) |
| Consumer code (an adapter of their own) reads the exchange after the step returns | Accepted, documented | It sees the state from before the run. The `Exchange` and `Assemble` godoc say to read a run's state in the terminal |
| The decision 4 marker after the run | Handled | The marker lives on the context, so restoring the context removes it from the exchange. A context kept elsewhere still carries the finished run, which is flagged done (decision 4's rows) |
| Gate marks (decision 2) | Handled, tested (decision 2) | They are restored by their own gate frame, inside the run |
| `SetContext` with a context not derived from the run's, inside the run | Accepted (decision 2's row) | Decision 2's accepted row. The restore puts back the caller's context, whatever the run did to it |
| Cost | Handled, measured | One deferred copy of ten fields per run and no allocation. `benchstat` over `-count=10` (2026-11-11): `Assemble/run/8` 5 allocs/op and 248 B/op, `ChainRequest/0` and `/8` 22 allocs/op, all unchanged; `ChainRequest` time +1.5% and +0.45%. `Assemble/run/8` reads 201–342 ns/op at both `-benchtime=1000x` and `16000x`, where before the restore it read 12–16 µs and 131 µs |

### 12. Work detached from the caller's cancellation has a deadline

Some work must finish even if the client hangs up, so the library runs it under `context.WithoutCancel`. Examples are a failed-attempt record, a reuse-triggered family revocation, a TOTP refund and a passkey state change. `WithoutCancel` also drops the caller's deadline, so a store or port that hangs holds the request goroutine without end. The sweep reproduced the mechanism on the MFA verify throttle (`TestVerifyThrottle_DetachedRecordCarriesDeadline`: the detached call carries no deadline). That particular call goes to the `ratelimit.Limiter` port, which this decision leaves to the port's own contract (class 5 below), so the reproduction is not carried forward as a red step. The store calls in class 4 get their own red tests in task 13.4. The library is inconsistent here. Three groups of sites already bound their detached work:
- `apikey` and the passkey pending-registration delete, at 5 s;
- `oidcprovider`, at 10 s (`revocationBudget`);
- the sign-in notice, the unavailable-store wrapper and the SMTP send, each by its own timeout.

The other sites do not.

The rule: every detached call on a request path into a store or a service gets a deadline. Where a site has no bound of its own, it uses a library default through one internal helper, `internal/detach`: 5 seconds for a write, and 10 seconds for a revocation (a session family, a session or a credential), the budget `oidcprovider` already gives revocations (`revocationBudget`), because a revocation that times out leaves something live that should not be. Sites that already have a bound keep it.

Two kinds of call are left unbounded on purpose:
- **The `ratelimit.Limiter` port** (`RecordFailure`, `Charge`, `Refund`, `Exceeded`). Its contract makes the limiter bound itself, and the shipped shared limiters do (`internal/unavailable` applies its own operation timeout under a fresh `WithoutCancel`, so a bound here would change nothing for them). A failed record is only logged, so a bound that cut a slow consumer limiter short would drop a guess the `multi-factor-auth` spec says SHALL be charged. The port's contract governs instead.
- **Consumer callbacks: session end observers and the event sink.** They run consumer code, and the settled `sessions` requirement "End reports survive a hang-up and a panic" promises the reports. A shared cap would let one slow observer starve the rest. Their godoc says the consumer's code bounds its own work (task 14.4). A site that runs several independent writes gives each its own bound, as `oidcprovider/endsignin.go` does. Where one bounded call fails, the site handles the timeout exactly as it already handles a store error from that call: it refuses, logs or carries on as it does today. No new error path is added.

The implementing task takes a fresh inventory of every `context.WithoutCancel` in production code and puts each site in one of four classes. The main session records the final table here:
1. **Already bounded:** unchanged.
2. **The rollback or close of a transaction or savepoint the same call opened:** accepted. It runs on a connection whose operation has just returned, under the driver's and the pool's own timeouts.
3. **The long-lived context of a background loop, queue or stream:** unchanged here. This covers the sweeper, the memory session store, signing keys, queued notifications, back-channel jobs, the signals reload and the fiber route context. Each is bounded by its own shutdown or per-job timeout. Decision 14 covers their documentation.
4. **A detached request-path call into a store or service with no bound:** bounded by the default for its kind.
5. **A limiter port call or a consumer callback:** unbounded on purpose, as above.

The inventory also searches production code for `context.Background()` and `context.TODO()` used to detach work (for example `httpsec/fibersec/exchange.go`), and classes those sites the same way.

The sweep put these in class 4:
- `authenticate/mfa`: `throttle.go:216`, `totp.go:279`;
- `authenticate/passkey`: `register_pending.go:372`, `manage.go:195`, `clone.go:117,183,210`, `messages.go:152`;
- `session`: the reuse and end-observer writes;
- `recovery`: its detached writes and limiter calls;
- the MFA verify and grant-revoke paths;
- `httpsec`: the detached limiter and store calls (login, Basic, throttle, renewal, enrolment, password change, logout, end session, back-channel and rehash).

The sweep's list includes limiter calls (`mfa/throttle.go:216`, `ratelimit/guard.go:460`, the recovery limiter calls), which are class 5 by the rule above. It also missed sites the audit found outside these packages: `internal/eventsink/eventsink.go:77` (class 5), `oidcprovider/endsignin.go:181`, `authenticate/oidc/remote.go:319` and `policy/lockout`. Task 13.2 classes them, and lane D takes the class-4 sites outside lanes A–C.

**Inventory (task 13.2, 2026-11-11).** A fresh search of production code for `context.WithoutCancel`, `context.Background()` and `context.TODO()` across every workspace module. Classes 1–3 need no change:
- **Class 1:** `oidcprovider` under `revocationBudget` (`endsignin.go`, `endsession.go`, `revoke.go`, `refresh.go`, `exchange.go`); `authenticate/apikey/keys.go:672`; `authenticate/passkey/register_pending.go:163`; `httpsec/signin_notice.go:377`; `internal/unavailable/wrap.go:409,724`; `authenticate/oidc/remote.go:319` and `oidcprovider/clientkeys.go:76` (the outbound client's timeout); `expiry/sweep/sweeper.go:455`.
- **Class 2:** the rollbacks and savepoint closes in `store/pgxstore`, `store/sqlstore`, `store/gormstore` and `internal/storekit/session_tx.go:81`.
- **Class 3:** `session/store_memory.go:156`, `expiry/sweep/sweeper.go:323`, `token/signingkey/keys_lifecycle.go:65`, `notify/queued.go:268`, `oidcprovider/backchannel.go:363,385`, `httpsec/signals_endpoint.go:168,186`, `httpsec/signals_bus.go:171`, `httpsec/fibersec/middleware.go:132`, `httpsec/fibersec/exchange.go:496`.
- Every other `context.Background()`, and the `context.WithoutCancel` at `oidcprovider/backchannel.go:729` and `authenticate/oidc/remote.go:326`, is the context of a log call, and starts no work (the 13.6 review's recheck, 2026-11-11).

Class 4 and class 5, with the lane that takes each class-4 site:

| Site | Callee | Class, bound | Lane | Today, on the callee's error |
|---|---|---|---|---|
| `authenticate/mfa/totp.go:279` | `RefundVerifyAttempt` (store) | 4, write | A | WARN log, carries on |
| `authenticate/mfa/throttle.go:216` | `Limiter.RecordFailure` | 5 | — | sampled ERROR log |
| `authenticate/passkey/register_pending.go:372` | `Limiter.RecordFailure` | 5 | — | ERROR log, refusal stands |
| `authenticate/passkey/manage.go:195` | `Sessions.DeleteByUserExcept` | 4, revocation | A | sampled ERROR log, change stands |
| `authenticate/passkey/clone.go:117` | `credentials.Find`; `credentials.Suspend` | 4, write; 4, revocation, each bounded | A | wrapped error; wrapped error matching `ErrCloneSuspected` |
| `authenticate/passkey/clone.go:183` | `Sessions.DeleteByUser` | 4, revocation | A | sampled ERROR log, refusal stands |
| `authenticate/passkey/clone.go:210` | `GrantRevoker.RevokeUserGrants` | 4, revocation | A | ERROR log and `GrantRevokeFailed` event |
| `authenticate/passkey/messages.go:152` | user loader; contact resolver; `Sender.Send` | 4, write, each; the send is class 1 | A | sampled ERROR log, change stands |
| `authenticate/passkey/webauthn/metadata.go:264` | the consumer's fetch | 4, `outbound.DefaultTimeout` | A2 | registration refused as attestation-refused |
| `session/reuse.go:511` | `SuccessorPresented` | 4, write | B | renewal refused (`storeFailed`) |
| `session/reuse.go:533` | `DeleteFamily` | 4, revocation | B | ERROR log, `ErrReused` joined with the store error |
| `session/end_observer.go:207` | `EndObserver.SignInsEnded` | 5 | — | panic recovered and logged |
| `recovery/recover.go:428`, `:717`; `recovery/codes.go:264`, `:317` | limiter calls | 5 | — | logged; refusal or carry on as today |
| `recovery/recover.go:578` | `mfa.Verify`; `Consume`; `codes.spend` | 4, write, each | B | `spendRefused` / `spendFailed` |
| `recovery/recover.go:602` | `spendMFA`; `RevokeUserGrants`; `spendCodes` | 4: revocation for the revoke, write for the rest | B | revoke: ERROR log, `ErrDependency` |
| `recovery/recover_complete.go:280` | record insert, hold start, `complete` (planner, `DeleteByUser`, `RevokeUserGrants`, codes, commit, notice) | 4: revocation for the two revocations, write for the rest | B | ERROR log and wrapped error; the grant revoke sets `GrantsNotRevoked`; the notice logs |
| `recovery/hold.go:406` | `records.Complete`; `consumeHoldToken`; `complete` | 4, write (revocations inside `complete` as above) | B | ERROR log and wrapped error; the token consume logs DEBUG |
| `recovery/hold.go:508` | `records.Cancel`; `consumeHoldToken`; user loader; notice | 4, write, each; the send is class 1 | B | logs, returns nothing |
| `ratelimit/guard.go:460`, `httpsec/throttle.go:355`, `httpsec/session_renewal.go:269`, `httpsec/mfa_enrol.go:722` | limiter calls | 5 | — | logged |
| `internal/eventsink/eventsink.go:77`, `oidcprovider/endsignin.go:181` | the event sink | 5 | — | panic recovered and logged |
| `httpsec/logout.go:165` | `Sessions.Logout` (`EndSignIn` is class 1) | 4, revocation | C | logout refused; `ErrNotFound` ignored |
| `httpsec/oidc_endsession.go:207` | `Sessions.Logout` | 4, revocation | C | refused |
| `httpsec/oidc_backchannel.go:115` | `DeleteByExternalSession`; `FindByExternal`; `DeleteByUser…` | 4: revocation for the deletes, write for the read | C | error returned to the provider |
| `httpsec/session.go:72` | `Sessions.Touch` | 4, write | C | DEBUG log, discarded |
| `httpsec/basic.go:225`, `httpsec/login.go:770` | `AttemptStore.RecordFailure` (the lockout store and sink run under it) | 4, write | C | ERROR log, outcome unchanged |
| `httpsec/mfa_enrol.go:838` | `VoidEmailCode` | 4, write | C | sampled ERROR log |
| `httpsec/mfa_enrol.go:905` | user loader; contact resolver; `Sender.Send` | 4, write, each; the send is class 1 | C | sampled ERROR log |
| `httpsec/password_change.go:331` | `AttemptStore.Reset`, per store | 4, write, each | C | ERROR log per store, carries on |
| `httpsec/rehash.go:63` | the consumer's `RehashFunc` | 4, write | C | ERROR log |

Settled by the main session on the agent's open points:
- **A notice's sender is class 1.** It owns its bound: the SMTP sender's timeout, or a queue that only enqueues. A 5-second cap would cut a synchronous SMTP notice short of its own timeout. The user loader and contact resolver before it are class 4 writes, each bounded.
- **`RehashFunc` is class 4.** It is a store-write port, not a reporting callback like the observers and the sink.
- **Session revocations are bounded at their call sites, not inside `session`.** `reportEnd` drops the deadline before the observers, so they stay class 5 whoever calls.
- **Calls inside a transaction the site opens are bounded as one unit**, with the bound of the transaction's strongest kind (a revocation inside it makes it 10 s). Bounding statements separately would let the transaction outlive a bound.
- **`recovery`'s first grant revocation without an MFA proof is not detached.** `revokeThenSpend` detaches only after it spends an MFA proof. With none, the revocation runs on the caller's own context, so a hang-up spends nothing, and the caller's deadline bounds it. It is outside every class. With an MFA proof it runs detached, bounded as a revocation (10 s).
- **The bound's expiry is an outage, not a hang-up.** A callee that picks its log level with `hangup.ByCaller` (for example `token/onetime`'s `Consume` and `Issue`) sees the bounded context. Its deadline has passed, and the store's error matches it, so the callee would log the library's own bound running out at DEBUG, as if the client had left. `detach.Bounded` therefore ends the context with an internal cause, and `hangup.ByCaller` reports false when that cause ended the context. A bound that runs out is logged at the callee's error level, the same as a store's own timeout. The maintainer chose this on 2026-11-11 over fixing `onetime` alone, which would leave every other such callee mislabelled, and over accepting DEBUG. A detached context's cancellation is never the client's (`WithoutCancel` drops it), so no real hang-up is relabelled.
- **Lane D has no class-4 site.** `policy/lockout` detaches nothing of its own: it runs under the context `httpsec/login.go:770` and `basic.go:225` detach, so lane C bounds it there. `oidcprovider/endsignin.go:181` is class 5, and `authenticate/oidc/remote.go:319` is class 1.

A consumer-supplied WebAuthn metadata fetch (`authenticate/passkey/webauthn/metadata.go`) runs detached under singleflight with no deadline. The built-in fetch is bounded by the outbound client's timeout, `outbound.DefaultTimeout` (10 s) unless the consumer configured another. The consumer's fetch now gets a context with a 10-second deadline, `outbound.DefaultTimeout`, and `MetadataBlob`'s godoc, which promises the fetch receives "not its cancellation or deadline", is corrected. A fetch that times out fails the registration as any metadata failure does: refused with the attestation-refused refusal, nothing stored.

- **Default:** 5 seconds per detached write, which two sites already use; 10 seconds per revocation, which `oidcprovider` already uses. Each is generous for one statement, and short enough that a hung store frees the request goroutine.
- **Override:** none in `v0.1.1`. An exported option is new API, and under Semantic Versioning a patch adds none (decision 8 ships a patch). `gorelease` does not enforce this for a `v0` base, so it is held by review, not by the gate. `library-design.md` rule 2 asks for the reason when a default cannot be replaced, and this is it. A consumer's own store or port can still impose a shorter bound of its own. An option to lengthen the bound is a candidate for the next minor. The main session proposed this on 2026-11-11, under the maintainer's instruction to fix #3 in this change, and the maintainer confirmed it the same day (task 13.1).

| Failure | State | Outcome |
|---|---|---|
| A store hangs on a detached call | Handled, tested | The call fails with `context.DeadlineExceeded` within the bound, and the site handles it as it handles that call's store error today. A test in each affected package asserts the deadline is present, and that the site's outcome for that error is unchanged |
| A slow store, over 5 s for one write (a row-lock wait under contention, for example) | Accepted, the stated line (`library-design.md` rule 4) | The write fails as a store error would, where before it completed late. A consumer who needs longer waits for the option in the next minor |
| A reuse-triggered family revocation slower than 10 s, under lock contention | Accepted, the stated line | The request is refused, as it is today on a store error, and the family stays live until the next presentation of a revoked member or the family's expiry. Before, the request waited without end |
| A slow limiter on a failed-attempt record | Handled (class 5) | Not bounded by the library, so the guess is charged as the spec requires. The limiter's own contract bounds it |
| A slow session end observer or event sink | Accepted, tested | Not bounded by the library. Their godoc tells the consumer to bound their own work (task 14.4). A test pins that their context carries no library deadline |
| The bound runs out inside a callee that classifies hang-ups (`token/onetime`, the recovery helpers) | Handled, tested | Logged at the callee's error level, not as a hang-up: `hangup.ByCaller` recognises the bound's own cause. A test in `hangup` and one in `onetime` pin it. The record still carries `internal/diag`'s `cancelled=true`, which says only that the error wraps a context's end, as it does: accepted |
| The client hangs up before or during the detached work | Handled, unchanged | It still runs, because it is detached, and now it has a bound |
| A site's cancel function is not called | Handled, tested by the lint | Each site defers it, or calls it as the bounded call returns (`passkey`, `session`, `mfa`), where a panicking callee leaves its timer to fire at the bound: harmless. `go vet`'s `lostcancel` check flags a missed one, and the lint runs it |
| A bounded call nests another (`recovery`'s `spendMFA` bounds `mfa.Verify`, which bounds its TOTP refund again) | Accepted | The inner bound starts when the inner call does, so that leg can take up to about twice the write bound. Each call still ends |
| A shared limiter reached under a bound (`internal/unavailable`, inside `recovery`'s bounded `mfa.Verify`) | Accepted | It classes any ended context as the caller leaving. Its own operation timeout (250 ms by default) fires long before the 5 s bound, unless a consumer configures it above 5 s, and then a bound that runs out is logged as a hang-up |
| A live path shares a helper with a detached one | Handled, tested | The bound goes on the detached path only: `httpsec`'s `boundedContactOf` beside `contactOf`, and passkey's likewise. The 13.6 review reproduced passkey's registration email code losing the caller's deadline when the shared helper was bounded (`TestFinishRegistration_EmailCodeContactKeepsCallersDeadline`) |
| The lockout observer under the chain's bound | Accepted, documented | The policy runs it on the context its caller passes. The chain's failure records and password-change resets bound that context at 5 s, so the observer shares that bound with the store write; a direct caller's context reaches it as given. Its godoc says so. Making it a class-5 callback with no deadline would also strip the cancellation of a direct `Reset` caller |
| The consumer's metadata fetch ignores its context | Accepted | Waiters still return on their own context, as today. The fetch's goroutine lasts as long as the consumer's code does |
| A class-2 rollback hangs | Accepted | As above: the driver and the pool bound the connection |
| The inventory misses a site | Handled | The task searches every `context.WithoutCancel` in production code, not the sweep's list alone. The review rechecks the search |
| A detached call keeps the request context's values, including an attached transaction | Accepted, unchanged from `v0.1.0` | As on `v0.1.0`. Decision 14 documents it for background starts, where it lasts longest |

### 13. A send the caller cancelled reports the caller's cancellation

The SMTP sender aborts a send when the caller's context ends, by forcing the connection deadline to now (`notify/smtp.go`). The send then fails with the network error from the interrupted read, which does not match `context.Canceled` or `context.DeadlineExceeded`. So a caller cannot tell its own hang-up from a broken mail server, and `Send` logs the failure at ERROR without consulting the library's hang-up classification (`internal/hangup`) at all. Reproduced: `TestSMTPSender_CancelMidTransferMatchesContextCanceled` fails with `got *diag.Fault: notify: the greeting from 127.0.0.1 failed`, alongside an `ERROR notify: smtp send failed` record. A throwaway fix that joins the context's error passes it.

When the exchange fails and the context `Send` received has ended, the send's error matches that context's error. That is the caller's context, not the one `send` derives with the sender's own deadline (`smtp.go:317`), which would make the sender's own timeout look like the caller's. A caller's deadline counts as passed when the clock has reached it, even if the context's timer has not fired yet, because the connection deadline and the context timer race. It is joined with the network error, which stays in the chain for diagnosis. A send that fails on the sender's own deadline, with the caller's context still live, keeps today's timeout error. A send the caller ended is logged at DEBUG, not ERROR, through the hang-up classification, as the rest of the library does.

- **Default and override:** on, with no override. This corrects what the existing requirement promises ("cancelling the caller's context SHALL abort a send").

| Failure | State | Outcome |
|---|---|---|
| The caller cancels mid-transfer | Handled, tested | The error matches `context.Canceled`, and there is no ERROR record |
| The caller's deadline passes mid-transfer | Handled, tested | The error matches `context.DeadlineExceeded` |
| The sender's own deadline passes while the caller's context is live | Handled, tested | Unchanged: the timeout error, logged as a failed send |
| The context ends after the server has accepted the message | Accepted | The send has succeeded, and returns nil |
| The caller cancels mid-dial | Handled, tested | The dial error is joined with the caller's, so it matches `context.Canceled`, logged at DEBUG |
| The server refuses (a 550 at `RCPT`, say) in the same instant the caller's context ends, or `Quit` fails after the server accepted `DATA` and the caller then cancelled | Accepted, UNREPRODUCED | The error also matches the context's error and is logged at DEBUG, as a hang-up. The window is the time between the server's reply and the check. Either outcome is already the caller's to own: they left. In the `Quit` case the message was delivered while the caller sees a cancelled send, as before this change, when `Quit`'s failure was already returned. A caller that retries may send twice. The 14.6 review found it; making it visible would need the reply's arrival time, which `net/smtp` does not expose |
| `callerHungUp` and `internal/detach`'s bound | Accepted, not reachable | `notify` keeps its own clock check, which does not know the detach bound's cause. No library path hands `Send` a bounded context (the recovery notice runs on the caller's context), and a consumer cannot make one |
| The queued sender, which detaches each message | Handled | Its per-delivery timeout (`queued.go:350`) is the context `SMTPSender.Send` receives, so a delivery that runs past it now matches `context.DeadlineExceeded` and `SMTPSender` logs it at DEBUG. The queue's own "delivery failed" record stays at ERROR, so an operator still sees it, and a test pins it. Nothing cancels a delivery already under way, as `QueuedSender.Shutdown`'s godoc says |

### 14. The remaining context hand-offs are documented or corrected

- **Background starts keep the start context's values (documented).** `expiry/sweep` `Start`, the signing-key lifecycle's `Start` and the memory session store's `Start` run their loops under `WithoutCancel` of the start context, for the life of the process. That is documented today. What is not documented is that a store transaction attached to that context goes with it. The godoc of each says to start from a context with no transaction attached. A `WithoutTx` helper would add API, so it is left to the next minor (Non-Goals). This is UNREPRODUCED as harm: a test showed the values reach the loop, and no shipped caller starts inside a transaction.
- **A context kept inside a context value (corrected).** `oidcprovider/events.go:128` routes a reuse event by putting a context inside another context's value. The value now holds what the event needs instead of a context. It is a refactor with no change in behaviour. The existing event tests cover it, and the task shows they would catch a broken route by breaking it temporarily.
- **`ginsec` leaves the chain's context on `c.Request` (documented).** gin has one `*http.Request` per `*gin.Context`. When the chain passed the request on, a gin middleware registered before the chain reads the chain's context after `c.Next()` returns; when the chain refused it before reaching the gin handlers, `c.Request` is unchanged, and when an interceptor refused it after `next` returned, `c.Request` keeps the chain's context (the whole-branch review reproduced this against an earlier wording that said every refusal leaves it unchanged). The `ginsec` godoc says so, as `fibersec`'s already does for its context.
- **`fibersec` logs a stream panic under `context.Background()` (corrected).** The record loses the request's values, such as a trace or request identifier, that a consumer's log handler reads. It now logs under `context.WithoutCancel` of the request's context. A test with a handler that reads a context value is red before the change.
- **`authenticate/password_upgrade.go` keeps the request context in a handle (accepted).** It is documented, and the handle is read after the call returns by design. Removing it breaks the published API.

| Failure | State | Outcome |
|---|---|---|
| A consumer starts a background manager inside a transaction | Accepted, documented | The godoc says not to. As before, the loop's store calls would join that transaction |
| The events refactor changes routing | Handled, tested | The existing event tests, shown to bite |
| A stream panic's log loses request values | Handled, tested | It carries them, and no cancellation |

## Open Questions

- **Refusing owed second-factor states on every chain.** The authorization stage refuses only challenges whose gate the chain registers (decision 3). A gateless chain run inside a gated chain's gates is now refused at publication (decision 2). What remains is a gateless chain mounted on its own, not inside a gated one, that shares the session store. The group 6 review leaned toward refusing the second-factor, enrolment and recovery states on every chain, failing closed even where that chain cannot satisfy them. That would close the remaining case. Left for the maintainer to decide, as a follow-up change with its own red test, not in this patch.

## Risks / Trade-offs

- **[A client that sends dot segments on purpose (for example a crawler's normaliser bug) now gets 400]** → No browser does this, and the 400 carries no detail. Recorded in the changelog.
- **[The gate mark makes a nested-chain design fail with 500 on its first request]** → It fails closed and visibly. The error names the slots to use.
- **[The fold rewrite changes a hot path every request takes]** → The conformance suite runs on all three adapters, with a benchmark comparison, and the Opus reviewer checks ordering, re-entry and the terminal lookup specifically.
- **[The fix is public before `v0.1.1` is tagged]** → Accepted: no consumer runs scrty in production (decision 8). The tag follows the merge as soon as CI on `main` is green.
- **[`govulncheck` never flags `v0.1.0`]** → Accepted (decision 8). The retraction and the changelog are the only signals.
- **[Decisions 11–14 widen a security patch to packages outside `httpsec`]** → The maintainer chose this on 2026-11-11. Each package's change has its own red test and a fresh reviewer, and the whole gate (task 10.15) runs after them.
- **[A 5-second bound on detached writes, or 10 seconds on revocations, fails a write that used to succeed slowly]** → Accepted (decision 12). The failure takes the path that site already takes for a store error.
- **[The release-probe fix in `release-readiness` has not landed when `v0.1.1` is tagged]** → Task 1.1 checks that it is on `main` before the branch is cut, and task 9.2 checks again before tagging.

## Migration Plan

1. A consumer upgrades all scrty modules to `v0.1.1`.
2. A chain that gives one of the five options twice fails construction with an error naming the option. The consumer removes the duplicate.
3. A consumer authenticator registered after the gates now gets 500 on publishing. The consumer moves it to `OrderBearerToken`.
4. Code that reads an exchange's context, session or authentication after the chain's step returns (a consumer's own adapter) reads them inside the terminal instead (decision 11).
5. A store that takes longer than 5 seconds on one detached write now sees that write fail as a store error (decision 12).
6. **Rollback:** pin `v0.1.0`. That reintroduces the defects, and `go` warns because the version is retracted.

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
- [Spring Security, Authorize HttpServletRequests](https://docs.spring.io/spring-security/reference/servlet/authorization/authorize-http-requests.html): the authorization filter runs on every dispatch, `FORWARD` included, and the security context established on the request dispatch carries over. Supports decision 2's gate-set rule: a forward is judged by the chain it goes through.
- [Spring Security, `HttpFirewall`](https://docs.spring.io/spring-security/reference/servlet/exploits/firewall.html): established practice is to reject un-normalised paths by default. The page does not say how that rejection is ordered against forwarded-header handling, so that point is unverified.

### Decision 9: header algorithm and dependencies

**Researched** (2026-11-10):
- [lestrrat-go/jwx v4.6.0 release notes](https://github.com/lestrrat-go/jwx/releases/tag/v4.6.0): #2422 retries a missing `alg` through `jws.Verify`; NumericDate parsing changes (#2368, #2369, #2409, #2411, #2413). The module declares `go 1.26.10`, below scrty's floor.
- [testcontainers-go v0.45.0 release notes](https://github.com/testcontainers/testcontainers-go/releases/tag/v0.45.0): the breaking changes move client SDK adapters into separate examples modules.
- [OSV API](https://api.osv.dev/v1/query), queried for both modules: no known vulnerabilities (live figure; drifts).
- `github/codeql-action` tag `v4.39.3` resolves to commit `33d7b85da1a04171e211befe2c739303b9a4c066` (GitHub API).

**Primary documentation:**
- [RFC 7515 §4.1.1](https://www.rfc-editor.org/rfc/rfc7515#section-4.1.1): the `alg` header parameter is required.
- [RFC 8725 §3.1](https://www.rfc-editor.org/rfc/rfc8725#section-3.1): verifiers perform algorithm verification.

### Decisions 11–14: context hand-offs

**Primary documentation:**
- [Go `context` package](https://pkg.go.dev/context): a context is passed explicitly and not stored in a struct; `WithoutCancel` returns a context with no deadline and no cancellation, so a bound must be added by the caller. Supports decisions 11 and 12.
- [Go blog, "Contexts and structs"](https://go.dev/blog/context-and-structs): a context stored in a struct outlives the call it belongs to. Supports decision 11's scoping and decision 14's events refactor.
- [`net/http` `Request.WithContext`](https://pkg.go.dev/net/http#Request.WithContext): middleware hands a shallow copy carrying the derived context to the next handler, and the caller's request is unchanged. Supports decision 11.

Otherwise reasoned from scrty's own settled specs (`http-security-chain`, `security-state-stores`, `email-notification`, `passkey-authentication`) and the 2026-11-11 sweep of every package. The researched comparison of options A and B was given to the maintainer in conversation on 2026-11-11. These are cited as standard references and were not re-checked when written down.

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
| A gated chain inside a gateless chain serves an owing session | `TestChain_GatedChainInsideGatelessChainServesOwingSession` (`repro/httpsec_nested_chains_repro_test.go.txt`) | `go test -run 'TestChain_GatedChainInsideGatelessChainServesOwingSession|TestChain_CoveringChainOnSharedExchangePublishes' -count=1 ./httpsec/` on `fbf89b6c` | `Should not be: 200 … the MFA-gated chain served its handler a session owing a second factor (authenticated=true, MFA=true)`. Fixed by decision 3's session helper |
| A covering chain on the same exchange is refused | `TestChain_CoveringChainOnSharedExchangePublishes` (same file) | same | `a session was published after the chain's gates had begun`; green with the own-exchange check removed. Fixed by decision 2's mark owner |
| The first cross-chain check refuses a handler's in-process forward through a gated chain | `TestReauthResolve/a_re-proof_racing_a_renewal_of_its_session_is_a_renewal_conflict_and_the_renewal's_session_stands` (existing), and a throwaway same-chain forward test during task 10.2 | `go test ./httpsec/... -count=1 -race` on the task 10.2 tree | `a session was published by a chain run inside another chain's gates`; the forward test `expected: 204 actual: 500`. On `fcec3a8f` both passed. Fixed by decision 2's gate-set condition |

The 10.14 review and the 2026-11-11 context sweep added these:

| Claim | Test | Command | Red output |
|---|---|---|---|
| A gateless chain's built-in publishes inside the outer chain's gates on a shared exchange whose context was replaced | `TestChain_GatelessBuiltInOnSharedExchangeWithReplacedContextPublishes` (`repro/httpsec_shared_exchange_repro_test.go.txt`) | `go test -run '…' -count=1 ./httpsec/` on `6d971f67` | The built-in publishes and the handler runs. Fixed by decision 2's own-exchange check in the built-in path (task 10.16) |
| A chain run leaks its context up to the caller's exchange, growing on reuse | `TestChain_RunPutsBackTheContextItFound` (task 12.1's red step), and `BenchmarkAssemble/run/8` | `go test -run TestChain_RunPutsBackTheContextItFound -count=1 ./httpsec/` | 7 cases fail: the context after the run is not the one before it, and the layer count reads `[0 1 2 3]` over four runs. The benchmark goes from 27 µs to 1 ms per run over 16,000 runs. Fixed by decision 11 |
| A detached failure record has no deadline | `TestVerifyThrottle_DetachedRecordCarriesDeadline` (`repro/mfa_detached_bound_repro_test.go.txt`) | `go test -run '…' -count=1 ./authenticate/mfa/` in a disposable worktree of `6d971f67` | `detached write got no deadline (cancelled=false): a hung limiter blocks the caller forever`. Resolved by decision 12's class 5: a limiter call is bounded by the port's own contract, not by the library, so this case is not changed |
| A cancelled SMTP send does not match `context.Canceled` | `TestSMTPSender_CancelMidTransferMatchesContextCanceled` (`repro/notify_cancel_repro_test.go.txt`) | `go test -run '…' -count=1 ./notify/` in a disposable worktree of `6d971f67` | `got *diag.Fault: notify: the greeting from 127.0.0.1 failed`, with an `ERROR notify: smtp send failed` record. A throwaway fix that joins the context's error passes it. Fixed by decision 13 |

The upper-case fiber case is not closed by decision 1. It is accepted as the consumer's to match (decision 7), so it is left out of the carried-forward test rather than kept as a test that can never pass. `TestRepro_NilOption` and `TestRepro_SameSlotOrderDependsOnOptionOrder` assert behaviour that is documented and stays. They are not carried forward as red steps.
