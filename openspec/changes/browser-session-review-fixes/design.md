## Context

`browser-session`, `browser-session-hardening` and `browser-session-coverage` are on the PR #160
branch. A code review (`/code-review high`) and a security review of the whole branch found the six
faults this change fixes:

- one important: the CSRF fail-open;
- four smaller: the write-once mark, quoting, prefix case, the role-switch race;
- one defense-in-depth: continuation of a bound session.

None of the six is yet proven by a failing test. Each is a defect claim labelled UNREPRODUCED
until its first task's red step shows it, as `defect-claims.md` requires. If a red step passes
instead, the claim was wrong: that fix is dropped and the user is told.

## Goals / Non-Goals

**Goals:**
- Each finding is reproduced by a failing test, then fixed, and the test passes.
- Every guarantee the cookie session states holds whatever shape a consumer's port returns, and
  whatever goroutine a consumer calls from.

**Non-Goals:**
- Detecting a response that a handler has already begun before it switches roles. The godoc
  already states this misuse and what it costs: the cookie is dropped and the old one becomes
  reuse after the window. It is a separate question from the end-of-run race and stays accepted
  (see Failure modes).
- Changing what a cookie chain does with DPoP proofs on unbound sessions.

## Decisions

### 1. A CSRF refusal never becomes an admission

`csrfAnswer` keeps the token source's non-verdict causes, such as a store outage, so they surface
as what they are. Before this change, a nil entry of an `Unwrap() []error` was taken for a cause:
`errors.Join(nil)` is nil, so the refusal turned into no error. A typed-nil child was unwrapped
through its pointer receiver, which panics.

- **Decision:**
  - `csrfAnswer` walks the token source's error tree once, through `internal/errwalk`. That
    walk is budgeted, cycle-safe and typed-nil-safe, and it recovers panics. Nodes are
    classified by type alone (wrappers, leaves, the sentinel), so no consumer `Is` or `Unwrap`
    method runs outside errwalk's recover.
  - Any abort (a panic, a cycle, errwalk's budget) and a tree longer than the CSRF walk budget
    are logged and answered as a cross-site refusal.
  - When no cause remains, the answer is `ErrCrossSiteRequest`.
  - Consequence: a wrapper whose `Unwrap` returns nothing, beside the sentinel, is not a cause.
    The answer is a cross-site refusal, not a dependency failure. Telling it apart would need a
    second call to its `Unwrap`, and refusal is the safe outcome.
  - Over HTTP, `CheckCSRFToken`'s `porterr.SanitizeTo` walks the tree first. A tree it cannot
    walk (a panicking `Unwrap`, a cycle, errwalk's budget) therefore reaches the client as a
    dependency failure. It is never an admission. `csrfAnswer`'s own abort branches guard
    callers that skip the sanitizer.
- **Default:** a refusal of any shape is a cross-site refusal (`403`), not charged, with the cookie
  left in place.
- **Override:** none. The consumer's `CSRFTokens` port stays replaceable. What it cannot do is
  turn its own refusal into an admission, since that would break the CSRF guarantee
  (`library-design.md` point 4).

### 2. `MFAAtFirstFactor` comes from the stored record at every rotation

Strict rotation (`sessions.go`) and the caller-built successor (`reuse.go`, `successorFromCaller`)
both pin `PersistentCookie` and `FirstFactor` to the stored record. They take `MFAAtFirstFactor`
from the copy, although its godoc calls it write-once.

- **Decision:** pin it to the stored record at both places. Plain grace rotations already build
  from the stored record. The godoc of `Session.MFAAtFirstFactor`, of `Rotate` and of the store's
  rotation contract is reworded to say the mark is the stored record's.
- **Default:** the mark follows the sign-in's creating write.
- **Override:** none. The mark records how the sign-in was created, and only the creating option
  (`WithSecondFactorAtLogin`) sets it.
- **Compatibility:** a caller that changed the mark on its copy and rotated had its change stored
  before. It is now ignored. This is a behaviour change to `Rotate`, which predates this branch.
  The CHANGELOG lists it under Fixed.

### 3. `sameCookie` compares `Quoted`

The delivery check refuses a cookie whose written attributes differ from the chain's. `Quoted`
changes the bytes `net/http` writes, so it is one of those attributes.

- **Decision:** add `Quoted` to the comparison. A quoted cookie is refused as an altered cookie,
  so the sign-in fails as an issuing failure and is ended, as for any other altered attribute.
- **Default / override:** unchanged. `SessionDelivery` stays replaceable within its stated bounds.

### 4. Cookie name prefixes are accepted only in canonical spelling (departure, user decision 2026-11-28)

`browser-session-hardening` decision 5 matched the prefixes case-insensitively, as `checkAttributes`
already did. Research (References) shows:

- the current drafts and Chromium match prefixes case-insensitively;
- Firefox did so only from 126 (CVE-2024-5699);
- an earlier draft, and the clients that implemented it, matched case-sensitively;
- Safari is unverified.

So a name such as `__host-sid` passes `New`, but some browsers store it as an ordinary cookie that
another origin can overwrite. The user asked for the choice that is secure and complies with
standards, regardless of the prior decision.

- **Decision:** accept only `__Host-` and `__Secure-` exactly. A name that starts with either one
  in any other letter case is a configuration error from `New` that names the canonical spelling.
  The canonical spelling is protected by every user agent that knows prefixes, whichever way it
  matches.
- **Default:** `__Host-scrty-session`, unchanged.
- **Override:** any valid `__Host-` name, or a `__Secure-` name with a Domain, as before.
- **Compatibility:** the cookie session is unreleased (`[Unreleased]`), so no released consumer
  breaks. The CHANGELOG entry for the `__Host-` rule is reworded.

### 5. The handler's return and a role switch exclude each other (revised 2026-11-28)

`rotateForSwitch` reads `run.done` before it takes the role source's lock, so nothing stops the run
from ending while the rotation and the cookie write proceed.

The first decision put a lock around the run's final step. Lane D's review showed that is not
enough. A switch on another goroutine still races every interceptor's code that runs after the
handler returns. The reviewer reproduced three race-detector reports: a concurrent write to the
response's header map, which crashes a real `net/http` server, and races on `ex.Session` and the
request context. The user chose to close it at the handler's return.

- **Decision (as built):**
  - One guard per request, held by the exchange (`Exchange.roleSwitch`). It is a cancellable
    one-slot lock with a "handler returned" mark that is only read and written under it.
  - Every handler return on the exchange sets the mark under the lock, and entering a handler
    clears it. A run whose handler never ran sets its end under the lock.
  - `SwitchActiveRole` takes the guard at its start (`holdRun`) when it rotates a cookie session,
    honouring its context. It then takes the role source's lock, checks the mark and the run's
    end, and holds the guard through the user reload, the rotation and the cookie write.
  - A switch that finds the mark or the end set is refused with `ErrConfig`, and stores nothing.
  - Every write the switch makes (the session store, `ex.Session`, the context, the response
    headers) therefore happens before any chain's code after `next` reads or writes them.
- **Waiting is cancellable:** a switch waiting for the guard gives up when its context ends, with
  that context's error, and stores nothing. A handler's return always waits.
- **Bound:** a switch holding the guard is bounded by the user loader's and the store's own
  timeouts and by the context the caller gave. Under `net/http` the request context is cancelled
  only after the handler chain returns, so it bounds nothing here. The godoc of `SwitchActiveRole`
  says so.
- **Lock order:** the guard, then the role source's lock. The chain's own steps take only the
  guard. A switch called on the handler's own goroutine completes before the handler returns.
- **Sharing:** chains nested as handlers share the exchange's guard. An exchange a chain builds on
  its own inside a guarded run inherits it, so adapter mounts and chains a handler runs on other
  goroutines are covered. Only the exchange that owns the guard clears the mark when its handler is
  entered. An inheriting exchange waits and sets it, but never clears it. A detached copy (a `SessionDelivery`'s) carries none, and nothing built
  from its context inherits one.
- **Cost:** only a chain that rotates on a role switch creates the guard. Every other request
  pays nothing.
- **Default / override:** no override. This is a correctness guarantee of `SwitchActiveRole`.
- **As implemented (lane D):**
  - **Where the lock is taken:** at the start of `SwitchActiveRole`, when it rotates a cookie
    session, before anything takes the role source's lock. `rotateForSwitch` was too late: a
    queued switch blocks earlier, on the role source's lock, which the first switch holds through
    its rotation. As a result, the switch's user reload also runs under the run's lock, and the
    handler's return can wait for the user loader as well. The godoc names the user loader's and
    the store's own timeouts as the bound.
  - **A second pass through the handler:** an interceptor that calls `next` twice runs the
    handler again. Entering the handler clears the mark under the lock, so a switch inside the
    second pass is not refused. A test row pins this.
  - **Marking the right run:** each handler entry on the exchange records its run, so the
    handler's return marks that run even if an interceptor replaced the context.
  - **Cost:** one small channel per run, which is one allocation.
  - **Revised after review:**
    - **One lock and one mark per request, not per run.** With a run per chain, a chain whose
      handler is another chain left the inner chain's code after `next` racing a goroutine
      switch. The reviewer reproduced 4 race-detector reports. The mark is therefore the
      exchange's: it is set when the innermost handler, the consumer's own, returns, and cleared
      when a handler is entered again. A switch is refused once it is set, so every chain's code
      after `next` follows the switch.
    - **Paid only where needed.** The lock exists only on a request on which a chain that can
      switch roles with a cookie-session rotation is running. Every other request pays nothing.
      The review measured one allocation and +4% per request on the chain benchmark when every
      request paid.
    - **Cost as measured:** chains without such switching match the pre-change benchmarks
      exactly (`BenchmarkChainRequest/0`: 25 allocs, 6388 B). A chain that rotates on a role
      switch pays 2 allocations, 128 B and about 56 ns per request.
    - **Consequence:** a handler that runs another chain on its own exchange, and then switches,
      is refused. Every handler return on the exchange sets the mark, and that case cannot be
      told apart from a chain nested as a handler. Refusing is the safe outcome.
- **Trade-off:** a switch an interceptor makes after `next` returns is refused with `ErrConfig`.
  The response's cookie can no longer be relied on there anyway, and no built-in interceptor
  switches roles.

### 6. A key-bound session is refused at continuation on a cookie chain

`credentialDelivery.continuingProof` returns nil on a cookie chain, so no proof is judged. That is
right for the unbound sessions a cookie chain creates. A bound session published by a consumer's
own authenticator would continue there with no proof at all.

- **Decision:** on a cookie chain, a session with a key binding is refused with
  `ErrAuthenticationRequired` before anything is spent. This matches the cookie interceptor's own
  refusal of a bound session (`errBoundSessionInCookie`). No proof or certificate is read.
- **Default:** refused.
- **Override:** none on a cookie chain. A consumer that needs bound sessions runs them on a token
  chain, where proofs are judged.

## Failure modes

| Failure | Category | State | Outcome a caller sees |
|---|---|---|---|
| Token source refusal with a nil entry in its error tree | Input (port), security | Tested (1) | `403` cross-site, not charged, cookie kept |
| Token source refusal with a typed-nil entry | Input (port) | Tested (1) | `403` cross-site, no panic |
| Token source refusal joined to an outage | Dependencies | Tested (1, existing) | the dependency failure, as before |
| Token source refusal whose `Is` panics | Input (port) | Tested (1) | `403` cross-site, not charged, cookie kept; the abort is logged |
| Token source refusal with a panicking `Unwrap`, a cycle, or past errwalk's budget | Input (port) | Tested (1) | over HTTP the sanitizer answers a dependency failure first; never an admission. Called directly, `csrfAnswer` answers `403` cross-site and logs the abort |
| Token source refusal tree longer than the CSRF walk budget | Input (port) | Tested (1) | `403` cross-site, not charged, cookie kept; the abort is logged |
| A wrapper whose own `Is` claims the sentinel | Input (port) | Tested (1) | over nothing: `403` cross-site; over an outage: the outage |
| A wrapper that wraps nothing, beside the sentinel | Input (port) | Tested (1) | `403` cross-site, not a dependency failure |
| The consumer's error, returned as an outage, is walked again by later `errors.Is` calls with no recover | Input (port) | Accepted (1) | predates this branch and is narrowed by it; a panicking `Is` is porterr's documented limit, recovered per request by `net/http`. The outcome is never an admission |
| Copy sets or clears `MFAAtFirstFactor`, then rotates | State | Tested (2) | successor carries the stored mark |
| Delivery quotes the cookie value | Configuration (port) | Tested (3) | issuing failure, sign-in ended, no cookie |
| Cookie name with a prefix in another case | Configuration | Tested (4) | configuration error from `New` naming the canonical spelling |
| Switch after the handler returned | Concurrency | Tested (5) | `ErrConfig`, nothing stored |
| Handler returns while a switch is in progress | Concurrency | Tested (5) | the return waits for the switch; the cookie is on the response; interceptors after `next` see the successor, with no data race |
| A chain mounted on its own exchange inside the switching chain (an adapter mount) | Concurrency | Tested (5) | its exchange inherits the guard; its code after `next` follows the switch |
| A `SessionDelivery` runs a chain on its detached copy during a switch | Concurrency | Tested (5) | the copy carries no guard and inherits none; no deadlock, later switches still allowed |
| The handler runs chains on its own goroutines, on exchanges built from the request's context | Concurrency | Tested (5) | they share the guard: their return waits for a switch in progress, and a later switch on the main request is refused |
| A chain on an exchange that inherited the guard enters its handler after the main handler returned | Concurrency | Tested (5) | it does not clear the mark; only the exchange that owns the guard does. A switch from the main request's code after `next` stays refused. An inherited exchange's second pass through its handler therefore cannot switch (accepted: the safe direction) |
| A `SessionDelivery` runs a chain on an exchange built from its copy's context | Concurrency | Tested (5) | that exchange inherits no guard; no deadlock |
| A handler runs another chain on its own exchange, then switches | Concurrency | Accepted (5) | `ErrConfig`, nothing stored |
| An interceptor calls `next` twice, and the handler's second pass switches | Concurrency | Tested (5) | the switch is made |
| A `SessionDelivery` calls `SwitchActiveRole` (forbidden by the godoc) | Configuration (port) | Accepted (5) | the inner switch waits until its context ends, returns that error and stores nothing; the outer switch completes |
| Interceptor code after `next` races a goroutine switch, on this chain or on a chain nested inside it | Concurrency | Tested (5) | impossible: the switch finished first or was refused |
| A queued switch whose context is cancelled | Concurrency, time | Tested (5) | it gives up with the context's error and stores nothing |
| Switch blocked on a slow store holds the handler's return | Concurrency, time | Accepted (5) | bounded by the store's own timeouts and the switch's context, not by the request context; documented in the godoc |
| Switch after the handler began its response | Concurrency | Accepted (non-goal) | the godoc's stated outcome: the cookie is dropped and the old one becomes reuse after the window |
| Bound session continued on a cookie chain, with or without a valid proof | Security | Tested (6) | `401`, nothing spent or rotated |
| Unbound session continued on a cookie chain with a DPoP header | Security | Tested (6) | proceeds as before; no proof is read |
| A red step passes on the unmodified code | Any | Handled | that fix is dropped and the user is told |

## Risks / Trade-offs

- [The switch lock adds cost to requests] → it exists only on requests through a chain that rotates
  on a role switch, and was measured (decision 5). Other chains pay nothing.
- [Canonical-only prefixes break a consumer who chose `__host-`] → nothing is released, and the
  error names the fix.
- [Pinning `MFAAtFirstFactor` changes `Rotate`, which is released] → only a caller that edited a
  library-owned mark on its copy notices. The godoc already called that mark write-once.

## Migration Plan

None. No schema or dependency change. The two behaviour changes are listed in the CHANGELOG.

## Open Questions

None. Decisions 4 and 5 were put to the user on 2026-11-28.

## References

**Researched (2026-11-28), decision 4:**
- [draft-ietf-httpbis-rfc6265bis-12](https://www.ietf.org/archive/id/draft-ietf-httpbis-rfc6265bis-12.html): user agents match cookie name prefixes case-insensitively.
- [httpwg/http-extensions issue 2605](https://github.com/httpwg/http-extensions/issues/2605): discussion of the move to case-insensitive matching.
- [Mozilla bug 1891349 (CVE-2024-5699)](https://bugzilla.mozilla.org/show_bug.cgi?id=1891349): Firefox matched case-sensitively until 126.
- [curl issue 4864](https://curl.haxx.se/bug/?i=4864): an earlier draft specified a case-sensitive match, and a client implemented it. Safari's current behaviour is unverified.

Decisions 1, 2, 3, 5 and 6 are reasoned from scrty's own settled specs and the established design.
