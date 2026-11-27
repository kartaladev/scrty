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
as what they are. Today `otherCauses` returns a nil entry of an `Unwrap() []error` as a leaf.
`errors.Join(nil)` is nil, so the refusal turns into no error. A typed-nil child is unwrapped
through its pointer receiver, which panics.

- **Decision:**
  - `otherCauses` skips nil entries and typed-nil values. A typed nil is a pointer kind whose
    pointer is nil, the same rule `internal/errwalk` applies.
  - `csrfAnswer` returns `ErrCrossSiteRequest` whenever the joined remainder is nil. The fallback
    holds even if a future walk returns something unexpected.
  - After lane A's review, the tree is walked once through `internal/errwalk`, so no consumer
    `Is` or `Unwrap` method is called outside its recover. Any abort (a panic, a cycle, the
    budget) is reported and answered as a cross-site refusal.
  - Consequence: a wrapper whose `Unwrap` returns nothing, beside the sentinel, is not a cause.
    The answer is a cross-site refusal, not a dependency failure. Telling it apart would need a
    second call to its `Unwrap`, and refusal is the safe outcome.
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

- **Decision:**
  - The run gets a lock and a "handler returned" mark. The innermost step of the run
    (`runTerminal`), once the terminal handler returns, takes the lock, sets the mark and
    releases it, before any interceptor's code after `next` runs.
  - `rotateForSwitch` takes the run's lock, then the role source's lock, and checks the mark under
    it. It holds the run's lock through the rotation and the cookie write.
  - A switch that finds the mark set is refused with `ErrConfig`, and stores nothing.
  - Every write the switch makes (the session store, `ex.Session`, the context, the response
    headers) therefore happens before the interceptors' code after `next` reads or writes them.
  - The run's own end keeps its existing `done` mark. A run whose terminal never runs, because an
    interceptor answered first, is marked at its end, as before.
- **Waiting is cancellable:** a switch waiting for the run's lock gives up when its context ends,
  with that context's error, and stores nothing. The lock is a one-slot channel rather than a
  `sync.Mutex`. The handler's return always waits.
- **Bound:** once a switch holds the lock, its rotation is bounded by the store's own timeouts and
  the context the caller gave. Under `net/http` the request context is cancelled only after the
  handler chain returns, so it does not bound the rotation the handler's return waits for. The
  godoc of `SwitchActiveRole` says so.
- **Lock order:** the run's lock, then the role source's. The handler's return takes only the
  run's lock. A switch called on the handler's own goroutine completes before the handler returns,
  so it never waits on that return.
- **Cost:** one uncontended lock and unlock per run, on every chain.
- **Default / override:** no override. This is a correctness guarantee of `SwitchActiveRole`.
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
| Copy sets or clears `MFAAtFirstFactor`, then rotates | State | Tested (2) | successor carries the stored mark |
| Delivery quotes the cookie value | Configuration (port) | Tested (3) | issuing failure, sign-in ended, no cookie |
| Cookie name with a prefix in another case | Configuration | Tested (4) | configuration error from `New` naming the canonical spelling |
| Switch after the handler returned | Concurrency | Tested (5) | `ErrConfig`, nothing stored |
| Handler returns while a switch is in progress | Concurrency | Tested (5) | the return waits for the switch; the cookie is on the response; interceptors after `next` see the successor, with no data race |
| Interceptor code after `next` races a goroutine switch | Concurrency | Tested (5) | impossible: the switch finished first or was refused |
| A queued switch whose context is cancelled | Concurrency, time | Tested (5) | it gives up with the context's error and stores nothing |
| Switch blocked on a slow store holds the handler's return | Concurrency, time | Accepted (5) | bounded by the store's own timeouts and the switch's context, not by the request context; documented in the godoc |
| Switch after the handler began its response | Concurrency | Accepted (non-goal) | the godoc's stated outcome: the cookie is dropped and the old one becomes reuse after the window |
| Bound session continued on a cookie chain | Security | Tested (6) | `401`, nothing spent or rotated |
| A red step passes on the unmodified code | Any | Handled | that fix is dropped and the user is told |

## Risks / Trade-offs

- [The run's mutex adds a lock to every request] → it is uncontended unless a switch is in
  progress. A benchmark is not required. If the review asks for one, the chain's existing
  benchmarks are run before and after.
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
