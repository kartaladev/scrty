## Context

See `proposal.md` for the motivation. This section covers only the state of the tree the design builds on.

- **Session records.**
  - The durable stores (`sqlstore`, `pgx`, `gorm`) key a session by `id_digest`, the SHA-256 of its identifier, under a separate `uuid` row id. The identifier itself is never stored, which is the `security-state-stores` requirement "Session identifiers are never stored".
  - The default in-memory store keys by the raw identifier, inside one process.
  - No session store exists outside those four.
- **Activity.**
  - `Manager.Touch` sets `LastAccessedAt` and the idle deadline, capped at the absolute deadline, then calls `Store.Save`, which replaces every field of the record.
  - The chain's activity interceptor calls it after every request that resolved a session, refusals included, detached from the request's cancellation, and logs a failure at debug.
- **Rotation.**
  - `Manager.Rotate` loads the session, creates a clone under a new identifier, then deletes the old one.
  - A per-identifier lock serialises it within one process only, and its godoc says so.
  - Its one caller is second-factor verification.
- **Lifetime.**
  - The absolute deadline is creation time plus the manager's `WithAbsoluteTimeout`, 12 h by default. `CreateOption` is `func(*Session)` and runs after both deadlines are set.
  - `RestoreEnrolmentDeadlines` recomputes the absolute deadline from `CreatedAt + absoluteTimeout`, capped by the confinement marker.
- **Bearer.**
  - The bearer interceptor verifies a signed token, loads the session by the token's `jti`, and reloads the user by username (the `sub`).
  - It publishes the session through the unexported `withSession`, then runs the unexported per-request phase with challenge marking.
  - Every login endpoint mints its credential with `token.Generator.Generate(ctx, s.ID, principal)`.
- **Users.** `identity.UserLoader.LoadByUserID` exists and is the documented way to resolve a recorded reference.
- **Adapters.** `ginsec` and `fibersec` wrap the same `httpsec` chain, so a new chain mode reaches them without adapter changes.
- **The established design.** It has no throttled activity write, no grace window, no reuse detection, no per-session lifetime and no opaque bearer. None of the decisions below departs from it. Each adds behaviour it did not have.

## Goals / Non-Goals

**Goals:**

- Every default stays what it is today:
  - a write on every request;
  - one absolute timeout;
  - the signed-token bearer;
  - rotation without grace at second-factor verification.
- Each new behaviour is opt-in and validated at construction.
- Reuse detection holds across replicas sharing one store, by store-side conditional writes rather than process locks.
- The opaque bearer and the cookie mode planned in `bff-resource-server` run the same resolution steps, from one implementation.

**Non-Goals:**

- Cookie handling, cookie `Max-Age` policy and CSRF: these belong to `bff-resource-server`.
- A general security-events port for login, logout and revocation. Only reuse gets a hook here.
- Releases and tags: these belong to `release-readiness`.
- Trusted-proxy client addresses: these belong to `trusted-proxy-client-ip`.
- Password hashing concurrency and strength policy: these are separate later changes.
- Sender-constrained tokens (DPoP, mTLS).

## Decisions

### 1. Activity writes coalesce on an interval, and a skipped write only brings expiry earlier

- **The option.** `session.WithTouchInterval(d)` is a `ManagerOption`.
- **Skipping.** With d > 0, `Touch` skips the store when `now - s.LastAccessedAt < d`, judged on the in-memory value the request loaded.
- **The write.**
  - Otherwise it writes, and the store applies the write only if the stored `last_accessed_at` is not later than `now - d`, so a write exactly one interval after the last one is applied, as the manager intends (an off-by-one between a strict store comparison and the manager's rule was found in review). A replica that lost the race writes nothing and is not an error.
  - The idle deadline written is `now + idleTimeout`, capped at the absolute deadline, as today.
- **Why this direction is safe.**
  - A skipped write leaves the stored idle deadline at most d earlier than the exact one, never later. A session can be ended up to d early, and is never kept alive past its exact idle deadline.
  - NIST SP 800-63B-4 §5.2 requires activity to reset the inactivity timeout. A reset that is at most d stale, with d well below the idle timeout, meets that, and the godoc states the bound.
  - The alternative, extending the deadline by d to hide the staleness, would keep a session alive past the configured idle timeout, so it is rejected.
- **Default:** 0, a write on every request, exactly today's behaviour.
- **Override:** the option.
- **Limit:** d below 0, or at or above the idle timeout, is a configuration error from `NewManager`. An interval that large would let a session in constant use expire mid-use.
- **Alternatives considered:**
  - A write when more than half the window has passed, the sliding-renewal rule some cookie middleware uses. It ties the bound to the idle timeout, so an operator cannot reason about it separately.
  - A write-behind buffer flushed asynchronously. It loses activity on a crash and adds a goroutine with a lifecycle.

### 2. Activity is recorded by a narrow, conditional store write

- **The port.** The `session.Store` port gains a method that writes only `last_accessed_at` and `idle_expires_at` for one identifier. It takes the threshold from decision 1, and does nothing when the stored record is fresher or superseded (decision 5).
- **Its contract.**
  - It returns the not-found error only when the record is absent.
  - It never inserts.
  - It never touches any other field.
- **Why narrow.**
  - Today the activity interceptor saves the whole record after the handler returns. It writes back the copy the request loaded, so it can overwrite a change another request made to the same session in the meantime. One example is the enrolment-only state's lowered deadlines.
  - That lost update is reproduced (see "Defect claims"). The narrow write removes it, and is also the only form in which decision 1's conditional write can be expressed.
- **Default:** used by `Touch` whatever the interval.
- **Override:** a consumer-written store implements the method. There is no option to fall back to a full save: it would reintroduce the race this decision closes.
- **Alternatives considered:**
  - Keep `Save` and add an optimistic version column to every record. It is a larger schema change, and every save would gain a conflict path for a field that is only bookkeeping.

### 3. A session's absolute lifetime can be chosen at creation, up to a manager maximum

- **The options.**
  - `session.WithAbsoluteLifetime(d)` is a `CreateOption`. It sets the absolute deadline to `CreatedAt + d`, and `Create` then caps the idle deadline at it.
  - `session.WithMaxAbsoluteLifetime(max)` is a `ManagerOption` that bounds d.
- **Refusal.**
  - `Create` refuses d ≤ 0 or d > max with a configuration error and stores nothing. It never shortens the lifetime silently (library-design rule 4).
  - The value comes from the consumer's wiring (for example, "remember" maps to 30 days), so an out-of-range value is a wiring mistake.
  - `Create` judges the lifetime the options produced, `AbsoluteExpiresAt - CreatedAt`, after every option has run. A consumer's own `CreateOption` that sets the absolute deadline directly is therefore bounded by the same maximum, so no option can lengthen a session past it unnoticed.
- **Defaults:**
  - max equals the absolute timeout, so no session outlives 12 h unless the consumer raises the maximum explicitly;
  - with no `WithAbsoluteLifetime`, a session gets the absolute timeout, as today.
- **Overrides:** both options. `NewManager` refuses a maximum below the absolute timeout.
- **Standards.** NIST SP 800-63B-4 sets the overall reauthentication timeout at no more than 30 days at AAL1 (§2.1.3) and 24 h at AAL2 (§2.2.3). The godoc names both, without enforcing either: the library does not know the assurance level the consumer targets.
- **Rotation and confinement.**
  - Rotation, including rotation with a grace window, already carries the absolute deadline over, so a chosen lifetime survives renewal.
  - `RestoreEnrolmentDeadlines` changes to restore exactly the confinement marker's recorded origin deadline, instead of recomputing `CreatedAt + absoluteTimeout`. Otherwise a long-lived or renewed session that passed through enrolment would come back with the global lifetime. A renewed successor's `CreatedAt` no longer says anything about its deadline. The recorded deadline was a valid deadline when it was recorded, so it is already within every cap, and restoring it can never lengthen the session. No new column is needed, because the marker already holds the origin deadline.
- **Alternatives considered:**
  - Changing `CreateOption` to return an error, to refuse inside the option. That breaks every existing option for one check `Create` can make after the options run.
  - Shortening after creation with a second save, which is what consumers do today. It costs a second write and leaves a window in which the long deadline is stored.

### 4. Login chooses the lifetime from the parsed login request

- **The option.** A `LoginOption` takes a function of the exchange and the parsed login parameters, and returns the lifetime to request, or zero for the default.
- **Where it applies.** The login completion path passes the result through `WithAbsoluteLifetime`.
- **What it governs.** Only the session's lifetime. Cookie persistence is `bff-resource-server`'s concern, and a responder can read the chosen deadline from `LoginResult.Session`.
- **Default:** no function, so every login gets the absolute timeout.
- **Override:** the option.
- **Errors.** A function returning a lifetime above the manager maximum fails the login with the configuration error from decision 3, and nothing is stored. That is a wiring fault, logged and answered as a server error, not a refusal of the user.
- **Alternative considered:** a fixed `remember` member read by the library. It would impose a request shape the consumer owns (library-design rule 5).

### 5. Sessions belong to a family, and supersession is one atomic store operation

- **New fields.** Each session gains six, written only by the library:
  - `FamilyID`, a `pkg/id.ID`: new at `Create`, and kept by every rotation;
  - `FamilyCreatedAt` (decision 13);
  - `SupersededAt`;
  - `AcceptUntil`;
  - `SuccessorDigest` (below);
  - `FirstPresentedAt` (decision 6).
- **Successor tracking.** The store also keeps a superseded record's successor as a digest (never the raw identifier), so it can tell which successor is current.
- **The store operation.** The store port gains an operation that, atomically, does three things:
  - marks the old record superseded, with an `AcceptUntil` and the new successor's digest, on the condition that its current successor is the one the caller observed (none, for a first rotation);
  - marks that previous successor, if any, superseded with `AcceptUntil` equal to now (decision 6);
  - inserts the new session.
- **Losing the race.** If the condition fails, nothing is written and the operation reports a conflict. Two replicas renewing the same identifier at once therefore produce exactly one successor.
- **Durable stores** run it in one transaction (joining a caller's transaction when one is attached, as every store already does) with a conditional `UPDATE`. The memory store runs it under its lock.
- **Why a store operation.** The existing rotation's process lock does not hold across replicas, and its godoc already tells consumers to enforce it in the store. Here the store enforces it.
- **The sweep.**
  - A superseded record keeps its family's absolute deadline, and its idle deadline is set to that absolute deadline. The sweep therefore deletes it only when the family as a whole could no longer be live.
  - Keeping it is what makes a late presentation detectable: a record deleted at the end of its grace window would read as "not found", indistinguishable from a forged identifier.
  - A consumer who emulates grace by shortening the old record's deadline, as a consumer might today, loses exactly that.
- **The family's deadline grows with renewal.** When a supersession gives its successor a later absolute deadline (decision 13), the store raises both deadlines of every superseded record in the family to it, in the same operation. Otherwise a superseded identifier presented after its own deadline, but while the family is live, reads as expired instead of reuse, and the family is never revoked (reproduced in review: `TestRenewalLifetime_ExtendedFamilyStillDetectsReuse`, `session/renewal_test.go`, and the conformance case "extended family keeps its superseded sessions"). Superseded records never authenticate past their window, so raising their deadlines grants nothing.
- **Saving a superseded record.** `Save` keeps the six library-only fields as stored and, on a superseded record, both deadlines too. A request that loaded the session before the supersession and saves after it, the normal case for concurrent requests inside the grace window, would otherwise put a short idle deadline back, and the sweep would delete the record before a late presentation could be judged as reuse.
- **The family identifier.**
  - **Default:** `id.NewV7Generator` on the manager's clock, like every other library-owned record identifier.
  - **Override:** `session.WithFamilyIDGenerator(g)`. Nil is a configuration error from `NewManager`. A generator that returns `id.Nil` or an error makes `Create` fail and store nothing, because a nil family could not be revoked. The option is named for the family because session identifiers themselves come from `crypto/rand`, not from an `id.Generator`.
- **Revocation reaches a successor being written.** A durable family revocation repeats its delete until it removes nothing. Under PostgreSQL's default isolation, a delete that waited on an in-flight supersession sees the old record once that commits, but not the successor it inserted, so a single pass would leave a live session in a revoked family (reproduced in review: `TestSessionFamilyRevocationRace` on each durable runner, which failed with the successor still stored after the revocation).
- **Durable stores lock a family in id order.** Raising superseded members' deadlines makes a supersession lock several rows of one family, and a re-rotation or a family revocation can reach the same rows in the other order. That deadlocked in normal use (reproduced on every durable store by `TestSessionExtendingRenewalLockOrder`, which failed with `SQLSTATE 40P01`). A supersession therefore first locks the family's rows ordered by row id, and a family revocation selects its rows the same way before deleting them, so every multi-row writer of one family takes its locks in one order.
- **A superseded record is superseded again only through its observed successor.** A record already superseded with no successor of its own (a knocked-out successor) still matched a supersession that observed none, so it could be renewed into a second live head (reproduced in review: the conformance case "knocked-out successor renewed as if fresh is a renewal conflict and writes nothing"). The store's condition therefore also requires that a record with no observed successor is not superseded; otherwise it is a renewal conflict.
- **A nil family is refused by supersession too.** A session stored with no family would make the family pre-lock and the deadline raise reach every family-less row of every user. Supersession refuses it with an error and writes nothing, as revocation does.
- **Superseded records are not active sessions.** Counting a user's active sessions, as the concurrent-session cap does, excludes superseded records. They keep the family's deadline only so a late presentation is judged as reuse; counting them made one sign-in renewed three times count as four, locking the user out of new logins (reproduced in review: `TestCountActive_RenewedSignInCountsOnce` and the conformance case "renewed sign-in counts once", which failed with a count of 4).
- **Activity never outlasts the stored absolute deadline.** The activity write stores the earlier of the idle deadline it was given and the absolute deadline the record holds, so a request that loaded the session before another request lowered its absolute deadline cannot store an idle deadline past it (reproduced in review: `TestTouch_StaleCopyNeverLeavesIdleAfterAbsolute` and the conformance case "activity write never stores an idle deadline past the stored absolute deadline").
- **A nil family is refused.** A family revocation naming `id.Nil` is an error and deletes nothing. Sessions written straight to a store with no family would all share the nil identifier, so revoking it would delete unrelated users' sessions.
- **Existing rows.** A family revocation operation deletes every record of one family. The migration gives existing rows `family_id = id` (their own row id), so every existing session is the sole member of its own family.
- **No override.** The family and supersession model is how the guarantee is kept, and a store that skipped it could not detect reuse.

### 6. Rotation with a grace window, re-rotation inside it, and reuse outside it

- **`Manager.RotateWithGrace(ctx, s, grace)`:**
  - creates the successor in the same family;
  - supersedes `s` with `AcceptUntil = min(now + grace, s.AbsoluteExpiresAt)`;
  - returns the successor.
- **Loading a superseded identifier:**
  - **Before `AcceptUntil`:** it authenticates. Its activity write does nothing, so grace never extends.
  - **At or after `AcceptUntil`:** this is reuse. The manager revokes the whole family, calls the reuse observer (decision 8), and returns a new `ErrSessionReused`. That error matches the existing expired-session class through `errors.Is`, so a caller that only checks for an ended session still refuses.
- **Re-rotation inside the grace window.** When the superseded identifier is rotated again before `AcceptUntil`:
  - a fresh successor S2 is created;
  - the previous successor S1 is superseded with `AcceptUntil` equal to now.
- **What re-rotation achieves.**
  - **A lost renewal response is recoverable.** The client retries with the old identifier and gets S2.
  - **A race with a thief is detected.** If an attacker renewed first, the legitimate client's later use of S1 is reuse, and the family is revoked. If the legitimate client renewed first, the attacker's use of S1 or of the old identifier after its window is reuse.
  - This is RFC 9700 §4.14.2's reasoning: whichever party presents an invalidated credential reveals the breach.
- **Rotating S1 directly** (the normal path) supersedes it as usual.
- **Recovery while the successor is unused (opt-in).** With `session.WithUnusedSuccessorRecovery()`, a superseded identifier presented *after* its window is not reuse while its current successor has never been presented. It authenticates only to be rotated again, exactly as inside the window:
  - the unused successor is superseded at once;
  - a fresh one is issued.
- **Why the opt-in exists.** A renewal response lost on a poor network, retried a day later, is otherwise indistinguishable from theft, and it costs the user a fresh sign-in they may not have connectivity for.
- **Recording first presentation.**
  - "Never presented" is recorded explicitly, by a `first_presented_at` marker that the first successful load of a session sets, in one conditional write.
  - The marker has to be explicit because a coalesced activity write (decision 1) can skip a successor's first request, so `last_accessed_at` cannot prove a session was never used.
- **How recovery is decided (chosen 2026-10-21).**
  - **Atomically, by the store.** The manager holds only the successor's digest and no port method can load a session by digest, and a separate check would race a presentation of S1. `Supersession` therefore carries `RequireUnpresentedSuccessor`. The store refuses with `ErrSuccessorAdvanced`, writing nothing, when the observed successor was presented, has been superseded or is gone, and the manager treats that as reuse.
  - **Ordinary requests do not revoke.** With recovery on, `Load` of a superseded identifier past its window returns `ErrSessionRenewalRequired`, which matches `ErrSessionExpired` (a 401), and revokes nothing. Mobile clients send queued requests before renewing, so revoking there would make recovery useless in practice. Only a renewal judges: an unused successor is recovered, a used one is reuse.
  - **Reaching the renewal endpoint.** `Manager.LoadForRenewal` returns such a session for rotation only. When the renewal endpoint is enabled, the resolution core lets a request refused with `ErrSessionRenewalRequired` through to that endpoint alone, publishing no session; every other request is refused with 401.
  - **Cost.** With recovery on, a stale identifier replayed only on ordinary requests is refused but not detected until a renewal; off by default.
- **Re-rotation after the successor moved on.** Re-rotating an identifier inside its window when its successor has itself been superseded, or is gone, is reuse, through the same store refusal. Otherwise the family would hold two live heads that no later presentation exposes (found in review).
- **Strict rotation of a superseded session (chosen 2026-10-21).** `Rotate`, used at second-factor verification, refuses a superseded session with `ErrSessionRenewalConflict` and writes nothing, so the client retries with its current credential and the family keeps one live head. Past the window it answers as `Load` does: reuse by default, `ErrSessionRenewalRequired` with recovery on.
- **Strict rotation is decided by the store too.** `Rotate` supersedes through the store's conditional `Supersede`, with a window that ends at once, and then deletes the old record, so its observable result is unchanged: the old identifier is not found afterwards. A process lock cannot stop a strict rotation and a grace rotation of one session, on one replica or two, from both producing a successor; the store's condition can. If the delete fails, the old record stays superseded with an ended window, so presenting it is reuse, which fails safe.
  - **Reproduced** by `TestRotate_RacingAGraceRotationLeavesOneLiveHead` (`session/rotate_strict_race_test.go`): on the previous `Rotate`, every interleaving of a strict and a grace rotation left two live heads, or none, through one manager and through two sharing a store.
  - **The strict successor is recorded as presented.** It goes straight to the client that completed the second factor, so marking it presented is accurate, and it stops a failed delete from being recovered into a second successor under unused-successor recovery.
  - **A grace rotation in the gap.** A grace rotation that reads the old record after a strict rotation superseded it, but before its delete, finds an ended window and is reuse. The gap is one store round trip; the outcome revokes the family, which fails safe. The per-process rotation lock stays, so on one replica a second strict rotation sees not-found instead.
- **Successors that were knocked out.** A superseded record with no successor of its own to recover into (a successor superseded by a re-rotation or a recovery) is reuse when presented, with or without recovery, whatever the reading clock says: a knock-out ends its window by definition, so the judgement cannot depend on clock skew between replicas or on a time read before a concurrent recovery (reproduced in review: the case of `TestUnusedSuccessorRecovery_FirstPresentationRacingRecovery` in which the recovery commits a second after S1's load read the clock, and `TestKnockedOutSuccessor_IsReuseWhateverTheReaderClock`).
- **The trade-off, documented in the godoc.** Theft is still detected, but later.
  - Whoever presents a stale credential second is caught: a thief who re-rotates first is caught by the real client's next use, and a real client that recovered first catches the thief's.
  - What is given up is the immediate verdict when the old identifier reappears. The exposure lasts until the second party appears, instead of ending at the window.
- **Default:** off, so a superseded identifier outside its window is always reuse.
- **Alternatives considered:**
  - **Refusing a second renewal inside the window.** Simpler, but a lost renewal response then forces a fresh login once the window ends, which is a routine failure for mobile clients on poor networks.
  - **Returning the same successor on a retry.** This would require storing the successor's raw identifier, sealed, against the settled rule that identifiers are never stored.
- **Grace rotation itself has no default use:** rotating with a grace window is an explicit call or endpoint (decision 9).
- **Override:** the grace duration.
- **Fixed by design:**
  - revoking the whole family on reuse. A weaker response would let an attacker who won the race keep the family.
  - the existing `Rotate`. It keeps deleting the old identifier at once (strict), and its successor now inherits the family.
- **Limit:** a grace below 0 or above 5 minutes is refused, because the window is the time a stolen identifier also works. 5 minutes is five times the largest grace the surveyed services allow, enough for slow mobile networks.

### 7. Reuse is judged by the manager from what the store returns

- **What stores return.** A store's `Load` returns a superseded record with its supersession fields set, past its `AcceptUntil` or not. It still enforces the idle and absolute deadlines as today.
- **What the manager does.** It judges `AcceptUntil` with its clock, and revokes and reports on reuse.
- **Why.** Every store enforces the same rule and none duplicates the revocation logic. It also keeps the existing rule that stores judge expiry with the configured clock.
- **The cost.** A consumer calling a store's `Load` directly sees superseded records. The port godoc states this, and the conformance suite pins it.
- **Alternative considered:** a `Load` that refuses superseded records past `AcceptUntil` itself. Every store would then need the revocation path, or the manager would lose the family it has to revoke.

### 8. A reuse observer is the only event hook in this change

- **The option.** `session.WithReuseObserver(fn)` is a `ManagerOption`.
- **When it runs.** Synchronously, after the family is revoked, with the request's context. A consumer whose stores join the request's transaction can therefore write an audit row in the same transaction.
- **What it receives:**
  - the user reference;
  - the family id;
  - when the presented identifier was superseded;
  - the time.
- **What it never receives:** the identifier itself, or any dependency's text.
- **Errors.**
  - A nil observer is a configuration error, as `policy.WithLockoutObserver` already treats one.
  - The observer returns nothing. It cannot fail the request or undo the revocation.
- **Transactions.**
  - Like every store write, the family revocation joins a transaction the consumer attached to the context. The library cannot commit a transaction it does not own, so the godoc of the observer, `ErrSessionReused` and the renewal endpoint states the consequence: a consumer that rolls back its request transaction on a refusal also rolls back the revocation.
  - Such a consumer must commit when the error matches `ErrSessionReused`.
  - If it writes its audit row from the observer in the same transaction, it must do so in a savepoint, because a failed statement aborts a PostgreSQL transaction and takes the revocation with it.
  - `ErrSessionReused` is distinguishable through `errors.Is` for exactly this purpose.
- **Alternative considered:** a hook that detaches the revocation from the consumer's transaction. Each adapter's transaction key is the consumer's own, so the hook would be one more seam the consumer has to implement correctly. The documented rule asks the same of them, with one fewer moving part.
- **Default:** none. Reuse is still refused, revoked and logged at warning, with the fixed reason and the family id.
- **Override:** the option.
- **Alternative considered:** the general security-events port, deferred to its own change. This hook is shaped so that port can call it, or replace it, without changing what is reported.

### 9. A session renewal endpoint rotates the presented session with a grace window

- **The option.** `httpsec.EnableSessionRenewal(deps, opts...)`.
- **What it does.**
  - Answers `POST` on `DefaultSessionRenewalPath` (`/session/renewal`) for an authenticated caller with a resolved session.
  - Rotates that session with `RotateWithGrace` (re-rotation, when the presented identifier is already in its window).
  - Answers through a replaceable responder, like the second-factor verification endpoint. It receives:
    - the successor session;
    - the reloaded user;
    - the renewal kind: a fresh rotation, a re-rotation inside the grace window, or a recovery while the successor is unused.
    - A consumer renders its own envelope and writes its audit row there, inside its own transaction.
- **Default response:** 200 with the new credential in the login endpoint's default JSON shape, and `Cache-Control: no-store`.
- **Refusals:**
  - no authentication result: `ErrAuthenticationRequired`;
  - a lost supersession race: a new `ErrSessionRenewalConflict`, which maps to 409, so the client retries with the credential it holds;
  - a reused identifier: the error from decision 6, which maps to 401.
- **Lifetime:** decision 13. By default the successor carries the deadline over.
- **Defaults and overrides:**
  - grace 30 s (Okta's default), `WithRenewalGrace`;
  - the successor's lifetime, `WithRenewalLifetime` (decision 13);
  - the path, `WithRenewalPath`;
  - the responder, `WithRenewalResponder`.
- **Order of work.** The endpoint reloads the user before rotating, so a removed user gets no successor written.
- **A late session reaching the endpoint through recovery** is checked before rotating, because the core published nothing and the gates never saw it: a session owing a second factor, confined to enrolment or recovery, or owing a password change is refused, and the per-request policy phase runs without marking anything (a deny keeps its reason, a challenge is `ErrAuthenticationRequired`). Otherwise recovery would be a way around confinement.
- **The endpoint's session manager.** `SessionRenewalDeps.Sessions` is optional and defaults to the bearer's manager. Given explicitly, it must be that same manager: a different one is a configuration error from `New`, because two managers that disagree on unused-successor recovery would let the bearer pass a late renewal through that the endpoint then judges as reuse, or the reverse, silently losing recovery (reproduced in review: the "other manager" cases of `TestEnableSessionRenewal_Construction`).
- **Consumer interceptors and the late path.** A renewal reaching the endpoint through recovery is anonymous to every interceptor between the bearer and the endpoint, because nothing is published. A consumer gate that judges the authenticated caller does not judge it; the godoc says so.
- **Logout ends the whole sign-in.** Logout revokes the family of the session it ends, not only that record. Otherwise logging out with an identifier inside its renewal window would leave the successor live until its absolute deadline, and a later presentation of the logged-out identifier would read as not-found rather than reuse. A session never renewed is its family's only member, so logout is unchanged for it (found in review).
- **Wiring.** A renewal path equal to the logout path is a configuration error. The endpoint sits inside every gate (recovery, enrolment, second factor, password change) and outside logout and activity recording.
- **Credential.** In the opaque mode the credential is the session reference (decision 10). In signed-token mode it is minted by the endpoint's token generator, which is then required at assembly.

### 10. An opaque session-reference bearer, built on a shared resolution core

- **The option.** `httpsec.EnableSessionBearer(deps, opts...)` occupies the bearer slot.
- **How it authenticates.**
  - It reads the `Authorization` header with the same scheme matching as `EnableBearerToken`.
  - It refuses a value that is not a well-formed session identifier before any store lookup.
  - It loads the session by the value, which the store looks up by digest. A high-entropy secret behind a digest lookup needs no constant-time comparison.
  - It reloads the user with `LoadByUserID(session.UserID)`, never by username, because a username is a reusable handle.
- **The resolution core.** The steps after extraction form one unexported core:
  - load and judge the session, including decision 6's reuse;
  - reload and check the user;
  - publish the caller and the session;
  - run the per-request policy phase with challenge marking;
  - leave activity to the activity interceptor.
  - `bff-resource-server`'s cookie mode will call the same core with a cookie extractor. The existing signed-token bearer keeps its own verification step and then joins the same core, so all three modes refuse identically.
- **Credentials issued.** With the opaque mode on the chain, every endpoint that issues a credential (login completion, second-factor verification, recovery completion, renewal) issues the session reference. Login completion includes every first factor that completes through it: form login, magic link, the OIDC handoff redemption and passwordless passkey login. None of them requires a token generator in this mode, and giving one is a configuration error.
- **Wiring mistakes** (errors from `New`):
  - enabling both `EnableSessionBearer` and `EnableBearerToken`;
  - giving such an endpoint a token generator while the opaque mode is on. The token it minted would not be accepted by this chain.
- **Default:** the signed-token bearer, unchanged. The opaque mode is opt-in.
- **Overrides:** the scheme, as for the signed-token bearer, and the replaceable dependencies in `deps`.
- **Why opaque.**
  - Revocation is immediate, because there is nothing to verify offline.
  - It needs no signing keys.
  - Its storage already meets OWASP's advice to keep only a hash of a high-entropy token.
- **The trade:** one store read per request, which the signed-token bearer also pays today.

### 11. Consumer interceptors can publish a session and run the per-request phase

- **The methods.** `Exchange` gains two:
  - one that publishes an authentication result and its session together, so `SessionFromContext` and the activity interceptor see the session;
  - one that runs the per-request policy phase with the challenge handling the built-ins use, and returns their refusal or nil.
- **Why on `Exchange`.** The exchange already carries the chain's policy engine and session manager, so neither has to be passed again.
- **Implementation.** The built-in core of decision 10 is implemented on the same two methods, so "a consumer interceptor has everything a built-in has" (the `httpsec` package documentation) is true by construction.
- **Fail closed.** The per-request method refuses with `ErrAuthenticationRequired`, and runs no policy, unless the exchange's published result names this principal and its published session is this session. Otherwise a consumer that skipped publication would have its policies judged on a missing password-change time.
- **The chain's session manager.**
  - **Default:** the manager of the first enabled built-in that has one, as today. A chain whose only session authenticator is a consumer interceptor therefore had none, so its published sessions were never touched (reproduced in review: `TestWithSessionManager`).
  - **Override:** `httpsec.WithSessionManager(m)`, which takes precedence over any built-in's manager whatever the option order. Nil is a configuration error from `New`. Built-ins keep using their own manager, so behaviour where both are wired is unchanged.
- **Default:** unused.
- **Override:** it is itself the consumer's extension point.

### 12. Schema

- **The migration.** A new security-state migration adds to `sessions`:
  - `family_id uuid NOT NULL`, backfilled from `id`, with an index;
  - `family_created_at timestamptz NOT NULL`, backfilled from `created_at` (decision 13);
  - `superseded_at` and `accept_until`, nullable;
  - `successor_digest bytea`, nullable;
  - `first_presented_at`, nullable (decision 6).
- **Applies to** `pgx`, `sqlstore` and `gorm`, which share the table. `gorm` maps the columns on its row type.
- **Downgrade.** The migration's down step drops the columns. Rolling back loses only supersession state, and a superseded record then reads as a live one until its deadline.

### 13. Renewal may give the successor a new lifetime, under a family maximum

- **Two ways to set the successor's deadline:**
  - **Carry-over (the default):** the successor keeps the absolute deadline it rotated from.
  - **New lifetime:** chosen by `WithRenewalLifetime(fn)`, a function of the exchange and the session being renewed, or by the matching argument to `RotateWithGrace`.
- **Bounds on a new lifetime.** It sets the successor's absolute deadline to `now + d`, capped twice:
  - by `WithMaxAbsoluteLifetime` (decision 3);
  - by a new family maximum, `session.WithMaxFamilyLifetime(max)`, counted from `FamilyCreatedAt`, the time of the sign-in that started the family. Every rotation copies `FamilyCreatedAt`, and nothing can reset it short of a new sign-in.
- **Refusal and cutting.**
  - A requested lifetime above the lifetime maximum is a fixed wiring choice, so it is refused with the configuration error from decision 3.
  - Reaching the family maximum is runtime state, not a wiring mistake: a deadline that would pass it is cut to end exactly at it, so the last renewal ends there and later renewals cannot extend further. The successor, and the responder, carry the deadline actually stored. The godoc states that the family maximum is the overall reauthentication limit.
- **Defaults:**
  - carry-over;
  - the family maximum equals the lifetime maximum, so no renewal can extend a family past where its first session would have ended, unless the consumer raises it.
- **Overrides:**
  - the lifetime function;
  - the family maximum. `NewManager` refuses a family maximum below the lifetime maximum. It accepts no "unlimited" value: a finite family maximum is what makes the session's overall limit a limit (library-design rule 4).
- **Strict at second-factor verification.** That rotation always carries over: a privilege change must not lengthen the session.
- **Standards and practice.**
  - NIST SP 800-63B-4 sets an overall reauthentication timeout (no more than 30 days at AAL1, §2.1.3), and a renewal is not a reauthentication.
  - Auth0 states that a rotated refresh token's lifetime does not extend.
  - Atlassian's window slides with use.
  - The family maximum lets a consumer slide renewals while keeping an overall limit. The godoc names the AAL figures and leaves the choice to the consumer.
- **Alternatives considered:**
  - Carry-over only. A mobile session would end a fixed time after sign-in, however often it renews.
  - An unlimited family maximum. It would let a session renew forever without the user ever signing in again.

## Defect claims

- **Stale activity write overwrites a concurrent session change.** `REPRODUCED` (2026-10-21).
  - **Claim.** Request A loads a session. Request B, on the same session, saves a change to a library-only field: for example, entering the enrolment-only state lowers its absolute deadline. A then finishes, and its activity write saves A's stale copy, restoring the higher deadline.
  - **Test.** `TestTouch_KeepsAConcurrentlyLoweredDeadline` in `session/touch_race_test.go`, run with `go test -count=1 -run TestTouch_KeepsAConcurrentlyLoweredDeadline ./session/`, against the memory store. It fails on all three fields B changed:
    - the absolute deadline: expected 09:15, actual 21:00, so A restored the higher deadline;
    - the enrolment-origin marker: expected 21:00, actual the zero time, so the marker was lost;
    - the second-factor state: expected enrolment-pending, actual none.
  - **Fix.** The test is task 3.1's red step, and decision 2's narrow activity write makes it pass.

### 14. The session-reference bearer and the renewal endpoint are throttled (chosen 2026-10-22)

- **Unknown references, per source.**
  - The session-reference bearer checks its source before any work and records a failure for every reference it refuses: malformed, unknown, expired, reused, or whose user is gone. A policy refusal of a valid session is not recorded. This is the API-key flow's model, because both are high-entropy credentials checked on every request.
  - **Default:** on, 100 failures per source per minute, in the `session-reference` namespace, built by the chain's limiter factory. Guessing a 256-bit reference is hopeless at any rate, so the guard bounds store reads rather than guesses, and can be more generous than the API-key guard's 20: legitimate clients present expired references in bursts, for example an office behind one address at the start of a shift.
  - **Override:** `WithSessionBearerLimiter(l)`; `WithRateLimiterFactory` makes it shared across replicas. Like every guard it fails closed when its backend is unavailable.
  - **The signed-token bearer is not guarded:** a forged token fails verification without reaching the store, and a guard would add a limiter call to every request in the default mode.
  - **Trade-off:** see Risks, "A guard on a shared client address throttles everyone behind it".
- **Renewals, per family.**
  - The renewal endpoint counts every renewal of a family, successful or not, and refuses one more than the limit with a new `ErrRenewalThrottled` before rotating anything. It answers 429, not the 401 source guards give: the caller holds a valid session, and a 401 would make a well-behaved client discard it.
  - **Default:** 10 renewals per family per 10 minutes, in the `session-renewal` namespace. A client renewing every few minutes, with a few lost-response retries, stays well inside it; a loop is held to about one row a minute.
  - **Override:** `WithRenewalLimiter(l)`.
  - **Departure:** this limiter counts events rather than failures, unlike the source guards. It is keyed by family, never by source, so it cannot be used to throttle other users.
- **Activity writes.** The `WithTouchInterval` godoc recommends an interval for deployments with busy clients; the default stays a write on every request.

## Pull request review (2026-10-21)

A code review of the pull request raised ten findings. Each is `UNREPRODUCED` until its first task's test fails; if a test passes instead, the claim is wrong and its decision is withdrawn.

1. **A renewal looked like a fresh authentication.** `RotateWithGrace` set the successor's `CreatedAt` to the renewal time, and recovery-code regeneration reads `max(CreatedAt, MFASatisfiedAt)` as the time the user last authenticated. A held credential could be renewed and the user's recovery codes regenerated at once.
   - **Decision (chosen 2026-10-22):** a dedicated `Session.AuthenticatedAt` records when the user last proved who they are. It is set at sign-in (`Create`), refreshed when a second factor is satisfied, and carried over unchanged by every renewal. `CreatedAt` keeps its plain meaning, when this record was written, so a successor's `CreatedAt` is its renewal time. Every freshness check reads `AuthenticatedAt` alone: recovery-code regeneration, and passkey registration and removal (`passkey.Manager`'s management freshness), which computed the same `max(CreatedAt, MFASatisfiedAt)` and so had the same defect (found while implementing 9.1; `UNREPRODUCED` until its test fails). A new non-null `authenticated_at` column, backfilled from `greatest(created_at, mfa_satisfied_at)`, joins the unreleased migration.
   - **Why a dedicated field:** one field with one meaning cannot be confused again. Overloading `CreatedAt` would have fixed this reader but left the next one to guess which meaning `CreatedAt` carries. The name follows the record's `…At` fields and the OpenID Connect `auth_time` claim's meaning: the time the authentication occurred.
   - **First test:** a session created at 09:00 is renewed at 15:00; the successor reports `AuthenticatedAt` 09:00 and `CreatedAt` 15:00, and regenerating recovery codes at 15:01 under the 15-minute freshness window is refused with the reauthentication-required error.
2. **An ordinary request racing second-factor rotation was judged as theft.** Strict `Rotate` superseded the old record with a window ending at once and then deleted it; a request loading the old identifier between the two writes found it superseded past its window and revoked the family.
   - **Decision:** strict rotation supersedes with a short in-flight window (`session.DefaultRenewalGrace`, 30 s) and then deletes the old record. Between the writes the old identifier is served as what it was, a session still owing its second factor, which every gate already confines. Once deleted it is not found, as before this change.
   - **First test:** a load of the old identifier interleaved between the strict rotation's two store writes returns the old session, and the family is not revoked.
3. **A failed delete turned the next request into reuse.** When the delete after a strict rotation failed, `Rotate` returned the error although the successor was stored, so the client kept the old credential and its next request revoked the family.
   - **Decision:** a failed delete does not fail the rotation. The successor is returned and the failure is logged; the old identifier stays superseded and expires as a superseded record when its in-flight window ends.
   - **First test:** a store whose delete fails; `Rotate` returns the successor, the old identifier loads inside the window, and nothing is revoked.
4. **A session with no family could not complete a second factor.** Supersession refuses the nil family, so `Rotate` of a session written straight to a store failed with a server error.
   - **Decision (chosen 2026-10-22):** a session with no family is made unrepresentable rather than half supported. Every `Store.Create` refuses a session whose family is the nil identifier, with an error and nothing written, and the conformance suite pins it for every store. `Manager.Create` always assigns one, and the migration's defaults give one to a row written by older code. The paths that tolerated a family-less session are removed: logout's fallback delete, and the refusals in `Supersede` and `DeleteFamily` stay only as defence in depth.
   - **Why refuse at creation:** every security mechanism of this change, reuse detection, family revocation, logout ending the sign-in, the family maximum and the active-session count, is defined over a family. A session outside one would silently get none of them, which is exactly the "quietly degrade" library-design rule 4 forbids. Enforcing the invariant where records are written gives one refusal at the boundary instead of a special case in every operation, the way refresh-token rotation binds every token to the grant it descends from (RFC 9700 §4.14.2). The library is unreleased, so the breaking change costs no consumer.
   - **First test:** creating a session with a nil family through each store fails and stores nothing.
5. **The migration broke replicas still running the previous release.** `family_id` and `family_created_at` became `NOT NULL` with no default, so an insert from code that does not name them failed.
   - **Decision:** the columns keep `NOT NULL` and gain defaults, a generated `uuid` and the insert time, so an older writer's session is the sole member of its own family. The migration has not been released, so the unreleased migration file itself changes.
   - **First test:** after the migration, an insert that names neither column succeeds, and the row has a family and a family start time.
6. **A coalescing interval could defeat a shorter idle-timeout policy.** With `WithTouchInterval(d)`, the stored last-access time can be up to `d` stale, so a `policy.IdleTimeoutPolicy` whose timeout is not longer than `d` would refuse sessions in constant use.
   - **Decision:** `httpsec.New` refuses, as a configuration error, a chain whose session manager coalesces activity writes over an interval at least as long as any idle timeout its policy engine reports. The manager exposes its interval for the check.
   - **First test:** a chain with a 10-minute touch interval and a 5-minute idle policy fails `New` with the configuration error; with a 15-minute idle policy it builds.
7. **The memory store scanned every record on each supersession.** It raised superseded members' deadlines with a scan of the whole store under its lock.
   - **Decision:** this goes with 8; the memory store also keeps a family index, so revoking a family touches only its members.
8. **Every renewal locked, and could rewrite, every row of the family.** The raise of superseded members' deadlines, and the family-wide lock it needed, cost O(N) per renewal, where N grows with every renewal of a long-lived family.
   - **Decision:** the raise is replaced. A supersession gives every record it supersedes a retention deadline the manager computes, the latest time the family could still be live (`FamilyCreatedAt` plus the family maximum), as both deadlines, through a new `Supersession.RetainUntil`. No later renewal needs to touch it. A supersession then writes only the rows it supersedes and inserts the successor, and locks only those rows, in row-id order. A superseded record never authenticates past its window, so keeping it longer grants nothing; the sweep still removes it once the family cannot be live. This supersedes "The family's deadline grows with renewal" and "Durable stores lock a family in id order" above.
   - **First test:** in a family renewed three times, the last supersession writes no row other than the one it supersedes and its successor.
   - **Changing the family maximum between deploys (decided after the review of the memory side).**
     - **Lowered:** the retention deadline is the latest of the family's end under the current maximum, the superseded record's own absolute deadline and its `AcceptUntil`, and no store ever lowers a deadline it writes. Otherwise a record renewed by a deploy with a smaller maximum would expire at once, inside its own grace window (reproduced in review: `TestReview_LoweredFamilyMaximumCutsTheGraceWindow`). A carried-over successor deadline is also cut at the family's end, so the family maximum bounds every renewal (`RotateWithGrace`), not only those with a chosen lifetime. Strict rotation at second-factor verification is not a renewal: it carries the session's own deadline over and never extends it, so it cannot take a family past what the session it replaces already had.
     - **One deadline for a superseded record.** A superseded record's absolute deadline becomes the later of its own and the retention deadline, and its idle deadline becomes that same value, so it is kept as one deadline whatever its idle deadline was (found in review: raising each deadline separately left a record idle-expired before its absolute deadline).
     - **Raised:** a record superseded before the change keeps the retention it was given. Presented after that retention but while the family, extended under the new maximum, is still live, it reads as expired rather than as reuse: it is still refused, but the family is not revoked (reproduced in review: `TestReview_RaisedFamilyMaximumMissesReuse`). Re-raising every member's deadline on each renewal would restore detection at the per-renewal cost this decision removes, so the limit is recorded in the `WithMaxFamilyLifetime` godoc instead.
   - **A supersession's successor belongs to a family.** Every store refuses a successor whose family is nil, as `Create` refuses such a session, and refuses a `RetainUntil` before the supersession's `AcceptUntil`. Strict `Rotate` takes the successor's family fields from the stored record, never from the caller's copy (reproduced in review: `TestReview_SupersedeStoresAFamilylessSuccessor`).
9. **First presentation needed a second read.** `recheckAfterMark` re-read the session after marking it presented, to catch a recovery committed in between.
   - **Decision:** the store decides it. `MarkPresented` on a superseded record writes nothing and returns a new `ErrSessionSuperseded`; only then does the manager re-load and judge the record. A live session's first presentation costs one write and no extra read.
   - **First test:** with unused-successor recovery on, a first presentation of a live session makes exactly one `Load` and one `MarkPresented`.
   - **As built:** the manager re-loads on `ErrSessionSuperseded` whether recovery is on or off, since the store's answer is authoritative either way, and judges the re-loaded record with the original load's purpose, so a renewal that meets the race is judged as a renewal. A record both superseded and already presented answers `ErrSessionSuperseded`. A mark that fails for any other reason, a store outage for example, also re-loads and judges, because a recovery may have committed in between and only a fresh read can tell (reproduced in review: `TestFailingMarkAfterRecoveryIsNotServed`); if that read fails too, the load fails closed with the store error. A healthy first presentation still costs one read and one write.
10. **Durable-store helpers were copied three times.** The digest argument, the not-found check, the supersession and presentation refusal mappings and the session data codec are moved into `internal/storekit` beside `SessionDigest`. Driver-specific transaction and savepoint code stays in each store. Behaviour is unchanged; the existing suites are its test.

The review also noted a behaviour the design chose: a second tab renewing the old credential inside its window knocks out the successor the first tab already holds, and the first tab's next request then revokes the family (decision 6's re-rotation). It stays as designed; the godoc on `EnableSessionRenewal` advises clients to serialise renewals across tabs.

## Pull request review, second round (2026-10-22)

A second code review and a security review of the pull request raised ten findings. Each was put to a reproduction test on the branch tip (`dde3af5`) before any decision. A finding marked `REPRODUCED` has a test that fails on that commit and passes with the defect temporarily removed; those tests are the red steps of task group 10. The decisions below were chosen on 2026-10-22.

1. **Retention overwrote a superseded record's real deadlines.** `REPRODUCED` by `TestSupersededRecord_RetentionIsNotADeadline` (`session/superseded_deadline_test.go`), six cases on the memory store. A supersession set the old record's absolute and idle deadlines to its retention deadline (finding 8 of the first round), so every later reader took the family's end for the record's own lifetime:
   - **A, re-rotation:** a session created with a 1-hour lifetime under a 30-day maximum, renewed and then renewed again with the old identifier inside the window, gave the second successor a 30-day deadline (expected 10:00 on day 1, actual 09:00 on day 31). Anyone holding the credential could do this; the renewal limit does not stop two requests.
   - **A2, enrolment-only session:** its 15-minute confinement became the full 12 hours after a re-rotation (expected 09:15, actual 21:00).
   - **A3, strict rotation whose delete failed,** then renewed in flight: the successor took the family's end.
   - **R1, in-flight load:** loading the old identifier between a strict rotation's two writes returned the retention deadline as both deadlines, against "the old session as it was" (sessions, "Rotation at second-factor verification keeps the old identifier only in flight"). That requirement and "Superseded sessions are returned by load and kept by the sweep" contradicted each other.
   - **B1, recovery past the absolute deadline,** and **B2, recovery past the idle deadline only:** with unused-successor recovery on, a family whose session had already ended was renewed.
   - Removing the raise turned all six green but broke three existing tests that need the record kept for reuse detection, so retention stays and moves out of the deadline fields.
   - **Decision: retention is its own field.** A session gains `RetainUntil`, library-only like the other supersession fields, and the unreleased migration gains a nullable `retain_until` column. A supersession sets it on the record it supersedes, and on a previous successor it knocks out, to the later of its stored value and the retention deadline the manager computes (first round, finding 8), and never changes either deadline of either record. `Supersession.RetainUntil` keeps its name and meaning; only where the store writes it changes.
   - **Who reads which.**
     - The store's `Load` returns a superseded record while its retention deadline has not passed, whatever its own deadlines say, with its own deadlines intact. A live record is judged by its deadlines, as before.
     - The expiry sweep deletes a superseded record once its retention deadline passes, and a live one once a deadline passes, as before.
     - The manager judges a superseded record's presentation by its window, then by its own deadlines: inside its window it is served only while both of its own deadlines are unexpired, and otherwise it is expired, revoking nothing. Outside its window it is reuse, as before, whatever its own deadlines say: a record kept past its own deadline exists precisely so a late presentation is detected.
     - Under unused-successor recovery, a late renewal of a record whose own idle or absolute deadline has passed fails with the session-expired error and revokes nothing; only a predecessor whose own deadlines are both unexpired can be recovered. This answers B2 (chosen 2026-10-22): an idle timeout exists so an abandoned session ends, and recovery must not be a way around it. The existing recovery fixtures already chose 72-hour and 48-hour timeouts so that a next-day retry is judged by its window rather than an ended deadline.
     - Rotation builds the successor from the record's own deadlines, so carry-over (A, A3), confinement (A2) and the in-flight load (R1) see real values.
   - **"Never lowers" moves with it.** No store lowers a stored retention deadline, and a supersession whose retention deadline is before its window's end is still refused. Saving a superseded record keeps its deadlines and its retention deadline as stored.
   - **Existing rows.** The column is null for every live session and every row written before it; a superseded row with a null retention deadline is kept until its own deadlines pass, which is no shorter than what the previous release gave it.
   - **Supersedes** "The sweep", "The family's deadline grows with renewal" and "Saving a superseded record" in decision 5, and the deadline part of the first round's finding 8. The retention deadline itself is unchanged: the latest of the family's end, the record's own absolute deadline and its window's end.
   - **Durable stores:** `UNREPRODUCED` on PostgreSQL, because the reproduction ran on the memory store only; `internal/pgschema/sessions.go` raises both deadlines with the same `GREATEST`, so the conformance case added with the fix is the durable red step.
   - **No override.** Retention is how reuse stays detectable; a consumer cannot choose to lose it.
2. **Revocation ran on the presenting request's context.** `REPRODUCED` by `TestReuse_RevokesTheFamilyWhenThePresentingRequestIsCancelled` (`session/reuse_revocation_context_test.go`): a store that honours its context, as the database/sql and pgx stores do, deleted nothing when the client disconnected after its session was read, on four paths (a load past the window, a grace renewal, a strict rotation, and a renewal refused because its successor moved on). The family a thief holds stayed alive behind a logged error.
   - **Also in logout:** `REPRODUCED` by `TestLogout_EndsTheSignInWhenTheClientHangsUp` (`httpsec/logout_cancel_test.go`). A client that disconnects mid-logout leaves its sign-in live, and will not retry.
   - **Decision:** both revocations run on `context.WithoutCancel(ctx)`. It keeps the context's values, so a revocation still joins a transaction the consumer attached; a consumer whose own transaction was begun on the cancelled request context loses it to the cancellation, which decision 8's commit rule already covers. Session touch, recovery's knock-out, passkey removal's second pass, clone handling, back-channel logout and password change already detach. The first-presentation mark and supersession fail closed when aborted, and the second-factor reset's session cleanup is an operator call with a documented retry, so they are unchanged.
   - **No override:** a revocation that a disconnect can abort is not a revocation.
3. **Removing a passkey with the old identifier signed the user out.** `REPRODUCED` by `TestRemove_EndsOtherSessionsByFamily` (`passkey/manage_other_sessions_test.go`). Removal kept only the presented identifier (`DeleteByUserExcept(user, s.ID)`), so a removal made with a predecessor inside its renewal window deleted the live successor and kept the dying predecessor; once the window ended nothing of the sign-in survived, against "The removing session SHALL stay valid" (passkey-authentication).
   - **Keeping the whole family is wrong too.** Presenting the successor, the identifier-only cut correctly ends a superseded predecessor a thief may hold; keeping the family would let it outlive the credential change. The same test pins that case.
   - **Decision: the store decides, in one operation.** `Store.DeleteByUserExcept(ctx, user, keep)` keeps the session `keep` names and, when that session belongs to a family, the family's current session, the one member not superseded; it deletes every other session of the user, every other member of that family included. One statement in the durable stores, under the lock in the memory store, so a renewal committing between a read and a delete cannot lose the successor. Every store implements it and the conformance suite pins both cases. Its only callers are passkey removal's two passes.
   - **Alternative considered:** computing the set in `passkey.Manager` with a read and then the cut. No interface change, but the gap between them is the same race in a smaller window.
   - **Other paths:** recovery completion, the second-factor reset, clone handling and back-channel logout end every session of the user, and registration, password change and recovery-code regeneration end none, so none is affected.
4. **A superseded record's fake deadlines were visible to readers.** `NOT A DEFECT` under the spec as it stood, which required them; settled by decision 1, which makes the deadlines real.
5. **Rotation resets `CreatedAt`.** `NOT A DEFECT`: chosen in the first round (finding 1). The cited `Thresholds(s.CreatedAt, now)` usage is not documented anywhere. The `CreatedAt` godoc is to say that a renewal writes a new record with a new `CreatedAt`, and point to `FamilyCreatedAt` for the sign-in time.
6. **Logout's documentation still promised a family-less fallback.** `NOT A DEFECT` in behaviour: a family-less session is refused, nothing is deleted, and the caller gets a 500, which fails closed as the first round decided (finding 4). The `logout` doc is corrected.
   - **Decision: a family-less session cannot be published.** The stores already refuse to create one, so it can reach the chain only through a consumer interceptor or a consumer store that drops the family, and it would then get no reuse detection, no family revocation and no logout. `Exchange.PublishSession` returns an error and publishes nothing when the session's family is the nil identifier, completing the first round's "every session has a family". The error carries fixed text and matches no sentinel, so it maps to 500: it is a consumer's wiring mistake, not the caller's. Publishing a result with no session is unchanged. Breaking for such a consumer, which is acceptable before the first release.
7. **A renewal touched the superseded session.** `NOT A DEFECT`: the renewal and logout endpoints end the chain before the session-touch step runs; a counting store saw no activity write on either.
8. **The supersession transaction was copied into three stores.** Confirmed: `atomically`, `underSavepoint` and the supersession sequence are about 135 lines in each of `sqlstore`, `pgx` and `gorm`, step for step alike, with two differences, both `UNREPRODUCED` until their tests run on PostgreSQL:
   - `gorm` passes an absent digest as a typed nil `[]byte` (`storekit.OptionalDigest`) where the other two pass an untyped nil (`storekit.OptionalDigestArg`), which its documentation says exists "so every driver sends NULL";
   - only `pgx` rolls back on `context.WithoutCancel(ctx)`.
   - **Decision:** each difference gets its test first; a reproduced one is fixed, an unreproduced one is aligned with the other stores and recorded as such. Then the sequence moves into `internal/storekit` behind a small per-driver adapter, as the first round's finding 10 did for the helpers, as its own commit: behaviour, statements and error text unchanged, with the session, race, lock-order and ambient suites as its test.
9. **Stale documentation.** Confirmed: the `Session.AbsoluteExpiresAt` godoc describes a `CreatedAt`-plus-timeout cap the restore no longer has; the `storeFailed` godoc omits `ErrSessionSuperseded`; the `Store.Save` godoc says only `Create` writes `AuthenticatedAt`, though a supersession's successor carries it too. The restore rule in the settled sessions spec is already replaced by this change's delta.
10. **A dead fixture line, and a gap behind it.** The conformance fixture's `s.AuthenticatedAt = ...` before `Save` has no effect, because `Save` keeps the stored value by design, pinned in every store. With passkey management's freshness check disabled, all twelve passkey conformance scenarios still passed: no end-to-end scenario checks it.
    - **Decision:** remove the line, and add a passkey conformance scenario in which registration and removal with a session older than the freshness window ask for reauthentication; the scenario must fail with the check disabled.

## Risks / Trade-offs

- **A stolen identifier also works inside the grace window.**
  - Mitigation: a short default (30 s), a hard 5-minute ceiling, and detection once either party uses a stale credential.
- **A legitimate client that queues requests with an old identifier past the window revokes its own family.**
  - Mitigation: the godoc tells clients to switch to the successor as soon as renewal returns, and to retry queued requests with it.
  - The consumer sizes the grace window for its clients. A consumer with an offline outbox might choose 60 s.
- **Superseded records accumulate until their family's absolute deadline,** at one row per renewal.
  - A renewal locks and writes only the record it supersedes, its previous successor if any, and the inserted successor, so its cost does not grow with the family (finding 8). The retained rows cost storage only, until the family's retention deadline passes and the sweep removes them.
  - Mitigation: renewals are explicit calls, not per-request.
  - The sweep still bounds the table, and the index on `family_id` keeps revocation cheap.
- **With unused-successor recovery on, a thief holding an old identifier is detected only when the real client next appears, not at the window's end.**
  - Mitigation: off by default. When on, the godoc states the trade-off, and detection still occurs on the second presentation.
- **A consumer's request transaction can roll back a revocation.**
  - Mitigation: `ErrSessionReused` is distinguishable, and the godoc states the commit-and-savepoint rule (decision 8).
- **A coalesced write can end a session up to the interval early.**
  - Mitigation: the interval is refused at or above the idle timeout. The godoc states the bound.
- **The store port grows.**
  - Consumer-written stores must implement the activity write, supersession and family revocation. The conformance suite gives them a red/green target.
  - Nothing is tagged, so this is recorded and not versioned.
- **Multi-row deletes outside a family's lock order.** Deletes by user and the expiry sweep still lock rows in scan order, so in principle they can deadlock with a supersession whose id order differs, as the old-record-then-previous-successor order already could before this change. A row a third transaction supersedes after the family pre-lock's snapshot could also be locked later, outside id order. `UNREPRODUCED`: both need a crafted interleaving.
  - Mitigation: PostgreSQL aborts one side with a deadlock error, so the operation fails loudly instead of missing a row, and a reused-session refusal still stands.
- **A guard on a shared client address throttles everyone behind it.** Without trusted-proxy configuration, every client behind a load balancer shares its address, so one source flooding unknown session references throttles every user's session-reference requests for the window. Every built-in guard has this property; for this one the cost is service, not only login.
  - Mitigation: the godoc of `EnableSessionBearer` and `WithSessionBearerLimiter` tells consumers to resolve the real client address (gin's and fiber's trusted-proxy settings, or `trusted-proxy-client-ip` when it lands) and how to replace the guard.
- **Opaque mode costs one store read per request.**
  - This is the same as the signed-token bearer, which already loads the session. It is not a regression.

## Migration Plan

- Apply the new security-state migration before deploying code that writes the new columns. The down step reverses it (decision 12).
- Consumers adopt each behaviour by option. A consumer that changes nothing sees today's defaults.

## References

### Decisions 1 and 2: coalesced and narrow activity writes

**Researched (accessed 2026-10-21):**
- [NIST SP 800-63B-4, §5 Session Management](https://pages.nist.gov/800-63-4/sp800-63b/session/): session activity shall reset the inactivity timeout, and cookie expiry shall not be relied on to enforce it.
- [NIST SP 800-63B-4, authenticator assurance levels](https://pages.nist.gov/800-63-4/sp800-63b/aal/): inactivity limits (none required at AAL1, no more than 1 h at AAL2, 15 min at AAL3).
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html): every session has an idle timeout, enforced server-side.
- [express-session](https://github.com/expressjs/session): `rolling`, `resave` and the store `touch` method, as one established split between activity and full saves.
- [ASP.NET Core cookie authentication](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/cookie?view=aspnetcore-9.0): sliding expiration as the rejected half-window alternative. The renewal-after-half rule was read only in older documentation.
- [Spring Session API](https://docs.spring.io/spring-session/reference/api.html): last-accessed time written on save.

### Decisions 3 and 4: per-session lifetime

**Researched (accessed 2026-10-21):**
- [NIST SP 800-63B-4, authenticator assurance levels](https://pages.nist.gov/800-63-4/sp800-63b/aal/): overall reauthentication timeout no more than 30 days at AAL1 (§2.1.3), 24 h at AAL2 (§2.2.3), and 12 h at AAL3 (§2.3.3).
- [NIST SP 800-63B-4, §5 Session Management](https://pages.nist.gov/800-63-4/sp800-63b/session/): "remember my browser" features shall not replace authentication, so a remembered session is still a session with an absolute limit.
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html): an absolute timeout regardless of activity, and persistent versus non-persistent cookies.
- [ASP.NET Core cookie authentication](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/cookie?view=aspnetcore-9.0): persistence only with the user's explicit "remember me" consent.
- [Spring Security remember-me](https://docs.spring.io/spring-security/reference/servlet/authentication/rememberme.html): the risks of a long-lived token usable from any user agent.

### Decisions 5 to 9 and 13: families, grace, reuse, renewal and family lifetime

**Researched (accessed 2026-10-21):**
- [RFC 9700, §2.2.2 and §4.14](https://datatracker.ietf.org/doc/html/rfc9700): refresh token rotation, tracking the relationship between old and new tokens, and revoking when an invalidated token is presented.
- [Okta refresh tokens](https://developer.okta.com/docs/guides/refresh-tokens/main/): a grace period for the previous token, 30 s by default and configurable from 0 to 60 s, and a reuse-detection event.
- [Auth0 refresh token rotation](https://auth0.com/docs/secure/tokens/refresh-tokens/refresh-token-rotation): invalidating the whole family on reuse.
- [Auth0, configure refresh token rotation](https://auth0.com/docs/secure/tokens/refresh-tokens/configure-refresh-token-rotation): leeway disabled by default and configurable in seconds; "the lifetime does not extend when tokens are rotated" (decision 13).
- [GitLab issue 472801](https://gitlab.com/gitlab-org/gitlab/-/issues/472801): a proposal to activate a rotated token only after its first use, because a lost rotation response otherwise strands the client. It is open, with no sign of being accepted, and it informs decision 6's unused-successor recovery.
- [WorkOS, refresh token behaviour across fourteen providers](https://workos.com/blog/refresh-token-behavior-across-fourteen-providers): reuse windows in practice (Atlassian 10 min, Linear 30 min, Box none), and Atlassian's sliding 90-day window (decision 13). This is a secondary survey and was not checked against each provider.
- [PostgreSQL: transactions and savepoints](https://www.postgresql.org/docs/current/tutorial-transactions.html): an error aborts the transaction unless a savepoint is used (decision 8). Primary documentation, not re-read on this date.

### Decision 10: opaque session-reference bearer

**Researched (accessed 2026-10-21):**
- [RFC 6750, §5](https://www.rfc-editor.org/rfc/rfc6750.html): bearer token references must be infeasible to guess, and their lifetime must be limited.
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html): at least 128 bits from a CSPRNG, and storing only a hash of the token server-side.
- [Paragon Initiative Enterprises, long-term persistence](https://paragonie.com/blog/2015/04/secure-authentication-php-with-long-term-persistence): the split-token timing concern, which a digest lookup avoids.

### Decisions 11 and 12

Reasoned from scrty's own settled specs (`http-security-chain`, `sessions`, `security-state-stores`, `schema-migrations`), the `httpsec` package documentation, and the established design.

### Pull request review, second round: findings 1 to 10

**Primary documentation:**
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html): every session has an idle timeout, enforced server-side (finding 1, recovery after the idle deadline). Read for decisions 1 and 2 on 2026-10-21, not re-read on this date.
- [Go `context.WithoutCancel`](https://pkg.go.dev/context#WithoutCancel): a context that keeps its parent's values and is never cancelled when the parent is (finding 2).
- [RFC 9700, §4.14](https://datatracker.ietf.org/doc/html/rfc9700): revoking when an invalidated token is presented, which reuse detection and its revocation implement (finding 2).

Findings 3 to 10 are reasoned from scrty's own settled specs (`passkey-authentication`, `sessions`, `security-state-stores`, `http-security-chain`) and the reproduction tests named with each finding.
