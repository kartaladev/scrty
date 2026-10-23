# Design

## Context

See `proposal.md` (Why) for the motivation, and the delta specs for the requirements. This section records only the state of the code, read on 2026-10-23, that shapes the approach.

**Evidence.**
- Every defect named here has a failing test. Each test lives in a disposable export of HEAD, and the main session reran it against code identical to HEAD.
- The tests are the red steps of this change. Implementers rewrite them in scrty's own style; they are not copied over as they are.
- IDs (`H1`, `M7`, `L6`, `N2`, `S4`, `U3`, …) refer to the audit's findings list, and the tasks use the same IDs.

**Claims recorded `UNREPRODUCED`.** Each starts with its red test (`defect-claims.md`) and is dropped if the test passes:
- `U1`: gorm replica reads;
- `U2`: unbounded user-wide delete loops;
- `U4`: an unrecorded first use enabling successor recovery;
- `U6`: fiber context cancellation;
- `U8`: RP ID validation;
- `S7`: nil records in recovery and passkey lists;
- the fiber `HEAD`-reaches-`GET` bypass of the cool-down, which was observed but not asserted;
- the unparseable-hash half of `M2`;
- the Argon2id constructor ceiling gap (finding 2 under the HIGH heading).

**State that shapes the approach.**
- **Route matching.** `httpsec.Route` is used only by the recovery cool-down. Every other path match in httpsec is either an endpoint the chain answers or an exemption a gate grants. Exemption and answer predicates are paired: a gate exempts exactly the paths its endpoint answers.
- **Isolation.** Store-owned transactions begin at the database default:
  - `pgx` `Begin`, `sqlstore` `BeginTx(ctx, nil)`, `gorm` `Begin()` for identity, sessions and recovery codes;
  - `StreakAdd` and the PostgreSQL limiter record run as autocommit statements.

  Their SQL assumes READ COMMITTED: an advisory lock, then a read; `ON CONFLICT DO UPDATE`; `FOR UPDATE` re-reads. Under a REPEATABLE READ default, five operations fail or silently keep stale rows (`M7`, `S4`, `S5`).
- **Count-then-issue.** Every issuance limit counts with `IssuedCount`/`Count` and then calls `Issue`/`Insert` in a separate step:
  - magic links;
  - recovery codes;
  - MFA challenges;
  - passkey registration challenges;
  - the passkey credential limit.

  `onetime.Store` has no bounded insert. The existing indexes `one_time_tokens_subject` and `passkey_credentials_user_id_idx` serve a per-subject count.
- **MFA store generations.** The MFA store's `Confirm` and `AcceptStep` carry no enrolment generation. `Complete` and the device-proof writes already do.
- **Signing keys.** Construction publishes every stored key. Reload filters by age. Neither filters future dates. `SigningKeyAAD` covers only the key id.
- **Recovery channels.** `factor.Kind` carries a channel. The way-back check's `AuthenticatorRef` does not.
- **Sentinel registry.** Every new sentinel must be registered in `httpsec/status_test.go` `TestStatusForErrorCoversEverySentinel`, and mapped in `status.go` where it needs a status.
- **Coordination with `release-readiness`.** That change's task 2.1 also edits `layout_test.go`.

## Goals / Non-Goals

**Goals:**
- Every reproduced defect fixed at its cause, with its sibling sites, on every backend and adapter where it applies.
- Each fix keeps every guarantee the settled specs make that this change does not deliberately alter, and the full gate stays green on PostgreSQL 15 and 18.
- Every changed default states its override, or why it has none.

**Non-Goals:**
- The gin trusted-proxy client IP (`U7`). The active `trusted-proxy-client-ip` change owns it.
- Routing gorm reads to a primary (`U1`). It is documented as a stated limit (decision 16), and no dependency is added.
- Refusing nil functional options (`U9`). The library-wide convention is to skip them, and about 55 constructors follow it. Flipping one would be the inconsistency.
- Pruning signing keys from the store. `expiry-sweeping` forbids deleting them, and `KeyStore` has no delete.
- Binding `CreatedAt` into the signing-key AAD. Every existing sealed key would stop opening, and construction fails closed, so every sealed deployment would fail to start (decision 9).
- A general redesign of rate limiting or lockout beyond bounding what is unbounded.

## Decisions

### 1. A resolved session authenticates only its own, active user (H1, M1)

- **The check.** After the user reload in the shared resolve core, refuse with `ErrAuthenticationRequired` when `details.ID != session.UserID` or `!details.Active`. The core serves both the signed-bearer and session-reference modes. Apply the same check in `sessionRenewal.user()`, which late renewal reaches without `resolve`, and in recovery `Finish` as a defence.
- **Username lookup kept.** The signed bearer still reloads by username, so the token's subject keeps its meaning. Reloading by `session.UserID` would be cleaner, but it rewrites about 15 strict mock expectations and adds no security once the ID check exists.
- **Refuse, don't revoke.** A disabled user's sessions are refused but not deleted. The library does not interpret what disabling means for the consumer's other systems. A consumer who wants revocation calls the session store's `DeleteByUser` when disabling.
- **Override:** none, deliberately. A session that authenticates someone else, or a disabled user, is never a legitimate configuration.
- **Departure** from the established design: it reloaded by username with no ID or active check.
- **Fixture to fix:** `httpsec` `TestRecoveryCodes/"a GET for a user with no set counts none, which is low"` has a session and loader for different users. That is a fixture mistake.

### 2. Stored hashes carry bounded work, and constructors share the ceilings (H2, N1)

- **Ceilings.** Each record parser checks one set of ceilings before deriving anything:
  - scrypt: `p ≤ 16` and `(N + p) · 128 · r ≤ 1 GiB`;
  - bcrypt: `cost ≤ 16`;
  - Argon2id: memory ≤ 1 GiB, iterations ≤ 16, threads ≤ 16, salt ≤ 64 bytes, key ≤ 64 bytes.
- **Constructors.** Each constructor refuses a parameter above its ceiling, so an encoder never produces hashes it would refuse.
- **No override:** a stated limit under `library-design.md` rule 4. The ceilings bound what stored data can make the process do. Configurable ceilings would let one configuration line reopen the process-kill.
- **Default bcrypt cost.** It stays 10, OWASP's bcrypt floor. The ceiling of 16 is far above every published recommendation, so a consumer raising the cost has ample room.
- **OIDC claim cost band.** The band must stay at or under the record ceiling, so its maximum falls from 31 to 16 (identity-linking delta). Without that, a hash would be accepted at provisioning and then never match.
- **Departure:** the established design bounds neither scrypt `p` nor bcrypt cost.

### 3. No usable hash costs one reference verification (M2)

- **When a stored hash is unusable.** When it is empty, or the encoder reports it does not recognise it, the provider runs `Match(presented, reference)` once and discards the result.
- **Exactly one derivation.** Running both the stored and the reference match would make "wrong password" twice as slow as "unknown user", which is a new oracle.
- **Recognition is optional.** It is an optional interface on the encoder, checked by type assertion; all three built-in encoders implement it.
  - **Default:** a consumer's encoder without it is treated as recognising every non-empty hash, so only an empty hash triggers the decoy. Recognition is how the consumer extends that.
- **Logging.** The refusal is the bare `ErrAuthenticationFailed` to the caller. The sampled refusal log names it `no-password-hash` at Debug (a federated user trying the password form is routine) or `unrecognised-hash` at Warn (an operator must fix the stored hash or the encoder).
- **The trap to avoid:** using the reference match's result. The reference password is a library constant, and a "match" must never admit. Tests assert that presenting it fails.
- **Departure:** the established design spends the decoy only on a lookup miss.

### 4. Matching is broad where a match refuses, exact where a match exempts (H3)

- **Cool-down only.** Only the recovery cool-down's marked routes are matched broadly: method upper-cased with `HEAD` treated as `GET`, path compared ignoring ASCII case and any trailing slashes, `/` staying `/` (fiber's default routing strips every trailing slash, so trimming one would leave `//` reaching the marked route). Both sides are normalised: the marked routes at construction, the request at match time.
- **Why it stops there.** The sweep's route table shows every other matcher exempts or answers. A gate that exempted a broadened path would call `next`, and the exact-matching endpoint would not claim it. On fiber the consumer's route would then run, which fails open. Every exemption and answer predicate therefore stays exact.
- **Rejected:**
  - adapter-aware matching, which every future adapter would have to re-implement;
  - refusing non-strict fiber apps, which is noisy and detectable only at the first request.
- **Override:** none. Over-matching is fail-closed and lasts only the cool-down window. The cost is that, on net/http and gin, a genuinely different route such as `/Account/Email` is also held during the window, and the godoc says so.
- **Consumer authorization rules.** These are consumer-written predicates the library does not match. The documentation states fiber's case- and slash-insensitive routing as a caveat.
- **Departure:** none; the established design has no cool-down.

### 5. One mailbox is one factor (M4)

- **The rule.** Recovery's shape check refuses an issued code paired with an MFA proof whose method's channel is `factor.Email`. It is refused as a malformed recovery at request time, before anything is checked. It is not refused at construction, because email MFA paired with a saved code remains valid.
- **The way-back check.** It must stop counting the impossible pairing. `AuthenticatorRef` gains the authenticator's channel, filled in by the MFA kind from the method's declared channel and empty for passwords and passkeys. `pairsWithIssuedCode` skips refs on the email channel.
  - **Why not the alternative:** having the check hold the method set duplicates the method registry.
- **No override** (user decision, 2026-10-23). Accepting the pairing would let one mailbox recover the account, which voids the "two proofs" guarantee. NIST SP 800-63B-4 §3.1.3.1 forbids email for out-of-band authentication, and §4.2.2 requires a recovery code plus a bound authenticator at AAL2.
- **Not covered, documented as a deployment risk:** an OIDC provider that also hosts the mailbox. It passes as a federated proof plus an email proof, and cannot be detected by the library.

### 6. Security names compare ASCII case only (L1, L2, N4)

- **The comparisons affected:**
  - the JIT domain allowlist;
  - the default privilege-name comparer, for group, resource and privilege alike;
  - the cancel-link `localhost` check.

  Each folds ASCII letters only and trims ASCII whitespace only, reusing `internal/origin`'s ASCII-folding helper.
- **Override:** the privilege comparer is already replaceable. The domain allowlist and the loopback check have none, because they are security comparisons with one correct answer.
- **Departure** for L2: the established design used Unicode folding.

### 7. Limits are decided by one bounded write under a per-subject lock (L6, L7, N2, user decision)

**The ports.**
- `onetime.Store` gains `InsertWithin(ctx, tok, since, limit) (bool, error)`.
- `onetime.Manager` gains `IssueWithin`, which reports `ErrIssueLimitReached` when the limit is reached.
- `passkey.CredentialStore` gains `InsertWithin(ctx, cred, limit) (bool, error)`. Plain `Insert` stays, for seeding and import.

**The callers.** Every count-then-issue site moves to the bounded call:
- magic-link request;
- recovery start;
- MFA begin;
- passkey registration begin;
- the passkey finish.

**The memory store** decides the bounded insert under its existing mutex.

**The SQL stores** decide it inside a store-owned READ COMMITTED transaction: `pg_advisory_xact_lock` on a namespaced key of (purpose, subject), then a count, then the insert. The same pattern already serves `RecoveryCodeLockUser`.
- **Why not `INSERT … WHERE (SELECT count(*) …) < n`:** under READ COMMITTED two such statements both see the old count, so it is not atomic.
- **No migration:** the existing indexes serve the count.

**Inside a caller's transaction.** The operation refuses at a stronger isolation (decision 8). Under a caller's REPEATABLE READ snapshot the count would predate the lock.

**Return shape.** `(bool, error)`, not new sentinels. A refused insert is an outcome, not a failure.

**Overrides:** the limits themselves stay replaceable exactly as before. The atomicity has none; it is the guarantee.

**Departure** for L6: the established design counted, then issued.

### 8. Stores pin READ COMMITTED, and refuse a caller's stronger transaction where it matters (M7, S4, S5, U2)

- **Store-owned transactions.** Every transaction a store opens runs `SET TRANSACTION ISOLATION LEVEL READ COMMITTED` as its first statement.
  - This covers identity, session supersede, recovery-code replace and the bounded inserts, in `pgx`, `sqlstore` and `gorm`.
  - A statement rather than a `TxOptions` field, so the `pgx` `base` interface (pool or tx) need not widen and the three drivers share one shape.
- **Autocommit statements.** `StreakAdd` and the PostgreSQL limiter record each run in their own READ COMMITTED transaction. An autocommit statement inherits the session default.
- **Inside a caller's transaction.** An operation whose guarantee depends on READ COMMITTED reads `current_setting('transaction_isolation')` once, in its savepoint (in the caller's transaction directly for `StreakAdd`, which has none), and refuses with an error naming the level when it is stronger. That covers recovery-code replace, the bounded inserts and `StreakAdd`. The error matches `storeerr.ErrIsolationTooStrong` on every backend: a new public root-module package `storeerr` holds it, and each backend's own name is an alias (user decision, 2026-10-23), so `httpsec` and a consumer can match it whichever backend runs, since `pgx` and `gorm` are separate modules.
  - **Why not degrade silently:** the recovery-code case keeps both sets with no error.
  - **Why not override the caller's isolation:** a store cannot change it mid-transaction.
  - **Other operations** join a caller's transaction at any isolation, as today. Their guarantees come from conditional writes that recheck on the committed row; the sweep checked one-time consume under REPEATABLE READ.
- **User-wide delete loops.** `DeleteByUser`, `DeleteByUserExcept`, `DeleteByExternalSession` and `DeleteByUserAndExternalIssuer` become bounded at 64 passes, matching `StreakAddMaxRuns`, and end with `session.ErrDeleteDidNotSettle`, which each backend wraps. `DeleteFamily` stays unbounded: a family gains a member only when its current member is superseded, and the delete removes that member, so concurrent work cannot keep refilling it.
- **Override:** none for the isolation. A consumer who needs a stronger isolation for their own work runs the store operation outside that transaction. The godoc states which operations refuse.
- **Departure:** the established design pinned no isolation.

### 9. Signing keys: one publishing rule, and the present bounds the current key (M5, M6)

**One rule.** One predicate decides publication, shared by construction, reload and housekeeping. A key is published when it is:
- within the lifetime; or
- the newest key of a configured algorithm.

This keeps "no replacement for an algorithm that already has a stored key" true, so a stale current key is kept, not re-minted, and it drops past-lifetime keys of every other kind.

**Future dates.**
- The current key is the newest whose `CreatedAt ≤ now + reloadInterval`. The allowance absorbs normal skew between replicas, so a key a slightly fast replica just minted is adopted on the next reload.
- Housekeeping retires a non-current key dated more than one lifetime ahead.
- A key dated slightly ahead by replica skew stays published, so that replica's tokens still verify.

**No AAD change.** The logic fix closes the tamper path without breaking every sealed key.

**Override:** the lifetime and reload interval stay configurable as today. The publishing rule has none, because it is what makes a retired key stop verifying.

**Departure:** the established design loaded every key, with no future-date check.

**Fixtures to change:**
- `housekeep_test.go:96` and `algs_test.go:83` pin the old construction behaviour the spec now changes.
- `boundary_test.go:382` and `reload_test.go:88-108` choose dates that become past-lifetime or future-dated. Seed them inside the lifetime, or pass `WithClock`.

### 10. TOTP writes are conditional on the enrolment generation (L3, L4, L5, U3)

- **The port.** `Confirm(ctx, user, gen, step, at)` and `AcceptStep(ctx, user, gen, step)` gain the generation. They write only on that generation; a nil generation matches nothing, as the device-proof port already does.
  - **Implementers:** memory, pgx, sqlstore, gorm and the sealing wrapper.
  - **Also updated:** the shared SQL in `internal/pgschema/mfa.go`, the three generated mocks, and the storetest suites, fakes and broken-store fixtures.
- **The manager.** `TOTP` passes the generation it read. A refused write maps to `ErrInvalidCode`, the same answer a wrong code gets, so the race reveals nothing.
- **The period.** It must be a whole number of seconds, at least one. Every `NewTOTP` error wraps `ErrConfig`.
- **The sealed secret (U3).** `seal.MFASecretAAD` gains the generation.
  - **Data:** existing sealed TOTP secrets stop opening. This is a deliberate pre-tag break: nothing is released, and an opt-in legacy fallback would keep the hole open while it was on. The CHANGELOG entry and the `secrets-at-rest` delta state that affected users enrol again.
- **The idiom fix (U12).** `seal/mfa.go`'s `==` on a sentinel becomes `errors.Is`.
- **Override:** none. Generations are the store's consistency mechanism, not a policy.
- **Departure:** the established design had no generations.

### 11. API keys: refuse the dead, decide the race by the write, never verify an empty digest (M3, N3, L10)

- **Refusing.** `Rotate` refuses a revoked or expired key with `ErrRotationRefused`, issuing nothing.
- **The race.** The spec and `returned_errors_test.go` pin the order issue-then-revoke, so the race is decided without reversing it:
  - `apikey.Store.Revoke` reports whether this call moved the key from live to revoked, as a conditional write;
  - `Rotate` issues the replacement, then revokes the old key conditionally;
  - when it finds the key already revoked, it revokes the replacement it just issued and returns `ErrRotationRefused`.
  - **Implementers:** memory, pgx, sqlstore, gorm and the storetest fakes.
- **Empty digests.** Issue and Verify refuse an empty digest. `NewManager` probes a consumer digest once: it must be non-empty, and must differ for two different inputs.
- **Override:** the digest stays replaceable; the probe only refuses a broken one.
- **Departure** for M3: the established design rotated whatever it was given.

### 12. Bounded memory fails closed (M8, M9, L15, U5, M10, N-sweep clocks)

**The default attempt store (M8).**
- `NewAccountLockoutPolicy` builds its default store knowing its own longest retention: the window, or the cap's retention.
- The store drops timestamps older than that on each write for the key it touches. Every window it sweeps inline, as `memoryShard` does.
- It caps identifiers at 100,000 (`WithAttemptStoreCapacity`) and digests identifiers over 256 bytes. A capacity of zero or less panics at wiring, since the store's constructor returns no error (as decision 14 does for guards).
- A store shared by several policies keeps what the longest-retaining of them needs: its inline sweep and its purge never drop a failure or streak younger than that retention, so one policy's purge cannot disarm another's lockout.
- Holds are never swept early.
- **When full after a sweep:** recording a new identifier fails, and lockout denies as it does on any store error. This mirrors "a full in-memory limiter refuses new keys". The trade-off is that a flood of distinct usernames denies new usernames' logins until failures age out. A durable or shared attempt store is the override.
- The store implements purge, so the default no longer reports purge-unsupported.
- **Rejected:** evicting counts. That is itself a way to disarm lockout.

**The outage hold (M9, L15).**
- It caps at the in-memory limiter's default key cap and digests long keys.
- When full, a check for a key it does not hold is answered exceeded for the window.
- Its sweep re-arms when the clock steps backwards, the same `now.Before(last)` reset `passkey/login.go` uses. `httpsec/mfabegin.go`'s `sweepClock` gets the same reset.

**The log sampler (U5).** It caps keys per window at 100,000 (option) and counts overflow under one key, so suppression accounting stays exact.

**The OIDC `next` (M10).** A requested destination over 2048 bytes is not recorded, and the login proceeds as if none was requested. OIDC allowlist entries over 2048 bytes fail construction; the bound is an option of the shared allowlist that only the OIDC wiring sets, so other allowlists (magic link) stay unbounded. The bound is fixed, because no allowlist entry can exceed it.

**Departure** for M8: the established default store never forgot.

### 13. A missing time or input denies (M11, L13 policy)

- **The rule.** `Engine.EvaluatePhase` denies a nil input. The idle-timeout, password-age and enrolment-path policies deny a zero `Now`.
- **Why not a clock fallback:** a clock on each policy, as lockout has, adds three options. A forgotten time is a caller bug, and denying surfaces it.
- **Override:** none, because the caller supplies the time.
- **Departure:** the established design failed open.

### 14. Wiring mistakes fail at construction; port results are not trusted (L13, S1, S2, S3, S6, S7, S9, U10, U11)

**Guards.**
- Ownership and resource guards panic at wiring on a nil checker or extractor, in httpsec, fibersec and ginsec.
- **Why panic:** these builders return no error. `net/http`'s `Handle` panics on a nil handler for the same reason. Changing their signatures to return an error would ripple through every consumer's route table.

**Port results.**
- A `(nil, nil)` from a user loader, session store or record store is treated as "not found", never dereferenced. This covers `session.Manager`, `passkey` names and lists, recovery `HasWayBack` and `Finish`, and authenticate.
- A typed-nil credential is unsupported.
- A typed-nil verification key is an unusable key set.

**Durations and names.**
- Token lifetime: a whole number of seconds, at least one.
- OIDC clock-skew leeway: at most 5 minutes.
- Logout max age: at most 1 hour.
- Rate-limit flow names: refused when empty or containing `:`.
- Magic-link and passkey-ceremony cookie TTLs: a whole number of seconds (S9).

**Override:** each bound is a stated limit, and its godoc names it:
- 5 minutes of skew is generous for synchronised clocks. The figure is a judgement, not taken from a standard; RFC 7519 leaves leeway to the implementer;
- 1 hour of logout-token age is the replay window.

### 15. Credential responses are never cached (L12)

- **Where.** `writeSuccessDocument` and the MFA begin responder set `Cache-Control: no-store`, matching the renewal, handoff and recovery responders that already do. RFC 6749 §5.1 requires it for token responses.
- **Override:** a consumer responder owns its headers.
- **Departure:** the established design set no cache header on its login responses.

### 16. Adapters keep the framework's meaning (M12, U6, M13, U1)

- **fibersec (M12, U6).**
  - Errors: `Middleware` captures the error `fc.Next()` returns and passes it back unchanged when the chain returns that same error (`errors.Is`). `ErrorHandler` answers a `*fiber.Error` with its code.
  - Cancellation: the chain runs on a context derived from fiber's request context and cancelled when the request's handling ends. fasthttp gives a handler no disconnect signal (`RequestCtx.Done()` fires only at server shutdown), and watching the socket would race fasthttp's own reads, so a mid-request disconnect is not detected; this is a stated limit in fibersec's godoc (user decision, 2026-10-23, after U6 reproduced).
- **Layout guard (M13).** It runs its file and `go.mod` checks for every workspace module except `./test`. This task follows `release-readiness` 2.1, which also edits `layout_test.go`.
- **gorm (U1).** A read/write-splitting plugin can route a store's reads to a lagging replica, which can serve a revoked session. This is documented as a stated limit in `gorm/doc.go`; no `dbresolver` dependency is added.

### 17. The remaining point fixes

- **L8:** a backed-up state without backup eligibility is refused in the `passkey` core, so a consumer verifier gets it too. It runs after lane E has changed `register.go`.
- **L9:** bcrypt refuses NUL in `Encode` and `Match`. The old 72-byte NUL-padding guard is subsumed.
- **L11:** a delegate's `ErrNoEligibleAuthenticator` counts as a skip. This is a departure; the established design stops at it.
- **L14:** SMTP normalises CRLF, CR and LF each to CRLF. This is a departure; the established design normalised only LF.
- **U4:** with unused-successor recovery on, a failed first-use write fails the load.
- **U8:** the RP ID must be a lowercase DNS name.

### 18. How the work splits

The tasks run in lanes with disjoint file ownership. Ownership follows the call graph: a port change owns every implementer, mock and suite of that port.

**Model choice.** Each lane's model follows `subagent-delegation.md`. Concurrency, security refusal logic and cross-package ports go to Opus; point fixes that a finding fully decides go to Sonnet.

| Lane | Findings | Owns | Model |
|---|---|---|---|
| A | H1, M1, H3, L12, N2's begin call site, L13 core guards, M10 httpsec part, the sentinel registry | `httpsec/` | Opus (A1); Sonnet (A2) |
| B | M12, U6, L13 adapter guards | `fibersec/`, `ginsec/` | Sonnet |
| C | H2, N1, L9, M2, L11, L13 typed-nil | `password/`, `authenticate/` | Sonnet (C1); Opus (C2) |
| D | L3, L4, L5, U3, U12 | the `mfa` store port, `seal/mfa.go`, `seal/aad.go`, its backends and suites | Opus |
| E | L6, L7, N2, passkey begin, L8 | `onetime/`, `magiclink/`, `recovery/start.go`, the `passkey` store and registration, their backends and suites | Opus |
| F | M7, S4, S5, U2 | the store transaction helpers in `pgx`, `sqlstore` and `gorm`; `internal/pgschema` streaks and recovery; `internal/pglimiter` | Opus |
| G | M4, N4, L13 way-back | `recovery/` except `start.go` | Opus |
| H | M5, M6 | `signingkey/` | Opus |
| I | M8, M11, L13 policy, M9, L15, U5, U10 | `policy/`, `internal/unavailable/`, `pkg/logsample/`, `ratelimit/guard.go` | Opus (I1); Sonnet (I2) |
| J | M3, N3, L10, L1, U11, L2, U8, L14, U4, S1, S2, S3, S6, S9, U1, M13 | `apikey/` with its store port; `oidc/`, `authorize/`, `passkey/webauthn/`, `notify/`, `session/`, `token/`, `gorm/doc.go`, the root layout tests | Sonnet; Opus for the `apikey` port |

**Sequencing.**
- **F before E.** Lane E's SQL bounded insert uses F's READ COMMITTED transaction helper and isolation check.
- **D before E.** They share `test/internal/storefix/{races,ambients}.go`, `test/{pgx,sql,gorm}store/broken_test.go` and the suite wiring.
- **The sentinel registry.** Lanes adding a sentinel hand the `status_test.go` row to lane A, which owns `httpsec`.
- **Passkey.** J's passkey part (U8, S3) runs after E, which changes `passkey/register.go`.
- **Layout guard.** J's M13 waits for `release-readiness` 2.1.
- **Everything else runs in parallel:** A, B, C, G, H, I and the rest of J. B starts after A has settled the core guard shape, which B mirrors.

## Risks / Trade-offs

- **[A bounded insert written as a count in the `WHERE`]** It still races under READ COMMITTED. Inside a caller's REPEATABLE READ transaction it over-issues silently.
  → Decision 7's advisory lock and decision 8's isolation check. The race suite runs bounded inserts concurrently on every backend, and the isolation suite runs them under a REPEATABLE READ default.
- **[Way-back reports a pairing M4 now refuses]** A user would believe they have a way back in when they do not, and lock themselves out.
  → Decision 5 changes the way-back check in the same lane and the same task as the shape check.
- **[A key-selection filter drops the newest key]** That would mint a replacement, breaking the spec, or strand a verify-only replica.
  → Decision 9's single predicate always keeps the newest key of a configured algorithm. A restart test covers a 3-day-old sole key.
- **[M2's reference match admits someone]** The reference password is a constant.
  → The result is discarded by construction. A test presents the reference password for a no-hash user and expects refusal.
- **[M1 misses late renewal]** Late renewal bypasses `resolve`.
  → Decision 1 adds the check to `renewal.user()`. A spec scenario renews a disabled user after the window.
- **[U3 breaks MFA for every enrolled user on upgrade]** → Accepted before the tag, and recorded in the CHANGELOG and the `secrets-at-rest` delta. There is no released data.
- **[A full default attempt store denies new users' logins under a username flood]** → Fail-closed by design, consistent with the in-memory limiter. The capacity is an option, and a durable attempt store is the override. Godoc states it.
- **[The cool-down over-matches a real route on net/http or gin]** → Fail-closed, and limited to the cool-down window. Godoc states it.
- **[Port changes ripple into consumer stores]** `onetime.Store`, `passkey.CredentialStore`, the MFA store and `apikey.Store` all change. → They are pre-tag breaks, recorded in the CHANGELOG. The shared conformance suites tell a consumer's store exactly what to implement.
- **[Stored hashes or bcrypt passwords beyond the new rules stop matching]** → Rare: the defaults are far below the ceilings, and NUL in a password needs a deliberate `\u0000`. Affected users reset their password, and the CHANGELOG says so.

## Migration Plan

- **Schema:** none. The bounded inserts use advisory locks over existing indexes.
- **Data, all pre-tag breaks recorded in `CHANGELOG.md` under `Unreleased`:**
  - sealed TOTP secrets need re-enrolment;
  - hashes above the ceilings, or bcrypt passwords with NUL, need a password reset.
- **Rollback:** this change lands before any tag, so rolling back is reverting the branch.

## References

**Researched (accessed 2026-10-23):**
- [NIST SP 800-63B-4 §3.1.3.1, Out-of-Band Devices](https://pages.nist.gov/800-63-4/sp800-63b.html): email SHALL NOT be used for out-of-band authentication, while email recovery codes are exempt as not authentication (decision 5).
- [NIST SP 800-63B-4 §4.2.2, Recovery at AAL2](https://pages.nist.gov/800-63-4/sp800-63b.html): recovery needs two recovery codes of different methods, or one recovery code plus a bound single-factor authenticator. It sets no rule on channel separation, which is why scrty states its own (decision 5).

**Primary documentation:**
- [W3C Web Authentication Level 3, §6.1 Authenticator Data (BE/BS flags)](https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data): the backup state may be set only when backup eligibility is set (decision 17, L8).
- [RFC 6749 §5.1, Successful Response](https://www.rfc-editor.org/rfc/rfc6749#section-5.1): token responses carry `Cache-Control: no-store` (decision 15).
- [RFC 6238, TOTP](https://www.rfc-editor.org/rfc/rfc6238): the time step is an integer number of seconds (decision 10).
- [RFC 5321 §2.3.8 and §4.1.1.4](https://www.rfc-editor.org/rfc/rfc5321): lines end in CRLF, and a bare CR must not be sent (decision 17, L14).
- [RFC 1035 §2.3.4 and RFC 1123 §2.1](https://www.rfc-editor.org/rfc/rfc1123#section-2.1): DNS label and name length and character rules (decision 17, U8).
- [PostgreSQL: Transaction Isolation](https://www.postgresql.org/docs/current/transaction-iso.html): at REPEATABLE READ, a snapshot is taken at the first statement and a concurrent update raises a serialization failure (decisions 7, 8).
- [PostgreSQL: Advisory Locks](https://www.postgresql.org/docs/current/explicit-locking.html#ADVISORY-LOCKS): transaction-level advisory locks release at commit (decision 7).
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html): bcrypt work factor of 10 or more, and the 72-byte limit (decision 2).

**Reasoned from scrty's own settled specs and the established design:** decisions 1, 3, 4, 6, 9, 11, 12, 13, 14, 16 and 18.
