## Context

See proposal.md for why. The code as it stands:

- **Request reads.** The framework-neutral `httpsec.Request` has `FormValue`, which keeps each framework's own semantics, and `Body(limit)`, which returns only the body. Every library credential read already goes through `Body` (form login, magic link, handoff redemption, back-channel logout, logout state, the enrolment endpoints), except the verify endpoint (`httpsec/mfaverify.go`), which calls `FormValue("code")`. The enrolment endpoints read through a private helper, `postedField` (`httpsec/mfaenrol.go`): body only, parsed only when it declares `application/x-www-form-urlencoded`, a parse error or an absent field refused as `ErrCredentialsMissing` (400).
- **Adapter precedence.** net/http's `FormValue`, which gin reuses, prefers the posted form and falls back to the query. fibersec's calls fiber's `c.FormValue`, which searches the query first (`fibersec/exchange.go`).
- **Samplers.** `pkg/logsample` samplers are built in 13 places. `Chain.FlushRefusalLogs` reaches two: the chain's own and the enrolment path's. The others:

| Owner | Built by | Flush today | Reachable |
|---|---|---|---|
| `mfa.VerifyThrottle` | the chain, in `EnableMFA`'s wiring | `FlushRefusalLogs() error` | no: held privately by the verify interceptor |
| `ratelimit.SourceGuard` (API key, magic link, OIDC handoff) | the chain, or given by the consumer | `Flush()` | no: behind a private `sourceGuard` seam that omits it |
| `oidc.Manager`, `oidc.HandoffManager`, `oidc.Broker` | the consumer | none | no method exists |
| password authenticator | the consumer | `FlushRefusalLogs() error` through `authenticate.RefusalLogFlusher` | only if the consumer kept it |
| `policy` MFA and requirement policies | the consumer | `FlushRefusalLogs() error` through `policy.RefusalLogFlusher` | only if the consumer kept them |
| `signingkey.KeyManager` | the consumer | flushes when its loops stop | through `Stop` |

- **The spec already promises the pieces.** `rate-limiting` says a guard's suppressed counts are reported "when the key ages out or the guard is flushed"; `security-policy` says each refusal-logging policy exposes a flush; `oidc-login` requires sampled refusal logs with a reporter but no flush.

## Goals / Non-Goals

**Goals:**
- No library credential read accepts the URL query, on any adapter.
- One call at shutdown reports every suppressed count the chain can reach.
- `FormValue` means the same thing on every adapter.

**Non-Goals:**
- Redacting error text and identifiers in logs or returned errors (`log-redaction`).
- Folding the other, already body-only readers into the shared helper. They differ in details (JSON support in login and magic link, different fields), and they are correct; unifying them is a refactor with no behaviour to gain.
- A general "flushable" registry the consumer can add arbitrary components to.
- Changing `signingkey.KeyManager`, which already flushes when it stops.

## Decisions

### 1. The verify endpoint reads its code through the shared body-only reader

- **Rule:** `code` is read from a URL-encoded POST body only. Absent, empty, not a URL-encoded form, or unparseable: `ErrCredentialsMissing` (400), returned before the throttle records anything and before the method is asked. A body over the limit: `ErrRequestTooLarge` (413), as the enrolment endpoints.
- **Order:** the throttle's check (is this user already locked out) still runs before the code is read, as today, so a locked-out user learns nothing new; only the recording of a failure moves behind the read.
- **Helper:** `postedField` moves from `mfaenrol.go` to a file of its own in `httpsec` and keeps its signature; the enrolment endpoints and the verify endpoint call it.
- **Default:** body only. **Override:** none. A query or multipart code has no legitimate use that outweighs a code in access logs, and a consumer who wants another encoding puts their own interceptor in front of the endpoint. The godoc of `EnableMFA` states the limit, as `EnableMFAEnrolment`'s does.
- **Alternative rejected:** accepting multipart as well. It widens the parser the endpoint exposes and gains nothing a browser form or client needs; form login already refuses multipart for the same reason.
- **Status:** the claim that `POST /mfa/totp?code=…` verifies is `UNREPRODUCED` (found by reading). Its reproducing test is the first red step; if it passes on the unchanged code, the claim was wrong and this decision is dropped.

### 2. fiber's `FormValue` prefers the posted form

- **Rule:** fibersec's `FormValue(name)` returns the URL-encoded or multipart posted value when present, and the query value otherwise, matching net/http's documented precedence.
- **How:** read the posted arguments and fiber's parsed multipart form first (within the app's `BodyLimit`, as today), then the query arguments; never call `c.FormValue`, whose order is the one being replaced.
- **Default:** body before query, on every adapter. **Override:** a consumer interceptor that wants the query reads `Query`; one that wants the body alone reads `Body`. Both exist on the abstraction.
- **Why here:** after decision 1 no library code calls `FormValue`, but the `framework-adapters` promise is that every adapter produces the same outcome, and a consumer interceptor reading a field is the case that promise exists for.
- **Status:** the precedence difference is `UNREPRODUCED` (from fiber's documentation and the adapter's own comment). The first task's conformance scenario reproduces it.

### 3. `Chain.FlushRefusalLogs` reaches every sampler the chain holds

- **What it flushes**, in this order, ignoring the errors that the component flushes are documented never to return:
  1. its own sampler;
  2. each registered interceptor that can flush: the enrolment interceptor (as today), the verify interceptor (its throttle), and the interceptors that hold a source guard;
  3. the policy engine, through a new `(*policy.Engine).FlushRefusalLogs()` that flushes every registered policy implementing `policy.RefusalLogFlusher`, including policies added after the chain was built;
  4. the authenticators of form login and basic authentication, when they implement `authenticate.RefusalLogFlusher`;
  5. the OIDC manager and handoff manager given to `EnableOIDCLogin` (decision 4).
- **How the chain finds them:** each interceptor that holds a flushable component implements a small unexported interface (`refusalLogFlusher`), and the chain walks its registrations. The private `sourceGuard` seam gains `Flush()`, which the real guard already has.
- **A guard the consumer supplied is flushed too.** Flushing reports pending counts and forgets keys; a second flush of a guard shared between chains reports nothing twice.
- **Signature unchanged:** `FlushRefusalLogs()` still returns nothing. The component flushes that return an error document that they never do; a future one that can fail would change that.
- **Default:** one call reaches everything above. **Override:** a consumer who flushes components individually still can; the calls are idempotent.
- **Godoc:** rewritten to list exactly what is reached, and to name what is not: a component the consumer holds but never handed the chain, and `signingkey.KeyManager`, which flushes when its loops stop.
- **Alternative rejected:** exporting accessors for the throttle and guards so the consumer flushes them. It exposes internals to solve a problem the chain can solve alone.

### 4. The OIDC components flush their own samplers

- **API:** `(*oidc.Manager).FlushRefusalLogs() error`, `(*oidc.HandoffManager).FlushRefusalLogs() error`, `(*oidc.Broker).FlushRefusalLogs() error`, matching the shape `authenticate` and `policy` already use. Each flushes its sampler and returns nil.
- **The manager flushes its broker** when the `IdentityBroker` it was given implements the flush, so a consumer holding only the manager reaches the broker.
- **Default:** none is called until a flush is asked for. **Override:** a consumer calls them directly, or relies on the chain (decision 3).

### 5. Ordering with `mfa-enrolment-path`

Both changes modify the verify-endpoint requirement of `multi-factor-auth`. `mfa-enrolment-path` cannot archive before `durable-persistence` does, so this change is expected to archive first. Whichever archives second updates its MODIFIED text to include the other's before archiving; the task list of this change and the Impact section of both changes say so.

## Risks / Trade-offs

- [A client posting the verify code as multipart, JSON or in the query breaks] → **BREAKING**, stated in the proposal and godoc. Nothing is tagged; the enrolment endpoints and form login already require a URL-encoded body, so clients already do this for every other credential.
- [A consumer fiber interceptor relied on the query winning] → **BREAKING** on fiber only. The abstraction's godoc states the precedence, and `Query` still reads the query.
- [Flushing a component the consumer also flushes] → Idempotent: the second flush reports nothing pending.
- [A policy that implements a flush with side effects beyond reporting] → The flush contract (`security-policy`, `log-sampling`) is report-then-forget; the chain relies on nothing more.
- [Reading multipart in fiber's `FormValue` parses the body] → Unchanged from today's `c.FormValue`, which already parses it under the app's `BodyLimit`.

## Migration Plan

Not applicable: no consumers and no tags. Clients of the verify endpoint post `code=<digits>` as `application/x-www-form-urlencoded`.
