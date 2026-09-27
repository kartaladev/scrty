## Context

See proposal.md for why. The code as it stands:

- **Request reads.** The framework-neutral `httpsec.Request` has `FormValue`, which keeps each framework's own semantics, and `Body(limit)`, which returns only the body. Every library credential read already goes through `Body` (form login, magic link, handoff redemption, back-channel logout, logout state, the enrolment endpoints), except the verify endpoint (`httpsec/mfaverify.go`), which calls `FormValue("code")`. The enrolment endpoints read through a private helper, `postedField` (`httpsec/mfaenrol.go`): body only, parsed only when it declares `application/x-www-form-urlencoded`, a parse error or an absent field refused as `ErrCredentialsMissing` (400).
- **Adapter precedence.** net/http's `FormValue`, which gin reuses, prefers the posted form and falls back to the query. fibersec's calls fiber's `c.FormValue`, which searches the query first (`fibersec/exchange.go`).
- **Samplers.** `pkg/logsample` samplers are built in 13 places. `Chain.FlushRefusalLogs` reaches two: the chain's own and the enrolment path's. The others:

| Owner | Built by | Flush today | Reachable |
|---|---|---|---|
| `mfa.VerifyThrottle` | the chain, in `EnableMFA`'s wiring | `FlushRefusalLogs() error` | no: held privately by the verify interceptor |
| `ratelimit.SourceGuard` (API key, magic link, OIDC handoff) | the chain (over a consumer-supplied limiter when one is given) | `Flush()` | no: behind a private `sourceGuard` seam that omits it |
| `oidc.Manager`, `oidc.HandoffManager`, `oidc.Broker` | the consumer | none | no method exists |
| password authenticator | the consumer | `FlushRefusalLogs() error` through `authenticate.RefusalLogFlusher` | only if the consumer kept it |
| `policy` MFA and requirement policies | the consumer | `FlushRefusalLogs() error` through `policy.RefusalLogFlusher` | only if the consumer kept them |
| `signingkey.KeyManager` | the consumer | flushes when its loops stop | through `Stop` |

- **The spec already promises the pieces.** `rate-limiting` says a guard's suppressed counts are reported "when the key ages out or the guard is flushed"; `security-policy` says each refusal-logging policy exposes a flush; `oidc-login` requires sampled refusal logs with a reporter but no flush.

## Goals / Non-Goals

**Goals:**
- No library credential read accepts the URL query, on any adapter, apart from the OIDC authorization response, whose `code` and `state` the protocol delivers in the query.
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
- **How:** parse the posted form from the request body with the same rules as the net/http adapter (see the bullets below: method gating, media-type parsing, the form caps, `url.ParseQuery`), then fall back to the query; never call `c.FormValue`, whose order is the one being replaced.
- **Default:** body before query, on every adapter. **Override:** a consumer interceptor that wants the query reads `Query`; one that wants the body alone reads `Body`. Both exist on the abstraction.
- **Why here:** after decision 1 no library code calls `FormValue`, but the `framework-adapters` promise is that every adapter produces the same outcome, and a consumer interceptor reading a field is the case that promise exists for.
- **Only methods that carry a form read the body.** net/http fills the posted form only for POST, PUT and PATCH, and reads the query alone for any other method; fasthttp's posted arguments read the body whatever the method. So fiber reads the body only for POST, PUT and PATCH, and a GET or DELETE with a body answers from the query on every adapter (reproduced in review: with the fiber fix alone, a GET carrying `x=body` in its body and `x=query` in its URL answered `body` on fiber and `query` on net/http).
- **Reading a field does not consume the body.** net/http's form parsing drains the request body, so on that adapter a `Body` call after `FormValue` read nothing, while fiber still returned it (predating this change, found in review). The net/http adapter now parses the form from the body it has already buffered, so `Body` and `FormValue` can be called in either order on every adapter.
- **A field read never loosens a body limit.** The first repair of the bullet above made `FormValue` read through the net/http adapter's body cache with a 32 MiB cap; because that cache's first read decides, a consumer interceptor calling `FormValue` first widened every later library read (the 4 KiB credential-field reader, login's 64 KiB) to 32 MiB, and on a multipart upload over the cap it consumed the body without restoring it (both reproduced in review). The rule now: on both adapters, a `FormValue` read never decides what a later `Body(limit)` answers. On net/http it reads through the same buffer `Body` uses, which keeps the bytes but not an answer, and a read that stops at the form cap restores what it read, so every later `Body(limit)` applies its own limit; a `Body` call that refuses a body as too large also restores what it consumed, so a later reader still sees the whole request.
- **Every body read judges its own limit, on every adapter.** The net/http adapter remembered its first `Body` answer and returned it to every later call, whatever that call's limit ("first call decides"): a consumer interceptor calling `Body(64 KiB)` first made the 4 KiB credential-field reader accept an 8 KiB body, and after a refused small read a larger read was refused too, while fiber judged each call on its own (both predating this change, reproduced in review). The rule now matches fiber: each `Body(limit)` call refuses a body longer than its own limit, whatever an earlier call read or refused. The net/http adapter still keeps the bytes it has read so the body is read from the network once, and a refused read gives its bytes back so a later, larger read can succeed. A transport error is the exception: it is remembered and returned to every later read, because net/http reports an early end of body only once, and re-reading after it would accept the partial body as complete (reproduced in review). `Body` returns a copy of the bytes, so no caller can change what a later reader sees, and a limit at the largest integer is read without overflowing. Rejected: remembering a refusal on fiber too, which needs per-request state the adapter does not have, and protects nothing once each read enforces its own limit.
- **The form read has its own caps, and its failures fall back to the query.** `FormValue` reads at most 10 MiB of a URL-encoded body and 32 MiB of a multipart one, the standard library's defaults. A larger body, a content type that does not parse as a media type, or a body that does not parse, answers from the query, on both adapters. Both adapters judge the content type with `mime.ParseMediaType` and parse URL-encoded bodies with the same parser, so they agree on case, parameters and malformed input. A consumer that needs a field from a larger upload parses the body itself; godoc states the caps.
- **Status:** the precedence difference is reproduced by task 2.1's conformance scenario: with `x=body` in a URL-encoded body and `x=query` in the query, fiber answered `query` while net/http and gin answered `body`.
- **Multipart, found while implementing:** net/http's `FormValue` documents that body values take precedence over the query, but for a multipart body its implementation appends the multipart values after the query's, so the query wins; gin inherits it. A multipart row therefore answered `query` on net/http and gin and, after the fiber fix, `body` on fiber: the adapters still disagreed. The rule stays as stated (posted form, URL-encoded or multipart, before the query), and the net/http and gin adapters now read the posted form explicitly before falling back to the query, instead of delegating to `http.Request.FormValue`, so all three agree with the documented rule. Rejected: copying net/http's multipart order into fiber, which would keep a behaviour that contradicts both net/http's own documentation and this rule. The change affects only a field present in both a multipart body and the query; no library endpoint reads `FormValue`.

### 3. `Chain.FlushRefusalLogs` reaches every sampler the chain holds

- **What it flushes**, ignoring the errors that the component flushes are documented never to return:
  1. its own sampler;
  2. each registered interceptor that can flush: the enrolment interceptor (as today), the verify interceptor (its throttle), and the interceptors that hold a source guard;
  3. the policy engine, through a new `(*policy.Engine).FlushRefusalLogs()` that flushes every registered policy implementing `policy.RefusalLogFlusher`, including policies added after the chain was built;
  4. the authenticators of form login and basic authentication, when they implement `authenticate.RefusalLogFlusher`;
  5. the OIDC manager and handoff manager given to `EnableOIDCLogin` (decision 4).

  The order is its own sampler first, then each registered built-in (items 2, 4 and 5) in the order the chain runs them, then the policy engine last. The order has no observable effect: each flush reports only its own pending counts.
- **How the chain finds them:** each interceptor that holds a flushable component implements a small unexported interface (`refusalLogFlusher`), and the chain walks its registrations. The private `sourceGuard` seam gains `Flush()`, which the real guard already has.
- **Every guard is the chain's own.** The chain builds each source guard itself; a consumer supplies at most the limiter behind it (`WithAPIKeyLimiter`, `WithMagicLinkLimiter`, `WithHandoffLimiter`), so there is no consumer-supplied guard to reach. A component that is shared between chains, such as an authenticator given to form login on one chain and to Basic on another, is flushed by both; flushing reports pending counts and forgets keys, so the second flush reports nothing twice.
- **Signature unchanged:** `FlushRefusalLogs()` still returns nothing. The component flushes that return an error document that they never do; a future one that can fail would change that.
- **Default:** one call reaches everything above. **Override:** a consumer who flushes components individually still can; the calls are idempotent.
- **Godoc:** rewritten to list exactly what is reached, and to name what is not: a component the consumer holds but never handed the chain, and `signingkey.KeyManager`, which flushes when its loops stop.
- **Alternative rejected:** exporting accessors for the throttle and guards so the consumer flushes them. It exposes internals to solve a problem the chain can solve alone.

### 4. The OIDC components flush their own samplers

- **API:** `(*oidc.Manager).FlushRefusalLogs() error`, `(*oidc.HandoffManager).FlushRefusalLogs() error`, `(*oidc.Broker).FlushRefusalLogs() error`, matching the shape `authenticate` and `policy` already use. Each flushes its sampler and returns nil.
- **The manager flushes its broker** when the `IdentityBroker` it was given implements the flush, so a consumer holding only the manager reaches the broker.
- **Default:** none is called until a flush is asked for. **Override:** a consumer calls them directly, or relies on the chain (decision 3).

### 5. Ordering with `mfa-enrolment-path`

Both changes modify the verify-endpoint requirement of `multi-factor-auth`. `mfa-enrolment-path` archived first (after `durable-persistence`), so this change's MODIFIED verify requirement carries its promoted text (the enrolment-path deadline restore, "only by this endpoint", and the scenarios "Upgrade from the enrolment path" and "Confirmation alone is not a second factor") and adds only the body-only read. Task 5.1 did that.

## Risks / Trade-offs

- [A client posting the verify code as multipart, JSON or in the query breaks] → **BREAKING**, stated in the proposal and godoc. Nothing is tagged; the enrolment endpoints and form login already require a URL-encoded body, so clients already do this for every other credential.
- [A consumer fiber interceptor relied on the query winning] → **BREAKING** on fiber only. The abstraction's godoc states the precedence, and `Query` still reads the query.
- [Flushing a component the consumer also flushes] → Idempotent: the second flush reports nothing pending.
- [A policy that implements a flush with side effects beyond reporting] → The flush contract (`security-policy`, `log-sampling`) is report-then-forget; the chain relies on nothing more.
- [A form read can hold up to about 64 MiB of a multipart body in memory (the 32 MiB cap plus the parts `ReadForm` keeps in memory)] → Bounded by the form caps on both adapters, within fiber's `BodyLimit`, and stated in godoc; a consumer needing a field from a larger upload parses it itself.

## Migration Plan

Not applicable: no consumers and no tags. Clients of the verify endpoint post `code=<digits>` as `application/x-www-form-urlencoded`.
