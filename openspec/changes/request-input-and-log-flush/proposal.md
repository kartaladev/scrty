## Why

An audit of every request read and every log sampler found two gaps that the enrolment work had already closed for its own endpoints but left open elsewhere:
- **A second-factor code can arrive in the URL.** The verify endpoint reads `code` through `Request.FormValue`, which merges the URL query into the form. `POST /mfa/totp?code=123456` verifies on every adapter, and on fiber a code in the query even wins over one in the body. A URL reaches access logs, proxy logs, APM traces and the Referer header. A missing or unreadable code is also charged as a wrong guess, so a client that posts multipart can lock its user out of verification. It is the only credential read in the library that still accepts the query, apart from the OIDC authorization response, whose `code` and `state` the protocol delivers in the query.
- **Suppressed log counts are lost at shutdown.** `Chain.FlushRefusalLogs` flushes the chain's sampler and the enrolment sampler only. Five samplers can be flushed by nobody: the MFA verification throttle and the per-flow source guards, which the chain builds and holds privately, and the three OIDC components (manager, handoff manager, broker), which have no flush at all. The godoc of `FlushRefusalLogs` says otherwise in several places.

Both are cheap to fix now, before the first tag, while changing a default costs nothing.

## What Changes

- **The verify endpoint reads `code` from a URL-encoded POST body only.** A code in the query is ignored. A body that carries no code, is not a URL-encoded form (multipart and JSON included) or does not parse is refused as missing credentials (400) and is not charged against the verification throttle. The enrolment endpoints' body-only reader becomes a shared helper both use. **BREAKING** for a client that posts the verify code as multipart, JSON or in the query.
- **fiber reads a form field with the same precedence as net/http.** `Request.FormValue` on the fiber adapter looks in the posted form first and falls back to the query, as net/http and gin do; today fiber looks in the query first. This affects only consumer interceptors that call `FormValue`; no library endpoint does after this change. **BREAKING** on fiber for a consumer interceptor that relied on the query winning.
- **One call flushes every sampler the chain holds.** `Chain.FlushRefusalLogs` flushes, in addition to what it flushes today:
  - the MFA verification throttle it built;
  - every source guard it holds, for API keys, magic links and OIDC handoff redemption;
  - every component handed to it that can flush its refusal logs: the policies registered on its engine, the form-login and basic authenticators, and the OIDC manager and handoff manager.
- **Every adapter reads the body and form fields by the same rules.** Found while implementing: the net/http adapter (which gin uses) no longer delegates `FormValue` to net/http, whose multipart order put the query first; it reads the posted form itself, only for POST, PUT and PATCH, within 10 MiB URL-encoded and 32 MiB multipart caps, and a larger or unparseable body answers from the query. Its `Body` judges every call's own limit, where the first call used to decide for every later one, so a consumer read can no longer widen a library endpoint's body limit; it returns a copy, and remembers a transport failure. Fiber parses the form by the same rules.
- **The OIDC components can flush their refusal logs.** `oidc.Manager`, `oidc.HandoffManager` and `oidc.Broker` gain `FlushRefusalLogs() error`; a manager also flushes the broker it was given when that broker can flush.
- **The `FlushRefusalLogs` godoc states exactly what it reaches**, and names what it does not: a component the consumer holds but never gave the chain, and `signingkey.KeyManager`, which flushes when it stops.

Not in this change: redacting error text and identifiers in logs and returned errors (the separate `log-redaction` change), and folding the other body readers (form login, magic link, handoff redemption, back-channel logout, logout state) into the shared helper. Those readers already refuse the query.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `multi-factor-auth`: the verify endpoint reads the code from a URL-encoded POST body only, and refuses an absent or unreadable code as missing credentials without charging the throttle.
- `framework-adapters`: every adapter reads a form field with the same precedence, the posted form before the query.
- `http-security-chain`: flushing the chain's refusal logs reaches every sampler the chain holds, including those of the components handed to it.
- `oidc-login`: the manager, the handoff manager and the broker expose a flush of their refusal logs.

## Impact

- **Code:** `httpsec` (verify endpoint, shared body reader, the net/http adapter's `Body` and `FormValue`, `FlushRefusalLogs` and its godoc, the source-guard seam), `fibersec` (`FormValue`), `oidc` (a flush on three types), and tests in each. `mfa`, `ratelimit`, `policy` and `authenticate` already expose the flushes the chain will call.
- **Behaviour:** the two **BREAKING** items above. Nothing is tagged and there are no consumers yet.
- **Other changes:** `mfa-enrolment-path` also modifies the verify-endpoint requirement of `multi-factor-auth`. `mfa-enrolment-path` archived first, so this change's MODIFIED requirement carries its text; `design.md` records the order.
- **Dependencies:** none new.
