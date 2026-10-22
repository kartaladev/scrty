## Why

An application that signs its own users in, with no external identity provider, needs sessions it can run at scale: hand to a mobile client as an opaque bearer, renew without dropping requests already in flight, and size per login ("remember me"). Today each of these takes a workaround outside the library. The workarounds are a hand-written verifier that loads every session twice, rotation that deletes the old identifier at once, and lifetimes shortened after creation. And every authenticated request writes the session back to the store. A first consumer is adopting the library on exactly this model, multi-replica over shared PostgreSQL, and is blocked on these gaps.

## What Changes

- **Coalesced activity writes.**
  - A manager option sets a minimum interval between activity writes, so a session in constant use is written once per interval, not once per request.
  - The idle deadline is never kept later than the exact one: a skipped write can only bring expiry earlier, by at most the interval.
  - The default stays a write on every request.
  - Activity is recorded by a narrow store write of the activity fields only, conditional on the stored record being older than the interval, so replicas do not all write and a stale activity write cannot overwrite other fields. **BREAKING** for consumer-written session stores: the store port gains methods. Nothing is tagged yet.
- **Rotation with a grace window and reuse detection.**
  - A new rotation keeps the old identifier usable for a bounded grace window, then refuses it.
  - Sessions carry a family. An identifier presented after its grace window, while its family is still live, is treated as stolen: the whole family is revoked, and the reuse is reported.
  - A second renewal with the same old identifier inside its grace window issues a fresh successor and supersedes the previous one, so a lost renewal response is recoverable and a race with a thief is still detected.
  - An opt-in recovery treats a superseded identifier whose successor was never presented as a lost response, not as theft, and rotates it again. Detection then happens on the second presentation instead of at the window's end.
  - Supersession is a conditional, atomic store operation, so two replicas cannot both win.
  - A renewal carries the absolute deadline over by default. An option gives the successor a new lifetime, bounded by the lifetime maximum and by a family maximum counted from the sign-in that started the family. The family maximum is finite, and it is the overall reauthentication limit.
  - The existing rotation at second-factor verification is unchanged, except that its successor stays in the family.
- **Per-session absolute lifetime.** A creation option sets one session's absolute lifetime, bounded by a manager maximum that defaults to the absolute timeout. A lifetime above the maximum is refused, never silently shortened. Login gains a way to choose the lifetime from the parsed login request.
- **Opaque session-reference bearer.**
  - A built-in authentication mode in which the bearer value is the session identifier itself: no signed token and no signing keys.
  - The user is reloaded by the reference the session records.
  - Its steps (load the session, reload the user, publish, run the per-request policy phase, record activity) are a shared core that the cookie mode planned in `bff-resource-server` will reuse.
  - A chain runs one bearer mode, and enabling both is a configuration error.
- **A session renewal endpoint.**
  - A built-in endpoint rotates the presented session with the grace window and hands back the new reference through a replaceable responder. The responder receives the successor, the user and the kind of renewal.
  - A minimal reuse observer port reports detected reuse.
- **Exported publication for consumer interceptors.**
  - An exported way to publish the resolved session, alongside the caller.
  - A helper that runs the per-request policy phase with the same challenge handling the built-ins use.
  - Together these honour the chain's promise that a consumer interceptor has everything a built-in has.
- **Schema.** A security-state migration adds the family and supersession columns, and the sweep keeps superseded records until their family's absolute deadline.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `sessions`:
  - the coalesced activity requirement;
  - the per-session absolute lifetime and its maximum;
  - rotation with a grace window, session families and reuse detection;
  - the reuse observer;
  - the new superseded and reused errors.
- `security-state-stores`: durable stores persist the family and supersession, record activity with a narrow conditional write, supersede atomically under concurrency, revoke a family, keep a superseded record's retention deadline apart from its own deadlines and sweep it only once that passes, and end a user's other sessions while keeping the presenting sign-in.
- `store-conformance`: the session suite covers the new store operations, including the supersession race.
- `schema-migrations`: the security-state migration set gains the new session columns (family, family creation time, supersession, retention deadline, successor digest, first presentation, authentication time) and indexes.
- `passkey-authentication`: removing a passkey with a renewed session keeps that sign-in's current session.
- `http-security-chain`:
  - the opaque session-reference bearer and its shared steps;
  - the session renewal endpoint;
  - login-chosen session lifetime;
  - exported session publication and the per-request phase helper;
  - the rule that one chain runs one bearer mode.
- `http-error-propagation`: the renewal endpoint's refusals, and the superseded and reused outcomes, map to status codes.

## Impact

- **Changed code:**
  - `session` (manager, options, store port, memory store, encrypted wrapper);
  - `passkey` (session revocation on removal);
  - `httpsec` (a new bearer mode, renewal endpoint, login option, exported helpers, activity interceptor);
  - `internal/pgschema`, `sqlstore`, the `pgx` and `gorm` modules;
  - `migrate/securitystate`;
  - `test/storetest` and its runners.
- **Compatibility:** the session store port gains methods, so consumer-written stores must implement them. Nothing is tagged, so this is recorded and not versioned. Today's defaults (a write on every request, the global absolute timeout, the signed-token bearer) are unchanged.
- **Related changes:**
  - `bff-resource-server` builds its cookie mode on the shared session-reference core introduced here, and keeps cookie handling and CSRF;
  - `trusted-proxy-client-ip` is independent;
  - releasing the modules is a separate change.
- **Dependencies:** none added.
