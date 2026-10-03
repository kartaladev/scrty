## Why

Wiring scrty's many components by hand is repetitive and easy to get subtly wrong:
- a durable session store next to an in-memory key store;
- a key manager that is never started;
- a sweeper that is never shut down;
- a shared rate-limiter factory that some flows receive and others do not.

Applications that already use a DI container want one call that composes the plain constructors with safe defaults. They also want it to fail loudly when the composition is contradictory.

This change was split out of `operation-hardening` so that container wiring can be designed with every seam it composes, and applied on its own schedule. **It is not scheduled for implementation.** Other changes may name its seams; none depends on it to ship.

## What Changes

- Add the nested, **optional** module **`github.com/kartaladev/scrty/do`**, which registers scrty's components with `samber/do` by calling the plain constructors:
  - by default it wires in-memory security stores;
  - when a database is registered, it wires the durable adapters and the default identity store, unless the consumer registered their own identity ports;
  - any component the consumer registers or overrides replaces the default;
  - contradictory wiring fails at registration or at start, with a message that names the component and the option. Examples are more than one database backend, missing identity ports, and a durable store without a sealer;
  - it does not apply or check migrations. The consumer applies them before deploying;
  - it warns when in-memory security stores, and in particular the in-memory signing-key store, are used where the deployment may run more than one replica;
  - building the container starts nothing. An explicit start runs key rotation and, when an interval is configured, the scheduled sweeper. Container shutdown stops them in reverse order and flushes refusal-log counts.
- **Shared rate limiting is an explicit choice.** A `ratelimit.LimiterFactory` the consumer registers reaches every flow that accepts one, and is verified at start. Registering a database never switches rate limiting to a shared backend by itself.

## Capabilities

### New Capabilities

- `di-wiring`: optional container wiring of scrty's components. Covers:
  - default composition, durable composition and the default identity store;
  - consumer overrides;
  - wiring errors and when they surface;
  - the schema being left to the consumer;
  - in-memory store warnings;
  - start and shutdown of background work;
  - the explicit selection of a shared rate-limiter factory.

### Modified Capabilities

None.

## Impact

- **New module:** `github.com/kartaladev/scrty/do`, which depends on `samber/do` v2, the `sweep` module, and the core module's `sqlstore` package. It is added to `go.work`, to the dependency guard and to the CI matrix. The core module gains no dependency.
- **Depends on:**
  - `operation-hardening` (`expiry-sweeping`): the expiry runner, task constructors and the `sweep` module;
  - `shared-rate-limiting` (`rate-limiting`): the limiter factory port;
  - `security-state-stores` (durable-persistence) and `default-identity-store`;
  - `log-sampling` and `module-layout` (project-foundation);
  - every constructor it composes.
- **Consumers:** none yet. Nothing is tagged, so every default here is recorded as a decision, not a compatibility obligation.
