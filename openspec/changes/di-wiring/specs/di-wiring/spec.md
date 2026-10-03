## Purpose

Lets an application that uses a dependency-injection container obtain all of scrty's components in one call, with the same safe defaults the plain constructors have. Consumer registrations take precedence, contradictions surface before traffic, and background work starts and stops only through the container's lifecycle.

## ADDED Requirements

### Requirement: Container wiring is optional and adds no behaviour
Container wiring SHALL be an optional integration. Every component SHALL remain constructible without it. Each component the wiring provides SHALL be built by calling that component's plain constructor with the options the consumer passed through the wiring. A component obtained from the container SHALL behave identically to the same component built directly with the same options. Optional features (magic link, MFA, API keys, OIDC) SHALL be provided only when the consumer configures them.

#### Scenario: Same behaviour as the constructor
- **WHEN** a session manager is obtained from the container configured with a 10-minute idle timeout, and another is built directly with a 10-minute idle timeout over the same store
- **THEN** both expire an idle session at the same instant and return the same errors for the same inputs

#### Scenario: Optional feature not configured
- **WHEN** the consumer registers the wiring without magic-link options
- **THEN** no magic-link component is provided by the container

### Requirement: Default wiring uses in-memory security stores
When no database backend is registered, the wiring SHALL provide each security-state store as its owning component's in-memory default. It SHALL provide no identity ports of its own. Obtaining a component that needs a user loader when none is registered SHALL fail with an error that names the missing port and both ways to supply it.

#### Scenario: Minimal wiring
- **WHEN** the consumer registers their own identity ports and the wiring with no other options
- **THEN** sessions, signing keys, login attempts and one-time tokens are held in memory

#### Scenario: No identity ports
- **WHEN** the consumer registers the wiring with no identity ports and no database, and obtains the authentication manager
- **THEN** it fails with an error naming the user loader port, registering one's own identity ports, and registering a database for the default identity store

### Requirement: A registered database selects durable stores and the default identity store
When a database backend is registered, every security-state store SHALL be taken from that backend. The backend is either a database handle, which gets the built-in adapters, or a consumer-registered set of stores built with another adapter. When a database handle is the backend and the consumer registered none of the identity ports, the default identity store SHALL provide all of them. Registering more than one backend SHALL fail at start and name both. A durable backend without a configured sealer SHALL fail at start with an error naming the sealer option, and SHALL NOT first fail when a request is served.

#### Scenario: Database handle registered
- **WHEN** the consumer registers a database handle, a sealer and the wiring, and starts the container
- **THEN** sessions, signing keys, login attempts, one-time tokens, MFA enrolments, API keys and OIDC links, flows and handoffs are read and written in that database
- **AND** users and roles are loaded from the default identity store

#### Scenario: Consumer's own identity ports with a database
- **WHEN** the consumer registers a database handle, a sealer and their own user loader, role loader, user provisioner and MFA requirement lookup
- **THEN** the durable security-state stores are used and the default identity store is not

#### Scenario: Consumer store set from another adapter
- **WHEN** the consumer registers a store set built with a different adapter, plus a sealer, and no database handle
- **THEN** every security-state store comes from that set

#### Scenario: Two backends
- **WHEN** the consumer registers both a database handle and a store set, and starts the container
- **THEN** start fails with an error naming both backends

#### Scenario: Missing sealer
- **WHEN** the consumer registers a database handle without a sealer and starts the container
- **THEN** start fails with an error naming the sealer option

#### Scenario: Partial identity ports
- **WHEN** the consumer registers a database handle and their own user loader, but no role loader, user provisioner or MFA requirement lookup, and starts the container
- **THEN** start fails with an error naming the identity ports that are missing

### Requirement: Consumer registrations replace any component
A component the consumer registered before the wiring SHALL be used instead of the wiring's default, and the wiring SHALL NOT fail because the component is already registered. A component the consumer overrides after the wiring and before it is first obtained SHALL replace the wiring's default for every dependent. A dependency that is not registered SHALL cause the dependent to omit the feature it enables, and that SHALL be logged at start. A dependency that is registered but fails to build SHALL be reported as an error with its own message, and SHALL NOT be treated as absent.

#### Scenario: Registered before the wiring
- **WHEN** the consumer registers their own session store and then registers the wiring with a database handle
- **THEN** the session manager uses the consumer's store and every other security-state store is durable

#### Scenario: Overridden after the wiring
- **WHEN** the consumer registers the wiring, then overrides the password encoder before starting the container
- **THEN** the authentication manager uses the consumer's encoder

#### Scenario: Registered dependency fails to build
- **WHEN** the consumer's role loader provider returns an error, and the authorization manager is obtained
- **THEN** obtaining it fails with an error that includes the role loader provider's message

#### Scenario: Optional dependency absent
- **WHEN** no role loader is registered and the container starts
- **THEN** authorization is built without per-resource privilege checks
- **AND** an informational log record states that they were omitted and why

### Requirement: Wiring errors surface before traffic
Registering the wiring SHALL validate every option that can be validated without external resources, and SHALL register nothing when any is invalid. Starting the container SHALL build every provided component, so that every constructor error is returned from start with the component's name and the underlying error.

#### Scenario: Invalid option at registration
- **WHEN** the consumer registers the wiring with an OIDC provider whose issuer is not an absolute HTTPS URL
- **THEN** registration fails naming the provider
- **AND** no component has been registered

#### Scenario: Constructor error at start
- **WHEN** the consumer passes a lockout threshold of zero through the wiring and starts the container
- **THEN** start fails with an error naming the lockout policy and wrapping its configuration error

### Requirement: The wiring does not change or check the schema
Registering or starting the container SHALL NOT apply migrations, and SHALL NOT query migration versions. The consumer SHALL apply the security-state migration set, and the identity migration set when the default identity store is used, before deploying. The wiring's documentation SHALL state this deploy order.

#### Scenario: Unmigrated database
- **WHEN** the consumer starts the container with a database handle against a database with no scrty tables
- **THEN** start creates no table and does not query migration versions

#### Scenario: Consumer migrates before start
- **WHEN** the consumer applies both migration sets with the migration runner and then starts the container
- **THEN** start succeeds and the durable stores read and write their tables

### Requirement: In-memory security stores are warned about
Starting the container SHALL log a warning for in-memory security-state stores:
- when a durable backend is registered, a warning for each store that is still in memory, naming it and what fails across replicas;
- when no durable backend is registered, one warning listing the in-memory stores and stating that they are per process.

The in-memory signing-key store SHALL always get its own warning, stating that tokens signed by one process are rejected by other processes and after a restart. Unless a shared rate-limiter factory is registered, the in-memory rate limiter SHALL get an informational record stating that the effective limit multiplies by the number of replicas. A consumer who declares a single-process deployment SHALL receive these records at debug level instead. Warnings SHALL be written through the logger the consumer configured, or the default logger otherwise.

#### Scenario: In-memory store next to a durable backend
- **WHEN** the consumer registers a database handle and their own in-memory session store, and starts the container
- **THEN** a warning names the session store as in memory in a deployment with a durable backend

#### Scenario: In-memory key store
- **WHEN** the container starts with no durable backend
- **THEN** a separate warning states that tokens signed by this process are rejected by other processes and after a restart

#### Scenario: Consumer declares a single process
- **WHEN** the consumer declares a single-process deployment and starts the container with no durable backend
- **THEN** no warning-level record about in-memory stores is written

### Requirement: Background work starts and stops through the container
Registering the wiring or building any component SHALL start no background work. Starting the container SHALL, in order:
1. build every component;
2. run the backend and identity checks;
3. write the warnings;
4. start signing-key rotation;
5. start the scheduled expiry sweeper when one is configured.

If any step fails, everything already started SHALL be stopped in reverse order before start returns the error. Starting twice SHALL fail. Shutting the container down SHALL stop the sweeper first, then key rotation, then flush every component's pending refusal-log counts. Shutdown SHALL be idempotent, SHALL be safe without a prior start, and SHALL leave no goroutine started by scrty running.

#### Scenario: Building starts nothing
- **WHEN** the wiring is registered and every component is obtained, but the container is not started
- **THEN** no key rotation or sweep runs and no scrty goroutine is running

#### Scenario: Start failure rolls back
- **WHEN** key rotation starts and the sweeper then fails to start
- **THEN** key rotation is stopped before start returns the sweeper's error

#### Scenario: Shutdown order and flush
- **WHEN** a started container is shut down after a component suppressed 4 refusal log records
- **THEN** the sweeper stops before key rotation stops
- **AND** the component's reporter then receives the count of 4
- **AND** no scrty goroutine remains

### Requirement: The container sweeps purge-capable stores on a consumer-chosen interval
The container SHALL provide an expiry runner with one task for each wired component whose store can purge. A wired store that cannot purge SHALL be left out, and start SHALL log an informational record naming it. When the consumer configures a sweep interval, start SHALL schedule and start the sweeper with that interval. When no interval is configured, no sweep SHALL be scheduled, start SHALL log one warning listing the state that will not be swept, and the runner SHALL remain available for manual runs. The consumer SHALL be able to tune the sweeper and add their own tasks.

#### Scenario: Interval configured
- **WHEN** the consumer configures a 10-minute sweep interval with a database handle and starts the container
- **THEN** the sweeper runs tasks for sessions, login attempts, one-time tokens of each wired purpose, OIDC flows and handoffs when OIDC is configured, and the rate limiter, every 10 minutes

#### Scenario: No interval configured
- **WHEN** the consumer starts the container without a sweep interval
- **THEN** no sweep runs on a schedule and a warning lists the state that will not be swept
- **AND** the expiry runner can be obtained from the container and run manually

#### Scenario: Store with native expiry
- **WHEN** the consumer registers a session store that cannot purge and starts the container with a sweep interval
- **THEN** no session task is scheduled and an informational record names the session store

#### Scenario: Consumer adds a task
- **WHEN** the consumer adds their own expiry task named `audit-log` and starts the container with a sweep interval
- **THEN** the `audit-log` task is scheduled alongside the built-in tasks

### Requirement: Shared rate limiting is selected only by registering a factory
By default every throttled flow SHALL build its own in-memory limiter, including when a database backend is registered. When the consumer registers a rate-limiter factory, the container SHALL pass it to every flow that accepts one. Start SHALL verify a registered factory that supports verification and fail if verification fails. Declaring a single-process deployment together with a registered shared factory SHALL fail start with an error naming both.

#### Scenario: Database alone does not share limits
- **WHEN** the consumer registers a database handle and no rate-limiter factory, and starts the container
- **THEN** every throttled flow uses an in-memory limiter and the per-replica informational record is written

#### Scenario: Consumer registers a shared factory
- **WHEN** the consumer registers a shared rate-limiter factory and starts the container
- **THEN** every throttled flow builds its limiter from that factory and no per-replica informational record is written

#### Scenario: Contradictory declaration
- **WHEN** the consumer declares a single-process deployment and registers a shared rate-limiter factory
- **THEN** start fails with an error naming the single-process declaration and the factory
