# time-source Specification

## Purpose

Defines how scrty components read and wait on time: one replaceable time source per component,
defaulting to the system clock, which also paces every background loop so a controlled clock drives
a component completely without real waiting.

## Requirements

### Requirement: Every component reads time from one replaceable time source
Every component in the core module and its driver adapters that offers a time-source option SHALL
read the current time from that single source. When no time source is configured, the component
SHALL use the system clock. Every time the component records, and every time check
it makes, SHALL come from that source. A default dependency that the component builds for itself
and that keeps time, such as a manager's default store, SHALL read the same source.

#### Scenario: System clock by default
- **WHEN** a one-time token store is constructed with no time-source option and issues a token with a 5-minute lifetime
- **THEN** the token's expiry is 5 minutes after the system time at issue

#### Scenario: Consumer time source
- **WHEN** a consumer configures a one-time token store with a time source reading 2030-01-01T12:00:00Z, issues a token with a 5-minute lifetime, and advances the source to 12:06
- **THEN** the token's expiry is 2030-01-01T12:05:00Z
- **AND** redeeming the token is refused as expired, with no real waiting

#### Scenario: A manager's default store follows the manager's time source
- **WHEN** a one-time token manager is built with a consumer time source and no store, issues a token, and the source advances past the token's expiry and the manager's issuance window
- **THEN** purging the manager's expired tokens removes that token, with no real waiting

### Requirement: An absent time source is a configuration error
Passing an absent time source to a time-source option, including a typed-nil one, SHALL fail
construction with the component's configuration error, and SHALL NOT fall back to the system clock.
The only exceptions are the in-memory session store, the in-memory one-time token store and the
UUIDv7 identifier generator, whose constructors return no error, and the MFA reset's notification
clock. Each of these SHALL keep the system clock when given an absent source, typed nil included,
and SHALL document that it does.

#### Scenario: Nil time source
- **WHEN** a session manager is constructed with its time-source option given a nil source
- **THEN** construction fails with a configuration error

#### Scenario: Absent source on a constructor that cannot fail
- **WHEN** an in-memory one-time token store is constructed with its time-source option given a typed-nil source
- **THEN** construction succeeds and the store reads the system clock

#### Scenario: Typed-nil time source
- **WHEN** a token generator is constructed with its time-source option given a typed-nil pointer to a consumer's clock type
- **THEN** construction fails with a configuration error

### Requirement: Background work is paced by the component's time source
A component that runs background work SHALL wait between runs on its own time source, never on
the system clock directly. Such a component SHALL only accept a time source that can wait as well
as read the time, so a controlled source controls everything the component does with time. A
component that only reads the time SHALL NOT require a source that can wait.

#### Scenario: Controlled source drives the loop
- **WHEN** a started component with a 1-hour background interval is given a controlled time source, and the source advances by 1 hour
- **THEN** the background work runs once, with no real waiting

#### Scenario: Read-only source for a read-only component
- **WHEN** a consumer supplies a time source that can only read the time to a component that runs no background work
- **THEN** construction succeeds

### Requirement: Background work runs one interval after the previous run finishes
Each background task SHALL next run one full interval after its previous run finishes, not on a
fixed schedule. When the time source moves forward by more than one interval at once, the task SHALL
run once, then wait a full interval again.

#### Scenario: Interval counted from the end of a run
- **WHEN** a task with a 1-minute interval starts a run at 12:00:00 that finishes at 12:00:05
- **THEN** its next run starts at 12:01:05

#### Scenario: A long jump runs once
- **WHEN** the time source of a started component with a 1-hour interval advances by 5 hours at once
- **THEN** the background task runs once, and runs again only after the source advances a further hour

### Requirement: The time-source contract uses only standard-library types
The methods a time source must provide SHALL use only standard-library types in their signatures,
so any clock type with methods of those signatures, including one from a third-party library,
satisfies the contract without an adapter. The core module's production build SHALL depend on no
clock library.

#### Scenario: Third-party fake clock passed directly
- **WHEN** a consumer passes a third-party fake clock whose read and wait methods have the contract's signatures to a component that runs background work
- **THEN** construction succeeds with no adapter, and advancing that fake drives the component's time and its background work
