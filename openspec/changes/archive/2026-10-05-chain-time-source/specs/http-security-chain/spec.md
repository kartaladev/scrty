## ADDED Requirements

### Requirement: The chain reads time from one replaceable time source
The chain SHALL offer a time-source option, and SHALL use the system clock when none is configured. Every time the chain's built-in interceptors record, and every time check they make, SHALL come from that source. Every time-keeping component the chain builds for itself SHALL read the same source: the second-factor challenge state and its default store, the second-factor verification throttle, the source guards and the limiters the chain's default factory builds, and the account-recovery core. A dependency the consumer builds and hands to the chain SHALL keep its own time source, including a recovery core given its own time source. An absent time source, including a typed-nil one, SHALL fail construction.

#### Scenario: System clock by default
- **WHEN** a chain is built with no time-source option and a second-factor challenge is begun
- **THEN** the challenge's expiry is measured from the system time at begin

#### Scenario: Consumer time source drives the chain's own state
- **WHEN** a consumer configures the chain with a controlled time source, a signed-in user begins a second-factor challenge, and the source advances past the challenge's lifetime
- **THEN** answering the challenge is refused as expired, with no real waiting
- **AND** after the source also passes the challenge's issuance window, the chain's expiry task for that method removes the challenge

#### Scenario: A throttle window follows the chain's source
- **WHEN** a chain with a controlled time source and the default limiter factory refuses a source for exceeding its password-login failures, and the source advances past the window
- **THEN** a login from that source is no longer refused for throttling, with no real waiting

#### Scenario: The second-factor verification throttle follows the chain's source
- **WHEN** a chain with a controlled time source and no limiter of the consumer's for second-factor verification throttles a user after too many wrong codes, and the source advances past the throttle's window
- **THEN** the user may answer again, with no real waiting

#### Scenario: A consumer's dependency keeps its own source
- **WHEN** the chain has one controlled time source and the consumer's recovery core is given a different one
- **THEN** the recovery core's codes and holds expire on the recovery core's own source

#### Scenario: Absent time source
- **WHEN** the chain's time-source option is given a nil or typed-nil source
- **THEN** construction fails with a configuration error naming the option

## MODIFIED Requirements

### Requirement: Wiring mistakes fail at construction
Building a chain SHALL return a configuration error, and no usable chain, when the configuration cannot take effect. This SHALL include at least:
- an absent interceptor;
- an enabled built-in interceptor missing a dependency it needs, including a dependency that is present but holds a nil value;
- an absent rate-limiter factory, when the option is given;
- an absent refusal log reporter;
- a login body limit of zero or less;
- form login or HTTP Basic authentication enabled more than once;
- MFA enabled more than once;
- account recovery enabled more than once.

The error SHALL name the option and the dependency at fault. Every public option SHALL either take effect or be refused at construction.

#### Scenario: Missing dependency
- **WHEN** form login is enabled without a session manager
- **THEN** construction fails with an error naming form login and the missing session manager

#### Scenario: Nil value behind an interface
- **WHEN** bearer token authentication is given a user loader that is a nil pointer of a concrete type
- **THEN** construction fails instead of the first request panicking

#### Scenario: Absent interceptor
- **WHEN** a consumer registers an absent interceptor at any slot
- **THEN** construction fails

#### Scenario: Form login enabled twice
- **WHEN** a consumer enables form login twice, on two paths, each with its own limiter
- **THEN** construction fails with an error naming form login, because one chain has one form login and its password-login flow names one endpoint

#### Scenario: MFA enabled twice
- **WHEN** a consumer enables MFA twice on one chain, on two prefixes, each with its own methods
- **THEN** construction fails with an error naming MFA, because one chain offers one set of second-factor methods, and every method belongs in a single MFA configuration

#### Scenario: Account recovery enabled twice
- **WHEN** a consumer enables account recovery twice on one chain
- **THEN** construction fails with an error naming account recovery, because one chain has one account recovery

#### Scenario: Absent factory
- **WHEN** the chain is given a rate-limiter factory option holding a nil value
- **THEN** construction fails with an error naming the rate-limiter factory
