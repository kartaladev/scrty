## MODIFIED Requirements

### Requirement: Wiring mistakes fail at construction
Building a chain SHALL return a configuration error, and no usable chain, when the configuration cannot take effect. This SHALL include at least:
- an absent interceptor;
- an enabled built-in interceptor missing a dependency it needs, including a dependency that is present but holds a nil value;
- an absent rate-limiter factory, when the option is given;
- an absent refusal log reporter;
- a login body limit of zero or less;
- form login or HTTP Basic authentication enabled more than once;
- MFA enabled more than once.

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

#### Scenario: Absent factory
- **WHEN** the chain is given a rate-limiter factory option holding a nil value
- **THEN** construction fails with an error naming the rate-limiter factory
