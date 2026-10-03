## ADDED Requirements

### Requirement: Chain-level rate-limit settings reach every guard the chain builds
A rate-limiter factory configured on the chain SHALL be used for every limiter the chain builds, including those of the second-factor, enrolment, recovery and passkey components it constructs, unless that flow was given its own limiter. An IPv6 source prefix configured on the chain SHALL be used by every source guard the chain builds. With neither configured, every flow SHALL keep its in-memory default and the /64 prefix.

#### Scenario: Chain prefix groups a wider allocation
- **WHEN** a chain configured with a 48-bit IPv6 prefix throttles a source from `2001:db8:1:1::1` on the API-key flow, and a request arrives from `2001:db8:1:2::1`
- **THEN** the second request is refused as throttled

#### Scenario: Chain factory reaches a flow
- **WHEN** a chain configured with a consumer's factory refuses a wrong API key
- **THEN** the failure is recorded through a limiter the factory built for the API-key flow

#### Scenario: Default prefix
- **WHEN** a chain with no prefix configured throttles `2001:db8:1:1::1` and a request arrives from `2001:db8:1:2::1`
- **THEN** the second request is not throttled

## MODIFIED Requirements

### Requirement: Wiring mistakes fail at construction
Building a chain SHALL return a configuration error, and no usable chain, when the configuration cannot take effect. This SHALL include at least:
- an absent interceptor;
- an enabled built-in interceptor missing a dependency it needs, including a dependency that is present but holds a nil value;
- an absent rate-limiter factory, when the option is given;
- an absent refusal log reporter;
- a login body limit of zero or less.

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

#### Scenario: Absent factory
- **WHEN** the chain is given a rate-limiter factory option holding a nil value
- **THEN** construction fails with an error naming the rate-limiter factory

### Requirement: Chain refusal logs are sampled and summarised
The chain's own refusal log records SHALL be sampled per key per window, one minute by default. These are the throttled-source warning, the limiter failure and the unattributable-address errors. The keys SHALL be:
- the flow and canonical source for the throttled-source warning, so that addresses grouped into one source share one key;
- the flow alone for a limiter failure;
- the flow and reason for an unattributable address.

A throttled attempt SHALL produce one throttled-source record, not one from the guard and another from the chain. A written record SHALL carry the count suppressed before it when that count is non-zero. The sampler SHALL always have a reporter. By default the reporter writes one summary record naming the key and the suppressed count. The consumer SHALL be able to:
- change the interval, with zero or less disabling sampling;
- replace the reporter;
- flush pending counts, for example at shutdown.

Flushing the chain's refusal logs SHALL report the pending counts of every log sampler the chain holds, not only its own:
- the samplers of the interceptors it built, including the second-factor verification throttle, the enrolment path and every per-flow source guard (the chain builds each guard itself; a consumer supplies at most the limiter behind it);
- the samplers of every component it was given that can flush its refusal logs: the policies registered on its policy engine, the authenticators of form login and basic authentication, and the OIDC manager and handoff manager.

A component the consumer holds but never gave the chain is not reached, and the chain's documentation SHALL say so and name the components that flush otherwise.

The interval SHALL govern only the chain's own records. It SHALL NOT change which requests are refused, or how any other component samples its logs. A request that ended before the rate-limit check SHALL be logged at DEBUG, unsampled.

#### Scenario: Flood from one source
- **WHEN** one source is throttled 50 times within a minute
- **THEN** one warning is written for that source in that window

#### Scenario: Rotating within one IPv6 source
- **WHEN** 50 different addresses inside one throttled IPv6 /64 are refused within a minute
- **THEN** one throttled-source warning is written for that /64 in that window

#### Scenario: Sources do not suppress each other
- **WHEN** two sources are throttled in the same window
- **THEN** a warning is written for each

#### Scenario: Summary for a key that goes quiet
- **WHEN** a source is throttled 5 times in one window and not again
- **THEN** once its count ages out, the default reporter writes a summary record naming that source's key with a count of 4

#### Scenario: Consumer reporter and flush
- **WHEN** the consumer supplies a reporter that increments a metric, 3 records are suppressed, and the chain's refusal logs are flushed
- **THEN** the consumer's reporter receives the pending count of 3

#### Scenario: Sampling disabled
- **WHEN** the interval is set to zero and a source is throttled 5 times
- **THEN** five warnings are written

#### Scenario: One flush reaches the components
- **WHEN** a chain with form login, the second-factor verify endpoint, a magic-link source guard and OIDC login holds suppressed counts in the password authenticator, the verification throttle, the guard and the OIDC manager, and the chain's refusal logs are flushed
- **THEN** each of those components' reporters receives its pending count

#### Scenario: Registered policy flushed
- **WHEN** a second-factor policy registered on the chain's engine has suppressed refusals and the chain's refusal logs are flushed
- **THEN** the policy's reporter receives its pending count
