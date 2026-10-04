## MODIFIED Requirements

### Requirement: Chain-level rate-limit settings reach every guard the chain builds
A rate-limiter factory configured on the chain SHALL be used for every limiter the chain builds, including those of the second-factor, enrolment, recovery and passkey components it constructs, unless that flow was given its own limiter. An IPv6 source prefix configured on the chain SHALL be used by every source guard the chain builds. With neither configured, every flow SHALL keep its in-memory default and the /64 prefix. The chain's IPv6 aggregate setting SHALL likewise be used by every source guard the chain builds.

#### Scenario: Chain prefix groups a wider allocation
- **WHEN** a chain configured with a 48-bit IPv6 prefix throttles a source from `2001:db8:1:1::1` on the API-key flow, and a request arrives from `2001:db8:1:2::1`
- **THEN** the second request is refused as throttled

#### Scenario: Chain factory reaches a flow
- **WHEN** a chain configured with a consumer's factory refuses a wrong API key
- **THEN** the failure is recorded through a limiter the factory built for the API-key flow

#### Scenario: Default prefix
- **WHEN** a chain with no prefix configured throttles `2001:db8:1:1::1` and a request arrives from `2001:db8:1:2::1`
- **THEN** the second request is not throttled

## ADDED Requirements

### Requirement: Chain source guards count an IPv6 aggregate by default
Every source guard the chain builds SHALL also count IPv6 sources by an aggregate prefix of /56, with a limit four times the flow's limit, over the flow's window, in a limiter of its own. A consumer SHALL be able to set the aggregate prefix and multiplier, or turn the aggregate off. When the source prefix is already /56 or wider and the aggregate was not set explicitly, the default aggregate SHALL be skipped. For a flow given its own limiter, the aggregate SHALL use that limiter's reported limit and window; when it reports none, the default aggregate SHALL be skipped for that flow with one warning at construction.

#### Scenario: Default aggregate
- **WHEN** a chain with default settings records 80 failed API-key attempts, 20 from each of `2001:db8:1:1::1`, `2001:db8:1:2::1`, `2001:db8:1:3::1` and `2001:db8:1:4::1`, and an attempt arrives from `2001:db8:1:5::1`
- **THEN** the attempt is refused as throttled

#### Scenario: Consumer aggregate
- **WHEN** a chain configured with a /48 aggregate and a multiplier of 2 records 40 failed API-key attempts, 20 from each of `2001:db8:1:1::1` and `2001:db8:1:200::1`, and an attempt arrives from `2001:db8:1:300::1`
- **THEN** the attempt is refused as throttled

#### Scenario: Aggregate turned off
- **WHEN** a chain with the aggregate turned off records 80 failed API-key attempts from four /64s in one /56, and an attempt arrives from a fifth /64 in it
- **THEN** the attempt is not throttled

#### Scenario: Wide source prefix skips the default aggregate
- **WHEN** a chain is configured with a 48-bit IPv6 source prefix and no aggregate setting
- **THEN** construction succeeds and its guards count no aggregate

#### Scenario: Aggregate follows a consumer limiter
- **WHEN** a chain with default settings gives the API-key flow its own limiter allowing 200 failures per minute, and 200 failed API-key attempts arrive from one /64
- **THEN** none of them is throttled by the aggregate, whose limit is 800 per minute

#### Scenario: Consumer limiter that reports no policy
- **WHEN** a chain with default settings gives the API-key flow its own limiter that does not report its limit and window
- **THEN** construction succeeds, the API-key guard counts no aggregate, and one warning names the flow

### Requirement: Contradictory aggregate settings fail at construction
Building a chain SHALL fail with a configuration error, naming the aggregate option for a contradictory setting and the flow for a flow limiter's policy, when an explicitly set aggregate prefix is not wider than the chain's source prefix, is outside 1 to 127, or has a multiplier below 1, when the aggregate is both set and turned off, when an explicitly set aggregate applies to a flow whose own limiter reports no limit and window, when a flow's own limiter reports a limit below 1 or a window of zero or less, and when an aggregate's limit, the multiplier times the flow's limit, does not fit in an int.

#### Scenario: Aggregate no wider than the source
- **WHEN** a chain is configured with a 48-bit IPv6 source prefix and an explicit /56 aggregate
- **THEN** construction fails with an error naming the aggregate option

#### Scenario: Zero multiplier
- **WHEN** a chain is configured with an aggregate multiplier of 0
- **THEN** construction fails with an error naming the aggregate option

#### Scenario: Explicit aggregate over a limiter that reports no policy
- **WHEN** a chain configured with an explicit /48 aggregate gives the API-key flow its own limiter that does not report its limit and window
- **THEN** construction fails with an error naming the aggregate option and the API-key flow

#### Scenario: Consumer limiter reports an unusable policy
- **WHEN** a chain with default settings gives the API-key flow its own limiter that reports a limit of 0 and a window of 0
- **THEN** construction fails with an error naming the API-key flow, without asking the factory for an aggregate limiter

#### Scenario: Consumer limit too large for the default aggregate
- **WHEN** a chain with default settings gives the API-key flow its own limiter whose limit times 4 does not fit in an int
- **THEN** construction fails with an error naming the API-key flow and pointing to the options that turn the aggregate off or set it
